# PhishGraph

**Explainable phishing detection, delivered as a Chrome extension.**
PhishGraph scores the page you are on using two kinds of clues, the **link itself** and the
**structure of the page**, and tells you *why* it thinks a page is phishing.

```
Chrome extension (Manifest V3)                         FastAPI backend
 ├─ features.js   34 page features from the DOM  ──►   ├─ URL model      (XGBoost, 40 lexical features)
 ├─ content.js    auto-scan login/payment pages        ├─ Content model  (XGBoost, 34 page features)
 ├─ background.js allowlist · cache · badge            ├─ Late fusion    (log-odds average)
 └─ popup         verdict · probability · reasons ◄──  ├─ TreeSHAP       → top-3 plain-English reasons
                                                       └─ Live context   domain age (RDAP) · DNS, cached
```

## Results

**Held-out test set** (20%, grouped by domain, never used for training or tuning):

| Model | Test rows | PR-AUC | ROC-AUC | At the "phishing" threshold: precision / recall / false-positive rate |
|---|---|---|---|---|
| URL: Logistic Regression baseline | 212,116 | 0.816 | 0.869 | (at 0.5: 0.82 / 0.62 / 7.0%) |
| **URL: XGBoost (Optuna-tuned)** | 212,116 | **0.921** | **0.946** | 0.96 / 0.66 / 1.4% |
| Page: Logistic Regression baseline | 3,141 | 0.850 | 0.912 | (at 0.5: 0.79 / 0.77 / 10.6%) |
| **Page: XGBoost (Optuna-tuned)** | 3,141 | **0.969** | **0.979** | 0.99 / 0.76 / 0.5% |

**5-fold grouped cross-validation** (mean ± 95% CI, PR-AUC):

| | Logistic Regression | Random Forest | XGBoost | XGBoost + Optuna |
|---|---|---|---|---|
| URL | 0.832 ± 0.022 | 0.906 ± 0.017 | 0.909 ± 0.025 | **0.916 ± 0.021** |
| Page | 0.868 ± 0.013 | 0.960 ± 0.006 | 0.961 ± 0.005 | **0.966 ± 0.004** |

**Real-world sanity check** (`scripts/sanity_check.py`, URL model alone, hand-picked URLs
outside the allowlist): 13/13 phishing-style URLs caught, and 1 red-banner false alarm on 17
everyday sites (`student.portal.vit.ac.in`). With a normal-looking page fused in, that one
drops to 0.39 (safe).

**What the models rely on** (mean |SHAP|, see `reports/shap_*.png`):
URL: TLD, path length/depth, host length, number of tokens, digit ratio, `.php`.
Page: number of links, form posting to `.php`, number of scripts, external hosts,
dead `#` links, title length, page size.

> The URL threshold was set for a 1% false-positive rate on the validation split, and it
> measured 1.4% on the test set. Thresholds can be tuned in `scripts/train.py`.

**Honest note on the first version.** The first URL model scored higher (PR-AUC 0.948), but it
flagged `shop.localbakery.in` as 97% phishing. In the training data, "subdomain + no path"
was phishing 91% of the time. Adding 80k benign URLs with real-world subdomains and login
paths lowered the headline number and made the model usable.

---

## Quick start (Windows, PowerShell)

The trained models are already in `models/`, so you only need to run the API and load the extension.

Double-click **`run_api.bat`**, or:
```powershell
cd C:\Users\ruman\PhishGraph
.\.venv\Scripts\Activate.ps1          # or: python -m venv .venv; pip install -r requirements-train.txt
uvicorn api.main:app --port 8000
```

Check it at <http://127.0.0.1:8000> (paste-a-link page) or <http://127.0.0.1:8000/docs> (Swagger).

**Load the extension**
1. Open `chrome://extensions` and switch on **Developer mode** (top right).
2. Click **Load unpacked** and select the `extension` folder.
3. Pin PhishGraph (puzzle icon → pin). The popup's dot turns green when the backend is reachable.

**Use it**
* Login and payment pages are scanned automatically. If one looks like phishing, a red banner
  appears at the top of the page with the reasons, and the toolbar badge shows **!**.
* Any other page: click the icon, then **Scan this page**.
* Badge: **!** phishing · **?** suspicious · **✓** safe/trusted · **×** backend unreachable.
* **Report mistake** sends the domain and your correction to the backend (`data/feedback.csv`).
* **Settings** lets you change the backend URL, turn off auto-scan, and manage sites you trusted.

**Docker**
```powershell
docker build -t phishgraph .
docker run -p 8000:8000 phishgraph
```
The same image deploys to Render, Railway or Hugging Face Spaces (they set `$PORT`). Then put
the public URL in the extension's Settings.

---

## How it works

### 1. Data
| Model | Source | Rows |
|---|---|---|
| URL | [ealvaradob/phishing-dataset](https://huggingface.co/datasets/ealvaradob/phishing-dataset) `urls.json` + 119k benign homepages + 80k benign subdomain/login-path URLs from [Tranco](https://tranco-list.eu) | 1,003,049 (370k phishing) |
| Content | same dataset, `webs.json` (HTML pages < 100 KB) | 15,701 (5.4k phishing) |

**Dataset artefacts that were found and removed** (a common source of fake 99% accuracy):
* **Scheme leak.** 45% of phishing URLs start with `http(s)://` but only 12% of benign ones do,
  because the two classes were collected differently. Scheme and `www.` are stripped before
  feature extraction, so the model cannot use them.
* **Homepage / subdomain bias.** 89% of benign URLs are deep article pages, while half of phishing
  URLs are bare domains, and "subdomain + no path" is 91% phishing. A model trained on this flags
  every homepage and every `shop.`/`mail.`/`login.` site. Benign samples were added: 119k Tranco
  homepages, plus 80k Tranco domains with common subdomains and login/account/checkout paths.
* **Duplicates.** URLs that appear with both labels are dropped. Pages are de-duplicated by hash.
* **Domain leakage.** Train/test splits and CV folds are **grouped by registered domain**, so
  the same website never appears on both sides.

Raw phishing HTML is never written to disk. `scripts/build_content_dataset.py` streams it,
keeps only numeric features, and drops the HTML (antivirus software rightly quarantines it).

### 2. Features
* **URL (40):** lengths, subdomain depth, hyphens/digits, Shannon entropy, IP host, port,
  `@`/`//` tricks, scam keywords, brand name outside the real domain (`paypal.verify-acc.xyz`),
  free-hosting and shortener services, punycode, file extension, and a **target-encoded TLD**
  (scikit-learn `TargetEncoder`, cross-fitted, so there is no label leakage).
* **Page (34):** forms and where they submit, password/hidden inputs, links that go nowhere,
  external resources, invisible iframes, meta-refresh, obfuscated JS (`eval`, `atob`...),
  page size, title, and scam wording (suspended, verify, card number...).
  The extension computes these from the live DOM in `extension/features.js`.
  `tests/parity.html` checks that the JS and Python implementations give **identical** values.

### 3. Models and evaluation
`scripts/train.py --modality url|content`:
1. 20% grouped hold-out **test set**, touched once at the end.
2. **5-fold StratifiedGroupKFold** comparison of Logistic Regression, Random Forest and XGBoost,
   reported as mean ± 95% CI.
3. **Optuna** (TPE, 20 trials, 3-fold grouped CV, PR-AUC objective) tunes XGBoost.
4. **Thresholds** are picked on a separate validation split, for a target false-positive rate
   of **1%** ("phishing", red banner) and **5%** ("suspicious", amber badge).
5. **SHAP** values (exact TreeSHAP) give the global plots in `reports/` and the per-page reasons.

**Why XGBoost and not deep learning?** The features are tabular and mixed. Gradient-boosted
trees are the strongest standard choice for that, train in seconds, and have *exact* SHAP
explanations. Logistic regression is the linear baseline.

**Class imbalance.** The training data is roughly balanced (40% phishing), but real browsing is
overwhelmingly benign. So instead of resampling, the decision threshold is set from a target
false-positive rate, and PR-AUC (not accuracy) is the main metric.

### 4. Late fusion
The HTML pages in the dataset come without their URLs, so a single joint model cannot be
trained. The two models are combined at prediction time:

`logit(p) = 0.5 · logit(p_url) + 0.5 · logit(p_page)`, and the same averaging is applied to the
thresholds. When page features are unavailable, the URL model is used alone (fallback).

### 5. Extension design (usability)
| Problem | What PhishGraph does |
|---|---|
| Speed | Popular sites skip the network entirely. Results are cached for 30 min in the extension and 1 h on the server. Domain lookups have a 3 s timeout and a 24 h cache. |
| False alarms | Tranco top-10k sites are trusted locally, *except* sites where anyone can publish (Google Sites/Forms, blogspot, GitHub Pages, cloud storage, shorteners...). The red banner only appears on login/payment-like pages at the 1% FPR threshold. "I trust this site" silences a site. |
| Privacy | Only login-like pages are auto-scanned. The extension sends the URL **without the #fragment** plus 34 numbers, never page text, HTML or anything typed. The server does not log requests. Feedback stores the domain only. |
| Backend down | The badge shows ×, the popup explains, and browsing is never blocked. |
| Single-page apps | A MutationObserver watches for 15 s for password fields added after load. |

---

## Project layout
```
phishgraph/        url_features.py · content_features.py · predictor.py · allowlist.py · infra.py
scripts/           build_url_dataset.py · build_content_dataset.py · build_allowlist.py · train.py
api/main.py        FastAPI: /predict · /feedback · /health · / (paste-a-link page)
extension/         manifest.json · background.js · features.js · content.js · popup.* · options.*
models/            url_model.joblib · content_model.joblib · allowlist.json
reports/           metrics_*.json · shap_*.png · training logs
tests/             pytest unit + API tests · parity.html · extension_harness.html
```

## Reproduce from scratch
```powershell
python -m venv .venv; .\.venv\Scripts\pip install -r requirements-train.txt
# download data (73 MB + 10 MB), the HTML is streamed later
python -c "from huggingface_hub import hf_hub_download as d; d('ealvaradob/phishing-dataset','urls.json',repo_type='dataset',local_dir='data/raw')"
curl -o data/raw/tranco/top-1m.csv.zip https://tranco-list.eu/top-1m.csv.zip
python scripts/build_url_dataset.py
python scripts/build_content_dataset.py
python scripts/build_allowlist.py
python scripts/train.py --modality content
python scripts/train.py --modality url
python scripts/sanity_check.py
python -m pytest
```

## Tests
* `python -m pytest`: feature extractors (normalisation, malformed URLs, scheme invariance,
  brand rules), API (allowlist, user-content hosts, fusion, cache, validation, feedback).
* `tests/parity.html`: the JS and Python page features match exactly.
* `tests/extension_harness.html`: runs the real extension scripts (with a stubbed `chrome.*`)
  against the live API. Auto-scan, badge, cache and warning banner.
* `tests/popup_harness.html?as=<url>`: renders the real popup with a live result.
  (Serve the project root with `python -m http.server 8765` for the three HTML harnesses.)

## Limitations (say these in the viva)
* **Static data.** The datasets are snapshots from a few years ago, so attackers' current
  tricks may differ. There are no per-row dates, so the time-drift study needs another dataset
  (see Roadmap).
* **Rendered vs static HTML.** Training pages are static HTML, while the extension sees the DOM
  after JavaScript runs. Features were chosen to be stable across both, but heavy JS sites can
  look different from the training data.
* **Fusion weights are not learned.** No dataset has both URL and HTML for the same page.
* **Domain age and DNS are shown as context only.** They are not model inputs, because looking
  up today's data for old, dead phishing domains would be misleading.
* Adaptive attackers can imitate benign feature values.

## Roadmap
1. **Infrastructure model + temporal study.** Use *Spotting the Hook* (Zenodo: DNS/WHOIS/TLS
   snapshots taken while the sites were live, Mar–Nov 2023) to train an infrastructure model,
   and compare how URL vs infrastructure features decay month by month.
2. Learn fusion weights from the feedback log.
3. Visual brand-similarity branch (pretrained CNN on screenshots via `chrome.tabs.captureVisibleTab`).
