"""Build the URL feature table.

Sources
* data/raw/urls.json  (Hugging Face ealvaradob/phishing-dataset, label 1 = phishing)
* data/raw/tranco/top-1m.csv.zip  (benign homepages)

Why add Tranco homepages: ~89% of benign URLs in urls.json are deep pages
("site.com/some/article") while about half of phishing URLs are bare domains.
Without benign homepages the model learns "no path = phishing" and flags
every homepage the user visits.

Output: data/processed/url_features.parquet
"""
import json
import random
import sys
import zipfile
from multiprocessing import Pool
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phishgraph.url_features import (  # noqa: E402
    FREE_HOSTING, extract_url_features, normalize_url, registered_domain,
)

N_TRANCO = 120_000
N_AUG = 80_000
TRANCO_MAX_RANK = 500_000

# Real browsing is full of legitimate subdomains (shop.x.in, mail.x.com) and
# login/account paths (github.com/login). The source data has few of them on
# the benign side (subdomain + no path: 92k phishing vs 9k benign), so the
# first model flagged them. These benign variants of real Tranco domains
# remove that shortcut.
AUG_SUBDOMAINS = ["shop", "mail", "app", "blog", "my", "portal", "support", "docs", "news",
                  "store", "m", "en", "account", "accounts", "login", "secure", "auth", "api",
                  "help", "community", "careers", "web", "online", "pay", "id", "sso", "forum",
                  "static", "cdn", "media", "student", "learn", "admin", "dashboard", "go"]
AUG_PATHS = ["/login", "/signin", "/sign-in", "/account", "/account/login", "/user/login",
             "/auth/login", "/my-account", "/checkout", "/cart", "/contact", "/about", "/about-us",
             "/products", "/blog", "/search?q=shoes", "/help", "/support", "/dashboard", "/settings",
             "/en/", "/index.html", "/index.php", "/login.php", "/wp-login.php", "/register",
             "/signup", "/password/reset", "/verify-email", "/account/billing", "/orders",
             "/profile", "/login?next=%2Fhome", "/auth/signin?redirect=/account", "/secure/login"]


def _work(chunk):
    """Process a chunk of (url, label, source) and return a compact DataFrame."""
    rows = []
    for url, label, source in chunk:
        f = extract_url_features(url)
        f.update(label=label, source=source, url_norm=normalize_url(url), group=registered_domain(url))
        rows.append(f)
    df = pd.DataFrame(rows)
    num = df.select_dtypes("float64").columns
    df[num] = df[num].astype("float32")
    return df


def main():
    raw = json.load(open(ROOT / "data/raw/urls.json", encoding="utf-8"))
    df = pd.DataFrame(raw).rename(columns={"text": "url"})
    df["url_norm"] = df.url.map(normalize_url)
    df = df[df.url_norm.str.len() > 3]
    # drop URLs that appear with both labels, then exact duplicates
    conflict = df.groupby("url_norm").label.nunique()
    df = df[~df.url_norm.isin(conflict[conflict > 1].index)].drop_duplicates("url_norm")
    print("hf urls after dedup:", len(df), df.label.value_counts().to_dict())

    with zipfile.ZipFile(ROOT / "data/raw/tranco/top-1m.csv.zip") as z:
        lines = z.read("top-1m.csv").decode().splitlines()
    domains = [l.split(",", 1)[1] for l in lines[:TRANCO_MAX_RANK]]
    domains = [d for d in domains if not any(d == h or d.endswith("." + h) for h in FREE_HOSTING)]
    random.seed(42)
    tranco = random.sample(domains, N_TRANCO)

    items = [(u, int(l), "hf") for u, l in zip(df.url, df.label)]
    seen = set(df.url_norm)
    items += [(d, 0, "tranco") for d in tranco if normalize_url(d) not in seen]
    for d in random.sample(domains, N_AUG):
        sub = random.random() < 0.5
        path = random.random() < 0.7 or not sub
        url = (random.choice(AUG_SUBDOMAINS) + "." if sub else "") + d + (random.choice(AUG_PATHS) if path else "")
        items.append((url, 0, "tranco_aug"))

    del raw, df
    chunks = [items[i:i + 50_000] for i in range(0, len(items), 50_000)]
    parts = []
    with Pool(4) as pool:  # 4 workers keeps peak RAM well under 8 GB
        for i, part in enumerate(pool.imap(_work, chunks)):
            parts.append(part)
            print(f"chunk {i + 1}/{len(chunks)}", flush=True)
    out = pd.concat(parts, ignore_index=True).drop_duplicates("url_norm")
    print("final:", len(out), out.groupby(["source", "label"]).size().to_dict())
    (ROOT / "data/processed").mkdir(parents=True, exist_ok=True)
    out.to_parquet(ROOT / "data/processed/url_features.parquet", index=False)


if __name__ == "__main__":
    main()
