"""Load the trained models and score a URL (+ optional page features).

Late fusion
-----------
Use learned logistic fusion when a fitted artifact is available. Otherwise
average the two log-odds and their alert thresholds. Without page features,
use the URL model and its own thresholds.

Explanations
------------
Per-prediction SHAP values come from XGBoost's exact TreeSHAP
(pred_contribs=True) and are turned into short sentences for the user.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from .allowlist import Allowlist
from .content_features import CONTENT_FEATURES
from .url_features import BRANDS, extract_url_features, normalize_url, registered_domain, split_url

MODELS = Path(__file__).resolve().parents[1] / "models"
W_URL, W_CONTENT = 0.5, 0.5

# feature -> (sentence when it pushes towards phishing, sentence when it pushes towards safe)
REASONS = {
    # URL
    "tld": ("The domain ending '.{tld}' is frequently used by phishing sites",
            "The domain ending '.{tld}' is rarely used for phishing"),
    "brand_not_registered": ("Mentions a well-known brand ({brand}) but the site is not that brand's real domain", None),
    "brand_in_url": ("The link mentions a well-known brand ({brand})", None),
    "n_keywords": ("The link contains scam-style words (login, verify, account...): {v:.0f}",
                   "The link contains no typical scam words"),
    "free_hosting": ("Hosted on a free website/hosting service that anyone can use", None),
    "shortener": ("Uses a link shortener that hides the real destination", None),
    "is_ip": ("Uses a raw IP address instead of a domain name", None),
    "punycode": ("Uses look-alike (punycode) characters in the domain", None),
    "n_subdomains": ("Uses {v:.0f} subdomain level(s) in front of the main domain", "Has a simple domain structure"),
    "n_hyphens_host": ("The domain has {v:.0f} hyphens, common in fake domains", "The domain has no unusual hyphens"),
    "host_len": ("The domain name is unusually long ({v:.0f} characters)", "The domain name has a normal length"),
    "url_len": ("The link is unusually long ({v:.0f} characters)", "The link has a normal length"),
    "domain_entropy": ("The domain looks randomly generated", "The domain looks like a normal word/name"),
    "host_entropy": ("The host name looks randomly generated", "The host name looks normal"),
    "domain_digits": ("The domain contains {v:.0f} digits", "The domain contains no digits"),
    "n_digits_host": ("The host name contains {v:.0f} digits", None),
    "has_port": ("Uses a non-standard port", None),
    "n_at": ("Contains an '@' symbol that can hide the real destination", None),
    "double_slash_path": ("Contains a '//' redirect pattern in the path", None),
    "ext_php": ("Points to a .php script, common in phishing kits", None),
    "ext_exe": ("Points to a downloadable file (.exe/.zip/.apk)", None),
    "n_path_segments": ("Has a deep, unusual path ({v:.0f} levels)", "Has a normal path structure"),
    "path_len": ("Has an unusually long path", "Has a short, normal path"),
    "n_tokens": ("The link is made of many fragments", "The link is short and simple"),
    "domain_len": ("The domain name is long ({v:.0f} characters)", "The domain name is short"),
    "suffix_len": (None, None),
    "domain_hyphens": ("The main domain contains hyphens", "The main domain has no hyphens"),
    # content
    "n_password": ("The page asks for a password", None),
    "form_abs_action": ("A form sends your data to a full external address", None),
    "form_null_action": ("A form has no real destination (often handled by hidden scripts)", None),
    "form_php_action": ("A form submits to a PHP script, common in phishing kits", None),
    "null_anchor_ratio": ("{pct:.0f}% of links on the page go nowhere ('#')", "Links on the page lead to real pages"),
    "abs_anchor_ratio": ("Most links point to other websites", "Most links stay on this website"),
    "n_anchors": ("The page has very few links ({v:.0f}), typical of a fake login page",
                  "The page has many links ({v:.0f}), typical of a real website"),
    "kw_login": ("The page talks about logging in / signing in", None),
    "kw_verify": ("The page asks you to verify or confirm something", None),
    "kw_suspend": ("The page warns of a suspended or locked account", None),
    "kw_card": ("The page asks for card details", None),
    "kw_bank": ("The page mentions banking", None),
    "kw_account": ("The page talks about your account", None),
    "js_obfuscation": ("The page uses hidden/obfuscated scripts", None),
    "js_redirect": ("The page uses script redirects", None),
    "n_invisible_iframes": ("The page has invisible frames", None),
    "n_meta_refresh": ("The page automatically redirects", None),
    "has_title": ("The page has no title", "The page has a proper title"),
    "title_len": ("The page title is unusually short", "The page has a descriptive title"),
    "log_n_tags": ("The page is very small/simple, typical of a phishing kit",
                   "The page is large and complex, typical of a real website"),
    "n_css_links": ("The page has little styling of its own", "The page has its own stylesheets"),
    "n_scripts": ("Unusual number of scripts", "Normal script usage"),
    "n_abs_hosts": ("Loads resources from many other websites", "Loads resources from few other websites"),
    "favicon_abs": ("The site icon is loaded from another website", None),
    "n_hidden_inputs": ("The page has hidden form fields", None),
}
PRETTY = {"url": "link", "content": "page"}


def _logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def _sigmoid(z: float) -> float:
    if z < 0:
        exp_z = math.exp(z)
        return exp_z / (1 + exp_z)
    return 1 / (1 + math.exp(-z))


class _Model:
    def __init__(self, path: Path):
        art = joblib.load(path)
        self.pipeline = art["pipeline"]
        self.prep = self.pipeline.named_steps["prep"]
        self.booster = self.pipeline.named_steps["clf"].get_booster()
        self.columns = art["numeric"] + art["categorical"]
        self.feature_names = art["feature_names"]
        self.thresholds = art["thresholds"]

    def score(self, row: dict):
        X = pd.DataFrame([row])[self.columns]
        Xt = self.prep.transform(X)
        dm = xgb.DMatrix(np.asarray(Xt, dtype=float), feature_names=self.feature_names)
        p = float(self.booster.predict(dm)[0])
        contrib = self.booster.predict(dm, pred_contribs=True)[0][:-1]
        return p, dict(zip(self.feature_names, contrib.tolist()))


class Predictor:
    def __init__(self, models_dir: Path = MODELS):
        self.url_model = _Model(models_dir / "url_model.joblib")
        cpath = models_dir / "content_model.joblib"
        self.content_model = _Model(cpath) if cpath.exists() else None
        fusion_path = models_dir / "fusion_model.json"
        self.fusion = json.loads(fusion_path.read_text(encoding="utf-8")) if fusion_path.exists() else None
        self.allowlist = Allowlist(models_dir / "allowlist.json")

    # ------------------------------------------------------------------
    def predict(self, url: str, content: dict | None = None, *, round_scores: bool = True) -> dict:
        norm, host, _, _, _ = split_url(url)
        domain = registered_domain(url)
        base = {"url": norm, "host": host, "domain": domain}

        trusted = self.allowlist.check(url)
        if trusted:
            return {**base, "verdict": "trusted", "probability": 0.0, "allowlisted": trusted,
                    "url_probability": None, "content_probability": None, "used_content": False, "fusion_method": None,
                    "thresholds": None,
                    "reasons": [{"text": f"{trusted} is one of the world's most visited websites (Tranco top 10k)",
                                 "direction": "safe", "source": "allowlist", "feature": "allowlist",
                                 "impact": 0.0}]}

        url_row = extract_url_features(url)
        p_url, c_url = self.url_model.score(url_row)
        contribs = [("url", k, v, url_row.get(k)) for k, v in c_url.items()]

        p_content = None
        if content is not None and self.content_model is not None:
            c_row = {k: float(content.get(k, 0.0) or 0.0) for k in CONTENT_FEATURES}
            p_content, c_cont = self.content_model.score(c_row)
            contribs += [("content", k, v, c_row.get(k)) for k, v in c_cont.items()]

        fusion_method = "url_only"
        if p_content is None:
            p, thr = p_url, dict(self.url_model.thresholds)
        else:
            weights = {"url": W_URL, "content": W_CONTENT}
            intercept = 0.0
            fusion_method = "fixed"
            thr = {k: _sigmoid(W_URL * _logit(self.url_model.thresholds[k])
                               + W_CONTENT * _logit(self.content_model.thresholds[k]))
                   for k in ("warn", "suspicious")}
            if self.fusion is not None:
                weights = self.fusion["weights"]
                intercept = self.fusion["intercept"]
                thr = self.fusion["thresholds"]
                fusion_method = "learned"
            p = _sigmoid(intercept + weights["url"] * _logit(p_url)
                         + weights["content"] * _logit(p_content))
            contribs = [(source, k, v * weights[source], x) for source, k, v, x in contribs]

        verdict = "phishing" if p >= thr["warn"] else "suspicious" if p >= thr["suspicious"] else "safe"
        return {**base, "verdict": verdict, "probability": round(p, 4),
                "url_probability": round(p_url, 4) if round_scores else p_url,
                "content_probability": round(p_content, 4) if round_scores and p_content is not None else p_content,
                "used_content": p_content is not None, "fusion_method": fusion_method, "allowlisted": None,
                "thresholds": {k: round(v, 4) for k, v in thr.items()},
                "reasons": self._reasons(contribs, verdict, url_row, norm)}

    # ------------------------------------------------------------------
    @staticmethod
    def _reasons(contribs, verdict, url_row, norm, k=3):
        want_phish = verdict != "safe"
        ranked = sorted(contribs, key=lambda c: -c[2] if want_phish else c[2])
        brand = next((b for b in BRANDS if b in norm.lower()), "")
        out = []
        for source, feat, val, x in ranked:
            if (val > 0) != want_phish or abs(val) < 0.05:
                continue
            tmpl = REASONS.get(feat, (None, None))[0 if val > 0 else 1]
            if not tmpl:
                continue
            x = x if isinstance(x, (int, float)) else 0.0
            if feat == "tld" and url_row.get("tld") == "<ip>":
                tmpl = "Uses a raw IP address instead of a domain name"
            text = tmpl.format(v=x, pct=100 * x, tld=url_row.get("tld", ""), brand=brand or "a brand")
            out.append({"text": text, "feature": feat, "source": PRETTY[source],
                        "impact": round(float(val), 3), "direction": "phishing" if val > 0 else "safe"})
            if len(out) == k:
                break
        return out
