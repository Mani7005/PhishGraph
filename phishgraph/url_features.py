"""Lexical URL features.

URLs are normalised before feature extraction so the model cannot learn
dataset artefacts:
* scheme (http/https) is removed: in the training data, benign URLs mostly
  have no scheme while phishing URLs often do, which is a collection artefact,
  not a phishing signal;
* leading "www." is removed;
* the #fragment is dropped (privacy, and it is never sent to the server).
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

import tldextract

# Bundled public-suffix snapshot: deterministic, no network calls.
# Private suffixes (blogspot.com, github.io, ...) count as suffixes, so
# "evil.blogspot.com" has registered domain "evil.blogspot.com".
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

BRANDS = [
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "hotmail", "live",
    "google", "gmail", "amazon", "netflix", "facebook", "instagram", "whatsapp",
    "linkedin", "twitter", "yahoo", "aol", "dropbox", "docusign", "adobe", "ebay",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays", "santander",
    "americanexpress", "amex", "visa", "mastercard", "dhl", "fedex", "usps", "ups",
    "steam", "roblox", "coinbase", "binance", "metamask", "blockchain", "irs", "sbi",
    "hdfc", "icici", "paytm", "airtel", "spotify", "walmart", "att", "verizon",
]
KEYWORDS = [
    "login", "logon", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "banking", "confirm", "password", "webscr", "wallet",
    "support", "unlock", "suspend", "billing", "invoice", "recover", "auth",
    "session", "token", "validate", "authenticate", "customer", "service",
]
FREE_HOSTING = {
    "000webhostapp.com", "blogspot.com", "weebly.com", "wixsite.com", "wix.com",
    "firebaseapp.com", "web.app", "duckdns.org", "ngrok.io", "ngrok-free.app",
    "github.io", "glitch.me", "netlify.app", "vercel.app", "herokuapp.com",
    "r2.dev", "workers.dev", "pages.dev", "sites.google.com", "godaddysites.com",
    "webflow.io", "square.site", "yolasite.com", "jimdosite.com", "azurewebsites.net",
    "appspot.com", "repl.co", "replit.app", "surge.sh", "framer.app", "carrd.co",
    "mybluehost.me", "selcdn.ru", "ipfs.io", "dweb.link", "translate.goog",
    "googleapis.com", "windows.net", "codeanyapp.com", "zapier.app", "weeblysite.com",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "qrco.de", "bit.do",
}
URL_NUMERIC_FEATURES = [
    "url_len", "host_len", "path_len", "query_len", "n_path_segments", "n_params",
    "n_subdomains", "n_dots_host", "n_hyphens_host", "n_digits_host", "host_digit_ratio",
    "host_entropy", "domain_len", "domain_entropy", "domain_digits", "domain_hyphens",
    "is_ip", "has_port", "n_at", "n_tilde", "n_percent", "n_eq", "n_amp", "n_underscore",
    "double_slash_path", "url_digit_ratio", "n_keywords", "brand_in_url",
    "brand_not_registered", "free_hosting", "shortener", "punycode", "ext_php",
    "ext_html", "ext_exe", "longest_token", "n_tokens", "suffix_len", "suffix_levels",
]
TLD_FEATURE = "tld"
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_TOKEN = re.compile(r"[^a-z0-9]+")


def normalize_url(url: str) -> str:
    """Lower-case host, strip scheme, 'www.', fragment and surrounding whitespace."""
    u = (url or "").strip()
    u = _SCHEME.sub("", u)
    u = u.split("#", 1)[0]
    host, sep, rest = u.partition("/")
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]
    if rest == "":  # "example.com/" == "example.com" (browsers always add the slash)
        sep = ""
    return host + sep + rest


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def split_url(url: str):
    norm = normalize_url(url)
    try:
        parts = urlsplit("http://" + norm)
        host = parts.hostname or ""
        path, query = parts.path or "", parts.query or ""
    except ValueError:  # malformed input such as "a[b.com/x" — parse by hand
        hostport, _, rest = norm.partition("/")
        host = hostport.split(":")[0].lower()
        path, _, query = ("/" + rest).partition("?")
        return norm, host, None, path, query
    try:
        port = parts.port
    except ValueError:
        port = None
    return norm, host, port, path, query


def registered_domain(url: str) -> str:
    """eTLD+1 (with private suffixes), e.g. 'evil.blogspot.com', 'paypal.com'."""
    _, host, _, _, _ = split_url(url)
    ext = _EXTRACT(host)
    return ext.top_domain_under_public_suffix or host


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)", host))  # hex / decimal IP forms


def extract_url_features(url: str) -> dict:
    norm, host, port, path, query = split_url(url)
    ext = _EXTRACT(host)
    domain, suffix, sub = ext.domain.lower(), ext.suffix.lower(), ext.subdomain.lower()
    reg = ext.top_domain_under_public_suffix.lower() if ext.top_domain_under_public_suffix else host
    low = norm.lower()
    tokens = [t for t in _TOKEN.split(low) if t]
    rest = low[len(host):]  # path + query
    is_ip = _is_ip(host)

    # Short brands (ups, att, irs...) must be a whole token; long ones may be
    # embedded ("paypal-secure", "securepaypal").
    token_set = set(tokens)
    brands_in_url = [b for b in BRANDS if (b in token_set) or (len(b) >= 5 and b in low)]
    brand_not_reg = any(b not in domain for b in brands_in_url)
    free_suffixes = {suffix, ".".join(host.split(".")[-2:]), ".".join(host.split(".")[-3:])}

    f = {
        "url_len": len(norm),
        "host_len": len(host),
        "path_len": len(path),
        "query_len": len(query),
        "n_path_segments": len([p for p in path.split("/") if p]),
        "n_params": len([p for p in query.split("&") if p]),
        "n_subdomains": 0 if is_ip else len([s for s in sub.split(".") if s]),
        "n_dots_host": host.count("."),
        "n_hyphens_host": host.count("-"),
        "n_digits_host": sum(c.isdigit() for c in host),
        "host_digit_ratio": (sum(c.isdigit() for c in host) / len(host)) if host else 0.0,
        "host_entropy": _entropy(host),
        "domain_len": len(domain),
        "domain_entropy": _entropy(domain),
        "domain_digits": sum(c.isdigit() for c in domain),
        "domain_hyphens": domain.count("-"),
        "is_ip": int(is_ip),
        "has_port": int(port is not None),
        "n_at": low.count("@"),
        "n_tilde": low.count("~"),
        "n_percent": low.count("%"),
        "n_eq": low.count("="),
        "n_amp": low.count("&"),
        "n_underscore": low.count("_"),
        "double_slash_path": int("//" in rest),
        "url_digit_ratio": (sum(c.isdigit() for c in low) / len(low)) if low else 0.0,
        "n_keywords": sum(k in low for k in KEYWORDS),
        "brand_in_url": len(brands_in_url),
        "brand_not_registered": int(brand_not_reg),
        "free_hosting": int(bool(free_suffixes & FREE_HOSTING)),
        "shortener": int(reg in SHORTENERS),
        "punycode": int("xn--" in host),
        "ext_php": int(path.lower().endswith(".php")),
        "ext_html": int(path.lower().endswith((".html", ".htm"))),
        "ext_exe": int(path.lower().endswith((".exe", ".zip", ".apk", ".scr", ".msi"))),
        "longest_token": max((len(t) for t in tokens), default=0),
        "n_tokens": len(tokens),
        "suffix_len": len(suffix),
        "suffix_levels": suffix.count(".") + 1 if suffix else 0,
    }
    out = {k: float(f[k]) for k in URL_NUMERIC_FEATURES}
    out[TLD_FEATURE] = "<ip>" if is_ip else (suffix.split(".")[-1] if suffix else "<none>")
    return out
