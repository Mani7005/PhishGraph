"""Page-content (HTML/DOM) features.

IMPORTANT: extension/content.js re-implements exactly these features in
JavaScript against the live DOM. If you change a definition here, change it
there too (tests/test_parity.py and the README explain how to check).

Design rules that keep training and serving consistent:
* Only raw attribute values are used (getAttribute in JS), never resolved URLs.
* "Absolute" means the value starts with http://, https:// or // . We do not
  know the page's own domain in the training data, so no feature depends on it.
* Keyword features run on the lower-cased HTML string.
"""
from __future__ import annotations

import math
import re
from urllib.parse import urlsplit

import lxml.html

CONTENT_FEATURES = [
    "n_forms", "n_inputs", "n_password", "n_hidden_inputs", "n_text_inputs",
    "form_abs_action", "form_null_action", "form_php_action", "form_mailto",
    "n_anchors", "abs_anchor_ratio", "null_anchor_ratio",
    "n_scripts", "n_ext_scripts", "n_iframes", "n_invisible_iframes",
    "n_imgs", "abs_img_ratio", "n_css_links", "favicon_abs", "n_meta_refresh",
    "title_len", "has_title", "log_n_tags", "n_abs_hosts",
    "kw_login", "kw_password", "kw_verify", "kw_account", "kw_bank",
    "kw_suspend", "kw_card", "js_obfuscation", "js_redirect",
]

_ABS = re.compile(r"^(https?:)?//", re.I)
_KW = {
    "kw_login": re.compile(r"log ?in|sign ?in"),
    "kw_password": re.compile(r"password|passcode|passwd"),
    "kw_verify": re.compile(r"verif|confirm your"),
    "kw_account": re.compile(r"account"),
    "kw_bank": re.compile(r"bank"),
    "kw_suspend": re.compile(r"suspend|locked|unusual activity|limited access"),
    "kw_card": re.compile(r"card number|cvv|expiration date|expiry date"),
}
_OBF = re.compile(r"eval\(|unescape\(|atob\(|fromcharcode|document\.write\(")
_REDIR = re.compile(r"window\.location|location\.href|location\.replace")
_TEXT_TYPES = {"", "text", "email", "tel", "number"}


def _attr(el, name: str) -> str:
    return (el.get(name) or "").strip()


def _is_abs(v: str) -> bool:
    return bool(_ABS.match(v))


def _host(v: str) -> str:
    try:
        return (urlsplit(v if not v.startswith("//") else "http:" + v).hostname or "").lower()
    except ValueError:
        return ""


def extract_content_features(html: str) -> dict:
    """Return a dict of numeric features for one HTML document."""
    low = (html or "").lower()
    try:
        doc = lxml.html.document_fromstring(html) if html and html.strip() else None
    except (ValueError, lxml.etree.ParserError):
        doc = None

    def q(xpath):
        return doc.xpath(xpath) if doc is not None else []

    forms = q("//form")
    inputs = q("//input")
    types = [_attr(i, "type").lower() for i in inputs]
    actions = [_attr(f, "action").lower() for f in forms]
    anchors = [_attr(a, "href").lower() for a in q("//a[@href]")]
    scripts = q("//script")
    ext_scripts = [_attr(s, "src") for s in scripts if _attr(s, "src")]
    iframes = q("//iframe")
    imgs = [_attr(i, "src") for i in q("//img[@src]")]
    links = q("//link")
    rels = [(_attr(l, "rel").lower(), _attr(l, "href")) for l in links]
    titles = q("//title")
    title = (titles[0].text_content() if titles else "").strip()
    n_tags = len(q("//*"))
    if doc is not None:  # browsers always create <head> and <body>; lxml only when needed
        n_tags += (doc.find("head") is None) + (doc.find("body") is None)

    def invisible(fr):
        style = _attr(fr, "style").lower().replace(" ", "")
        return (_attr(fr, "width") in ("0", "1") or _attr(fr, "height") in ("0", "1")
                or "display:none" in style or "visibility:hidden" in style)

    abs_urls = [v for v in anchors + ext_scripts + imgs + [h for _, h in rels] if _is_abs(v)]
    n_a = len(anchors)
    f = {
        "n_forms": len(forms),
        "n_inputs": len(inputs),
        "n_password": types.count("password"),
        "n_hidden_inputs": types.count("hidden"),
        "n_text_inputs": sum(t in _TEXT_TYPES for t in types),
        "form_abs_action": sum(_is_abs(a) for a in actions),
        "form_null_action": sum(a in ("", "#", "about:blank") or a.startswith("javascript:") for a in actions),
        "form_php_action": sum(".php" in a for a in actions),
        "form_mailto": sum(a.startswith("mailto:") for a in actions),
        "n_anchors": n_a,
        "abs_anchor_ratio": (sum(_is_abs(a) for a in anchors) / n_a) if n_a else 0.0,
        "null_anchor_ratio": (sum(a.startswith("#") or a.startswith("javascript:") for a in anchors) / n_a) if n_a else 0.0,
        "n_scripts": len(scripts),
        "n_ext_scripts": len(ext_scripts),
        "n_iframes": len(iframes),
        "n_invisible_iframes": sum(invisible(fr) for fr in iframes),
        "n_imgs": len(imgs),
        "abs_img_ratio": (sum(_is_abs(s) for s in imgs) / len(imgs)) if imgs else 0.0,
        "n_css_links": sum("stylesheet" in r for r, _ in rels),
        "favicon_abs": int(any("icon" in r and _is_abs(h) for r, h in rels)),
        "n_meta_refresh": sum(_attr(m, "http-equiv").lower() == "refresh" for m in q("//meta")),
        "title_len": len(title),
        "has_title": int(bool(title)),
        "log_n_tags": math.log1p(n_tags),
        "n_abs_hosts": len({_host(u) for u in abs_urls} - {""}),
        "js_obfuscation": len(_OBF.findall(low)),
        "js_redirect": len(_REDIR.findall(low)),
    }
    for k, rx in _KW.items():
        f[k] = int(bool(rx.search(low)))
    return {k: float(f[k]) for k in CONTENT_FEATURES}
