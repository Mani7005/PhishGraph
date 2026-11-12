import json
from pathlib import Path

import pytest

from phishgraph.content_features import CONTENT_FEATURES, extract_content_features
from phishgraph.url_features import (URL_NUMERIC_FEATURES, extract_url_features, normalize_url,
                                     registered_domain)

FIX = Path(__file__).parent / "fixtures"


# ------------------------------------------------------------------ URL
@pytest.mark.parametrize("raw,norm", [
    ("https://www.Example.COM/Path?q=1#frag", "example.com/Path?q=1"),
    ("HTTP://example.com/", "example.com"),
    ("example.com", "example.com"),
    ("  http://sub.example.co.uk/a  ", "sub.example.co.uk/a"),
])
def test_normalize(raw, norm):
    assert normalize_url(raw) == norm


def test_scheme_does_not_change_features():
    # the dataset's http:// artefact must not leak into features
    a = extract_url_features("http://evil-login.xyz/verify")
    b = extract_url_features("evil-login.xyz/verify")
    c = extract_url_features("https://www.evil-login.xyz/verify#x")
    assert a == b == c


def test_registered_domain_private_suffix():
    assert registered_domain("https://accounts.google.com/x") == "google.com"
    assert registered_domain("evil.blogspot.com/paypal") == "evil.blogspot.com"
    assert registered_domain("a.b.example.co.uk") == "example.co.uk"


def test_brand_impersonation_flags():
    f = extract_url_features("http://paypal-secure.account-verify.xyz/login.php")
    assert f["brand_not_registered"] == 1 and f["ext_php"] == 1 and f["n_keywords"] >= 3
    real = extract_url_features("https://www.paypal.com/signin")
    assert real["brand_not_registered"] == 0


def test_short_brand_needs_whole_token():
    assert extract_url_features("example.com/delivery-status")["brand_in_url"] == 0  # 'live', 'ups' inside words
    assert extract_url_features("ups.track-parcel.top")["brand_in_url"] == 1


def test_ip_and_malformed_urls():
    assert extract_url_features("http://192.168.10.5:8080/login")["is_ip"] == 1
    for bad in ["", "http://[abc/x", "a[b.com/x?y=1", "%%%", "http://x.com:99999/"]:
        f = extract_url_features(bad)
        assert set(URL_NUMERIC_FEATURES) <= set(f)


# ------------------------------------------------------------------ content
def test_content_fake_login():
    f = extract_content_features((FIX / "fake_login.html").read_text(encoding="utf-8"))
    assert f["n_password"] == 1 and f["form_abs_action"] == 1 and f["form_php_action"] == 1
    assert f["n_invisible_iframes"] == 2 and f["kw_suspend"] == 1 and f["kw_card"] == 1
    assert f["null_anchor_ratio"] == pytest.approx(2 / 3)


def test_content_empty_and_garbage():
    for html in ["", "   ", "<<<>>>", "\x00\x01"]:
        f = extract_content_features(html)
        assert list(f) == CONTENT_FEATURES


def test_write_parity_expectations():
    """Writes the Python feature values that tests/parity.html checks the JS against."""
    expected = {p.name: extract_content_features(p.read_text(encoding="utf-8"))
                for p in sorted(FIX.glob("*.html"))}
    (FIX / "expected_features.json").write_text(json.dumps(expected, indent=1))
    assert len(expected) >= 3
