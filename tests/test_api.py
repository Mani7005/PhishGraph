"""API tests. Infra lookups are switched off (infra=false) so tests run offline."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from phishgraph.content_features import extract_content_features

pytest.importorskip("xgboost")
MODELS = Path(__file__).resolve().parents[1] / "models"
if not (MODELS / "url_model.joblib").exists():
    pytest.skip("train the models first (scripts/train.py)", allow_module_level=True)

from api.main import app  # noqa: E402

client = TestClient(app)
FIX = Path(__file__).parent / "fixtures"


def post(url, content=None):
    r = client.post("/predict", json={"url": url, "content": content, "infra": False})
    assert r.status_code == 200, r.text
    return r.json()


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_allowlisted_domain_is_trusted():
    d = post("https://www.google.com/search?q=x")
    assert d["verdict"] == "trusted" and d["allowlisted"] == "google.com"


def test_user_content_host_is_not_allowlisted():
    d = post("https://sites.google.com/view/secure-account-login")
    assert d["verdict"] != "trusted"


def test_obvious_phishing_url_is_flagged():
    d = post("http://paypal.com-secure-login.verify-account.xyz/webscr/signin.php?cmd=login")
    assert d["verdict"] in ("phishing", "suspicious")
    assert d["probability"] > 0.5 and len(d["reasons"]) >= 1


def test_fusion_with_page_features():
    page = extract_content_features((FIX / "fake_login.html").read_text(encoding="utf-8"))
    d = post("http://account-verify-center.top/login.php", page)
    assert d["used_content"] and d["content_probability"] is not None
    assert d["verdict"] in ("phishing", "suspicious")


def test_response_schema_and_cache():
    a = post("https://some-small-blog.net/2021/05/recipes")
    for k in ("verdict", "probability", "url_probability", "reasons", "thresholds", "domain"):
        assert k in a
    b = client.post("/predict", json={"url": "https://some-small-blog.net/2021/05/recipes", "infra": False}).json()
    assert b["cached"] is True


def test_bad_input():
    assert client.post("/predict", json={}).status_code == 422
    assert client.post("/predict", json={"url": "x" * 5000}).status_code == 422
    d = post("not a url at all")
    assert "verdict" in d


def test_feedback(tmp_path, monkeypatch):
    import api.main as m
    monkeypatch.setattr(m, "FEEDBACK", tmp_path / "fb.csv")
    r = client.post("/feedback", json={"domain": "Example.com", "verdict": "phishing", "user_label": "safe"})
    assert r.json() == {"status": "saved"}
    assert "example.com" in (tmp_path / "fb.csv").read_text()
    assert client.post("/feedback", json={"domain": "x", "verdict": "y", "user_label": "maybe"}).status_code == 422
