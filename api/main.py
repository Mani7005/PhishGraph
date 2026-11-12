"""PhishGraph API.

    uvicorn api.main:app --port 8000

POST /predict   {"url": "...", "content": {...page features...} | null, "infra": true}
POST /feedback  {"domain": "...", "verdict": "...", "user_label": "safe" | "phishing"}
GET  /health

Privacy: the request body is never logged. Feedback stores only the domain,
the verdict and the user's label, with a timestamp.
"""
from __future__ import annotations

import csv
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from cachetools import TTLCache
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from phishgraph import infra
from phishgraph.predictor import Predictor

ROOT = Path(__file__).resolve().parents[1]
FEEDBACK = ROOT / "data" / "feedback.csv"
MODEL_VERSION = "1.0"

app = FastAPI(title="PhishGraph API", version=MODEL_VERSION,
              description="Explainable phishing detection from URL and page features.")
app.add_middleware(CORSMiddleware, allow_origin_regex=r"^(chrome-extension://.*|http://(localhost|127\.0\.0\.1)(:\d+)?)$",
                   allow_methods=["GET", "POST"], allow_headers=["*"])

predictor = Predictor()
_cache: TTLCache = TTLCache(maxsize=20_000, ttl=3600)


class PredictRequest(BaseModel):
    url: str = Field(..., max_length=4096, examples=["http://paypal-login.verify-account.xyz/signin.php"])
    content: dict[str, float] | None = Field(None, description="Page features computed by the extension")
    infra: bool = Field(True, description="Also look up domain age and DNS (cached, ~3 s max)")


class FeedbackRequest(BaseModel):
    domain: str = Field(..., max_length=253)
    verdict: str = Field(..., max_length=20)
    user_label: Literal["safe", "phishing"]


@app.get("/health")
def health():
    return {"status": "ok", "model_version": MODEL_VERSION,
            "content_model": predictor.content_model is not None}


@app.post("/predict")
def predict(req: PredictRequest):
    t0 = time.perf_counter()
    key = hashlib.sha1(json.dumps([req.url.split("#")[0], req.content, req.infra], sort_keys=True).encode()).hexdigest()
    if key in _cache:
        return {**_cache[key], "cached": True}
    out = predictor.predict(req.url, req.content)
    if req.infra and out["verdict"] != "trusted" and out["host"]:
        ctx = infra.lookup(out["domain"], out["host"])
        out["infra"] = ctx
        age = ctx.get("domain_age_days")
        if age is not None and age < 60:
            out["notes"] = [f"Domain registered only {age} days ago (new domains are often used for phishing)"]
        elif ctx.get("n_a_records") == 0:
            out["notes"] = ["The domain does not resolve (site may already be taken down)"]
    out["model_version"] = MODEL_VERSION
    out["latency_ms"] = round((time.perf_counter() - t0) * 1000)
    if out.get("infra", {}).get("complete", True):  # retry later if a lookup timed out
        _cache[key] = out
    return {**out, "cached": False}


@app.post("/feedback")
def feedback(req: FeedbackRequest):
    FEEDBACK.parent.mkdir(parents=True, exist_ok=True)
    new = not FEEDBACK.exists()
    with FEEDBACK.open("a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["timestamp", "domain", "verdict", "user_label"])
        w.writerow([datetime.now(timezone.utc).isoformat(), req.domain.lower(), req.verdict, req.user_label])
    return {"status": "saved"}


@app.get("/", response_class=HTMLResponse)
def home():
    return """<!doctype html><html><head><title>PhishGraph</title><style>
body{font-family:system-ui;max-width:720px;margin:40px auto;padding:0 16px;color:#222}
input{width:100%;padding:10px;font-size:15px;box-sizing:border-box}button{margin-top:8px;padding:10px 18px;font-size:15px}
.card{margin-top:16px;padding:16px;border-radius:10px;border:1px solid #ddd}.phishing{background:#fdecec}
.suspicious{background:#fff6e0}.safe,.trusted{background:#eaf7ee}li{margin:4px 0}</style></head><body>
<h2>PhishGraph</h2><p>Paste a link to check it (URL-only check; the browser extension also uses page content).</p>
<input id=u placeholder="https://example.com/login"><button onclick=go()>Check</button><div id=out></div>
<script>
async function go(){const o=document.getElementById('out');o.textContent='Checking...';
const r=await fetch('/predict',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:document.getElementById('u').value})});
const d=await r.json();const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
o.innerHTML=`<div class="card ${d.verdict}"><b>${esc(d.verdict.toUpperCase())}</b> — phishing probability ${(d.probability*100).toFixed(1)}%
<ul>${d.reasons.map(x=>`<li>${esc(x.text)}</li>`).join('')}${(d.notes||[]).map(x=>`<li>${esc(x)}</li>`).join('')}</ul>
<small>domain ${esc(d.domain)} · age ${d.infra&&d.infra.domain_age_days!=null?d.infra.domain_age_days+' days':'unknown'} · ${d.latency_ms} ms</small></div>`}
document.getElementById('u').addEventListener('keydown',e=>{if(e.key==='Enter')go()});
</script></body></html>"""
