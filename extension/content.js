// PhishGraph content script.
// 1. Computes page features from the live DOM (features.js, which mirrors
//    phishgraph/content_features.py).
// 2. Auto-scans pages that look like login/payment pages.
// 3. Shows a warning banner when the backend says "phishing".
// Only numeric features leave the page, never the HTML or anything typed.
(() => {
  if (window.__phishgraphLoaded) return;
  window.__phishgraphLoaded = true;

  const { extractFeatures } = globalThis.PhishGraphFeatures;

  // A page is "login-like" if it asks for a password, or has a form with text
  // fields plus login / verification / card wording.
  function isLoginLike(f) {
    return f.n_password > 0 || (f.n_forms > 0 && f.n_text_inputs > 0 && (f.kw_login || f.kw_verify || f.kw_card));
  }

  let scanned = false;
  async function scan(auto) {
    const features = extractFeatures();
    if (auto && !isLoginLike(features)) return null;
    scanned = true;
    const res = await chrome.runtime.sendMessage({ type: "pg-scan", url: location.href, features, auto });
    if (res && res.result && res.result.verdict === "phishing" && auto && !res.ignored) showBanner(res.result);
    return res;
  }

  // ------------------------------------------------------------ banner
  function showBanner(r) {
    if (document.getElementById("phishgraph-banner-host")) return;
    const host = document.createElement("div");
    host.id = "phishgraph-banner-host";
    const root = host.attachShadow({ mode: "closed" });
    const reasons = (r.reasons || []).map((x) => x.text).concat(r.notes || []).slice(0, 4);
    root.innerHTML = `
      <style>
        .wrap{position:fixed;inset:0 0 auto 0;z-index:2147483647;font:14px/1.45 system-ui,Segoe UI,Arial,sans-serif;
          background:#b3261e;color:#fff;box-shadow:0 4px 18px rgba(0,0,0,.35);padding:16px 20px}
        h2{margin:0 0 4px;font-size:18px} ul{margin:6px 0 10px 18px;padding:0} li{margin:2px 0}
        button{font:600 14px system-ui;border:0;border-radius:6px;padding:8px 14px;margin-right:8px;cursor:pointer}
        .leave{background:#fff;color:#b3261e} .stay{background:transparent;color:#fff;border:1px solid #fff}
        small{opacity:.85}
      </style>
      <div class="wrap" role="alert">
        <h2>\u26a0 PhishGraph: this page is likely a phishing page</h2>
        <div>Phishing probability <b>${Math.round(r.probability * 100)}%</b>. Do not enter passwords or payment details.</div>
        <ul></ul>
        <button class="leave">Leave this page</button>
        <button class="stay">I trust this site</button>
        <small>Domain: <span class="dom"></span></small>
      </div>`;
    const ul = root.querySelector("ul");
    for (const t of reasons) { const li = document.createElement("li"); li.textContent = t; ul.appendChild(li); }
    root.querySelector(".dom").textContent = r.host || r.domain || "";
    root.querySelector(".leave").onclick = () => {
      if (history.length > 1) history.back(); else location.replace("about:blank");
    };
    root.querySelector(".stay").onclick = async () => {
      await chrome.runtime.sendMessage({ type: "pg-ignore", host: location.hostname });
      host.remove();
    };
    document.documentElement.appendChild(host);
  }

  // ------------------------------------------------------------ wiring
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === "pg-scan-now") {
      scan(false).then(sendResponse);
      return true; // async response
    }
    if (msg.type === "pg-features") {
      sendResponse({ features: extractFeatures() });
    }
  });

  (async () => {
    const { autoScan } = await chrome.runtime.sendMessage({ type: "pg-page", url: location.href });
    if (!autoScan) return;
    await scan(true);
    // Single-page apps often add the login form after load: watch for 15 s.
    if (!scanned) {
      const obs = new MutationObserver(() => {
        if (!scanned && document.querySelector("input[type=password i]")) { obs.disconnect(); scan(true); }
      });
      obs.observe(document.documentElement, { childList: true, subtree: true });
      setTimeout(() => obs.disconnect(), 15000);
    }
  })();
})();
