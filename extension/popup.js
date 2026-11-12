const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);
let tab = null;
let current = null;

const LABEL = { phishing: "Phishing", suspicious: "Suspicious", safe: "Looks safe", trusted: "Trusted site" };

function render(state) {
  const r = state && state.result;
  current = r;
  $("message").className = "message";
  $("message").textContent = "";
  $("card").className = "card hidden";
  $("report").classList.add("hidden");

  if (!r) {
    $("message").textContent = state && state.status === "not-scanned"
      ? "Not a login page, so it wasn't scanned automatically. Click \u201cScan this page\u201d to check it."
      : "Click \u201cScan this page\u201d to check it.";
    return;
  }
  if (r.verdict === "unsupported") { $("message").textContent = "PhishGraph only checks http/https pages."; return; }
  if (r.verdict === "error") {
    $("message").className = "message err";
    $("message").textContent = `Could not check this page: ${r.error}. Is the backend running? (Settings)`;
    return;
  }

  $("card").className = "card " + r.verdict;
  $("verdict").textContent = LABEL[r.verdict] || r.verdict;
  $("prob").textContent = r.verdict === "trusted" ? "" : `phishing probability ${(r.probability * 100).toFixed(1)}%`;
  $("bar").style.width = `${Math.max(2, r.probability * 100)}%`;

  const parts = [];
  if (r.url_probability != null) parts.push(`link model ${(r.url_probability * 100).toFixed(0)}%`);
  if (r.content_probability != null) parts.push(`page model ${(r.content_probability * 100).toFixed(0)}%`);
  if (r.cached) parts.push("cached");
  $("parts").textContent = parts.join(" \u00b7 ");

  const ul = $("reasons");
  ul.textContent = "";
  for (const x of r.reasons || []) {
    const li = document.createElement("li");
    li.className = x.direction;
    li.textContent = x.text;
    if (x.source) { const t = document.createElement("span"); t.className = "tag"; t.textContent = x.source; li.appendChild(t); }
    ul.appendChild(li);
  }
  for (const n of r.notes || []) {
    const li = document.createElement("li"); li.className = "phishing"; li.textContent = n; ul.appendChild(li);
  }

  const inf = r.infra;
  const age = (d) => (d == null ? "unknown" : d >= 730 ? `${Math.floor(d / 365)} years` : `${d} days`);
  const ips = (n) => (n == null ? "DNS lookup pending" : n === 0 ? "does not resolve" : `${n} IP address${n > 1 ? "es" : ""}`);
  $("infra").textContent = inf
    ? `Domain ${inf.domain} \u00b7 age ${age(inf.domain_age_days)}` +
      `${inf.registrar ? " \u00b7 " + inf.registrar : ""} \u00b7 ${ips(inf.n_a_records)}`
    : "";
  if (r.verdict !== "trusted") $("report").classList.remove("hidden");
}

async function scan() {
  $("scan").disabled = true;
  $("message").textContent = "Scanning\u2026";
  let res = null;
  try {
    res = await chrome.tabs.sendMessage(tab.id, { type: "pg-scan-now" });
  } catch (_) {
    // content script not present (page opened before install): inject it, then retry
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["features.js", "content.js"] });
      res = await chrome.tabs.sendMessage(tab.id, { type: "pg-scan-now" });
    } catch (_) {
      res = await send({ type: "pg-scan-url", url: tab.url, tabId: tab.id }); // URL-only fallback
    }
  }
  $("scan").disabled = false;
  render(res ? { result: res.result } : null);
}

async function report() {
  if (!current) return;
  const label = current.verdict === "safe" ? "phishing" : "safe";
  const r = await send({ type: "pg-feedback", domain: current.domain || current.host, verdict: current.verdict, user_label: label });
  $("report").disabled = true;
  $("report").textContent = r && r.ok ? "Thanks \u2014 reported" : "Report failed";
}

(async () => {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try { $("host").textContent = new URL(tab.url).hostname; } catch { $("host").textContent = ""; }
  render(await send({ type: "pg-get", tabId: tab.id }));
  $("scan").onclick = scan;
  $("report").onclick = report;
  $("options").onclick = (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); };
  const h = await send({ type: "pg-health" });
  $("backend").className = "dot " + (h && h.ok ? "ok" : "down");
  $("backend").title = h && h.ok ? "Backend connected" : "Backend not reachable";
})();
