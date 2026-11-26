// PhishGraph service worker: allowlist, cache, backend calls, toolbar badge.
const DEFAULTS = { backend: "http://127.0.0.1:8000", autoScan: true };
const CACHE_TTL_MS = 30 * 60 * 1000;
const TIMEOUT_MS = 10000;
const cache = new Map(); // key -> {t, result}
let allow = null;

async function settings() {
  return { ...DEFAULTS, ...(await chrome.storage.local.get(["backend", "autoScan"])) };
}

async function allowlist() {
  if (!allow) {
    const d = await (await fetch(chrome.runtime.getURL("allowlist.json"))).json();
    allow = { trusted: new Set(d.trusted), user: new Set(d.user_content) };
  }
  return allow;
}

function suffixMatch(host, set) {
  const p = host.split(".");
  for (let i = 0; i < p.length - 1; i++) {
    const c = p.slice(i).join(".");
    if (set.has(c)) return c;
  }
  return null;
}

async function isIgnored(host) {
  const { ignored = [] } = await chrome.storage.local.get("ignored");
  return ignored.includes(host);
}

const BADGE = {
  phishing: ["!", "#b3261e"], suspicious: ["?", "#e8a200"], safe: ["\u2713", "#1e8e3e"],
  trusted: ["\u2713", "#1e8e3e"], error: ["\u00d7", "#777"],
};

async function setBadge(tabId, verdict) {
  const [text, color] = BADGE[verdict] || ["", "#777"];
  try {
    await chrome.action.setBadgeText({ tabId, text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color });
  } catch (_) { /* tab closed */ }
}

async function check(url, features) {
  let u;
  try { u = new URL(url); } catch { return { verdict: "unsupported" }; }
  if (!["http:", "https:"].includes(u.protocol)) return { verdict: "unsupported" };
  const host = u.hostname.toLowerCase();

  // Popular, non-user-content domains are trusted locally: no network call at all.
  const a = await allowlist();
  if (!suffixMatch(host, a.user)) {
    const d = suffixMatch(host, a.trusted);
    if (d) {
      return { verdict: "trusted", probability: 0, host, domain: d, allowlisted: d, local: true,
               reasons: [{ text: `${d} is one of the world's most visited websites (Tranco top 10k)`, direction: "safe" }] };
    }
  }

  const { backend } = await settings();
  const endpoint = backend.replace(/\/$/, "");
  const scanUrl = u.origin + u.pathname + u.search;
  const key = JSON.stringify([endpoint, scanUrl, features]);
  const hit = cache.get(key);
  if (hit && Date.now() - hit.t < CACHE_TTL_MS) return hit.result;

  if (hit) cache.delete(key);

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(endpoint + "/predict", {
      method: "POST", headers: { "Content-Type": "application/json" }, signal: ctrl.signal,
      // the #fragment is stripped: it can hold tokens/emails and is not needed
      body: JSON.stringify({ url: scanUrl, content: features || null, infra: true }),
    });
    if (!r.ok) throw new Error(`backend returned HTTP ${r.status}`);
    const result = await r.json();
    if (result.infra?.complete !== false) {
      cache.set(key, { t: Date.now(), result });
    }
    return result;
  } catch (e) {
    return { verdict: "error", error: e.name === "AbortError" ? "backend timed out" : `cannot reach backend (${e.message})` };
  } finally {
    clearTimeout(timer);
  }
}

async function saveTab(tabId, data) {
  await chrome.storage.session.set({ ["tab_" + tabId]: data });
}

async function handle(msg, sender) {
  const tabId = msg.tabId ?? sender.tab?.id;
  switch (msg.type) {
    case "pg-page": { // new page loaded in a tab: reset its state
      if (sender.frameId === 0 && tabId != null) {
        await saveTab(tabId, { url: msg.url, status: "not-scanned" });
        await setBadge(tabId, null);
      }
      return { autoScan: (await settings()).autoScan };
    }
    case "pg-scan": { // from content script (auto or user-triggered)
      const result = await check(msg.url, msg.features);
      if (tabId != null) {
        await saveTab(tabId, { url: msg.url, status: "scanned", auto: msg.auto, result, t: Date.now() });
        await setBadge(tabId, result.verdict);
      }
      return { result, ignored: await isIgnored(new URL(msg.url).hostname) };
    }
    case "pg-scan-url": { // popup fallback when no content script is available
      const result = await check(msg.url, null);
      await saveTab(tabId, { url: msg.url, status: "scanned", auto: false, result, t: Date.now() });
      await setBadge(tabId, result.verdict);
      return { result };
    }
    case "pg-get":
      return (await chrome.storage.session.get("tab_" + tabId))["tab_" + tabId] || null;
    case "pg-ignore": {
      const { ignored = [] } = await chrome.storage.local.get("ignored");
      if (!ignored.includes(msg.host)) ignored.push(msg.host);
      await chrome.storage.local.set({ ignored });
      return { ok: true };
    }
    case "pg-feedback": {
      const { backend } = await settings();
      try {
        const r = await fetch(backend.replace(/\/$/, "") + "/feedback", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain: msg.domain, verdict: msg.verdict, user_label: msg.user_label }),
        });
        return { ok: r.ok };
      } catch (e) { return { ok: false, error: e.message }; }
    }
    case "pg-health": {
      const { backend } = await settings();
      try {
        const r = await fetch((msg.backend || backend).replace(/\/$/, "") + "/health", { signal: AbortSignal.timeout(4000) });
        return { ok: r.ok, ...(await r.json()) };
      } catch (e) { return { ok: false, error: e.message }; }
    }
  }
  return null;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handle(msg, sender).then(sendResponse, (error) => {
    const message = error.message;
    const result = { verdict: "error", error: message };
    sendResponse({ ok: false, error: message, result });
  });
  return true; // keep the channel open for the async response
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove("tab_" + tabId));
