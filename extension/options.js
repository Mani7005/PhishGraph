const $ = (id) => document.getElementById(id);
const DEFAULTS = { backend: "http://127.0.0.1:8000", autoScan: true };

async function load() {
  const s = { ...DEFAULTS, ...(await chrome.storage.local.get(["backend", "autoScan", "ignored"])) };
  $("backend").value = s.backend;
  $("autoScan").checked = s.autoScan;
  const ul = $("ignored");
  ul.textContent = "";
  for (const h of s.ignored || []) {
    const li = document.createElement("li");
    li.textContent = h;
    const b = document.createElement("button");
    b.textContent = "Remove";
    b.onclick = async () => {
      const { ignored = [] } = await chrome.storage.local.get("ignored");
      await chrome.storage.local.set({ ignored: ignored.filter((x) => x !== h) });
      load();
    };
    li.appendChild(b);
    ul.appendChild(li);
  }
  if (!(s.ignored || []).length) ul.innerHTML = "<li class='muted'>None</li>";
}

$("save").onclick = async () => {
  const backend = $("backend").value.trim().replace(/\/$/, "") || DEFAULTS.backend;
  await chrome.storage.local.set({ backend, autoScan: $("autoScan").checked });
  $("status").textContent = "Saved \u2713";
};

$("test").onclick = async () => {
  $("status").textContent = "Testing\u2026";
  const r = await chrome.runtime.sendMessage({ type: "pg-health", backend: $("backend").value.trim() });
  $("status").textContent = r && r.ok ? `Connected \u2713 (model v${r.model_version})` : `Not reachable: ${r && r.error}`;
};

load();
