// PhishGraph page features: MUST match phishgraph/content_features.py exactly.
// Kept in its own file so tests/parity.html can run the same code.
(() => {
  const ABS = /^(https?:)?\/\//i;
  const KW = {
    kw_login: /log ?in|sign ?in/,
    kw_password: /password|passcode|passwd/,
    kw_verify: /verif|confirm your/,
    kw_account: /account/,
    kw_bank: /bank/,
    kw_suspend: /suspend|locked|unusual activity|limited access/,
    kw_card: /card number|cvv|expiration date|expiry date/,
  };
  const OBF = /eval\(|unescape\(|atob\(|fromcharcode|document\.write\(/g;
  const REDIR = /window\.location|location\.href|location\.replace/g;
  const TEXT_TYPES = new Set(["", "text", "email", "tel", "number"]);

  const attr = (el, n) => (el.getAttribute(n) || "").trim();
  const isAbs = (v) => ABS.test(v);
  const hostOf = (v) => {
    try { return new URL(v.startsWith("//") ? "http:" + v : v).hostname.toLowerCase(); }
    catch { return ""; }
  };
  const count = (s, rx) => (s.match(rx) || []).length;
  

  function extractFeatures(doc = document) {
    const $$ = (sel) => Array.from(doc.querySelectorAll(sel));
    const low = doc.documentElement.outerHTML.toLowerCase();
    const forms = $$("form");
    const inputs = $$("input");
    const types = inputs.map((i) => attr(i, "type").toLowerCase());
    const actions = forms.map((f) => attr(f, "action").toLowerCase());
    const anchors = $$("a[href]").map((a) => attr(a, "href").toLowerCase());
    const scripts = $$("script");
    const extScripts = scripts.map((s) => attr(s, "src")).filter(Boolean);
    const iframes = $$("iframe");
    const imgs = $$("img[src]").map((i) => attr(i, "src"));
    const rels = $$("link").map((l) => [attr(l, "rel").toLowerCase(), attr(l, "href")]);
    const titleEl = doc.querySelector("title");
    const title = titleEl ? titleEl.textContent.trim() : "";
    const nTags = doc.getElementsByTagName("*").length;
    const invisible = (fr) => {
      const st = attr(fr, "style").toLowerCase().replace(/ /g, "");
      return ["0", "1"].includes(attr(fr, "width")) || ["0", "1"].includes(attr(fr, "height")) ||
        st.includes("display:none") || st.includes("visibility:hidden");
    };
    const absUrls = [...anchors, ...extScripts, ...imgs, ...rels.map((r) => r[1])].filter(isAbs);
    const hosts = new Set(absUrls.map(hostOf));
    hosts.delete("");
    const nA = anchors.length;
    const sum = (arr, fn) => arr.reduce((acc, x) => acc + (fn(x) ? 1 : 0), 0);

    const f = {
      n_forms: forms.length,
      n_inputs: inputs.length,
      n_password: sum(types, (t) => t === "password"),
      n_hidden_inputs: sum(types, (t) => t === "hidden"),
      n_text_inputs: sum(types, (t) => TEXT_TYPES.has(t)),
      form_abs_action: sum(actions, isAbs),
      form_null_action: sum(actions, (a) => ["", "#", "about:blank"].includes(a) || a.startsWith("javascript:")),
      form_php_action: sum(actions, (a) => a.includes(".php")),
      form_mailto: sum(actions, (a) => a.startsWith("mailto:")),
      n_anchors: nA,
      abs_anchor_ratio: nA ? sum(anchors, isAbs) / nA : 0,
      null_anchor_ratio: nA ? sum(anchors, (a) => a.startsWith("#") || a.startsWith("javascript:")) / nA : 0,
      n_scripts: scripts.length,
      n_ext_scripts: extScripts.length,
      n_iframes: iframes.length,
      n_invisible_iframes: sum(iframes, invisible),
      n_imgs: imgs.length,
      abs_img_ratio: imgs.length ? sum(imgs, isAbs) / imgs.length : 0,
      n_css_links: sum(rels, (r) => r[0].includes("stylesheet")),
      favicon_abs: rels.some((r) => r[0].includes("icon") && isAbs(r[1])) ? 1 : 0,
      n_meta_refresh: sum($$("meta"), (m) => attr(m, "http-equiv").toLowerCase() === "refresh"),
      title_len: title.length,
      has_title: title ? 1 : 0,
      log_n_tags: Math.log1p(nTags),
      n_abs_hosts: hosts.size,
      js_obfuscation: count(low, OBF),
      js_redirect: count(low, REDIR),
    };
    for (const [k, rx] of Object.entries(KW)) f[k] = rx.test(low) ? 1 : 0;
    return f;
  }

  globalThis.PhishGraphFeatures = { extractFeatures };
})();
