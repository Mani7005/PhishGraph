"""Trusted-domain allowlist (fewer false alarms, fewer server calls).

Popular domains (Tranco top 10k) are skipped, EXCEPT hosts where anyone can
publish content (Google Sites/Forms, blogspot, GitHub Pages, cloud storage,
file-sharing, link shorteners...). Phishers abuse exactly those, so they are
always scored by the model.
"""
from __future__ import annotations

import json
from pathlib import Path

from .url_features import FREE_HOSTING, SHORTENERS, split_url

USER_CONTENT_HOSTS = sorted(FREE_HOSTING | SHORTENERS | {
    "docs.google.com", "drive.google.com", "forms.gle", "sites.google.com", "script.google.com",
    "storage.googleapis.com", "firebasestorage.googleapis.com",
    "dropboxusercontent.com", "onedrive.live.com", "1drv.ms", "sharepoint.com",
    "notion.site", "wordpress.com", "githubusercontent.com",
    "gitlab.io", "amazonaws.com", "cloudfront.net", "azureedge.net", "core.windows.net",
    "typeform.com", "jotform.com", "formstack.com", "wufoo.com", "canva.site", "linktr.ee",
    "wetransfer.com", "mediafire.com", "telegra.ph", "pastebin.com", "glitch.com",
    "cloudflare-ipfs.com", "myshopify.com", "webnode.page", "site123.me", "tilda.ws",
})

ALLOWLIST_PATH = Path(__file__).resolve().parents[1] / "models" / "allowlist.json"


def _matches(host: str, domains) -> str | None:
    parts = host.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in domains:
            return cand
    return None


class Allowlist:
    def __init__(self, path: Path = ALLOWLIST_PATH):
        data = json.loads(Path(path).read_text()) if Path(path).exists() else {"trusted": []}
        self.trusted = set(data["trusted"])
        self.user_content = set(USER_CONTENT_HOSTS)

    def check(self, url: str) -> str | None:
        """Return the matching trusted domain, or None if the URL must be scored."""
        _, host, _, _, _ = split_url(url)
        if not host or _matches(host, self.user_content):
            return None
        return _matches(host, self.trusted)
