"""Write models/allowlist.json and extension/allowlist.json from Tranco top 10k."""
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phishgraph.allowlist import USER_CONTENT_HOSTS, _matches  # noqa: E402

TOP_N = 10_000

with zipfile.ZipFile(ROOT / "data/raw/tranco/top-1m.csv.zip") as z:
    lines = z.read("top-1m.csv").decode().splitlines()[:TOP_N]
user = set(USER_CONTENT_HOSTS)
trusted = sorted({l.split(",", 1)[1].lower() for l in lines} - user)
trusted = [d for d in trusted if not _matches(d, user)]
data = {"source": f"Tranco top {TOP_N}", "trusted": trusted, "user_content": sorted(user)}
for out in (ROOT / "models/allowlist.json", ROOT / "extension/allowlist.json"):
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, separators=(",", ":")))
print(f"trusted {len(trusted)}, user-content exclusions {len(user)}")
