"""Stream the HTML dataset from Hugging Face and keep only numeric features.

Raw phishing HTML is never written to disk: antivirus software (correctly)
flags it, and we don't need it after feature extraction.

Usage:  python scripts/build_content_dataset.py
Output: data/processed/content_features.parquet
"""
import hashlib
import sys
from multiprocessing import Pool
from pathlib import Path

import ijson
import pandas as pd
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phishgraph.content_features import extract_content_features  # noqa: E402

URL = "https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/webs.json"
OUT = Path(__file__).resolve().parents[1] / "data" / "processed" / "content_features.parquet"


def _records():
    with requests.get(URL, stream=True, timeout=120) as r:
        r.raise_for_status()
        r.raw.decode_content = True
        for obj in ijson.items(r.raw, "item"):
            yield obj["text"], int(obj["label"])


def _work(rec):
    html, label = rec
    feats = extract_content_features(html)
    feats["label"] = label
    # hash lets us drop exact-duplicate pages without storing them
    feats["html_sha1"] = hashlib.sha1(html.encode("utf-8", "ignore")).hexdigest()
    return feats


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    parts, batch, n = [], [], 0
    # Fixed-size batches keep memory bounded (Pool.imap would read the whole
    # 465 MB stream ahead of the workers). 4 workers fits in 8 GB RAM.
    with Pool(4) as pool:
        for rec in _records():
            batch.append(rec)
            if len(batch) == 1000:
                parts.append(pd.DataFrame(pool.map(_work, batch, chunksize=25)))
                n += len(batch)
                batch = []
                print(f"{n} pages processed", flush=True)
        if batch:
            parts.append(pd.DataFrame(pool.map(_work, batch, chunksize=25)))
    df = pd.concat(parts, ignore_index=True)
    before = len(df)
    df = df.drop_duplicates("html_sha1")
    print(f"total {before}, after dedup {len(df)}; labels: {df.label.value_counts().to_dict()}")
    df.to_parquet(OUT, index=False)
    print("saved", OUT)


if __name__ == "__main__":
    main()
