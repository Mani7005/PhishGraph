"""Fit and evaluate logistic fusion using independently labeled paired examples."""

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score

from phishgraph.content_features import CONTENT_FEATURES
from phishgraph.predictor import MODELS, W_CONTENT, W_URL, Predictor, _logit, _sigmoid
from phishgraph.url_features import registered_domain

SPLITS = ("train", "validation", "test")


def load_pairs(path):
    groups = {}
    splits = {name: [] for name in SPLITS}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        url, label, content, split = (row[key] for key in ("url", "label", "content", "split"))
        domain = registered_domain(url)
        if split not in splits or label not in (0, 1) or not domain:
            raise ValueError(f"Invalid split, label or URL on line {line_number}")
        if set(content) != set(CONTENT_FEATURES) or not np.isfinite(list(content.values())).all():
            raise ValueError(f"Expected all finite page features on line {line_number}")
        if groups.setdefault(domain, split) != split:
            raise ValueError(f"Domain {domain} occurs in multiple splits")
        splits[split].append((url, label, content))
    return splits


def threshold(labels, scores, target):
    negatives = np.sort(scores[labels == 0])[::-1]
    allowed = int(target * len(negatives))
    return float(np.nextafter(negatives[allowed], np.inf))


def evaluate(labels, scores, cutoff):
    flagged = scores >= cutoff
    return {
        "pr_auc": float(average_precision_score(labels, scores)),
        "recall": float(flagged[labels == 1].mean()),
        "false_positive_rate": float(flagged[labels == 0].mean()),
    }


def score_split(predictor, rows, split):
    labels, logits = [], []
    for url, label, content in rows:
        result = predictor.predict(url, content, round_scores=False)
        if result["verdict"] == "trusted":
            continue
        labels.append(label)
        logits.append([_logit(result[key]) for key in ("url_probability", "content_probability")])
    if set(labels) != {0, 1}:
        raise ValueError(f"The {split} split needs both classes after the allowlist is applied")
    return np.array(labels), np.array(logits)


def scores(model, logits):
    url, page = logits.T
    url_weight, page_weight = model.coef_[0]
    combined = {
        "url_only": url,
        "page_only": page,
        "fixed": W_URL * url + W_CONTENT * page,
        "learned": model.intercept_[0] + url_weight * url + page_weight * page,
    }
    return {name: np.array([_sigmoid(value) for value in values]) for name, values in combined.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pairs", type=Path)
    parser.add_argument("--models-dir", type=Path, default=MODELS)
    parser.add_argument("--output", type=Path, help="Defaults to fusion_model.json in --models-dir")
    parser.add_argument("--report", type=Path, default=MODELS.parent / "reports" / "metrics_fusion.json")
    args = parser.parse_args()

    pairs = load_pairs(args.pairs)
    predictor = Predictor(args.models_dir)
    if predictor.content_model is None:
        raise ValueError("Fusion training requires both base models")
    train_y, train_x = score_split(predictor, pairs["train"], "train")
    validation_y, validation_x = score_split(predictor, pairs["validation"], "validation")
    test_y, test_x = score_split(predictor, pairs["test"], "test")

    model = LogisticRegression().fit(train_x, train_y)
    validation = scores(model, validation_x)
    test = scores(model, test_x)
    warn = {name: threshold(validation_y, values, 0.01) for name, values in validation.items()}
    report = {
        "rows": {"train": len(train_y), "validation": len(validation_y), "test": len(test_y)},
        "validation_negatives": int((validation_y == 0).sum()),
        "target_warning_fpr": 0.01,
        "test_at_warning": {name: evaluate(test_y, values, warn[name]) for name, values in test.items()},
    }
    artifact = {
        "weights": dict(zip(("url", "content"), model.coef_[0].tolist())),
        "intercept": float(model.intercept_[0]),
        "thresholds": {
            "warn": warn["learned"],
            "suspicious": threshold(validation_y, validation["learned"], 0.05),
        },
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    output = args.output or args.models_dir / "fusion_model.json"
    output.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
