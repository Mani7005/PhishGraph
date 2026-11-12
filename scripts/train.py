"""Train, compare and export a model for one modality.

    python scripts/train.py --modality url
    python scripts/train.py --modality content

Steps
1. Hold out a TEST set (20%). For URLs the split is grouped by registered
   domain, so the same site never appears in both train and test.
2. Compare Logistic Regression, Random Forest and XGBoost with 5-fold
   (grouped) cross-validation on a subsample; report mean +/- 95% CI.
3. Tune XGBoost with Optuna (3-fold grouped CV, PR-AUC objective).
4. Fit the tuned model, choose alert thresholds on a validation split
   (target false-positive rates of 1% and 5%), evaluate once on TEST.
5. Save the model, metrics and SHAP plots.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import matplotlib
import numpy as np
import optuna
import pandas as pd
import shap
import xgboost as xgb
from scipy import stats
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, TargetEncoder
from xgboost import XGBClassifier

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phishgraph.content_features import CONTENT_FEATURES  # noqa: E402
from phishgraph.url_features import TLD_FEATURE, URL_NUMERIC_FEATURES  # noqa: E402

SEED = 42
CV_SAMPLE = 100_000
TUNE_SAMPLE = 120_000
N_TRIALS = 20
optuna.logging.set_verbosity(optuna.logging.WARNING)


# ---------------------------------------------------------------- data
def load(modality: str):
    if modality == "url":
        df = pd.read_parquet(ROOT / "data/processed/url_features.parquet")
        num, cat, groups = URL_NUMERIC_FEATURES, [TLD_FEATURE], df["group"].values
    else:
        df = pd.read_parquet(ROOT / "data/processed/content_features.parquet")
        num, cat = CONTENT_FEATURES, []
        groups = df["html_sha1"].values  # already de-duplicated: one group per page
    return df[num + cat], df["label"].values.astype(int), groups, num, cat


def preprocessor(num, cat, scale=False):
    steps = []
    if cat:  # TargetEncoder cross-fits internally, so no label leakage in fit_transform
        steps.append(("tld", TargetEncoder(target_type="binary", random_state=SEED), cat))
    steps.append(("num", StandardScaler() if scale else "passthrough", num))
    return ColumnTransformer(steps, verbose_feature_names_out=False)


def make_models(num, cat, xgb_params=None):
    xgb_params = xgb_params or {}
    return {
        "logistic_regression": Pipeline([("prep", preprocessor(num, cat, scale=True)),
                                          ("clf", LogisticRegression(max_iter=2000, C=1.0))]),
        "random_forest": Pipeline([("prep", preprocessor(num, cat)),
                                   ("clf", RandomForestClassifier(n_estimators=200, min_samples_leaf=2,
                                                                  n_jobs=-1, random_state=SEED))]),
        "xgboost": Pipeline([("prep", preprocessor(num, cat)),
                             ("clf", XGBClassifier(tree_method="hist", n_jobs=6, random_state=SEED,
                                                   eval_metric="logloss", **xgb_params))]),
    }


def metrics(y, p, thr=0.5) -> dict:
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"roc_auc": roc_auc_score(y, p), "pr_auc": average_precision_score(y, p),
            "f1": f1_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred), "fpr": fp / (fp + tn) if fp + tn else 0.0,
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}


def ci95(values):
    v = np.asarray(values)
    half = stats.t.ppf(0.975, len(v) - 1) * v.std(ddof=1) / np.sqrt(len(v))
    return {"mean": float(v.mean()), "ci95": float(half)}


def subsample(X, y, g, n):
    if len(y) <= n:
        return X, y, g
    idx = np.random.default_rng(SEED).choice(len(y), n, replace=False)
    return X.iloc[idx], y[idx], g[idx]


# ---------------------------------------------------------------- steps
def compare_models(X, y, g, num, cat, xgb_params=None, only=None):
    Xs, ys, gs = subsample(X, y, g, CV_SAMPLE)
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    results = {}
    for name, model in make_models(num, cat, xgb_params).items():
        if only and name != only:
            continue
        t0, folds = time.time(), []
        for tr, va in cv.split(Xs, ys, gs):
            model.fit(Xs.iloc[tr], ys[tr])
            folds.append(metrics(ys[va], model.predict_proba(Xs.iloc[va])[:, 1]))
        results[name] = {k: ci95([f[k] for f in folds]) for k in ("roc_auc", "pr_auc", "f1", "precision", "recall")}
        print(f"  {name:20s} PR-AUC {results[name]['pr_auc']['mean']:.4f} "
              f"+/- {results[name]['pr_auc']['ci95']:.4f}  F1 {results[name]['f1']['mean']:.4f}"
              f"  ({time.time() - t0:.0f}s)", flush=True)
    return results


def tune_xgb(X, y, g, num, cat):
    Xs, ys, gs = subsample(X, y, g, TUNE_SAMPLE)
    cv = list(StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=SEED).split(Xs, ys, gs))

    def objective(trial):
        params = {
            "n_estimators": trial.suggest_int("n_estimators", 200, 800, step=100),
            "max_depth": trial.suggest_int("max_depth", 3, 10),
            "learning_rate": trial.suggest_float("learning_rate", 0.03, 0.3, log=True),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
            "reg_lambda": trial.suggest_float("reg_lambda", 1e-3, 10, log=True),
        }
        model = make_models(num, cat, params)["xgboost"]
        scores = []
        for tr, va in cv:
            model.fit(Xs.iloc[tr], ys[tr])
            scores.append(average_precision_score(ys[va], model.predict_proba(Xs.iloc[va])[:, 1]))
        return float(np.mean(scores))

    study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=SEED))
    study.optimize(objective, n_trials=N_TRIALS, show_progress_bar=False)
    print(f"  best CV PR-AUC {study.best_value:.4f} with {study.best_params}", flush=True)
    return study.best_params, study.best_value


def threshold_at_fpr(y, p, target_fpr):
    fpr, _, thr = roc_curve(y, p)
    ok = np.where(fpr <= target_fpr)[0]
    return float(min(1.0, thr[ok[-1]]))


def shap_plots(model, X_test, modality, out_dir):
    prep, clf = model.named_steps["prep"], model.named_steps["clf"]
    Xs = X_test.sample(min(3000, len(X_test)), random_state=SEED)
    Xt = pd.DataFrame(prep.transform(Xs), columns=prep.get_feature_names_out())
    # XGBoost's built-in exact TreeSHAP (same algorithm as shap.TreeExplainer;
    # used because shap 0.49 cannot parse XGBoost 3.x models). Last column = bias.
    sv = clf.get_booster().predict(xgb.DMatrix(Xt), pred_contribs=True)[:, :-1]
    for kind in ("bar", "dot"):
        plt.figure()
        shap.summary_plot(sv, Xt, plot_type=kind, show=False, max_display=20)
        plt.title(f"SHAP ({modality} model)")
        plt.tight_layout()
        plt.savefig(out_dir / f"shap_{modality}_{kind}.png", dpi=130)
        plt.close("all")
    imp = pd.Series(np.abs(sv).mean(0), index=Xt.columns).sort_values(ascending=False)
    return imp.head(15).round(4).to_dict()


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--modality", choices=["url", "content"], required=True)
    args = ap.parse_args()
    m = args.modality
    (ROOT / "models").mkdir(exist_ok=True)
    (ROOT / "reports").mkdir(exist_ok=True)

    X, y, g, num, cat = load(m)
    print(f"[{m}] rows {len(y)}, phishing share {y.mean():.3f}", flush=True)

    # 1. held-out test set (grouped) and a validation set for thresholds
    tr_idx, te_idx = next(GroupShuffleSplit(1, test_size=0.2, random_state=SEED).split(X, y, g))
    Xtr, ytr, gtr = X.iloc[tr_idx], y[tr_idx], g[tr_idx]
    Xte, yte = X.iloc[te_idx], y[te_idx]
    fit_idx, val_idx = next(GroupShuffleSplit(1, test_size=0.1, random_state=SEED).split(Xtr, ytr, gtr))

    print("[1/4] 5-fold CV model comparison (default hyper-parameters)", flush=True)
    cv_default = compare_models(Xtr, ytr, gtr, num, cat)

    print("[2/4] Optuna tuning of XGBoost", flush=True)
    best_params, best_cv = tune_xgb(Xtr, ytr, gtr, num, cat)
    cv_tuned = compare_models(Xtr, ytr, gtr, num, cat, best_params, only="xgboost")["xgboost"]
    print(f"  tuned xgboost PR-AUC {cv_tuned['pr_auc']['mean']:.4f} +/- {cv_tuned['pr_auc']['ci95']:.4f}")

    print("[3/4] final fit + thresholds + test evaluation", flush=True)
    model = make_models(num, cat, best_params)["xgboost"]
    model.fit(Xtr.iloc[fit_idx], ytr[fit_idx])
    p_val = model.predict_proba(Xtr.iloc[val_idx])[:, 1]
    thresholds = {"warn": threshold_at_fpr(ytr[val_idx], p_val, 0.01),
                  "suspicious": threshold_at_fpr(ytr[val_idx], p_val, 0.05)}
    p_te = model.predict_proba(Xte)[:, 1]
    test = {"at_0.5": metrics(yte, p_te, 0.5),
            "at_warn": metrics(yte, p_te, thresholds["warn"]),
            "at_suspicious": metrics(yte, p_te, thresholds["suspicious"])}
    print(f"  TEST PR-AUC {test['at_0.5']['pr_auc']:.4f} ROC-AUC {test['at_0.5']['roc_auc']:.4f} | "
          f"warn thr {thresholds['warn']:.3f}: recall {test['at_warn']['recall']:.3f} "
          f"FPR {test['at_warn']['fpr']:.4f}", flush=True)

    # simple baseline on the same test set, for the report
    lr = make_models(num, cat)["logistic_regression"].fit(*subsample(Xtr, ytr, gtr, 200_000)[:2])
    test["logistic_regression_baseline"] = metrics(yte, lr.predict_proba(Xte)[:, 1])

    print("[4/4] SHAP", flush=True)
    top = shap_plots(model, Xte, m, ROOT / "reports")

    report = {"modality": m, "n_rows": int(len(y)), "phishing_share": float(y.mean()),
              "n_train": int(len(fit_idx)), "n_val": int(len(val_idx)), "n_test": int(len(te_idx)),
              "cv_default": cv_default, "optuna_best_params": best_params,
              "optuna_best_cv_pr_auc": best_cv, "cv_xgboost_tuned": cv_tuned,
              "thresholds": thresholds, "test": test, "shap_top_features": top}
    (ROOT / "reports" / f"metrics_{m}.json").write_text(json.dumps(report, indent=2))
    joblib.dump({"pipeline": model, "numeric": num, "categorical": cat,
                 "feature_names": list(model.named_steps["prep"].get_feature_names_out()),
                 "thresholds": thresholds}, ROOT / "models" / f"{m}_model.joblib")
    print("saved models/%s_model.joblib and reports/metrics_%s.json" % (m, m))


if __name__ == "__main__":
    main()
