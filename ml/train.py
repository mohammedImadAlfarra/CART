"""The ML experiment: compare 3 algorithms for detecting malicious HTTP parameters.

Research question:
  Can supervised ML models detect malicious HTTP request parameters
  (SQL injection, XSS, command injection, path traversal), and which of
  Logistic Regression, SVM and Random Forest performs best?

Steps (all with seed 42, so every run gives the same numbers):
  1. dataset   -> 18 features per payload               (ml/dataset.py)
  2. cleaning  -> remove duplicates (data-leakage check) (ml/dataset.py)
  3. EDA       -> class balance, descriptive stats, charts (ml/eda.py)
  4. split     -> stratified 70% train / 30% test
  5. for each model (ml/models.py):
       a. DEFAULT hyperparameters -> test metrics
       b. GridSearchCV (5-fold, F1) on the TRAIN set -> best hyperparameters
       c. 5-fold cross-validation of the tuned model on TRAIN (mean +/- std)
       d. tuned model -> test metrics: Accuracy, Precision, Recall, F1, ROC-AUC
  6. choose the best model by CROSS-VALIDATION F1 (not by the test set)
  7. charts: model comparison, ROC curves, confusion matrix
  8. save the best model -> models/request_classifier/model.joblib

Run:  python -m ml.train     (or  python run.py --ml-only)
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_validate, train_test_split

from ml import eda
from ml.dataset import load_clean
from ml.models import MODELS, SEED
from ml.payload_features import FEATURES

OUT = Path("models/request_classifier")      # model + metrics.json
CHARTS = Path("reports/ml")                  # all charts (shown in report.html)
METRICS = ["accuracy", "precision", "recall", "f1", "roc_auc"]
COLORS = {"logistic_regression": "#64748b", "svm": "#ea580c", "random_forest": "#2563eb"}


# ------------------------------------------------------------------ helpers
def _scores(model, X):
    """Continuous score for ROC-AUC: probability if the model has one, else the SVM margin."""
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    return model.decision_function(X)


def evaluate(model, X, y) -> dict:
    pred = model.predict(X)
    cm = confusion_matrix(y, pred, labels=[0, 1])
    return {
        "accuracy": round(float(accuracy_score(y, pred)), 4),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y, _scores(model, X))), 4),
        "confusion_matrix": {"tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
                             "fn": int(cm[1, 0]), "tp": int(cm[1, 1])},
    }


def _cv(model, X, y, skf) -> dict:
    cv = cross_validate(model, X, y, cv=skf, scoring=METRICS, n_jobs=-1)
    return {m: {"mean": round(float(cv[f"test_{m}"].mean()), 4),
                "std": round(float(cv[f"test_{m}"].std()), 4)} for m in METRICS}


# values that cannot be pushed any further (no depth limit / smallest possible leaf)
NATURAL_LIMITS = {"max_depth": None, "min_samples_leaf": 1}


def edge_check(grid: dict, best_params: dict) -> dict:
    """Is a chosen hyperparameter the smallest or largest number we searched?
    If yes, the true best might lie outside the range and the grid should grow."""
    at_edge, natural = [], []
    for key, values in grid.items():
        name, best = key.replace("clf__", ""), best_params[key]
        if name in NATURAL_LIMITS and best == NATURAL_LIMITS[name]:
            natural.append(name)
            continue
        nums = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
        if isinstance(best, (int, float)) and len(nums) > 2 and best in (min(nums), max(nums)):
            at_edge.append(name)
    return {"at_edge": at_edge, "natural_limit": natural}


def run_model(key, X_tr, y_tr, X_te, y_te, skf) -> tuple[dict, object]:
    spec = MODELS[key]

    # a) default hyperparameters
    default = spec["build"]()
    default.fit(X_tr, y_tr)
    default_test = evaluate(default, X_te, y_te)

    # b) hyperparameter search on the TRAIN set only
    t0 = time.time()
    search = GridSearchCV(spec["build"](), spec["grid"], scoring="f1", cv=skf, n_jobs=-1)
    search.fit(X_tr, y_tr)
    search_s = round(time.time() - t0, 1)
    best = search.best_estimator_
    best_params = {k.replace("clf__", ""): v for k, v in search.best_params_.items()}

    # c) cross-validation of the tuned model (TRAIN set)
    cv = _cv(spec["build"]().set_params(**search.best_params_), X_tr, y_tr, skf)

    # d) final test-set evaluation
    t0 = time.time()
    tuned = spec["build"]().set_params(**search.best_params_).fit(X_tr, y_tr)
    fit_s = round(time.time() - t0, 2)
    test = evaluate(tuned, X_te, y_te)

    result = {
        "label": spec["label"], "why": spec["why"],
        "search_space": {k.replace("clf__", ""): [str(v) for v in vals] for k, vals in spec["grid"].items()},
        "combinations_tried": int(len(search.cv_results_["params"])),
        "best_params": {k: (str(v) if v is None else v) for k, v in best_params.items()},
        "edge_check": edge_check(spec["grid"], search.best_params_),
        "param_notes": spec["params"],
        "search_seconds": search_s, "fit_seconds": fit_s,
        "default_test": default_test,
        "cv": cv,
        "test": test,
    }
    return result, tuned


# ------------------------------------------------------------------ charts
def plot_comparison(results, path):
    keys = list(results)
    x = np.arange(len(METRICS))
    w = 0.8 / len(keys)
    fig, ax = plt.subplots(figsize=(9, 4.5))
    for i, k in enumerate(keys):
        vals = [results[k]["test"][m] for m in METRICS]
        ax.bar(x + i * w - 0.4 + w / 2, vals, w, label=results[k]["label"], color=COLORS[k])
    lo = min(results[k]["test"][m] for k in keys for m in METRICS)
    ax.set_ylim(max(0.0, round(lo - 0.01, 2)), 1.0)
    ax.set_xticks(x, ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"])
    ax.set_title(f"Model comparison on the test set (y-axis starts at {ax.get_ylim()[0]:.2f})")
    ax.legend(loc="lower right"); ax.grid(alpha=.3, axis="y")
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def plot_roc(models, X_te, y_te, results, path):
    fig, (ax, zoom) = plt.subplots(1, 2, figsize=(11, 4.8))
    for k, m in models.items():
        fpr, tpr, _ = roc_curve(y_te, _scores(m, X_te))
        lab = f"{results[k]['label']} (AUC = {results[k]['test']['roc_auc']:.4f})"
        ax.plot(fpr, tpr, color=COLORS[k], lw=2, label=lab)
        zoom.plot(fpr, tpr, color=COLORS[k], lw=2, label=lab)
    ax.plot([0, 1], [0, 1], "--", color="#94a3b8", label="random guess (AUC = 0.5)")
    ax.set_xlabel("False positive rate"); ax.set_ylabel("True positive rate (recall)")
    ax.set_title("ROC curves (test set)")
    ax.legend(loc="lower right", fontsize=8); ax.grid(alpha=.3)
    zoom.set_xlim(0, 0.05); zoom.set_ylim(0.95, 1.001)
    zoom.set_xlabel("False positive rate"); zoom.set_title("Zoom: top-left corner")
    zoom.legend(loc="lower right", fontsize=8); zoom.grid(alpha=.3)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def plot_confusion(cm, label, path):
    m = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    fig, ax = plt.subplots(figsize=(4.4, 4))
    ax.imshow(m, cmap="Blues")
    ax.set_xticks([0, 1], ["normal", "malicious"]); ax.set_yticks([0, 1], ["normal", "malicious"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    ax.set_title(f"Confusion matrix - {label}")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{int(m[i, j]):,}", ha="center", va="center", fontsize=13, fontweight="bold",
                    color="white" if m[i, j] > m.max() / 2 else "#0f172a")
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


# ------------------------------------------------------------------ main experiment
def train(seed=SEED) -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    CHARTS.mkdir(parents=True, exist_ok=True)

    raw, clean, quality, is_real = load_clean()
    eda_info = eda.run(raw, clean, CHARTS)

    X, y = clean[FEATURES].to_numpy(dtype=float), clean["label"].to_numpy()
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, random_state=seed, stratify=y)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)

    results, fitted = {}, {}
    for key in MODELS:
        print(f"      - {MODELS[key]['label']}: grid search + cross-validation ...")
        results[key], fitted[key] = run_model(key, X_tr, y_tr, X_te, y_te, skf)

    # choose by cross-validation F1 (then ROC-AUC) -> the test set stays untouched by the choice
    best_key = max(results, key=lambda k: (results[k]["cv"]["f1"]["mean"], results[k]["cv"]["roc_auc"]["mean"]))
    best = results[best_key]

    plot_comparison(results, CHARTS / "model_comparison.png")
    plot_roc(fitted, X_te, y_te, results, CHARTS / "roc_curves.png")
    plot_confusion(best["test"]["confusion_matrix"], best["label"], CHARTS / "confusion_matrix.png")

    metrics = {
        "research_question": ("Can supervised machine-learning models detect malicious HTTP request "
                              "parameters (SQLi, XSS, command injection, path traversal), and which of "
                              "Logistic Regression, SVM and Random Forest performs best?"),
        "dataset": "HTTP Params Dataset (Morzeux) - benign values from CSIC 2010; MIT licence",
        "dataset_url": "https://github.com/Morzeux/HttpParamsDataset",
        "is_real_dataset": bool(is_real),
        "features": FEATURES,
        "data_quality": quality,
        "eda": eda_info,
        "split": {"train": int(len(X_tr)), "test": int(len(X_te)), "test_fraction": 0.3,
                  "stratified": True, "seed": seed, "cv_folds": 5},
        "models": results,
        "best_model": best_key,
        "best_model_label": best["label"],
        "selection_rule": "highest 5-fold cross-validation F1 on the training set (tie-break: ROC-AUC)",
    }

    import joblib
    joblib.dump({"clf": fitted[best_key], "features": FEATURES, "name": best["label"]}, OUT / "model.joblib")
    (OUT / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def main():
    m = train()
    q = m["data_quality"]
    print("=" * 72)
    print("  ML experiment: malicious HTTP-parameter detection (real dataset)")
    print("=" * 72)
    print(f"  Dataset : {m['dataset']}  ({'REAL' if m['is_real_dataset'] else 'SAMPLE fallback'})")
    print(f"  Cleaning: {q['rows_raw']:,} rows -> {q['rows_clean']:,} rows "
          f"(removed {q['duplicate_feature_rows']:,} duplicate feature rows, "
          f"{q['conflicting_rows']} contradictory rows)")
    print(f"  Classes : normal {q['class_counts_clean']['normal']:,} / "
          f"malicious {q['class_counts_clean']['malicious']:,}")
    print(f"  Split   : train {m['split']['train']:,} / test {m['split']['test']:,}  (stratified, seed 42)")
    print("-" * 72)
    print(f"  {'Model':22} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7} {'AUC':>7} {'CV-F1':>15}")
    for k, r in m["models"].items():
        t, cv = r["test"], r["cv"]["f1"]
        print(f"  {r['label']:22} {t['accuracy']:7.4f} {t['precision']:7.4f} {t['recall']:7.4f} "
              f"{t['f1']:7.4f} {t['roc_auc']:7.4f}  {cv['mean']:.4f}±{cv['std']:.4f}")
    print("-" * 72)
    for k, r in m["models"].items():
        edge = r["edge_check"]["at_edge"]
        where = f"AT EDGE: {edge}" if edge else "inside searched range"
        print(f"  {r['label']:22} best params: {r['best_params']}  ({where})")
    print("-" * 72)
    print(f"  BEST MODEL: {m['best_model_label']}  (chosen by {m['selection_rule']})")
    print(f"  Saved -> {OUT}/model.joblib + metrics.json, charts -> {CHARTS}/")
    print("=" * 72)


if __name__ == "__main__":
    main()
