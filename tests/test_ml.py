"""Tests for the ML part: features, data cleaning, model definitions, training.

Run:  pytest -q tests/test_ml.py
"""
from __future__ import annotations

import pandas as pd
import pytest

from ml.dataset import clean
from ml.models import MODELS
from ml.payload_features import FEATURES, featurize, vector


def test_featurize_flags_sql_injection():
    f = featurize("' OR 1=1 --")
    assert f["sql_kw"] >= 1 and f["n_single_quote"] >= 1


def test_featurize_flags_xss():
    assert featurize("<script>alert(1)</script>")["xss_kw"] >= 1


def test_featurize_flags_traversal():
    assert featurize("../../etc/passwd")["traversal"] >= 1


def test_benign_payload_is_calm():
    f = featurize("barcelona 08001")
    assert f["sql_kw"] == 0 and f["xss_kw"] == 0 and f["traversal"] == 0


def test_vector_matches_feature_count():
    assert len(vector("test")) == len(FEATURES) == 18


def _row(payload, label):
    return {"payload": payload, "attack_type": "x", **featurize(payload), "label": label}


def test_clean_removes_duplicate_feature_vectors():
    # "abc" and "xyz" have identical features -> only one may stay
    df = pd.DataFrame([_row("abc", 0), _row("xyz", 0), _row("' OR 1=1 --", 1)])
    out, rep = clean(df)
    assert len(out) == 2 and rep["duplicate_feature_rows"] == 1


def test_clean_removes_contradictory_rows():
    # same features, different labels -> both removed
    df = pd.DataFrame([_row("abc", 0), _row("xyz", 1), _row("' OR 1=1 --", 1)])
    out, rep = clean(df)
    assert len(out) == 1 and rep["conflicting_rows"] == 2


def test_three_models_with_grids():
    assert set(MODELS) == {"logistic_regression", "svm", "random_forest"}
    for spec in MODELS.values():
        assert spec["grid"] and spec["why"] and spec["params"]
        spec["build"]().set_params(**{k: v[0] for k, v in spec["grid"].items()})


def test_edge_check():
    from ml.train import edge_check
    grid = {"clf__C": [1, 10, 100], "clf__min_samples_leaf": [1, 3]}
    assert edge_check(grid, {"clf__C": 10, "clf__min_samples_leaf": 1}) == \
        {"at_edge": [], "natural_limit": ["min_samples_leaf"]}
    assert edge_check(grid, {"clf__C": 100, "clf__min_samples_leaf": 3})["at_edge"] == ["C"]


def test_detector_flags_sql_injection():
    from ml.detector import PayloadDetector
    det = PayloadDetector.load()
    if not det.ready:
        pytest.skip("model not trained yet")
    assert det.verdict("' OR 1=1 --")["malicious"] is True
    assert det.verdict("barcelona")["malicious"] is False


@pytest.mark.slow
def test_full_experiment():
    from ml.train import train
    m = train()
    assert m["best_model"] in MODELS
    for r in m["models"].values():
        assert r["test"]["f1"] >= 0.9
        assert 0.5 < r["test"]["roc_auc"] <= 1.0
    assert m["data_quality"]["rows_clean"] < m["data_quality"]["rows_raw"]
