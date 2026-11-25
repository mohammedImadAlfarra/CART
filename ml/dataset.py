"""Load the real HTTP Params dataset, turn it into features, and clean it.

  dataset/raw/http_params_dataset.csv   (downloaded real dataset, MIT licence)
        |  payload_features.featurize
        v
  dataset/processed/features.csv        (18 numeric features + attack_type + label)
        |  clean()  -> remove duplicates (data-leakage check)
        v
  the table every model is trained and tested on

If the raw file is missing, we try to download it; if the network is blocked,
we fall back to a tiny bundled sample so the pipeline still runs, and say so.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pandas as pd

from .payload_features import FEATURES, featurize

RAW = Path("dataset/raw/http_params_dataset.csv")
PROCESSED = Path("dataset/processed/features.csv")
RAW_URL = "https://raw.githubusercontent.com/Morzeux/HttpParamsDataset/master/payload_full.csv"

# minimal offline fallback so the demo never hard-fails (clearly marked)
_SAMPLE = [
    ("c/ caridad s/n", "norm"), ("campello el", "norm"), ("john.doe@mail.com", "norm"),
    ("12 de octubre", "norm"), ("barcelona 08001", "norm"), ("usuario123", "norm"),
    ("' or '1'='1", "anom"), ("1 UNION SELECT username,password FROM users", "anom"),
    ("<script>alert(1)</script>", "anom"), ("../../etc/passwd", "anom"),
    ("; cat /etc/passwd", "anom"), ("admin'--", "anom"),
]


def ensure_raw() -> tuple[Path, bool]:
    """Returns (path, is_real). is_real=False means the bundled sample is used."""
    if RAW.exists() and RAW.stat().st_size > 10_000:
        return RAW, True
    RAW.parent.mkdir(parents=True, exist_ok=True)
    try:
        import urllib.request
        urllib.request.urlretrieve(RAW_URL, RAW)
        if RAW.stat().st_size > 10_000:
            return RAW, True
    except Exception:
        pass
    with open(RAW, "w", newline="", encoding="utf-8") as f:   # fallback sample
        w = csv.writer(f)
        w.writerow(["payload", "length", "attack_type", "label"])
        for pay, lab in _SAMPLE:
            w.writerow([pay, len(pay), "norm" if lab == "norm" else "sqli", lab])
    return RAW, False


def build_processed() -> tuple[pd.DataFrame, bool]:
    """Read the raw CSV and compute the 18 features for every payload.
    Returns (table, is_real) and also saves the table to dataset/processed/."""
    path, is_real = ensure_raw()
    raw = pd.read_csv(path, dtype={"payload": str}, keep_default_na=False)
    rows = [{"payload": p, "attack_type": t, **featurize(p), "label": 1 if lab == "anom" else 0}
            for p, t, lab in zip(raw["payload"], raw["attack_type"], raw["label"])]
    df = pd.DataFrame(rows)
    PROCESSED.parent.mkdir(parents=True, exist_ok=True)
    df.drop(columns=["payload"]).to_csv(PROCESSED, index=False)
    return df, is_real


def clean(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Data-quality / leakage check.

    The models only see the 18 features, never the raw text. Two different
    payloads can produce exactly the same feature vector (e.g. many short
    Spanish words). If one copy lands in TRAIN and the other in TEST, the test
    set is no longer "unseen" and the score is inflated. So we:
      1. drop exact duplicate payload strings,
      2. drop feature vectors that appear with BOTH labels (contradictory rows),
      3. keep only ONE row per remaining feature vector.
    """
    report = {"rows_raw": int(len(df))}
    d = df.drop_duplicates("payload")
    report["duplicate_payloads"] = int(len(df) - len(d))

    n_labels = d.groupby(FEATURES)["label"].transform("nunique")
    conflict = n_labels > 1
    report["conflicting_rows"] = int(conflict.sum())
    d = d[~conflict]

    before = len(d)
    d = d.drop_duplicates(FEATURES).reset_index(drop=True)
    report["duplicate_feature_rows"] = int(before - len(d))
    report["rows_clean"] = int(len(d))
    report["class_counts_raw"] = {"normal": int((df.label == 0).sum()), "malicious": int((df.label == 1).sum())}
    report["class_counts_clean"] = {"normal": int((d.label == 0).sum()), "malicious": int((d.label == 1).sum())}
    return d, report


def load_clean() -> tuple[pd.DataFrame, pd.DataFrame, dict, bool]:
    """(raw_table, clean_table, quality_report, is_real)"""
    raw, is_real = build_processed()
    cleaned, report = clean(raw)
    return raw, cleaned, report, is_real


if __name__ == "__main__":
    raw, cleaned, rep, real = load_clean()
    print(f"{rep['rows_raw']} raw rows -> {rep['rows_clean']} clean rows "
          f"({'REAL dataset' if real else 'bundled sample fallback'})")
    print(rep)
