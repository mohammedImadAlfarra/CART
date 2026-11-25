"""Exploratory data analysis (EDA) of the dataset.

Produces what the course asks for when introducing a dataset:
  * class distribution (normal vs malicious) before and after cleaning
  * number of rows per attack type
  * descriptive statistics (mean, median, mode, std) of the 6 most telling
    features, overall and per class
  * box plots of the same 6 features (normal vs malicious)

Charts go to reports/ml/, the numbers are returned as a dict (saved in metrics.json).
"""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

BLUE, ORANGE = "#2563eb", "#ea580c"
KEY_FEATURES = ["length", "n_specials", "special_ratio", "sql_kw", "entropy", "n_single_quote"]


def _stats(col: pd.Series) -> dict:
    mode = col.mode()
    return {"mean": round(float(col.mean()), 3), "median": round(float(col.median()), 3),
            "mode": round(float(mode.iloc[0]), 3) if len(mode) else None,
            "std": round(float(col.std()), 3)}


def describe(df: pd.DataFrame) -> dict:
    """Descriptive statistics of the key features: overall + mean per class."""
    return {f: {**_stats(df[f]),
                "mean_normal": round(float(df.loc[df.label == 0, f].mean()), 3),
                "mean_malicious": round(float(df.loc[df.label == 1, f].mean()), 3)}
            for f in KEY_FEATURES}


def _bar(ax, labels, values, colors, title):
    bars = ax.bar(labels, values, color=colors)
    total = sum(values)
    for b, v in zip(bars, values):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:,}\n({v / total:.0%})",
                ha="center", va="bottom", fontsize=9)
    ax.set_title(title)
    ax.set_ylim(0, max(values) * 1.25)
    ax.grid(alpha=.3, axis="y")


def plot_class_distribution(raw, clean, path):
    fig, axes = plt.subplots(1, 2, figsize=(9, 4))
    for ax, d, t in [(axes[0], raw, "Before cleaning"), (axes[1], clean, "After cleaning")]:
        _bar(ax, ["normal", "malicious"], [int((d.label == 0).sum()), int((d.label == 1).sum())],
             [BLUE, ORANGE], f"{t} ({len(d):,} rows)")
    fig.suptitle("Class distribution")
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def plot_boxplots(clean, path):
    fig, axes = plt.subplots(2, 3, figsize=(11, 6))
    for ax, f in zip(axes.ravel(), KEY_FEATURES):
        data = [clean.loc[clean.label == 0, f], clean.loc[clean.label == 1, f]]
        bp = ax.boxplot(data, patch_artist=True, showfliers=False)
        ax.set_xticks([1, 2], ["normal", "malicious"])
        for patch, c in zip(bp["boxes"], [BLUE, ORANGE]):
            patch.set_facecolor(c); patch.set_alpha(.6)
        ax.set_title(f)
        ax.grid(alpha=.3, axis="y")
    fig.suptitle("Feature values: normal vs malicious (outliers hidden)")
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def run(raw: pd.DataFrame, clean: pd.DataFrame, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    plot_class_distribution(raw, clean, out_dir / "class_distribution.png")
    plot_boxplots(clean, out_dir / "feature_boxplots.png")
    return {
        "attack_types_clean": {k: int(v) for k, v in clean["attack_type"].value_counts().items()},
        "descriptive_stats": describe(clean),
    }
