"""The three algorithms we compare, their hyperparameters, and WHY.

Every model is a scikit-learn Pipeline with a final step called "clf", so the
search grids all use the same "clf__<param>" naming.

  * Logistic Regression - simple linear baseline
  * SVM (RBF kernel)    - classic for web-attack detection, non-linear boundary
  * Random Forest       - ensemble of decision trees, non-linear, explainable
"""
from __future__ import annotations

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

SEED = 42

MODELS = {
    "logistic_regression": {
        "label": "Logistic Regression",
        "why": "Simplest linear classifier: the baseline every other model must beat. Fast, and its "
               "weights are easy to interpret.",
        "build": lambda: Pipeline([("scale", StandardScaler()),
                                   ("clf", LogisticRegression(max_iter=2000, random_state=SEED))]),
        "grid": {"clf__C": [0.01, 0.1, 1, 10, 100, 1000, 10000, 100000],
                 "clf__class_weight": [None, "balanced"]},
        "params": {
            "C": "Inverse regularisation strength. Small C = simpler model (less over-fitting), "
                 "large C = fits the training data more closely. Searched 0.01 to 100,000.",
            "class_weight": "'balanced' gives the smaller class more weight. Tested because the "
                            "cleaned data is 72% malicious / 28% normal.",
            "max_iter": "2000 (fixed) so the optimiser always converges.",
            "StandardScaler": "Features are scaled to mean 0 / std 1 first, because length (~100) "
                              "and ratios (0-1) live on very different scales.",
        },
    },
    "svm": {
        "label": "SVM (RBF kernel)",
        "why": "Support Vector Machines are among the most used algorithms in web-attack detection "
               "papers. The RBF kernel draws a non-linear boundary between normal and malicious.",
        "build": lambda: Pipeline([("scale", StandardScaler()),
                                   ("clf", SVC(kernel="rbf", random_state=SEED))]),
        "grid": {"clf__C": [0.1, 1, 10, 100, 1000],
                 "clf__gamma": ["scale", 0.01, 0.1, 1, 10]},
        "params": {
            "kernel": "'rbf' (fixed): allows a curved decision boundary.",
            "C": "Penalty for misclassified training points. Large C = fewer training errors but a "
                 "risk of over-fitting. Searched 0.1 to 1000.",
            "gamma": "How far the influence of one training point reaches. 'scale' = 1/(n_features*var). "
                     "Searched 'scale', 0.01, 0.1, 1, 10.",
            "StandardScaler": "Required: SVM uses distances, so unscaled features would dominate.",
        },
    },
    "random_forest": {
        "label": "Random Forest",
        "why": "Many decision trees vote together. Handles non-linear patterns, needs no scaling "
               "and resists over-fitting.",
        "build": lambda: Pipeline([("clf", RandomForestClassifier(random_state=SEED, n_jobs=1))]),
        "grid": {"clf__n_estimators": [100, 200, 400],
                 "clf__max_depth": [8, 16, None],
                 "clf__min_samples_leaf": [1, 3]},
        "params": {
            "n_estimators": "Number of trees. More trees = more stable votes, slower. Searched 100/200/400.",
            "max_depth": "Maximum depth of each tree. Limits how specific a tree can get "
                         "(None = no limit, the natural upper end). Searched 8/16/None.",
            "min_samples_leaf": "Minimum rows in a leaf (1 is the smallest possible). 3 smooths the trees "
                                "and reduces over-fitting. Searched 1/3.",
            "scaling": "Not needed: trees split on thresholds, so feature scale does not matter.",
        },
    },
}
