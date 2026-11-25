# CART-ML — Detecting Malicious HTTP Requests with Machine Learning

A machine-learning study that compares **Logistic Regression**, **SVM** and **Random Forest** for detecting malicious HTTP request parameters (SQL injection, XSS, command injection, path traversal) on a **real public dataset**, plus a small **security scanner** that attacks a local lab with the same attack families, as a practical application.

## Research question

> Can supervised machine-learning models detect malicious HTTP request parameters (SQLi, XSS, command injection, path traversal), and which of Logistic Regression, SVM and Random Forest performs best?

---

## 1. Dataset

| | |
|---|---|
| **Name** | [HTTP Params Dataset](https://github.com/Morzeux/HttpParamsDataset) (Morzeux), MIT licence |
| **Normal values** | from the **HTTP DATASET CSIC 2010** |
| **Attack values** | SQL injection, XSS, command injection, path traversal |
| **Raw size** | 31,067 rows · normal 19,304 / malicious 11,763 |
| **Features** | 18 numeric features per value (length, digits, letters, special characters, quotes, `<>`, `=`, `%`, `;`, SQL / XSS / command keywords, traversal patterns, entropy, non-ASCII) — see `ml/payload_features.py` |

### Data cleaning (leakage check)

The models only see the 18 features. Different payloads can produce the **same feature vector**; if one copy lands in the training set and another in the test set, the test is not on unseen data and the score is inflated. So, **before splitting**:

| Step | Rows |
|------|-----:|
| Raw dataset | 31,067 |
| Duplicate payload strings removed | 0 |
| Contradictory rows removed (same features, both labels) | 34 |
| Duplicate feature vectors removed | 15,119 |
| **Clean dataset used by every model** | **15,914** (normal 4,470 / malicious 11,444) |

Attack types after cleaning: SQLi 10,569 · normal 4,470 · XSS 529 · path traversal 273 · command injection 73.

The analysis also produces descriptive statistics (mean, median, mode, std, and the mean per class) of the 6 most telling features, a class-distribution chart and box plots (`ml/eda.py`).

---

## 2. Method

1. Stratified **70% train / 30% test** split (11,139 / 4,775), seed 42.
2. For each algorithm (`ml/models.py`):
   - train with **default** hyperparameters → test score;
   - **GridSearchCV** (5-fold, F1) on the **training set only** → best hyperparameters;
   - **5-fold cross-validation** of the tuned model (mean ± std);
   - final test-set evaluation: **Accuracy, Precision, Recall, F1, ROC-AUC**.
3. The final model is chosen by **cross-validation F1** (not by the test score), so the test set stays a fair judge.

| Model | Why | Hyperparameters searched | Best |
|-------|-----|--------------------------|------|
| Logistic Regression | Linear baseline, fast, interpretable | `C` 0.01–100,000, `class_weight` None/balanced | `C=10000`, `class_weight=None` |
| SVM (RBF kernel) | Widely used in web-attack detection, non-linear boundary | `C` 0.1–1000, `gamma` scale/0.01/0.1/1/10 | `C=100`, `gamma=1` |
| Random Forest | Tree ensemble, non-linear, no scaling needed | `n_estimators` 100/200/400, `max_depth` 8/16/None, `min_samples_leaf` 1/3 | `200`, `None`, `1` |

Every best value lies **inside** the searched range (Random Forest's `max_depth=None` and `min_samples_leaf=1` are natural limits that cannot go further), so the search range was wide enough. Logistic Regression and SVM use `StandardScaler` (they depend on feature scale); Random Forest does not need it.

---

## 3. Results (test set, tuned models)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | CV F1 (train) | Fit time |
|-------|:--------:|:---------:|:------:|:--:|:-------:|:-------------:|:--------:|
| Logistic Regression | 0.9962 | 0.9991 | 0.9956 | 0.9974 | 0.9998 | 0.9976 ± 0.0006 | 0.03 s |
| **SVM (RBF kernel)** ★ | **0.9977** | 0.9994 | **0.9974** | **0.9984** | 0.9988 | **0.9984 ± 0.0005** | 0.74 s |
| Random Forest | 0.9966 | 0.9994 | 0.9959 | 0.9977 | 0.9996 | 0.9972 ± 0.0005 | 0.70 s |

★ Selected model: **SVM**, highest cross-validation F1 (chosen on the training set, not the test set). It is also the best on the test set: 2 false positives and 9 false negatives out of 4,775 rows. Logistic Regression is the fastest to train with almost the same score.

Tuning helped: test F1 default → tuned: Logistic Regression 0.9952 → 0.9974, SVM 0.9955 → 0.9984, Random Forest 0.9977 → 0.9977 (its defaults were already near-optimal).

**Answer to the research question:** yes — all three models detect malicious parameters with test F1 between 0.9974 and 0.9984 and ROC-AUC ≥ 0.9988. SVM performs best, but the three are very close (differences ≈ one to two standard deviations), so the features matter more than the choice of algorithm.

Charts (in `reports/ml/` and in the report): class distribution, feature box plots, model comparison, ROC curves, confusion matrix.

### Limitations

- The three models are very close; the ranking could change with a different split.
- The dataset is an easy benchmark (attacks differ sharply from normal values), so results on real traffic would be lower.
- Attack types are imbalanced (SQLi 10,569 vs command injection 73).
- Hand-made features: a new attack style that does not use these signs may be missed.

**Future work:** learn features from the raw text (e.g. TF-IDF of character n-grams) and compare with the hand-made ones; use the trained model as an ML firewall (WAF) in front of the lab websites.

---

## 4. Application: security scanner

As a practical application, a small rule-based scanner attacks 4 local websites with the same attack families (SQL injection, XSS, path traversal):

| Website | Port | Vulnerabilities |
|---------|:----:|-----------------|
| **MicroBank** | 5001 | SQL injection on `/login` (authentication bypass) and `/accounts` |
| **DevBlog** | 5002 | Reflected XSS on `/search` and `/comment` |
| **CloudFiles** | 5003 | Path traversal on `/download` |
| **SecureCorp** | 5004 | None — control site for false positives |

Pipeline per website: **Recon → Plan → Discover → Prove → Remediate → Retest**. A vulnerability is reported only after a harmless **proof** (canary), then the fix is switched on and the same proof is re-run.

| Scanner result | Value |
|----------------|:-----:|
| Proven vulnerabilities | 4 |
| Precision | 1.0 |
| Recall | 0.8 (missed `/comment`: no page links to it, and recon follows links only) |
| Fixed and verified on retest | 4 / 4 |
| False positives on SecureCorp | 0 |

**ML check (demonstration):** every payload the scanner proved is also given to the trained SVM (`ml/detector.py`); the report shows its verdict in an extra *ML check* row of each finding. This only illustrates how the model is used — it is not a measure of its accuracy (that comes from the 4,775-row test set).

A policy engine (`policy.toml`) limits the scanner to allowed hosts, ports and methods, rate-limits it, blocks destructive payloads, and logs every request.

---

## 5. How to run

**Requirements:** Python 3.10+

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

The report is saved to **`reports/report.html`** — open it in a browser. The whole run takes about a minute.

| Command | What it does |
|---------|--------------|
| `python run.py` | **Full run**: ML experiment → security scan → report |
| `python run.py --ml-only` | ML experiment only (cleaning, EDA, 3 models, results) |
| `python run.py --scan-only` | Security scan only (uses the trained model) |
| `python run.py --report-only` | Rebuild `report.html` from saved results — nothing re-runs |
| `python run.py --targets bank blog` | Scan only some lab websites |
| `python run.py --url http://localhost:8000` | Scan one external URL (must be allowed in `policy.toml`) |
| `python serve_targets.py` | Keep the 4 lab websites running to show them in a browser |
| `pytest -q` | Run the 28 automated tests |
| `docker compose up` | Run everything in Docker (optional) |

---

## 6. Project structure

```
ml/            ML experiment: features, dataset + cleaning, EDA, models, training, detector
dataset/       HTTP Params Dataset (raw CSV + source information)
models/        Saved best model (model.joblib) and all results (metrics.json)
cart/          Security scanner: policy, recon, attack modules, remediation, retest, scoring, report
targets/       The 4 local lab websites
reports/       report.html, report.json, charts (reports/ml/) and attack graphs
tests/         Automated tests (pytest)
policy.toml    Scope and safety rules for the scanner
run.py         Single entry point
```

## 7. Tech stack

Python · scikit-learn · pandas · NumPy · Matplotlib · Flask · Requests · NetworkX · pytest · Docker · GitHub Actions

## 8. Ethics

Educational project. The scanner attacks **only** the local websites in this repository; the policy engine blocks anything outside that scope, and all proofs are harmless.

## License

MIT
