"""Render the project report: one interactive HTML page (+ a console summary).

The page has two top-level tabs:
  * ML    (opens first) — the machine-learning experiment: research question,
            dataset + cleaning, descriptive statistics, the 3 models and their
            hyperparameters, results (Accuracy / Precision / Recall / F1 / ROC-AUC),
            charts and limitations.
  * Scan  — the security scanner (the practical application): summary cards,
            per-type accuracy, a target picker, and every finding laid out as a
            staged table (Discover -> Prove -> Impact -> Remediate -> Retest), plus a small
            ML check row (demonstration only, not part of the results).

All data is rendered server-side; the small amount of JavaScript only shows and
hides sections, so the report works from the local file with no server.
"""
from __future__ import annotations

import html
import json
from pathlib import Path

from .graph import draw

ML_METRICS = Path("models/request_classifier/metrics.json")

SEV_COLOR = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb"}
STATUS_BADGE = {
    "fixed": ("fixed on retest", "#16a34a"),
    "still_vulnerable": ("STILL VULNERABLE", "#b91c1c"),
    "fix_available": ("fix available", "#2563eb"),
}
METRIC_LABEL = {"accuracy": "Accuracy", "precision": "Precision", "recall": "Recall",
                "f1": "F1", "roc_auc": "ROC-AUC"}

CSS = """
*{box-sizing:border-box}
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;color:#0f172a;background:#f1f5f9}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
header{background:#0f172a;color:#fff;padding:26px 24px 0}
header .wrap{padding:0}
header h1{margin:0 0 6px;font-size:26px} header p{margin:2px 0;color:#cbd5e1}
.tabbar{max-width:1100px;margin:16px auto -1px;display:flex;gap:8px;padding:0 24px}
.tabbtn{background:#1e293b;color:#cbd5e1;border:none;padding:11px 22px;font-size:15px;font-weight:600;
  border-radius:10px 10px 0 0;cursor:pointer}
.tabbtn.active{background:#f1f5f9;color:#0f172a}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;color:#fff;font-size:12px;font-weight:600}
.cards{display:flex;flex-wrap:wrap;gap:14px;margin:22px 0}
.card{background:#fff;border-radius:12px;padding:16px 18px;flex:1;min-width:140px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card .n{font-size:28px;font-weight:700} .card .l{color:#64748b;font-size:13px}
table{border-collapse:collapse;width:100%;background:#fff;border-radius:10px;overflow:hidden;margin:10px 0}
th,td{padding:8px 11px;text-align:left;border-bottom:1px solid #e2e8f0;font-size:14px;vertical-align:top}
th{background:#e2e8f0} tr:last-child td{border-bottom:none}
tr.best td{background:#ecfdf5;font-weight:600}
h2{margin:28px 0 6px} h1.section{margin:30px 0 4px;font-size:22px}
h3{margin:18px 0 6px}
.pill{font-size:12px;color:#334155;background:#e2e8f0;padding:1px 8px;border-radius:999px}
.kv{color:#475569;font-size:13px;margin:3px 0}
pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;font-size:12.5px;line-height:1.45;margin:6px 0}
img.graph{width:100%;border:1px solid #e2e8f0;border-radius:8px;background:#fff}
.imgrow{display:flex;flex-wrap:wrap;gap:14px;margin:10px 0}
.imgrow > div{flex:1;min-width:300px}
.note{background:#ecfeff;border:1px solid #a5f3fc;padding:10px 14px;border-radius:8px;margin:14px 0;font-size:14px}
.rq{background:#eef2ff;border:1px solid #c7d2fe;padding:14px 18px;border-radius:10px;margin:18px 0;font-size:15px}
.limits{background:#fff7ed;border:1px solid #fed7aa;padding:12px 16px;border-radius:8px;margin:16px 0;font-size:14px}
.limits h3{margin:0 0 8px}
.model{background:#fff;border-radius:12px;padding:14px 18px;margin:12px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.model h3{margin:0 0 4px}
/* target picker */
.picker{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0 4px}
.site-btn{background:#fff;border:1px solid #cbd5e1;border-radius:10px;padding:10px 16px;cursor:pointer;
  font-size:14px;font-weight:600;color:#0f172a;box-shadow:0 1px 2px rgba(0,0,0,.05)}
.site-btn .sub{display:block;font-weight:400;color:#64748b;font-size:12px;margin-top:2px}
.site-btn.active{border-color:#0f172a;background:#0f172a;color:#fff}
.site-btn.active .sub{color:#cbd5e1}
.site-btn .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}
.hint{color:#64748b;font-size:15px;margin:18px 0;padding:18px;border:2px dashed #cbd5e1;border-radius:12px;text-align:center}
.site-panel{display:none;background:#fff;border-radius:12px;padding:18px 20px;margin:14px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.site-panel.show{display:block}
/* staged finding table */
.finding{border:1px solid #e2e8f0;border-left:5px solid #94a3b8;border-radius:0 10px 10px 0;margin:14px 0;overflow:hidden}
.finding .fhead{padding:11px 14px;background:#f8fafc;border-bottom:1px solid #e2e8f0}
.finding .fhead h4{margin:0 0 4px;font-size:15px}
.finding table{margin:0;border-radius:0}
.finding th{width:150px;background:#f1f5f9;color:#0f172a;font-size:13px;white-space:nowrap}
.stage-num{display:inline-block;width:20px;height:20px;line-height:20px;text-align:center;border-radius:50%;
  background:#0f172a;color:#fff;font-size:12px;margin-right:7px}
.evidence{background:#fef9c3;border:1px solid #fde047;padding:7px 10px;border-radius:6px;font-size:13px}
code{background:#eef2f7;padding:1px 5px;border-radius:4px;font-size:12.5px}
"""

JS = """
function showTab(t){
  document.querySelectorAll('.tabpane').forEach(function(p){p.style.display='none';});
  document.querySelectorAll('.tabbtn').forEach(function(b){b.classList.remove('active');});
  document.getElementById('tab-'+t).style.display='block';
  document.getElementById('btn-'+t).classList.add('active');
}
function showSite(name){
  document.querySelectorAll('.site-panel').forEach(function(p){p.classList.remove('show');});
  document.querySelectorAll('.site-btn').forEach(function(b){b.classList.remove('active');});
  var panel=document.getElementById('site-'+name);
  if(panel){panel.classList.add('show');}
  var btn=document.getElementById('btn-site-'+name);
  if(btn){btn.classList.add('active');}
  var hint=document.getElementById('site-hint');
  if(hint){hint.style.display='none';}
}
"""

e = html.escape


def _img(name, alt):
    return f'<div><img class="graph" src="ml/{name}" alt="{e(alt)}"></div>'


# =============================================================== ML TAB
def _load_ml():
    if not ML_METRICS.exists():
        return None
    try:
        return json.loads(ML_METRICS.read_text(encoding="utf-8"))
    except Exception:
        return None


def _ml_tab() -> str:
    m = _load_ml()
    if m is None:
        return ('<div class="note">The ML experiment has not been run yet. Run <code>python run.py</code> '
                '(or <code>python run.py --ml-only</code>) to train the models and fill this tab.</div>')
    q, split, models, best = m["data_quality"], m["split"], m["models"], m["best_model"]
    eda = m["eda"]

    # ---- 1. research question + dataset
    head = f"""
      <div class="rq"><b>Research question.</b> {e(m['research_question'])}</div>
      <h1 class="section">1. Dataset</h1>
      <div class="note"><b>Real, public dataset:</b> {e(m['dataset'])}
        · <a href="{e(m['dataset_url'])}">source</a>. Each row is one HTTP parameter value labelled
        <b>normal</b> or <b>malicious</b>; every value is turned into {len(m['features'])} numeric features
        (length, special characters, quotes, SQL/XSS/command keywords, traversal patterns, entropy ...).</div>
      <div class="cards">
        <div class="card"><div class="n">{q['rows_raw']:,}</div><div class="l">Rows (raw)</div></div>
        <div class="card"><div class="n">{q['rows_clean']:,}</div><div class="l">Rows after cleaning</div></div>
        <div class="card"><div class="n">{q['class_counts_clean']['normal']:,}</div><div class="l">Normal</div></div>
        <div class="card"><div class="n">{q['class_counts_clean']['malicious']:,}</div><div class="l">Malicious</div></div>
        <div class="card"><div class="n">{len(m['features'])}</div><div class="l">Features</div></div>
        <div class="card"><div class="n">{split['train']:,} / {split['test']:,}</div><div class="l">Train / test</div></div>
      </div>"""

    # ---- data cleaning
    cleaning = f"""
      <h2>Data cleaning (leakage check)</h2>
      <p class="kv">The models only see the 18 features. Two different payloads can give the exact same
        feature vector; if one copy is in the training set and the other in the test set, the test is no
        longer on unseen data and the score is inflated. So duplicates are removed <b>before</b> splitting.</p>
      <table><tr><th>Step</th><th>Rows</th></tr>
        <tr><td>Raw dataset</td><td>{q['rows_raw']:,}</td></tr>
        <tr><td>Duplicate payload strings removed</td><td>{q['duplicate_payloads']:,}</td></tr>
        <tr><td>Contradictory rows removed (same features, both labels)</td><td>{q['conflicting_rows']:,}</td></tr>
        <tr><td>Duplicate feature vectors removed</td><td>{q['duplicate_feature_rows']:,}</td></tr>
        <tr class="best"><td>Clean dataset used for every model</td><td>{q['rows_clean']:,}</td></tr>
      </table>"""

    # ---- 2. EDA
    attack_rows = "".join(f"<tr><td>{e(k)}</td><td>{v:,}</td><td>{v / q['rows_clean']:.1%}</td></tr>"
                          for k, v in eda["attack_types_clean"].items())
    stat_rows = "".join(
        f"<tr><td><code>{e(f)}</code></td><td>{s['mean']}</td><td>{s['median']}</td><td>{s['mode']}</td>"
        f"<td>{s['std']}</td><td>{s['mean_normal']}</td><td>{s['mean_malicious']}</td></tr>"
        for f, s in eda["descriptive_stats"].items())
    eda_html = f"""
      <h1 class="section">2. Exploratory data analysis</h1>
      <div class="imgrow">{_img('class_distribution.png', 'class distribution')}</div>
      <p class="kv">After cleaning, the data is imbalanced (about {q['class_counts_clean']['malicious'] / q['rows_clean']:.0%}
        malicious). That is why we report Precision, Recall, F1 and ROC-AUC, not only Accuracy, and use a
        <b>stratified</b> split that keeps the same ratio in train and test.</p>
      <table><tr><th>Attack type</th><th>Rows</th><th>Share</th></tr>{attack_rows}</table>
      <h2>Descriptive statistics (6 key features, clean dataset)</h2>
      <table><tr><th>Feature</th><th>Mean</th><th>Median</th><th>Mode</th><th>Std</th>
        <th>Mean (normal)</th><th>Mean (malicious)</th></tr>{stat_rows}</table>
      <div class="imgrow">{_img('feature_boxplots.png', 'feature box plots')}</div>"""

    # ---- 3. models + hyperparameters
    model_cards = []
    for k, r in models.items():
        notes = r["param_notes"]
        rows = [f"<tr><td><code>{e(p)}</code></td><td>{e(', '.join(v))}</td>"
                f"<td><b>{e(str(r['best_params'].get(p, '')))}</b></td><td>{e(notes.get(p, ''))}</td></tr>"
                for p, v in r["search_space"].items()]
        rows += [f"<tr><td><code>{e(p)}</code></td><td>fixed</td><td>—</td><td>{e(t)}</td></tr>"
                 for p, t in notes.items() if p not in r["search_space"]]
        ec = r.get("edge_check", {})
        if ec.get("at_edge"):
            edge = (f"⚠ Best value of {', '.join(ec['at_edge'])} is at the edge of the searched range "
                    f"— the range should be widened.")
        else:
            edge = "✓ Every best value lies inside the searched range"
            if ec.get("natural_limit"):
                edge += (f" or at a natural limit that cannot go further "
                         f"({', '.join(ec['natural_limit'])})")
            edge += "."
        model_cards.append(f"""
        <div class="model"><h3>{e(r['label'])}</h3>
          <p class="kv"><b>Why this algorithm:</b> {e(r['why'])}</p>
          <table><tr><th>Hyperparameter</th><th>Values searched</th><th>Best</th><th>Meaning</th></tr>{''.join(rows)}</table>
          <p class="kv">{e(edge)}</p>
        </div>""")
    models_html = f"""
      <h1 class="section">3. Algorithms and hyperparameters</h1>
      <p class="kv">Each model is tuned with <b>GridSearchCV</b>: every combination is scored with
        5-fold cross-validation (F1) on the <b>training set only</b>; the test set is never used for tuning.</p>
      {''.join(model_cards)}"""

    # ---- 4. results
    res_rows = []
    for k, r in models.items():
        t, cv = r["test"], r["cv"]
        cls = ' class="best"' if k == best else ""
        res_rows.append(
            f"<tr{cls}><td>{e(r['label'])}{' ★' if k == best else ''}</td>"
            + "".join(f"<td>{t[mm]}</td>" for mm in METRIC_LABEL)
            + f"<td>{cv['f1']['mean']} ± {cv['f1']['std']}</td><td>{r['fit_seconds']}s</td></tr>")
    dt_rows = "".join(
        f"<tr><td>{e(r['label'])}</td><td>{r['default_test']['f1']}</td><td>{r['test']['f1']}</td>"
        f"<td>{round(r['test']['f1'] - r['default_test']['f1'], 4):+}</td></tr>"
        for r in models.values())
    head_cells = "".join(f"<th>{v}</th>" for v in METRIC_LABEL.values())
    b = models[best]
    cmx = b["test"]["confusion_matrix"]
    fastest = min(models.values(), key=lambda r: r["fit_seconds"])
    f1s = [r["test"]["f1"] for r in models.values()]
    no_fp = [r["label"] for r in models.values() if r["test"]["confusion_matrix"]["fp"] == 0]
    choice = (f"All three models reach a test F1 between {min(f1s)} and {max(f1s)}, so accuracy alone does "
              f"not separate them. We therefore choose by 5-fold cross-validation F1 on the training set: "
              f"<b>{e(b['label'])}</b> ({b['cv']['f1']['mean']}).")
    if b["label"] in no_fp:
        choice += f" It also made <b>no false alarms</b> on the test set (FP = 0)."
    if fastest["label"] != b["label"]:
        choice += (f" If training speed mattered more, <b>{e(fastest['label'])}</b> trains fastest "
                   f"({fastest['fit_seconds']}s) with almost the same score.")
    results_html = f"""
      <h1 class="section">4. Results</h1>
      <h2>Test set (tuned models)</h2>
      <table><tr><th>Model</th>{head_cells}<th>CV F1 (train)</th><th>Fit time</th></tr>{''.join(res_rows)}</table>
      <h2>Which model do we choose?</h2>
      <div class="note">{choice} Choosing by cross-validation rather than by the test score keeps the
        test set a fair, untouched judge. (★ = selected model.)</div>
      <div class="imgrow">{_img('model_comparison.png', 'model comparison')}</div>
      <div class="imgrow">{_img('roc_curves.png', 'ROC curves')}</div>
      <h2>Default vs tuned hyperparameters (test set F1)</h2>
      <table><tr><th>Model</th><th>Default</th><th>Tuned</th><th>Change</th></tr>{dt_rows}</table>
      <h2>Selected model: confusion matrix</h2>
      <p class="kv">{e(b['label'])} on {split['test']:,} test rows: TP={cmx['tp']:,} · TN={cmx['tn']:,}
        · FP={cmx['fp']:,} (normal flagged as attack) · FN={cmx['fn']:,} (attack missed).</p>
      <div class="imgrow" style="max-width:480px">{_img('confusion_matrix.png', 'confusion matrix')}</div>"""

    limits = f"""
      <div class="limits"><h3>Limitations</h3>
        <ul style="margin:0;padding-left:20px;line-height:1.6">
          <li><b>The three models are very close.</b> Test F1 ranges from {min(f1s)} to {max(f1s)}; the differences
            are about the size of one standard deviation in cross-validation, so the ranking could change with
            another split.</li>
          <li><b>The dataset is an easy benchmark.</b> Attacks differ sharply from normal values (see the box
            plots), so very high scores are expected. Results on real, messier traffic would be lower.</li>
          <li><b>Imbalanced attack types.</b> SQL injection is {eda['attack_types_clean'].get('sqli', 0):,} rows,
            command injection only {eda['attack_types_clean'].get('cmdi', 0):,}; the model learns the rare
            types from few examples.</li>
          <li><b>Hand-made features.</b> The 18 features encode known attack signs; a new attack style that
            does not use them may not be detected.</li>
        </ul>
        <h3 style="margin-top:12px">Future work</h3>
        <ul style="margin:0;padding-left:20px;line-height:1.6">
          <li><b>Learned features:</b> train on the raw text (e.g. TF-IDF of character n-grams) so the model
            learns attack patterns by itself, and compare with the 18 hand-made features.</li>
          <li><b>ML firewall:</b> place the trained model in front of the lab websites as a web application
            firewall (WAF) and measure how many of the scanner's attacks it blocks.</li>
        </ul>
      </div>"""
    return head + cleaning + eda_html + models_html + results_html + limits


# =============================================================== SCAN TAB
def _sev(f):
    c = SEV_COLOR.get(f["severity"], "#64748b")
    return f'<span class="badge" style="background:{c}">{f["severity"].upper()} · CVSS {f["cvss"]}</span>'


def _status(f):
    label, color = STATUS_BADGE.get(f["status"], (f["status"], "#64748b"))
    return f'<span class="badge" style="background:{color}">{label}</span>'


def _row(num, title, body):
    return f'<tr><th><span class="stage-num">{num}</span>{e(title)}</th><td>{body}</td></tr>'


def _ml_cell(f):
    """Demo row: how the trained model classifies this finding's payload."""
    ml = f.get("ml")
    if not ml:
        return '<span class="kv">— (no payload, or the model is not trained)</span>'
    verdict = ("<b style='color:#b91c1c'>malicious</b>" if ml["malicious"]
               else "<b style='color:#16a34a'>normal</b>")
    return (f'<span class="pill">demo</span> The trained {e(ml["model"])} classifies the payload '
            f'<code>{e(str(f["payload"]))}</code> as {verdict}.')


def _finding_table(f):
    """One proven finding laid out as a staged pipeline table."""
    rem = f.get("remediation", {})
    param = f' · param <code>{e(str(f["param"]))}</code>' if f.get("param") else ""
    discover = (f'{e(f["method"])} <code>{e(f["path"])}</code>{param}'
                + (f'<div class="kv">Probe payload: <code>{e(str(f["payload"]))}</code></div>'
                   if f.get("payload") else ""))
    prove = (f'<div class="evidence"><b>Proof:</b> {e(f["evidence"])}</div>'
             f'<div class="kv"><b>Reproduce:</b> <code>{e(f["proof_request"])}</code></div>')
    impact = f'{e(f["impact"])}<div class="kv">{e(f["cwe"])} · {e(f["owasp"])}</div>'
    remediate = (f'<span class="pill">{e(rem.get("engine", "knowledge-base"))}</span> {e(str(rem.get("fix", "")))}'
                 + (f'<div class="kv" style="margin-top:6px"><b>Vulnerable code:</b></div>'
                    f'<pre>{e(str(rem["vulnerable_code"]))}</pre>' if rem.get("vulnerable_code") else "")
                 + (f'<div class="kv"><b>Recommended patch:</b></div><pre>{e(str(rem["reference_patch"]))}</pre>'
                    if rem.get("reference_patch") else ""))
    return f"""
    <div class="finding" data-type="{e(f['vuln_type'])}" style="border-left-color:{SEV_COLOR.get(f['severity'], '#64748b')}">
      <div class="fhead"><h4>{e(f['id'])} — {e(f['title'])}</h4>{_sev(f)} {_status(f)}</div>
      <table>
        {_row(1, "Discover", discover)}
        {_row(2, "Prove", prove)}
        {_row(3, "Impact", impact)}
        {_row(4, "Remediate", remediate)}
        {_row(5, "Retest", _status(f))}
        {_row(6, "ML check", _ml_cell(f))}
      </table>
    </div>"""


def _site_panel(name, res, scored=True) -> str:
    findings = res["findings"]

    s = res.get("score", {})
    if scored and s.get("expected"):
        det = f"detected {s['true_positives']}/{s['expected']} known vulns · {s['false_positives']} false positive(s)"
        if s.get("missed"):
            det += f" · missed: {', '.join(s['missed'])}"
    elif scored:
        det = f"{s.get('false_positives', 0)} false positive(s) (control site)"
    else:
        det = f"{len(findings)} proven findings (external target — no answer key)"

    body = "".join(_finding_table(f) for f in findings) or "<p>No findings (clean target).</p>"
    return f"""
    <section class="site-panel" id="site-{name}">
      <h2>{e(res['title'])} <span class="pill">{e(res['theme'])}</span></h2>
      <div class="kv">{e(res['target'])} · {e(det)} · {res['requests_sent']} requests · {res['duration_s']}s</div>
      <img class="graph" src="graphs/{name}.png" alt="attack graph for {e(res['title'])}">
      <div class="findings-list">{body}</div>
    </section>"""


def _scan_tab(report: dict | None, out_dir: Path) -> str:
    if not report:
        return ('<div class="note">The security scan has not been run yet. Run <code>python run.py</code> '
                '(or <code>python run.py --scan-only</code>).</div>')
    img_dir = out_dir / "graphs"
    totals = report["totals"]
    intro = ('<div class="note"><b>The practical application.</b> A rule-based scanner attacks 4 small local '
             'websites with the same three attack families the ML model learned (SQL injection, XSS, path '
             'traversal). A vulnerability is only reported after it is <b>proven</b> with a harmless canary; '
             'then the fix is switched on and the same proof is <b>re-tested</b>. As a small demonstration, the '
             '<b>ML check</b> row shows how the trained model classifies the attack payload.</div>')

    if report.get("external"):
        res = report["results"]["external"]
        draw(res, img_dir / "external.png")
        cards = f"""<div class="cards">
          <div class="card"><div class="n">{totals['findings']}</div><div class="l">Proven findings</div></div>
          <div class="card"><div class="n">{totals['requests']}</div><div class="l">Requests sent</div></div>
          <div class="card"><div class="n">{res['duration_s']}s</div><div class="l">Duration</div></div></div>
          <div class="note">This target was supplied at run time, so there is no answer key — precision/recall
          are not computed. Every finding was still proven, and a fix is attached.</div>"""
        panel = _site_panel("external", res, scored=False).replace('class="site-panel"', 'class="site-panel show"')
        return intro + cards + panel

    m = report["metrics"]["overall"]
    cards = f"""
      <div class="cards">
        <div class="card"><div class="n">{totals['targets']}</div><div class="l">Websites scanned</div></div>
        <div class="card"><div class="n">{totals['findings']}</div><div class="l">Proven findings</div></div>
        <div class="card"><div class="n">{m['precision']}</div><div class="l">Precision</div></div>
        <div class="card"><div class="n">{m['recall']}</div><div class="l">Recall</div></div>
      </div>"""

    picker_btns, panels = [], []
    for name in report["targets"]:
        res = report["results"][name]
        draw(res, img_dir / f"{name}.png")
        nf = len(res["findings"])
        color = SEV_COLOR["critical"] if nf >= 2 else (SEV_COLOR["high"] if nf else "#16a34a")
        sub = f"{nf} finding(s)" if nf else "clean (control)"
        picker_btns.append(
            f'<button class="site-btn" id="btn-site-{name}" onclick="showSite(\'{name}\')">'
            f'<span class="dot" style="background:{color}"></span>{e(res["title"])}'
            f'<span class="sub">{e(res["theme"])} · {sub}</span></button>')
        panels.append(_site_panel(name, res, scored=True))
    picker = (f'<h2>Findings by website</h2><div class="picker">{"".join(picker_btns)}</div>'
              f'<div class="hint" id="site-hint">Select a website above to view its findings.</div>'
              f'{"".join(panels)}')
    return intro + cards + picker


# =============================================================== PAGE
def _page(generated_at, ml_html, scan_html) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>CART-ML Report</title><style>{CSS}</style></head><body>
    <header>
      <div class="wrap">
        <h1>CART-ML — Detecting malicious HTTP requests with machine learning</h1>
        <p>Comparison of Logistic Regression, SVM and Random Forest on a real public dataset,
          with a small security scanner as a practical application.</p>
        <p>Generated {e(generated_at)}</p>
      </div>
    </header>
    <div class="tabbar">
      <button class="tabbtn active" id="btn-ml" onclick="showTab('ml')">Machine learning</button>
      <button class="tabbtn" id="btn-scan" onclick="showTab('scan')">Security scan (application)</button>
    </div>
    <div class="wrap">
      <div class="tabpane" id="tab-ml">{ml_html}</div>
      <div class="tabpane" id="tab-scan" style="display:none">{scan_html}</div>
      <p class="kv" style="margin-top:30px">Educational project. Lab websites are intentionally
        vulnerable and run on localhost only.</p>
    </div>
    <script>{JS}</script>
    </body></html>"""


def render_html(report: dict | None, out_dir: Path) -> Path:
    import time
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    generated = (report or {}).get("generated_at") or time.strftime("%Y-%m-%d %H:%M:%S")
    ml_html = _ml_tab()
    scan_html = _scan_tab(report, out_dir)
    out = out_dir / "report.html"
    out.write_text(_page(generated, ml_html, scan_html), encoding="utf-8")
    return out


def console_summary(report: dict) -> str:
    m = report["metrics"]["overall"]
    if report.get("external"):
        res = report["results"]["external"]
        lines = ["=" * 60, "  External scan summary", "=" * 60,
                 f"  Target          : {res['target']}",
                 f"  Proven findings : {report['totals']['findings']}",
                 f"  Requests sent   : {report['totals']['requests']}",
                 "  (external target: no answer key, so precision/recall are not computed)",
                 "-" * 60, "  Proven findings:"]
        for f in res["findings"]:
            lines.append(f"    {f['vuln_type']:20} {f['severity']:8} {f['path']}")
        lines.append("=" * 60)
        return "\n".join(lines)
    lines = ["=" * 60, "  Security scan summary", "=" * 60,
             f"  Websites scanned: {report['totals']['targets']}",
             f"  Proven findings : {report['totals']['findings']}",
             f"  Precision       : {m['precision']}",
             f"  Recall          : {m['recall']}",
             f"  Fixed on retest : {report['totals']['fixed_on_retest']}/{report['totals']['findings']}",
             "=" * 60]
    return "\n".join(lines)
