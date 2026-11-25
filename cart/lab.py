"""Benchmark runner: scan every lab target, retest fixes, score the scanner.

As a small demonstration, every proven attack payload is also given to the
trained ML model (if it exists) - see _ml_check.
"""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path

from .metrics import aggregate, norm_path, score_target
from .orchestrator import Orchestrator
from .policy import Policy, ScopeViolation
from targets.server import start_targets, stop_targets
from targets.registry import get


def _fix_resolver(ground_truth):
    default = {"sqli_auth_bypass": "sqli_login", "sqli": "sqli_search",
               "xss_reflected": "xss_search", "path_traversal": "path_traversal"}
    index = {(g["type"], norm_path(g["path"])): g["fix"] for g in ground_truth}

    def resolve(f):
        return index.get((f.vuln_type, norm_path(f.path))) or default.get(f.vuln_type)
    return resolve


def _ml_check(results: dict) -> dict:
    """DEMO only: ask the trained model about every proven payload.
    Adds f["ml"] to each finding. Skipped if the model has not been trained."""
    try:
        from ml.detector import PayloadDetector
        det = PayloadDetector.load()
    except Exception:
        return {"available": False}
    if not det.ready:
        return {"available": False}
    checked = flagged = 0
    for res in results.values():
        for f in res["findings"]:
            if f.get("payload"):
                f["ml"] = det.verdict(f["payload"])
                checked += 1
                flagged += int(f["ml"]["malicious"])
    return {"available": True, "model": det.name, "checked": checked, "flagged": flagged}


def scan_url(url, policy_path="policy.toml", out_dir="reports", verbose=True, auth=None) -> dict:
    """Scan ONE arbitrary URL the user points us at (e.g. a site on the professor's
    laptop). No answer key and no fix toggles, so we prove findings and propose
    fixes, but do not score precision/recall or retest.
    The policy still applies: an out-of-scope host/port is refused.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    policy = Policy.load(policy_path)
    if auth:
        policy.auth = dict(auth)
    try:
        orch = Orchestrator(url, policy, source=None, audit_path=out / "audit.jsonl",
                            verbose=verbose, name="external")
    except ScopeViolation as e:
        print(f"[policy] REFUSED to scan {url}: {e} -- not allowed by policy.toml. "
              f"Add its host/port to [scope] in policy.toml to authorize it.")
        raise SystemExit(2)
    res = orch.run()
    res["name"], res["title"], res["theme"] = "external", url, "user-provided target"
    res["ground_truth"] = []
    res["score"] = score_target(res["findings"], [], scored=False)
    results = {"external": res}

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "engine": "rule-based",
        "external": True,
        "targets": ["external"],
        "results": results,
        "metrics": aggregate({"external": {"findings": res["findings"], "ground_truth": [], "scored": False}}),
        "ml_check": _ml_check(results),
        "totals": {"targets": 1, "findings": len(res["findings"]),
                   "requests": res["requests_sent"], "fixed_on_retest": 0},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def run_benchmark(names=None, policy_path="policy.toml", out_dir="reports", verbose=True) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base_policy = Policy.load(policy_path)

    targets = get(names)
    running = start_targets([t.name for t in targets], run_dir=out / "_run")
    results, per_target_scores, order = {}, {}, []
    try:
        for t in targets:                      # ONE orchestrator per site
            rt = running[t.name]
            policy = copy.deepcopy(base_policy)
            policy.auth = dict(t.auth)         # per-target test account
            try:
                orch = Orchestrator(rt.base_url, policy, source=t.source,
                                    audit_path=out / "audit.jsonl", verbose=verbose, name=t.name)
            except ScopeViolation as e:
                print(f"[policy] REFUSED to scan {t.title} ({rt.base_url}): {e} "
                      f"-- not allowed by policy.toml")
                continue
            orch.fix_resolver = _fix_resolver(t.ground_truth)
            orch.fix_toggle = rt.set_fix
            res = orch.run()
            rt.reset_fixes()
            res["name"], res["title"], res["theme"] = t.name, t.title, t.theme
            res["ground_truth"] = t.ground_truth
            res["score"] = score_target(res["findings"], t.ground_truth)
            results[t.name] = res
            per_target_scores[t.name] = {"findings": res["findings"], "ground_truth": t.ground_truth}
            order.append(t.name)
    finally:
        stop_targets(running)

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "engine": "rule-based",
        "targets": order,
        "results": results,
        "metrics": aggregate(per_target_scores),
        "ml_check": _ml_check(results),
        "totals": {
            "targets": len(order),
            "findings": sum(len(results[n]["findings"]) for n in order),
            "requests": sum(results[n]["requests_sent"] for n in order),
            "fixed_on_retest": sum(1 for n in order for f in results[n]["findings"]
                                   if f["status"] == "fixed"),
        },
    }
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
