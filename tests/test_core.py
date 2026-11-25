"""Scanner tests: policy safety, full lab scan, retest.

Run:  pytest -q tests/test_core.py
"""
from __future__ import annotations

import pytest

from cart.lab import run_benchmark
from cart.metrics import norm_path, score_target
from cart.policy import Policy, ScopeViolation


# --------------------------------------------------------------- policy / safety
def test_policy_blocks_out_of_scope_host():
    with pytest.raises(ScopeViolation):
        Policy.load("policy.toml").check_url("http://evil.example.com:5001/")


def test_policy_blocks_destructive_method():
    with pytest.raises(ScopeViolation):
        Policy.load("policy.toml").check_method("DELETE")


def test_policy_blocks_destructive_payloads():
    p = Policy.load("policy.toml")
    for bad in ["'; DROP TABLE users; --", "x UNION SELECT load_file('/etc/passwd')", "a; rm -rf /"]:
        with pytest.raises(ScopeViolation):
            p.check_payload(bad)


def test_policy_allows_safe_canary_payload():
    Policy.load("policy.toml").check_payload("<cart-canary-1234>", "../private/canary.txt")


def test_metrics_pathnorm():
    assert norm_path("/api/users/5") == "/api/users/<id>"
    assert norm_path("/Search/") == "/search"


def test_score_counts_false_positive():
    s = score_target([{"vuln_type": "sqli", "path": "/x"}], [])
    assert s["false_positives"] == 1 and s["true_positives"] == 0


# --------------------------------------------------------------- full lab scan
@pytest.fixture(scope="module")
def report(tmp_path_factory):
    return run_benchmark(verbose=False, out_dir=str(tmp_path_factory.mktemp("reports")))


def test_scanned_all_targets(report):
    assert report["totals"]["targets"] == 4


def test_no_false_positives_on_clean_target(report):
    assert report["results"]["clean"]["score"]["false_positives"] == 0
    assert len(report["results"]["clean"]["findings"]) == 0


def test_overall_precision_perfect(report):
    assert report["metrics"]["overall"]["precision"] == 1.0


@pytest.mark.parametrize("vtype", ["sqli_auth_bypass", "sqli", "xss_reflected", "path_traversal"])
def test_vuln_type_detected(report, vtype):
    found = {f["vuln_type"] for r in report["results"].values() for f in r["findings"]}
    assert vtype in found


def test_unlinked_page_is_a_known_miss(report):
    # /comment is not linked anywhere, so link-based recon cannot find it (documented limitation)
    assert report["results"]["blog"]["score"]["missed"] == ["xss_reflected @ /comment"]


def test_every_finding_has_proof(report):
    for r in report["results"].values():
        for f in r["findings"]:
            assert f["evidence"] and f["proof_request"], f["id"]


def test_all_fixes_verified_on_retest(report):
    for r in report["results"].values():
        for f in r["findings"]:
            assert f["status"] == "fixed", (f["id"], f["status"])


def test_request_budget_respected(report):
    assert report["totals"]["requests"] <= 2000
