"""Orchestrator: runs the full CART pipeline against ONE target.

  recon -> plan -> DISCOVER -> PROVE (safe exploit) -> REMEDIATE -> RETEST
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from .agents.modules import ALL_MODULES
from .agents.planner import PlannerAgent
from .agents.recon import ReconAgent
from .agents.remediation import RemediationAgent
from .client import ScopedClient
from .knowledge import SEVERITY_ORDER
from .models import Endpoint, Finding
from .policy import Policy, ScopeViolation


@dataclass
class Context:
    client: ScopedClient
    policy: Policy
    counter: int = 0          # used to number findings F01, F02, ...


class Orchestrator:
    def __init__(self, base_url, policy: Policy, source: Path | None = None,
                 audit_path: Path | None = None, verbose=True, name="target"):
        self.base_url = base_url
        self.policy = policy
        self.source = source
        self.name = name
        self.verbose = verbose
        self.client = ScopedClient(base_url, policy, audit_path)
        self.ctx = Context(self.client, policy)
        self.logs: list[str] = []

    def log(self, msg, agent="cart"):
        line = f"[{agent}] {msg}"
        self.logs.append(line)
        if self.verbose:
            print(line)

    def run(self) -> dict:
        t0 = time.time()
        self.log(f"=== scanning {self.base_url} ===")

        recon = ReconAgent(self.client, self.policy, lambda m: self.log(m, "recon")).run()
        modules = [M(self.ctx) for M in ALL_MODULES]
        plan = PlannerAgent(modules, lambda m: self.log(m, "planner")).run(recon)

        # ---- stage 1: DISCOVERY (cheap signals, may be wrong) -----------------
        for step in plan:
            mod, ep, param = step["module"], step["endpoint"], step["param"]
            step["candidate"] = None
            try:
                step["candidate"] = mod.discover(ep, param)
            except ScopeViolation as e:
                self.log(f"blocked by policy: {e}", mod.name)
            except Exception as e:
                self.log(f"module error ({mod.name} {ep.path}): {e}", mod.name)
        queue = [s for s in plan if s["candidate"]]
        self.log(f"discovery: {len(queue)} suspicious candidates from {len(plan)} tests", "discover")

        # ---- stage 2: PROOF (safe exploitation) -------------------------------
        findings: list[Finding] = []
        proven_keys = set()
        for step in queue:
            mod = step["module"]
            try:
                finding = mod.exploit(step["candidate"])
            except ScopeViolation as e:
                self.log(f"blocked by policy: {e}", mod.name)
                continue
            except Exception as e:
                self.log(f"exploit error ({mod.name} {step['endpoint'].path}): {e}", mod.name)
                continue
            if not finding:
                continue
            key = (finding.vuln_type, finding.path, finding.param)
            if key in proven_keys:
                continue
            proven_keys.add(key)
            findings.append(finding)
            self.log(f"PROVEN {finding.id} {finding.vuln_type} @ {finding.path} "
                     f"(sev {finding.severity})", "exploit")

        # ---- stage 3: REMEDIATE + RETEST --------------------------------------
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.cvss))
        RemediationAgent(lambda m: self.log(m, "remediation"), self.source).run(findings)
        self._retest(findings)

        dt = round(time.time() - t0, 1)
        self.log(f"=== done: {len(findings)} proven findings in {dt}s, "
                 f"{self.client.policy.requests_sent} requests ===")
        return {
            "target": self.base_url,
            "recon": {"endpoints": [e.__dict__ for e in recon["endpoints"]],
                      "hidden_paths": recon["hidden_paths"], "server": recon["server"]},
            "findings": [f.to_dict() for f in findings],
            "plan_size": len(plan),
            "candidates": len(queue),
            "requests_sent": self.client.policy.requests_sent,
            "duration_s": dt,
            "logs": self.logs,
        }

    # ------------------------------------------------------------------ retest
    def _retest(self, findings):
        """Enable each finding's fix on the live target and re-run the exact proof.

        Needs fix_resolver(finding)->switch and fix_toggle(switch,bool), set by
        the lab runner. Without them (e.g. an external URL) we only note that a
        fix is available.
        """
        resolver = getattr(self, "fix_resolver", None)
        toggle = getattr(self, "fix_toggle", None)
        if not resolver or not toggle:
            for f in findings:
                f.status = "fix_available"
            return
        modmap = {M.vuln_type: M for M in ALL_MODULES}
        for f in findings:
            switch = resolver(f)
            if not switch:
                f.status = "fix_available"
                continue
            toggle(switch, True)          # turn the fix ON
            time.sleep(0.05)
            still = self._reprove(f, modmap)
            toggle(switch, False)         # turn it OFF again (lab goes back to vulnerable)
            f.status = "still_vulnerable" if still else "fixed"
            self.log(f"retest {f.id} ({f.vuln_type}@{f.path}): "
                     f"{'STILL VULNERABLE' if still else 'fixed OK'}", "retest")

    def _reprove(self, f, modmap):
        """Re-run discover + exploit for one finding. True = still vulnerable."""
        if f.vuln_type == "sqli_auth_bypass":
            mod = modmap["sqli"](self.ctx)
            ep, param = Endpoint(f.path, "POST", ["username", "password"]), "username"
        else:
            mod = modmap[f.vuln_type](self.ctx)
            param = f.param
            ep = Endpoint(f.path, f.method, [param] if param else [])
        try:
            cand = mod.discover(ep, param)
            return bool(cand and mod.exploit(cand))
        except Exception:
            return False
