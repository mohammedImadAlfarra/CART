#!/usr/bin/env python3
"""CART-ML — single entry point for the whole project.

  python run.py                      # FULL run: ML experiment -> security scan -> report
  python run.py --ml-only            # ML experiment only (dataset, cleaning, EDA, 3 models, results)
  python run.py --scan-only          # security scan only (uses the already-trained model)
  python run.py --report-only        # rebuild report.html from saved results (nothing re-runs)
  python run.py --url http://localhost:8000   # scan ONE external URL (must pass policy.toml)
  python run.py --targets bank blog  # scan only some lab websites

The report is written to  reports/report.html  — open it in any browser.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cart.report import console_summary, render_html


# ----------------------------------------------------------------------------- ml
def do_ml() -> bool:
    print("=" * 72)
    print("  [1] MACHINE-LEARNING EXPERIMENT")
    print("=" * 72)
    try:
        import sklearn  # noqa: F401
    except ImportError:
        print("scikit-learn is not installed. Run: pip install -r requirements.txt")
        return False
    from ml.train import main as train_main
    print("  dataset -> cleaning -> EDA -> 3 models (grid search + 5-fold CV) -> results")
    train_main()
    return True


# --------------------------------------------------------------------------- scan
def do_scan(args) -> dict:
    from cart.lab import run_benchmark, scan_url
    print("\n" + "=" * 72)
    print("  [2] SECURITY SCAN (practical application)")
    print("=" * 72)
    if args.url:
        report = scan_url(args.url, policy_path=args.policy, out_dir=args.out, verbose=not args.quiet)
    else:
        report = run_benchmark(names=args.targets, policy_path=args.policy, out_dir=args.out,
                               verbose=not args.quiet)
    print(console_summary(report))
    return report


# ------------------------------------------------------------------------- report
def load_saved(out: Path):
    p = out / "report.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def main(argv=None):
    ap = argparse.ArgumentParser(description="CART-ML - ML detection of malicious HTTP requests + security scanner")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--ml-only", action="store_true", help="ML experiment only")
    mode.add_argument("--scan-only", action="store_true", help="security scan only")
    mode.add_argument("--report-only", action="store_true", help="rebuild report.html from saved results")
    ap.add_argument("--targets", nargs="*", default=None,
                    help="lab websites to scan (bank blog files clean); default: all")
    ap.add_argument("--url", default=None, help="scan ONE external URL instead of the lab")
    ap.add_argument("--policy", default="policy.toml")
    ap.add_argument("--out", default="reports")
    ap.add_argument("--quiet", action="store_true", help="less scanner output")
    args = ap.parse_args(argv)
    out = Path(args.out)

    if args.report_only:
        render_html(load_saved(out), out)
        print(f"Report rebuilt: {out / 'report.html'}")
        return 0

    if not args.scan_only:
        if not do_ml():
            return 1
    report = load_saved(out)
    if not args.ml_only:
        report = do_scan(args)

    render_html(report, out)
    print(f"\nHTML report : {out / 'report.html'}")
    if report:
        still = [f["id"] for r in report["results"].values() for f in r["findings"]
                 if f["status"] == "still_vulnerable"]
        if still:
            print(f"WARNING: still vulnerable after fix: {still}")
    print("All done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
