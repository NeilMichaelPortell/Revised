#!/usr/bin/env python3
"""
smoke_test.py
=============

Quick sanity check for run_baseline_experiment.py BEFORE the full multi-hour run.

Runs every installed model against only the first 3 scenarios (R001-R003) in
baseline mode, then inspects the output folders to confirm each model produced:
  - a review CSV with 3 data rows
  - a raw JSONL audit trail
  - a summary file

This is deliberately small so you can confirm end to end that Ollama responds,
JSON parses, files land in outputs/<model>/, and the review columns look right.
It does NOT touch the dataset and uses the same leakage-safe path as the real run.

USAGE
-----
    python smoke_test.py
    python smoke_test.py --scenarios 5          # test more scenarios
    python smoke_test.py --models llama3         # test one model only
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import time
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]   # scripts\runs\ -> revised\
MAIN_SCRIPT = Path(__file__).resolve().parent / "1-run_baseline.py"
OUTPUTS_DIR = ROOT_DIR / "outputs"

# Same five models, main three first (matches the real runner).
MODELS = ["llama3", "deepseek-r1:8b", "gemma3:12b", "qwen3:8b", "gpt-oss:20b"]


def safe_model_dir(model: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9._-]", "_", model)


def run_smoke(models: list[str], scenarios: int) -> None:
    if not MAIN_SCRIPT.exists():
        sys.exit(f"Cannot find {MAIN_SCRIPT}. Put smoke_test.py next to "
                 f"run_baseline_experiment.py (the dataset root).")

    print(f"Smoke test: {len(models)} model(s) x {scenarios} scenarios (baseline)\n")
    started = time.time()

    # Delegate to the real runner so we test the exact same code path.
    cmd = [sys.executable, str(MAIN_SCRIPT),
           "--models", *models,
           "--limit", str(scenarios)]
    print("Running:", " ".join(cmd), "\n")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        sys.exit(f"\nRunner exited with code {result.returncode}. Fix errors above "
                 f"before the full run.")

    # ---- verify outputs ------------------------------------------------------
    print("\n" + "=" * 60)
    print("VERIFICATION")
    print("=" * 60)

    all_ok = True
    for model in models:
        mdir = OUTPUTS_DIR / safe_model_dir(model)
        review = mdir / f"{safe_model_dir(model)}_baseline_review.csv"
        raw = mdir / f"{safe_model_dir(model)}_baseline_raw.jsonl"
        summary = mdir / f"{safe_model_dir(model)}_baseline_summary.txt"

        problems = []
        n_rows = n_valid = 0
        if review.exists():
            with review.open(encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            n_rows = len(rows)
            n_valid = sum(1 for r in rows if r.get("json_valid") == "TRUE")
            if n_rows != scenarios:
                problems.append(f"expected {scenarios} rows, got {n_rows}")
            if n_valid == 0:
                problems.append("0 valid JSON outputs - model may not be answering in JSON")
        else:
            problems.append("review CSV missing")
        if not raw.exists():
            problems.append("raw JSONL missing")
        if not summary.exists():
            problems.append("summary missing")

        status = "OK" if not problems else "CHECK"
        if problems:
            all_ok = False
        print(f"  [{status}] {model:<16} rows={n_rows} validJSON={n_valid} "
              f"{'| ' + '; '.join(problems) if problems else ''}")

    elapsed = time.time() - started
    print(f"\nElapsed: {elapsed:.0f}s")
    if all_ok:
        print("\nAll models produced valid output. Safe to launch the full run:")
        print("    python 1-run_baseline.py")
    else:
        print("\nSome models need attention (see CHECK rows above) before the full run.")

    # Show one model's review rows so you can eyeball the human-readable format.
    first = OUTPUTS_DIR / safe_model_dir(models[0]) / f"{safe_model_dir(models[0])}_baseline_review.csv"
    if first.exists():
        print(f"\nSample rows from {models[0]}:")
        print("-" * 60)
        with first.open(encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                print(f"  {r['record_id']} {r['scenario_id']:<14} "
                      f"pred={r['predicted_class'] or '?':<9} gt={r['ground_truth_class']:<9} "
                      f"{r['outcome']:<9} {r['latency_seconds']}s")
                print(f"      feedback: {r['model_explanation'][:70]}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Smoke test for the baseline experiment runner.")
    p.add_argument("--models", nargs="+", default=MODELS)
    p.add_argument("--scenarios", type=int, default=3, help="Scenarios per model (default 3).")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_smoke(args.models, args.scenarios)