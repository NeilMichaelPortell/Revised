#!/usr/bin/env python3
"""
analyse_validation_runs.py
==========================
Reads every completed run folder under validation_outputs/ and produces:

    validation_results.csv    one row per validation run
    validation_summary.txt    aggregate rates + breakdowns

This tool is SEPARATE from the frozen offline experiment. It never reads or
merges the frozen baseline/RAG metrics. It only aggregates the supplementary
live-validation runs.

Usage:
    python tools/analyse_validation_runs.py
    python tools/analyse_validation_runs.py --root /path/to/project
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys

# Allow running as a script: make the project root importable for the helper.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from validation.validation_config import (  # noqa: E402
    VALIDATION_OUTPUT_DIRNAME, RUN_FILES, summarise_latency,
)

CSV_COLUMNS = [
    "validation_run_id", "scenario_id", "repetition", "mode",
    "scenario_type", "events_captured", "alerts_generated", "alerts_expected",
    "false_alerts", "missed_alerts", "cooldown_suppressions", "duplicate_events",
    "llm_calls", "json_parse_valid_count", "strict_schema_valid_count",
    "fallback_count", "timeout_count", "retry_count",
    "mean_detection_latency_ms", "median_detection_latency_ms", "p95_detection_latency_ms",
    "mean_llm_latency_ms", "median_llm_latency_ms", "p95_llm_latency_ms",
    "mean_end_to_end_latency_ms", "median_end_to_end_latency_ms", "p95_end_to_end_latency_ms",
]


def _scenario_type(scenario_id: str) -> str:
    """Coarse scenario grouping from the id prefix, e.g. LIVE_AUTH_001 -> AUTH."""
    parts = scenario_id.split("_")
    return parts[1] if len(parts) >= 2 else "UNKNOWN"


def load_runs(root: str) -> list[dict]:
    base = os.path.join(root, VALIDATION_OUTPUT_DIRNAME)
    runs = []
    if not os.path.isdir(base):
        return runs
    for name in sorted(os.listdir(base)):
        folder = os.path.join(base, name)
        metrics_path = os.path.join(folder, RUN_FILES["metrics"])
        if not os.path.isfile(metrics_path):
            continue
        try:
            with open(metrics_path, encoding="utf-8") as f:
                m = json.load(f)
        except Exception:
            continue
        m["_scenario_type"] = _scenario_type(m.get("scenario_id", name))
        runs.append(m)
    return runs


def _rate(numer: int, denom: int) -> float:
    return round(numer / denom, 3) if denom else 0.0


def write_csv(runs: list[dict], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for m in runs:
            row = {k: m.get(k, "") for k in CSV_COLUMNS}
            row["scenario_type"] = m.get("_scenario_type", "")
            w.writerow(row)


def build_summary(runs: list[dict]) -> str:
    if not runs:
        return "No completed validation runs found.\n"

    n = len(runs)
    events = sum(r.get("events_captured", 0) for r in runs)
    alerts = sum(r.get("alerts_generated", 0) for r in runs)
    llm = sum(r.get("llm_calls", 0) for r in runs)
    json_valid = sum(r.get("json_parse_valid_count", 0) for r in runs)
    strict_valid = sum(r.get("strict_schema_valid_count", 0) for r in runs)
    fallback = sum(r.get("fallback_count", 0) for r in runs)
    timeouts = sum(r.get("timeout_count", 0) for r in runs)
    duplicates = sum(r.get("duplicate_events", 0) for r in runs)
    cooldowns = sum(r.get("cooldown_suppressions", 0) for r in runs)

    # detection/alert rates against the explicit plan
    alert_expected_runs = [r for r in runs if r.get("alerts_expected")]
    benign_runs = [r for r in runs if not r.get("alerts_expected")]
    detected = sum(1 for r in alert_expected_runs if r.get("alerts_generated", 0) > 0)
    benign_with_false = sum(1 for r in benign_runs if r.get("false_alerts", 0) > 0)

    # pooled latencies
    det = [r.get("mean_detection_latency_ms", 0) for r in runs if r.get("llm_calls")]
    gen = [r.get("mean_llm_latency_ms", 0) for r in runs if r.get("llm_calls")]
    e2e = [r.get("mean_end_to_end_latency_ms", 0) for r in runs if r.get("llm_calls")]

    L = []
    L.append("VALIDATION AGGREGATE SUMMARY (supplementary live study)")
    L.append("=" * 60)
    L.append(f"Completed runs                 : {n}")
    L.append("")
    L.append("CAPTURE / DETECTION")
    L.append("-" * 60)
    L.append(f"Total events captured          : {events}")
    L.append(f"Alert detection rate (planned) : {_rate(detected, len(alert_expected_runs))} "
             f"({detected}/{len(alert_expected_runs)})")
    L.append(f"Benign false-alert rate        : {_rate(benign_with_false, len(benign_runs))} "
             f"({benign_with_false}/{len(benign_runs)})")
    L.append(f"Duplicate-event count          : {duplicates}")
    L.append(f"Cooldown suppressions          : {cooldowns}")
    L.append("")
    L.append("LLM OUTPUT RELIABILITY")
    L.append("-" * 60)
    L.append(f"LLM calls                      : {llm}")
    L.append(f"JSON validity rate             : {_rate(json_valid, llm)}")
    L.append(f"Strict schema-compliance rate  : {_rate(strict_valid, llm)}")
    L.append(f"Fallback rate                  : {_rate(fallback, llm)}")
    L.append(f"Timeout rate                   : {_rate(timeouts, llm)}")
    L.append("")
    L.append("LATENCY across runs (ms, mean of per-run means)")
    L.append("-" * 60)
    for label, vals in (("Detection", det), ("LLM generation", gen), ("End-to-end", e2e)):
        s = summarise_latency(vals)
        L.append(f"{label:<16} n={s['count']:<3} mean={s['mean']:<9} "
                 f"median={s['median']:<9} p95={s['p95']}")
    L.append("")
    L.append("RESULTS BY SCENARIO TYPE")
    L.append("-" * 60)
    types = sorted({r.get("_scenario_type", "UNKNOWN") for r in runs})
    for t in types:
        sub = [r for r in runs if r.get("_scenario_type") == t]
        sub_llm = sum(r.get("llm_calls", 0) for r in sub)
        sub_strict = sum(r.get("strict_schema_valid_count", 0) for r in sub)
        sub_alerts = sum(r.get("alerts_generated", 0) for r in sub)
        L.append(f"  {t:<10} runs={len(sub):<3} alerts={sub_alerts:<3} "
                 f"strict_schema_rate={_rate(sub_strict, sub_llm)}")
    L.append("")
    L.append("RESULTS BY VALIDATION MODE")
    L.append("-" * 60)
    modes = sorted({r.get("mode", "unknown") for r in runs})
    for md in modes:
        sub = [r for r in runs if r.get("mode") == md]
        sub_llm = sum(r.get("llm_calls", 0) for r in sub)
        sub_fallback = sum(r.get("fallback_count", 0) for r in sub)
        L.append(f"  {md:<30} runs={len(sub):<3} fallback_rate={_rate(sub_fallback, sub_llm)}")
    L.append("")
    L.append("NOTE: These supplementary metrics are NOT merged with the frozen")
    L.append("offline 120-scenario baseline/RAG results.")
    return "\n".join(L) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Aggregate live validation runs.")
    ap.add_argument("--root", default=_ROOT, help="Project root (contains validation_outputs/).")
    args = ap.parse_args()

    runs = load_runs(args.root)
    out_csv = os.path.join(args.root, "validation_results.csv")
    out_txt = os.path.join(args.root, "validation_summary.txt")
    write_csv(runs, out_csv)
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(build_summary(runs))
    print(f"Analysed {len(runs)} run(s).")
    print(f"  -> {out_csv}")
    print(f"  -> {out_txt}")


if __name__ == "__main__":
    main()
