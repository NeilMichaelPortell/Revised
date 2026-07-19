#!/usr/bin/env python3
"""
4-compare_baseline_vs_rag.py
============================

Detailed paired comparison of the BASELINE condition (results/baseline/) against
the KNOWLEDGE-AUGMENTED / RAG condition (results/rag/), across all five models on
the identical 120 scenarios.

This script is SEPARATE from 2-evaluate_results.py and does not modify it, the
baseline outputs, or the RAG outputs. It only READS the per-model review CSVs
that 1-run_baseline.py and 3-run_rag.py produced, plus the frozen ground truth,
and writes new comparison tables + a written report to results/comparison/.

CORRECTED OUTPUT-CATEGORY MODEL (2026-07-19 evidence-integrity pass)
---------------------------------------------------------------------
The previous version of this script excluded every non-classifiable response
from recall, F1 and the class-level metrics ("classifiable" = json_valid AND
predicted_class in {normal, abnormal}). That silently rewarded models for
refusing to commit to a classification: a model that echoed the schema
placeholder ("normal or risky") on every abnormal scenario would have scored
a PERFECT valid-output recall, because none of those refusals were ever in
the recall denominator.

This version distinguishes five, mutually exclusive, exhaustive output
categories for every one of the 120 expected scenarios, per model, per
condition:

    valid_correct     - json basic-schema valid AND predicted_class in
                        {normal, abnormal} AND it matches ground truth.
    valid_incorrect   - as above but predicted_class does NOT match ground
                        truth (a genuine TP/TN/FP/FN cell).
    invalid           - json basic-schema valid (required keys present) but
                        predicted_class is NOT in {normal, abnormal} -- e.g.
                        the template-echo placeholder "normal or risky".
                        Parseable JSON is not necessarily a valid
                        classification.
    missing           - no review/raw record exists at all for this
                        scenario_id. NOT the same bucket as fallback.
    fallback          - a record exists but never reached basic schema
                        validity (json_valid == FALSE, i.e. the required
                        keys classification/risk_level/indicators were never
                        all present after every retry).

In this frozen dataset, "missing" and "fallback" are structurally checked but
turn out to be zero for every model/condition except one exception recorded
in docs/final_audit/EVIDENCE_INVENTORY.md (see there for the full audit);
"invalid" occurs only for deepseek-r1:8b (1/120 baseline, 38/120 RAG).

Every invalid/missing/fallback response counts as UNSUCCESSFUL in primary
("all-scenario") accuracy, and is folded into the coverage-adjusted recall,
false-negative rate, specificity and F1 so that a model cannot inflate its
apparent reliability by refusing to answer. See COMPARISON_REPORT.md for the
full metric definitions and how to read them.

STATISTICS
----------
- McNemar's exact test (paired, per model): of the 120 scenarios, how many did
  ONLY baseline get right vs ONLY RAG (invalid/missing/fallback counted as
  wrong for BOTH conditions), and is that split significant. Holm-Bonferroni
  step-down correction is then applied across the 5 per-model comparisons.
- Cohen's kappa vs ground truth (chance-corrected agreement), computed over
  valid-classification outputs only (labelled as such -- it is not defined
  for a non-committal response).
- Wilson 95% CI on all-scenario (primary) accuracy, per condition.

OUTPUTS (written to ROOT/results/comparison/)
-------------------------------------
- overall_comparison.csv          : the full required metric table (see
                                     REQUIRED_COLUMNS below), one row per
                                     model x condition.
- output_reliability.csv          : coverage / invalid / missing / fallback
                                     breakdown only.
- confusion_and_invalid_counts.csv: confusion cells + invalid/missing/
                                     fallback split by ground-truth class.
- per_category_comparison.csv     : all-scenario accuracy per category,
                                     baseline vs RAG.
- mcnemar_tests.csv               : paired McNemar + Holm results per model.
- scenario_level_changes.csv      : per-scenario, what changed (error
                                     analysis), with output category (not
                                     just correct/incorrect).
- COMPARISON_REPORT.md            : written narrative of what the results
                                     show, primary vs secondary metrics
                                     clearly labelled.
- comparison_summary.json         : machine-readable summary for reuse
                                     (thesis write-up pack, tests).

USAGE
-----
    python 4-compare_baseline_vs_rag.py
"""
from __future__ import annotations

import argparse
import csv
import json
from math import comb, sqrt
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]
MODELS = ["llama3", "deepseek-r1_8b", "gemma3_12b", "qwen3_8b", "gpt-oss_20b"]
CATEGORIES = ["NORMAL", "AUTH", "USB", "SEC", "PROC", "NET", "PERSIST"]
VALID_CLASSES = {"normal", "abnormal"}

# The exact required-column order for overall_comparison.csv (task spec).
REQUIRED_COLUMNS = [
    "model", "condition", "expected_scenarios", "observed_outputs",
    "valid_classification_outputs", "invalid_classification_outputs",
    "missing_outputs", "fallback_outputs", "output_coverage",
    "ground_truth_normal", "ground_truth_abnormal",
    "TP", "TN", "valid_FP", "valid_FN",
    "invalid_normal", "invalid_abnormal",
    "missing_normal", "missing_abnormal",
    "fallback_normal", "fallback_abnormal",
    "all_scenario_accuracy", "valid_output_accuracy",
    "committed_output_precision", "valid_output_recall", "valid_output_f1",
    "coverage_adjusted_recall", "coverage_adjusted_false_negative_rate",
    "coverage_adjusted_specificity", "coverage_adjusted_balanced_accuracy",
    "coverage_adjusted_f1",
    "risk_accuracy_all_scenarios", "indicator_overlap", "mean_latency_seconds",
    "accuracy_ci_low", "accuracy_ci_high", "cohens_kappa_valid_outputs",
]


# --------------------------------------------------------------------------- #
# Loading                                                                      #
# --------------------------------------------------------------------------- #
def load_ground_truth(path: Path) -> dict[str, dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as fh:
        return {r["scenario_id"]: r for r in csv.DictReader(fh)}


def validate_ground_truth_classes(gt: dict[str, dict[str, str]]) -> None:
    """Fail loudly on any ground-truth row whose class is not exactly
    'normal' or 'abnormal'. Without this guard, aggregate_metrics()'s
    normal/abnormal bucketing (`if gt_class == "normal" else abnormal`)
    would silently fold an unexpected label (e.g. an 'unknown' class from a
    corrupted or hand-edited ground-truth file) into the abnormal bucket,
    quietly inflating ground_truth_abnormal and every recall/specificity
    denominator derived from it."""
    bad = {sid: r["ground_truth_class"] for sid, r in gt.items()
           if r["ground_truth_class"].strip().lower() not in VALID_CLASSES}
    if bad:
        raise ValueError(
            f"Ground truth contains {len(bad)} scenario(s) with a class outside "
            f"{VALID_CLASSES}: {bad}. Refusing to silently bucket an unknown "
            f"ground-truth label as normal/abnormal.")


def load_review(path: Path) -> dict[str, dict[str, str]]:
    """Load a per-model review CSV keyed by scenario_id. Returns {} if the
    file does not exist (the caller treats every expected scenario as
    'missing' in that case, rather than crashing)."""
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8-sig") as fh:
        return {r["scenario_id"]: r for r in csv.DictReader(fh)}


def review_path(base_dir: Path, model: str, kind: str) -> Path:
    return base_dir / model / f"{model}_{kind}_review.csv"


# --------------------------------------------------------------------------- #
# Core output-category classification (identical for both conditions)         #
# --------------------------------------------------------------------------- #
def classify_output(row: dict[str, str] | None) -> str:
    """One of 'missing', 'fallback', 'invalid', 'valid_correct',
    'valid_incorrect'. Requires the caller to already know ground truth
    matched separately (see confusion_cell) -- this function only decides
    which of the 5 buckets the row falls into, not correctness."""
    if row is None:
        return "missing"
    if row.get("json_valid", "").strip().upper() != "TRUE":
        return "fallback"
    pred = row.get("predicted_class", "").strip().lower()
    if pred not in VALID_CLASSES:
        return "invalid"
    gt = row.get("_gt_class", "").strip().lower()
    return "valid_correct" if pred == gt else "valid_incorrect"


def confusion_cell(pred: str, gt: str) -> str:
    """TP / TN / valid_FP / valid_FN for a valid (committed) prediction."""
    if pred == "abnormal" and gt == "abnormal":
        return "TP"
    if pred == "normal" and gt == "normal":
        return "TN"
    if pred == "abnormal" and gt == "normal":
        return "valid_FP"
    return "valid_FN"  # pred == "normal" and gt == "abnormal"


# --------------------------------------------------------------------------- #
# Wilson CI + Cohen's kappa                                                    #
# --------------------------------------------------------------------------- #
def wilson_ci(correct: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = correct / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def cohens_kappa(pairs: list[tuple[str, str]]) -> float:
    """Chance-corrected agreement over VALID (committed) predictions only.
    pairs = [(predicted_class, ground_truth_class), ...], both in
    {'normal', 'abnormal'}."""
    tab = {("normal", "normal"): 0, ("normal", "abnormal"): 0,
           ("abnormal", "normal"): 0, ("abnormal", "abnormal"): 0}
    n = len(pairs)
    if n == 0:
        return 0.0
    for pred, gt in pairs:
        tab[(pred, gt)] += 1
    po = (tab[("normal", "normal")] + tab[("abnormal", "abnormal")]) / n
    pred_norm = (tab[("normal", "normal")] + tab[("normal", "abnormal")]) / n
    pred_abn = (tab[("abnormal", "normal")] + tab[("abnormal", "abnormal")]) / n
    gt_norm = (tab[("normal", "normal")] + tab[("abnormal", "normal")]) / n
    gt_abn = (tab[("normal", "abnormal")] + tab[("abnormal", "abnormal")]) / n
    pe = pred_norm * gt_norm + pred_abn * gt_abn
    return (po - pe) / (1 - pe) if (1 - pe) else 0.0


def fmt_p(p: float) -> str:
    """Never render p = 0.000: report '< 0.001' instead."""
    if p is None:
        return "n/a"
    return "< 0.001" if p < 0.001 else f"{p:.3f}"


def fmt(x: float) -> str:
    return f"{x:.4f}"


# --------------------------------------------------------------------------- #
# Per (model, condition) aggregate metrics                                     #
# --------------------------------------------------------------------------- #
def aggregate_metrics(scenario_ids: list[str], gt: dict[str, dict[str, str]],
                      review: dict[str, dict[str, str]]) -> dict[str, Any]:
    counts = {
        "valid_correct": 0, "valid_incorrect": 0, "invalid": 0,
        "missing": 0, "fallback": 0,
        "TP": 0, "TN": 0, "valid_FP": 0, "valid_FN": 0,
        "invalid_normal": 0, "invalid_abnormal": 0,
        "missing_normal": 0, "missing_abnormal": 0,
        "fallback_normal": 0, "fallback_abnormal": 0,
    }
    gt_normal = gt_abnormal = 0
    risk_correct_all = 0
    overlaps: list[float] = []
    latencies: list[float] = []
    kappa_pairs: list[tuple[str, str]] = []
    per_scenario: dict[str, dict[str, Any]] = {}

    for sid in scenario_ids:
        gt_row = gt[sid]
        gt_class = gt_row["ground_truth_class"].strip().lower()
        if gt_class == "normal":
            gt_normal += 1
        else:
            gt_abnormal += 1

        row = review.get(sid)
        row_with_gt = dict(row) if row else None
        if row_with_gt is not None:
            row_with_gt["_gt_class"] = gt_class
        category = classify_output(row_with_gt)
        counts[category] += 1

        pred = ""
        cell = ""
        if category in ("valid_correct", "valid_incorrect"):
            pred = row["predicted_class"].strip().lower()
            cell = confusion_cell(pred, gt_class)
            counts[cell] += 1
            kappa_pairs.append((pred, gt_class))
            ov = row.get("indicator_overlap", "")
            if ov not in ("", None, "None"):
                overlaps.append(float(ov))
            if row.get("risk_match", "").strip().upper() == "TRUE":
                risk_correct_all += 1
        elif category in ("invalid", "fallback", "missing"):
            counts[f"{category}_{gt_class}"] += 1

        if row is not None:
            lat = row.get("latency_seconds", "")
            if lat not in ("", None, "None"):
                latencies.append(float(lat))

        per_scenario[sid] = {
            "category": category, "predicted_class": pred, "cell": cell,
            "ground_truth_class": gt_class,
        }

    n = len(scenario_ids)
    observed = n - counts["missing"]
    valid_n = counts["valid_correct"] + counts["valid_incorrect"]
    tp, tn = counts["TP"], counts["TN"]
    vfp, vfn = counts["valid_FP"], counts["valid_FN"]

    abnormal_failures = (vfn + counts["invalid_abnormal"]
                         + counts["missing_abnormal"] + counts["fallback_abnormal"])
    normal_failures = (vfp + counts["invalid_normal"]
                       + counts["missing_normal"] + counts["fallback_normal"])

    committed_precision = tp / (tp + vfp) if (tp + vfp) else 0.0
    valid_recall = tp / (tp + vfn) if (tp + vfn) else 0.0
    valid_f1 = (2 * committed_precision * valid_recall / (committed_precision + valid_recall)
               if (committed_precision + valid_recall) else 0.0)

    coverage_adjusted_recall = tp / gt_abnormal if gt_abnormal else 0.0
    coverage_adjusted_fnr = abnormal_failures / gt_abnormal if gt_abnormal else 0.0
    coverage_adjusted_specificity = tn / gt_normal if gt_normal else 0.0
    coverage_adjusted_bal_acc = (coverage_adjusted_recall + coverage_adjusted_specificity) / 2
    cov_f1_denom = (2 * tp + vfp + vfn + counts["invalid_abnormal"]
                   + counts["missing_abnormal"] + counts["fallback_abnormal"])
    coverage_adjusted_f1 = (2 * tp / cov_f1_denom) if cov_f1_denom else 0.0

    all_scenario_accuracy = counts["valid_correct"] / n if n else 0.0
    valid_output_accuracy = counts["valid_correct"] / valid_n if valid_n else 0.0
    ci_low, ci_high = wilson_ci(counts["valid_correct"], n)
    kappa = cohens_kappa(kappa_pairs)

    return {
        "expected_scenarios": n, "observed_outputs": observed,
        "valid_classification_outputs": valid_n,
        "invalid_classification_outputs": counts["invalid"],
        "missing_outputs": counts["missing"], "fallback_outputs": counts["fallback"],
        "output_coverage": observed / n if n else 0.0,
        "ground_truth_normal": gt_normal, "ground_truth_abnormal": gt_abnormal,
        "TP": tp, "TN": tn, "valid_FP": vfp, "valid_FN": vfn,
        "invalid_normal": counts["invalid_normal"], "invalid_abnormal": counts["invalid_abnormal"],
        "missing_normal": counts["missing_normal"], "missing_abnormal": counts["missing_abnormal"],
        "fallback_normal": counts["fallback_normal"], "fallback_abnormal": counts["fallback_abnormal"],
        "all_scenario_accuracy": all_scenario_accuracy,
        "valid_output_accuracy": valid_output_accuracy,
        "committed_output_precision": committed_precision,
        "valid_output_recall": valid_recall, "valid_output_f1": valid_f1,
        "coverage_adjusted_recall": coverage_adjusted_recall,
        "coverage_adjusted_false_negative_rate": coverage_adjusted_fnr,
        "coverage_adjusted_specificity": coverage_adjusted_specificity,
        "coverage_adjusted_balanced_accuracy": coverage_adjusted_bal_acc,
        "coverage_adjusted_f1": coverage_adjusted_f1,
        "risk_accuracy_all_scenarios": risk_correct_all / n if n else 0.0,
        "indicator_overlap": sum(overlaps) / len(overlaps) if overlaps else 0.0,
        "mean_latency_seconds": sum(latencies) / len(latencies) if latencies else 0.0,
        "accuracy_ci_low": ci_low, "accuracy_ci_high": ci_high,
        "cohens_kappa_valid_outputs": kappa,
        "abnormal_failures": abnormal_failures, "normal_failures": normal_failures,
        "_per_scenario": per_scenario,
    }


def per_category_accuracy(scenario_ids: list[str], gt: dict[str, dict[str, str]],
                          per_scenario: dict[str, dict[str, Any]]) -> dict[str, tuple[int, int]]:
    out = {}
    for cat in CATEGORIES:
        ids = [sid for sid in scenario_ids if gt[sid]["category"] == cat]
        ok = sum(1 for sid in ids if per_scenario[sid]["category"] == "valid_correct")
        out[cat] = (ok, len(ids))
    return out


# --------------------------------------------------------------------------- #
# McNemar's exact paired test + Holm-Bonferroni                                #
# --------------------------------------------------------------------------- #
def exact_mcnemar(base_ps: dict[str, dict[str, Any]],
                  rag_ps: dict[str, dict[str, Any]]) -> dict[str, Any]:
    both = both_wrong = base_only = rag_only = 0
    for sid in base_ps:
        if sid not in rag_ps:
            continue
        bc = base_ps[sid]["category"] == "valid_correct"
        rc = rag_ps[sid]["category"] == "valid_correct"
        if bc and rc:
            both += 1
        elif not bc and not rc:
            both_wrong += 1
        elif bc and not rc:
            base_only += 1
        else:
            rag_only += 1
    n = base_only + rag_only
    if n == 0:
        p = 1.0
    else:
        k = min(base_only, rag_only)
        p = min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / (2 ** n))
    return {"both_correct": both, "both_wrong": both_wrong,
            "baseline_only_correct": base_only, "rag_only_correct": rag_only,
            "discordant_pairs": n, "raw_p_value": p}


def holm_adjust(pairs: list[tuple[str, float]]) -> dict[str, float]:
    """Holm-Bonferroni step-down across models. pairs = [(model, raw_p), ...]."""
    m = len(pairs)
    ordered = sorted(pairs, key=lambda x: x[1])
    out: dict[str, float] = {}
    prev = 0.0
    for i, (label, p) in enumerate(ordered):
        adj = min(1.0, (m - i) * p)
        adj = max(adj, prev)
        prev = adj
        out[label] = adj
    return out


# --------------------------------------------------------------------------- #
# Report writing                                                               #
# --------------------------------------------------------------------------- #
def write_overall(results: dict[str, Any], out_dir: Path, models: list[str]) -> None:
    with (out_dir / "overall_comparison.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(REQUIRED_COLUMNS)
        for model in models:
            for cond in ("baseline", "rag"):
                m = results[model][cond]
                row = [model, cond]
                for col in REQUIRED_COLUMNS[2:]:
                    v = m[col]
                    row.append(fmt(v) if isinstance(v, float) else v)
                w.writerow(row)


def write_output_reliability(results: dict[str, Any], out_dir: Path, models: list[str]) -> None:
    cols = ["model", "condition", "expected_scenarios", "observed_outputs",
            "valid_classification_outputs", "invalid_classification_outputs",
            "missing_outputs", "fallback_outputs", "output_coverage",
            "invalid_normal", "invalid_abnormal", "missing_normal", "missing_abnormal",
            "fallback_normal", "fallback_abnormal"]
    with (out_dir / "output_reliability.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for model in models:
            for cond in ("baseline", "rag"):
                m = results[model][cond]
                w.writerow([model, cond] + [
                    fmt(m[c]) if isinstance(m[c], float) else m[c] for c in cols[2:]
                ])


def write_confusion_and_invalid(results: dict[str, Any], out_dir: Path, models: list[str]) -> None:
    cols = ["model", "condition", "ground_truth_normal", "ground_truth_abnormal",
            "TP", "TN", "valid_FP", "valid_FN", "invalid_normal", "invalid_abnormal",
            "missing_normal", "missing_abnormal", "fallback_normal", "fallback_abnormal"]
    with (out_dir / "confusion_and_invalid_counts.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for model in models:
            for cond in ("baseline", "rag"):
                m = results[model][cond]
                w.writerow([model, cond] + [m[c] for c in cols[2:]])


def write_per_category(results: dict[str, Any], out_dir: Path, models: list[str]) -> None:
    with (out_dir / "per_category_comparison.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["model", "category", "baseline_all_scenario_accuracy",
                    "rag_all_scenario_accuracy", "delta", "n"])
        for model in models:
            bpc = results[model]["baseline_percat"]
            rpc = results[model]["rag_percat"]
            for cat in CATEGORIES:
                bok, bn = bpc[cat]
                rok, rn = rpc[cat]
                ba = bok / bn if bn else 0.0
                ra = rok / rn if rn else 0.0
                w.writerow([model, cat, fmt(ba), fmt(ra), fmt(ra - ba), bn])


def write_mcnemar(results: dict[str, Any], out_dir: Path, models: list[str]) -> None:
    pairs = [(m, results[m]["mcnemar"]["raw_p_value"]) for m in models]
    holm = holm_adjust(pairs)
    with (out_dir / "mcnemar_tests.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["model", "both_correct", "both_wrong", "baseline_only_correct",
                    "rag_only_correct", "discordant_pairs", "exact_mcnemar_raw_p",
                    "holm_adjusted_p", "significant_at_0.05_holm",
                    "change_in_correct_predictions", "change_in_abnormal_failures",
                    "change_in_normal_failures", "direction"])
        for model in models:
            mc = results[model]["mcnemar"]
            hp = holm[model]
            b, r = results[model]["baseline"], results[model]["rag"]
            change_correct = r["_raw_correct"] - b["_raw_correct"]
            change_abn_fail = r["abnormal_failures"] - b["abnormal_failures"]
            change_norm_fail = r["normal_failures"] - b["normal_failures"]
            sig = hp < 0.05
            if not sig:
                direction = "no significant difference"
            elif mc["rag_only_correct"] > mc["baseline_only_correct"]:
                direction = "RAG significantly better"
            elif mc["baseline_only_correct"] > mc["rag_only_correct"]:
                direction = "baseline significantly better"
            else:
                direction = "no significant difference"
            w.writerow([model, mc["both_correct"], mc["both_wrong"],
                        mc["baseline_only_correct"], mc["rag_only_correct"],
                        mc["discordant_pairs"], fmt_p(mc["raw_p_value"]), fmt_p(hp),
                        "YES" if sig else "no", change_correct, change_abn_fail,
                        change_norm_fail, direction])


def write_scenario_changes(results: dict[str, Any], out_dir: Path, models: list[str],
                          rag_review: dict[str, dict[str, dict[str, str]]]) -> None:
    with (out_dir / "scenario_level_changes.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["model", "scenario_id", "category", "ground_truth_class",
                    "baseline_output_category", "baseline_predicted_class",
                    "rag_output_category", "rag_predicted_class",
                    "change", "rag_retrieved_doc_ids"])
        for model in models:
            base_ps = results[model]["baseline"]["_per_scenario"]
            rag_ps = results[model]["rag"]["_per_scenario"]
            gt = results["_gt"]
            for sid in sorted(base_ps):
                if sid not in rag_ps:
                    continue
                b, r = base_ps[sid], rag_ps[sid]
                bc = b["category"] == "valid_correct"
                rc = r["category"] == "valid_correct"
                if bc == rc:
                    change = "same"
                elif rc and not bc:
                    change = "RAG fixed"
                else:
                    change = "RAG broke"
                rag_row = rag_review.get(model, {}).get(sid, {})
                w.writerow([model, sid, gt[sid]["category"], gt[sid]["ground_truth_class"],
                            b["category"], b["predicted_class"] or "(none)",
                            r["category"], r["predicted_class"] or "(none)",
                            change, rag_row.get("retrieved_doc_ids", "")])


def write_report(results: dict[str, Any], out_dir: Path, models: list[str],
                deepseek_check: dict[str, Any] | None) -> None:
    L = ["# Baseline vs Knowledge-Augmented (RAG) -- Comparison Report", ""]
    L.append(
        "All metrics are recomputed from the per-scenario review files, re-joined "
        "to the frozen ground truth (`Dataset/ground_truth_FINAL.csv`), using one "
        "identical definition for both conditions. Every one of the 120 expected "
        "scenarios is classified into exactly one output category: "
        "**valid_correct**, **valid_incorrect**, **invalid** (parseable but a "
        "non-committal/placeholder classification), **missing** (no record at "
        "all), or **fallback** (a record exists but never reached basic schema "
        "validity). Invalid, missing and fallback outputs are never dropped from "
        "a denominator -- they count as unsuccessful."
    )
    L.append("")
    L.append("## Primary vs secondary metrics")
    L.append("")
    L.append(
        "- **PRIMARY**: `all_scenario_accuracy` (correct / 120, every non-valid "
        "response counted wrong) and the **coverage-adjusted** recall / false-"
        "negative-rate / specificity / balanced-accuracy / F1 (denominators are "
        "the full ground-truth abnormal/normal counts, 58/62; invalid, missing "
        "and fallback abnormal outputs count as missed detections). These are "
        "the numbers that should be quoted as *the* result."
    )
    L.append(
        "- **SECONDARY**: `valid_output_accuracy`, `committed_output_precision`, "
        "`valid_output_recall`, `valid_output_f1` and `cohens_kappa_valid_outputs` "
        "are computed over valid (committed) classifications only. They answer "
        "\"how good is the model when it commits to an answer\", which is a "
        "useful diagnostic but must never be quoted as the headline result, "
        "because it is not adjusted for how often the model failed to commit."
    )
    L.append("")
    L.append("## Overall (PRIMARY: all-scenario accuracy + coverage-adjusted recall)")
    L.append("")
    L.append("| Model | Cond | All-scenario acc | Cov-adj recall | Cov-adj specificity | "
             "Cov-adj F1 | Invalid | Missing | Fallback |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for model in models:
        for cond in ("baseline", "rag"):
            m = results[model][cond]
            L.append(f"| {model} | {cond} | {fmt(m['all_scenario_accuracy'])} | "
                     f"{fmt(m['coverage_adjusted_recall'])} | "
                     f"{fmt(m['coverage_adjusted_specificity'])} | "
                     f"{fmt(m['coverage_adjusted_f1'])} | "
                     f"{m['invalid_classification_outputs']} | {m['missing_outputs']} | "
                     f"{m['fallback_outputs']} |")
    L.append("")
    L.append("## McNemar's exact test + Holm-Bonferroni correction (5 models)")
    L.append("")
    L.append("| Model | Baseline-only correct | RAG-only correct | Discordant | Raw p | Holm p | Verdict |")
    L.append("|---|---|---|---|---|---|---|")
    pairs = [(m, results[m]["mcnemar"]["raw_p_value"]) for m in models]
    holm = holm_adjust(pairs)
    for model in models:
        mc = results[model]["mcnemar"]
        hp = holm[model]
        sig = hp < 0.05
        if not sig:
            verdict = "not statistically significant"
        elif mc["rag_only_correct"] > mc["baseline_only_correct"]:
            verdict = "**statistically significant improvement**"
        else:
            verdict = "**statistically significant deterioration**"
        L.append(f"| {model} | {mc['baseline_only_correct']} | {mc['rag_only_correct']} | "
                 f"{mc['discordant_pairs']} | {fmt_p(mc['raw_p_value'])} | {fmt_p(hp)} | {verdict} |")
    L.append("")
    L.append(
        "McNemar treats invalid, missing and fallback outputs as incorrect for "
        "the paired correctness used above (a model that stops committing to a "
        "classification under RAG is scored as having gotten those scenarios "
        "wrong, not as unscored). Holm-Bonferroni is applied across the 5 "
        "per-model comparisons; p-values below 0.001 are reported as `< 0.001` "
        "rather than `0.000`."
    )
    L.append("")
    if deepseek_check is not None:
        L.append("## DeepSeek RAG acceptance check")
        L.append("")
        ok = "PASSED" if deepseek_check["ok"] else "FAILED -- INVESTIGATE"
        L.append(f"Status: **{ok}**")
        L.append("")
        L.append("| Quantity | Expected (approx.) | Observed |")
        L.append("|---|---|---|")
        for label, expected, observed in deepseek_check["rows"]:
            L.append(f"| {label} | {expected} | {observed} |")
        L.append("")
    L.append("## Per-model notes")
    L.append("")
    for model in models:
        b, r = results[model]["baseline"], results[model]["rag"]
        mc = results[model]["mcnemar"]
        L.append(f"### {model}")
        L.append(
            f"- All-scenario accuracy: {fmt(b['all_scenario_accuracy'])} -> "
            f"{fmt(r['all_scenario_accuracy'])}. Coverage-adjusted recall: "
            f"{fmt(b['coverage_adjusted_recall'])} -> {fmt(r['coverage_adjusted_recall'])}. "
            f"Coverage-adjusted specificity: {fmt(b['coverage_adjusted_specificity'])} -> "
            f"{fmt(r['coverage_adjusted_specificity'])}."
        )
        L.append(
            f"- McNemar: baseline-only-correct={mc['baseline_only_correct']}, "
            f"rag-only-correct={mc['rag_only_correct']}, raw p={fmt_p(mc['raw_p_value'])}, "
            f"Holm p={fmt_p(holm[model])}."
        )
        if r["invalid_classification_outputs"] >= 5:
            L.append(
                f"- **Output-reliability flag:** {r['invalid_classification_outputs']} "
                f"RAG outputs were invalid (non-committal placeholder classification), "
                f"vs {b['invalid_classification_outputs']} under baseline. Valid-output "
                f"accuracy is {fmt(r['valid_output_accuracy'])} (secondary; excludes "
                f"invalid outputs) vs all-scenario accuracy {fmt(r['all_scenario_accuracy'])} "
                f"(primary; invalid counted wrong) -- the gap shows the longer RAG prompt "
                f"harmed structured-output reliability more than it harmed reasoning on "
                f"the scenarios the model still committed to."
            )
        L.append("")
    L.append("## Suggested overall framing")
    L.append("")
    L.append(
        "Report the effect of knowledge augmentation as **model-dependent**, not "
        "uniformly positive or negative: state each model's direction, whether it "
        "is statistically significant after Holm correction, and always quote the "
        "coverage-adjusted / all-scenario (primary) numbers rather than the "
        "valid-output-only (secondary) numbers as the headline result."
    )
    (out_dir / "COMPARISON_REPORT.md").write_text("\n".join(L) + "\n", encoding="utf-8")


def deepseek_acceptance_check(results: dict[str, Any]) -> dict[str, Any]:
    r = results["deepseek-r1_8b"]["rag"]
    rows = [
        ("Expected scenarios", "120", r["expected_scenarios"]),
        ("Correct classifications (valid_correct)", "75",
         results["deepseek-r1_8b"]["rag"]["_raw_correct"]),
        ("All-scenario accuracy", "0.625", fmt(r["all_scenario_accuracy"])),
        ("Invalid/non-committal outputs", "38", r["invalid_classification_outputs"]),
        ("Invalid abnormal outputs", "24", r["invalid_abnormal"]),
        ("True-positive abnormal detections", "29", r["TP"]),
        ("Ground-truth abnormal scenarios", "58", r["ground_truth_abnormal"]),
        ("Coverage-adjusted abnormal recall", "0.500", fmt(r["coverage_adjusted_recall"])),
    ]
    ok = (r["_raw_correct"] == 75 and r["invalid_classification_outputs"] == 38
         and r["invalid_abnormal"] == 24 and r["TP"] == 29
         and r["ground_truth_abnormal"] == 58
         and abs(r["coverage_adjusted_recall"] - 0.5) < 1e-9)
    return {"ok": ok, "rows": rows}


def write_comparison_summary_json(results: dict[str, Any], out_dir: Path,
                                  models: list[str],
                                  deepseek_check: dict[str, Any] | None) -> None:
    pairs = [(m, results[m]["mcnemar"]["raw_p_value"]) for m in models]
    holm = holm_adjust(pairs)
    summary = {
        "models": {},
        "deepseek_rag_acceptance_check": (deepseek_check["ok"] if deepseek_check is not None else None),
    }
    for model in models:
        b, r = results[model]["baseline"], results[model]["rag"]
        mc = results[model]["mcnemar"]
        summary["models"][model] = {
            "baseline": {k: v for k, v in b.items() if not k.startswith("_")},
            "rag": {k: v for k, v in r.items() if not k.startswith("_")},
            "mcnemar_raw_p": mc["raw_p_value"], "mcnemar_holm_p": holm[model],
            "mcnemar_significant_holm_0.05": holm[model] < 0.05,
            "baseline_only_correct": mc["baseline_only_correct"],
            "rag_only_correct": mc["rag_only_correct"],
        }
    (out_dir / "comparison_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="Detailed baseline-vs-RAG comparison.")
    results_dir = ROOT_DIR / "results"
    ap.add_argument("--baseline-dir", default=str(results_dir / "baseline"))
    ap.add_argument("--rag-dir", default=str(results_dir / "rag"))
    ap.add_argument("--out-dir", default=str(results_dir / "comparison"))
    ap.add_argument("--ground-truth", default=str(ROOT_DIR / "Dataset" / "ground_truth_FINAL.csv"))
    args = ap.parse_args()

    base_dir = Path(args.baseline_dir)
    rag_dir = Path(args.rag_dir)
    out_dir = Path(args.out_dir)
    gt = load_ground_truth(Path(args.ground_truth))
    validate_ground_truth_classes(gt)
    scenario_ids = sorted(gt.keys())

    results: dict[str, Any] = {"_gt": gt}
    rag_review_by_model: dict[str, dict[str, dict[str, str]]] = {}
    missing_models = []
    for model in MODELS:
        bpath = review_path(base_dir, model, "baseline")
        rpath = review_path(rag_dir, model, "rag")
        base_rows = load_review(bpath)
        rag_rows = load_review(rpath)
        if not base_rows and not rag_rows:
            missing_models.append(model)
            continue
        rag_review_by_model[model] = rag_rows

        base_m = aggregate_metrics(scenario_ids, gt, base_rows)
        rag_m = aggregate_metrics(scenario_ids, gt, rag_rows)
        base_m["_raw_correct"] = base_m["TP"] + base_m["TN"]
        rag_m["_raw_correct"] = rag_m["TP"] + rag_m["TN"]

        results[model] = {
            "baseline": base_m, "rag": rag_m,
            "baseline_percat": per_category_accuracy(scenario_ids, gt, base_m["_per_scenario"]),
            "rag_percat": per_category_accuracy(scenario_ids, gt, rag_m["_per_scenario"]),
            "mcnemar": exact_mcnemar(base_m["_per_scenario"], rag_m["_per_scenario"]),
        }

    if missing_models:
        print(f"WARNING: no review CSVs found for: {missing_models}")
    compared_models = [m for m in MODELS if m in results]
    if not compared_models:
        raise SystemExit("No models could be compared. Check --baseline-dir and --rag-dir.")

    out_dir.mkdir(parents=True, exist_ok=True)
    write_overall(results, out_dir, compared_models)
    write_output_reliability(results, out_dir, compared_models)
    write_confusion_and_invalid(results, out_dir, compared_models)
    write_per_category(results, out_dir, compared_models)
    write_mcnemar(results, out_dir, compared_models)
    write_scenario_changes(results, out_dir, compared_models, rag_review_by_model)

    deepseek_check = None
    if "deepseek-r1_8b" in results:
        deepseek_check = deepseek_acceptance_check(results)
        status = "PASSED" if deepseek_check["ok"] else "FAILED"
        print(f"DeepSeek RAG acceptance check: {status}")
        if not deepseek_check["ok"]:
            for label, expected, observed in deepseek_check["rows"]:
                print(f"  {label}: expected~{expected} observed={observed}")

    write_report(results, out_dir, compared_models, deepseek_check)
    write_comparison_summary_json(results, out_dir, compared_models, deepseek_check)

    print(f"Comparison complete for {len(compared_models)} models. Wrote to {out_dir}:")
    for f in ["overall_comparison.csv", "output_reliability.csv",
              "confusion_and_invalid_counts.csv", "per_category_comparison.csv",
              "mcnemar_tests.csv", "scenario_level_changes.csv",
              "COMPARISON_REPORT.md", "comparison_summary.json"]:
        print(f"  - {f}")


if __name__ == "__main__":
    main()
