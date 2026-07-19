#!/usr/bin/env python3
"""
2-evaluate_results.py
=====================

Aggregates the baseline experiment outputs from every model into the metric
tables needed for the dissertation Chapter 4.

INPUTS (read-only)
------------------
* Dataset/ground_truth_FINAL.csv   - the FROZEN authoritative labels (single
                                     source of truth for class, risk, indicators).
* outputs/<model>/<model>_baseline_review.csv  - one row per scenario per model,
                                     produced by 1-run_baseline.py.

The ground truth is joined by scenario_id. We deliberately re-join to the frozen
file rather than trusting any label copied into the review CSV, so the scoring
has one authoritative source that cannot drift.

OUTPUTS (written to results/)
-----------------------------
* overall_metrics.csv        - one row per model: accuracy, precision, recall,
                               F1, risk-level accuracy, indicator overlap
                               (strict AND lenient), JSON validity, latency,
                               TP/FP/TN/FN.
* per_category_metrics.csv   - one row per (model, category): accuracy, P, R, F1,
                               n, plus per-category confusion counts.
* confusion_matrices.txt     - a readable 2x2 confusion matrix per model.
* indicator_overlap_note.txt - strict vs lenient overlap comparison, to show
                               whether low overlap is a real weakness or a
                               vocabulary-matching artifact.

METRIC INTERPRETATION (foregrounded per board feedback)
-------------------------------------------------------
Positive class = risky (abnormal). Recall is the primary metric: a false
negative is a genuine risky action the model failed to flag. Precision is the
counterweight: too many false positives cause alert fatigue. F1 balances them.
Risk-level accuracy checks severity; indicator overlap checks whether the model
cited the right reasons, not just the right label.

USAGE
-----
    python 2-evaluate_results.py
    python 2-evaluate_results.py --models llama3 deepseek-r1:8b gemma3:12b
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------- #
# Paths (script lives in scripts/runs/, dataset root is two levels up)         #
# --------------------------------------------------------------------------- #
ROOT_DIR = Path(__file__).resolve().parents[2]   # scripts\runs\ -> revised\
GROUND_TRUTH_PATH = ROOT_DIR / "Dataset" / "ground_truth_FINAL.csv"
OUTPUTS_DIR = ROOT_DIR / "outputs"
RESULTS_DIR = ROOT_DIR / "results"

# All five models. The evaluator auto-detects which are present, so this list
# just fixes the reporting order (main three first).
MODELS = ["llama3", "deepseek-r1:8b", "gemma3:12b", "qwen3:8b", "gpt-oss:20b"]
CATEGORIES = ["NORMAL", "AUTH", "USB", "SEC", "PROC", "NET", "PERSIST"]


def safe_model_dir(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", model)


# --------------------------------------------------------------------------- #
# Loading                                                                      #
# --------------------------------------------------------------------------- #
def load_ground_truth() -> dict[str, dict[str, str]]:
    """scenario_id -> ground-truth row (authoritative). Proper CSV parsing so
    quoted commas in expected_indicators / label_reason are handled."""
    truth: dict[str, dict[str, str]] = {}
    with GROUND_TRUTH_PATH.open("r", newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            truth[row["scenario_id"]] = row
    return truth


def load_review(model: str) -> list[dict[str, str]]:
    """Load one model's review CSV, or [] if that model wasn't run."""
    path = OUTPUTS_DIR / safe_model_dir(model) / f"{safe_model_dir(model)}_baseline_review.csv"
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- #
# Indicator overlap: strict vs lenient                                         #
# --------------------------------------------------------------------------- #
def tokenise(text: str) -> set[str]:
    """Split an indicator string into normalised word tokens for lenient match."""
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 2}


def overlap_strict(predicted: str, expected: str) -> float:
    """
    Strict overlap: proportion of expected indicators whose exact normalised
    label appears among the predicted indicators. This mirrors the runner's
    scoring and tends to be low when models use near-synonyms.
    """
    exp = [e.strip().lower() for e in re.split(r"[;,]", expected) if e.strip()]
    if not exp:
        return 0.0
    pred_text = predicted.lower()
    hits = sum(1 for e in exp if e in pred_text)
    return hits / len(exp)


def overlap_lenient(predicted: str, expected: str) -> float:
    """
    Lenient overlap: an expected indicator counts as matched if the MAJORITY of
    its content words appear anywhere in the predicted indicators. This credits
    'scheduled task creation' against ground-truth 'scheduled_task_change'
    (shared words: scheduled, task) even though the exact label differs.
    Reveals whether low strict overlap is a vocabulary artifact rather than the
    model genuinely missing the concept.
    """
    exp = [e.strip() for e in re.split(r"[;,]", expected) if e.strip()]
    if not exp:
        return 0.0
    pred_tokens = tokenise(predicted)
    hits = 0
    for e in exp:
        e_tokens = tokenise(e)
        if not e_tokens:
            continue
        shared = e_tokens & pred_tokens
        if len(shared) >= max(1, len(e_tokens) // 2):  # majority of words present
            hits += 1
    return hits / len(exp)


# --------------------------------------------------------------------------- #
# Metric computation                                                           #
# --------------------------------------------------------------------------- #
def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def score_row(row: dict[str, str], truth: dict[str, dict[str, str]]) -> dict[str, Any] | None:
    """
    Re-score one review row against the FROZEN ground truth. Returns a dict of
    per-scenario scored fields, or None if the row was not a parseable/scoreable
    prediction (json invalid, or model echoed the schema template).
    """
    scenario_id = row["scenario_id"]
    gt = truth.get(scenario_id)
    if not gt:
        return None

    pred_class = (row.get("predicted_class") or "").strip().lower()
    # Guard against the template-echo case (e.g. "normal or risky").
    if pred_class not in {"normal", "abnormal"}:
        return {"scoreable": False, "category": gt["category"]}

    gt_class = gt["ground_truth_class"].strip().lower()
    pred_risk = (row.get("predicted_risk") or "").strip().lower()
    gt_risk = gt["ground_truth_risk"].strip().lower()
    pred_inds = row.get("predicted_indicators") or ""
    exp_inds = gt["expected_indicators"]

    # confusion cell (positive = abnormal/risky)
    if pred_class == "abnormal" and gt_class == "abnormal":
        cell = "TP"
    elif pred_class == "normal" and gt_class == "normal":
        cell = "TN"
    elif pred_class == "abnormal" and gt_class == "normal":
        cell = "FP"
    else:
        cell = "FN"

    return {
        "scoreable": True,
        "category": gt["category"],
        "cell": cell,
        "risk_correct": bool(pred_risk) and pred_risk == gt_risk,
        "overlap_strict": overlap_strict(pred_inds, exp_inds),
        "overlap_lenient": overlap_lenient(pred_inds, exp_inds),
        "latency": float(row["latency_seconds"]) if row.get("latency_seconds") else 0.0,
        "json_valid": (row.get("json_valid") or "").upper() == "TRUE",
    }


def evaluate_model(model: str, truth: dict[str, dict[str, str]]) -> dict[str, Any] | None:
    rows = load_review(model)
    if not rows:
        return None

    scored = [score_row(r, truth) for r in rows]
    scored = [s for s in scored if s is not None]
    valid = [s for s in scored if s.get("scoreable")]

    cells = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for s in valid:
        cells[s["cell"]] += 1
    tp, fp, tn, fn = cells["TP"], cells["FP"], cells["TN"], cells["FN"]
    precision, recall, f1 = prf(tp, fp, fn)
    acc = (tp + tn) / len(valid) if valid else 0.0

    n_total = len(rows)
    n_json_valid = sum(1 for r in rows if (r.get("json_valid") or "").upper() == "TRUE")
    n_scoreable = len(valid)

    def mean(key: str) -> float:
        return sum(s[key] for s in valid) / len(valid) if valid else 0.0

    # per-category
    per_cat: dict[str, dict[str, Any]] = {}
    for cat in CATEGORIES:
        sub = [s for s in valid if s["category"] == cat]
        c = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        for s in sub:
            c[s["cell"]] += 1
        p, r, fone = prf(c["TP"], c["FP"], c["FN"])
        a = (c["TP"] + c["TN"]) / len(sub) if sub else 0.0
        per_cat[cat] = {
            "n": len(sub), "accuracy": a, "precision": p, "recall": r, "f1": fone,
            **c,
        }

    return {
        "model": model,
        "n_total": n_total,
        "json_valid": n_json_valid,
        "json_valid_rate": n_json_valid / n_total if n_total else 0.0,
        "scoreable": n_scoreable,
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "accuracy": acc, "precision": precision, "recall": recall, "f1": f1,
        "risk_accuracy": mean("risk_correct"),
        "overlap_strict": mean("overlap_strict"),
        "overlap_lenient": mean("overlap_lenient"),
        "mean_latency": mean("latency"),
        "per_category": per_cat,
    }


# --------------------------------------------------------------------------- #
# Output writers                                                               #
# --------------------------------------------------------------------------- #
def write_overall(results: list[dict[str, Any]]) -> Path:
    path = RESULTS_DIR / "overall_metrics.csv"
    header = ["model", "n_total", "json_valid_rate", "scoreable",
              "accuracy", "precision", "recall", "f1", "risk_accuracy",
              "overlap_strict", "overlap_lenient", "mean_latency",
              "TP", "FP", "TN", "FN"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for r in results:
            w.writerow([
                r["model"], r["n_total"], round(r["json_valid_rate"], 4), r["scoreable"],
                round(r["accuracy"], 4), round(r["precision"], 4), round(r["recall"], 4),
                round(r["f1"], 4), round(r["risk_accuracy"], 4),
                round(r["overlap_strict"], 4), round(r["overlap_lenient"], 4),
                round(r["mean_latency"], 2),
                r["TP"], r["FP"], r["TN"], r["FN"],
            ])
    return path


def write_per_category(results: list[dict[str, Any]]) -> Path:
    path = RESULTS_DIR / "per_category_metrics.csv"
    header = ["model", "category", "n", "accuracy", "precision", "recall", "f1",
              "TP", "FP", "TN", "FN"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for r in results:
            for cat in CATEGORIES:
                pc = r["per_category"][cat]
                w.writerow([
                    r["model"], cat, pc["n"],
                    round(pc["accuracy"], 4), round(pc["precision"], 4),
                    round(pc["recall"], 4), round(pc["f1"], 4),
                    pc["TP"], pc["FP"], pc["TN"], pc["FN"],
                ])
    return path


def write_confusion(results: list[dict[str, Any]]) -> Path:
    path = RESULTS_DIR / "confusion_matrices.txt"
    lines = ["CONFUSION MATRICES (positive class = risky / abnormal)",
             "=" * 60, ""]
    for r in results:
        lines += [
            f"{r['model']}",
            "-" * 40,
            "                 predicted",
            "                 risky   normal",
            f"  actual risky   {r['TP']:>5}   {r['FN']:>5}    (TP / FN)",
            f"  actual normal  {r['FP']:>5}   {r['TN']:>5}    (FP / TN)",
            "",
            f"  Recall (risky caught)   : {r['recall']:.3f}   <- primary metric",
            f"  Precision (flags correct): {r['precision']:.3f}   <- alert-fatigue guard",
            f"  F1                       : {r['f1']:.3f}",
            f"  FN = {r['FN']} genuine risks missed | FP = {r['FP']} false alarms",
            "",
        ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_overlap_note(results: list[dict[str, Any]]) -> Path:
    path = RESULTS_DIR / "indicator_overlap_note.txt"
    lines = [
        "INDICATOR OVERLAP: STRICT vs LENIENT MATCHING",
        "=" * 60,
        "",
        "Strict  = expected indicator's exact label must appear in the model's",
        "          indicator list.",
        "Lenient = expected indicator counts as matched if the majority of its",
        "          content words appear (credits near-synonyms, e.g. model's",
        "          'scheduled task creation' vs ground-truth 'scheduled_task_change').",
        "",
        "If lenient is much higher than strict, the low strict score is largely a",
        "VOCABULARY-MATCHING artifact rather than the model missing the concept.",
        "",
        f"{'model':<16}{'strict':>10}{'lenient':>10}{'gap':>10}",
        "-" * 46,
    ]
    for r in results:
        gap = r["overlap_lenient"] - r["overlap_strict"]
        lines.append(f"{r['model']:<16}{r['overlap_strict']:>10.3f}"
                     f"{r['overlap_lenient']:>10.3f}{gap:>10.3f}")
    lines += ["", "Interpretation: report both. A large gap supports adding a",
              "controlled indicator vocabulary (or lenient scoring) as future work,",
              "and means strict overlap understates the models' actual reasoning."]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Console summary                                                              #
# --------------------------------------------------------------------------- #
def print_summary(results: list[dict[str, Any]]) -> None:
    print("\n" + "=" * 78)
    print("BASELINE EVALUATION SUMMARY (positive class = risky)")
    print("=" * 78)
    print(f"{'model':<16}{'acc':>7}{'prec':>7}{'recall':>8}{'F1':>7}"
          f"{'risk':>7}{'ovl_S':>7}{'ovl_L':>7}{'lat':>7}{'JSON%':>7}")
    print("-" * 78)
    for r in results:
        print(f"{r['model']:<16}{r['accuracy']:>7.3f}{r['precision']:>7.3f}"
              f"{r['recall']:>8.3f}{r['f1']:>7.3f}{r['risk_accuracy']:>7.3f}"
              f"{r['overlap_strict']:>7.3f}{r['overlap_lenient']:>7.3f}"
              f"{r['mean_latency']:>7.1f}{r['json_valid_rate']*100:>6.0f}%")
    print("-" * 78)
    print("recall = primary (missed risks) | ovl_S/L = indicator overlap strict/lenient")


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate baseline model outputs.")
    parser.add_argument("--models", nargs="+", default=MODELS)
    args = parser.parse_args()

    if not GROUND_TRUTH_PATH.exists():
        raise SystemExit(f"Ground truth not found at {GROUND_TRUTH_PATH}")
    truth = load_ground_truth()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    results = []
    for model in args.models:
        r = evaluate_model(model, truth)
        if r is None:
            print(f"[skip] no review CSV found for {model}")
            continue
        results.append(r)

    if not results:
        raise SystemExit("No model outputs found to evaluate.")

    overall = write_overall(results)
    per_cat = write_per_category(results)
    confusion = write_confusion(results)
    overlap = write_overlap_note(results)

    print_summary(results)
    print(f"\nWritten to {RESULTS_DIR}:")
    for p in (overall, per_cat, confusion, overlap):
        print(f"  {p.name}")


if __name__ == "__main__":
    main()