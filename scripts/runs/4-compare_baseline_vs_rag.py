#!/usr/bin/env python3
"""
4-compare_baseline_vs_rag.py
============================

Detailed paired comparison of the BASELINE condition (results/baseline/) against
the KNOWLEDGE-AUGMENTED / RAG condition (results/rag/), across all five models on
the identical 120 scenarios.

This script is SEPARATE from 2-evaluate_results.py and does not modify it, the
baseline outputs, or the RAG outputs. It only READS the per-model review CSVs
that 1-run_baseline.py and 3-run_rag.py produced, and writes new comparison
tables + a written report to results/comparison/.

WHY RECOMPUTE FROM THE REVIEW CSVs
----------------------------------
The two runners wrote their own summary .txt files in slightly different formats
(baseline reported metrics over valid outputs; RAG reported all-120 primary plus
valid-only secondary). To compare fairly, EVERY metric here is recomputed from
the raw per-scenario review rows using ONE identical definition for both
conditions. Nothing is taken from the pre-written summaries.

KEY DEFINITIONS (applied identically to both conditions)
--------------------------------------------------------
- A prediction is CLASSIFIABLE if json_valid is TRUE and predicted_class is
  exactly 'normal' or 'abnormal'. Anything else (missing, template-echo such as
  'normal or risky', unparseable) is counted as INVALID.
- PRIMARY accuracy = correct / 120 (invalid counted as wrong).
- SECONDARY accuracy = correct / classifiable (invalid excluded).
- Positive class = abnormal/risky. Recall is the priority metric (a false
  negative is a missed real risk); precision guards against alert fatigue.
- Invalid outputs cannot be TP/TN/FP/FN and are reported as a separate cell.

STATISTICS
----------
- McNemar's exact test (paired, per model): of the 120 scenarios, how many did
  ONLY baseline get right vs ONLY RAG, and is that difference significant.
- Cohen's kappa vs ground truth (chance-corrected agreement), per condition.
- Wilson 95% confidence interval on primary accuracy, per condition.

OUTPUTS (written to ROOT/results/comparison/)
-------------------------------------
- overall_comparison.csv       : every metric, both conditions, all models
- per_category_comparison.csv  : all-120 accuracy per category, baseline vs RAG
- confusion_matrices.txt       : TP/TN/FP/FN/Invalid per model per condition
- mcnemar_tests.csv            : paired test results per model
- scenario_level_changes.csv   : per-scenario, what changed (for error analysis)
- COMPARISON_REPORT.md         : written narrative of what the results show

USAGE
-----
    python 4-compare_baseline_vs_rag.py
    python 4-compare_baseline_vs_rag.py
"""
from __future__ import annotations

import argparse
import csv
import glob
from math import comb, sqrt
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[2]
MODELS = ["deepseek-r1_8b", "gemma3_12b", "gpt-oss_20b", "llama3", "qwen3_8b"]
CATEGORIES = ["NORMAL", "AUTH", "USB", "SEC", "PROC", "NET", "PERSIST"]
VALID_CLASSES = {"normal", "abnormal"}


# --------------------------------------------------------------------------- #
# Loading                                                                      #
# --------------------------------------------------------------------------- #
def load_review(path: str) -> dict[str, dict[str, str]]:
    """Load a per-model review CSV keyed by scenario_id."""
    with open(path, encoding="utf-8-sig") as fh:
        return {r["scenario_id"]: r for r in csv.DictReader(fh)}


def find_review(base_dir: Path, model: str, kind: str) -> str | None:
    """Locate the review CSV for a model under a condition directory."""
    patterns = [
        str(base_dir / model / f"{model}_{kind}_review.csv"),
        str(base_dir / model / f"*{kind}*review*.csv"),
        str(base_dir / model / "*review*.csv"),
    ]
    for p in patterns:
        hits = glob.glob(p)
        if hits:
            return hits[0]
    return None


# --------------------------------------------------------------------------- #
# Core scoring (identical for both conditions)                                 #
# --------------------------------------------------------------------------- #
def is_classifiable(row: dict[str, str]) -> bool:
    if row.get("json_valid", "").strip().upper() != "TRUE":
        return False
    return row.get("predicted_class", "").strip().lower() in VALID_CLASSES


def is_correct(row: dict[str, str]) -> bool:
    """Correct class prediction; invalid rows are never correct."""
    if not is_classifiable(row):
        return False
    return (row.get("predicted_class", "").strip().lower()
            == row.get("ground_truth_class", "").strip().lower())


def confusion(rows: dict[str, dict[str, str]]) -> dict[str, int]:
    c = {"TP": 0, "TN": 0, "FP": 0, "FN": 0, "INVALID": 0}
    for r in rows.values():
        if not is_classifiable(r):
            c["INVALID"] += 1
            continue
        pred = r["predicted_class"].strip().lower()
        gt = r["ground_truth_class"].strip().lower()
        if pred == "abnormal" and gt == "abnormal":
            c["TP"] += 1
        elif pred == "normal" and gt == "normal":
            c["TN"] += 1
        elif pred == "abnormal" and gt == "normal":
            c["FP"] += 1
        elif pred == "normal" and gt == "abnormal":
            c["FN"] += 1
    return c


def wilson_ci(correct: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% CI for a proportion."""
    if n == 0:
        return 0.0, 0.0
    p = correct / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def cohens_kappa(rows: dict[str, dict[str, str]]) -> float:
    """Chance-corrected agreement between prediction and ground truth over
    classifiable rows (2 classes: normal/abnormal)."""
    tab = {("normal", "normal"): 0, ("normal", "abnormal"): 0,
           ("abnormal", "normal"): 0, ("abnormal", "abnormal"): 0}
    n = 0
    for r in rows.values():
        if not is_classifiable(r):
            continue
        pred = r["predicted_class"].strip().lower()
        gt = r["ground_truth_class"].strip().lower()
        tab[(pred, gt)] += 1
        n += 1
    if n == 0:
        return 0.0
    po = (tab[("normal", "normal")] + tab[("abnormal", "abnormal")]) / n
    pred_norm = (tab[("normal", "normal")] + tab[("normal", "abnormal")]) / n
    pred_abn = (tab[("abnormal", "normal")] + tab[("abnormal", "abnormal")]) / n
    gt_norm = (tab[("normal", "normal")] + tab[("abnormal", "normal")]) / n
    gt_abn = (tab[("normal", "abnormal")] + tab[("abnormal", "abnormal")]) / n
    pe = pred_norm * gt_norm + pred_abn * gt_abn
    return (po - pe) / (1 - pe) if (1 - pe) else 0.0


def metrics(rows: dict[str, dict[str, str]]) -> dict[str, Any]:
    c = confusion(rows)
    tp, tn, fp, fn, inv = c["TP"], c["TN"], c["FP"], c["FN"], c["INVALID"]
    n = len(rows)
    scored = tp + tn + fp + fn
    correct = tp + tn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    risk_ok = sum(1 for r in rows.values()
                  if r.get("risk_match", "").strip().upper() == "TRUE")
    ov = [float(r["indicator_overlap"]) for r in rows.values()
          if r.get("indicator_overlap", "") not in ("", "None")]
    lat = [float(r["latency_seconds"]) for r in rows.values()
           if r.get("latency_seconds", "") not in ("", "None")]
    lo, hi = wilson_ci(correct, n)
    return {
        "n": n, "TP": tp, "TN": tn, "FP": fp, "FN": fn, "invalid": inv,
        "acc_all120": correct / n if n else 0.0,
        "acc_valid": correct / scored if scored else 0.0,
        "acc_ci_low": lo, "acc_ci_high": hi,
        "precision": prec, "recall": rec, "f1": f1,
        "risk_accuracy": risk_ok / n if n else 0.0,
        "indicator_overlap": sum(ov) / len(ov) if ov else 0.0,
        "kappa": cohens_kappa(rows),
        "mean_latency": sum(lat) / len(lat) if lat else 0.0,
    }


# --------------------------------------------------------------------------- #
# McNemar's exact paired test                                                  #
# --------------------------------------------------------------------------- #
def mcnemar(base: dict[str, dict[str, str]],
            rag: dict[str, dict[str, str]]) -> dict[str, Any]:
    both = agree_wrong = base_only = rag_only = 0
    changed_ids: list[str] = []
    for scn in base:
        if scn not in rag:
            continue
        bc = is_correct(base[scn])
        rc = is_correct(rag[scn])
        if bc and rc:
            both += 1
        elif not bc and not rc:
            agree_wrong += 1
        elif bc and not rc:
            base_only += 1
            changed_ids.append(f"{scn}(base-only-correct)")
        else:
            rag_only += 1
            changed_ids.append(f"{scn}(rag-only-correct)")
    n = base_only + rag_only               # discordant pairs
    if n == 0:
        p = 1.0
    else:
        k = min(base_only, rag_only)
        p = min(1.0, 2 * sum(comb(n, i) for i in range(0, k + 1)) / (2 ** n))
    return {
        "both_correct": both, "both_wrong": agree_wrong,
        "baseline_only_correct": base_only, "rag_only_correct": rag_only,
        "discordant": n, "p_value": p, "significant_05": p < 0.05,
        "changed_ids": changed_ids,
    }


# --------------------------------------------------------------------------- #
# Per-category                                                                 #
# --------------------------------------------------------------------------- #
def per_category_accuracy(rows: dict[str, dict[str, str]]) -> dict[str, tuple[int, int]]:
    out = {}
    for cat in CATEGORIES:
        cat_rows = [r for r in rows.values() if r.get("category") == cat]
        ok = sum(1 for r in cat_rows if is_correct(r))
        out[cat] = (ok, len(cat_rows))
    return out


# --------------------------------------------------------------------------- #
# Report writing                                                               #
# --------------------------------------------------------------------------- #
def fmt(x: float) -> str:
    return f"{x:.3f}"


def write_all(results: dict[str, Any], out_dir: Path, models: list[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. overall_comparison.csv
    with (out_dir / "overall_comparison.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["model", "condition", "n", "acc_all120", "acc_all120_ci_low",
                    "acc_all120_ci_high", "acc_valid_only", "precision", "recall",
                    "f1", "risk_accuracy", "cohens_kappa", "indicator_overlap",
                    "mean_latency_s", "TP", "TN", "FP", "FN", "invalid"])
        for model in models:
            for cond in ("baseline", "rag"):
                m = results[model][cond]
                w.writerow([model, cond, m["n"], fmt(m["acc_all120"]),
                            fmt(m["acc_ci_low"]), fmt(m["acc_ci_high"]),
                            fmt(m["acc_valid"]), fmt(m["precision"]), fmt(m["recall"]),
                            fmt(m["f1"]), fmt(m["risk_accuracy"]), fmt(m["kappa"]),
                            fmt(m["indicator_overlap"]), fmt(m["mean_latency"]),
                            m["TP"], m["TN"], m["FP"], m["FN"], m["invalid"]])

    # 2. per_category_comparison.csv
    with (out_dir / "per_category_comparison.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["model", "category", "baseline_acc", "rag_acc", "delta", "n"])
        for model in models:
            bpc = results[model]["baseline_percat"]
            rpc = results[model]["rag_percat"]
            for cat in CATEGORIES:
                bok, bn = bpc[cat]
                rok, rn = rpc[cat]
                ba = bok / bn if bn else 0.0
                ra = rok / rn if rn else 0.0
                w.writerow([model, cat, fmt(ba), fmt(ra), fmt(ra - ba), bn])

    # 3. confusion_matrices.txt
    lines = ["CONFUSION MATRICES (positive class = abnormal/risky)",
             "Invalid = json invalid or non-committal class (e.g. template echo)", ""]
    for model in models:
        lines.append(f"### {model}")
        for cond in ("baseline", "rag"):
            m = results[model][cond]
            lines.append(f"  {cond:<9} TP={m['TP']:>3} FP={m['FP']:>3} "
                         f"FN={m['FN']:>3} TN={m['TN']:>3} Invalid={m['invalid']:>3}")
        lines.append("")
    (out_dir / "confusion_matrices.txt").write_text("\n".join(lines), encoding="utf-8")

    # 4. mcnemar_tests.csv
    with (out_dir / "mcnemar_tests.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["model", "both_correct", "both_wrong", "baseline_only_correct",
                    "rag_only_correct", "discordant_pairs", "p_value",
                    "significant_at_0.05", "direction"])
        for model in models:
            mc = results[model]["mcnemar"]
            if mc["rag_only_correct"] > mc["baseline_only_correct"]:
                direction = "RAG better"
            elif mc["baseline_only_correct"] > mc["rag_only_correct"]:
                direction = "baseline better"
            else:
                direction = "tie"
            w.writerow([model, mc["both_correct"], mc["both_wrong"],
                        mc["baseline_only_correct"], mc["rag_only_correct"],
                        mc["discordant"], fmt(mc["p_value"]),
                        "YES" if mc["significant_05"] else "no", direction])

    # 5. scenario_level_changes.csv (error analysis)
    with (out_dir / "scenario_level_changes.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["model", "scenario_id", "category", "ground_truth",
                    "baseline_pred", "baseline_correct", "rag_pred", "rag_correct",
                    "change", "rag_retrieved_docs"])
        for model in models:
            base = results[model]["_rows_base"]
            rag = results[model]["_rows_rag"]
            for scn in sorted(base):
                if scn not in rag:
                    continue
                b, r = base[scn], rag[scn]
                bc, rc = is_correct(b), is_correct(r)
                if bc == rc:
                    change = "same"
                elif rc and not bc:
                    change = "RAG fixed"
                else:
                    change = "RAG broke"
                w.writerow([model, scn, b.get("category", ""),
                            b.get("ground_truth_class", ""),
                            b.get("predicted_class", ""), "Y" if bc else "N",
                            r.get("predicted_class", ""), "Y" if rc else "N",
                            change, r.get("retrieved_doc_ids", "")])

    # 6. COMPARISON_REPORT.md (narrative)
    write_report(results, out_dir / "COMPARISON_REPORT.md", models)


def write_report(results: dict[str, Any], path: Path, models: list[str]) -> None:
    L = ["# Baseline vs Knowledge-Augmented (RAG) — Comparison Report", ""]
    L.append("All metrics are recomputed from the per-scenario review files using "
             "one identical definition for both conditions. Primary accuracy is "
             "over all 120 scenarios (invalid outputs counted as wrong); "
             "valid-only accuracy excludes invalid outputs. Positive class = "
             "abnormal/risky; recall is the priority metric.")
    L.append("")
    L.append("## Overall (primary all-120 accuracy)")
    L.append("")
    L.append("| Model | Baseline acc | RAG acc | Baseline F1 | RAG F1 | "
             "Baseline recall | RAG recall | RAG invalid | McNemar p | Verdict |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for model in models:
        b = results[model]["baseline"]
        r = results[model]["rag"]
        mc = results[model]["mcnemar"]
        if mc["significant_05"] and mc["rag_only_correct"] > mc["baseline_only_correct"]:
            verdict = "RAG better (sig.)"
        elif mc["significant_05"] and mc["baseline_only_correct"] > mc["rag_only_correct"]:
            verdict = "baseline better (sig.)"
        else:
            verdict = "no sig. difference"
        L.append(f"| {model} | {fmt(b['acc_all120'])} | {fmt(r['acc_all120'])} | "
                 f"{fmt(b['f1'])} | {fmt(r['f1'])} | {fmt(b['recall'])} | "
                 f"{fmt(r['recall'])} | {r['invalid']} | {fmt(mc['p_value'])} | {verdict} |")
    L.append("")
    L.append("## How to read this")
    L.append("")
    L.append("- **McNemar's test** compares the two conditions on the SAME 120 "
             "scenarios. It counts how many scenarios only baseline got right "
             "versus only RAG, and tests whether that split is beyond chance. A "
             "significant result (p < 0.05) means the change in that model's "
             "accuracy is unlikely to be random.")
    L.append("- **Invalid outputs** are responses that were not classifiable "
             "(malformed JSON, or a non-committal class such as echoing the "
             "schema example 'normal or risky'). These are counted as wrong in "
             "the primary accuracy and reported separately so a reliability "
             "problem is not hidden inside the accuracy number.")
    L.append("- **Valid-only accuracy** shows how the model did on the responses "
             "it actually committed to; a large gap between all-120 and "
             "valid-only accuracy points to an output-reliability issue rather "
             "than a reasoning one.")
    L.append("")
    L.append("## Per-model notes")
    L.append("")
    for model in models:
        b = results[model]["baseline"]
        r = results[model]["rag"]
        mc = results[model]["mcnemar"]
        note = []
        note.append(f"acc {fmt(b['acc_all120'])}→{fmt(r['acc_all120'])}")
        note.append(f"recall {fmt(b['recall'])}→{fmt(r['recall'])}")
        note.append(f"precision {fmt(b['precision'])}→{fmt(r['precision'])}")
        note.append(f"indicator overlap {fmt(b['indicator_overlap'])}→{fmt(r['indicator_overlap'])}")
        gap = r["acc_valid"] - r["acc_all120"]
        L.append(f"### {model}")
        L.append(f"- {', '.join(note)}.")
        L.append(f"- McNemar: baseline-only-correct={mc['baseline_only_correct']}, "
                 f"rag-only-correct={mc['rag_only_correct']}, p={fmt(mc['p_value'])} "
                 f"({'significant' if mc['significant_05'] else 'not significant'}).")
        if r["invalid"] >= 5:
            L.append(f"- **Output-reliability flag:** {r['invalid']} RAG outputs "
                     f"were invalid/non-committal. Valid-only accuracy is "
                     f"{fmt(r['acc_valid'])} vs all-120 {fmt(r['acc_all120'])} "
                     f"(gap {fmt(gap)}). The longer prompt appears to have harmed "
                     f"structured-output reliability rather than reasoning; the "
                     f"model reasoned acceptably on the responses it committed to.")
        L.append("")
    L.append("## Suggested overall framing")
    L.append("")
    L.append("Report the effect of knowledge augmentation as model-dependent "
             "rather than uniformly positive: state per-model direction, whether "
             "it is statistically significant (McNemar), and treat JSON/schema "
             "validity as a first-class result so that any output-reliability "
             "regression is reported openly rather than absorbed into accuracy.")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="Detailed baseline-vs-RAG comparison.")
    results_dir = ROOT_DIR / "results"
    ap.add_argument("--baseline-dir", default=str(results_dir / "baseline"))
    ap.add_argument("--rag-dir", default=str(results_dir / "rag"))
    ap.add_argument("--out-dir", default=str(results_dir / "comparison"))
    args = ap.parse_args()

    base_dir = Path(args.baseline_dir)
    rag_dir = Path(args.rag_dir)
    out_dir = Path(args.out_dir)

    results: dict[str, Any] = {}
    missing = []
    for model in MODELS:
        bpath = find_review(base_dir, model, "baseline")
        rpath = find_review(rag_dir, model, "rag")
        if not bpath or not rpath:
            missing.append((model, bpath, rpath))
            continue
        base_rows = load_review(bpath)
        rag_rows = load_review(rpath)
        results[model] = {
            "baseline": metrics(base_rows),
            "rag": metrics(rag_rows),
            "baseline_percat": per_category_accuracy(base_rows),
            "rag_percat": per_category_accuracy(rag_rows),
            "mcnemar": mcnemar(base_rows, rag_rows),
            "_rows_base": base_rows,
            "_rows_rag": rag_rows,
        }

    if missing:
        print("WARNING: could not locate review CSVs for:")
        for m, b, r in missing:
            print(f"  {m}: baseline={b} rag={r}")
    if not results:
        raise SystemExit("No models could be compared. Check --baseline-dir and --rag-dir.")

    compared_models = [m for m in MODELS if m in results]
    write_all(results, out_dir, compared_models)
    print(f"Comparison complete for {len(compared_models)} models. Wrote to {out_dir}:")
    for f in ["overall_comparison.csv", "per_category_comparison.csv",
              "confusion_matrices.txt", "mcnemar_tests.csv",
              "scenario_level_changes.csv", "COMPARISON_REPORT.md"]:
        print(f"  - {f}")


if __name__ == "__main__":
    main()
