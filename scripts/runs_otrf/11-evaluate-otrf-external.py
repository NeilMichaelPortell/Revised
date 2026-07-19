#!/usr/bin/env python3
"""
11-evaluate-otrf-external.py
============================

Evaluator for the supplementary OTRF external validation. Joins model outputs to
the external answer key ONLY here (never during inference). Keeps invalid and
missing outputs in the denominator. Reports metrics appropriate to an
abnormal-dominated public sample and explicitly marks metrics that are not
estimable.

Denominator rules (enforced here, not left to convention):
  * The expected denominator for every rate is the full set of scenarios in the
    frozen manifest/answer key -- missing outputs are never dropped.
  * A MISSING output (no record at all) is counted as missing_output, which is
    NOT the same bucket as a FALLBACK (a record exists but never reached basic
    JSON schema validity after retries). Both count as abnormal misses when the
    ground truth is abnormal, but they are reported in separate columns.
  * Ground truth "unknown" (a manifest label that mapped to neither abnormal
    nor benign) is excluded from the abnormal/benign detection counts AND from
    the paired baseline-vs-RAG correctness used for McNemar. It is never
    treated as abnormal by default.
  * Duplicate outputs and any manifest source/neutral-input hash drift FAIL
    evaluation by default (see --allow-duplicates / --allow-hash-drift).
  * A benign-truth scenario with an invalid/missing prediction counts as an
    UNSUCCESSFUL prediction against specificity's denominator whenever
    specificity is estimable (i.e. it is not silently dropped from the benign
    subset the way a naive "only usable predictions count" rule would do).
  * Output coverage (how many of the expected scenarios actually produced a
    model record at all) is reported as its own column, separate from
    correctness/validity rates.

It does NOT compare OTRF numbers to the 120-scenario accuracy results and does
not claim organisational real-world validation.

Usage:
    python 11-evaluate-otrf-external.py --config external_validation/config/otrf_external_config.json
    python 11-evaluate-otrf-external.py --config <cfg> --allow-duplicates --allow-hash-drift
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import otrf_common as oc  # noqa: E402

CONDITIONS = ["baseline", "rag"]
NOT_ESTIMABLE = "not_estimable"


def load_answer_key() -> dict[str, dict[str, str]]:
    key = {}
    for row in oc.read_csv(oc.EXTERNAL_GROUND_TRUTH_PATH):
        key[row["external_scenario_id"]] = row
    return key


def load_manifest() -> list[dict[str, str]]:
    return oc.read_csv(oc.FROZEN_MANIFEST_PATH)


def load_condition_outputs(condition: str) -> dict[str, dict[str, list[dict]]]:
    """{model: {ext_id: [records]}} for a condition. Lists let us detect dupes."""
    out_dir = oc.OUTPUTS_BASELINE_DIR if condition == "baseline" else oc.OUTPUTS_RAG_DIR
    result: dict[str, dict[str, list[dict]]] = {}
    if not out_dir.exists():
        return result
    for model_dir in sorted(out_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        raw = model_dir / f"{model_dir.name}_{condition}_raw.jsonl"
        by_id: dict[str, list[dict]] = {}
        for rec in oc.read_jsonl(raw):
            by_id.setdefault(rec["external_scenario_id"], []).append(rec)
        result[model_dir.name] = by_id
    return result


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="OTRF external evaluator.")
    ap.add_argument("--config", default=str(oc.DEFAULT_CONFIG_PATH),
                    help="Path to the run config JSON. Defaults to "
                         f"{oc.DEFAULT_CONFIG_PATH} if omitted.")
    ap.add_argument("--allow-duplicates", action="store_true",
                    help="Proceed even if duplicate scenario outputs are found. Off by "
                         "default: duplicates fail evaluation.")
    ap.add_argument("--allow-hash-drift", action="store_true",
                    help="Proceed even if manifest source/neutral-input hashes have "
                         "drifted since preparation. Off by default: drift fails evaluation.")
    args = ap.parse_args(argv)
    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    models = cfg.get("models", oc.MODELS)
    model_dirs = [oc.safe_model_dir(m) for m in models]

    answer_key = load_answer_key()
    manifest = load_manifest()
    vocab = oc.load_controlled_vocabulary()

    if not answer_key:
        raise SystemExit("No external answer key found. Run 8-prepare-otrf-external.py first.")

    # ---- SHA-256 enforcement: fail by default on manifest drift --------------
    integrity_violations = oc.verify_manifest_integrity(manifest)
    try:
        oc.require_no_violations(integrity_violations,
                                 "frozen manifest vs. current source/neutral inputs",
                                 args.allow_hash_drift)
    except oc.IntegrityError as exc:
        raise SystemExit(str(exc))

    scenario_ids = sorted(answer_key.keys())
    abnormal_ids = [s for s in scenario_ids if answer_key[s]["external_class"] == "abnormal"]
    benign_ids = [s for s in scenario_ids
                  if answer_key[s]["external_class"] in {"normal", "benign"}]
    unknown_ids = [s for s in scenario_ids
                   if answer_key[s]["external_class"] not in {"abnormal", "normal", "benign"}]
    has_benign = len(benign_ids) > 0
    sev_ids = [s for s in scenario_ids
               if answer_key[s].get("severity_if_provided", "not_provided")
               in {"low", "medium", "high", "critical"}]
    has_severity_key = len(sev_ids) > 0

    oc.EVALUATION_DIR.mkdir(parents=True, exist_ok=True)

    # ---- manifest hash re-verification (reported, in addition to the fail-by-
    # default gate above) -----------------------------------------------------
    hash_rows = []
    for row in manifest:
        ext_id = row["external_scenario_id"]
        neutral_path = oc.NEUTRAL_INPUTS_DIR / f"{ext_id}.json"
        current = oc.sha256_text(neutral_path.read_text(encoding="utf-8")) if neutral_path.exists() else "missing"
        source_path = oc.resolve_source_path(row.get("source_path", ""))
        current_source = oc.sha256_file(source_path)
        hash_rows.append({
            "external_scenario_id": ext_id,
            "manifest_neutral_hash": row.get("neutral_input_hash", ""),
            "current_neutral_hash": current,
            "neutral_match": str(current == row.get("neutral_input_hash", "")).upper(),
            "manifest_source_hash": row.get("source_hash", ""),
            "current_source_hash": current_source,
            "source_match": str(current_source == row.get("source_hash", "")).upper(),
        })
    oc.write_csv(oc.EVALUATION_DIR / "manifest_hash_check.csv",
                 ["external_scenario_id", "manifest_neutral_hash", "current_neutral_hash",
                  "neutral_match", "manifest_source_hash", "current_source_hash", "source_match"],
                 hash_rows)

    outputs = {c: load_condition_outputs(c) for c in CONDITIONS}

    missing_rows, duplicate_rows = [], []
    reliability_rows, abnormal_rows, latency_rows = [], [], []
    indicator_rows, oov_rows, schema_fail_rows, retrieval_rows = [], [], [], []
    model_condition_rows = []
    # paired correctness for McNemar: {model: {condition: {ext_id: bool}}}
    # Only scenarios with KNOWN ground truth (abnormal/benign) are eligible;
    # "unknown" ground truth is excluded, never defaulted to abnormal.
    paired_correct: dict[str, dict[str, dict[str, bool]]] = {}

    for model, mdir in zip(models, model_dirs):
        paired_correct[model] = {}
        for condition in CONDITIONS:
            by_id = outputs[condition].get(mdir, {})
            paired_correct[model][condition] = {}

            # audit expected vs observed
            for sid in scenario_ids:
                recs = by_id.get(sid, [])
                if len(recs) == 0:
                    missing_rows.append({"model": model, "condition": condition,
                                         "external_scenario_id": sid})
                elif len(recs) > 1:
                    duplicate_rows.append({"model": model, "condition": condition,
                                           "external_scenario_id": sid, "count": len(recs)})

            # counters (all expected scenarios remain in the denominator)
            n = len(scenario_ids)
            c_parse = c_keys = c_cls = c_risk = c_ind = c_strict = 0
            c_timeout = c_empty = c_fallback = c_retry = c_first_strict = 0
            c_missing = c_present = 0
            latencies: list[float] = []
            canon_total = oov_total = 0
            abn_detected = abn_missed = 0
            # benign_tn: usable & predicted normal. benign_not_tn: everything
            # else for a benign-truth scenario (invalid, missing, or predicted
            # abnormal) -- ALL of these count against specificity, per
            # requirement: benign invalid outputs are unsuccessful predictions,
            # not silently dropped from the denominator.
            benign_tn = benign_not_tn = 0

            for sid in scenario_ids:
                recs = by_id.get(sid, [])
                rec = recs[0] if recs else None  # first record; dupes flagged separately
                truth = answer_key[sid]["external_class"]

                if rec is None:
                    # Missing output: NOT a fallback. Counted separately, but
                    # still remains in every denominator (n) and still counts
                    # as an abnormal miss / benign non-TN where applicable.
                    c_missing += 1
                    if truth == "abnormal":
                        abn_missed += 1
                    elif truth in {"normal", "benign"}:
                        benign_not_tn += 1
                    schema_fail_rows.append({"model": model, "condition": condition,
                                             "external_scenario_id": sid,
                                             "reason": "missing_output"})
                    continue

                c_present += 1
                c_parse += int(rec.get("json_parse_valid", False))
                c_keys += int(rec.get("required_keys_valid", False))
                c_cls += int(rec.get("classification_valid", False))
                c_risk += int(rec.get("risk_level_valid", False))
                c_ind += int(rec.get("indicator_list_valid", False))
                strict = bool(rec.get("strict_schema_valid", False))
                c_strict += int(strict)
                c_timeout += int(rec.get("timeout", False))
                c_empty += int(rec.get("empty_response", False))
                c_fallback += int(rec.get("fallback", False))  # present-but-invalid only
                c_retry += int(rec.get("retries_used", 0) > 0)
                if strict and rec.get("attempts_used", 99) == 1:
                    c_first_strict += 1
                if rec.get("total_latency_seconds") is not None:
                    latencies.append(float(rec["total_latency_seconds"]))
                if not strict:
                    schema_fail_rows.append({"model": model, "condition": condition,
                                             "external_scenario_id": sid,
                                             "reason": "strict_schema_invalid"})

                # indicator vocabulary (exact canonical-token, OOV preserved)
                split = oc.classify_indicators(rec.get("predicted_indicators", []), vocab)
                canon_total += len(split["canonical"])
                oov_total += len(split["out_of_vocabulary"])
                for tok in split["out_of_vocabulary"]:
                    oov_rows.append({"model": model, "condition": condition,
                                     "external_scenario_id": sid, "oov_indicator": tok})

                # classification correctness (usable classification only).
                # The model's binary vocabulary is normal/abnormal; the answer
                # key stores benign for the negative class, so map it before
                # comparing. "unknown" ground truth is EXCLUDED entirely (not
                # defaulted to abnormal).
                pred = rec.get("predicted_class", "")
                usable = bool(rec.get("classification_valid", False)) and pred in {"normal", "abnormal"}

                if truth == "abnormal":
                    if usable and pred == "abnormal":
                        abn_detected += 1
                    else:
                        abn_missed += 1   # invalid/normal both count as a miss
                    correct = usable and pred == "abnormal"
                    paired_correct[model][condition][sid] = bool(correct)
                elif truth in {"normal", "benign"}:
                    if usable and pred == "normal":
                        benign_tn += 1
                    else:
                        # invalid prediction OR predicted abnormal: both are an
                        # unsuccessful prediction against a benign truth.
                        benign_not_tn += 1
                    correct = usable and pred == "normal"
                    paired_correct[model][condition][sid] = bool(correct)
                # truth == "unknown": excluded from detection counts and from
                # paired_correct on purpose (ground truth is not defensible).

            def rate(x: int) -> float:
                return round(x / n, 4) if n else 0.0

            reliability_rows.append({
                "model": model, "condition": condition, "n_scenarios": n,
                "output_coverage_rate": rate(c_present),
                "missing_output_rate": rate(c_missing),
                "json_parse_valid_rate": rate(c_parse),
                "required_field_valid_rate": rate(c_keys),
                "classification_valid_rate": rate(c_cls),
                "risk_level_valid_rate": rate(c_risk),
                "indicator_list_valid_rate": rate(c_ind),
                "strict_schema_valid_rate": rate(c_strict),
                "timeout_rate": rate(c_timeout),
                "empty_response_rate": rate(c_empty),
                "fallback_rate": rate(c_fallback),
                "retry_rate": rate(c_retry),
                "first_attempt_strict_success_rate": rate(c_first_strict),
            })

            # abnormal detection (invalid AND missing outputs counted as
            # misses -> conservative). unknown-truth scenarios are excluded
            # from n_abnormal entirely (they are neither abnormal nor benign).
            n_abn = len(abnormal_ids)
            recall_ci = oc.proportion_ci_bootstrap(abn_detected, n_abn)
            abnormal_rows.append({
                "model": model, "condition": condition,
                "n_abnormal": n_abn,
                "abnormal_true_positives": abn_detected,
                "abnormal_false_negatives": abn_missed,
                "abnormal_recall": recall_ci["rate"] if recall_ci["estimable"] else NOT_ESTIMABLE,
                "recall_ci_low": recall_ci["ci_low"], "recall_ci_high": recall_ci["ci_high"],
                "false_negative_rate": (round(abn_missed / n_abn, 4) if n_abn else NOT_ESTIMABLE),
            })

            # latency
            lat = oc.mean_ci_bootstrap(latencies)
            latency_rows.append({"model": model, "condition": condition, **lat})

            # indicator summary
            total_ind = canon_total + oov_total
            indicator_rows.append({
                "model": model, "condition": condition,
                "canonical_indicator_count": canon_total,
                "out_of_vocabulary_count": oov_total,
                "total_indicators_emitted": total_ind,
                "out_of_vocabulary_rate": (round(oov_total / total_ind, 4) if total_ind else NOT_ESTIMABLE),
                "in_vocabulary_rate": (round(canon_total / total_ind, 4) if total_ind else NOT_ESTIMABLE),
                "grounded_against_expected_indicators": NOT_ESTIMABLE,  # no expected-indicator key for OTRF
            })

            # precision/specificity/balanced accuracy ONLY with a benign subset
            if has_benign:
                tp = abn_detected
                fp = benign_not_tn  # invalid/missing/wrong benign predictions
                precision = round(tp / (tp + fp), 4) if (tp + fp) else NOT_ESTIMABLE
                specificity = (round(benign_tn / (benign_tn + benign_not_tn), 4)
                              if (benign_tn + benign_not_tn) else NOT_ESTIMABLE)
                recall_val = recall_ci["rate"] if recall_ci["estimable"] else 0.0
                bal_acc = (round((recall_val + (specificity if isinstance(specificity, float) else 0.0)) / 2, 4)
                           if isinstance(specificity, float) else NOT_ESTIMABLE)
            else:
                precision = specificity = bal_acc = NOT_ESTIMABLE

            model_condition_rows.append({
                "model": model, "condition": condition, "n_scenarios": n,
                "n_abnormal": len(abnormal_ids), "n_benign": len(benign_ids),
                "n_unknown_ground_truth": len(unknown_ids),
                "output_coverage_rate": rate(c_present),
                "abnormal_recall": abnormal_rows[-1]["abnormal_recall"],
                "false_negative_rate": abnormal_rows[-1]["false_negative_rate"],
                "precision": precision, "specificity": specificity,
                "balanced_accuracy": bal_acc,
                "strict_schema_valid_rate": rate(c_strict),
                "mean_latency_s": lat["mean"], "median_latency_s": lat["median"],
            })

            # retrieval audit (RAG only)
            if condition == "rag":
                for sid in scenario_ids:
                    recs = by_id.get(sid, [])
                    if recs:
                        r = recs[0]
                        retrieval_rows.append({
                            "model": model, "external_scenario_id": sid,
                            "retrieved_doc_ids": "; ".join(r.get("retrieved_doc_ids", [])),
                            "retrieved_scores": "; ".join(str(s) for s in r.get("retrieved_scores", [])),
                            "num_docs_retrieved": r.get("num_docs_retrieved", 0),
                            "no_document_found": r.get("no_document_found", ""),
                        })

    # ---- duplicate outputs fail evaluation by default ------------------------
    if duplicate_rows and not args.allow_duplicates:
        oc.write_csv(oc.EVALUATION_DIR / "duplicate_outputs.csv",
                     ["model", "condition", "external_scenario_id", "count"], duplicate_rows)
        raise SystemExit(
            f"Evaluation failed: {len(duplicate_rows)} duplicate scenario output(s) found "
            f"(see {oc.EVALUATION_DIR / 'duplicate_outputs.csv'}). Duplicate outputs indicate "
            f"a corrupted or manually-edited raw JSONL. Re-run the affected model with "
            f"--overwrite, or pass --allow-duplicates to evaluate using only the first "
            f"record per scenario (not recommended).")

    # ---- baseline vs RAG: exact McNemar per model, Holm across models -------
    mcnemar_pairs = []
    mcnemar_results = {}
    for model in models:
        bc = paired_correct[model].get("baseline", {})
        rc = paired_correct[model].get("rag", {})
        mc = oc.exact_mcnemar(bc, rc)
        mcnemar_results[model] = mc
        mcnemar_pairs.append((model, mc["p_value"]))
    holm = oc.holm_adjust(mcnemar_pairs) if mcnemar_pairs else {}
    comparison_rows = []
    for model in models:
        mc = mcnemar_results[model]
        comparison_rows.append({
            "model": model,
            "baseline_only_correct": mc["baseline_only_correct"],
            "rag_only_correct": mc["rag_only_correct"],
            "both_correct": mc["both_correct"], "both_wrong": mc["both_wrong"],
            "discordant": mc["discordant"],
            "raw_p_value": oc.fmt_p(mc["p_value"]),
            "holm_adjusted_p": oc.fmt_p(holm.get(model, mc["p_value"])),
            "note": ("descriptive only; discordant pairs small" if mc["discordant"] < 10
                     else "exact McNemar"),
        })

    # ---- write machine-readable tables --------------------------------------
    W = oc.write_csv
    W(oc.EVALUATION_DIR / "output_reliability.csv", list(reliability_rows[0].keys()) if reliability_rows else ["model"], reliability_rows)
    W(oc.EVALUATION_DIR / "abnormal_detection_results.csv", list(abnormal_rows[0].keys()) if abnormal_rows else ["model"], abnormal_rows)
    W(oc.EVALUATION_DIR / "latency_results.csv", list(latency_rows[0].keys()) if latency_rows else ["model"], latency_rows)
    W(oc.EVALUATION_DIR / "indicator_results.csv", list(indicator_rows[0].keys()) if indicator_rows else ["model"], indicator_rows)
    W(oc.EVALUATION_DIR / "out_of_vocabulary_indicators.csv", ["model", "condition", "external_scenario_id", "oov_indicator"], oov_rows)
    W(oc.EVALUATION_DIR / "model_condition_metrics.csv", list(model_condition_rows[0].keys()) if model_condition_rows else ["model"], model_condition_rows)
    W(oc.EVALUATION_DIR / "missing_outputs.csv", ["model", "condition", "external_scenario_id"], missing_rows)
    W(oc.EVALUATION_DIR / "duplicate_outputs.csv", ["model", "condition", "external_scenario_id", "count"], duplicate_rows)
    W(oc.EVALUATION_DIR / "schema_failures.csv", ["model", "condition", "external_scenario_id", "reason"], schema_fail_rows)
    W(oc.EVALUATION_DIR / "retrieval_audit.csv", ["model", "external_scenario_id", "retrieved_doc_ids", "retrieved_scores", "num_docs_retrieved", "no_document_found"], retrieval_rows)
    W(oc.EVALUATION_DIR / "baseline_vs_rag_comparison.csv", list(comparison_rows[0].keys()) if comparison_rows else ["model"], comparison_rows)

    summary = {
        "generated_utc": oc.utc_now(),
        "n_external_scenarios": len(scenario_ids),
        "n_abnormal": len(abnormal_ids),
        "n_defensibly_benign": len(benign_ids),
        "n_unknown_ground_truth": len(unknown_ids),
        "has_benign_subset": has_benign,
        "has_severity_answer_key": has_severity_key,
        "precision_specificity_balanced_accuracy": ("estimated" if has_benign else NOT_ESTIMABLE),
        "severity_accuracy": ("estimated" if has_severity_key else NOT_ESTIMABLE),
        "missing_output_count": len(missing_rows),
        "duplicate_output_count": len(duplicate_rows),
        "manifest_hash_mismatches": sum(1 for r in hash_rows
                                        if r["neutral_match"] != "TRUE" or r["source_match"] != "TRUE"),
        "note": "OTRF is controlled public adversary-simulation telemetry; results demonstrate "
                "technical transportability of the pipeline, not organisational real-world performance.",
    }
    (oc.EVALUATION_DIR / "validation_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # ---- dissertation-ready markdown report ---------------------------------
    write_report(summary, model_condition_rows, reliability_rows, abnormal_rows,
                 latency_rows, indicator_rows, comparison_rows, has_benign, has_severity_key)

    print(json.dumps(summary, indent=2))


def write_report(summary, mc_rows, rel_rows, abn_rows, lat_rows, ind_rows,
                 cmp_rows, has_benign, has_severity_key) -> None:
    lines = []
    lines.append("# OTRF External Validation Report (Supplementary)\n")
    lines.append(f"Generated (UTC): {summary['generated_utc']}\n")
    lines.append("This is a supplementary external validation using controlled public "
                 "OTRF Windows adversary-simulation telemetry. It demonstrates that the "
                 "implemented analysis pipeline can process independently sourced Windows "
                 "security data after deterministic normalisation. It is **not** a comparison "
                 "with the 120-scenario accuracy results and **not** evidence of organisational "
                 "real-world performance.\n")
    lines.append("## Sample composition\n")
    lines.append(f"- External scenarios: {summary['n_external_scenarios']}")
    lines.append(f"- Abnormal: {summary['n_abnormal']}")
    lines.append(f"- Defensibly benign: {summary['n_defensibly_benign']}")
    lines.append(f"- Unknown ground truth (excluded from detection metrics): "
                 f"{summary['n_unknown_ground_truth']}")
    lines.append(f"- Missing outputs: {summary['missing_output_count']}; "
                 f"Duplicate outputs: {summary['duplicate_output_count']}; "
                 f"Manifest hash mismatches: {summary['manifest_hash_mismatches']}\n")
    lines.append("## Metrics not estimable from this sample\n")
    if not has_benign:
        lines.append("- Precision, specificity and balanced accuracy are **not estimable** "
                     "(no defensibly benign subset).")
    if not has_severity_key:
        lines.append("- Severity accuracy is **not estimable** (no defensible severity answer key).")
    lines.append("- Indicator grounding against expected indicators is **not estimable** "
                 "(OTRF provides no per-scenario expected-indicator list); in-vocabulary vs "
                 "out-of-vocabulary rates are reported instead.\n")

    def tbl(headers, rows, keys):
        out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
        for r in rows:
            out.append("| " + " | ".join(str(r.get(k, "")) for k in keys) + " |")
        return "\n".join(out) + "\n"

    lines.append("## Abnormal detection (invalid AND missing outputs counted as misses)\n")
    lines.append(tbl(["Model", "Condition", "N abn", "TP", "FN", "Recall", "CI low", "CI high", "FN rate"],
                     abn_rows, ["model", "condition", "n_abnormal", "abnormal_true_positives",
                                "abnormal_false_negatives", "abnormal_recall", "recall_ci_low",
                                "recall_ci_high", "false_negative_rate"]))
    lines.append("## Output reliability and coverage (all scenarios in denominator)\n")
    lines.append(tbl(["Model", "Cond", "Coverage", "Parse", "Strict", "Timeout", "Fallback", "Retry"],
                     rel_rows, ["model", "condition", "output_coverage_rate", "json_parse_valid_rate",
                                "strict_schema_valid_rate", "timeout_rate", "fallback_rate", "retry_rate"]))
    lines.append("## Latency (seconds, total across attempts)\n")
    lines.append(tbl(["Model", "Cond", "n", "Mean", "Median", "Std", "CI low", "CI high"],
                     lat_rows, ["model", "condition", "n", "mean", "median", "std", "ci_low", "ci_high"]))
    lines.append("## Indicator vocabulary compliance (exact canonical-token match)\n")
    lines.append(tbl(["Model", "Cond", "Canonical", "OOV", "OOV rate", "In-vocab rate"],
                     ind_rows, ["model", "condition", "canonical_indicator_count",
                                "out_of_vocabulary_count", "out_of_vocabulary_rate", "in_vocabulary_rate"]))
    lines.append("## Baseline vs RAG (exact McNemar, Holm across models)\n")
    lines.append("Paired only over scenarios with known ground truth where a correctness "
                 "verdict could be assigned. Small discordant counts mean differences are "
                 "descriptive.\n")
    lines.append(tbl(["Model", "Base-only", "RAG-only", "Discordant", "p", "Holm p"],
                     cmp_rows, ["model", "baseline_only_correct", "rag_only_correct",
                                "discordant", "raw_p_value", "holm_adjusted_p"]))
    lines.append("\n## Interpretation guidance\n")
    lines.append("- Recall is the primary metric here: a false negative means genuine risky "
                 "endpoint behaviour was missed. It is reported conservatively (invalid or "
                 "missing outputs are treated as misses).")
    lines.append("- Because the sample is abnormal-dominated, precision-style metrics are only "
                 "reported if a defensible benign subset exists; otherwise they are marked not estimable.")
    lines.append("- Output coverage is reported separately from validity/correctness rates so a "
                 "low coverage rate (missing outputs) cannot be mistaken for a model correctness result.")
    lines.append("- This evaluation supports a limited claim of **technical transportability** and "
                 "supplementary external validation only.")
    (oc.EVALUATION_DIR / "external_validation_report.md").write_text("\n".join(lines), encoding="utf-8")

    # also emit a compact machine-readable summary CSV
    oc.write_csv(oc.EVALUATION_DIR / "external_validation_summary.csv",
                 list(mc_rows[0].keys()) if mc_rows else ["model"], mc_rows)


if __name__ == "__main__":
    main()
