"""
test_compare_baseline_vs_rag.py
================================

Offline test suite for the corrected primary comparison evaluator
(scripts/runs/4-compare_baseline_vs_rag.py). These tests run WITHOUT Ollama,
without network access, and without modifying any frozen raw output file.

Run from the repository root:
    python -m pytest scripts/runs/tests/ -v
or directly:
    python scripts/runs/tests/test_compare_baseline_vs_rag.py
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import sys
from pathlib import Path

THIS = Path(__file__).resolve()
RUNS_DIR = THIS.parents[1]
REPO_ROOT = THIS.parents[3]


def load_script(filename: str):
    """Import a numbered pipeline script (invalid module name) by path."""
    path = RUNS_DIR / filename
    mod_name = filename.replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cmp = load_script("4-compare_baseline_vs_rag.py")


# --------------------------------------------------------------------------- #
# Small synthetic fixtures (no disk I/O)                                       #
# --------------------------------------------------------------------------- #
def make_gt(rows: dict[str, str]) -> dict[str, dict[str, str]]:
    """{scenario_id: ground_truth_class} -> ground-truth dict rows."""
    return {sid: {"scenario_id": sid, "category": "NORMAL", "ground_truth_class": cls}
            for sid, cls in rows.items()}


def review_row(predicted_class: str, json_valid: str = "TRUE",
              indicator_overlap: str = "1.0", risk_match: str = "TRUE",
              latency_seconds: str = "1.0") -> dict[str, str]:
    return {"predicted_class": predicted_class, "json_valid": json_valid,
            "indicator_overlap": indicator_overlap, "risk_match": risk_match,
            "latency_seconds": latency_seconds}


# --------------------------------------------------------------------------- #
# 1. Invalid abnormal output lowers coverage-adjusted recall                   #
# --------------------------------------------------------------------------- #
def test_invalid_abnormal_lowers_coverage_adjusted_recall():
    gt = make_gt({"S1": "abnormal", "S2": "abnormal"})
    review = {
        "S1": review_row("abnormal"),                          # TP
        "S2": review_row("normal or risky"),                    # invalid, abnormal truth
    }
    m = cmp.aggregate_metrics(["S1", "S2"], gt, review)
    assert m["TP"] == 1
    assert m["invalid_abnormal"] == 1
    # recall counting ONLY TP over ground-truth abnormal (2) must be lowered
    # by the invalid response, not silently excluded from the denominator.
    assert m["coverage_adjusted_recall"] == 0.5
    assert m["coverage_adjusted_recall"] < 1.0


# --------------------------------------------------------------------------- #
# 2. Invalid normal output lowers coverage-adjusted specificity                #
# --------------------------------------------------------------------------- #
def test_invalid_normal_lowers_coverage_adjusted_specificity():
    gt = make_gt({"S1": "normal", "S2": "normal"})
    review = {
        "S1": review_row("normal"),               # TN
        "S2": review_row("normal or risky"),       # invalid, normal truth
    }
    m = cmp.aggregate_metrics(["S1", "S2"], gt, review)
    assert m["TN"] == 1
    assert m["invalid_normal"] == 1
    assert m["coverage_adjusted_specificity"] == 0.5
    assert m["coverage_adjusted_specificity"] < 1.0


# --------------------------------------------------------------------------- #
# 3. Missing output is distinct from fallback                                  #
# --------------------------------------------------------------------------- #
def test_missing_is_distinct_from_fallback():
    gt = make_gt({"S1": "abnormal", "S2": "abnormal"})
    review = {
        "S2": review_row("abnormal", json_valid="FALSE"),  # present but schema-invalid -> fallback
        # S1 has no row at all -> missing
    }
    m = cmp.aggregate_metrics(["S1", "S2"], gt, review)
    assert m["missing_outputs"] == 1
    assert m["fallback_outputs"] == 1
    assert m["missing_abnormal"] == 1
    assert m["fallback_abnormal"] == 1
    assert cmp.classify_output(None) == "missing"
    assert cmp.classify_output({"json_valid": "FALSE", "predicted_class": "abnormal",
                                "_gt_class": "abnormal"}) == "fallback"


# --------------------------------------------------------------------------- #
# 4. Placeholder classification is invalid                                     #
# --------------------------------------------------------------------------- #
def test_placeholder_classification_is_invalid():
    for placeholder in ["normal or risky", "normal or abnormal",
                        "low, medium, high, or critical"]:
        row = {"json_valid": "TRUE", "predicted_class": placeholder, "_gt_class": "normal"}
        assert cmp.classify_output(row) == "invalid", placeholder


# --------------------------------------------------------------------------- #
# 5. All expected cases remain in primary (all-scenario) accuracy              #
# --------------------------------------------------------------------------- #
def test_all_expected_cases_remain_in_primary_accuracy():
    gt = make_gt({"S1": "normal", "S2": "abnormal", "S3": "normal", "S4": "abnormal"})
    review = {
        "S1": review_row("normal"),                       # valid_correct
        "S2": review_row("normal or risky"),               # invalid
        # S3 missing entirely
        "S4": review_row("abnormal", json_valid="FALSE"),  # fallback
    }
    m = cmp.aggregate_metrics(["S1", "S2", "S3", "S4"], gt, review)
    assert m["expected_scenarios"] == 4
    # Only 1 of 4 is valid_correct; invalid/missing/fallback are all unsuccessful.
    assert m["all_scenario_accuracy"] == 0.25
    assert m["valid_classification_outputs"] + m["invalid_classification_outputs"] \
        + m["missing_outputs"] + m["fallback_outputs"] == m["expected_scenarios"]


# --------------------------------------------------------------------------- #
# 6. Valid-only metrics are secondary                                          #
# --------------------------------------------------------------------------- #
def test_valid_only_metrics_are_secondary():
    gt = make_gt({"S1": "normal", "S2": "abnormal"})
    review = {
        "S1": review_row("normal"),           # valid_correct
        "S2": review_row("normal or risky"),   # invalid abnormal truth
    }
    m = cmp.aggregate_metrics(["S1", "S2"], gt, review)
    # valid_output_accuracy (secondary) is computed over valid outputs ONLY (1/1
    # = perfect), which must differ from all_scenario_accuracy (primary, 1/2),
    # proving the two are genuinely different denominators and cannot be
    # conflated as headline results.
    assert m["valid_output_accuracy"] == 1.0
    assert m["all_scenario_accuracy"] == 0.5
    assert m["valid_output_accuracy"] != m["all_scenario_accuracy"]
    assert "valid_output_accuracy" in cmp.REQUIRED_COLUMNS
    assert "all_scenario_accuracy" in cmp.REQUIRED_COLUMNS


# --------------------------------------------------------------------------- #
# 7. Coverage-adjusted F1 includes abnormal invalid responses                  #
# --------------------------------------------------------------------------- #
def test_coverage_adjusted_f1_includes_invalid_abnormal():
    gt = make_gt({"S1": "abnormal", "S2": "abnormal", "S3": "abnormal"})
    review = {
        "S1": review_row("abnormal"),          # TP
        "S2": review_row("abnormal"),          # TP
        "S3": review_row("normal or risky"),    # invalid, abnormal truth
    }
    m = cmp.aggregate_metrics(["S1", "S2", "S3"], gt, review)
    tp = m["TP"]
    denom = 2 * tp + m["valid_FP"] + m["valid_FN"] + m["invalid_abnormal"] \
        + m["missing_abnormal"] + m["fallback_abnormal"]
    expected_f1 = (2 * tp / denom) if denom else 0.0
    assert m["coverage_adjusted_f1"] == expected_f1
    # Sanity: without folding the invalid response into the denominator, F1
    # would incorrectly read as a perfect 1.0 (2/2 valid predictions correct).
    assert m["coverage_adjusted_f1"] < 1.0


# --------------------------------------------------------------------------- #
# 8. McNemar treats invalid output as incorrect                                #
# --------------------------------------------------------------------------- #
def test_mcnemar_treats_invalid_as_incorrect():
    gt = make_gt({"S1": "abnormal"})
    base_review = {"S1": review_row("abnormal")}           # baseline: correct
    rag_review = {"S1": review_row("normal or risky")}      # rag: invalid (non-committal)
    base_m = cmp.aggregate_metrics(["S1"], gt, base_review)
    rag_m = cmp.aggregate_metrics(["S1"], gt, rag_review)
    mc = cmp.exact_mcnemar(base_m["_per_scenario"], rag_m["_per_scenario"])
    # baseline got it right, RAG's invalid output must be scored as WRONG,
    # i.e. this is a baseline-only-correct discordant pair, not a tie/ignore.
    assert mc["baseline_only_correct"] == 1
    assert mc["rag_only_correct"] == 0
    assert mc["discordant_pairs"] == 1


# --------------------------------------------------------------------------- #
# 9. Holm correction is applied across five models                             #
# --------------------------------------------------------------------------- #
def test_holm_correction_across_five_models():
    # Five identical small p-values: Holm step-down must inflate them
    # differently from a flat Bonferroni (m * p capped, then monotone).
    pairs = [(f"model{i}", 0.01) for i in range(5)]
    holm = cmp.holm_adjust(pairs)
    assert len(holm) == 5
    # First-ranked (smallest p, all tied here) gets multiplied by m=5.
    assert holm["model0"] == 0.05
    # Step-down is monotone non-decreasing when sorted by raw p.
    ordered = sorted(pairs, key=lambda x: x[1])
    adj_values = [holm[label] for label, _ in ordered]
    assert adj_values == sorted(adj_values)


# --------------------------------------------------------------------------- #
# 10. p = 0.000 is never generated                                             #
# --------------------------------------------------------------------------- #
def test_p_equals_0_000_never_generated():
    assert cmp.fmt_p(0.0) == "< 0.001"
    assert cmp.fmt_p(1e-12) == "< 0.001"
    assert cmp.fmt_p(0.0009) == "< 0.001"
    assert "0.000" not in cmp.fmt_p(0.0)
    assert cmp.fmt_p(0.009) == "0.009"
    assert cmp.fmt_p(0.238) == "0.238"


# --------------------------------------------------------------------------- #
# 11. Unknown ground truth fails validation                                    #
# --------------------------------------------------------------------------- #
def test_unknown_ground_truth_fails_validation():
    gt = make_gt({"S1": "normal", "S2": "unknown"})
    try:
        cmp.validate_ground_truth_classes(gt)
        assert False, "expected ValueError for an 'unknown' ground-truth class"
    except ValueError as exc:
        assert "S2" in str(exc)
    # A clean ground truth (normal/abnormal only) must pass silently.
    cmp.validate_ground_truth_classes(make_gt({"S1": "normal", "S2": "abnormal"}))


# --------------------------------------------------------------------------- #
# 12. DeepSeek frozen-result acceptance values are derived correctly           #
# --------------------------------------------------------------------------- #
def test_deepseek_acceptance_values_synthetic():
    """Construct a synthetic 120-scenario, 58-abnormal/62-normal dataset that
    reproduces the exact frozen DeepSeek-RAG pattern (75 correct, 38 invalid,
    24 of them abnormal, 29 TP) and check the derived formulas land on the
    documented acceptance values without hardcoding the arithmetic twice."""
    scenario_ids = [f"S{i:03d}" for i in range(120)]
    # 58 abnormal ground truth, 62 normal.
    gt_rows = {}
    for i, sid in enumerate(scenario_ids):
        gt_rows[sid] = "abnormal" if i < 58 else "normal"
    gt = make_gt(gt_rows)

    review = {}
    idx = 0
    # 29 TP (abnormal correctly predicted abnormal)
    for _ in range(29):
        review[scenario_ids[idx]] = review_row("abnormal"); idx += 1
    # 5 valid_FN (abnormal predicted normal)
    for _ in range(5):
        review[scenario_ids[idx]] = review_row("normal"); idx += 1
    # 24 invalid abnormal (placeholder)
    for _ in range(24):
        review[scenario_ids[idx]] = review_row("normal or risky"); idx += 1
    assert idx == 58  # all abnormal scenarios accounted for
    # 46 TN (normal correctly predicted normal)
    for _ in range(46):
        review[scenario_ids[idx]] = review_row("normal"); idx += 1
    # 2 valid_FP (normal predicted abnormal)
    for _ in range(2):
        review[scenario_ids[idx]] = review_row("abnormal"); idx += 1
    # 14 invalid normal (placeholder)
    for _ in range(14):
        review[scenario_ids[idx]] = review_row("normal or risky"); idx += 1
    assert idx == 120

    m = cmp.aggregate_metrics(scenario_ids, gt, review)
    assert m["expected_scenarios"] == 120
    assert m["TP"] + m["TN"] == 75
    assert round(m["all_scenario_accuracy"], 3) == 0.625
    assert m["invalid_classification_outputs"] == 38
    assert m["invalid_abnormal"] == 24
    assert m["TP"] == 29
    assert m["ground_truth_abnormal"] == 58
    assert round(m["coverage_adjusted_recall"], 3) == 0.500


def test_deepseek_acceptance_values_real_frozen_data():
    """Regression guard against the real frozen files, if present."""
    base_dir = REPO_ROOT / "results" / "rag" / "deepseek-r1_8b" / "deepseek-r1_8b_rag_review.csv"
    gt_path = REPO_ROOT / "Dataset" / "ground_truth_FINAL.csv"
    if not base_dir.exists() or not gt_path.exists():
        return  # frozen data not present in this checkout; skip silently
    gt = cmp.load_ground_truth(gt_path)
    review = cmp.load_review(base_dir)
    m = cmp.aggregate_metrics(sorted(gt.keys()), gt, review)
    assert m["TP"] + m["TN"] == 75
    assert m["invalid_classification_outputs"] == 38
    assert m["invalid_abnormal"] == 24
    assert m["TP"] == 29
    assert m["ground_truth_abnormal"] == 58
    assert round(m["coverage_adjusted_recall"], 3) == 0.500


# --------------------------------------------------------------------------- #
# 12b. Primary indicator overlap uses EXACT canonical-token matching           #
# --------------------------------------------------------------------------- #
def test_primary_indicator_overlap_is_exact_not_substring():
    # exact token overlap: 1 of 2 expected tokens present verbatim
    assert cmp.exact_indicator_overlap(
        "network_profile_viewed; no_additional_risky_activity",
        "network_profile_viewed;network_profile_unchanged") == 0.5
    # substring must NOT be credited: 'authorised_usb' is a substring of the
    # predicted 'authorised_usb_device' but is a DIFFERENT token -> no credit.
    assert cmp.exact_indicator_overlap("authorised_usb_device", "authorised_usb") == 0.0
    # space / hyphen variants are not folded to the underscored token
    assert cmp.exact_indicator_overlap("failed login", "failed_login") == 0.0
    assert cmp.exact_indicator_overlap("failed-login", "failed_login") == 0.0
    # exact match earns full credit; case-insensitive
    assert cmp.exact_indicator_overlap("FAILED_LOGIN", "failed_login") == 1.0
    # empty expected -> 0.0, never a divide-by-zero
    assert cmp.exact_indicator_overlap("anything", "") == 0.0


# --------------------------------------------------------------------------- #
# 13. Evaluators run without Ollama                                            #
# --------------------------------------------------------------------------- #
def test_evaluator_has_no_ollama_or_network_dependency():
    source = (RUNS_DIR / "4-compare_baseline_vs_rag.py").read_text(encoding="utf-8")
    forbidden = ["import urllib", "import socket", "import requests", "ollama"]
    hits = [f for f in forbidden if f in source]
    assert not hits, f"comparison evaluator unexpectedly references: {hits}"


# --------------------------------------------------------------------------- #
# 14. Frozen raw-output hashes remain unchanged (portable ledger)              #
# --------------------------------------------------------------------------- #
def _canonical_text_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")).hexdigest()


def test_frozen_ledger_uses_forward_slash_repo_relative_paths():
    hashes_csv = REPO_ROOT / "docs" / "final_audit" / "FROZEN_ARTIFACT_HASHES.csv"
    if not hashes_csv.exists():
        return  # audit not present in this checkout; skip silently
    with hashes_csv.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows, "portable ledger has no data rows"
    expected_cols = {"category", "path", "repository_sha256", "canonical_text_sha256",
                     "original_windows_crlf_sha256", "size_bytes", "line_count",
                     "newline_style"}
    assert expected_cols.issubset(rows[0].keys())
    for row in rows:
        assert "\\" not in row["path"], f"non-portable backslash path: {row['path']}"


def test_frozen_raw_output_hashes_unchanged():
    """Content-drift check, robust to line-ending conversion.

    Compares the CURRENT on-disk file's line-ending-normalised (canonical)
    text hash against the ledger's `canonical_text_sha256`. A file whose bytes
    changed only because of CRLF<->LF conversion (e.g. checked out on a
    different platform, or after .gitattributes normalisation) must NOT be
    reported as drift -- only a genuine content change may fail this test.
    The raw, un-normalised hash is also compared against
    `original_windows_crlf_sha256` purely to CLASSIFY a mismatch (as
    line-ending-only vs real drift), never to fail the test by itself.
    """
    hashes_csv = REPO_ROOT / "docs" / "final_audit" / "FROZEN_ARTIFACT_HASHES.csv"
    if not hashes_csv.exists():
        return  # audit not present in this checkout; skip silently
    frozen_categories = {
        "primary_baseline_raw", "primary_rag_raw",
        "consistency_baseline_raw", "consistency_rag_raw",
        "otrf_baseline_raw", "otrf_rag_raw",
    }
    with hashes_csv.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    checked = 0
    for row in rows:
        if row["category"] not in frozen_categories:
            continue
        if row["canonical_text_sha256"] == "MISSING":
            continue
        path = REPO_ROOT / row["path"]  # forward-slash, portable on every OS
        raw = path.read_bytes()
        current_raw_sha = hashlib.sha256(raw).hexdigest()
        current_canonical_sha = _canonical_text_sha256(raw)
        line_ending_only = (
            current_raw_sha != row["original_windows_crlf_sha256"]
            and current_canonical_sha == row["canonical_text_sha256"]
        )
        assert current_canonical_sha == row["canonical_text_sha256"], (
            f"CONTENT DRIFT (not just line-ending conversion): {row['path']}")
        assert line_ending_only or current_raw_sha == row["original_windows_crlf_sha256"]
        checked += 1
    assert checked > 0


# --------------------------------------------------------------------------- #
# Runner (so the file is also runnable directly, without pytest)               #
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    tests = [(name, fn) for name, fn in list(globals().items())
             if name.startswith("test_") and callable(fn)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS  {name}")
            passed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL  {name}: {exc}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed, out of {len(tests)}")
    sys.exit(1 if failed else 0)
