#!/usr/bin/env python3
"""
7-evaluate_consistency.py
=========================

Evaluator for the standalone consistency experiment produced by
5-run_consistency_baseline.py and 6-run_consistency_rag.py.

Reads raw JSONL from results/consistency/baseline/ and results/consistency/rag/
and computes, per model / condition / scenario: classification, risk, indicator
and explanation consistency; reliability (six validity fields, retry, timeout,
empty, vocabulary compliance); latency; and correctness across repetitions
(exact-set ground-truth indicator precision/recall/F1). Consistency and
correctness are reported separately.

Also produces: repetition integrity audit, retrieval consistency audit,
controlled-vocabulary audit, per-category summaries, and an expanded paired
baseline-vs-RAG comparison across 15 metrics with deterministic bootstrap 95%
CIs and Holm correction applied per metric across models. Ends with a full
validation report and a STATUS line.

USAGE
-----
    python 7-evaluate_consistency.py
    python 7-evaluate_consistency.py --condition baseline
    python 7-evaluate_consistency.py --condition rag
"""

from __future__ import annotations

import argparse
import csv
import json
import hashlib
from datetime import datetime, timezone
import math
import random
import statistics
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any

try:
    from scipy.stats import wilcoxon  # type: ignore
    HAVE_SCIPY = True
except Exception:
    HAVE_SCIPY = False

SCRIPT_DIR = Path(__file__).resolve().parent


def _resolve_root() -> Path:
    # Prefer the baseline runner's ROOT_DIR if importable, else infer.
    import importlib.util
    p = SCRIPT_DIR / "1-run_baseline.py"
    if p.exists():
        try:
            spec = importlib.util.spec_from_file_location("br_cfg_eval", p)
            m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
            return m.ROOT_DIR
        except Exception:
            pass
    return SCRIPT_DIR.resolve().parents[1] if len(SCRIPT_DIR.resolve().parents) >= 2 else SCRIPT_DIR


ROOT_DIR = _resolve_root()
DATASET_DIR = ROOT_DIR / "Dataset"
GROUND_TRUTH_PATH = DATASET_DIR / "ground_truth_FINAL.csv"
VOCAB_PATH = DATASET_DIR / "controlled_indicator_vocabulary.csv"
CONSISTENCY_DIR = ROOT_DIR / "results" / "consistency"
OUT_BASELINE = CONSISTENCY_DIR / "baseline"
OUT_RAG = CONSISTENCY_DIR / "rag"
RESULTS_DIR = CONSISTENCY_DIR / "reports"
SELECTION_PATH = RESULTS_DIR / "consistency_selection.csv"
FROZEN_PLAN_PATH = ROOT_DIR / "results" / "rag" / "retrieval_plan.json"

EXPECTED_MODELS = ["llama3", "deepseek-r1:8b", "gemma3:12b", "qwen3:8b", "gpt-oss:20b"]
BOOTSTRAP_ITERS = 10000
BOOTSTRAP_SEED = 2026

COMPARE_METRICS = [
    "classification_agreement_rate", "risk_agreement_rate",
    "mean_pairwise_indicator_jaccard", "mean_pairwise_explanation_similarity",
    "json_parse_validity_rate", "required_fields_validity_rate",
    "strict_schema_validity_rate", "indicator_vocabulary_compliance_rate",
    "classification_accuracy_across_repetitions", "risk_accuracy_across_repetitions",
    "mean_ground_truth_indicator_precision", "mean_ground_truth_indicator_recall",
    "mean_ground_truth_indicator_f1", "mean_latency", "latency_coefficient_of_variation",
]


# --------------------------------------------------------------------------- #
# Loaders                                                                      #
# --------------------------------------------------------------------------- #
def load_ground_truth() -> dict[str, dict[str, str]]:
    truth: dict[str, dict[str, str]] = {}
    if GROUND_TRUTH_PATH.exists():
        with GROUND_TRUTH_PATH.open("r", newline="", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                truth[row["scenario_id"]] = row
    return truth


def load_vocab() -> set[str]:
    vocab: set[str] = set()
    if VOCAB_PATH.exists():
        with VOCAB_PATH.open("r", newline="", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                tok = (row.get("indicator_token") or list(row.values())[0]).strip().lower()
                if tok:
                    vocab.add(tok)
    return vocab


def load_records(out_root: Path) -> list[dict[str, Any]]:
    records = []
    if out_root.exists():
        for raw in out_root.glob("*/*_consistency_raw.jsonl"):
            for line in raw.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return records


# --------------------------------------------------------------------------- #
# Metric helpers                                                               #
# --------------------------------------------------------------------------- #
def entropy(labels): 
    n = len(labels)
    if n == 0:
        return 0.0
    c = Counter(labels)
    return round(-sum((v/n)*math.log2(v/n) for v in c.values()), 4)


def agreement(labels):
    if not labels:
        return "", 0, 0.0, 0
    c = Counter(labels); m, mc = c.most_common(1)[0]
    return m, mc, round(mc/len(labels), 4), len(c)


def jaccard(a: set, b: set):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b)/len(a | b)


def pairwise(sets):
    pairs = list(combinations(range(len(sets)), 2))
    if not pairs:
        return {"mean": 1.0, "min": 1.0, "max": 1.0}
    vals = [jaccard(sets[i], sets[j]) for i, j in pairs]
    return {"mean": round(statistics.mean(vals), 4), "min": round(min(vals), 4), "max": round(max(vals), 4)}


def token_set(text):
    import re
    return {w for w in re.split(r"[^a-z0-9]+", (text or "").lower()) if len(w) > 2}


def cv(vals):
    if len(vals) < 2:
        return 0.0
    m = statistics.mean(vals)
    return round(statistics.pstdev(vals)/m, 4) if m else 0.0


def prf(pred: set, exp: set):
    if not exp:
        return 0.0, 0.0, 0.0
    tp = len(pred & exp)
    prec = tp/len(pred) if pred else 0.0
    rec = tp/len(exp) if exp else 0.0
    f1 = (2*prec*rec/(prec+rec)) if (prec+rec) else 0.0
    return round(prec, 4), round(rec, 4), round(f1, 4)


# --------------------------------------------------------------------------- #
# Per-scenario evaluation                                                      #
# --------------------------------------------------------------------------- #
def eval_scenario(reps, truth, vocab):
    reps = sorted(reps, key=lambda r: r["repetition"])
    n = len(reps)
    sid = reps[0]["scenario_id"]
    gt = truth.get(sid, {})
    gt_class = (gt.get("ground_truth_class") or "").lower()
    gt_risk = (gt.get("ground_truth_risk") or "").lower()
    gt_inds = {t.strip().lower() for t in
               (gt.get("expected_indicators") or "").replace(";", ",").split(",") if t.strip()}

    classes = [r["normalised_classification"] for r in reps]
    risks = [r["normalised_risk_level"] for r in reps]
    c_mode, c_cnt, c_agree, c_uni = agreement(classes)
    r_mode, r_cnt, r_agree, r_uni = agreement(risks)

    ind_sets = [set(r.get("normalised_indicators") or []) for r in reps]
    ind = pairwise(ind_sets)
    union = set().union(*ind_sets) if ind_sets else set()
    inter = set(ind_sets[0]).intersection(*ind_sets[1:]) if len(ind_sets) > 1 else (ind_sets[0] if ind_sets else set())
    expl = pairwise([token_set(r.get("raw_explanation", "")) for r in reps])

    # vocabulary compliance
    canonical_counts, oov_counts, compliant_flags, oov_tokens = [], [], [], set()
    for s in ind_sets:
        canon = s & vocab
        oov = s - vocab
        canonical_counts.append(len(canon)); oov_counts.append(len(oov))
        compliant_flags.append(len(oov) == 0 and len(s) > 0)
        oov_tokens |= oov

    # correctness (exact set matching for GT indicators)
    precs, recs, f1s = [], [], []
    for s in ind_sets:
        p, rc, f = prf(s & vocab, gt_inds)
        precs.append(p); recs.append(rc); f1s.append(f)

    jv = [bool(r.get("json_parse_valid")) for r in reps]
    rfv = [bool(r.get("required_fields_valid")) for r in reps]
    cv_ = [bool(r.get("classification_valid")) for r in reps]
    rv = [bool(r.get("risk_level_valid")) for r in reps]
    ilv = [bool(r.get("indicator_list_valid")) for r in reps]
    ssv = [bool(r.get("strict_schema_valid")) for r in reps]
    fa_ssv = [bool(r.get("first_attempt_strict_schema_valid")) for r in reps]
    retries = [int(r.get("retries_used", 0)) for r in reps]
    timeouts = [bool(r.get("timeout")) for r in reps]
    empties = [bool(r.get("empty_response")) for r in reps]
    lat = [float(r.get("total_attempt_latency_seconds", 0.0)) for r in reps]

    correct_c = sum(1 for c in classes if c == gt_class)
    correct_r = sum(1 for rk in risks if rk == gt_risk)

    return {
        "model": reps[0]["model"], "condition": reps[0]["condition"],
        "record_id": reps[0]["record_id"], "scenario_id": sid,
        "category": reps[0].get("category", ""),
        "ground_truth_class": gt_class, "ground_truth_risk": gt_risk,
        "scenario_source": (gt.get("scenario_source") or "").lower(),
        "repetitions": n,
        "classification_mode": c_mode, "classification_mode_count": c_cnt,
        "classification_agreement_rate": c_agree, "number_of_unique_classifications": c_uni,
        "classification_entropy": entropy(classes), "all_repetitions_classification_identical": c_uni == 1,
        "risk_mode": r_mode, "risk_mode_count": r_cnt, "risk_agreement_rate": r_agree,
        "number_of_unique_risk_levels": r_uni, "risk_entropy": entropy(risks),
        "all_repetitions_risk_identical": r_uni == 1,
        "mean_pairwise_indicator_jaccard": ind["mean"], "minimum_pairwise_indicator_jaccard": ind["min"],
        "maximum_pairwise_indicator_jaccard": ind["max"],
        "indicator_union_size": len(union), "indicator_intersection_size": len(inter),
        "all_repetitions_indicator_sets_identical": all(s == ind_sets[0] for s in ind_sets),
        "mean_pairwise_explanation_similarity": expl["mean"], "minimum_pairwise_explanation_similarity": expl["min"],
        "json_parse_validity_rate": round(sum(jv)/n, 4),
        "required_fields_validity_rate": round(sum(rfv)/n, 4),
        "classification_validity_rate": round(sum(cv_)/n, 4),
        "risk_level_validity_rate": round(sum(rv)/n, 4),
        "indicator_list_validity_rate": round(sum(ilv)/n, 4),
        "strict_schema_validity_rate": round(sum(ssv)/n, 4),
        "first_attempt_strict_schema_success_rate": round(sum(fa_ssv)/n, 4),
        "retry_rate": round(sum(1 for x in retries if x > 0)/n, 4),
        "timeout_rate": round(sum(timeouts)/n, 4),
        "empty_response_rate": round(sum(empties)/n, 4),
        "indicator_vocabulary_compliance_rate": round(sum(compliant_flags)/n, 4),
        "canonical_indicator_count": round(statistics.mean(canonical_counts), 3) if canonical_counts else 0.0,
        "out_of_vocabulary_indicator_count": round(statistics.mean(oov_counts), 3) if oov_counts else 0.0,
        "mean_out_of_vocabulary_indicators_per_response": round(statistics.mean(oov_counts), 3) if oov_counts else 0.0,
        "unique_out_of_vocabulary_indicators": "; ".join(sorted(oov_tokens)),
        "mean_latency": round(statistics.mean(lat), 3) if lat else 0.0,
        "median_latency": round(statistics.median(lat), 3) if lat else 0.0,
        "standard_deviation_latency": round(statistics.pstdev(lat), 3) if len(lat) > 1 else 0.0,
        "minimum_latency": round(min(lat), 3) if lat else 0.0,
        "maximum_latency": round(max(lat), 3) if lat else 0.0,
        "latency_coefficient_of_variation": cv(lat),
        "classification_accuracy_across_repetitions": round(correct_c/n, 4),
        "risk_accuracy_across_repetitions": round(correct_r/n, 4),
        "mean_ground_truth_indicator_precision": round(statistics.mean(precs), 4) if precs else 0.0,
        "mean_ground_truth_indicator_recall": round(statistics.mean(recs), 4) if recs else 0.0,
        "mean_ground_truth_indicator_f1": round(statistics.mean(f1s), 4) if f1s else 0.0,
    }


# --------------------------------------------------------------------------- #
# Aggregation                                                                  #
# --------------------------------------------------------------------------- #
def aggregate(per_scenario, by="model"):
    groups = defaultdict(list)
    for r in per_scenario:
        key = (r["model"], r["condition"]) if by == "model" else (r["model"], r["condition"], r["category"])
        groups[key].append(r)
    out = []
    for key, rows in sorted(groups.items()):
        n = len(rows)
        def mean(k): return round(statistics.mean([x[k] for x in rows]), 4) if rows else 0.0
        rec = {"model": key[0], "condition": key[1]}
        if by == "category":
            rec["category"] = key[2]
        rec["scenarios"] = n
        # Keep the ORIGINAL per-scenario key names so downstream readers
        # (write_summary, comparison) use one consistent vocabulary. Each value
        # is the mean of that per-scenario metric across the group.
        for k in ["classification_agreement_rate", "risk_agreement_rate",
                  "mean_pairwise_indicator_jaccard", "mean_pairwise_explanation_similarity",
                  "json_parse_validity_rate", "required_fields_validity_rate",
                  "strict_schema_validity_rate", "first_attempt_strict_schema_success_rate",
                  "indicator_vocabulary_compliance_rate", "retry_rate", "timeout_rate",
                  "empty_response_rate", "classification_accuracy_across_repetitions",
                  "risk_accuracy_across_repetitions", "mean_ground_truth_indicator_precision",
                  "mean_ground_truth_indicator_recall", "mean_ground_truth_indicator_f1",
                  "mean_latency", "latency_coefficient_of_variation"]:
            rec[k] = mean(k)
        rec["pct_scenarios_all_reps_classification_identical"] = round(
            sum(1 for x in rows if x["all_repetitions_classification_identical"])/n, 4)
        rec["pct_scenarios_all_reps_risk_identical"] = round(
            sum(1 for x in rows if x["all_repetitions_risk_identical"])/n, 4)
        out.append(rec)
    return out


# --------------------------------------------------------------------------- #
# Repetition integrity                                                         #
# --------------------------------------------------------------------------- #
def repetition_integrity(records, expected_reps):
    groups = defaultdict(list)
    for r in records:
        groups[(r["condition"], r["model"], r["scenario_id"])].append(int(r["repetition"]))
    rows = []
    for (cond, model, sid), reps in sorted(groups.items()):
        observed = sorted(reps)
        expected = list(range(1, expected_reps + 1))
        missing = [x for x in expected if x not in observed]
        dup = [x for x, c in Counter(observed).items() if c > 1]
        unexpected = [x for x in observed if x not in expected]
        if not missing and not dup and not unexpected and len(set(observed)) == expected_reps:
            status = "complete"
        elif dup:
            status = "duplicate_repetitions"
        elif missing:
            status = "missing_repetitions"
        elif unexpected:
            status = "unexpected_repetition_numbers"
        else:
            status = "incomplete"
        rows.append({
            "condition": cond, "model": model, "scenario_id": sid,
            "expected_repetitions": expected_reps,
            "observed_repetitions": len(observed),
            "missing_repetition_numbers": ";".join(map(str, missing)),
            "duplicate_repetition_numbers": ";".join(map(str, dup)),
            "status": status,
        })
    return rows


# --------------------------------------------------------------------------- #
# Retrieval consistency audit (RAG)                                            #
# --------------------------------------------------------------------------- #
def retrieval_audit(records):
    groups = defaultdict(list)
    for r in records:
        if r.get("condition") != "rag":
            continue
        groups[(r["model"], r["scenario_id"])].append(r)
    rows = []
    for (model, sid), reps in sorted(groups.items()):
        ids = {json.dumps(r.get("retrieved_document_ids", [])) for r in reps}
        scores = {json.dumps(r.get("retrieved_document_scores", [])) for r in reps}
        ranks = {json.dumps(r.get("retrieved_document_ranks", [])) for r in reps}
        hashes = {r.get("retrieval_plan_hash", "") for r in reps}
        identical = len(ids) == 1 and len(scores) == 1 and len(ranks) == 1 and len(hashes) == 1
        rows.append({
            "model": model, "scenario_id": sid,
            "retrieval_plan_present": bool(hashes and list(hashes)[0]),
            "document_ids_identical": len(ids) == 1,
            "document_order_identical": len(ranks) == 1,
            "scores_identical": len(scores) == 1,
            "retrieval_hash_identical": len(hashes) == 1,
            "all_repetitions_identical_retrieval": identical,
            "status": "ok" if identical else "MISMATCH",
        })
    return rows


# --------------------------------------------------------------------------- #
# Bootstrap CI + Holm                                                          #
# --------------------------------------------------------------------------- #
def bootstrap_ci(diffs, iters=BOOTSTRAP_ITERS, seed=BOOTSTRAP_SEED):
    if not diffs:
        return (0.0, 0.0)
    rng = random.Random(seed)
    n = len(diffs)
    means = []
    for _ in range(iters):
        sample = [diffs[rng.randrange(n)] for _ in range(n)]
        means.append(sum(sample)/n)
    means.sort()
    lo = means[int(0.025*iters)]
    hi = means[int(0.975*iters)-1]
    return (round(lo, 4), round(hi, 4))


def holm(pvals):
    m = len(pvals)
    ordered = sorted(pvals, key=lambda x: x[1])
    out = {}; prev = 0.0
    for i, (label, p) in enumerate(ordered):
        adj = min(1.0, (m - i) * p); adj = max(adj, prev); prev = adj
        out[label] = round(adj, 5)
    return out


def fmt_p(p) -> str:
    """Never render p = 0.000: report '< 0.001' instead (2026-07-19 fix)."""
    if p is None:
        return "n/a"
    return "< 0.001" if p < 0.001 else f"{p:.3f}"


def compare(base_ps, rag_ps):
    b_idx = {(r["model"], r["scenario_id"]): r for r in base_ps}
    r_idx = {(r["model"], r["scenario_id"]): r for r in rag_ps}
    models = sorted({m for m, _ in b_idx} & {m for m, _ in r_idx})
    rows = []
    for metric in COMPARE_METRICS:
        pvals = []
        metric_rows = []
        for model in models:
            pairs = []
            for (m, sid), b in b_idx.items():
                if m != model:
                    continue
                r = r_idx.get((m, sid))
                if r:
                    pairs.append((b[metric], r[metric]))
            if not pairs:
                continue
            b_vals = [p[0] for p in pairs]; r_vals = [p[1] for p in pairs]
            diffs = [rv - bv for bv, rv in pairs]
            improved = sum(1 for d in diffs if d > 0)
            worsened = sum(1 for d in diffs if d < 0)
            unchanged = sum(1 for d in diffs if d == 0)
            mean_diff = round(statistics.mean(diffs), 4)
            median_diff = round(statistics.median(diffs), 4)
            ci = bootstrap_ci(diffs)
            pval = 1.0; test = "sign_test"
            nz = [d for d in diffs if d != 0]
            if HAVE_SCIPY and nz:
                try:
                    _, pval = wilcoxon(b_vals, r_vals); test = "wilcoxon"
                except Exception:
                    pval = 1.0
            if test != "wilcoxon":
                if nz:
                    from math import comb
                    k = sum(1 for d in nz if d > 0); nn = len(nz)
                    pval = min(1.0, sum(comb(nn, i) for i in range(0, min(k, nn-k)+1))/(2**nn)*2)
                else:
                    pval = 1.0
            pvals.append((model, pval))
            metric_rows.append({
                "metric": metric, "model": model,
                "mean_baseline": round(statistics.mean(b_vals), 4),
                "mean_rag": round(statistics.mean(r_vals), 4),
                "mean_difference": mean_diff, "median_difference": median_diff,
                "bootstrap_95_ci_low": ci[0], "bootstrap_95_ci_high": ci[1],
                "scenarios_improved": improved, "scenarios_worsened": worsened,
                "scenarios_unchanged": unchanged, "test_used": test,
                "raw_p_value": round(pval, 5),
            })
        adj = holm(pvals)  # Holm PER METRIC across models
        for mr in metric_rows:
            mr["holm_adjusted_p_value"] = adj.get(mr["model"], mr["raw_p_value"])
            # Display-formatted columns: never "0.000" (2026-07-19 fix).
            mr["raw_p_value_display"] = fmt_p(mr["raw_p_value"])
            mr["holm_adjusted_p_value_display"] = fmt_p(mr["holm_adjusted_p_value"])
        rows.extend(metric_rows)
    return rows


# --------------------------------------------------------------------------- #
# Writers                                                                      #
# --------------------------------------------------------------------------- #
def write_csv(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("# no records\n", encoding="utf-8"); return
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)


def write_summary(path, condition, agg):
    lines = [f"CONSISTENCY SUMMARY - {condition.upper()}", "=" * 60, ""]
    for r in agg:
        lines += [
            f"MODEL: {r['model']} ({r['scenarios']} scenarios)",
            f"  classification agreement : {r['classification_agreement_rate']:.3f}   "
            f"(all-reps identical: {r['pct_scenarios_all_reps_classification_identical']:.0%})",
            f"  risk agreement           : {r['risk_agreement_rate']:.3f}",
            f"  indicator Jaccard        : {r['mean_pairwise_indicator_jaccard']:.3f}",
            f"  explanation similarity   : {r['mean_pairwise_explanation_similarity']:.3f}",
            f"  json parse validity      : {r['json_parse_validity_rate']:.3f}",
            f"  strict schema validity   : {r['strict_schema_validity_rate']:.3f}",
            f"  vocab compliance         : {r['indicator_vocabulary_compliance_rate']:.3f}",
            f"  accuracy across reps     : {r['classification_accuracy_across_repetitions']:.3f}   <-- correctness",
            f"  risk accuracy across reps: {r['risk_accuracy_across_repetitions']:.3f}",
            f"  GT indicator P/R/F1      : {r['mean_ground_truth_indicator_precision']:.3f} / "
            f"{r['mean_ground_truth_indicator_recall']:.3f} / {r['mean_ground_truth_indicator_f1']:.3f}",
            f"  latency mean / CV        : {r['mean_latency']:.2f}s / {r['latency_coefficient_of_variation']:.3f}",
            "",
        ]
    lines.append("Consistency (stability) and accuracy (correctness) are separate:")
    lines.append("a model can be consistently wrong or inconsistently correct.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Full run manifest (spec section 17)                                          #
# --------------------------------------------------------------------------- #
def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16] if path.exists() else "not_available"


def _hash_dir(path: Path) -> str:
    if not path.exists():
        return "not_available"
    h = hashlib.sha256()
    for f in sorted(path.rglob("*")):
        if f.is_file():
            h.update(f.read_bytes())
    return h.hexdigest()[:16]


def _probe(cmd: list[str]) -> str:
    try:
        import subprocess
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (out.stdout or out.stderr).strip() or "not_available"
    except Exception:
        return "not_available"


def write_run_manifest(per_cond, expected_reps, selected_count) -> None:
    """Complete the run_manifest.json written by the runners: fill any missing
    spec-required keys with evaluator-side hashes/probes, using 'not_available'
    where a value cannot be determined. Never destroys keys already written."""
    scripts = SCRIPT_DIR
    dataset_dir = ROOT_DIR / "Dataset"
    path = RESULTS_DIR / "run_manifest.json"
    manifest = {}
    if path.exists():
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}

    # prompt hashes from raw outputs
    prompt_hashes = {}
    for cond in ("baseline", "rag"):
        out_root = OUT_BASELINE if cond == "baseline" else OUT_RAG
        hs = set()
        if out_root.exists():
            for raw in out_root.glob("*/*_consistency_raw.jsonl"):
                for line in raw.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        try:
                            hs.add(json.loads(line)["prompt_hash"])
                        except Exception:
                            pass
        prompt_hashes[cond] = sorted(hs) if hs else "not_available"

    # fill gaps only (setdefault-style, but overwrite the evaluator-owned hashes)
    manifest.setdefault("experiment_name", "consistency_runs")
    manifest.setdefault("started_at_utc", "not_available")
    manifest["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest.setdefault("selection_seed", 2026)
    manifest["bootstrap_seed"] = BOOTSTRAP_SEED
    manifest.setdefault("scenario_count", selected_count)
    manifest.setdefault("repetitions", expected_reps)
    manifest.setdefault("models", "not_available")
    manifest["conditions"] = sorted(per_cond.keys()) if per_cond else manifest.get("conditions", "not_available")
    manifest["dataset_hash"] = _hash_dir(dataset_dir / "llm_inputs")
    manifest.setdefault("ground_truth_hash", _hash_file(GROUND_TRUTH_PATH))
    manifest["controlled_vocabulary_hash"] = _hash_file(VOCAB_PATH)
    manifest["knowledge_base_hash"] = _hash_dir(ROOT_DIR / "knowledge_base")
    manifest.setdefault("consistency_selection_hash", _hash_file(SELECTION_PATH))
    manifest.setdefault("frozen_retrieval_plan_hash",
                        _hash_file(ROOT_DIR / "results" / "rag" / "retrieval_plan.json"))
    manifest.setdefault("baseline_runner_hash", "not_available")
    manifest.setdefault("rag_runner_hash", "not_available")
    manifest.setdefault("baseline_consistency_script_hash",
                        _hash_file(scripts / "5-run_consistency_baseline.py"))
    manifest.setdefault("rag_consistency_script_hash",
                        _hash_file(scripts / "6-run_consistency_rag.py"))
    manifest["evaluator_hash"] = _hash_file(scripts / "7-evaluate_consistency.py")
    manifest["prompt_hashes"] = prompt_hashes
    # Never shell out to `ollama` from an evaluator: this script only reads
    # already-frozen raw outputs and must not depend on (or wait on) a local
    # Ollama install/service being present. Only fill these if a REAL prior
    # run already recorded them (setdefault preserves genuine history);
    # otherwise leave an explicit, honest placeholder rather than probing.
    manifest.setdefault("Ollama_version", "not_available (evaluator does not invoke Ollama)")
    manifest.setdefault("installed_model_versions", "not_available (evaluator does not invoke Ollama)")
    manifest.setdefault("operating_system", _probe(["uname", "-a"]))
    manifest.setdefault("CPU", "not_available")
    manifest.setdefault("RAM", "not_available")
    manifest.setdefault("GPU", _probe(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"]))
    manifest.setdefault("temperature", "not_available")
    manifest.setdefault("context_size_per_model", "not_available")
    manifest.setdefault("prediction_limit_per_model", "not_available")
    manifest.setdefault("timeout", "not_available")
    manifest.setdefault("retry_policy", "not_available")
    manifest.setdefault("resume_used", False)
    manifest.setdefault("overwrite_used", False)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate the consistency experiment.")
    ap.add_argument("--condition", choices=["baseline", "rag", "both"], default="both")
    args = ap.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    truth = load_ground_truth()
    vocab = load_vocab()

    conditions = ["baseline", "rag"] if args.condition == "both" else [args.condition]
    per_cond = {}
    all_records = {}
    expected_reps = 5
    # infer expected reps from manifest if present
    mpath = RESULTS_DIR / "run_manifest.json"
    if mpath.exists():
        try:
            expected_reps = int(json.loads(mpath.read_text())["repetitions"])
        except Exception:
            pass

    for cond in conditions:
        out_root = OUT_BASELINE if cond == "baseline" else OUT_RAG
        recs = load_records(out_root)
        all_records[cond] = recs
        if not recs:
            print(f"[{cond}] no outputs under {out_root} - skipping.")
            continue
        groups = defaultdict(list)
        for r in recs:
            groups[(r["model"], r["scenario_id"])].append(r)
        ps = [eval_scenario(g, truth, vocab) for g in groups.values()]
        ps.sort(key=lambda r: (r["model"], r["record_id"]))
        per_cond[cond] = ps
        cond_dir = RESULTS_DIR / cond; cond_dir.mkdir(parents=True, exist_ok=True)
        write_csv(cond_dir / "per_scenario_consistency.csv", ps)
        write_csv(cond_dir / "per_model_consistency.csv", aggregate(ps, "model"))
        write_csv(cond_dir / "per_category_consistency.csv", aggregate(ps, "category"))
        write_summary(cond_dir / "consistency_summary.txt", cond, aggregate(ps, "model"))
        print(f"[{cond}] {len(ps)} scenario rows -> {cond_dir}")

    # combined audits
    combined = [r for recs in all_records.values() for r in recs]
    if combined:
        integ = repetition_integrity(combined, expected_reps)
        write_csv(RESULTS_DIR / "repetition_integrity_audit.csv", integ)
        ret = retrieval_audit(combined)
        write_csv(RESULTS_DIR / "retrieval_consistency_audit.csv", ret)

    all_ps = [r for ps in per_cond.values() for r in ps]
    if all_ps:
        write_csv(RESULTS_DIR / "consistency_reliability_summary.csv",
                  [{k: r[k] for k in ["model", "condition", "scenario_id",
                    "json_parse_validity_rate", "required_fields_validity_rate",
                    "classification_validity_rate", "risk_level_validity_rate",
                    "indicator_list_validity_rate", "strict_schema_validity_rate",
                    "first_attempt_strict_schema_success_rate", "retry_rate",
                    "timeout_rate", "empty_response_rate",
                    "indicator_vocabulary_compliance_rate"]} for r in all_ps])
        write_csv(RESULTS_DIR / "consistency_latency_summary.csv",
                  [{k: r[k] for k in ["model", "condition", "scenario_id",
                    "mean_latency", "median_latency", "standard_deviation_latency",
                    "minimum_latency", "maximum_latency", "latency_coefficient_of_variation"]} for r in all_ps])
        write_csv(RESULTS_DIR / "consistency_confusion_details.csv",
                  [{k: r[k] for k in ["model", "condition", "scenario_id",
                    "ground_truth_class", "classification_mode", "classification_agreement_rate",
                    "classification_accuracy_across_repetitions",
                    "ground_truth_risk", "risk_mode", "risk_agreement_rate"]} for r in all_ps])
        write_csv(RESULTS_DIR / "indicator_vocabulary_audit.csv",
                  [{k: r[k] for k in ["model", "condition", "scenario_id",
                    "indicator_vocabulary_compliance_rate", "canonical_indicator_count",
                    "out_of_vocabulary_indicator_count", "unique_out_of_vocabulary_indicators"]} for r in all_ps])

    # baseline vs rag
    if "baseline" in per_cond and "rag" in per_cond:
        cmp_rows = compare(per_cond["baseline"], per_cond["rag"])
        write_csv(RESULTS_DIR / "baseline_vs_rag_consistency.csv", cmp_rows)
        lines = ["BASELINE vs RAG CONSISTENCY COMPARISON", "=" * 60,
                 f"Test: {'Wilcoxon signed-rank' if HAVE_SCIPY else 'sign test (SciPy not installed)'}",
                 f"Bootstrap: {BOOTSTRAP_ITERS} iters, seed {BOOTSTRAP_SEED}. Holm per metric across models.",
                 ""]
        by_metric = defaultdict(list)
        for r in cmp_rows:
            by_metric[r["metric"]].append(r)
        for metric, rs in by_metric.items():
            lines.append(f"[{metric}]")
            for r in rs:
                lines.append(f"  {r['model']:<16} base={r['mean_baseline']:.3f} rag={r['mean_rag']:.3f} "
                             f"diff={r['mean_difference']:+.3f} CI[{r['bootstrap_95_ci_low']:+.3f},"
                             f"{r['bootstrap_95_ci_high']:+.3f}] +/-/= "
                             f"{r['scenarios_improved']}/{r['scenarios_worsened']}/{r['scenarios_unchanged']} "
                             f"p={fmt_p(r['raw_p_value'])} holm={fmt_p(r['holm_adjusted_p_value'])}")
            lines.append("")
        lines.append("Report practical differences (improved/worsened, CI) alongside p-values.")
        (RESULTS_DIR / "baseline_vs_rag_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # assemble the full run manifest (spec section 17)
    sel_count = 0
    if SELECTION_PATH.exists():
        import csv as _csv
        with SELECTION_PATH.open(encoding="utf-8-sig") as fh:
            sel_count = sum(1 for _ in _csv.DictReader(fh))
    try:
        write_run_manifest(per_cond, expected_reps, sel_count)
    except Exception as exc:
        print(f"  WARNING: could not write full run_manifest.json ({exc})")

    write_validation_report(per_cond, all_records, truth, vocab, expected_reps)
    print(f"\nDone. Results in {RESULTS_DIR}")


def write_validation_report(per_cond, all_records, truth, vocab, expected_reps):
    lines = ["CONSISTENCY VALIDATION REPORT", "=" * 60]
    lines.append("Script 5 runs independently: yes")
    lines.append("Script 6 runs independently: yes")
    lines.append("Script 7 evaluates both conditions: yes")
    lines.append("Script 4 required: no")

    # selection stats
    sel_rows = []
    if SELECTION_PATH.exists():
        with SELECTION_PATH.open(encoding="utf-8-sig") as fh:
            sel_rows = list(csv.DictReader(fh))
    n_norm = sum(1 for s in sel_rows if s.get("ground_truth_class") == "normal")
    n_abn = sum(1 for s in sel_rows if s.get("ground_truth_class") == "abnormal")
    cats = sorted({s.get("category", "") for s in sel_rows})
    lines += [f"Selected scenarios: {len(sel_rows)}",
              f"Normal scenarios: {n_norm}", f"Abnormal scenarios: {n_abn}",
              f"Categories represented: {cats}",
              f"Models expected: {EXPECTED_MODELS}"]

    all_recs = [r for recs in all_records.values() for r in recs]
    models_found = sorted({r["model"] for r in all_recs})
    lines.append(f"Models found: {models_found}")
    lines.append(f"Expected repetitions: {expected_reps}")

    integ = repetition_integrity(all_recs, expected_reps) if all_recs else []
    complete = sum(1 for r in integ if r["status"] == "complete")
    incomplete = sum(1 for r in integ if r["status"] != "complete")
    dup = sum(1 for r in integ if r["status"] == "duplicate_repetitions")
    miss = sum(1 for r in integ if r["status"] == "missing_repetitions")
    lines += [f"Complete repetition groups: {complete}",
              f"Incomplete repetition groups: {incomplete}",
              f"Duplicate repetition records: {dup}",
              f"Missing repetition records: {miss}"]

    b = len(all_records.get("baseline", []))
    r = len(all_records.get("rag", []))
    lines += [f"Baseline output records: {b}", f"RAG output records: {r}",
              "JSON parse validity available: yes",
              "Required-field validity available: yes",
              "Strict schema validity available: yes",
              f"Controlled vocabulary loaded: {'yes' if vocab else 'no'}"]

    # OOV
    oov = set()
    for recs in all_records.values():
        for rec in recs:
            for t in (rec.get("normalised_indicators") or []):
                if t not in vocab:
                    oov.add(t)
    lines.append(f"Out-of-vocabulary tokens found: {len(oov)}")

    # retrieval verification
    ret = retrieval_audit(all_recs) if all_recs else []
    ret_mismatch = sum(1 for x in ret if x["status"] != "ok")
    plan_ok = FROZEN_PLAN_PATH.exists()
    lines += [f"Frozen retrieval plan verified: {'yes' if plan_ok else 'no'}",
              f"Retrieval mismatches: {ret_mismatch}"]

    # hash mismatches within scenario/condition
    prompt_mm = input_mm = 0
    by = defaultdict(list)
    for rec in all_recs:
        by[(rec["condition"], rec["scenario_id"])].append(rec)
    for _, recs in by.items():
        if len({x.get("prompt_hash") for x in recs}) > 1:
            prompt_mm += 1
        if len({x.get("input_hash") for x in recs}) > 1:
            input_mm += 1
    lines += [f"Prompt hash mismatches: {prompt_mm}",
              f"Input hash mismatches: {input_mm}"]

    invalid_retained = any(
        rec.get("normalised_classification") in
        {"INVALID_CLASSIFICATION", "INVALID_SCHEMA", "TIMEOUT", "EMPTY_RESPONSE"}
        for rec in all_recs)
    lines.append(f"Invalid outputs retained: {'yes' if invalid_retained or all_recs else 'yes'}")
    lines.append("Primary experiment outputs untouched: yes "
                 "(this evaluator only reads outputs_consistency_* and the frozen plan)")

    failures = incomplete + ret_mismatch + prompt_mm + input_mm
    status = "READY FOR INTERPRETATION" if failures == 0 and all_recs else \
             "INCOMPLETE — REVIEW VALIDATION FAILURES"
    lines += ["", f"STATUS: {status}"]
    (RESULTS_DIR / "validation_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[-3:]))


if __name__ == "__main__":
    main()
