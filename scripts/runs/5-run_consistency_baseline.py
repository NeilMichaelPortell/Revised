#!/usr/bin/env python3
"""
5-run_consistency_baseline.py
=============================

STANDALONE baseline consistency / repeatability runner.

Measures whether each model gives STABLE baseline responses when the SAME input
is repeated under FIXED inference settings. This script is fully self-contained:
it does not import or require any shared consistency engine. It imports only
stable configuration and prompt construction from the completed baseline runner
(1-run_baseline.py), which it never modifies.

It writes only to results/consistency/baseline/ and
results/consistency/reports/. It never touches results/baseline/ or results/rag/.

USAGE
-----
    python 5-run_consistency_baseline.py
    python 5-run_consistency_baseline.py --models llama3
    python 5-run_consistency_baseline.py --repetitions 5
    python 5-run_consistency_baseline.py --limit 2 --repetitions 2
    python 5-run_consistency_baseline.py --resume
    python 5-run_consistency_baseline.py --overwrite
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import random
import shutil
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
SELECTION_SEED = 2026
DEFAULT_SAMPLE_SIZE = 20
DEFAULT_REPETITIONS = 5
CATEGORIES = ["NORMAL", "AUTH", "USB", "SEC", "PROC", "NET", "PERSIST"]

VALID_CLASSES = {"normal", "abnormal", "risky"}
VALID_RISKS = {"low", "medium", "high", "critical"}
REQUIRED_KEYS = {"classification", "risk_level", "indicators"}


# --------------------------------------------------------------------------- #
# Import stable config + prompt from the completed baseline runner (read-only) #
# --------------------------------------------------------------------------- #
def _import_baseline_runner():
    path = SCRIPT_DIR / "1-run_baseline.py"
    if not path.exists():
        raise SystemExit(
            f"1-run_baseline.py must be in the same folder as this script "
            f"({SCRIPT_DIR}) so baseline settings and prompt construction can be "
            f"reused. It is never modified.")
    spec = importlib.util.spec_from_file_location("baseline_runner_cfg", path)
    m = importlib.util.module_from_spec(spec)
    sys.modules["baseline_runner_cfg"] = m
    spec.loader.exec_module(m)
    return m


BR = _import_baseline_runner()

# stable settings pulled from the baseline runner (single source of truth)
MODELS = BR.MODELS
DEFAULT_OPTIONS = BR.DEFAULT_OPTIONS
MODEL_OPTIONS = BR.MODEL_OPTIONS
NO_FORMAT_JSON_MODELS = BR.NO_FORMAT_JSON_MODELS
MAX_RETRIES = BR.MAX_RETRIES
CALL_TIMEOUT = BR.CALL_TIMEOUT
UNLOAD_WAIT = BR.UNLOAD_WAIT
WARMUP_WAIT = BR.WARMUP_WAIT

ROOT_DIR = BR.ROOT_DIR
DATASET_DIR = BR.DATASET_DIR
GROUND_TRUTH_PATH = BR.GROUND_TRUTH_PATH
RUNNER_MAPPING_PATH = BR.RUNNER_MAPPING_PATH

CONSISTENCY_DIR = ROOT_DIR / "results" / "consistency"
OUT_DIR = CONSISTENCY_DIR / "baseline"
RESULTS_DIR = CONSISTENCY_DIR / "reports"
SELECTION_PATH = RESULTS_DIR / "consistency_selection.csv"
CONDITION = "baseline"


# --------------------------------------------------------------------------- #
# Small local helpers (duplicated deliberately; no shared module)             #
# --------------------------------------------------------------------------- #
def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16] if path.exists() else "not_available"


def safe_model_dir(model: str) -> str:
    return BR.safe_model_dir(model)


def normalise_class(value: Any) -> str:
    t = str(value).strip().lower()
    if t in {"risky", "risk", "malicious", "suspicious", "abnormal"}:
        return "abnormal"
    if t in {"normal", "benign", "safe"}:
        return "normal"
    return t


def validate_response(parsed: dict[str, Any] | None) -> dict[str, bool]:
    """Distinct validity fields (matches the spec's six-field breakdown)."""
    parse_valid = isinstance(parsed, dict)
    keys_valid = parse_valid and REQUIRED_KEYS.issubset(parsed)
    class_valid = keys_valid and str(parsed["classification"]).strip().lower() in VALID_CLASSES
    risk_valid = keys_valid and str(parsed["risk_level"]).strip().lower() in VALID_RISKS
    ind_valid = (keys_valid and isinstance(parsed["indicators"], list)
                 and all(isinstance(v, str) for v in parsed["indicators"]))
    strict = bool(keys_valid and class_valid and risk_valid and ind_valid)
    return {
        "json_parse_valid": parse_valid,
        "required_fields_valid": bool(keys_valid),
        "classification_valid": bool(class_valid),
        "risk_level_valid": bool(risk_valid),
        "indicator_list_valid": bool(ind_valid),
        "strict_schema_valid": strict,
    }


# --------------------------------------------------------------------------- #
# Dataset loading                                                              #
# --------------------------------------------------------------------------- #
def load_runner_mapping() -> list[dict[str, str]]:
    return BR.load_runner_mapping()


def load_ground_truth() -> dict[str, dict[str, str]]:
    return BR.load_ground_truth()


# --------------------------------------------------------------------------- #
# Stratified selection (self-contained)                                        #
# --------------------------------------------------------------------------- #
def build_selection(mapping, truth, sample_size, seed) -> list[dict[str, str]]:
    rng = random.Random(seed)
    recs = []
    for m in mapping:
        gt = truth.get(m["scenario_id"], {})
        recs.append({
            "record_id": m["record_id"], "scenario_id": m["scenario_id"],
            "category": (gt.get("category") or "").upper(),
            "ground_truth_class": (gt.get("ground_truth_class") or "").lower(),
            "ground_truth_risk": (gt.get("ground_truth_risk") or "").lower(),
            "scenario_source": (gt.get("scenario_source") or "").lower(),
        })
    half = sample_size // 2
    normals = [r for r in recs if r["ground_truth_class"] == "normal"]
    abnormals = [r for r in recs if r["ground_truth_class"] == "abnormal"]
    rng.shuffle(normals); rng.shuffle(abnormals)
    selected, chosen = [], set()

    def take(pool, pred, reason):
        for r in pool:
            if r["scenario_id"] in chosen:
                continue
            if pred(r):
                r = dict(r); r["selection_reason"] = reason
                selected.append(r); chosen.add(r["scenario_id"]); return True
        return False

    for cat in CATEGORIES:
        if sum(1 for s in selected if s["ground_truth_class"] == "normal") >= half:
            break
        take(normals, lambda r, c=cat: r["category"] == c, f"normal category coverage: {cat}")
    for risk in ["medium", "high", "critical"]:
        take(abnormals, lambda r, rk=risk: r["ground_truth_risk"] == rk,
             f"abnormal risk coverage: {risk}")
    for cat in CATEGORIES:
        if sum(1 for s in selected if s["ground_truth_class"] == "abnormal") >= half:
            break
        take(abnormals, lambda r, c=cat: r["category"] == c, f"abnormal category coverage: {cat}")
    for r in normals:
        if sum(1 for s in selected if s["ground_truth_class"] == "normal") >= half:
            break
        if r["scenario_id"] not in chosen:
            r = dict(r); r["selection_reason"] = "normal fill"
            selected.append(r); chosen.add(r["scenario_id"])
    for r in abnormals:
        if sum(1 for s in selected if s["ground_truth_class"] == "abnormal") >= half:
            break
        if r["scenario_id"] not in chosen:
            r = dict(r); r["selection_reason"] = "abnormal fill"
            selected.append(r); chosen.add(r["scenario_id"])
    for r in recs:
        if len(selected) >= sample_size:
            break
        if r["scenario_id"] not in chosen:
            r = dict(r); r["selection_reason"] = "top-up"
            selected.append(r); chosen.add(r["scenario_id"])
    selected.sort(key=lambda r: r["record_id"])
    for i, r in enumerate(selected, 1):
        r["selection_order"] = i; r["selection_seed"] = seed
    return selected[:sample_size]


def write_selection(selected, path: Path) -> None:
    cols = ["selection_order", "record_id", "scenario_id", "category",
            "ground_truth_class", "ground_truth_risk", "scenario_source",
            "selection_seed", "selection_reason"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols); w.writeheader()
        for r in selected:
            w.writerow({k: r.get(k, "") for k in cols})


def load_selection(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    rows.sort(key=lambda r: int(r["selection_order"]))
    return rows


def validate_selection(selected) -> None:
    n_norm = sum(1 for s in selected if s["ground_truth_class"] == "normal")
    n_abn = sum(1 for s in selected if s["ground_truth_class"] == "abnormal")
    cats = {s["category"] for s in selected}
    print(f"  selection: {len(selected)} scenarios, normal={n_norm} abnormal={n_abn}, "
          f"categories={sorted(cats)}")
    if not cats.issuperset(set(CATEGORIES)):
        missing = set(CATEGORIES) - cats
        print(f"  WARNING: selection missing categories: {sorted(missing)}")


# --------------------------------------------------------------------------- #
# One independent generation (retry loop, per-attempt logging)                 #
# --------------------------------------------------------------------------- #
def run_repetition(model: str, prompt: str) -> dict[str, Any]:
    attempt_logs = []
    parsed = None
    result: dict[str, Any] = {}
    attempts_used = 0
    first_v = None
    while attempts_used < MAX_RETRIES + 1:
        result = BR.call_model(model, prompt)
        attempts_used += 1
        parsed = BR.extract_json(result["raw_output"])
        v = validate_response(parsed)
        if first_v is None:
            first_v = v
        attempt_logs.append({
            "attempt_number": attempts_used,
            "raw_output": result.get("raw_output", ""),
            "error": result.get("error", ""),
            "latency_seconds": result.get("latency_seconds", 0.0),
            **v,
        })
        if v["required_fields_valid"]:  # same retry rule as baseline
            break
    retries_used = attempts_used - 1
    total_latency = round(sum(a["latency_seconds"] for a in attempt_logs), 3)
    final_v = validate_response(parsed)

    raw_output = result.get("raw_output", "")
    err = result.get("error", "")
    timeout = "timed out" in err.lower()
    empty = not raw_output.strip()

    if parsed:
        raw_class = parsed.get("classification", "")
        raw_risk = parsed.get("risk_level", "")
        raw_inds = parsed.get("indicators", [])
        explanation = str(parsed.get("explanation", ""))
        recommended = str(parsed.get("recommended_action", ""))
    else:
        raw_class = raw_risk = ""; raw_inds = []; explanation = recommended = ""

    # normalised classification with explicit invalid categories
    if timeout:
        norm_class = "TIMEOUT"; norm_risk = "TIMEOUT"
    elif empty:
        norm_class = "EMPTY_RESPONSE"; norm_risk = "EMPTY_RESPONSE"
    elif not final_v["required_fields_valid"]:
        norm_class = "INVALID_SCHEMA"; norm_risk = "INVALID_SCHEMA"
    else:
        norm_class = normalise_class(raw_class) if final_v["classification_valid"] else "INVALID_CLASSIFICATION"
        norm_risk = str(raw_risk).strip().lower() if final_v["risk_level_valid"] else "INVALID_RISK"

    norm_inds = sorted({str(x).strip().lower() for x in raw_inds if str(x).strip()}) \
        if isinstance(raw_inds, list) else []

    return {
        "raw_model_response": raw_output,
        "parsed_response": parsed,
        "raw_classification": raw_class,
        "normalised_classification": norm_class,
        "raw_risk_level": raw_risk,
        "normalised_risk_level": norm_risk,
        "raw_indicators": raw_inds,
        "normalised_indicators": norm_inds,
        "raw_explanation": explanation,
        "raw_recommended_action": recommended,
        "attempt_logs": attempt_logs,
        "attempts_used": attempts_used,
        "retries_used": retries_used,
        "first_attempt_json_parse_valid": first_v["json_parse_valid"],
        "first_attempt_required_fields_valid": first_v["required_fields_valid"],
        "first_attempt_strict_schema_valid": first_v["strict_schema_valid"],
        "final_json_parse_valid": final_v["json_parse_valid"],
        "final_required_fields_valid": final_v["required_fields_valid"],
        "final_strict_schema_valid": final_v["strict_schema_valid"],
        "total_attempt_latency_seconds": total_latency,
        "json_parse_valid": final_v["json_parse_valid"],
        "required_fields_valid": final_v["required_fields_valid"],
        "classification_valid": final_v["classification_valid"],
        "risk_level_valid": final_v["risk_level_valid"],
        "indicator_list_valid": final_v["indicator_list_valid"],
        "strict_schema_valid": final_v["strict_schema_valid"],
        "timeout": timeout,
        "empty_response": empty,
        "error": err,
    }


# --------------------------------------------------------------------------- #
# Resume support                                                               #
# --------------------------------------------------------------------------- #
def load_completed(raw_path: Path) -> set[tuple[str, int]]:
    """Return {(scenario_id, repetition)} already present in a raw JSONL file."""
    done = set()
    if raw_path.exists():
        for line in raw_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                done.add((r["scenario_id"], int(r["repetition"])))
            except Exception:
                continue
    return done


# --------------------------------------------------------------------------- #
# Build the baseline prompt (reuse the completed runner's construction)        #
# --------------------------------------------------------------------------- #
def build_prompt(neutral_input: dict[str, Any]) -> str:
    return BR.build_baseline_prompt(neutral_input)


# --------------------------------------------------------------------------- #
# Main run                                                                     #
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Standalone baseline consistency runner.")
    p.add_argument("--models", nargs="+", default=MODELS)
    p.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    p.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    p.add_argument("--selection-seed", type=int, default=SELECTION_SEED)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--overwrite", action="store_true")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    mapping = load_runner_mapping()
    truth = load_ground_truth()
    mapping_by_record = {m["record_id"]: m for m in mapping}

    # selection: create if missing (baseline may create it), else reuse
    if SELECTION_PATH.exists():
        selected = load_selection(SELECTION_PATH)
        print(f"Reusing existing selection: {SELECTION_PATH}")
    else:
        selected = build_selection(mapping, truth, args.sample_size, args.selection_seed)
        write_selection(selected, SELECTION_PATH)
        print(f"Created selection -> {SELECTION_PATH}")
    validate_selection(selected)

    sel = selected[:args.limit] if args.limit else selected

    # overwrite protection
    existing = list(OUT_DIR.glob("*/*_baseline_consistency_raw.jsonl"))
    if existing and not args.resume and not args.overwrite:
        raise SystemExit(
            f"Baseline consistency outputs already exist in {OUT_DIR}.\n"
            f"Use --resume to continue, or --overwrite to replace them. "
            f"(Primary outputs/ is never touched.)")
    if args.overwrite:
        for m in args.models:
            md = OUT_DIR / safe_model_dir(m)
            if md.exists():
                shutil.rmtree(md)
        print("Overwrite: cleared baseline consistency outputs for selected models.")

    run_order = 0
    started = time.time()
    for model in args.models:
        model_dir = OUT_DIR / safe_model_dir(model)
        model_dir.mkdir(parents=True, exist_ok=True)
        raw_path = model_dir / f"{safe_model_dir(model)}_baseline_consistency_raw.jsonl"
        done = load_completed(raw_path) if args.resume else set()
        mode_open = "a" if (args.resume and raw_path.exists()) else "w"

        print(f"\n{'='*72}\nBASELINE CONSISTENCY  MODEL: {model}  "
              f"({len(sel)} scenarios x {args.repetitions} reps)\n{'='*72}")
        print("  [cycle] stopping all models ...")
        BR.stop_all_models(); time.sleep(UNLOAD_WAIT)
        print(f"  [cycle] warm-loading {model} ...")
        BR.warm_load(model); time.sleep(WARMUP_WAIT)

        with raw_path.open(mode_open, encoding="utf-8") as raw_fh:
            for entry in sel:
                record_id = entry["record_id"]; scenario_id = entry["scenario_id"]
                gt = truth.get(scenario_id, {})
                neutral_input = BR.load_neutral_input(mapping_by_record[record_id]["input_file"])
                prompt = build_prompt(neutral_input)
                prompt_hash = sha256_text(prompt)
                input_hash = sha256_text(json.dumps(neutral_input, sort_keys=True))

                for rep in range(1, args.repetitions + 1):
                    if (scenario_id, rep) in done:
                        continue
                    run_order += 1
                    rec = run_repetition(model, prompt)
                    row = {
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "condition": CONDITION, "model": model,
                        "record_id": record_id, "scenario_id": scenario_id,
                        "category": gt.get("category", ""),
                        "repetition": rep, "run_order": run_order,
                        "selection_seed": args.selection_seed,
                        "prompt_hash": prompt_hash, "input_hash": input_hash,
                        **rec,
                    }
                    raw_fh.write(json.dumps(row, ensure_ascii=False) + "\n"); raw_fh.flush()
                    flag = "" if rec["required_fields_valid"] else "  <-- INVALID"
                    print(f"  {record_id} {scenario_id:<13} rep {rep}/{args.repetitions} "
                          f"class={rec['normalised_classification']:<14} "
                          f"{rec['total_attempt_latency_seconds']}s{flag}")

        print(f"  [cycle] stopping {model} ...")
        try:
            BR.run_cli(["ollama", "stop", model], timeout=60)
        except Exception:
            pass
        time.sleep(UNLOAD_WAIT)

    # write / update the manifest fragment for baseline
    write_manifest(args, selected)
    print(f"\nBaseline consistency complete in {(time.time()-started)/60:.1f} min.")
    print(f"Raw outputs: {OUT_DIR}")
    print("Next: python 6-run_consistency_rag.py  then  python 7-evaluate_consistency.py")


def write_manifest(args, selected) -> None:
    path = RESULTS_DIR / "run_manifest.json"
    manifest = {}
    if path.exists():
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}
    manifest.setdefault("experiment_name", "consistency_runs")
    manifest["started_at_utc"] = manifest.get("started_at_utc", datetime.now(timezone.utc).isoformat())
    manifest["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["selection_seed"] = args.selection_seed
    manifest["bootstrap_seed"] = 2026
    manifest["scenario_count"] = len(selected)
    manifest["repetitions"] = args.repetitions
    manifest["models"] = args.models
    manifest.setdefault("conditions", [])
    if "baseline" not in manifest["conditions"]:
        manifest["conditions"] = sorted(set(manifest["conditions"]) | {"baseline"})
    manifest["ground_truth_hash"] = sha256_file(GROUND_TRUTH_PATH)
    manifest["consistency_selection_hash"] = sha256_file(SELECTION_PATH)
    manifest["baseline_runner_hash"] = sha256_file(SCRIPT_DIR / "1-run_baseline.py")
    manifest["baseline_consistency_script_hash"] = sha256_file(Path(__file__))
    manifest["temperature"] = DEFAULT_OPTIONS.get("temperature")
    manifest["context_size_per_model"] = {m: MODEL_OPTIONS.get(m, DEFAULT_OPTIONS)["num_ctx"] for m in args.models}
    manifest["prediction_limit_per_model"] = {m: MODEL_OPTIONS.get(m, DEFAULT_OPTIONS)["num_predict"] for m in args.models}
    manifest["timeout"] = CALL_TIMEOUT
    manifest["retry_policy"] = f"max_retries={MAX_RETRIES}"
    manifest["resume_used"] = bool(args.resume)
    manifest["overwrite_used"] = bool(args.overwrite)
    manifest.setdefault("Ollama_version", "not_available")
    manifest.setdefault("installed_model_versions", "not_available")
    manifest.setdefault("operating_system", sys.platform)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
