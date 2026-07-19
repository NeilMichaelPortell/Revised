#!/usr/bin/env python3
"""
6-run_consistency_rag.py
========================

STANDALONE RAG (knowledge-augmented) consistency / repeatability runner.

Measures whether each model gives STABLE knowledge-augmented responses when the
SAME input (plus the SAME frozen retrieved documents) is repeated under FIXED
inference settings. Fully self-contained: it does not import or require any
shared consistency engine. It imports only stable configuration and prompt
construction from the completed RAG runner (3-run_rag.py), which it never
modifies.

It REQUIRES the frozen retrieval plan produced by the completed RAG experiment
and reuses it unchanged (identical documents/order/scores across all
repetitions and models). It writes only to results/consistency/rag/ and
results/consistency/reports/. It never modifies results/baseline/ or results/rag/;
it only reads the frozen retrieval_plan.json from the latter.

It NEVER creates the consistency selection; it reuses the one created by the
baseline consistency script.

USAGE
-----
    python 6-run_consistency_rag.py
    python 6-run_consistency_rag.py --models llama3
    python 6-run_consistency_rag.py --repetitions 5
    python 6-run_consistency_rag.py --limit 2 --repetitions 2
    python 6-run_consistency_rag.py --resume
    python 6-run_consistency_rag.py --overwrite
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import shutil
import sys
import time
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


def _import_rag_runner():
    path = SCRIPT_DIR / "3-run_rag.py"
    if not path.exists():
        raise SystemExit(
            f"3-run_rag.py must be in the same folder as this script "
            f"({SCRIPT_DIR}) so RAG settings and prompt construction can be "
            f"reused. It is never modified.")
    spec = importlib.util.spec_from_file_location("rag_runner_cfg", path)
    m = importlib.util.module_from_spec(spec)
    sys.modules["rag_runner_cfg"] = m
    spec.loader.exec_module(m)
    return m


RR = _import_rag_runner()

MODELS = RR.MODELS
DEFAULT_OPTIONS = RR.DEFAULT_OPTIONS
MODEL_OPTIONS = RR.MODEL_OPTIONS
MAX_RETRIES = RR.MAX_RETRIES
CALL_TIMEOUT = RR.CALL_TIMEOUT
UNLOAD_WAIT = RR.UNLOAD_WAIT
WARMUP_WAIT = RR.WARMUP_WAIT

ROOT_DIR = RR.ROOT_DIR
DATASET_DIR = RR.DATASET_DIR
GROUND_TRUTH_PATH = RR.GROUND_TRUTH_PATH
KNOWLEDGE_BASE_DIR = RR.KNOWLEDGE_BASE_DIR
RAG_OUTPUTS_DIR = RR.OUTPUTS_DIR                      # completed RAG outputs (read-only)
FROZEN_PLAN_PATH = RAG_OUTPUTS_DIR / "retrieval_plan.json"

CONSISTENCY_DIR = ROOT_DIR / "results" / "consistency"
OUT_DIR = CONSISTENCY_DIR / "rag"
RESULTS_DIR = CONSISTENCY_DIR / "reports"
SELECTION_PATH = RESULTS_DIR / "consistency_selection.csv"
CONDITION = "rag"


# --------------------------------------------------------------------------- #
# Local helpers (duplicated deliberately; no shared module)                    #
# --------------------------------------------------------------------------- #
def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16] if path.exists() else "not_available"


def safe_model_dir(model: str) -> str:
    return RR.safe_model_dir(model)


def normalise_class(value: Any) -> str:
    t = str(value).strip().lower()
    if t in {"risky", "risk", "malicious", "suspicious", "abnormal"}:
        return "abnormal"
    if t in {"normal", "benign", "safe"}:
        return "normal"
    return t


def validate_response(parsed: dict[str, Any] | None) -> dict[str, bool]:
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


def load_selection(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    rows.sort(key=lambda r: int(r["selection_order"]))
    return rows


def run_repetition(model: str, prompt: str) -> dict[str, Any]:
    attempt_logs = []
    parsed = None
    result: dict[str, Any] = {}
    attempts_used = 0
    first_v = None
    while attempts_used < MAX_RETRIES + 1:
        result = RR.call_model(model, prompt)
        attempts_used += 1
        parsed = RR.extract_json(result["raw_output"])
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
        if v["required_fields_valid"]:
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

    if timeout:
        norm_class = norm_risk = "TIMEOUT"
    elif empty:
        norm_class = norm_risk = "EMPTY_RESPONSE"
    elif not final_v["required_fields_valid"]:
        norm_class = norm_risk = "INVALID_SCHEMA"
    else:
        norm_class = normalise_class(raw_class) if final_v["classification_valid"] else "INVALID_CLASSIFICATION"
        norm_risk = str(raw_risk).strip().lower() if final_v["risk_level_valid"] else "INVALID_RISK"

    norm_inds = sorted({str(x).strip().lower() for x in raw_inds if str(x).strip()}) \
        if isinstance(raw_inds, list) else []

    return {
        "raw_model_response": raw_output, "parsed_response": parsed,
        "raw_classification": raw_class, "normalised_classification": norm_class,
        "raw_risk_level": raw_risk, "normalised_risk_level": norm_risk,
        "raw_indicators": raw_inds, "normalised_indicators": norm_inds,
        "raw_explanation": explanation, "raw_recommended_action": recommended,
        "attempt_logs": attempt_logs, "attempts_used": attempts_used, "retries_used": retries_used,
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
        "timeout": timeout, "empty_response": empty, "error": err,
    }


def load_completed(raw_path: Path) -> set:
    done = set()
    if raw_path.exists():
        for line in raw_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line); done.add((r["scenario_id"], int(r["repetition"])))
            except Exception:
                continue
    return done


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Standalone RAG consistency runner.")
    p.add_argument("--models", nargs="+", default=MODELS)
    p.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--overwrite", action="store_true")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # selection MUST already exist (created by baseline consistency script)
    if not SELECTION_PATH.exists():
        raise SystemExit(
            "Consistency selection not found. Run the baseline consistency script "
            "first or provide the frozen consistency_selection.csv.")
    selected = load_selection(SELECTION_PATH)
    print(f"Reusing selection: {SELECTION_PATH} ({len(selected)} scenarios)")

    # frozen retrieval plan MUST exist
    if not FROZEN_PLAN_PATH.exists():
        raise SystemExit(
            "Frozen RAG retrieval plan not found. RAG consistency testing requires "
            "the exact retrieval plan used by the completed RAG experiment.")
    rag_plan = json.loads(FROZEN_PLAN_PATH.read_text(encoding="utf-8"))
    plan_hash = sha256_file(FROZEN_PLAN_PATH)
    print(f"Loaded frozen retrieval plan: {FROZEN_PLAN_PATH} (hash {plan_hash})")

    kb = RR.load_knowledge_base()
    if not kb:
        raise SystemExit(f"No knowledge base found under {KNOWLEDGE_BASE_DIR}.")
    kb_by_id = {d["doc_id"]: d for d in kb}

    mapping = RR.load_runner_mapping()
    truth = RR.load_ground_truth()
    mapping_by_record = {m["record_id"]: m for m in mapping}

    sel = selected[:args.limit] if args.limit else selected

    existing = list(OUT_DIR.glob("*/*_rag_consistency_raw.jsonl"))
    if existing and not args.resume and not args.overwrite:
        raise SystemExit(
            f"RAG consistency outputs already exist in {OUT_DIR}.\n"
            f"Use --resume to continue, or --overwrite to replace them. "
            f"(Completed results/rag/ is never modified.)")
    if args.overwrite:
        for m in args.models:
            md = OUT_DIR / safe_model_dir(m)
            if md.exists():
                shutil.rmtree(md)
        print("Overwrite: cleared RAG consistency outputs for selected models.")

    run_order = 0
    started = time.time()
    for model in args.models:
        model_dir = OUT_DIR / safe_model_dir(model)
        model_dir.mkdir(parents=True, exist_ok=True)
        raw_path = model_dir / f"{safe_model_dir(model)}_rag_consistency_raw.jsonl"
        done = load_completed(raw_path) if args.resume else set()
        mode_open = "a" if (args.resume and raw_path.exists()) else "w"

        print(f"\n{'='*72}\nRAG CONSISTENCY  MODEL: {model}  "
              f"({len(sel)} scenarios x {args.repetitions} reps)\n{'='*72}")
        print("  [cycle] stopping all models ...")
        RR.stop_all_models(); time.sleep(UNLOAD_WAIT)
        print(f"  [cycle] warm-loading {model} ...")
        RR.warm_load(model); time.sleep(WARMUP_WAIT)

        with raw_path.open(mode_open, encoding="utf-8") as raw_fh:
            for entry in sel:
                record_id = entry["record_id"]; scenario_id = entry["scenario_id"]
                gt = truth.get(scenario_id, {})
                neutral_input = RR.load_neutral_input(mapping_by_record[record_id]["input_file"])

                plan_entry = rag_plan.get(record_id)
                if plan_entry is None:
                    raise SystemExit(
                        f"Frozen retrieval plan has no entry for {record_id}. "
                        f"The plan does not match the current dataset/selection.")
                retrieved = [
                    {"doc": kb_by_id[d["document_id"]], "score": d["score"], "rank": d["rank"]}
                    for d in plan_entry["documents"]
                ]
                retrieved_ids = [r["doc"]["doc_id"] for r in retrieved]
                retrieved_scores = [r["score"] for r in retrieved]
                retrieved_ranks = [r["rank"] for r in retrieved]
                retrieval_plan_hash = sha256_text(json.dumps(plan_entry["documents"], sort_keys=True))

                prompt = RR.build_rag_prompt(neutral_input, retrieved)
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
                        "selection_seed": SELECTION_SEED,
                        "prompt_hash": prompt_hash, "input_hash": input_hash,
                        "retrieval_plan_hash": retrieval_plan_hash,
                        "retrieved_document_ids": retrieved_ids,
                        "retrieved_document_scores": retrieved_scores,
                        "retrieved_document_ranks": retrieved_ranks,
                        **rec,
                    }
                    raw_fh.write(json.dumps(row, ensure_ascii=False) + "\n"); raw_fh.flush()
                    flag = "" if rec["required_fields_valid"] else "  <-- INVALID"
                    kb_disp = ",".join(retrieved_ids) if retrieved_ids else "NONE"
                    print(f"  {record_id} {scenario_id:<13} rep {rep}/{args.repetitions} "
                          f"class={rec['normalised_classification']:<14} kb=[{kb_disp}] "
                          f"{rec['total_attempt_latency_seconds']}s{flag}")

        print(f"  [cycle] stopping {model} ...")
        try:
            RR.run_cli(["ollama", "stop", model], timeout=60)
        except Exception:
            pass
        time.sleep(UNLOAD_WAIT)

    write_manifest(args, selected, plan_hash)
    print(f"\nRAG consistency complete in {(time.time()-started)/60:.1f} min.")
    print(f"Raw outputs: {OUT_DIR}")
    print("Next: python 7-evaluate_consistency.py")


def write_manifest(args, selected, plan_hash) -> None:
    path = RESULTS_DIR / "run_manifest.json"
    manifest = {}
    if path.exists():
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}
    manifest.setdefault("experiment_name", "consistency_runs")
    manifest.setdefault("started_at_utc", datetime.now(timezone.utc).isoformat())
    manifest["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["selection_seed"] = SELECTION_SEED
    manifest["bootstrap_seed"] = 2026
    manifest["scenario_count"] = len(selected)
    manifest["repetitions"] = args.repetitions
    manifest["models"] = args.models
    manifest.setdefault("conditions", [])
    manifest["conditions"] = sorted(set(manifest["conditions"]) | {"rag"})
    manifest["ground_truth_hash"] = sha256_file(GROUND_TRUTH_PATH)
    manifest["consistency_selection_hash"] = sha256_file(SELECTION_PATH)
    manifest["frozen_retrieval_plan_hash"] = plan_hash
    manifest["rag_runner_hash"] = sha256_file(SCRIPT_DIR / "3-run_rag.py")
    manifest["rag_consistency_script_hash"] = sha256_file(Path(__file__))
    manifest["temperature"] = DEFAULT_OPTIONS.get("temperature")
    manifest["timeout"] = CALL_TIMEOUT
    manifest["retry_policy"] = f"max_retries={MAX_RETRIES}"
    manifest["resume_used"] = bool(args.resume)
    manifest["overwrite_used"] = bool(args.overwrite)
    manifest.setdefault("Ollama_version", "not_available")
    manifest.setdefault("operating_system", sys.platform)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
