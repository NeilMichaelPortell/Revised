#!/usr/bin/env python3
"""
run_baseline_experiment.py
==========================

Unattended BASELINE-ONLY experiment runner for the revised MCAST dissertation:
"Real-Time Detection and Adaptive Analysis of Risky User Actions on Endpoints".

WHAT THIS SCRIPT DOES
---------------------
* Runs each installed local Ollama model, one at a time, against ALL 120 neutral
  scenario inputs (R001-R120) using BASELINE prompting only (no knowledge base).
  This isolates each model's raw tendency toward false positives / false negatives.
* For every model it performs a controlled load cycle so the machine can be left
  running for hours unattended:
      stop everything -> wait -> warm-load target model -> wait -> run 120 -> stop -> wait
* It is LEAKAGE-SAFE. Models only ever see llm_inputs/R###.json (context_state +
  event_summary). Ground-truth labels are joined in AFTERWARDS, purely for scoring
  and for the review columns, never inside the prompt.
* Output is written per model into results/baseline/<model>/ as:
      - a human-readable review CSV (one row per scenario)
      - a raw JSONL audit trail (full prompt-free record of each call)
      - a summary text block with the headline metrics

The review CSV is designed to drop straight into the dissertation. Per-row it gives
you the raw ingredients (predicted vs ground truth, a match flag, latency, indicator
overlap). Aggregate metrics that only make sense across the whole set (precision,
recall, F1, risk accuracy) are written to a SEPARATE summary section, because a
per-row "F1 score" would be meaningless.

PRIVACY / LOCAL EXECUTION
-------------------------
All inference runs ENTIRELY on the local machine. This script talks to Ollama's
HTTP interface at http://localhost:11434 -- "localhost" (127.0.0.1) is this
computer only and is not reachable from the internet. The models used are the
ones already downloaded locally via `ollama pull`; they execute on the local
GPU. No endpoint behaviour data, prompt, or scenario is ever sent to any cloud
or external service. The run works with the network disconnected (aside from
the local loopback), which can be used to verify this. This preserves the
privacy-preserving, on-premises design that motivates using local LLMs.

USAGE
-----
    python run_baseline_experiment.py                 # all 5 models, full 120
    python run_baseline_experiment.py --limit 3       # smoke test, first 3 scenarios
    python run_baseline_experiment.py --models llama3 # single model
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------- #
# Paths                                                                        #
# --------------------------------------------------------------------------- #
# Resolve everything relative to the dataset root so the script works no matter
# where the terminal was opened from. Adjust ROOT_DIR if you move the script.
ROOT_DIR = Path(__file__).resolve().parents[2]   # scripts\runs\ -> revised\
DATASET_DIR = ROOT_DIR / "Dataset"
LLM_INPUTS_DIR = DATASET_DIR / "llm_inputs"
RUNNER_MAPPING_PATH = DATASET_DIR / "runner_mapping.csv"
GROUND_TRUTH_PATH = DATASET_DIR / "ground_truth_FINAL.csv"
RESULTS_DIR = ROOT_DIR / "results"
OUTPUTS_DIR = RESULTS_DIR / "baseline"


# --------------------------------------------------------------------------- #
# Experiment configuration                                                     #
# --------------------------------------------------------------------------- #
# The five installed models. The three "main" models come first so, if you ever
# interrupt the run, the dissertation-critical results are captured first.
MODELS = [
    "llama3",
    "deepseek-r1:8b",
    "gemma3:12b",
    "qwen3:8b",
    "gpt-oss:20b",
]

# This run is baseline-only by design (see the message thread): no knowledge base
# context is injected. The knowledge-augmented run is a separate experiment.
PROMPT_MODE = "baseline"

# Load-cycle timing (seconds). These are deliberately generous because the point
# is an unattended multi-hour run where a model must be fully unloaded and the
# next fully resident in VRAM before timing begins. Tune to taste.
UNLOAD_WAIT = 20        # after 'ollama stop', let VRAM clear
WARMUP_WAIT = 25        # after warm-load, let the model settle before timing
BETWEEN_CALL_WAIT = 0   # optional pause between scenarios (0 = none)

CALL_TIMEOUT = 300      # per-scenario hard timeout (seconds); raised for gpt-oss:20b
MAX_RETRIES = 2         # retries on invalid/empty JSON before recording a failure

# Per-model generation options passed to the Ollama API.
#
# The critical setting is num_predict (max output tokens). Reasoning models
# (deepseek-r1, qwen3, and especially gpt-oss:20b) emit a long chain-of-thought
# BEFORE the JSON answer. With the default output budget (~128-256 tokens) the
# response is truncated mid-reasoning and never reaches a complete JSON object,
# which is exactly why gpt-oss:20b returned 0 valid JSON. Giving it a large
# num_predict lets it finish thinking AND produce the JSON. num_ctx sets the
# context window so the prompt + reasoning + output all fit.
#
# temperature 0 = deterministic output, for reproducibility (an examiner point).
DEFAULT_OPTIONS = {"temperature": 0, "num_ctx": 4096, "num_predict": 1024}
MODEL_OPTIONS: dict[str, dict[str, Any]] = {
    # gpt-oss:20b reasons heavily in prose; give it a much larger budget so the
    # JSON is reached and completed rather than cut off mid-thought.
    "gpt-oss:20b": {"temperature": 0, "num_ctx": 8192, "num_predict": 4096},
    # Other reasoning models also benefit from headroom.
    "deepseek-r1:8b": {"temperature": 0, "num_ctx": 4096, "num_predict": 2048},
    "qwen3:8b": {"temperature": 0, "num_ctx": 4096, "num_predict": 2048},
}


def options_for(model: str) -> dict[str, Any]:
    """Return the generation options for a model, falling back to the default."""
    return MODEL_OPTIONS.get(model, DEFAULT_OPTIONS)


# Models that should NOT be constrained with format:json (their reasoning
# format produces malformed output when JSON-constrained). extract_json()
# recovers the JSON from their free-form prose instead.
NO_FORMAT_JSON_MODELS = {"gpt-oss:20b"}


# --------------------------------------------------------------------------- #
# Loading dataset artefacts (ground truth used ONLY for post-hoc scoring)      #
# --------------------------------------------------------------------------- #
def load_runner_mapping() -> list[dict[str, str]]:
    """record_id -> scenario_id -> input_file. Defines run order (R001..R120)."""
    with RUNNER_MAPPING_PATH.open("r", newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    rows.sort(key=lambda r: r["record_id"])  # stable R001..R120 order
    return rows


def load_ground_truth() -> dict[str, dict[str, str]]:
    """
    scenario_id -> full ground-truth row.

    Uses csv.DictReader (NOT manual comma-splitting) because expected_indicators
    and label_reason contain commas inside quoted fields.
    """
    truth: dict[str, dict[str, str]] = {}
    with GROUND_TRUTH_PATH.open("r", newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            truth[row["scenario_id"]] = row
    return truth


def load_neutral_input(input_file: str) -> dict[str, Any]:
    """Load a single leakage-safe R###.json input (context_state + event_summary)."""
    path = LLM_INPUTS_DIR / input_file
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Prompt construction (baseline, no knowledge base)                            #
# --------------------------------------------------------------------------- #
# Fixed output schema so responses can be parsed and scored automatically.
OUTPUT_SCHEMA = {
    "classification": "normal or risky",
    "risk_level": "low, medium, high, or critical",
    "indicators": ["indicator_1", "indicator_2"],
    "explanation": "one or two sentence explanation a user could understand",
    "recommended_action": "short safe recommendation",
}


def build_baseline_prompt(neutral_input: dict[str, Any]) -> str:
    """
    Baseline prompt: the model receives ONLY the neutral scenario data and the
    required schema. No category label, no knowledge-base context, no hints.
    """
    return (
        "You are an endpoint-security analyst reviewing a summary of user and "
        "endpoint activity on a Windows device.\n"
        "Decide whether the activity is normal or risky, and estimate the risk "
        "level. Base your judgement only on the data provided.\n"
        "Return ONLY valid JSON. No markdown, no code fences, no commentary, no "
        "text before or after the JSON object.\n"
        "Use exactly this JSON schema and keep values concise:\n"
        f"{json.dumps(OUTPUT_SCHEMA, indent=2)}\n\n"
        "Observed scenario data:\n"
        f"{json.dumps(neutral_input, indent=2)}\n"
    )


# --------------------------------------------------------------------------- #
# Ollama process control                                                       #
# --------------------------------------------------------------------------- #
# The Ollama HTTP API. Default host/port; override with the OLLAMA_HOST env var
# if you run the server elsewhere.
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


def urllib_request(url: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    """
    POST a JSON payload to the Ollama API and return the parsed JSON response.
    Uses only the standard library (no requests dependency). Raises on network
    or timeout errors so call_model can classify them.
    """
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return json.loads(body)


def run_cli(args: list[str], timeout: int | None = None,
            stdin_text: str | None = None) -> subprocess.CompletedProcess:
    """Thin wrapper around subprocess.run with text mode and captured output.

    encoding/errors are set EXPLICITLY. On Windows, subprocess otherwise decodes
    with the legacy cp1252 codec, which crashes on the UTF-8 bytes Ollama emits
    in its progress/status output (e.g. byte 0x8f). Forcing utf-8 with
    errors='replace' makes decoding robust and can never raise.

    We also pass an environment with TERM=dumb and NO_COLOR set. Ollama's `run`
    command uses an interactive terminal renderer that redraws lines with ANSI
    escape codes (spinners, cursor moves). When captured to a pipe on Windows
    those escape codes get injected INTO the response text, corrupting the JSON.
    Signalling a dumb, colourless terminal reduces that; extract_json() also
    strips any escape codes that still slip through, as a second line of defence.
    """
    env = dict(os.environ)
    env["TERM"] = "dumb"
    env["NO_COLOR"] = "1"
    return subprocess.run(
        args,
        input=stdin_text,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
        check=False,
        env=env,
    )


def stop_all_models() -> None:
    """
    Best-effort unload of every installed model. 'ollama stop' is a no-op if a
    model is not loaded, so this is safe to call blindly at the start of a cycle.
    """
    for model in MODELS:
        try:
            run_cli(["ollama", "stop", model], timeout=60)
        except Exception:
            pass  # unloading is best-effort; never let it abort the run


def warm_load(model: str) -> None:
    """
    Force the target model fully into memory BEFORE timed scenarios begin, so the
    first scenario's latency is not polluted by cold-load time. Uses the HTTP API
    with an empty prompt, which Ollama treats as a load-only request.
    """
    try:
        urllib_request(
            f"{OLLAMA_HOST}/api/generate",
            {"model": model, "prompt": "", "stream": False},
            timeout=CALL_TIMEOUT,
        )
    except Exception:
        pass


def call_model(model: str, prompt: str) -> dict[str, Any]:
    """
    Run one scenario through the model via the Ollama HTTP API.

    We deliberately use the HTTP API (/api/generate) rather than `ollama run`.
    The interactive CLI renders output through a terminal (ANSI escape codes,
    spinners, line redraws) which corrupts and can truncate the captured JSON on
    Windows. The API returns the complete response as a clean JSON field with no
    terminal artefacts. We also pass "format": "json", which instructs Ollama to
    constrain the model to emit valid JSON, and stream=False to get one response.
    """
    started = time.perf_counter()
    try:
        # format:json constrains most models to emit valid JSON and helps a lot.
        # gpt-oss:20b is the exception: in the original thesis, constraining it
        # to JSON produced malformed/empty output because its reasoning format
        # fights the constraint. For that model we let it answer freely and rely
        # on extract_json()'s brace-matcher to pull the JSON out of the prose.
        use_format_json = model not in NO_FORMAT_JSON_MODELS
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": options_for(model),  # per-model token/context budget
        }
        if use_format_json:
            payload["format"] = "json"
        response = urllib_request(f"{OLLAMA_HOST}/api/generate", payload,
                                  timeout=CALL_TIMEOUT)
        # The model's text answer is in the "response" field of the API result.
        model_text = response.get("response", "") if isinstance(response, dict) else ""
        return {
            "raw_output": model_text.strip(),
            "stderr": "",
            "exit_code": 0,
            "error": "" if model_text else "Empty response from API.",
            "latency_seconds": round(time.perf_counter() - started, 3),
        }
    except urllib.error.URLError as exc:
        return {
            "raw_output": "", "stderr": "", "exit_code": None,
            "error": (f"Could not reach Ollama API at {OLLAMA_HOST}. Is 'ollama serve' "
                      f"running? ({exc})"),
            "latency_seconds": round(time.perf_counter() - started, 3),
        }
    except TimeoutError:
        return {
            "raw_output": "", "stderr": "", "exit_code": None,
            "error": f"API call timed out after {CALL_TIMEOUT}s.",
            "latency_seconds": round(time.perf_counter() - started, 3),
        }
    except Exception as exc:  # never let one bad call abort the batch
        return {
            "raw_output": "", "stderr": "", "exit_code": None,
            "error": f"Unexpected API error: {exc}",
            "latency_seconds": round(time.perf_counter() - started, 3),
        }


# --------------------------------------------------------------------------- #
# Response parsing + schema validation                                         #
# --------------------------------------------------------------------------- #
# Matches ANSI/VT escape sequences: ESC [ ... letter, plus bare ESC-bracket runs.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[<>=]|\x1b\][^\x07]*\x07?")


def clean_model_text(text: str) -> str:
    """
    Remove terminal artefacts and reasoning preambles before JSON extraction.

    Ollama's `run` renders output through an interactive terminal that redraws
    lines using ANSI escape codes (e.g. '\\x1b[5D\\x1b[K'). When captured to a
    pipe these codes get injected INTO the text, and they frequently sit right
    where a line was rewrapped, e.g. '...produ\\x1b[5D\\x1b[K\\nproductivity...'.
    Naively deleting the escape code alone would leave 'produ\\nproductivity'.
    The redraw pattern is: some truncated letters, then ESC[<n>D (cursor left n),
    ESC[K (clear line), newline, then the FULL word. So we drop the escape codes
    AND the partial fragment before the newline, keeping the corrected line.

    Reasoning models (deepseek-r1, qwen3, gpt-oss) also emit visible chain-of-
    thought, sometimes wrapped in <think>...</think>, before the JSON answer.
    We strip those tags so the JSON that follows can be found.
    """
    if not text:
        return ""
    # 1. Remove <think>...</think> reasoning blocks entirely.
    text = re.sub(r"<think>.*?</think>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    # 2. Repair the line-redraw pattern: '<partial>\x1b[..D\x1b[K\n<full>' -> '<full>'
    #    Drop the truncated fragment that precedes a cursor-left + clear-line + newline.
    text = re.sub(r"[^\n]*?\x1b\[[0-9]*D\x1b\[K\n", "", text)
    # 3. Strip any remaining ANSI escape sequences.
    text = _ANSI_RE.sub("", text)
    # 4. Remove a leading 'Thinking...' marker some models print.
    text = re.sub(r"^\s*Thinking\.\.\.\s*", "", text, flags=re.IGNORECASE)
    return text


def extract_json(text: str) -> dict[str, Any] | None:
    """
    Pull the first valid JSON object out of a model response.

    Order of attempts: clean terminal/reasoning noise, then try (a) fenced
    ```json blocks, (b) the LAST balanced {...} span (reasoning models emit
    prose containing braces before the real answer, so the last object is
    usually the intended one), (c) the first balanced span as a fallback.
    Returns None if nothing parseable is found.
    """
    if not text:
        return None
    cleaned = clean_model_text(text)

    candidates: list[str] = []
    # (a) fenced code block
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if fenced:
        candidates.append(fenced.group(1))
    # (b) every balanced-looking {...} span, tried last-first
    spans = re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", cleaned, re.DOTALL)
    candidates.extend(reversed(spans))
    # (c) greedy first-to-last as a final fallback
    greedy = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if greedy:
        candidates.append(greedy.group(0))

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "classification" in parsed:
            return parsed
    return None


REQUIRED_KEYS = {"classification", "risk_level", "indicators"}


def is_schema_valid(parsed: dict[str, Any] | None) -> bool:
    """A response is 'valid' if it parsed and contains the required fields."""
    if not parsed:
        return False
    return REQUIRED_KEYS.issubset(parsed.keys())


def normalise_class(value: Any) -> str:
    """Map assorted model phrasings to the two ground-truth labels."""
    text = str(value).strip().lower()
    if text in {"risky", "risk", "malicious", "suspicious", "abnormal"}:
        return "abnormal"
    if text in {"normal", "benign", "safe"}:
        return "normal"
    return text  # leave anything unexpected visible for manual review


# --------------------------------------------------------------------------- #
# Scoring helpers (applied AFTER the model has responded)                      #
# --------------------------------------------------------------------------- #
def indicator_overlap(predicted: Any, expected_field: str) -> float:
    """
    Proportion of expected indicators that appear as an EXACT, case-insensitive
    token among the model's returned indicators.

    Corrected 2026-07-19: tokens are normalised by case-folding and trimming
    outer whitespace ONLY -- no substring matching, no space/hyphen ->
    underscore folding, no synonym mapping. 0.0 if no indicators are expected.
    """
    expected = {e.strip().casefold() for e in re.split(r"[;,]", expected_field) if e.strip()}
    if not expected:
        return 0.0
    if isinstance(predicted, list):
        pred_tokens = {str(p).strip().casefold() for p in predicted if str(p).strip()}
    else:
        pred_tokens = {t.strip().casefold() for t in re.split(r"[;,]", str(predicted)) if t.strip()}
    return round(len(expected & pred_tokens) / len(expected), 3)


# --------------------------------------------------------------------------- #
# Per-model execution                                                          #
# --------------------------------------------------------------------------- #
REVIEW_COLUMNS = [
    "record_id",
    "scenario_id",
    "category",
    "scenario_name",
    "predicted_class",          # model output, normalised
    "ground_truth_class",       # from ground_truth_FINAL.csv
    "class_match",              # TRUE/FALSE - auto-computed
    "outcome",                  # TP / TN / FP / FN - auto-computed (risky=positive)
    "manual_review",            # BLANK - for you to fill / override
    "predicted_risk",
    "ground_truth_risk",
    "risk_match",
    "indicator_overlap",
    "predicted_indicators",
    "expected_indicators",
    "model_explanation",        # human-like feedback
    "model_recommendation",     # human-like feedback
    "latency_seconds",
    "json_valid",
    "error",
]


def classify_outcome(pred_class: str, truth_class: str) -> str:
    """Confusion-matrix cell. Positive class = 'abnormal' (a genuine risk)."""
    if pred_class == "abnormal" and truth_class == "abnormal":
        return "TP"
    if pred_class == "normal" and truth_class == "normal":
        return "TN"
    if pred_class == "abnormal" and truth_class == "normal":
        return "FP"
    if pred_class == "normal" and truth_class == "abnormal":
        return "FN"
    return "UNSCORED"  # unparseable / unexpected label


def safe_model_dir(model: str) -> str:
    """Turn 'deepseek-r1:8b' into a filesystem-safe folder name."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", model)


def run_one_model(model: str, mapping: list[dict[str, str]],
                  truth: dict[str, dict[str, str]], limit: int | None) -> None:
    model_dir = OUTPUTS_DIR / safe_model_dir(model)
    model_dir.mkdir(parents=True, exist_ok=True)
    review_path = model_dir / f"{safe_model_dir(model)}_baseline_review.csv"
    raw_path = model_dir / f"{safe_model_dir(model)}_baseline_raw.jsonl"
    summary_path = model_dir / f"{safe_model_dir(model)}_baseline_summary.txt"

    rows = mapping[:limit] if limit else mapping

    print(f"\n{'='*70}\nMODEL: {model}  ({len(rows)} scenarios, baseline)\n{'='*70}")

    # --- controlled load cycle ------------------------------------------------
    print("  [cycle] stopping all models ...")
    stop_all_models()
    time.sleep(UNLOAD_WAIT)
    print(f"  [cycle] warm-loading {model} ...")
    warm_load(model)
    time.sleep(WARMUP_WAIT)

    review_rows: list[dict[str, Any]] = []
    with raw_path.open("w", encoding="utf-8") as raw_fh:
        for entry in rows:
            record_id = entry["record_id"]
            scenario_id = entry["scenario_id"]
            gt = truth.get(scenario_id, {})

            neutral_input = load_neutral_input(entry["input_file"])
            prompt = build_baseline_prompt(neutral_input)

            # retry loop for reliability -------------------------------------
            attempt, result, parsed = 0, {}, None
            while attempt <= MAX_RETRIES:
                result = call_model(model, prompt)
                parsed = extract_json(result["raw_output"])
                if is_schema_valid(parsed):
                    break
                attempt += 1
            json_valid = is_schema_valid(parsed)

            pred_class = normalise_class(parsed.get("classification")) if parsed else ""
            pred_risk = str(parsed.get("risk_level", "")).strip().lower() if parsed else ""
            pred_inds = parsed.get("indicators", "") if parsed else ""
            explanation = str(parsed.get("explanation", "")) if parsed else ""
            recommendation = str(parsed.get("recommended_action", "")) if parsed else ""

            gt_class = gt.get("ground_truth_class", "").strip().lower()
            gt_risk = gt.get("ground_truth_risk", "").strip().lower()
            gt_inds = gt.get("expected_indicators", "")

            class_match = bool(pred_class) and pred_class == gt_class
            outcome = classify_outcome(pred_class, gt_class) if json_valid else "UNSCORED"

            review_rows.append({
                "record_id": record_id,
                "scenario_id": scenario_id,
                "category": gt.get("category", ""),
                "scenario_name": gt.get("scenario_name", ""),
                "predicted_class": pred_class,
                "ground_truth_class": gt_class,
                "class_match": str(class_match).upper(),
                "outcome": outcome,
                "manual_review": "",  # intentionally blank for you
                "predicted_risk": pred_risk,
                "ground_truth_risk": gt_risk,
                "risk_match": str(bool(pred_risk) and pred_risk == gt_risk).upper(),
                "indicator_overlap": indicator_overlap(pred_inds, gt_inds),
                "predicted_indicators": "; ".join(pred_inds) if isinstance(pred_inds, list) else str(pred_inds),
                "expected_indicators": gt_inds,
                "model_explanation": explanation,
                "model_recommendation": recommendation,
                "latency_seconds": result.get("latency_seconds", ""),
                "json_valid": str(json_valid).upper(),
                "error": result.get("error", ""),
            })

            # raw audit trail (no prompt stored; inputs are on disk already)
            raw_fh.write(json.dumps({
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "model": model, "prompt_mode": PROMPT_MODE,
                "record_id": record_id, "scenario_id": scenario_id,
                "retries_used": attempt, "json_valid": json_valid,
                **result,
            }, ensure_ascii=False) + "\n")
            raw_fh.flush()

            flag = "" if json_valid else "  <-- INVALID JSON"
            print(f"  {record_id} {scenario_id:<14} pred={pred_class or '?':<8} "
                  f"gt={gt_class:<8} {outcome:<9} {result.get('latency_seconds')}s{flag}")

            if BETWEEN_CALL_WAIT:
                time.sleep(BETWEEN_CALL_WAIT)

    # --- write review CSV -----------------------------------------------------
    with review_path.open("w", newline="", encoding="utf-8") as csv_fh:
        writer = csv.DictWriter(csv_fh, fieldnames=REVIEW_COLUMNS)
        writer.writeheader()
        writer.writerows(review_rows)

    write_summary(model, review_rows, summary_path)

    print(f"  [cycle] stopping {model} ...")
    try:
        run_cli(["ollama", "stop", model], timeout=60)
    except Exception:
        pass
    time.sleep(UNLOAD_WAIT)

    print(f"  Saved: {review_path.name}, raw JSONL, and summary.")


# --------------------------------------------------------------------------- #
# Summary metrics (aggregate + per category)                                   #
# --------------------------------------------------------------------------- #
def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    """Precision, recall, F1 for the positive (risky/abnormal) class."""
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return round(precision, 3), round(recall, 3), round(f1, 3)


def write_summary(model: str, rows: list[dict[str, Any]], path: Path) -> None:
    scored = [r for r in rows if r["outcome"] in {"TP", "TN", "FP", "FN"}]
    total = len(rows)
    valid = sum(1 for r in rows if r["json_valid"] == "TRUE")

    def counts(subset: list[dict[str, Any]]) -> dict[str, int]:
        c = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        for r in subset:
            if r["outcome"] in c:
                c[r["outcome"]] += 1
        return c

    overall = counts(scored)
    tp, tn, fp, fn = overall["TP"], overall["TN"], overall["FP"], overall["FN"]
    acc = (tp + tn) / len(scored) if scored else 0.0
    precision, recall, f1 = prf(tp, fp, fn)
    risk_acc = (sum(1 for r in scored if r["risk_match"] == "TRUE") / len(scored)) if scored else 0.0
    mean_overlap = (sum(float(r["indicator_overlap"]) for r in scored) / len(scored)) if scored else 0.0
    lat = [float(r["latency_seconds"]) for r in rows if r["latency_seconds"] not in ("", None)]
    mean_lat = sum(lat) / len(lat) if lat else 0.0

    lines = [
        f"BASELINE SUMMARY - {model}",
        "=" * 60,
        f"Scenarios run          : {total}",
        f"Valid JSON outputs     : {valid}/{total} ({valid/total:.0%})" if total else "",
        f"Scored (valid+labelled): {len(scored)}",
        "",
        "Confusion matrix (positive class = risky/abnormal)",
        f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}",
        "",
        f"Accuracy          : {acc:.3f}",
        f"Precision         : {precision:.3f}   (guards against alert fatigue)",
        f"Recall            : {recall:.3f}   (KEY: misses = real risks not caught)",
        f"F1-score          : {f1:.3f}",
        f"Risk-level accuracy: {risk_acc:.3f}",
        f"Indicator overlap  : {mean_overlap:.3f}",
        f"Mean latency (s)   : {mean_lat:.2f}",
        "",
        "PER-CATEGORY (accuracy | P | R | F1 | n scored)",
        "-" * 60,
    ]

    categories = sorted({r["category"] for r in rows if r["category"]})
    for cat in categories:
        sub = [r for r in scored if r["category"] == cat]
        c = counts(sub)
        p, rec, fone = prf(c["TP"], c["FP"], c["FN"])
        a = (c["TP"] + c["TN"]) / len(sub) if sub else 0.0
        lines.append(f"  {cat:<8} {a:.3f} | {p:.3f} | {rec:.3f} | {fone:.3f} | n={len(sub)}")

    text = "\n".join(l for l in lines if l != "")
    path.write_text(text + "\n", encoding="utf-8")
    print("\n" + text)


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Baseline-only unattended Ollama experiment runner.")
    p.add_argument("--models", nargs="+", default=MODELS, help="Models to run, in order.")
    p.add_argument("--limit", type=int, default=None, help="Run only the first N scenarios (smoke test).")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    mapping = load_runner_mapping()
    truth = load_ground_truth()

    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Loaded {len(mapping)} scenarios, {len(truth)} ground-truth rows.")
    print(f"Models: {', '.join(args.models)}")
    print(f"Mode: {PROMPT_MODE} (no knowledge augmentation)")

    started = time.time()
    for model in args.models:
        run_one_model(model, mapping, truth, args.limit)

    elapsed = (time.time() - started) / 60
    print(f"\nAll models complete in {elapsed:.1f} min. Results in {OUTPUTS_DIR}")


if __name__ == "__main__":
    main()
