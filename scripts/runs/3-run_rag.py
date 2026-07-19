#!/usr/bin/env python3
"""
3-run_rag.py
============

Knowledge-augmented (RAG) experiment runner for the revised MCAST dissertation.

This is a SEPARATE script from 1-run_baseline.py. It does not modify or read the
baseline script, the results/baseline/ folder, 0-test.py, or
2-evaluate_results.py.

CONDITION
---------
Prompt = the EXACT baseline prompt + the top-3 retrieved knowledge-base category
documents inserted as context. Nothing else changes. Same 5 models, same 120
neutral inputs, same temperature, same per-model options, same timeout, same
retry policy, same parsing, same model load-cycling as the baseline. The ONLY
difference between this and the baseline condition is the retrieved context.

The GLOBAL knowledge-base folder is NOT used for retrieval and NO global preamble
is injected (per the experiment design: baseline vs baseline+retrieved-docs).

RETRIEVAL (deterministic, reproducible, no ML)
----------------------------------------------
For each scenario, a query is built ONLY from active evidence in the neutral
input (booleans that are true, non-zero ints, non-empty/non-"none" strings and
lists). Scenario ID, record ID, category, scenario name, ground truth, expected
indicators, and label reason are never used. Each of the 34 category documents
is scored by weighted token overlap with the query:
    Expected-indicator match  : weight 3 (most evidence-specific)
    Applies-when match         : weight 2
    Body-text match            : weight 1
Top-3 documents are selected. Ties are broken deterministically by document ID.
No ground-truth category filtering is applied.

PRIVACY / LOCAL EXECUTION
-------------------------
Identical to the baseline: all inference is local via the Ollama HTTP API on
localhost. Nothing is sent externally.

OUTPUT
------
Writes to results/rag/<model>/ : review CSV, raw JSONL (with full retrieval log),
and summary. Never touches results/baseline/.

USAGE
-----
    python 3-run_rag.py                 # all 5 models, full 120
    python 3-run_rag.py --limit 3       # smoke test
    python 3-run_rag.py --models llama3 # single model
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
# Paths (script in scripts/runs/, dataset root two levels up)                  #
# --------------------------------------------------------------------------- #
ROOT_DIR = Path(__file__).resolve().parents[2]   # scripts\runs\ -> revised\
DATASET_DIR = ROOT_DIR / "Dataset"
LLM_INPUTS_DIR = DATASET_DIR / "llm_inputs"
RUNNER_MAPPING_PATH = DATASET_DIR / "runner_mapping.csv"
GROUND_TRUTH_PATH = DATASET_DIR / "ground_truth_FINAL.csv"
KNOWLEDGE_BASE_DIR = ROOT_DIR / "knowledge_base"
RESULTS_DIR = ROOT_DIR / "results"
OUTPUTS_DIR = RESULTS_DIR / "rag"               # Separate from baseline results

# Retrieval reads the seven category folders; GLOBAL is intentionally excluded.
CATEGORY_FOLDERS = ["NORMAL", "AUTH", "USB", "SEC", "PROC", "NET", "PERSIST"]


# --------------------------------------------------------------------------- #
# Experiment configuration (IDENTICAL to baseline)                             #
# --------------------------------------------------------------------------- #
MODELS = ["llama3", "deepseek-r1:8b", "gemma3:12b", "qwen3:8b", "gpt-oss:20b"]
PROMPT_MODE = "knowledge_augmented"

UNLOAD_WAIT = 20
WARMUP_WAIT = 25
BETWEEN_CALL_WAIT = 0

CALL_TIMEOUT = 300
MAX_RETRIES = 2

DEFAULT_OPTIONS = {"temperature": 0, "num_ctx": 4096, "num_predict": 1024}
MODEL_OPTIONS: dict[str, dict[str, Any]] = {
    "gpt-oss:20b": {"temperature": 0, "num_ctx": 8192, "num_predict": 4096},
    "deepseek-r1:8b": {"temperature": 0, "num_ctx": 4096, "num_predict": 2048},
    "qwen3:8b": {"temperature": 0, "num_ctx": 4096, "num_predict": 2048},
}
NO_FORMAT_JSON_MODELS = {"gpt-oss:20b"}
TOP_K = 3


def options_for(model: str) -> dict[str, Any]:
    return MODEL_OPTIONS.get(model, DEFAULT_OPTIONS)


# --------------------------------------------------------------------------- #
# Dataset loading (identical approach to baseline)                             #
# --------------------------------------------------------------------------- #
def load_runner_mapping() -> list[dict[str, str]]:
    with RUNNER_MAPPING_PATH.open("r", newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    rows.sort(key=lambda r: r["record_id"])
    return rows


def load_ground_truth() -> dict[str, dict[str, str]]:
    truth: dict[str, dict[str, str]] = {}
    with GROUND_TRUTH_PATH.open("r", newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            truth[row["scenario_id"]] = row
    return truth


def load_neutral_input(input_file: str) -> dict[str, Any]:
    return json.loads((LLM_INPUTS_DIR / input_file).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Knowledge base loading + parsing                                             #
# --------------------------------------------------------------------------- #
def parse_kb_document(path: Path) -> dict[str, Any]:
    """
    Parse a KB markdown doc into the fields the retriever scores against:
    doc_id, title, category, the Expected-indicator tokens, the Applies-when
    text, and the full body text.
    """
    text = path.read_text(encoding="utf-8", errors="replace")

    def section(header: str) -> str:
        m = re.search(rf"##\s+{re.escape(header)}\s*\n(.*?)(?=\n##\s|\Z)",
                      text, re.DOTALL)
        return m.group(1).strip() if m else ""

    doc_id_m = re.search(r"Document ID:\s*(\S+)", text)
    doc_id = doc_id_m.group(1) if doc_id_m else path.stem
    title_m = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    title = title_m.group(1).strip() if title_m else path.stem

    expected = section("Expected indicators")
    expected_tokens = [ln.strip("- ").strip()
                       for ln in expected.splitlines() if ln.strip().startswith("-")]
    # Accept either heading: the cleaned SOC docs use "Observable conditions";
    # the earlier template used "Applies when". Fall back so both parse.
    applies = section("Observable conditions") or section("Applies when")

    return {
        "doc_id": doc_id,
        "title": title,
        "category": path.parent.name,
        "path": str(path),
        "expected_tokens": expected_tokens,
        "expected_text": " ".join(expected_tokens).lower(),
        "applies_text": applies.lower(),
        "body_text": text.lower(),
        "full_text": text,
    }


def load_knowledge_base() -> list[dict[str, Any]]:
    """Load all category documents. GLOBAL is intentionally NOT loaded."""
    docs = []
    for cat in CATEGORY_FOLDERS:
        cat_dir = KNOWLEDGE_BASE_DIR / cat
        if not cat_dir.exists():
            continue
        for md in sorted(cat_dir.glob("*.md")):
            docs.append(parse_kb_document(md))
    docs.sort(key=lambda d: d["doc_id"])  # deterministic base order for tie-breaks
    return docs


# --------------------------------------------------------------------------- #
# Deterministic weighted retrieval                                             #
# --------------------------------------------------------------------------- #
# Values that mean "not observed" and must be excluded from the query.
_INACTIVE_STRINGS = {"", "none", "not_applicable", "unknown", "n/a", "null"}

# Common words that carry little discriminative power and would otherwise let
# long documents accumulate spurious matches. Excluded from the body-word score.
STOPWORDS = {
    "activity", "value", "true", "present", "observed", "normal", "none",
    "change", "changed", "information", "device", "endpoint", "user",
    "windows", "the", "and", "for", "with", "was", "not", "may", "are",
    "this", "that", "when", "from", "count", "band", "details", "context",
    "profile", "state", "action", "type", "name", "status", "event", "events",
}


def build_query_features(neutral_input: dict[str, Any]) -> dict[str, list[str]]:
    """
    Build retrieval features from ACTIVE evidence, prioritising what ACTUALLY
    HAPPENED (event_summary) over the always-present ambient configuration
    (context_state).

    The problem this solves: context_state (collector_is_admin, defender flags,
    firewall profiles, network_profile, running_monitored_processes) is populated
    in EVERY scenario. If treated equally, its generic words (network, private,
    protection, enabled) dominate scoring and pull the same benign network/normal
    documents to the top of every scenario. The distinguishing signal lives in
    event_summary (failed_login_activity, scheduled_task_change, defender_disabled,
    usb_connection_count, risky_processes, verified_activity_context, ...).

    Strategy:
      - event_summary active fields/values/words are PRIMARY features (full weight).
      - context_state contributes ONLY when it deviates from the normal baseline:
        defender disabled, a firewall profile OFF, or a non-private network
        profile. Normal context (defender on, private network) is NOT added,
        because it is not distinguishing evidence.

    Returns fields / values / words as before. Leakage-safe: none of scenario_id,
    category, ground truth, etc. exist in the neutral input.
    """
    fields: list[str] = []
    values: list[str] = []
    words: list[str] = []

    def add_words(text: str) -> None:
        for w in re.split(r"[^a-z0-9]+", text.lower()):
            if len(w) > 2 and w not in STOPWORDS:
                words.append(w)

    def walk(obj: Any, key: str | None = None) -> None:
        if isinstance(obj, bool):
            if obj and key:
                fields.append(key.lower()); add_words(key)
        elif isinstance(obj, (int, float)):
            if obj != 0 and key:
                fields.append(key.lower()); add_words(key)
        elif isinstance(obj, str):
            v = obj.strip().lower()
            if v and v not in _INACTIVE_STRINGS:
                if key:
                    fields.append(key.lower()); values.append(f"{key.lower()}={v}"); add_words(key)
                values.append(v); add_words(v)
        elif isinstance(obj, list):
            if obj and key:
                fields.append(key.lower()); add_words(key)
            for item in obj:
                walk(item, None)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, k)

    event = neutral_input.get("event_summary", {})
    context = neutral_input.get("context_state", {})

    # PRIMARY: everything active in event_summary.
    walk(event)

    # SECONDARY: only ABNORMAL context deviations, not the normal baseline.
    defender = context.get("defender", {})
    if defender.get("realtime_protection_enabled") is False or \
       defender.get("antivirus_enabled") is False or \
       defender.get("am_service_enabled") is False:
        fields.append("defender_disabled"); add_words("defender disabled protection")
    firewall = context.get("firewall", {})
    for profile, on in firewall.items():
        if on is False:
            values.append(f"firewall_{profile.lower()}=off"); add_words("firewall")
    np = str(context.get("network_profile", "")).strip().lower()
    if np and np not in _INACTIVE_STRINGS and np != "private":
        # only a non-private (e.g. public) profile is distinguishing
        fields.append("network_profile"); values.append(f"network_profile={np}"); add_words(np)

    def dedup(seq: list[str]) -> list[str]:
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    return {"fields": dedup(fields), "values": dedup(values), "words": dedup(words)}


def retrieve(features: dict[str, list[str]], kb: list[dict[str, Any]],
             top_k: int = TOP_K) -> list[dict[str, Any]]:
    """
    Score every KB doc against the query features and return up to top_k docs
    with a POSITIVE score. Weighting (per the review):

        exact expected-indicator match  : 6
        exact Applies-when field/value   : 5
        exact Applies-when field         : 3
        title phrase (word) match        : 2
        body keyword match               : 1

    The Expected-indicator and Applies-when text are excluded from the body-word
    score to avoid double counting. Ties are broken deterministically by doc_id
    (kb is pre-sorted by doc_id and Python's sort is stable).

    Documents scoring zero are NOT returned: injecting arbitrary guidance when
    nothing matches would pollute the condition. If all docs score zero, an
    empty list is returned and the scenario is logged as no_document_found.
    """
    fset = set(features["fields"])
    vset = set(features["values"])
    wset = set(features["words"])

    scored = []
    for doc in kb:
        # exact expected-indicator matches (fields or values equal a token)
        exp_tokens = set(doc["expected_tokens"])
        exp_hits = len((fset | vset) & exp_tokens)

        # Applies-when: reward exact field=value, then exact field mentions
        applies = doc["applies_text"]
        av_hits = sum(1 for v in vset if v in applies)
        af_hits = sum(1 for f in fset if f in applies)

        # title word matches
        title_words = set(re.split(r"[^a-z0-9]+", doc["title"].lower()))
        title_hits = len(wset & title_words)

        # body words EXCLUDING expected + applies sections (avoid double count)
        body_only = doc["body_text"].replace(doc["expected_text"], " ")
        body_only = body_only.replace(applies, " ")
        body_words = set(re.split(r"[^a-z0-9]+", body_only)) - STOPWORDS
        body_hits = len(wset & body_words)

        score = (6 * exp_hits + 5 * av_hits + 3 * af_hits
                 + 2 * title_hits + 1 * body_hits)
        scored.append((score, doc))

    scored.sort(key=lambda s: -s[0])   # stable; doc_id order preserved on ties
    results = []
    for rank, (score, doc) in enumerate(scored, start=1):
        if score <= 0:
            continue                    # drop zero-score docs entirely
        results.append({"doc": doc, "score": score, "rank": len(results) + 1})
        if len(results) >= top_k:
            break
    return results


# --------------------------------------------------------------------------- #
# Prompt construction: baseline prompt + retrieved context                     #
# --------------------------------------------------------------------------- #
# This OUTPUT_SCHEMA and prompt wording are IDENTICAL to the baseline runner.
OUTPUT_SCHEMA = {
    "classification": "normal or risky",
    "risk_level": "low, medium, high, or critical",
    "indicators": ["indicator_1", "indicator_2"],
    "explanation": "one or two sentence explanation a user could understand",
    "recommended_action": "short safe recommendation",
}


def load_neutral_input_raw(input_file: str) -> str:
    return (LLM_INPUTS_DIR / input_file).read_text(encoding="utf-8")


def _sha256(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def precompute_retrieval_plan(mapping: list[dict[str, str]],
                              kb: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Build ONE retrieval plan for all records. Retrieval is deterministic and
    model-independent, so it is computed once and reused for every model,
    guaranteeing all five models receive byte-identical retrieved documents.
    Stores content hashes of the KB, dataset inputs, and this script for
    reproducibility auditing.
    """
    plan: dict[str, Any] = {}
    for entry in mapping:
        neutral_input = load_neutral_input(entry["input_file"])
        features = build_query_features(neutral_input)
        retrieved = retrieve(features, kb, TOP_K)
        plan[entry["record_id"]] = {
            "scenario_id": entry["scenario_id"],
            "query_fields": features["fields"],
            "query_values": features["values"],
            "documents": [
                {"document_id": r["doc"]["doc_id"], "score": r["score"],
                 "rank": r["rank"]} for r in retrieved
            ],
            "num_docs_retrieved": len(retrieved),
            "no_document_found": len(retrieved) == 0,
        }
    kb_concat = "".join(sorted(d["full_text"] for d in kb))
    inputs_concat = "".join(load_neutral_input_raw(e["input_file"]) for e in mapping)
    plan["_meta"] = {
        "top_k": TOP_K,
        "kb_documents_hash": _sha256(kb_concat),
        "dataset_inputs_hash": _sha256(inputs_concat),
        "runner_script_hash": _sha256(Path(__file__).read_text(encoding="utf-8")),
        "kb_document_count": len(kb),
        "record_count": len(mapping),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
    }
    return plan


def build_rag_prompt(neutral_input: dict[str, Any],
                     retrieved: list[dict[str, Any]]) -> str:
    """
    The EXACT baseline prompt, with a retrieved-context block inserted before the
    scenario data. Removing the context block yields the baseline prompt verbatim.
    """
    context_lines = []
    for r in retrieved:
        doc = r["doc"]
        context_lines.append(f"--- {doc['title']} ---\n{doc['full_text'].strip()}")
    context_block = "\n\n".join(context_lines) if context_lines else "(no relevant context found)"

    return (
        "You are an endpoint-security analyst reviewing a summary of user and "
        "endpoint activity on a Windows device.\n"
        "Decide whether the activity is normal or risky, and estimate the risk "
        "level. Base your judgement only on the data provided.\n"
        "Return ONLY valid JSON. No markdown, no code fences, no commentary, no "
        "text before or after the JSON object.\n"
        "Use exactly this JSON schema and keep values concise:\n"
        f"{json.dumps(OUTPUT_SCHEMA, indent=2)}\n\n"
        "Reference guidance (may or may not be relevant; use your judgement):\n"
        f"{context_block}\n\n"
        "Observed scenario data:\n"
        f"{json.dumps(neutral_input, indent=2)}\n"
    )


# --------------------------------------------------------------------------- #
# Ollama HTTP API (identical to baseline)                                      #
# --------------------------------------------------------------------------- #
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


def urllib_request(url: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def run_cli(args: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["TERM"] = "dumb"
    env["NO_COLOR"] = "1"
    return subprocess.run(args, text=True, encoding="utf-8", errors="replace",
                          capture_output=True, timeout=timeout, check=False, env=env)


def stop_all_models() -> None:
    for model in MODELS:
        try:
            run_cli(["ollama", "stop", model], timeout=60)
        except Exception:
            pass


def warm_load(model: str) -> None:
    try:
        urllib_request(f"{OLLAMA_HOST}/api/generate",
                       {"model": model, "prompt": "", "stream": False},
                       timeout=CALL_TIMEOUT)
    except Exception:
        pass


def call_model(model: str, prompt: str) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        use_format_json = model not in NO_FORMAT_JSON_MODELS
        payload = {"model": model, "prompt": prompt, "stream": False,
                   "options": options_for(model)}
        if use_format_json:
            payload["format"] = "json"
        response = urllib_request(f"{OLLAMA_HOST}/api/generate", payload, CALL_TIMEOUT)
        model_text = response.get("response", "") if isinstance(response, dict) else ""
        return {"raw_output": model_text.strip(), "error": "" if model_text else "Empty response.",
                "latency_seconds": round(time.perf_counter() - started, 3)}
    except urllib.error.URLError as exc:
        return {"raw_output": "",
                "error": f"Could not reach Ollama API at {OLLAMA_HOST}. Is it running? ({exc})",
                "latency_seconds": round(time.perf_counter() - started, 3)}
    except TimeoutError:
        return {"raw_output": "", "error": f"API timed out after {CALL_TIMEOUT}s.",
                "latency_seconds": round(time.perf_counter() - started, 3)}
    except Exception as exc:
        return {"raw_output": "", "error": f"Unexpected API error: {exc}",
                "latency_seconds": round(time.perf_counter() - started, 3)}


# --------------------------------------------------------------------------- #
# Response parsing (identical to baseline)                                     #
# --------------------------------------------------------------------------- #
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[<>=]|\x1b\][^\x07]*\x07?")


def clean_model_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<think>.*?</think>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"[^\n]*?\x1b\[[0-9]*D\x1b\[K\n", "", text)
    text = _ANSI_RE.sub("", text)
    text = re.sub(r"^\s*Thinking\.\.\.\s*", "", text, flags=re.IGNORECASE)
    return text


def extract_json(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    cleaned = clean_model_text(text)
    candidates: list[str] = []
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if fenced:
        candidates.append(fenced.group(1))
    spans = re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", cleaned, re.DOTALL)
    candidates.extend(reversed(spans))
    greedy = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if greedy:
        candidates.append(greedy.group(0))
    for c in candidates:
        try:
            parsed = json.loads(c)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "classification" in parsed:
            return parsed
    return None


REQUIRED_KEYS = {"classification", "risk_level", "indicators"}
VALID_CLASSES = {"normal", "risky", "abnormal"}
VALID_RISKS = {"low", "medium", "high", "critical"}


def is_schema_valid(parsed: dict[str, Any] | None) -> bool:
    """BASIC validity: parsed dict with the required keys present. This drives
    the retry loop and outcome scoring, and is IDENTICAL to the baseline rule,
    so the two conditions use the same retry behaviour (fairness)."""
    return bool(parsed) and REQUIRED_KEYS.issubset(parsed.keys())


def validate_response(parsed: dict[str, Any] | None) -> dict[str, bool]:
    """STRICT validity: logged separately for reporting. Does NOT change the
    retry rule. Checks that classification/risk are in the permitted value sets
    and indicators is a list of strings, catching template-echo responses like
    {"classification": "normal or risky"} that pass the basic check."""
    parse_valid = isinstance(parsed, dict)
    keys_valid = parse_valid and REQUIRED_KEYS.issubset(parsed)
    classification_valid = keys_valid and str(parsed["classification"]).strip().lower() in VALID_CLASSES
    risk_valid = keys_valid and str(parsed["risk_level"]).strip().lower() in VALID_RISKS
    indicators_valid = (keys_valid and isinstance(parsed["indicators"], list)
                        and all(isinstance(v, str) for v in parsed["indicators"]))
    strict = keys_valid and classification_valid and risk_valid and indicators_valid
    return {
        "json_parse_valid": parse_valid,
        "required_keys_valid": keys_valid,
        "classification_valid": classification_valid,
        "risk_valid": risk_valid,
        "indicators_valid": indicators_valid,
        "strict_schema_valid": strict,
    }


def normalise_class(value: Any) -> str:
    t = str(value).strip().lower()
    if t in {"risky", "risk", "malicious", "suspicious", "abnormal"}:
        return "abnormal"
    if t in {"normal", "benign", "safe"}:
        return "normal"
    return t


# --------------------------------------------------------------------------- #
# Scoring helpers (identical to baseline)                                      #
# --------------------------------------------------------------------------- #
def indicator_overlap(predicted: Any, expected_field: str) -> float:
    expected = [e.strip().lower() for e in re.split(r"[;,]", expected_field) if e.strip()]
    if not expected:
        return 0.0
    pred_text = (" ".join(str(p).lower() for p in predicted)
                 if isinstance(predicted, list) else str(predicted).lower())
    hits = sum(1 for e in expected if e in pred_text)
    return round(hits / len(expected), 3)


def classify_outcome(pred_class: str, truth_class: str) -> str:
    if pred_class == "abnormal" and truth_class == "abnormal":
        return "TP"
    if pred_class == "normal" and truth_class == "normal":
        return "TN"
    if pred_class == "abnormal" and truth_class == "normal":
        return "FP"
    if pred_class == "normal" and truth_class == "abnormal":
        return "FN"
    return "UNSCORED"


def safe_model_dir(model: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", model)


# --------------------------------------------------------------------------- #
# Per-model run                                                                #
# --------------------------------------------------------------------------- #
REVIEW_COLUMNS = [
    "record_id", "scenario_id", "category", "scenario_name",
    "predicted_class", "ground_truth_class", "class_match", "outcome",
    "manual_review", "predicted_risk", "ground_truth_risk", "risk_match",
    "indicator_overlap", "predicted_indicators", "expected_indicators",
    "retrieved_doc_ids", "retrieved_scores",          # RAG-specific columns
    "model_explanation", "model_recommendation",
    "latency_seconds", "retries_used", "json_valid", "strict_schema_valid", "error",
]


def run_one_model(model: str, mapping: list[dict[str, str]],
                  truth: dict[str, dict[str, str]], kb: list[dict[str, Any]],
                  plan: dict[str, Any], limit: int | None) -> None:
    kb_by_id = {d["doc_id"]: d for d in kb}
    model_dir = OUTPUTS_DIR / safe_model_dir(model)
    model_dir.mkdir(parents=True, exist_ok=True)
    review_path = model_dir / f"{safe_model_dir(model)}_rag_review.csv"
    raw_path = model_dir / f"{safe_model_dir(model)}_rag_raw.jsonl"
    summary_path = model_dir / f"{safe_model_dir(model)}_rag_summary.txt"

    rows = mapping[:limit] if limit else mapping
    print(f"\n{'='*70}\nMODEL: {model}  ({len(rows)} scenarios, knowledge-augmented)\n{'='*70}")

    print("  [cycle] stopping all models ...")
    stop_all_models()
    time.sleep(UNLOAD_WAIT)
    print(f"  [cycle] warm-loading {model} ...")
    warm_load(model)
    time.sleep(WARMUP_WAIT)

    num_ctx = options_for(model)["num_ctx"]
    review_rows: list[dict[str, Any]] = []
    with raw_path.open("w", encoding="utf-8") as raw_fh:
        for entry in rows:
            record_id = entry["record_id"]
            scenario_id = entry["scenario_id"]
            gt = truth.get(scenario_id, {})
            neutral_input = load_neutral_input(entry["input_file"])

            # ---- retrieval: reuse the PRECOMPUTED plan (identical for all models) ----
            plan_entry = plan[record_id]
            retrieved = [
                {"doc": kb_by_id[d["document_id"]], "score": d["score"], "rank": d["rank"]}
                for d in plan_entry["documents"]
            ]
            retrieved_ids = [r["doc"]["doc_id"] for r in retrieved]
            retrieved_scores = [r["score"] for r in retrieved]

            prompt = build_rag_prompt(neutral_input, retrieved)

            # prompt-size guard (approx 4 chars/token)
            approx_tokens = len(prompt) // 4
            if approx_tokens > num_ctx * 0.70:
                print(f"    WARNING {record_id}: prompt ~{approx_tokens} tokens may "
                      f"leave little generation space (num_ctx={num_ctx})")

            # ---- generation with retry; LOG EVERY ATTEMPT (#3) ----
            attempt_logs = []
            attempts_used = 0
            parsed = None
            result = {}
            while attempts_used < MAX_RETRIES + 1:
                result = call_model(model, prompt)
                attempts_used += 1
                parsed = extract_json(result["raw_output"])
                attempt_logs.append({
                    "attempt": attempts_used,
                    "latency_seconds": result.get("latency_seconds", 0.0),
                    "raw_output": result.get("raw_output", ""),
                    "error": result.get("error", ""),
                    "basic_schema_valid": is_schema_valid(parsed),
                })
                if is_schema_valid(parsed):   # SAME retry rule as baseline (fairness)
                    break

            retries_used = max(0, attempts_used - 1)
            total_generation_latency = round(
                sum(a["latency_seconds"] for a in attempt_logs), 3)

            # basic validity (drives retry + scoring, matches baseline)
            json_valid = is_schema_valid(parsed)
            # strict validity (logged separately, does NOT change retry) (#1)
            strict = validate_response(parsed)

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

            retrieval_latency = 0.0  # retrieval precomputed; per-call cost ~0
            review_rows.append({
                "record_id": record_id, "scenario_id": scenario_id,
                "category": gt.get("category", ""),
                "scenario_name": gt.get("scenario_name", ""),
                "predicted_class": pred_class, "ground_truth_class": gt_class,
                "class_match": str(class_match).upper(), "outcome": outcome,
                "manual_review": "",
                "predicted_risk": pred_risk, "ground_truth_risk": gt_risk,
                "risk_match": str(bool(pred_risk) and pred_risk == gt_risk).upper(),
                "indicator_overlap": indicator_overlap(pred_inds, gt_inds),
                "predicted_indicators": "; ".join(pred_inds) if isinstance(pred_inds, list) else str(pred_inds),
                "expected_indicators": gt_inds,
                "retrieved_doc_ids": "; ".join(retrieved_ids),
                "retrieved_scores": "; ".join(str(s) for s in retrieved_scores),
                "model_explanation": explanation, "model_recommendation": recommendation,
                "latency_seconds": total_generation_latency,   # TOTAL across attempts (#3)
                "retries_used": retries_used,
                "json_valid": str(json_valid).upper(),
                "strict_schema_valid": str(strict["strict_schema_valid"]).upper(),
                "error": result.get("error", ""),
            })

            raw_fh.write(json.dumps({
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "model": model, "prompt_mode": PROMPT_MODE,
                "record_id": record_id, "scenario_id": scenario_id,
                "retries_used": retries_used, "attempts_used": attempts_used,
                "json_valid": json_valid,
                "strict_schema_validity": strict,        # (#1) full breakdown
                # ---- retrieval log (from precomputed plan) ----
                "retrieval_query_fields": plan_entry["query_fields"],
                "retrieval_query_values": plan_entry["query_values"],
                "retrieved_doc_ids": retrieved_ids,
                "retrieved_ranks": [r["rank"] for r in retrieved],
                "retrieved_scores": retrieved_scores,
                "retrieval_latency_seconds": retrieval_latency,
                "num_docs_retrieved": len(retrieved),
                "no_document_found": plan_entry["no_document_found"],
                # ---- generation ----
                "attempt_logs": attempt_logs,            # (#3) every attempt
                "total_generation_latency_seconds": total_generation_latency,
                "prompt_characters": len(prompt),
                "approx_prompt_tokens": approx_tokens,
                "raw_output": result.get("raw_output", ""),
                "parsed_response": parsed,
                "schema_valid": json_valid,
                "error": result.get("error", ""),
            }, ensure_ascii=False) + "\n")
            raw_fh.flush()

            flag = "" if json_valid else "  <-- INVALID JSON"
            kb_disp = ",".join(retrieved_ids) if retrieved_ids else "NONE"
            print(f"  {record_id} {scenario_id:<14} pred={pred_class or '?':<8} "
                  f"gt={gt_class:<8} {outcome:<9} kb=[{kb_disp}] "
                  f"{total_generation_latency}s{flag}")

            if BETWEEN_CALL_WAIT:
                time.sleep(BETWEEN_CALL_WAIT)

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
    print(f"  Saved: {review_path.name}, raw JSONL (with retrieval log), and summary.")


# --------------------------------------------------------------------------- #
# Summary (identical metric logic to baseline)                                 #
# --------------------------------------------------------------------------- #
def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return round(precision, 3), round(recall, 3), round(f1, 3)


def write_summary(model: str, rows: list[dict[str, Any]], path: Path) -> None:
    scored = [r for r in rows if r["outcome"] in {"TP", "TN", "FP", "FN"}]
    total = len(rows)
    valid = sum(1 for r in rows if r["json_valid"] == "TRUE")
    strict_valid = sum(1 for r in rows if r.get("strict_schema_valid") == "TRUE")
    invalid = total - len(scored)

    def counts(subset):
        c = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
        for r in subset:
            if r["outcome"] in c:
                c[r["outcome"]] += 1
        return c

    o = counts(scored)
    tp, tn, fp, fn = o["TP"], o["TN"], o["FP"], o["FN"]
    precision, recall, f1 = prf(tp, fp, fn)

    # (#2) PRIMARY accuracy: correct over ALL scenarios (invalid = wrong).
    correct_all = sum(1 for r in rows if r["class_match"] == "TRUE")
    accuracy_all = correct_all / total if total else 0.0
    # SECONDARY accuracy: correct over classifiable (valid) outputs only.
    accuracy_valid = (tp + tn) / len(scored) if scored else 0.0

    risk_acc = (sum(1 for r in scored if r["risk_match"] == "TRUE") / len(scored)) if scored else 0.0
    mean_overlap = (sum(float(r["indicator_overlap"]) for r in scored) / len(scored)) if scored else 0.0
    lat = [float(r["latency_seconds"]) for r in rows if r["latency_seconds"] not in ("", None)]
    mean_lat = sum(lat) / len(lat) if lat else 0.0

    lines = [
        f"KNOWLEDGE-AUGMENTED (RAG) SUMMARY - {model}",
        "=" * 60,
        f"Scenarios run              : {total}",
        f"Valid JSON (basic) outputs : {valid}/{total} ({valid/total:.0%})" if total else "",
        f"Strict-schema-valid outputs: {strict_valid}/{total} ({strict_valid/total:.0%})" if total else "",
        f"Scored (valid+labelled)    : {len(scored)}",
        f"Invalid/unclassifiable     : {invalid}",
        "",
        "Confusion matrix (positive class = risky/abnormal)",
        f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}  Invalid/unclassifiable={invalid}",
        "",
        f"ALL-SCENARIO accuracy (primary): {accuracy_all:.3f}   (correct / {total}; invalid counted wrong)",
        f"Valid-output accuracy          : {accuracy_valid:.3f}   (correct / {len(scored)} classifiable)",
        f"Precision         : {precision:.3f}   (guards against alert fatigue)",
        f"Recall            : {recall:.3f}   (KEY: misses = real risks not caught)",
        f"F1-score          : {f1:.3f}",
        f"Risk-level accuracy: {risk_acc:.3f}",
        f"Indicator overlap  : {mean_overlap:.3f}",
        f"Mean total latency (s): {mean_lat:.2f}   (summed across retry attempts)",
        "",
        "PER-CATEGORY (all-scenario acc | P | R | F1 | n | invalid)",
        "-" * 60,
    ]
    for cat in sorted({r["category"] for r in rows if r["category"]}):
        cat_rows = [r for r in rows if r["category"] == cat]
        sub = [r for r in scored if r["category"] == cat]
        c = counts(sub)
        p, rc, fo = prf(c["TP"], c["FP"], c["FN"])
        cat_correct = sum(1 for r in cat_rows if r["class_match"] == "TRUE")
        cat_acc_all = cat_correct / len(cat_rows) if cat_rows else 0.0
        cat_invalid = len(cat_rows) - len(sub)
        lines.append(f"  {cat:<8} {cat_acc_all:.3f} | {p:.3f} | {rc:.3f} | {fo:.3f} "
                     f"| n={len(cat_rows)} | inv={cat_invalid}")

    text = "\n".join(l for l in lines if l != "")
    path.write_text(text + "\n", encoding="utf-8")
    print("\n" + text)


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Knowledge-augmented (RAG) experiment runner.")
    p.add_argument("--models", nargs="+", default=MODELS)
    p.add_argument("--limit", type=int, default=None)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    mapping = load_runner_mapping()
    truth = load_ground_truth()
    kb = load_knowledge_base()

    if not kb:
        raise SystemExit(f"No knowledge-base category documents found under "
                         f"{KNOWLEDGE_BASE_DIR}. Expected folders: {CATEGORY_FOLDERS}")

    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Loaded {len(mapping)} scenarios, {len(truth)} ground-truth rows.")
    print(f"Knowledge base: {len(kb)} category documents (GLOBAL excluded from retrieval).")
    print(f"Models: {', '.join(args.models)}")
    print(f"Mode: {PROMPT_MODE} (baseline prompt + top-{TOP_K} retrieved docs)")
    print(f"Output: {OUTPUTS_DIR} (baseline outputs/ untouched)")

    # (#5) Precompute the retrieval plan ONCE. Deterministic and model-independent,
    # so every model receives byte-identical retrieved documents.
    print("Precomputing retrieval plan (identical for all models) ...")
    plan = precompute_retrieval_plan(mapping, kb)
    plan_path = OUTPUTS_DIR / "retrieval_plan.json"
    plan_path.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    no_doc = sum(1 for k, v in plan.items() if k != "_meta" and v["no_document_found"])
    print(f"  Saved {plan_path.name}. Scenarios with no matching document: {no_doc}")
    print(f"  Hashes -> KB:{plan['_meta']['kb_documents_hash']} "
          f"inputs:{plan['_meta']['dataset_inputs_hash']} "
          f"script:{plan['_meta']['runner_script_hash']}")

    started = time.time()
    for model in args.models:
        run_one_model(model, mapping, truth, kb, plan, args.limit)
    print(f"\nAll models complete in {(time.time()-started)/60:.1f} min. Results in {OUTPUTS_DIR}")


if __name__ == "__main__":
    main()
