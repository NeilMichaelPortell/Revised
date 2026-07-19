#!/usr/bin/env python3
"""
otrf_common.py
==============

Shared, stable helpers for the SUPPLEMENTARY OTRF external-validation workflow
(scripts 8-11). This module exists ONLY for the OTRF scripts. It does not import
from, modify, or affect any of the primary scripts (0-7) or their frozen outputs.

Design intent
-------------
The like-for-like requirement means the external OTRF run must use the *same*
model settings, the *same* prompt wording, the *same* JSON parsing, the *same*
strict validation and the *same* deterministic retrieval as the primary
experiment. Rather than copy those blocks into four new scripts, the stable
pieces are centralised here once and imported. The values below are transcribed
verbatim from scripts/runs/1-run_baseline.py and scripts/runs/3-run_rag.py so
the external condition is identical to the frozen primary condition.

Nothing here reads any answer key or ground truth. Ground truth is joined only
inside the evaluator (script 11), never during inference.
"""

from __future__ import annotations

import csv
import hashlib
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
# Paths (this file lives in scripts/runs/, dataset root two levels up)         #
# --------------------------------------------------------------------------- #
ROOT_DIR = Path(__file__).resolve().parents[2]              # -> revised/
DATASET_DIR = ROOT_DIR / "Dataset"
KNOWLEDGE_BASE_DIR = ROOT_DIR / "knowledge_base"
VOCAB_PATH = DATASET_DIR / "controlled_indicator_vocabulary.csv"

EXTERNAL_DIR = ROOT_DIR / "external_validation"
CONFIG_DIR = EXTERNAL_DIR / "config"
SOURCE_DIR = EXTERNAL_DIR / "source"
PREPARED_DIR = EXTERNAL_DIR / "prepared"
NEUTRAL_INPUTS_DIR = PREPARED_DIR / "neutral_inputs"
RETRIEVAL_DIR = EXTERNAL_DIR / "retrieval"
OUTPUTS_BASELINE_DIR = EXTERNAL_DIR / "outputs_baseline"
OUTPUTS_RAG_DIR = EXTERNAL_DIR / "outputs_rag"
EVALUATION_DIR = EXTERNAL_DIR / "evaluation"
LOGS_DIR = EXTERNAL_DIR / "logs"

FROZEN_MANIFEST_PATH = PREPARED_DIR / "frozen_external_manifest.csv"
EXTERNAL_GROUND_TRUTH_PATH = PREPARED_DIR / "external_ground_truth.csv"
FROZEN_RETRIEVAL_PLAN_PATH = RETRIEVAL_DIR / "frozen_otrf_retrieval_plan.jsonl"

# Default run configuration, used when --config is omitted on the CLI. An
# absolute path (derived from ROOT_DIR), so it resolves correctly regardless
# of the caller's current working directory.
DEFAULT_CONFIG_PATH = CONFIG_DIR / "otrf_external_config.json"

ADAPTER_VERSION = "otrf-adapter-1.2.0"
MANIFEST_VERSION = "otrf-manifest-1.1.0"

# --------------------------------------------------------------------------- #
# Source-path resolution (requirement: OTRF source paths resolve relative to  #
# external_validation/source/ unless an absolute path is explicitly given)    #
# --------------------------------------------------------------------------- #
def resolve_source_path(rel: str, source_dir: Path | None = None) -> Path:
    """Resolve a manifest 'source_relative_path' value.

    An absolute path is used as-is. Otherwise the path is resolved relative to
    `source_dir` (defaults to SOURCE_DIR, i.e. external_validation/source/),
    NOT relative to the repository root. This keeps the manifest column
    portable and unambiguous regardless of current working directory."""
    p = Path(rel)
    if p.is_absolute():
        return p
    base = source_dir if source_dir is not None else SOURCE_DIR
    return base / rel


# --------------------------------------------------------------------------- #
# Documented retrieval-implementation version and divergence from primary     #
# --------------------------------------------------------------------------- #
# Requirement: OTRF retrieval must exactly match the frozen primary retrieval
# implementation (scripts/runs/3-run_rag.py); if impossible, the external
# implementation must be explicitly versioned and every difference documented.
#
# retrieve(), build_query_features(), parse_kb_document(), load_knowledge_base()
# and the scoring weights below are transcribed verbatim from 3-run_rag.py and
# are byte-identical in behaviour. ONE intentional difference exists:
#
#   _INACTIVE_STRINGS here additionally contains "not_available". The primary
#   pipeline's neutral inputs never contain the literal string "not_available"
#   inside event_summary; only this OTRF adapter emits it, as the documented
#   telemetry-availability sentinel (see otrf_adapter.py) for evidence whose
#   channel family is absent from a given source file. Without this addition,
#   "not_available" strings would be treated as active retrieval features
#   (query fields/words), which would bias retrieval toward KB documents that
#   happen to share vocabulary with the word "not available" -- an artefact of
#   the OTRF-specific availability sentinel, not a real behavioural signal.
#   Excluding it restores the primary pipeline's intent ("only ACTIVE evidence
#   drives retrieval") for the new sentinel value the primary pipeline never
#   has to handle.
#
# This is the ONLY functional difference from 3-run_rag.py's retrieval code.
RETRIEVAL_IMPLEMENTATION_VERSION = "otrf-retrieval-1.1.0"
RETRIEVAL_DIFFERENCES_FROM_PRIMARY = [
    "_INACTIVE_STRINGS includes the additional sentinel 'not_available' "
    "(absent from scripts/runs/3-run_rag.py), so that the OTRF telemetry-"
    "availability marker never becomes a spurious retrieval feature. No other "
    "difference exists: retrieve(), build_query_features() scoring, "
    "parse_kb_document(), load_knowledge_base() and the category folder list "
    "are transcribed verbatim.",
]

# --------------------------------------------------------------------------- #
# Experiment configuration - TRANSCRIBED VERBATIM FROM THE FROZEN RUNNERS      #
# (1-run_baseline.py / 3-run_rag.py). Do not change: like-for-like depends on  #
# these being byte-identical to the primary condition.                         #
# --------------------------------------------------------------------------- #
MODELS = ["llama3", "deepseek-r1:8b", "gemma3:12b", "qwen3:8b", "gpt-oss:20b"]

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

CATEGORY_FOLDERS = ["NORMAL", "AUTH", "USB", "SEC", "PROC", "NET", "PERSIST"]

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


def options_for(model: str) -> dict[str, Any]:
    return MODEL_OPTIONS.get(model, DEFAULT_OPTIONS)


def safe_model_dir(model: str) -> str:
    """'deepseek-r1:8b' -> 'deepseek-r1_8b' (matches the primary runners)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", model)


# --------------------------------------------------------------------------- #
# Hashing / time helpers                                                       #
# --------------------------------------------------------------------------- #
def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.exists():
        return "not_available"
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_config(config_path: Path) -> str:
    """Hash of the run configuration JSON, recorded so drift in models/top_k/
    window settings between prepare/freeze/run/evaluate is detectable."""
    return sha256_file(config_path)


# --------------------------------------------------------------------------- #
# Integrity verification (SHA-256 enforcement, fail-by-default)               #
# --------------------------------------------------------------------------- #
class IntegrityError(RuntimeError):
    """Raised when a frozen artefact hash does not match its current content,
    or a required frozen artefact is missing. Callers fail by default; an
    explicit --allow-hash-drift (or equivalent) flag is required to proceed
    anyway, and any such override must be logged."""


def verify_manifest_integrity(manifest_rows: list[dict[str, str]],
                              source_dir: Path | None = None) -> list[str]:
    """Recompute source_hash and neutral_input_hash for every frozen manifest
    row and return a list of human-readable violations (empty == clean).
    Does not raise; callers decide whether to treat violations as fatal."""
    violations: list[str] = []
    for row in manifest_rows:
        ext_id = row.get("external_scenario_id", "(unknown)")
        src = resolve_source_path(row.get("source_path", ""), source_dir)
        expected_src_hash = row.get("source_hash", "")
        if expected_src_hash and expected_src_hash != "not_available":
            current_src_hash = sha256_file(src)
            if current_src_hash != expected_src_hash:
                violations.append(
                    f"{ext_id}: source file hash drift ({src})")
        neutral_path = NEUTRAL_INPUTS_DIR / f"{ext_id}.json"
        expected_neutral_hash = row.get("neutral_input_hash", "")
        if not neutral_path.exists():
            violations.append(f"{ext_id}: neutral input missing ({neutral_path})")
            continue
        current_neutral_hash = sha256_text(neutral_path.read_text(encoding="utf-8"))
        if expected_neutral_hash and current_neutral_hash != expected_neutral_hash:
            violations.append(f"{ext_id}: neutral input hash drift ({neutral_path})")
    return violations


def verify_retrieval_plan_integrity(plan_meta: dict[str, Any],
                                    kb: list[dict[str, Any]],
                                    neutral_files: list[Path]) -> list[str]:
    """Recompute the KB-documents hash and neutral-inputs hash recorded in the
    frozen retrieval plan header and compare against the CURRENT knowledge
    base / prepared inputs. Empty list == clean."""
    violations: list[str] = []
    kb_concat = "".join(sorted(d["full_text"] for d in kb))
    current_kb_hash = sha256_text(kb_concat)
    if plan_meta.get("kb_documents_hash") and current_kb_hash != plan_meta["kb_documents_hash"]:
        violations.append("knowledge-base documents changed since the retrieval plan was frozen")
    inputs_concat = "".join(p.read_text(encoding="utf-8") for p in neutral_files)
    current_inputs_hash = sha256_text(inputs_concat)
    if plan_meta.get("neutral_inputs_hash") and current_inputs_hash != plan_meta["neutral_inputs_hash"]:
        violations.append("prepared neutral inputs changed since the retrieval plan was frozen")
    return violations


def require_no_violations(violations: list[str], context: str, allow_override: bool) -> None:
    """Fail loudly by default when integrity violations are present. An
    explicit allow_override=True (only ever set via a documented CLI flag)
    permits continuing, but the violations are still printed so an override
    is never silent."""
    if not violations:
        return
    message = (f"Integrity check failed ({context}): {len(violations)} violation(s):\n  "
              + "\n  ".join(violations))
    if allow_override:
        print(f"WARNING (overridden, --allow-hash-drift given): {message}")
        return
    raise IntegrityError(
        message + "\n\nFailing by default. Re-run with --allow-hash-drift only if this "
        "drift is expected and understood.")


# --------------------------------------------------------------------------- #
# Ollama HTTP API (identical behaviour to the primary runners)                 #
# --------------------------------------------------------------------------- #
def urllib_request(url: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
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
    """One scenario through the model via the Ollama HTTP API. Identical to the
    primary runners: format:json for all models except gpt-oss:20b."""
    started = time.perf_counter()
    try:
        use_format_json = model not in NO_FORMAT_JSON_MODELS
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": options_for(model),
        }
        if use_format_json:
            payload["format"] = "json"
        response = urllib_request(f"{OLLAMA_HOST}/api/generate", payload, timeout=CALL_TIMEOUT)
        model_text = response.get("response", "") if isinstance(response, dict) else ""
        return {
            "raw_output": model_text.strip(),
            "error": "" if model_text else "Empty response from API.",
            "latency_seconds": round(time.perf_counter() - started, 3),
        }
    except urllib.error.URLError as exc:
        return {"raw_output": "", "error": f"Could not reach Ollama API at {OLLAMA_HOST} ({exc}).",
                "latency_seconds": round(time.perf_counter() - started, 3)}
    except TimeoutError:
        return {"raw_output": "", "error": f"API call timed out after {CALL_TIMEOUT}s.",
                "latency_seconds": round(time.perf_counter() - started, 3)}
    except Exception as exc:
        return {"raw_output": "", "error": f"Unexpected API error: {exc}",
                "latency_seconds": round(time.perf_counter() - started, 3)}


# --------------------------------------------------------------------------- #
# Response parsing + validation (identical to the primary runners)             #
# --------------------------------------------------------------------------- #
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[<>=]|\x1b\][^\x07]*\x07?")
REQUIRED_KEYS = {"classification", "risk_level", "indicators"}
VALID_CLASSES = {"normal", "risky", "abnormal"}
VALID_RISKS = {"low", "medium", "high", "critical"}

# Template-echo placeholder values that must FAIL strict validation even though
# they parse as JSON with the right keys (matches the schema definition text).
PLACEHOLDER_CLASSES = {"normal or risky", "normal or abnormal"}
PLACEHOLDER_RISKS = {"low, medium, high, or critical", "low medium high or critical"}


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


def is_schema_valid(parsed: dict[str, Any] | None) -> bool:
    """BASIC validity: parsed dict with the required keys. Drives the retry loop,
    identical to both primary runners so retry behaviour matches."""
    return bool(parsed) and REQUIRED_KEYS.issubset(parsed.keys())


def validate_response(parsed: dict[str, Any] | None) -> dict[str, bool]:
    """STRICT validity, reported separately. Placeholder/template echoes fail."""
    parse_valid = isinstance(parsed, dict)
    keys_valid = parse_valid and REQUIRED_KEYS.issubset(parsed)
    cls = str(parsed["classification"]).strip().lower() if keys_valid else ""
    rsk = str(parsed["risk_level"]).strip().lower() if keys_valid else ""
    classification_valid = (keys_valid and cls in VALID_CLASSES
                            and cls not in PLACEHOLDER_CLASSES)
    risk_valid = (keys_valid and rsk in VALID_RISKS and rsk not in PLACEHOLDER_RISKS)
    indicators_valid = (keys_valid and isinstance(parsed["indicators"], list)
                        and all(isinstance(v, str) for v in parsed["indicators"]))
    strict = bool(keys_valid and classification_valid and risk_valid and indicators_valid)
    return {
        "json_parse_valid": bool(parse_valid),
        "required_keys_valid": bool(keys_valid),
        "classification_valid": bool(classification_valid),
        "risk_valid": bool(risk_valid),
        "indicators_valid": bool(indicators_valid),
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
# Output schema + prompt construction (VERBATIM from the primary runners)       #
# --------------------------------------------------------------------------- #
OUTPUT_SCHEMA = {
    "classification": "normal or risky",
    "risk_level": "low, medium, high, or critical",
    "indicators": ["indicator_1", "indicator_2"],
    "explanation": "one or two sentence explanation a user could understand",
    "recommended_action": "short safe recommendation",
}


def build_baseline_prompt(neutral_input: dict[str, Any]) -> str:
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


def build_rag_prompt(neutral_input: dict[str, Any],
                     retrieved: list[dict[str, Any]]) -> str:
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
# Knowledge base + deterministic retrieval (VERBATIM from 3-run_rag.py)         #
# --------------------------------------------------------------------------- #
# NOTE: "not_available" is the ONE documented difference from the primary
# pipeline's _INACTIVE_STRINGS (scripts/runs/3-run_rag.py). See
# RETRIEVAL_DIFFERENCES_FROM_PRIMARY above for the justification.
_INACTIVE_STRINGS = {"", "none", "not_applicable", "unknown", "n/a", "null", "not_available"}
STOPWORDS = {
    "activity", "value", "true", "present", "observed", "normal", "none",
    "change", "changed", "information", "device", "endpoint", "user",
    "windows", "the", "and", "for", "with", "was", "not", "may", "are",
    "this", "that", "when", "from", "count", "band", "details", "context",
    "profile", "state", "action", "type", "name", "status", "event", "events",
}


def parse_kb_document(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")

    def section(header: str) -> str:
        m = re.search(rf"##\s+{re.escape(header)}\s*\n(.*?)(?=\n##\s|\Z)", text, re.DOTALL)
        return m.group(1).strip() if m else ""

    doc_id_m = re.search(r"Document ID:\s*(\S+)", text)
    doc_id = doc_id_m.group(1) if doc_id_m else path.stem
    title_m = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    title = title_m.group(1).strip() if title_m else path.stem
    expected = section("Expected indicators")
    expected_tokens = [ln.strip("- ").strip()
                       for ln in expected.splitlines() if ln.strip().startswith("-")]
    applies = section("Observable conditions") or section("Applies when")
    return {
        "doc_id": doc_id, "title": title, "category": path.parent.name, "path": str(path),
        "expected_tokens": expected_tokens,
        "expected_text": " ".join(expected_tokens).lower(),
        "applies_text": applies.lower(), "body_text": text.lower(), "full_text": text,
    }


def load_knowledge_base() -> list[dict[str, Any]]:
    """Load active category docs only (GLOBAL and _archive_not_indexed excluded),
    matching the frozen primary retrieval."""
    docs = []
    for cat in CATEGORY_FOLDERS:
        cat_dir = KNOWLEDGE_BASE_DIR / cat
        if not cat_dir.exists():
            continue
        for md in sorted(cat_dir.glob("*.md")):
            docs.append(parse_kb_document(md))
    docs.sort(key=lambda d: d["doc_id"])
    return docs


def build_query_features(neutral_input: dict[str, Any]) -> dict[str, list[str]]:
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
    walk(event)
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
    fset = set(features["fields"])
    vset = set(features["values"])
    wset = set(features["words"])
    scored = []
    for doc in kb:
        exp_tokens = set(doc["expected_tokens"])
        exp_hits = len((fset | vset) & exp_tokens)
        applies = doc["applies_text"]
        av_hits = sum(1 for v in vset if v in applies)
        af_hits = sum(1 for f in fset if f in applies)
        title_words = set(re.split(r"[^a-z0-9]+", doc["title"].lower()))
        title_hits = len(wset & title_words)
        body_only = doc["body_text"].replace(doc["expected_text"], " ").replace(applies, " ")
        body_words = set(re.split(r"[^a-z0-9]+", body_only)) - STOPWORDS
        body_hits = len(wset & body_words)
        score = (6 * exp_hits + 5 * av_hits + 3 * af_hits + 2 * title_hits + 1 * body_hits)
        scored.append((score, doc))
    scored.sort(key=lambda s: -s[0])
    results = []
    for score, doc in scored:
        if score <= 0:
            continue
        results.append({"doc": doc, "score": score, "rank": len(results) + 1})
        if len(results) >= top_k:
            break
    return results


# --------------------------------------------------------------------------- #
# Controlled indicator vocabulary + EXACT canonical-token matching             #
# --------------------------------------------------------------------------- #
def load_controlled_vocabulary() -> set[str]:
    """The authoritative canonical indicator tokens from the frozen dataset."""
    vocab: set[str] = set()
    with VOCAB_PATH.open("r", newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            tok = (row.get("indicator_token") or "").strip().lower()
            if tok:
                vocab.add(tok)
    return vocab


def canonicalise_indicator(raw: Any) -> str:
    """Normalise a single model-produced indicator to a canonical token FORM
    (lowercase, spaces/hyphens -> underscore, trimmed). This is a deterministic
    surface normalisation only; it does NOT map synonyms. Whether the result is
    an accepted indicator is decided by exact set membership against the frozen
    controlled vocabulary - never by substring matching."""
    t = str(raw).strip().lower()
    t = re.sub(r"[\s\-]+", "_", t)
    t = re.sub(r"[^a-z0-9_]", "", t)
    t = re.sub(r"_+", "_", t).strip("_")
    return t


def classify_indicators(predicted: Any, vocab: set[str]) -> dict[str, list[str]]:
    """Split model indicators into canonical (exact vocab hit) vs out-of-vocab.
    Exact match only. No substring credit."""
    if isinstance(predicted, list):
        items = predicted
    elif isinstance(predicted, str):
        items = [p for p in re.split(r"[;,]", predicted) if p.strip()]
    else:
        items = []
    canonical, oov = [], []
    for item in items:
        tok = canonicalise_indicator(item)
        if tok in vocab:
            canonical.append(tok)
        elif tok:
            oov.append(tok)
    return {"canonical": canonical, "out_of_vocabulary": oov}


# --------------------------------------------------------------------------- #
# Small IO helpers                                                             #
# --------------------------------------------------------------------------- #
def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------------------- #
# Shared inference runner core (used by 9-run-otrf-baseline / 10-run-otrf-rag) #
# --------------------------------------------------------------------------- #
def frozen_manifest_scenario_ids() -> list[str]:
    """The authoritative, frozen list of external_scenario_id values. Runners
    must process ONLY these ids -- never every file that happens to exist in
    the prepared neutral_inputs/ folder -- so a stray or stale file left over
    from an earlier prepare run can never silently get processed."""
    rows = read_csv(FROZEN_MANIFEST_PATH)
    return sorted({row["external_scenario_id"] for row in rows if row.get("external_scenario_id")})


def load_neutral_inputs() -> list[tuple[str, dict[str, Any]]]:
    """Return [(external_scenario_id, neutral_input)] in deterministic id order,
    restricted to the ids listed in the FROZEN MANIFEST (never a directory
    listing). Reads ONLY the leakage-safe prepared inputs. Never reads the
    answer key. Raises if the frozen manifest is missing, or if it lists a
    scenario whose neutral-input file is not present (a stale/incomplete
    prepared-inputs folder must fail loudly, not silently skip or silently
    process an unrelated file)."""
    if not FROZEN_MANIFEST_PATH.exists():
        raise SystemExit(f"No frozen manifest at {FROZEN_MANIFEST_PATH}. "
                         f"Run 8-prepare-otrf-external.py first.")
    ids = frozen_manifest_scenario_ids()
    out = []
    missing = []
    for ext_id in ids:
        p = NEUTRAL_INPUTS_DIR / f"{ext_id}.json"
        if not p.exists():
            missing.append(ext_id)
            continue
        out.append((ext_id, json.loads(p.read_text(encoding="utf-8"))))
    if missing:
        raise SystemExit(
            f"Frozen manifest lists {len(missing)} scenario(s) with no neutral-input "
            f"file under {NEUTRAL_INPUTS_DIR}: {missing[:10]}"
            f"{'...' if len(missing) > 10 else ''}. Re-run 8-prepare-otrf-external.py.")
    return out


def completed_ids(raw_path: Path) -> set[str]:
    """External scenario ids already present in a model's raw JSONL (for resume
    and duplicate protection)."""
    done: set[str] = set()
    for rec in read_jsonl(raw_path):
        sid = rec.get("external_scenario_id")
        if sid:
            done.add(sid)
    return done


def run_model_over_scenarios(
    model: str,
    scenarios: list[tuple[str, dict[str, Any]]],
    prompt_for,                     # callable(ext_id, neutral_input) -> (prompt, extra_log)
    condition: str,                 # "baseline" | "rag"
    out_dir: Path,
    resume: bool,
    overwrite: bool,
    cycle: bool = True,
) -> dict[str, Any]:
    """Run one model over all scenarios with retry/timeout/fallback tracking,
    resume and overwrite protection. Writes an append-safe raw JSONL. Ground
    truth is NEVER read here."""
    model_dir = out_dir / safe_model_dir(model)
    model_dir.mkdir(parents=True, exist_ok=True)
    raw_path = model_dir / f"{safe_model_dir(model)}_{condition}_raw.jsonl"

    existing = completed_ids(raw_path)
    if existing and not resume and not overwrite:
        raise SystemExit(
            f"Outputs already exist for {model} ({condition}) in {raw_path}.\n"
            f"Use --resume to continue or --overwrite to replace."
        )
    if overwrite and raw_path.exists():
        raw_path.unlink()
        existing = set()

    if cycle:
        stop_all_models()
        time.sleep(UNLOAD_WAIT)
        warm_load(model)
        time.sleep(WARMUP_WAIT)

    written = skipped = 0
    with raw_path.open("a", encoding="utf-8") as raw_fh:
        for ext_id, neutral_input in scenarios:
            if ext_id in existing:            # resume / duplicate protection
                skipped += 1
                continue
            prompt, extra_log = prompt_for(ext_id, neutral_input)

            attempt_logs = []
            attempts_used = 0
            parsed = None
            result: dict[str, Any] = {}
            timed_out = False
            empty = False
            while attempts_used < MAX_RETRIES + 1:
                result = call_model(model, prompt)
                attempts_used += 1
                parsed = extract_json(result["raw_output"])
                err = result.get("error", "")
                if "timed out" in err:
                    timed_out = True
                if err == "Empty response from API.":
                    empty = True
                attempt_logs.append({
                    "attempt": attempts_used,
                    "latency_seconds": result.get("latency_seconds", 0.0),
                    "error": err,
                    "basic_schema_valid": is_schema_valid(parsed),
                })
                if is_schema_valid(parsed):
                    break

            total_latency = round(sum(a["latency_seconds"] for a in attempt_logs), 3)
            retries_used = max(0, attempts_used - 1)
            json_basic_valid = is_schema_valid(parsed)
            strict = validate_response(parsed)
            # A "fallback" is a scenario that never reached basic validity after
            # all retries. It must NOT be counted as a successful model output.
            fallback = not json_basic_valid

            pred_class = normalise_class(parsed.get("classification")) if parsed else ""
            pred_risk = str(parsed.get("risk_level", "")).strip().lower() if parsed else ""
            pred_inds = parsed.get("indicators", []) if parsed else []

            record = {
                "timestamp_utc": utc_now(),
                "external_scenario_id": ext_id,
                "model": model,
                "condition": condition,
                "attempts_used": attempts_used,
                "retries_used": retries_used,
                "timeout": timed_out,
                "empty_response": empty,
                "fallback": fallback,
                "json_parse_valid": strict["json_parse_valid"],
                "required_keys_valid": strict["required_keys_valid"],
                "classification_valid": strict["classification_valid"],
                "risk_level_valid": strict["risk_valid"],
                "indicator_list_valid": strict["indicators_valid"],
                "strict_schema_valid": strict["strict_schema_valid"],
                "basic_schema_valid": json_basic_valid,
                "predicted_class": pred_class,
                "predicted_risk": pred_risk,
                "predicted_indicators": pred_inds if isinstance(pred_inds, list) else [pred_inds],
                "total_latency_seconds": total_latency,
                "attempt_logs": attempt_logs,
                "error": result.get("error", ""),
                "raw_output": result.get("raw_output", ""),
                **extra_log,
            }
            raw_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            raw_fh.flush()
            written += 1
            flag = "" if json_basic_valid else "  <-- FALLBACK (invalid)"
            print(f"  {ext_id} {model:<14} pred={pred_class or '?':<8} "
                  f"{total_latency}s{flag}")

    if cycle:
        try:
            run_cli(["ollama", "stop", model], timeout=60)
        except Exception:
            pass
        time.sleep(UNLOAD_WAIT)

    return {"model": model, "condition": condition, "written": written,
            "skipped_existing": skipped, "raw_path": str(raw_path)}


# --------------------------------------------------------------------------- #
# Statistics helpers (reproducible; mirror the primary scripts' methods)       #
# --------------------------------------------------------------------------- #
import math       # noqa: E402
import random     # noqa: E402
from math import comb  # noqa: E402

BOOTSTRAP_SEED = 2026
BOOTSTRAP_ITERS = 10000


def mean_ci_bootstrap(values: list[float], iters: int = BOOTSTRAP_ITERS,
                      seed: int = BOOTSTRAP_SEED) -> dict[str, Any]:
    """Mean, median, std, IQR and a reproducible bootstrap 95% CI for the mean."""
    if not values:
        return {"n": 0, "mean": None, "median": None, "std": None,
                "iqr_low": None, "iqr_high": None, "ci_low": None, "ci_high": None}
    xs = sorted(values)
    n = len(xs)
    mean = sum(xs) / n
    median = xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2
    std = math.sqrt(sum((x - mean) ** 2 for x in xs) / n) if n > 1 else 0.0

    def pct(p: float) -> float:
        if n == 1:
            return xs[0]
        idx = p * (n - 1)
        lo = int(math.floor(idx)); hi = int(math.ceil(idx))
        if lo == hi:
            return xs[lo]
        return xs[lo] + (xs[hi] - xs[lo]) * (idx - lo)

    rng = random.Random(seed)
    means = []
    for _ in range(iters):
        s = [xs[rng.randrange(n)] for _ in range(n)]
        means.append(sum(s) / n)
    means.sort()
    return {
        "n": n, "mean": round(mean, 4), "median": round(median, 4),
        "std": round(std, 4), "iqr_low": round(pct(0.25), 4), "iqr_high": round(pct(0.75), 4),
        "ci_low": round(means[int(0.025 * iters)], 4),
        "ci_high": round(means[int(0.975 * iters) - 1], 4),
    }


def proportion_ci_bootstrap(successes: int, n: int, iters: int = BOOTSTRAP_ITERS,
                            seed: int = BOOTSTRAP_SEED) -> dict[str, Any]:
    """Reproducible bootstrap 95% CI for a proportion. Not estimable if n == 0."""
    if n == 0:
        return {"n": 0, "rate": None, "ci_low": None, "ci_high": None, "estimable": False}
    data = [1] * successes + [0] * (n - successes)
    rng = random.Random(seed)
    rates = []
    for _ in range(iters):
        s = sum(data[rng.randrange(n)] for _ in range(n))
        rates.append(s / n)
    rates.sort()
    return {"n": n, "rate": round(successes / n, 4),
            "ci_low": round(rates[int(0.025 * iters)], 4),
            "ci_high": round(rates[int(0.975 * iters) - 1], 4), "estimable": True}


def exact_mcnemar(base_correct: dict[str, bool], rag_correct: dict[str, bool]) -> dict[str, Any]:
    """Exact (binomial) McNemar on paired baseline-vs-RAG correctness. Uses the
    exact test throughout (appropriate for small discordant counts)."""
    b_only = r_only = both = neither = 0
    for sid in base_correct:
        if sid not in rag_correct:
            continue
        bc, rc = base_correct[sid], rag_correct[sid]
        if bc and rc:
            both += 1
        elif not bc and not rc:
            neither += 1
        elif bc and not rc:
            b_only += 1
        else:
            r_only += 1
    n = b_only + r_only
    if n == 0:
        p = 1.0
    else:
        k = min(b_only, r_only)
        p = min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / (2 ** n))
    return {"baseline_only_correct": b_only, "rag_only_correct": r_only,
            "both_correct": both, "both_wrong": neither, "discordant": n,
            "p_value": p}


def holm_adjust(pairs: list[tuple[str, float]]) -> dict[str, float]:
    """Holm-Bonferroni step-down adjustment across a set of (label, p) tests."""
    m = len(pairs)
    ordered = sorted(pairs, key=lambda x: x[1])
    out: dict[str, float] = {}
    prev = 0.0
    for i, (label, p) in enumerate(ordered):
        adj = min(1.0, (m - i) * p)
        adj = max(adj, prev)
        prev = adj
        out[label] = round(adj, 5)
    return out


def fmt_p(p: float) -> str:
    """Report p < 0.001 rather than p = 0.000."""
    if p is None:
        return "n/a"
    return "<0.001" if p < 0.001 else f"{p:.3f}"
