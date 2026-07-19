"""
validation_config.py
====================
Configuration and shared constants for the supplementary real-time validation
study. This module is deliberately self-contained and standard-library only.

IMPORTANT SCOPE NOTE
--------------------
This validation layer is SEPARATE from the frozen offline experiment
(120 scenarios, five models, baseline/RAG). It never reads, writes, modifies or
recalculates any frozen dataset, baseline output, RAG output or evaluation
script. Its purpose is supplementary evidence of operational feasibility only.
"""

from __future__ import annotations

# --- validation modes ------------------------------------------------------- #
MODE_INDEPENDENT = "independent_validation"
MODE_ADAPTIVE = "adaptive_feedback_validation"
VALID_MODES = {MODE_INDEPENDENT, MODE_ADAPTIVE}

# --- output layout ---------------------------------------------------------- #
# All validation output lives under this top-level folder, one subfolder per run.
VALIDATION_OUTPUT_DIRNAME = "validation_outputs"

RUN_FILES = {
    "metadata": "run_metadata.json",
    "raw_events": "raw_events.jsonl",
    "alerts": "alerts.jsonl",
    "llm_calls": "llm_calls.jsonl",
    "session_summary": "session_summary.json",
    "metrics": "prototype_metrics.json",
    "report": "run_validation_report.txt",
}

# --- strict output schema (what the model is EXPECTED to return) ------------ #
# The prototype's user-facing feedback uses a five-field explanatory schema
# (title/what_happened/why_risky/how_to_prevent/learning_tip). For the
# validation study we ALSO require the classification-style fields so that
# JSON-vs-schema validity can be measured against the dissertation's stated
# expected structure.
EXPECTED_CLASSIFICATION_TOKENS = {"normal", "abnormal", "risky"}
# 'risky' is accepted as raw input then normalised to 'abnormal'; the canonical
# post-normalisation set is:
CANONICAL_CLASSIFICATION_TOKENS = {"normal", "abnormal"}
EXPECTED_RISK_TOKENS = {"low", "medium", "high", "critical"}

# Fields required for STRICT schema validity (classification-style response).
STRICT_REQUIRED_FIELDS = (
    "classification",
    "risk_level",
    "indicators",
    "explanation",
    "recommended_action",
)

# --- rule severity ladder (defensible triggers, see README §rule logic) ----- #
# These describe the RULE layer only. They are intentionally conservative and
# are kept separate from any LLM classification. Severity here is the rule's
# provisional assessment, NOT ground truth.
SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


def severity_rank(sev: str) -> int:
    """Return an ordinal rank for a severity string (unknown -> -1)."""
    s = (sev or "").strip().lower()
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else -1


# --- retry / reliability policy --------------------------------------------- #
MAX_LLM_RETRIES = 1          # limited and documented (see README)
DEDUP_WINDOW_SECONDS = 3.0   # process/app dedup window


# --- latency aggregation ---------------------------------------------------- #
def percentile(values: list[float], pct: float) -> float:
    """
    Nearest-rank percentile using only the standard library. Returns 0.0 for an
    empty list. pct is 0..100.
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(float(ordered[0]), 3)
    # nearest-rank method
    k = max(1, int(round((pct / 100.0) * len(ordered))))
    k = min(k, len(ordered))
    return round(float(ordered[k - 1]), 3)


def summarise_latency(values: list[float]) -> dict:
    """count/mean/median/min/max/p95 for a list of latency values (ms)."""
    if not values:
        return {"count": 0, "mean": 0.0, "median": 0.0,
                "min": 0.0, "max": 0.0, "p95": 0.0}
    ordered = sorted(values)
    n = len(ordered)
    mean = sum(ordered) / n
    mid = n // 2
    median = ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2
    return {
        "count": n,
        "mean": round(mean, 3),
        "median": round(median, 3),
        "min": round(float(ordered[0]), 3),
        "max": round(float(ordered[-1]), 3),
        "p95": percentile(ordered, 95),
    }
