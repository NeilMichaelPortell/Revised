"""
schema_validation.py
====================
Strict validation of model responses for the validation study.

Distinguishes four separate concepts (dissertation §6):

  1. JSON parse validity      - did the text parse as a JSON object at all?
  2. Required-field validity  - are all STRICT_REQUIRED_FIELDS present?
  3. Semantic/schema validity - do the field VALUES satisfy the rules?
  4. Fallback response        - was this the client's hard-coded fallback,
                                i.e. NOT a genuine model response?

A fallback response is never counted as a successful LLM response.

The raw classification value is always preserved BEFORE 'risky' is normalised
to 'abnormal'.
"""

from __future__ import annotations

import json
import re
from typing import Any

from validation.validation_config import (
    STRICT_REQUIRED_FIELDS,
    EXPECTED_CLASSIFICATION_TOKENS,
    CANONICAL_CLASSIFICATION_TOKENS,
    EXPECTED_RISK_TOKENS,
)

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _clean(text: str) -> str:
    if not text:
        return ""
    text = _THINK_RE.sub(" ", text)
    text = _ANSI_RE.sub("", text)
    return text.strip()


def parse_json_object(text: str) -> dict | None:
    """
    Attempt to extract a single JSON object from model text.
    Returns the dict on success, or None if nothing parseable is found.
    This measures JSON PARSE validity only.
    """
    cleaned = _clean(text)
    if not cleaned:
        return None

    candidates: list[str] = []
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if fenced:
        candidates.append(fenced.group(1))
    spans = re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", cleaned, re.DOTALL)
    candidates.extend(reversed(spans))
    greedy = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if greedy:
        candidates.append(greedy.group(0))

    for cand in candidates:
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def validate_response(parsed: dict | None, is_fallback: bool) -> dict:
    """
    Run the full validity ladder against an already-parsed object.

    Returns a dict of boolean/scalar flags plus a normalised copy. The raw
    classification value is preserved in 'raw_classification' before any
    normalisation of 'risky' -> 'abnormal'.
    """
    result = {
        "json_parse_valid": parsed is not None,
        "required_fields_valid": False,
        "classification_valid": False,
        "risk_level_valid": False,
        "indicator_list_valid": False,
        "explanation_valid": False,
        "recommended_action_valid": False,
        "strict_schema_valid": False,
        "fallback_used": bool(is_fallback),
        "raw_classification": None,
        "normalised_classification": None,
    }

    if parsed is None:
        return result

    # 2. required-field validity
    result["required_fields_valid"] = all(
        k in parsed for k in STRICT_REQUIRED_FIELDS
    )

    # 3. semantic checks (each independent so partial validity is visible)
    raw_class = parsed.get("classification")
    if raw_class is not None:
        raw_text = str(raw_class).strip().lower()
        result["raw_classification"] = raw_text
        if raw_text in EXPECTED_CLASSIFICATION_TOKENS:
            result["classification_valid"] = True
            # normalise 'risky' -> 'abnormal' AFTER preserving raw value
            norm = "abnormal" if raw_text == "risky" else raw_text
            if norm in CANONICAL_CLASSIFICATION_TOKENS:
                result["normalised_classification"] = norm

    risk = parsed.get("risk_level")
    if risk is not None and str(risk).strip().lower() in EXPECTED_RISK_TOKENS:
        result["risk_level_valid"] = True

    inds = parsed.get("indicators")
    if isinstance(inds, list) and all(isinstance(i, str) for i in inds):
        result["indicator_list_valid"] = True

    expl = parsed.get("explanation")
    if isinstance(expl, str) and expl.strip():
        result["explanation_valid"] = True

    rec = parsed.get("recommended_action")
    if isinstance(rec, str) and rec.strip():
        result["recommended_action_valid"] = True

    # A fallback is never counted as a successful/strict-valid response.
    if not is_fallback:
        result["strict_schema_valid"] = (
            result["required_fields_valid"]
            and result["classification_valid"]
            and result["risk_level_valid"]
            and result["indicator_list_valid"]
            and result["explanation_valid"]
            and result["recommended_action_valid"]
        )

    return result
