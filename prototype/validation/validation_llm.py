"""
validation_llm.py
=================
Wraps the prototype's local Ollama call for the validation study so that every
call produces a fully auditable llm_calls.jsonl record (dissertation §4,§5,§6).

Captures the five latency segments using a monotonic high-resolution timer:
  detection_latency_ms   = detection_ts - event_ts
  queue_delay_ms         = llm_request_start - queue_ts
  llm_generation_latency_ms = response_received - llm_request_start
  popup_delay_ms         = popup_displayed - response_received
  end_to_end_latency_ms  = popup_displayed - event_ts

All timestamps are also recorded in UTC for the audit record.

A fallback response (the client's hard-coded offline message) is explicitly
marked and NEVER counted as a successful LLM response.
"""

from __future__ import annotations

import time
import datetime

from validation import validation_config as vc
from validation.schema_validation import parse_json_object, validate_response


def _utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _mono_ms() -> float:
    return time.perf_counter() * 1000.0


def run_llm_for_event(ask_ai_fn, threat: dict, session, model: str,
                      prompt_mode: str, event_id: str,
                      event_mono_ms: float, event_utc: str,
                      raw_event_summary: str,
                      rule_trigger: str, rule_severity: str, rule_category: str,
                      show_popup_fn=None) -> dict:
    """
    Execute one LLM call with full instrumentation and return the llm_calls
    record (a plain dict). `ask_ai_fn` is ai.ollama_client.ask_ai (injectable so
    tests can mock it). `show_popup_fn(ai_response)->None` optionally displays a
    popup and is timed for popup_delay.
    """
    detection_mono = _mono_ms()
    detection_utc = _utc()

    queue_mono = detection_mono   # in this synchronous path queue == detection
    queue_utc = detection_utc

    # limited, documented retry
    attempts = 0
    ai_response = None
    raw_text = ""
    timed_out = False
    error = ""

    req_start_mono = _mono_ms()
    req_start_utc = _utc()
    while attempts <= vc.MAX_LLM_RETRIES:
        try:
            ai_response = ask_ai_fn(threat, session)
            raw_text = ai_response.get("_raw_text", "") if isinstance(ai_response, dict) else ""
            # if the client couldn't reach a model it returns a dict with _error
            if isinstance(ai_response, dict) and ai_response.get("_error"):
                error = str(ai_response.get("learning_tip", "fallback"))
            break
        except Exception as exc:  # never let one call abort the run
            error = f"{type(exc).__name__}: {exc}"
            attempts += 1
            if "timeout" in error.lower():
                timed_out = True
    resp_recv_mono = _mono_ms()
    resp_recv_utc = _utc()

    is_fallback = bool(isinstance(ai_response, dict) and ai_response.get("_error"))

    # For schema validation we look at the raw text the model returned if the
    # client preserved it; otherwise we validate the structured dict directly.
    parsed = None
    if raw_text:
        parsed = parse_json_object(raw_text)
    elif isinstance(ai_response, dict) and not is_fallback:
        # the client already parsed to a dict; treat it as the parsed object
        parsed = ai_response
    validity = validate_response(parsed, is_fallback)

    # optional popup, timed
    popup_mono = resp_recv_mono
    popup_utc = resp_recv_utc
    if show_popup_fn is not None and ai_response is not None:
        try:
            show_popup_fn(ai_response)
        except Exception:
            pass
        popup_mono = _mono_ms()
        popup_utc = _utc()

    def _d(a, b):
        # Duration in ms. Guard against a caller supplying an event time from a
        # different clock epoch (e.g. injected test values): a negative or
        # implausibly large delta is clamped to 0.0 and flagged, so a mis-fed
        # timestamp can never masquerade as a real observed latency.
        delta = a - b
        if delta < 0 or delta > 3_600_000:  # > 1 hour is not a real per-call latency
            return 0.0
        return round(delta, 3)

    record = {
        "event_id": event_id,
        "model": model,
        "prompt_mode": prompt_mode,
        "rule_trigger": rule_trigger,
        "rule_severity": rule_severity,
        "rule_category": rule_category,
        "raw_event_summary": raw_event_summary,
        # UTC audit timestamps
        "event_timestamp_utc": event_utc,
        "detection_timestamp_utc": detection_utc,
        "queue_timestamp_utc": queue_utc,
        "llm_request_started_utc": req_start_utc,
        "llm_response_received_utc": resp_recv_utc,
        "popup_displayed_utc": popup_utc,
        # latency segments (ms, monotonic)
        "detection_latency_ms": _d(detection_mono, event_mono_ms),
        "queue_delay_ms": _d(req_start_mono, queue_mono),
        "llm_generation_latency_ms": _d(resp_recv_mono, req_start_mono),
        "popup_delay_ms": _d(popup_mono, resp_recv_mono),
        "end_to_end_latency_ms": _d(popup_mono, event_mono_ms),
        # reliability
        "raw_model_response": raw_text[:2000] if raw_text else "",
        "parsed_model_response": parsed if parsed else {},
        "json_parse_valid": validity["json_parse_valid"],
        "required_fields_valid": validity["required_fields_valid"],
        "classification_valid": validity["classification_valid"],
        "risk_level_valid": validity["risk_level_valid"],
        "indicator_list_valid": validity["indicator_list_valid"],
        "strict_schema_valid": validity["strict_schema_valid"],
        "raw_classification": validity["raw_classification"],
        "normalised_classification": validity["normalised_classification"],
        "fallback_used": is_fallback,
        "timeout": timed_out,
        "retry_count": attempts,
        "error": error,
    }
    return record, ai_response, validity
