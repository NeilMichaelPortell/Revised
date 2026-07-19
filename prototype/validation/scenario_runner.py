"""
scenario_runner.py
==================
Ties the validation pieces together for ONE scenario:

  plan metadata -> ValidationRun (isolated folder)
                -> state reset (mode-aware)
                -> per event: raw record + rule trigger + optional LLM feedback
                -> finalise (metrics + report)

Designed to be driven two ways:
  1. by run_validation.py against the LIVE pipeline on Windows;
  2. by the automated tests, feeding mocked events and a mocked ask_ai.

The runner NEVER embeds plan ground truth (expected category / alert_expected /
acceptable_severity) into the LLM prompt. That metadata is used only for the
post-hoc report, exactly as the brief requires.
"""

from __future__ import annotations

import time
import datetime
import threading

from validation.validation_run import ValidationRun
from validation import state_reset
from validation.state_reset import apply_risk
from validation import validation_llm
from validation.rule_triggers import ScenarioEvidence, CATEGORY_RULES, RuleDecision
from validation.validation_config import (
    MODE_INDEPENDENT, MODE_ADAPTIVE, severity_rank,
)


def _mono_ms() -> float:
    return time.perf_counter() * 1000.0


def _utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# Which prototype threat "type" maps to which category is already known to the
# threat detector; here we only need the category to pick the rule function.
def _category_for_event(event_type: str, plan_category: str,
                        expected_event_types: set[str]) -> str:
    # The plan selects the scenario rule only for event types that the scenario
    # explicitly expects. Unexpected events may still add context to the shared
    # evidence accumulator, but cannot masquerade as the planned category.
    if event_type not in expected_event_types:
        return "NORMAL"
    return (plan_category or "").upper() or "NORMAL"


class ScenarioRunner:
    def __init__(self, base_dir: str, plan_row: dict, session,
                 ask_ai_fn, model: str, history_module=None,
                 cooldown_seconds: float = 45.0, show_popup_fn=None,
                 finalise_wait_seconds: float = 245.0):
        self.base_dir = base_dir
        self.plan = plan_row
        self.session = session
        self.ask_ai_fn = ask_ai_fn
        self.model = model
        self.history_module = history_module
        self.cooldown_seconds = cooldown_seconds
        self.show_popup_fn = show_popup_fn
        self.finalise_wait_seconds = finalise_wait_seconds

        self.mode = plan_row["validation_mode"]
        self.repetition = int(plan_row.get("repetition", 1))
        self.scenario_id = plan_row["scenario_id"]
        self.run_id = f"{self.scenario_id}_R{self.repetition}"

        self.evidence = ScenarioEvidence()
        self.run: ValidationRun | None = None
        self.reset_record: dict | None = None
        self.history_supplied: list | None = None
        self._handler_condition = threading.Condition()
        self._active_handlers = 0
        self._accepting_events = False

    # -- lifecycle ----------------------------------------------------------- #
    def start(self) -> ValidationRun:
        meta = self._build_metadata()
        self.run = ValidationRun(self.base_dir, meta, self.mode)

        # mode-aware reset BEFORE the scenario begins
        self.reset_record = state_reset.reset_session(
            self.session, self.mode, self.history_module)

        # In adaptive mode, record EXACTLY what prior history was supplied.
        if self.mode == MODE_ADAPTIVE and self.history_module is not None:
            self.history_supplied = self.history_module.get_recent()
            self.run.meta["adaptive_history_supplied"] = self.history_supplied
        else:
            self.run.meta["adaptive_history_supplied"] = []
        self.run.meta["reset_record"] = self.reset_record
        self.run.meta["scenario_boundary"] = "scenario_started"
        self.run._write_metadata()
        with self._handler_condition:
            self._accepting_events = True
        return self.run

    def _build_metadata(self) -> dict:
        return {
            "validation_run_id": f"{self.plan['scenario_id']}_R{self.plan.get('repetition',1)}",
            "scenario_id": self.plan["scenario_id"],
            "repetition": int(self.plan.get("repetition", 1)),
            "scenario_title": self.plan.get("scenario_title", ""),
            "expected_event_types": _split(self.plan.get("expected_event_types", "")),
            "alert_expected": _to_bool(self.plan.get("alert_expected", "false")),
            "expected_category": self.plan.get("expected_category", ""),
            "acceptable_severity": _split(self.plan.get("acceptable_severity", "")),
            "validation_mode": self.mode,
        }

    def complete(self, status: str = "completed") -> dict:
        assert self.run is not None, "start() not called"
        deadline = time.monotonic() + self.finalise_wait_seconds
        with self._handler_condition:
            self._accepting_events = False
            while self._active_handlers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._handler_condition.wait(remaining)
            handlers_remaining = self._active_handlers
        self.run.meta["finalise_drain"] = {
            "wait_seconds": self.finalise_wait_seconds,
            "handlers_remaining": handlers_remaining,
        }
        self.run.meta["scenario_boundary"] = (
            "scenario_completed" if status == "completed" else "scenario_aborted"
        )
        self.run.write_session_summary(self.session.build_summary())
        return self.run.finalise(status)

    def abort(self) -> dict:
        return self.complete(status="aborted")

    # -- evidence accumulation ---------------------------------------------- #
    def _update_evidence(self, event_type: str, raw: dict) -> None:
        ev = self.evidence
        if event_type == "login_failed":
            ev.failed_logins += 1
        elif event_type == "usb_connected":
            ev.usb_connections += 1
            if raw.get("exec_visible"):
                ev.usb_exec_visible = True
            if raw.get("exec_accessed"):
                ev.usb_exec_accessed = True
        elif event_type == "defender_disabled":
            ev.defender_disabled = True
            ev.security_controls_changed += 1
        elif event_type == "network_profile_changed":
            if "public" in str(raw.get("profile", "")).lower():
                ev.public_network = True
        elif event_type in ("process_started", "process_seen"):
            name = (raw.get("process_name") or "").lower()
            cmd = (raw.get("command_line") or raw.get("cmdline") or "").lower()
            if raw.get("script_execution") or cmd.endswith(".ps1") or " -enc" in cmd:
                ev.script_execution = True
            if "-enc" in cmd or "frombase64" in cmd:
                ev.encoded_command = True
            if raw.get("process_enumeration") or "tasklist" in cmd or "get-process" in cmd:
                ev.process_enumeration = True
        elif event_type in ("scheduled_task_created", "scheduled_task_updated"):
            ev.scheduled_task_created = True
            if ev.defender_disabled or ev.security_controls_changed:
                ev.persistence_plus_weakening = True

    # -- the main per-event entry point ------------------------------------- #
    def handle_event(self, event_type: str, raw: dict, monitor_source: str,
                     collector_generated: bool = False,
                     prompt_mode: str = "baseline",
                     event_mono_ms: float | None = None,
                     rule_hints: dict | None = None) -> dict:
        """Track an event handler so finalisation cannot race active LLM work."""
        assert self.run is not None, "start() not called"
        with self._handler_condition:
            if not self._accepting_events:
                return {"skipped": "run_finalising"}
            self._active_handlers += 1
        try:
            return self._handle_event(
                event_type, raw, monitor_source, collector_generated,
                prompt_mode, event_mono_ms, rule_hints)
        finally:
            with self._handler_condition:
                self._active_handlers -= 1
                self._handler_condition.notify_all()

    def _handle_event(self, event_type: str, raw: dict, monitor_source: str,
                     collector_generated: bool = False,
                     prompt_mode: str = "baseline",
                     event_mono_ms: float | None = None,
                     rule_hints: dict | None = None) -> dict:
        """
        Process one event end-to-end. Returns a small result dict describing what
        happened (for tests). event_mono_ms lets tests inject a deterministic
        event time; in live use it defaults to 'now'.
        """
        assert self.run is not None, "start() not called"
        if event_mono_ms is None:
            event_mono_ms = _mono_ms()
        event_utc = _utc()

        # 1) preserve raw evidence (returns record incl. event_id + dup flags)
        rec = self.run.record_raw_event(
            event_type=event_type, monitor_source=monitor_source,
            raw_event_data=raw, collector_generated=collector_generated)
        event_id = rec["event_id"]

        # collector-generated events are context, never user evidence
        if collector_generated:
            return {"event_id": event_id, "skipped": "collector_generated"}

        # duplicate events are recorded but do not re-trigger
        if rec["duplicate_event"]:
            return {"event_id": event_id, "duplicate_of": rec["duplicate_of_event_id"]}

        # 2) accumulate evidence, then run the defensible rule layer
        self._update_evidence(event_type, raw)
        decision = self._evaluate_rule(event_type, raw, rule_hints or {})

        # 3) risk scoring (zeroed per scenario, auditable before/added/after)
        risk_delta = max(0, severity_rank(decision.severity))
        risk_audit = apply_risk(self.session, risk_delta)

        if not decision.alert:
            return {"event_id": event_id, "alert": False,
                    "rule_id": decision.rule_id, "severity": decision.severity,
                    **risk_audit}

        # 4) cooldown check (logged if suppressed)
        cooldown_key = f"{self.scenario_id}:{decision.category}:{decision.rule_id}"
        if not self.run.cooldown_ok(cooldown_key, self.cooldown_seconds, event_id):
            return {"event_id": event_id, "alert": False,
                    "cooldown_suppressed": True, "rule_id": decision.rule_id}

        # 5) build a NEUTRAL threat dict for the LLM (no plan ground truth)
        threat = {
            "type": event_type,
            "severity": decision.severity,
            "category": decision.category,
            "summary": decision.rationale,
            "context": _neutral_context(event_type, raw),
        }
        raw_summary = decision.rationale

        # 6) LLM call with full latency + validity instrumentation
        llm_record, ai_response, validity = validation_llm.run_llm_for_event(
            ask_ai_fn=self.ask_ai_fn, threat=threat, session=self.session,
            model=self.model, prompt_mode=prompt_mode, event_id=event_id,
            event_mono_ms=event_mono_ms, event_utc=event_utc,
            raw_event_summary=raw_summary, rule_trigger=decision.rule_id,
            rule_severity=decision.severity, rule_category=decision.category,
            show_popup_fn=self.show_popup_fn)
        self.run.record_llm_call(llm_record)

        # 7) alert record (fallback is never counted as a genuine response)
        alert_record = {
            "event_id": event_id,
            "event_type": event_type,
            "event_timestamp_utc": event_utc,
            "detection_timestamp_utc": llm_record["detection_timestamp_utc"],
            "queue_timestamp_utc": llm_record["queue_timestamp_utc"],
            "llm_request_started_utc": llm_record["llm_request_started_utc"],
            "llm_response_received_utc": llm_record["llm_response_received_utc"],
            "popup_displayed_utc": llm_record["popup_displayed_utc"],
            "model": self.model,
            "prompt_mode": prompt_mode,
            "raw_event_summary": raw_summary,
            "rule_trigger": decision.rule_id,
            "rule_severity": decision.severity,
            "rule_category": decision.category,
            "raw_model_response": llm_record["raw_model_response"],
            "parsed_model_response": llm_record["parsed_model_response"],
            "json_parse_valid": validity["json_parse_valid"],
            "required_fields_valid": validity["required_fields_valid"],
            "classification_valid": validity["classification_valid"],
            "risk_level_valid": validity["risk_level_valid"],
            "indicator_list_valid": validity["indicator_list_valid"],
            "strict_schema_valid": validity["strict_schema_valid"],
            "fallback_used": validity["fallback_used"],
            "timeout": llm_record["timeout"],
            "retry_count": llm_record["retry_count"],
            "error": llm_record["error"],
            "cooldown_suppressed": False,
            "duplicate_event": False,
            **risk_audit,
        }
        self.run.record_alert(alert_record)

        # record adaptive history AFTER the call (so the next repeat sees it)
        if self.history_module is not None:
            self.history_module.record(event_type, decision.severity, raw_summary)

        return {"event_id": event_id, "alert": True,
                "rule_id": decision.rule_id, "severity": decision.severity,
                "strict_schema_valid": validity["strict_schema_valid"],
                "fallback_used": validity["fallback_used"], **risk_audit}

    def _evaluate_rule(self, event_type: str, raw: dict, hints: dict) -> RuleDecision:
        expected_types = set(_split(self.plan.get("expected_event_types", "")))
        category = _category_for_event(
            event_type, self.plan.get("expected_category", ""), expected_types)
        fn = CATEGORY_RULES.get(category)
        combined_risky = (self.evidence.usb_connections > 0
                          or self.evidence.defender_disabled
                          or self.evidence.script_execution)
        if category == "AUTH":
            return fn(self.evidence, combined_risky)
        if category == "USB":
            return fn(self.evidence, authorised=hints.get("authorised", False))
        if category == "NET":
            return fn(self.evidence)
        if category == "PROC":
            return fn(self.evidence, shell_opened=hints.get("shell_opened", False),
                      basic_cmd=hints.get("basic_cmd", False))
        if category == "SEC":
            return fn(self.evidence, settings_viewed=hints.get("settings_viewed", False))
        if category == "PERSIST":
            return fn(self.evidence, ui_viewed=hints.get("ui_viewed", False),
                      artefact_removed=hints.get("artefact_removed", False))
        # NORMAL / unknown -> no alert
        from validation.rule_triggers import _d
        return _d(False, "normal", "NORMAL", "NORMAL_NONE", "No risky signal.")


def _neutral_context(event_type: str, raw: dict) -> dict:
    """Build LLM context from observed evidence only — no plan ground truth."""
    ctx = {"event_type": event_type}
    for k in ("device_name", "domain", "scheme", "filename", "extension",
              "process_name", "profile", "event_id"):
        if k in raw and raw[k] not in ("", None):
            ctx[k] = raw[k]
    return ctx


def _split(value: str) -> list:
    if not value:
        return []
    return [v.strip() for v in str(value).replace(",", ";").split(";") if v.strip()]


def _to_bool(value) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes", "y")
