"""
validation_run.py
=================
Owns one validation RUN: its isolated output folder, its identifiers, and all
auditable JSONL/JSON writers. One ValidationRun instance == one folder under
validation_outputs/<validation_run_id>/.

Responsibilities:
  * generate + propagate run/scenario/session identifiers onto every record
  * preserve raw evidence in raw_events.jsonl (never overwritten)
  * record alerts (alerts.jsonl) and llm calls (llm_calls.jsonl)
  * capture real latency with a monotonic timer + UTC audit timestamps
  * process/app deduplication with a short window
  * cooldown-suppression logging
  * per-scenario state reset (independent vs adaptive mode)
  * write run_metadata.json, session_summary.json, prototype_metrics.json,
    run_validation_report.txt

It does NOT touch the frozen offline experiment.
"""

from __future__ import annotations

import json
import os
import time
import uuid
import datetime
import threading

from validation import validation_config as vc
from validation.validation_config import (
    MODE_INDEPENDENT, MODE_ADAPTIVE, RUN_FILES, summarise_latency,
)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _mono_ms() -> float:
    """High-resolution monotonic clock in milliseconds (for durations)."""
    return time.perf_counter() * 1000.0


class ValidationRun:
    def __init__(self, base_dir: str, run_metadata: dict, mode: str):
        if mode not in vc.VALID_MODES:
            raise ValueError(f"Unknown validation mode: {mode!r}")
        self.mode = mode
        self.meta = dict(run_metadata)
        self.run_id = self.meta["validation_run_id"]
        self.scenario_id = self.meta["scenario_id"]
        self.repetition = int(self.meta.get("repetition", 1))

        self.session_id = uuid.uuid4().hex
        self.session_started_at = _utc_now()

        # isolated output folder (never mixes independent sessions)
        self.out_dir = os.path.join(base_dir, vc.VALIDATION_OUTPUT_DIRNAME, self.run_id)
        os.makedirs(self.out_dir, exist_ok=True)

        self._lock = threading.Lock()

        # accumulators for metrics
        self._events: list[dict] = []
        self._alerts: list[dict] = []
        self._llm_calls: list[dict] = []
        self._cooldowns: list[dict] = []

        # dedup + cooldown state
        self._recent_procs: dict[tuple, dict] = {}   # key -> {event_id, ts_mono}
        self._cooldown_last: dict[str, float] = {}   # cooldown_key -> mono ms

        # write initial metadata
        self.meta.setdefault("mode", mode)
        self.meta.setdefault("session_id", self.session_id)
        self.meta.setdefault("session_started_at", self.session_started_at)
        self.meta.setdefault("started_at_utc", _utc_now())
        self.meta.setdefault("status", "running")
        self._write_metadata()

    # -- identifiers stamped on every record --------------------------------- #
    def _ident(self) -> dict:
        return {
            "validation_run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "repetition": self.repetition,
            "session_id": self.session_id,
            "session_started_at": self.session_started_at,
        }

    # -- raw evidence (never overwritten) ------------------------------------ #
    def record_raw_event(self, event_type: str, monitor_source: str,
                         raw_event_data: dict, normalised_event: dict | None = None,
                         collector_generated: bool = False) -> dict:
        """
        Append one raw event. Returns the stored record (including its event_id
        and duplicate flags) so the caller can correlate an alert to it.
        """
        event_id = uuid.uuid4().hex
        ts_utc = _utc_now()
        ts_mono = _mono_ms()

        duplicate, dup_of = self._check_duplicate(event_type, raw_event_data, event_id, ts_mono)

        record = {
            "event_id": event_id,
            **self._ident(),
            "timestamp_utc": ts_utc,
            "_detect_mono_ms": ts_mono,          # internal, stripped on write
            "event_type": event_type,
            "monitor_source": monitor_source,
            "raw_event_data": raw_event_data,
            "normalised_event": normalised_event or {},
            "collector_generated": bool(collector_generated),
            "duplicate_event": duplicate,
            "duplicate_of_event_id": dup_of,
        }
        with self._lock:
            self._events.append(record)
        self._append_jsonl(RUN_FILES["raw_events"], _strip_internal(record))
        return record

    def _check_duplicate(self, event_type, raw, event_id, ts_mono):
        """Process/app dedup by (name, pid, exe) within a short window."""
        if event_type not in ("process_started", "application_started", "process_seen"):
            return False, None
        name = (raw.get("process_name") or "").lower()
        pid = raw.get("pid") or raw.get("process_id") or ""
        exe = (raw.get("exe") or raw.get("exe_path") or "").lower()
        key = (name, str(pid), exe)
        if not name:
            return False, None
        prior = self._recent_procs.get(key)
        if prior and (ts_mono - prior["ts_mono"]) <= vc.DEDUP_WINDOW_SECONDS * 1000.0:
            return True, prior["event_id"]
        # record first observation (preserve original event_id)
        self._recent_procs[key] = {"event_id": event_id, "ts_mono": ts_mono}
        return False, None

    # -- cooldown ------------------------------------------------------------ #
    def cooldown_ok(self, cooldown_key: str, duration_s: float,
                    source_event_id: str) -> bool:
        """
        Return True if an alert may fire; False (and log a suppression) if the
        same cooldown_key fired within duration_s.
        """
        now = _mono_ms()
        last = self._cooldown_last.get(cooldown_key)
        if last is not None and (now - last) < duration_s * 1000.0:
            remaining = round(duration_s - (now - last) / 1000.0, 3)
            record = {
                **self._ident(),
                "cooldown_key": cooldown_key,
                "cooldown_duration_seconds": duration_s,
                "cooldown_remaining_seconds": remaining,
                "suppressed_at_utc": _utc_now(),
                "source_event_id": source_event_id,
            }
            with self._lock:
                self._cooldowns.append(record)
            return False
        self._cooldown_last[cooldown_key] = now
        return True

    # -- alerts + llm calls -------------------------------------------------- #
    def record_alert(self, alert_record: dict) -> None:
        rec = {**self._ident(), **alert_record}
        with self._lock:
            self._alerts.append(rec)
        self._append_jsonl(RUN_FILES["alerts"], rec)

    def record_llm_call(self, llm_record: dict) -> None:
        rec = {**self._ident(), **llm_record}
        with self._lock:
            self._llm_calls.append(rec)
        self._append_jsonl(RUN_FILES["llm_calls"], rec)

    # -- writers ------------------------------------------------------------- #
    def _append_jsonl(self, filename: str, record: dict) -> None:
        path = os.path.join(self.out_dir, filename)
        with self._lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _write_metadata(self) -> None:
        path = os.path.join(self.out_dir, RUN_FILES["metadata"])
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.meta, f, indent=2)

    def write_session_summary(self, summary: dict) -> None:
        path = os.path.join(self.out_dir, RUN_FILES["session_summary"])
        with open(path, "w", encoding="utf-8") as f:
            json.dump({**self._ident(), **summary}, f, indent=2)

    # -- finalisation -------------------------------------------------------- #
    def finalise(self, status: str = "completed") -> dict:
        self.meta["status"] = status
        self.meta["completed_at_utc"] = _utc_now()
        self._write_metadata()
        metrics = self.compute_metrics()
        with open(os.path.join(self.out_dir, RUN_FILES["metrics"]), "w",
                  encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        report = self.build_report(metrics)
        with open(os.path.join(self.out_dir, RUN_FILES["report"]), "w",
                  encoding="utf-8") as f:
            f.write(report)
        return metrics

    # -- metrics ------------------------------------------------------------- #
    def compute_metrics(self) -> dict:
        expected_types = set(self.meta.get("expected_event_types", []))
        events = self._events
        alerts = self._alerts
        llm = self._llm_calls

        captured_types = {e["event_type"] for e in events if not e["duplicate_event"]}
        unexpected = sorted(captured_types - expected_types) if expected_types else []
        expected_captured = sorted(captured_types & expected_types)

        alert_expected = bool(self.meta.get("alert_expected", False))
        alerts_generated = len(alerts)

        # false alert: an alert fired in a scenario where none was expected
        false_alerts = alerts_generated if (not alert_expected) else 0
        # missed alert: an alert was expected but none fired
        missed_alerts = 1 if (alert_expected and alerts_generated == 0) else 0

        genuine_llm = [c for c in llm if not c.get("fallback_used")]
        json_valid = sum(1 for c in llm if c.get("json_parse_valid"))
        strict_valid = sum(1 for c in llm if c.get("strict_schema_valid"))
        fallback = sum(1 for c in llm if c.get("fallback_used"))
        timeouts = sum(1 for c in llm if c.get("timeout"))
        retries = sum(int(c.get("retry_count", 0)) for c in llm)

        det = [c["detection_latency_ms"] for c in llm if _num(c.get("detection_latency_ms"))]
        gen = [c["llm_generation_latency_ms"] for c in llm if _num(c.get("llm_generation_latency_ms"))]
        e2e = [c["end_to_end_latency_ms"] for c in llm if _num(c.get("end_to_end_latency_ms"))]

        det_s = summarise_latency(det)
        gen_s = summarise_latency(gen)
        e2e_s = summarise_latency(e2e)

        return {
            "validation_run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "repetition": self.repetition,
            "mode": self.mode,
            "events_captured": len([e for e in events if not e["duplicate_event"]]),
            "expected_events_captured": expected_captured,
            "unexpected_events": unexpected,
            "alerts_generated": alerts_generated,
            "alerts_expected": alert_expected,
            "false_alerts": false_alerts,
            "missed_alerts": missed_alerts,
            "cooldown_suppressions": len(self._cooldowns),
            "duplicate_events": sum(1 for e in events if e["duplicate_event"]),
            "llm_calls": len(llm),
            "json_parse_valid_count": json_valid,
            "strict_schema_valid_count": strict_valid,
            "fallback_count": fallback,
            "timeout_count": timeouts,
            "retry_count": retries,
            "genuine_llm_responses": len(genuine_llm),
            "mean_detection_latency_ms": det_s["mean"],
            "median_detection_latency_ms": det_s["median"],
            "p95_detection_latency_ms": det_s["p95"],
            "mean_llm_latency_ms": gen_s["mean"],
            "median_llm_latency_ms": gen_s["median"],
            "p95_llm_latency_ms": gen_s["p95"],
            "mean_end_to_end_latency_ms": e2e_s["mean"],
            "median_end_to_end_latency_ms": e2e_s["median"],
            "p95_end_to_end_latency_ms": e2e_s["p95"],
            "_latency_detail": {"detection": det_s, "llm": gen_s, "end_to_end": e2e_s},
        }

    # -- human-readable report ---------------------------------------------- #
    def build_report(self, metrics: dict) -> str:
        m = self.meta
        L = []
        L.append("ENDPOINT PROTOTYPE - RUN VALIDATION REPORT")
        L.append("=" * 60)
        L.append(f"Run ID          : {self.run_id}")
        L.append(f"Scenario        : {self.scenario_id}  ({m.get('scenario_title','')})")
        L.append(f"Mode            : {self.mode}")
        L.append(f"Repetition      : {self.repetition}")
        L.append(f"Start (UTC)     : {m.get('started_at_utc','')}")
        L.append(f"End   (UTC)     : {m.get('completed_at_utc','')}")
        L.append(f"Status          : {m.get('status','')}")
        L.append("")
        L.append("EVENTS")
        L.append("-" * 60)
        L.append(f"Events captured        : {metrics['events_captured']}")
        L.append(f"Expected types present : {', '.join(metrics['expected_events_captured']) or '(none)'}")
        L.append(f"Unexpected types       : {', '.join(metrics['unexpected_events']) or '(none)'}")
        L.append(f"Duplicate events       : {metrics['duplicate_events']}")
        L.append("")
        L.append("ALERTS")
        L.append("-" * 60)
        L.append(f"Alerts generated       : {metrics['alerts_generated']}")
        L.append(f"Alert expected (plan)  : {metrics['alerts_expected']}")
        L.append(f"False alerts           : {metrics['false_alerts']}")
        L.append(f"Missed alerts          : {metrics['missed_alerts']}")
        L.append(f"Cooldown suppressions  : {metrics['cooldown_suppressions']}")
        L.append("")
        L.append("LLM OUTPUT RELIABILITY")
        L.append("-" * 60)
        L.append(f"LLM calls              : {metrics['llm_calls']}")
        L.append(f"JSON-parse valid       : {metrics['json_parse_valid_count']}")
        L.append(f"Strict-schema valid    : {metrics['strict_schema_valid_count']}")
        L.append(f"Fallbacks (not success): {metrics['fallback_count']}")
        L.append(f"Timeouts               : {metrics['timeout_count']}")
        L.append(f"Retries                : {metrics['retry_count']}")
        L.append("")
        L.append("LATENCY (ms)")
        L.append("-" * 60)
        d = metrics["_latency_detail"]
        for label, key in (("Detection", "detection"), ("LLM generation", "llm"),
                           ("End-to-end", "end_to_end")):
            s = d[key]
            L.append(f"{label:<16} n={s['count']:<3} mean={s['mean']:<9} "
                     f"median={s['median']:<9} p95={s['p95']}")
        L.append("")
        L.append("WARNINGS AND LIMITATIONS")
        L.append("-" * 60)
        L.append("* Observed events are compared to the EXPLICIT validation plan,")
        L.append("  not to any hidden ground truth. The plan is a test plan only.")
        L.append("* Rule severity is the prototype's provisional trigger, NOT")
        L.append("  ground truth and NOT the LLM classification.")
        L.append("* This is a controlled test on a limited Windows environment.")
        L.append("  It supports operational feasibility and ecological validity")
        L.append("  but is NOT independent organisational/real-world validation.")
        if metrics["missed_alerts"]:
            L.append("* An expected alert did not fire - review raw_events.jsonl.")
        if metrics["false_alerts"]:
            L.append("* Alert(s) fired in a scenario the plan marked benign.")
        drain = m.get("finalise_drain", {})
        if drain.get("handlers_remaining"):
            L.append("* Finalisation timed out while event handler(s) were still active;")
            L.append("  LLM/alert/latency metrics may be incomplete. Review run metadata.")
        return "\n".join(L) + "\n"


def _num(v) -> bool:
    try:
        float(v)
        return True
    except (TypeError, ValueError):
        return False


def _strip_internal(record: dict) -> dict:
    """Remove internal-only keys (leading underscore) before writing to disk."""
    return {k: v for k, v in record.items() if not k.startswith("_")}
