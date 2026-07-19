#!/usr/bin/env python3
"""
test_validation.py
==================
Automated tests for the validation layer (dissertation §18, §22). Uses only the
standard library (unittest) so it runs anywhere without pytest, Windows or a
live Ollama server. Windows events and Ollama responses are mocked.

The tests must not require disabling any real security control.

Run:
    python -m unittest tests.test_validation -v
    (or)  python tests/test_validation.py
"""

from __future__ import annotations

import json
import os
import sys
import shutil
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.session_state import SessionState
from validation.scenario_runner import ScenarioRunner
from validation import state_reset
from validation.schema_validation import parse_json_object, validate_response
from validation.validation_config import (
    MODE_INDEPENDENT, MODE_ADAPTIVE, VALIDATION_OUTPUT_DIRNAME, RUN_FILES,
)


# --- mock Ollama responses -------------------------------------------------- #
def mock_ask_ai_valid(threat, session=None):
    """A well-formed, strict-schema-valid response (with preserved raw text)."""
    body = {
        "classification": "risky",   # will normalise to abnormal
        "risk_level": "high",
        "indicators": ["failed_logins", "usb_connected"],
        "explanation": "Repeated failures then a USB device were observed.",
        "recommended_action": "Lock the account and remove the device.",
        # feedback fields the display path uses:
        "title": "Suspicious activity",
        "what_happened": "Repeated failed logins then USB insertion.",
        "why_risky": "This pattern can precede data theft.",
        "how_to_prevent": ["Enable MFA", "Do not insert unknown USB devices"],
        "learning_tip": "Repeated failures are a warning sign.",
    }
    resp = dict(body)
    resp["_raw_text"] = json.dumps(body)
    return resp


def mock_ask_ai_bad_schema(threat, session=None):
    """Valid JSON, but missing required fields -> schema invalid."""
    body = {"classification": "normal or risky", "risk_level": "low, medium"}
    resp = dict(body)
    resp["_raw_text"] = json.dumps(body)
    return resp


def mock_ask_ai_fallback(threat, session=None):
    """The client's hard-coded fallback (must NOT count as success)."""
    return {
        "title": "Security alert detected",
        "what_happened": "A security event was flagged.",
        "why_risky": "See details.",
        "how_to_prevent": ["Make sure Ollama is running"],
        "learning_tip": "AI coach unavailable: offline",
        "_error": True,
    }


def _plan(scenario_id, mode, expected_types, alert_expected,
          category, repetition=1, severity="medium;high"):
    return {
        "scenario_id": scenario_id,
        "scenario_title": f"test {scenario_id}",
        "validation_mode": mode,
        "repetition": str(repetition),
        "expected_event_types": ";".join(expected_types),
        "alert_expected": "true" if alert_expected else "false",
        "expected_category": category,
        "acceptable_severity": severity,
        "required_output_fields": "classification;risk_level;indicators;explanation;recommended_action",
        "researcher_notes": "unit test",
    }


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vtest_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_dir(self, run_id):
        return os.path.join(self.tmp, VALIDATION_OUTPUT_DIRNAME, run_id)

    def _read_jsonl(self, run_id, key):
        path = os.path.join(self._run_dir(run_id), RUN_FILES[key])
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    # -- run/scenario id propagation + output isolation --------------------- #
    def test_run_and_scenario_id_propagation_and_isolation(self):
        session = SessionState()
        r = ScenarioRunner(self.tmp, _plan("LIVE_AUTH_001", MODE_INDEPENDENT,
                                           ["login_failed"], True, "AUTH"),
                           session, mock_ask_ai_valid, "llama3")
        run = r.start()
        for _ in range(3):
            r.handle_event("login_failed", {"event_id": 4625}, "eventlog",
                           event_mono_ms=0.0)
        r.complete()

        # isolated folder exists and is named by run id
        self.assertTrue(os.path.isdir(self._run_dir("LIVE_AUTH_001_R1")))
        events = self._read_jsonl("LIVE_AUTH_001_R1", "raw_events")
        self.assertTrue(events)
        for e in events:
            self.assertEqual(e["validation_run_id"], "LIVE_AUTH_001_R1")
            self.assertEqual(e["scenario_id"], "LIVE_AUTH_001")
            self.assertEqual(e["repetition"], 1)
            self.assertIn("session_id", e)
            self.assertIn("timestamp_utc", e)

        # a second independent run gets its OWN folder
        session2 = SessionState()
        r2 = ScenarioRunner(self.tmp, _plan("LIVE_NORMAL_001", MODE_INDEPENDENT,
                                            ["website_visited"], False, "NORMAL"),
                            session2, mock_ask_ai_valid, "llama3")
        r2.start(); r2.complete()
        self.assertTrue(os.path.isdir(self._run_dir("LIVE_NORMAL_001_R1")))
        self.assertNotEqual(self._run_dir("LIVE_AUTH_001_R1"),
                            self._run_dir("LIVE_NORMAL_001_R1"))

    # -- state reset -------------------------------------------------------- #
    def test_state_reset_zeroes_session(self):
        session = SessionState()
        session.usb_connections = 5
        session.risk_score = 99
        session.record_event("login_failed", {})
        rec = state_reset.reset_session(session, MODE_INDEPENDENT, None)
        self.assertEqual(session.usb_connections, 0)
        self.assertEqual(session.risk_score, 0)
        self.assertEqual(session.total_events, 0)
        self.assertIn("risk_score", rec["cleared"])

    # -- history reset ------------------------------------------------------ #
    def test_history_reset_independent_vs_adaptive(self):
        # fake history module
        class FakeHistory:
            def __init__(self): self.events = [{"threat_type": "x"}]
            def get_recent(self, n=10): return list(self.events)
            def reset_history(self):
                c = len(self.events); self.events = []
                return {"cleared_adaptive_history_events": c}
            def record(self, *a, **k): self.events.append({"threat_type": a[0]})

        # independent -> history cleared
        h1 = FakeHistory()
        session = SessionState()
        rec = state_reset.reset_session(session, MODE_INDEPENDENT, h1)
        self.assertEqual(h1.events, [])
        self.assertIn("adaptive_user_history", rec["cleared"])

        # adaptive -> history preserved
        h2 = FakeHistory()
        rec2 = state_reset.reset_session(session, MODE_ADAPTIVE, h2)
        self.assertEqual(len(h2.events), 1)
        self.assertTrue(any("adaptive_user_history" in p for p in rec2["preserved"]))

    # -- USB count regression ---------------------------------------------- #
    def test_usb_count_regression(self):
        # Uses the real threat detector + session to prove no double count.
        from core.threat_detection import evaluate_threat
        session = SessionState()
        # first connection
        session.record_event("usb_connected", {"device_name": "Stick"})
        t1 = evaluate_threat("usb_connected", {"device_name": "Stick"}, session)
        self.assertEqual(t1["context"]["usb_plugged_in_today"], 1)
        # second connection
        session.record_event("usb_connected", {"device_name": "Stick"})
        t2 = evaluate_threat("usb_connected", {"device_name": "Stick"}, session)
        self.assertEqual(t2["context"]["usb_plugged_in_today"], 2)

    # -- process deduplication --------------------------------------------- #
    def test_process_deduplication(self):
        session = SessionState()
        r = ScenarioRunner(self.tmp, _plan("LIVE_PROC_001", MODE_INDEPENDENT,
                                           ["process_started"], False, "PROC"),
                           session, mock_ask_ai_valid, "llama3")
        r.start()
        raw = {"process_name": "powershell.exe", "pid": 111, "exe": "C:/ps.exe"}
        res1 = r.handle_event("process_started", raw, "process", event_mono_ms=0.0)
        res2 = r.handle_event("process_started", raw, "app", event_mono_ms=100.0)
        r.complete()
        self.assertNotIn("duplicate_of", res1)
        self.assertIn("duplicate_of", res2)
        events = self._read_jsonl("LIVE_PROC_001_R1", "raw_events")
        dups = [e for e in events if e["duplicate_event"]]
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0]["duplicate_of_event_id"], events[0]["event_id"])

    # -- cooldown logging --------------------------------------------------- #
    def test_cooldown_logging(self):
        session = SessionState()
        r = ScenarioRunner(self.tmp, _plan("LIVE_AUTH_002", MODE_INDEPENDENT,
                                           ["login_failed"], True, "AUTH"),
                           session, mock_ask_ai_valid, "llama3",
                           cooldown_seconds=9999.0)
        r.start()
        # push evidence to repeated-fail (>=3) so the rule fires
        for _ in range(3):
            r.handle_event("login_failed", {}, "eventlog", event_mono_ms=0.0)
        # further identical triggers should be cooldown-suppressed
        res = r.handle_event("login_failed", {}, "eventlog", event_mono_ms=0.0)
        r.complete()
        self.assertTrue(res.get("cooldown_suppressed"))
        with open(os.path.join(self._run_dir("LIVE_AUTH_002_R1"),
                               RUN_FILES["metrics"]), encoding="utf-8") as _mf:
            metrics = json.load(_mf)
        self.assertGreaterEqual(metrics["cooldown_suppressions"], 1)

    # -- browser URL sanitisation ------------------------------------------ #
    def test_browser_url_sanitisation(self):
        from monitors.browser_endpoint import _sanitize
        out = _sanitize("https://example.com/secret/path?token=abc#frag")
        self.assertEqual(set(out.keys()), {"scheme", "domain"})
        self.assertEqual(out["domain"], "example.com")
        self.assertNotIn("original_url", out)
        # sensitive path -> domain dropped too
        blocked = _sanitize("https://bank.com/login?u=me")
        self.assertTrue(blocked.get("blocked"))
        self.assertNotIn("domain", blocked)

    # -- JSON parse validity ------------------------------------------------ #
    def test_json_parse_validation(self):
        self.assertIsNone(parse_json_object("not json at all"))
        self.assertIsNotNone(parse_json_object('{"classification":"normal"}'))
        # embedded in reasoning prose
        self.assertIsNotNone(parse_json_object(
            'thinking...\n{"classification":"normal","risk_level":"low"} done'))

    # -- strict schema validation ------------------------------------------ #
    def test_strict_schema_validation(self):
        good = parse_json_object(mock_ask_ai_valid(None)["_raw_text"])
        v = validate_response(good, is_fallback=False)
        self.assertTrue(v["json_parse_valid"])
        self.assertTrue(v["strict_schema_valid"])
        self.assertEqual(v["raw_classification"], "risky")
        self.assertEqual(v["normalised_classification"], "abnormal")

        bad = parse_json_object(mock_ask_ai_bad_schema(None)["_raw_text"])
        v2 = validate_response(bad, is_fallback=False)
        self.assertTrue(v2["json_parse_valid"])          # valid JSON
        self.assertFalse(v2["strict_schema_valid"])      # invalid schema

    # -- fallback classification ------------------------------------------- #
    def test_fallback_not_counted_as_success(self):
        session = SessionState()
        r = ScenarioRunner(self.tmp, _plan("LIVE_SEC_001", MODE_INDEPENDENT,
                                           ["defender_disabled"], True, "SEC"),
                           session, mock_ask_ai_fallback, "llama3")
        r.start()
        r.handle_event("defender_disabled", {}, "security", event_mono_ms=0.0)
        r.complete()
        llm = self._read_jsonl("LIVE_SEC_001_R1", "llm_calls")
        self.assertTrue(llm)
        self.assertTrue(all(c["fallback_used"] for c in llm))
        self.assertTrue(all(not c["strict_schema_valid"] for c in llm))
        with open(os.path.join(self._run_dir("LIVE_SEC_001_R1"),
                               RUN_FILES["metrics"]), encoding="utf-8") as _mf:
            metrics = json.load(_mf)
        self.assertEqual(metrics["strict_schema_valid_count"], 0)
        self.assertGreaterEqual(metrics["fallback_count"], 1)

    # -- latency field generation ------------------------------------------ #
    def test_latency_fields_present(self):
        session = SessionState()
        r = ScenarioRunner(self.tmp, _plan("LIVE_COMBINED_001", MODE_INDEPENDENT,
                                           ["login_failed", "usb_connected"], True, "AUTH"),
                           session, mock_ask_ai_valid, "llama3")
        r.start()
        for _ in range(3):
            r.handle_event("login_failed", {}, "eventlog", event_mono_ms=0.0)
        r.complete()
        llm = self._read_jsonl("LIVE_COMBINED_001_R1", "llm_calls")
        self.assertTrue(llm)
        for c in llm:
            for field in ("detection_latency_ms", "queue_delay_ms",
                          "llm_generation_latency_ms", "popup_delay_ms",
                          "end_to_end_latency_ms"):
                self.assertIn(field, c)
                self.assertIsInstance(c[field], (int, float))

    # -- output directory isolation already covered; metrics file exists ---- #
    def test_metrics_and_report_written(self):
        session = SessionState()
        r = ScenarioRunner(self.tmp, _plan("LIVE_NET_001", MODE_INDEPENDENT,
                                           ["network_profile_changed"], False, "NET"),
                           session, mock_ask_ai_valid, "llama3")
        r.start()
        r.handle_event("network_profile_changed", {"profile": "Public"},
                       "network", event_mono_ms=0.0)
        r.complete()
        d = self._run_dir("LIVE_NET_001_R1")
        for key in ("metadata", "raw_events", "metrics", "report", "session_summary"):
            self.assertTrue(os.path.exists(os.path.join(d, RUN_FILES[key])),
                            f"missing {key}")

    # -- rule logic is defensible: public network alone does NOT alert ------ #
    def test_public_network_alone_no_alert(self):
        session = SessionState()
        r = ScenarioRunner(self.tmp, _plan("LIVE_NET_003", MODE_INDEPENDENT,
                                           ["network_profile_changed"], False, "NET"),
                           session, mock_ask_ai_valid, "llama3")
        r.start()
        res = r.handle_event("network_profile_changed", {"profile": "Public"},
                             "network", event_mono_ms=0.0)
        r.complete()
        self.assertFalse(res.get("alert"))

    # -- single failed login does NOT auto-alert --------------------------- #
    def test_single_failed_login_no_alert(self):
        session = SessionState()
        r = ScenarioRunner(self.tmp, _plan("LIVE_AUTH_003", MODE_INDEPENDENT,
                                           ["login_failed"], False, "AUTH"),
                           session, mock_ask_ai_valid, "llama3")
        r.start()
        res = r.handle_event("login_failed", {}, "eventlog", event_mono_ms=0.0)
        r.complete()
        self.assertFalse(res.get("alert"))

    def test_unexpected_usb_does_not_trigger_auth_rule(self):
        calls = []

        def ask_ai(threat, session=None):
            calls.append(threat)
            return mock_ask_ai_valid(threat, session)

        session = SessionState()
        r = ScenarioRunner(self.tmp, _plan("LIVE_AUTH_005", MODE_INDEPENDENT,
                                           ["login_failed"], True, "AUTH"),
                           session, ask_ai, "llama3")
        r.start()
        r.handle_event("login_failed", {}, "eventlog", event_mono_ms=0.0)
        r.handle_event("login_failed", {}, "eventlog", event_mono_ms=0.0)
        res = r.handle_event("usb_connected", {}, "usb", event_mono_ms=0.0)
        metrics = r.complete()

        self.assertFalse(res.get("alert"))
        self.assertEqual(calls, [])
        self.assertEqual(metrics["cooldown_suppressions"], 0)

    def test_complete_waits_for_inflight_llm_call(self):
        entered = threading.Event()
        release = threading.Event()

        def blocking_ask_ai(threat, session=None):
            entered.set()
            release.wait(1.0)
            return mock_ask_ai_valid(threat, session)

        session = SessionState()
        r = ScenarioRunner(self.tmp, _plan("LIVE_AUTH_006", MODE_INDEPENDENT,
                                           ["login_failed"], True, "AUTH"),
                           session, blocking_ask_ai, "llama3",
                           finalise_wait_seconds=1.0)
        r.start()
        r.handle_event("login_failed", {}, "eventlog", event_mono_ms=0.0)
        r.handle_event("login_failed", {}, "eventlog", event_mono_ms=0.0)
        worker = threading.Thread(
            target=r.handle_event,
            args=("login_failed", {}, "eventlog"),
            kwargs={"event_mono_ms": 0.0})
        worker.start()
        self.assertTrue(entered.wait(1.0))
        threading.Timer(0.05, release.set).start()

        metrics = r.complete()
        worker.join(1.0)

        self.assertFalse(worker.is_alive())
        self.assertEqual(metrics["llm_calls"], 1)
        self.assertEqual(metrics["alerts_generated"], 1)
        self.assertEqual(r.run.meta["finalise_drain"]["handlers_remaining"], 0)

    # -- risk scoring is per-scenario and auditable ------------------------- #
    def test_risk_scoring_audit_fields(self):
        session = SessionState()
        r = ScenarioRunner(self.tmp, _plan("LIVE_AUTH_004", MODE_INDEPENDENT,
                                           ["login_failed"], True, "AUTH"),
                           session, mock_ask_ai_valid, "llama3")
        r.start()
        res = None
        for _ in range(3):
            res = r.handle_event("login_failed", {}, "eventlog", event_mono_ms=0.0)
        r.complete()
        self.assertIn("risk_score_before_event", res)
        self.assertIn("risk_score_added", res)
        self.assertIn("risk_score_after_event", res)


if __name__ == "__main__":
    unittest.main(verbosity=2)
