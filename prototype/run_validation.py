#!/usr/bin/env python3
"""
run_validation.py
=================
Launcher for a single supplementary validation scenario on a controlled Windows
test machine. It:

  1. loads a scenario row from a validation plan CSV (by scenario_id);
  2. creates an isolated ValidationRun folder;
  3. resets state according to the scenario's validation_mode;
  4. starts the live monitors and routes every event through the validation
     ScenarioRunner (raw evidence -> rule trigger -> local LLM feedback);
  5. on 'stop' (q / Ctrl+C), finalises metrics and the run report.

Only ONE model runs at a time (chosen at startup), matching the dissertation's
single-machine, manual model-comparison design.

This launcher never modifies the frozen offline experiment. If the Windows
monitor modules are unavailable (e.g. running on a non-Windows box for a dry
run), it still creates the run folder and lets you inject events manually so the
plumbing can be checked; it prints a clear warning that live capture is off.

USAGE
-----
    python run_validation.py --scenario LIVE_AUTH_001 --plan example_validation_plan.csv
    python run_validation.py --scenario LIVE_AUTH_001 --model deepseek-r1:8b
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import config  # noqa: E402
from core.session_state import SessionState  # noqa: E402
from validation.scenario_runner import ScenarioRunner  # noqa: E402
from validation.validation_config import VALID_MODES  # noqa: E402

try:
    from ai import user_history as history_module
except Exception:
    history_module = None


def load_plan_row(plan_path: str, scenario_id: str) -> dict:
    with open(plan_path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if (row.get("scenario_id") or "").strip() == scenario_id:
                return row
    raise SystemExit(f"Scenario '{scenario_id}' not found in {plan_path}")


def pick_model(explicit: str | None) -> str:
    if explicit:
        return explicit
    # default to the first main model; the researcher can override with --model
    return "llama3"


def _make_ask_ai():
    """Return the real ask_ai if importable, else a clearly-marked stub."""
    try:
        from ai.ollama_client import ask_ai
        return ask_ai, True
    except Exception as exc:
        def _stub(threat, session=None):
            return {
                "title": "AI coach unavailable",
                "what_happened": "Model client could not be imported.",
                "why_risky": "n/a",
                "how_to_prevent": ["Install Ollama and run 'ollama serve'."],
                "learning_tip": f"stub: {exc}",
                "_error": True,
            }
        return _stub, False


def main() -> None:
    ap = argparse.ArgumentParser(description="Run one live validation scenario.")
    ap.add_argument("--scenario", required=True, help="scenario_id from the plan CSV")
    ap.add_argument("--plan", default=os.path.join(BASE_DIR, "example_validation_plan.csv"))
    ap.add_argument("--model", default=None, help="Ollama model (default llama3)")
    ap.add_argument("--prompt-mode", default="baseline", choices=["baseline", "rag"])
    args = ap.parse_args()

    plan_row = load_plan_row(args.plan, args.scenario)
    mode = (plan_row.get("validation_mode") or "").strip()
    if mode not in VALID_MODES:
        raise SystemExit(f"Scenario '{args.scenario}' has invalid validation_mode "
                         f"'{mode}'. Must be one of {sorted(VALID_MODES)}.")

    model = pick_model(args.model)
    config.OLLAMA_MODEL = model
    ask_ai_fn, live_ai = _make_ask_ai()

    session = SessionState()
    runner = ScenarioRunner(
        base_dir=BASE_DIR, plan_row=plan_row, session=session,
        ask_ai_fn=ask_ai_fn, model=model, history_module=history_module,
        cooldown_seconds=getattr(config, "COOLDOWN_SECONDS", 45.0),
        finalise_wait_seconds=(2 * getattr(config, "OLLAMA_TIMEOUT", 120) + 5))

    run = runner.start()
    print("=" * 64)
    print(f"  VALIDATION RUN: {run.run_id}")
    print(f"  scenario : {plan_row.get('scenario_title','')}")
    print(f"  mode     : {mode}")
    print(f"  model    : {model}  (AI client {'live' if live_ai else 'STUB — no model'})")
    print(f"  output   : {run.out_dir}")
    print("=" * 64)

    expected_types = set(run.meta.get("expected_event_types", []))
    if "login_failed" in expected_types:
        print("[AUTH preflight] Event ID 4625 capture requires Windows Logon "
              "failure auditing and permission to read the Security event log.")
        print("[AUTH preflight] The repeated-login rule requires 3 distinct "
              "captured failures unless a planned combined-risk rule applies; "
              "verify the live count before stopping.")

    # Attempt to start live monitors. They are Windows-only and best-effort:
    # a monitor that cannot start must never abort the run.
    live_started = _try_start_live_monitors(session, runner, args.prompt_mode)
    if not live_started:
        print("[warn] Live Windows monitors are not available in this environment.")
        print("       The run folder is created and the pipeline is ready; perform")
        print("       the scenario on a Windows test machine for live capture.")

    print("\nPerform the scenario now. Type 'stop' (or press Ctrl+C) to finish.\n")
    try:
        while True:
            line = input().strip().lower()
            if line in ("stop", "q", "quit", "exit"):
                break
    except (EOFError, KeyboardInterrupt):
        pass

    metrics = runner.complete("completed")
    print("\n[done] Run finalised.")
    print(f"  events captured : {metrics['events_captured']}")
    print(f"  alerts generated: {metrics['alerts_generated']}")
    print(f"  report          : {os.path.join(run.out_dir, 'run_validation_report.txt')}")


def _try_start_live_monitors(session, runner, prompt_mode) -> bool:
    """
    Bridge the existing monitors to the validation runner. Each monitor calls
    core.logger.write_log(); we intercept those events by installing a pipeline
    shim that forwards to the ScenarioRunner. Returns True if at least the
    logging bridge was installed.
    """
    try:
        from core import logger as core_logger

        class _Bridge:
            def process(self, entry):
                try:
                    runner.handle_event(
                        event_type=entry["event_type"],
                        raw=entry.get("data", {}),
                        monitor_source=entry.get("source", ""),
                        prompt_mode=prompt_mode)
                except Exception as exc:
                    print(f"[bridge] error handling event: {exc}")

        core_logger.set_pipeline(_Bridge())
    except Exception as exc:
        print(f"[warn] could not install event bridge: {exc}")
        return False

    started_any = False
    # Best-effort start of each monitor; failures are logged, never fatal.
    monitor_specs = [
        ("browser", "monitors.browser_endpoint", "start_and_wait", (session,), False),
        ("apps", "monitors.app_monitor", "run", (session,), True),
        ("process", "monitors.process_monitor", "run", (session,), True),
        ("files", "monitors.file_monitor", "run", (session,), True),
        ("network", "monitors.network_monitor", "run", (session,), True),
        ("usb", "monitors.usb_monitor", "run", (session,), True),
        ("eventlog", "monitors.eventlog_monitor", "run", (session,), True),
        ("security", "monitors.security_monitor", "run", (session,), True),
    ]
    import importlib
    import threading
    for name, modpath, fn, fnargs, threaded in monitor_specs:
        try:
            mod = importlib.import_module(modpath)
            func = getattr(mod, fn)
            if name == "browser":
                try:
                    func()  # start_and_wait takes no session in this build
                except TypeError:
                    func
                started_any = True
            elif threaded:
                threading.Thread(target=func, args=fnargs, daemon=True).start()
                started_any = True
        except Exception as exc:
            print(f"[warn] monitor '{name}' unavailable: {exc}")
    return started_any


if __name__ == "__main__":
    main()
