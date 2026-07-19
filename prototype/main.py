"""
Cyber Monitor — main entry point
=================================
1. Pick an Ollama model
2. Warm it up
3. Start all monitors
4. Run until the user presses  q  or  Ctrl+C
"""

import os
import sys
import ctypes
import threading
import subprocess
import time

import config                               # sets OLLAMA_MODEL at startup
from config import (
    LOG_FILE, ALERT_TXT, ALERT_JSON, SUMMARY_FILE, DATASET_FILE,
    FLASK_HOST, FLASK_PORT,
    SUMMARY_INTERVAL,
)

from core.session_state  import SessionState
from core.event_pipeline import EventPipeline
from core.logger         import set_pipeline

from monitors.browser_endpoint import start_and_wait as start_browser
from monitors.app_monitor      import run as run_apps
from monitors.process_monitor  import run as run_process
from monitors.file_monitor     import run as run_files
from monitors.network_monitor  import run as run_network

# Admin-only monitors
try:
    import win32evtlog, wmi
    ADMIN_MODULES_OK = True
except ImportError:
    ADMIN_MODULES_OK = False

CREATE_NO_WINDOW = 0x08000000
stop_event       = threading.Event()


# ═════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _ensure_dirs():
    for path in [LOG_FILE, ALERT_TXT, ALERT_JSON, SUMMARY_FILE, DATASET_FILE]:
        os.makedirs(os.path.dirname(path), exist_ok=True)


# ═════════════════════════════════════════════════════════════
#  MODEL PICKER + WARM-UP
# ═════════════════════════════════════════════════════════════
def _get_models() -> list:
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=10, creationflags=CREATE_NO_WINDOW,
        )
        models = []
        for line in result.stdout.strip().splitlines()[1:]:
            parts = line.split()
            if parts:
                models.append(parts[0])
        return models
    except FileNotFoundError:
        print("\n[Ollama] ✗  Not found — install from https://ollama.com\n")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("\n[Ollama] ✗  Timeout — is Ollama running?\n")
        sys.exit(1)


def _speed_hint(name: str) -> str:
    n = name.lower()
    if "qwen3" in n and "8b" in n:                   return "⚡⚡  fast + thinking  ★ recommended"
    if "qwen3" in n:                                  return "⚡   qwen3 series"
    if "gpt-oss" in n and "20b" in n:                return "🔥  accurate, needs ~12 GB RAM  ★ supported"
    if any(x in n for x in ("0.5b", "1b", "1.5b")): return "⚡⚡⚡ very fast"
    if any(x in n for x in ("2b", "3b")):            return "⚡⚡  fast"
    if any(x in n for x in ("7b", "8b")):            return "⚡   moderate  (~30s)"
    if any(x in n for x in ("13b","14b","12b")):     return "🔥  slower    (~60-90s)"
    if any(x in n for x in ("20b","32b","70b")):     return "🐌  slow / needs lots of RAM"
    return "❓  unknown speed"


def pick_model() -> str:
    print("\n" + "═"*60)
    print("  STEP 1 OF 2  —  Choose your AI model")
    print("═"*60)
    models = _get_models()
    if not models:
        print("  No models installed. Install one or more of the five evaluation models:")
        print("    ollama pull llama3")
        print("    ollama pull deepseek-r1:8b")
        print("    ollama pull gemma3:12b")
        print("    ollama pull qwen3:8b")
        print("    ollama pull gpt-oss:20b")
        sys.exit(1)

    for i, m in enumerate(models, 1):
        print(f"    {i}.  {m:<42}  {_speed_hint(m)}")
    print()
    print("  All five evaluation models are equal choices; select the one to run now.")
    print()
    while True:
        try:
            idx = int(input(f"  Enter number [1–{len(models)}]: ").strip()) - 1
            if 0 <= idx < len(models):
                chosen = models[idx]
                print(f"\n  ✓  Selected: {chosen}\n")
                return chosen
            print(f"  Please enter a number between 1 and {len(models)}.")
        except ValueError:
            print("  Please enter a valid number.")
        except KeyboardInterrupt:
            print("\n  Cancelled.")
            sys.exit(0)


def warm_up(model: str):
    print("═"*60)
    print("  STEP 2 OF 2  —  Loading model into memory")
    print("═"*60)
    print(f"  Warming up {model} — this only happens once at startup...")
    try:
        proc = subprocess.run(
            ["ollama", "run", model],
            input="Reply with one word: ready",
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=120, creationflags=CREATE_NO_WINDOW,
        )
        reply = proc.stdout.strip()
        print(f"  ✓  Model says: \"{reply[:60]}\"")
        print("  ✓  Ready.\n")
    except subprocess.TimeoutExpired:
        print("  ✗  Warm-up timed out — continuing anyway.\n")
    except Exception as e:
        print(f"  ✗  {e}\n")


# ═════════════════════════════════════════════════════════════
#  SUMMARY LOOP
# ═════════════════════════════════════════════════════════════
def summary_loop(session: SessionState):
    print(f"[Summary] Rolling summary every {SUMMARY_INTERVAL}s → {SUMMARY_FILE}")
    while not stop_event.is_set():
        time.sleep(SUMMARY_INTERVAL)
        try:
            summary = session.save_summary()
            ri      = summary.get("risk_indicators", [])
            risk    = summary.get("risk_analysis", {})
            web     = summary.get("web_activity", {})
            print(
                f"\n[Summary] {summary['total_events']} events | "
                f"{summary['threat_count']} threats | "
                f"Risk: {risk.get('risk_score',0)} ({risk.get('risk_level','low')}) | "
                f"Web: {web.get('total_requests',0)} reqs, "
                f"{web.get('https_ratio',1)*100:.0f}% HTTPS"
                + (f" | ⚠ {len(ri)} indicator(s)" if ri else "")
            )
            for r in ri:
                print(f"           • {r}")
        except Exception as e:
            print(f"[Summary] Error: {e}")


# ═════════════════════════════════════════════════════════════
#  SHUTDOWN
# ═════════════════════════════════════════════════════════════
def shutdown(reason: str = ""):
    if not stop_event.is_set():
        print(f"\n[Main] Stopping{' — '+reason if reason else ''}...")
        stop_event.set()


def _listen_for_quit():
    print("[Main] Type  q  + Enter   OR   Ctrl+C   to stop.\n")
    while not stop_event.is_set():
        try:
            if input().strip().lower() in ("q", "quit", "stop", "exit"):
                shutdown("user typed quit")
                break
        except (EOFError, KeyboardInterrupt):
            break


# ═════════════════════════════════════════════════════════════
#  BANNER
# ═════════════════════════════════════════════════════════════
def _banner():
    W = 72
    print("╔" + "═"*W + "╗")
    print("║" + "  🛡  CYBER MONITOR — Real-Time Security + Adaptive AI Coach".center(W) + "║")
    print("╠" + "═"*W + "╣")

    def row(k, v):
        print(f"║  {k:<22}: {str(v):<{W-27}}║")

    row("Usage log",        "outputs/usage_logs.jsonl")
    row("Alert report",     "outputs/security_alerts.txt  ← human-readable")
    row("Alert data",       "outputs/security_alerts.jsonl")
    row("Session summary",  f"outputs/session_summary.json  (every {SUMMARY_INTERVAL}s)")
    row("Research dataset", "outputs/research_dataset.jsonl")
    row("Browser endpoint", f"http://{FLASK_HOST}:{FLASK_PORT}  (health-checked on startup)")
    row("Admin mode",       "YES — full monitoring" if is_admin()
                            else "NO  — event log + USB disabled (run as Admin for full coverage)")
    print("╚" + "═"*W + "╝\n")


# ═════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════
if __name__ == "__main__":

    _banner()

    if not is_admin():
        print("[WARNING] Not running as Administrator.")
        print("          Event log, USB, and Defender monitoring are DISABLED.")
        print("          Right-click VS Code → Run as Administrator for full coverage.\n")

    # Create output directories
    _ensure_dirs()

    # ── Step 1: Pick model ────────────────────────────────────
    config.OLLAMA_MODEL = pick_model()

    # ── Step 2: Warm up ───────────────────────────────────────
    warm_up(config.OLLAMA_MODEL)

    # ── Wire up core objects ──────────────────────────────────
    session  = SessionState()
    pipeline = EventPipeline(session)
    set_pipeline(pipeline)

    # ── Start monitors ────────────────────────────────────────
    print("═"*60)
    print("  Starting all monitors...")
    print("═"*60)

    # Browser endpoint — Flask in a daemon thread, health-checked before continuing
    start_browser()

    # User-mode monitors
    threading.Thread(target=run_apps,    args=(session,), daemon=True).start()
    threading.Thread(target=run_process, args=(session,), daemon=True).start()
    threading.Thread(target=run_files,   args=(session,), daemon=True).start()
    threading.Thread(target=run_network, args=(session,), daemon=True).start()

    # Admin-only monitors
    if is_admin() and ADMIN_MODULES_OK:
        from monitors.usb_monitor      import run as run_usb
        from monitors.security_monitor import run as run_security
        from monitors.eventlog_monitor import run as run_eventlog

        threading.Thread(target=run_usb,      args=(session,), daemon=True).start()
        threading.Thread(target=run_security, args=(session,), daemon=True).start()
        threading.Thread(target=run_eventlog, args=(session,), daemon=True).start()
    elif not ADMIN_MODULES_OK:
        print("[WARNING] win32evtlog / wmi not found.")
        print("          Run:  pip install pywin32 wmi\n")

    # Rolling summary
    threading.Thread(target=summary_loop, args=(session,), daemon=True).start()

    print(f"\n  ✅  All monitors running.  Model: {config.OLLAMA_MODEL}")
    print("  ──────────────────────────────────────────────────────────")
    print("  To stop:  type  q  + Enter   OR   press  Ctrl+C")
    print("  ──────────────────────────────────────────────────────────\n")

    # Quit listener
    threading.Thread(target=_listen_for_quit, daemon=True).start()

    # Keep main thread alive
    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        shutdown("Ctrl+C")

    # ── Final summary on exit ─────────────────────────────────
    print("\n  ── FINAL SESSION SUMMARY ─────────────────────────────────")
    try:
        summary = session.save_summary()
        risk    = summary.get("risk_analysis", {})
        web     = summary.get("web_activity", {})
        print(f"  Total events   : {summary['total_events']}")
        print(f"  Threats found  : {summary['threat_count']}")
        print(f"  Risk score     : {risk.get('risk_score', 0)} ({risk.get('risk_level','low')})")
        print(f"  Web requests   : {web.get('total_requests',0)}  "
              f"({web.get('https_ratio',1)*100:.0f}% encrypted)")
        if summary.get("risk_indicators"):
            print("  Risk indicators:")
            for r in summary["risk_indicators"]:
                print(f"    • {r}")
        print(f"  Saved → {SUMMARY_FILE}")
    except Exception as e:
        print(f"  Could not save final summary: {e}")

    print(f"\n  Alerts saved → {ALERT_TXT}")
    sys.exit(0)
