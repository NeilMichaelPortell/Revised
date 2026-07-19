import os
import json
import datetime
import threading
import time

from core.threat_detection import evaluate_threat
from core.risk_scoring import calculate_risk
from core.logger import export_dataset
from ai.ollama_client import ask_ai
from ai.user_history import record as record_history
from config import ALERT_TXT, ALERT_JSON, COOLDOWN_SECONDS

from collections import defaultdict


class EventPipeline:

    def __init__(self, session):
        self.session     = session
        self._last_alert = defaultdict(float)
        self._lock       = threading.Lock()
        self._queue      = []
        self._queue_lock = threading.Lock()
        self._alert_num  = 0
        self._num_lock   = threading.Lock()

        os.makedirs(os.path.dirname(ALERT_TXT), exist_ok=True)

        # Worker thread drains the queue — monitors are never blocked by Ollama
        threading.Thread(target=self._worker, daemon=True).start()


    def process(self, event: dict):
        """Called by write_log() for every single event. Non-blocking."""
        event_type = event["event_type"]
        data       = event["data"]
        source     = event["source"]

        # 1 — always record into session state (ALL events, not just threats)
        self.session.record_event(event_type, data)

        # 2 — check if it's a threat, passing session for context
        threat = evaluate_threat(event_type, data, self.session)
        if not threat:
            return

        # 3 — cooldown: don't repeat same threat type within window
        if not self._cooldown_ok(threat["type"]):
            return

        # 4 — enqueue for AI analysis
        with self._queue_lock:
            self._queue.append((threat, source, event))

        print(f"\n  [⚠ THREAT DETECTED]  {threat['type'].upper()}")
        print(f"  {threat['summary']}")


    def _cooldown_ok(self, threat_type: str) -> bool:
        now = time.time()
        with self._lock:
            if now - self._last_alert[threat_type] < COOLDOWN_SECONDS:
                return False
            self._last_alert[threat_type] = now
        return True


    def _next_num(self) -> int:
        with self._num_lock:
            self._alert_num += 1
            return self._alert_num


    def _worker(self):
        """Background thread: take one threat at a time, call AI, display."""
        while True:
            time.sleep(0.5)
            with self._queue_lock:
                if not self._queue:
                    continue
                item = self._queue.pop(0)

            threat, source, event = item
            try:
                self._handle(threat, source, event)
            except Exception as e:
                print(f"[Pipeline] Error: {e}")


    def _handle(self, threat: dict, source: str, event: dict):
        threat_type = threat["type"]
        severity    = threat["severity"]
        risk_score  = calculate_risk(threat_type)

        self.session.record_threat(threat_type, risk_score)

        # Persist to user history BEFORE calling AI so the prompt includes
        # this event if the model is slow (history is written immediately).
        record_history(threat_type, severity, threat.get("summary", ""))

        print(f"  [Ollama] Analysing {threat_type} ...", flush=True)
        ai_response = ask_ai(threat, self.session)

        num = self._next_num()
        alert = {
            "alert_number": num,
            "timestamp"   : datetime.datetime.now().isoformat(),
            "event_type"  : event["event_type"],
            "source"      : source,
            "threat_type" : threat_type,
            "category"    : threat.get("category", "NORMAL"),
            "severity"    : severity,
            "risk_score"  : risk_score,
            "summary"     : threat.get("summary", ""),
            "context"     : threat.get("context", {}),
            "event_data"  : event["data"],
            "ai_response" : ai_response,
        }

        self._display(alert)
        self._write_alert(alert)
        export_dataset(threat_type, severity, risk_score, source)


    def _display(self, alert: dict):
        from ai.display import format_alert, popup_body
        block = format_alert(alert)
        print(block, flush=True)

        try:
            import ctypes
            body  = popup_body(alert)
            sev   = alert["severity"]
            title = (f"{'🚨 CRITICAL' if sev == 'critical' else '🔴 HIGH' if sev == 'high' else '🟠 MEDIUM' if sev == 'medium' else '🟡 LOW'}"
                     f"  — Alert #{alert['alert_number']}: {alert['threat_type'].replace('_',' ').title()}")
            # Keep the alert above terminals and other applications. Previously
            # it could open behind the active window and look like it was absent.
            icon = 0x00000010 if sev in ("high", "critical") else 0x00000030
            flags = icon | 0x00010000 | 0x00040000  # SETFOREGROUND | TOPMOST

            def show_windows_popup():
                try:
                    result = ctypes.windll.user32.MessageBoxW(
                        None, body, title, flags
                    )
                    if result == 0:
                        print("[Popup] Windows did not display the alert.", flush=True)
                except Exception as exc:
                    print(f"[Popup] Could not display Windows alert: {exc}", flush=True)

            threading.Thread(
                target=show_windows_popup,
                name=f"alert-popup-{alert['alert_number']}",
                daemon=True,
            ).start()
        except Exception as exc:
            print(f"[Popup] Could not prepare Windows alert: {exc}", flush=True)


    def _write_alert(self, alert: dict):
        from ai.display import format_alert
        with open(ALERT_TXT, "a", encoding="utf-8") as f:
            f.write(format_alert(alert))
        with open(ALERT_JSON, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")
