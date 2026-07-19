import json
import threading
import datetime
from collections import defaultdict
from config import SUMMARY_FILE


class SessionState:

    def __init__(self):
        self.lock               = threading.Lock()
        self.total_events       = 0
        self.threat_count       = 0

        # Web tracking — ALL visits, not just HTTP
        self.sites_visited      = []          # list of {domain, scheme, ts}
        self.scheme_counts      = defaultdict(int)
        self.domain_counts      = defaultdict(int)
        self.tld_counts         = defaultdict(int)

        # App tracking
        self.app_counts         = defaultdict(int)
        self.app_first_seen     = {}
        self.app_last_seen      = {}

        # Downloads
        self.downloads          = []          # list of {filename, ext, source, ts}

        # Other
        self.usb_connections    = 0
        self.usb_devices        = []
        self.security_events    = defaultdict(int)
        self.risk_score         = 0
        self.risk_events        = []

        self.first_event        = None
        self.last_event         = None


    def record_event(self, event_type: str, data: dict):
        with self.lock:
            now = datetime.datetime.now().isoformat()
            if not self.first_event:
                self.first_event = now
            self.last_event    = now
            self.total_events += 1

            if event_type == "website_visited":
                domain = data.get("domain", "")
                scheme = data.get("scheme", "https")
                self.scheme_counts[scheme] += 1
                if domain:
                    self.domain_counts[domain] += 1
                    tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
                    if tld:
                        self.tld_counts[tld] += 1
                    self.sites_visited.append({
                        "domain": domain,
                        "scheme": scheme,
                        "ts"    : now,
                    })

            elif event_type == "file_downloaded":
                import os
                fname = (data.get("filename") or data.get("file_name") or
                         data.get("url", "")).lower()
                self.downloads.append({
                    "filename": fname,
                    "ext"     : os.path.splitext(fname)[1],
                    "source"  : data.get("source_domain", ""),
                    "ts"      : now,
                })

            elif event_type == "application_started":
                name = data.get("process_name", "unknown")
                self.app_counts[name] += 1
                self.app_first_seen.setdefault(name, now)
                self.app_last_seen[name] = now

            elif "usb" in event_type:
                self.usb_connections += 1
                self.usb_devices.append({
                    "name": data.get("device_name", data.get("device", "unknown")),
                    "ts"  : now,
                })

            else:
                self.security_events[event_type] += 1


    def record_threat(self, threat_type: str, score: int):
        with self.lock:
            self.threat_count += 1
            self.risk_score   += score
            self.risk_events.append({"type": threat_type, "score": score})


    def risk_level(self) -> str:
        if self.risk_score >= 15: return "high"
        if self.risk_score >= 7:  return "medium"
        return "low"


    # ── Snapshot helpers used by the AI prompt ────────────────
    def recent_sites(self, n: int = 10) -> list:
        with self.lock:
            return list(self.sites_visited[-n:])

    def recent_downloads(self, n: int = 5) -> list:
        with self.lock:
            return list(self.downloads[-n:])

    def top_domains(self, n: int = 5) -> list:
        with self.lock:
            return sorted(self.domain_counts.items(),
                          key=lambda x: x[1], reverse=True)[:n]

    def http_visit_count(self) -> int:
        with self.lock:
            return self.scheme_counts.get("http", 0)

    def https_visit_count(self) -> int:
        with self.lock:
            return self.scheme_counts.get("https", 0)


    def build_summary(self) -> dict:
        with self.lock:
            total_web   = sum(self.scheme_counts.values())
            https_ratio = round(
                self.scheme_counts.get("https", 0) / max(1, total_web), 2
            )
            top_apps = sorted(
                self.app_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]

            risk_indicators = []
            http_count = self.scheme_counts.get("http", 0)
            if http_count > 0:
                risk_indicators.append(
                    f"{http_count} site(s) visited over unencrypted HTTP."
                )
            if self.usb_connections > 0:
                names = [d["name"] for d in self.usb_devices]
                risk_indicators.append(
                    f"{self.usb_connections} USB device(s) connected: "
                    f"{', '.join(names[:3])}."
                )
            if self.security_events.get("login_failed", 0) >= 3:
                risk_indicators.append(
                    f"{self.security_events['login_failed']} failed login attempts."
                )
            if self.security_events.get("defender_disabled", 0) > 0:
                risk_indicators.append("Windows Defender was disabled this session.")
            if self.security_events.get("security_log_cleared", 0) > 0:
                risk_indicators.append("Security event log was cleared.")
            if self.threat_count > 0:
                risk_indicators.append(
                    f"{self.threat_count} threat(s) flagged "
                    f"(risk score: {self.risk_score} — {self.risk_level()})."
                )

            return {
                "generated_at"    : datetime.datetime.now().isoformat(),
                "session_window"  : {
                    "first_event": self.first_event,
                    "last_event" : self.last_event,
                },
                "total_events"    : self.total_events,
                "threat_count"    : self.threat_count,
                "risk_analysis"   : {
                    "risk_score" : self.risk_score,
                    "risk_level" : self.risk_level(),
                    "risk_events": list(self.risk_events[-20:]),
                },
                "web_activity"    : {
                    "total_requests"  : total_web,
                    "protocol_counts" : dict(self.scheme_counts),
                    "https_ratio"     : https_ratio,
                    "top_domains"     : dict(
                        sorted(self.domain_counts.items(),
                               key=lambda x: x[1], reverse=True)[:10]
                    ),
                    "top_tlds"        : dict(
                        sorted(self.tld_counts.items(),
                               key=lambda x: x[1], reverse=True)[:10]
                    ),
                },
                "recent_downloads": list(self.downloads[-10:]),
                "top_applications": [
                    {
                        "name"      : k,
                        "launches"  : v,
                        "first_seen": self.app_first_seen.get(k),
                        "last_seen" : self.app_last_seen.get(k),
                    }
                    for k, v in top_apps
                ],
                "security_events" : dict(self.security_events),
                "usb_connections" : self.usb_connections,
                "risk_indicators" : risk_indicators,
            }


    def save_summary(self) -> dict:
        import os
        os.makedirs(os.path.dirname(SUMMARY_FILE), exist_ok=True)
        summary = self.build_summary()
        with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        return summary
