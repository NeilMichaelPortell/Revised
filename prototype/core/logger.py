import os
import json
import threading
import datetime
from config import LOG_FILE, DATASET_FILE

log_lock  = threading.Lock()
_pipeline = None


def set_pipeline(p):
    global _pipeline
    _pipeline = p


def write_log(event_type: str, data: dict, source: str) -> dict:
    """
    Write one event to outputs/usage_logs.jsonl.

    The 'source' field is enriched with the actual name of what
    triggered the event so logs are human-readable at a glance:

        browser   → "browser:bbc.com"
        app       → "app:chrome.exe"
        process   → "process:notepad.exe"
        filesystem→ "filesystem:setup.exe"
        usb       → "usb:SanDisk Ultra"
        eventlog  → "eventlog:Security"
        network   → "network:Public"
        security  → "security:defender"
    """
    readable_source = _enrich_source(source, event_type, data)

    entry = {
        "timestamp" : datetime.datetime.now().isoformat(),
        "event_type": event_type,
        "source"    : readable_source,
        "data"      : data,
    }

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    if _pipeline:
        _pipeline.process(entry)

    return entry


def _enrich_source(source: str, event_type: str, data: dict) -> str:
    """
    Append the specific name/domain to the source tag so each log
    entry is self-explanatory without opening the data field.
    """
    try:
        if source == "browser":
            if event_type == "website_visited":
                domain = data.get("domain", "")
                scheme = data.get("scheme", "https")
                # Flag HTTP clearly in the source
                tag = f"http:{domain}" if scheme == "http" else f"browser:{domain}"
                return tag
            elif event_type == "file_downloaded":
                fname = (data.get("filename") or data.get("file_name") or "")
                name  = os.path.basename(fname) if fname else "unknown"
                return f"browser-download:{name}"

        elif source == "app":
            name = data.get("process_name", "")
            return f"app:{name}" if name else "app"

        elif source == "process":
            name = data.get("process_name", "")
            return f"process:{name}" if name else "process"

        elif source == "filesystem":
            fname = data.get("filename", "")
            name  = os.path.basename(fname) if fname else "unknown"
            return f"filesystem:{name}"

        elif source == "usb":
            device = data.get("device_name", data.get("device", ""))
            return f"usb:{device}" if device else "usb"

        elif source == "eventlog":
            log   = data.get("log", "")
            eid   = data.get("event_id", "")
            return f"eventlog:{log}:{eid}" if log else "eventlog"

        elif source == "network":
            profile = data.get("profile", "")
            return f"network:{profile}" if profile else "network"

        elif source == "security":
            return f"security:{event_type}"

    except Exception:
        pass

    return source


def export_dataset(event_type: str, severity: str, risk_score: int, source: str):
    """Append one row to the research dataset."""
    os.makedirs(os.path.dirname(DATASET_FILE), exist_ok=True)
    record = {
        "timestamp" : datetime.datetime.now().isoformat(),
        "event_type": event_type,
        "severity"  : severity,
        "risk_score": risk_score,
        "source"    : source,
    }
    with log_lock:
        with open(DATASET_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
