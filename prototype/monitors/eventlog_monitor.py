import time
import win32evtlog
from core.logger import write_log


# Security log events
SECURITY_EVENTS = {
    4625: "login_failed",
    4624: "login_success",
    4688: "process_created",
    1102: "security_log_cleared",
    4719: "audit_policy_changed",
    4698: "scheduled_task_created",
    4702: "scheduled_task_updated",
    5001: "defender_disabled",
    5007: "defender_config_changed",
}

# System log events
SYSTEM_EVENTS = {
    7040: "service_start_changed",
    41  : "unexpected_shutdown",
}

# Events we log but don't need to alert on every occurrence
HIGH_VOLUME_EVENTS = {"login_success", "process_created"}


def _open_log(server: str, log_name: str):
    try:
        return win32evtlog.OpenEventLog(server, log_name)
    except Exception as e:
        print(f"[EventLogMonitor] Could not open {log_name} log: {e}")
        if log_name == "Security":
            print("[EventLogMonitor] AUTH capture unavailable: grant this process "
                  "permission to read the Windows Security event log (normally "
                  "run from an elevated Administrator terminal).")
        return None


def run(session):
    """
    Tail the Windows Security and System event logs for threat-relevant
    events.  Uses FORWARDS_READ so only NEW events are processed after
    the monitor starts — no replay of old history.
    Requires admin privileges.
    """
    print("[EventLogMonitor] Monitoring Windows Security + System event logs...")

    server = "localhost"
    flags  = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    handles = {}
    for log_name in ["Security", "System"]:
        h = _open_log(server, log_name)
        if h:
            handles[log_name] = h

    if "Security" not in handles:
        print("[EventLogMonitor] WARNING: Event ID 4625 login failures cannot be "
              "captured in this run.")

    seen = set()

    # ── Seek to the current end of each log so we don't replay history ──
    for log_name, handle in handles.items():
        try:
            while True:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for e in batch:
                    seen.add(e.RecordNumber)
        except Exception:
            pass

    print(f"[EventLogMonitor] Positioned at end of logs — watching for new events...")

    while True:
        for log_name, handle in handles.items():
            mapping = SECURITY_EVENTS if log_name == "Security" else SYSTEM_EVENTS
            try:
                events = win32evtlog.ReadEventLog(handle, flags, 0) or []
            except Exception:
                events = []

            for event in events:
                rid = event.RecordNumber
                eid = event.EventID & 0xFFFF

                if rid in seen:
                    continue
                seen.add(rid)

                if eid not in mapping:
                    continue

                event_type = mapping[eid]

                # Skip high-volume benign events from full pipeline processing
                if event_type in HIGH_VOLUME_EVENTS:
                    continue

                data = {
                    "event_id": eid,
                    "record"  : rid,
                    "log"     : log_name,
                }

                write_log(event_type, data, "eventlog")

        time.sleep(3)
