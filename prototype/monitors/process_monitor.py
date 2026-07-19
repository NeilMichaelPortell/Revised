import time
import psutil
from core.logger import write_log


def run(session):
    """Scan all running processes — catches things the app_monitor misses."""
    seen = set()
    print("[ProcessMonitor] Scanning all running processes...")

    while True:
        try:
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                pid = proc.info["pid"]
                if pid in seen:
                    continue
                seen.add(pid)
                data = {
                    "process_name": proc.info["name"],
                    "pid"         : pid,
                    "exe"         : proc.info["exe"],
                }
                write_log("process_started", data, "process")

        except Exception:
            pass

        time.sleep(5)
