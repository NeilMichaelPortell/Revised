import time
import psutil
import win32gui
import win32process
from core.logger import write_log
from config import KNOWN_SAFE_PROCESSES


def run(session):
    """Track the foreground application — logs each new exe seen once."""
    seen = set()
    print("[AppMonitor] Monitoring foreground applications...")

    while True:
        try:
            hwnd     = win32gui.GetForegroundWindow()
            _, pid   = win32process.GetWindowThreadProcessId(hwnd)
            p        = psutil.Process(pid)
            exe      = p.exe()

            if exe not in seen:
                seen.add(exe)
                data = {"process_name": p.name(), "exe": exe}
                write_log("application_started", data, "app")

        except Exception:
            pass

        time.sleep(2)
