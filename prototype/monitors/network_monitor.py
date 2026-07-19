import time
import subprocess
from core.logger import write_log

CREATE_NO_WINDOW = 0x08000000


def _get_network_profile() -> str:
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory"],
            creationflags=CREATE_NO_WINDOW,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return result.strip()
    except Exception:
        return ""


def run(session):
    """
    Monitor two things:
      1. Network profile changes (Private → Public is a risk signal)
      2. New outbound connections (logged for the dataset, not alerted on)
    """
    print("[NetworkMonitor] Monitoring network profile changes...")
    last_profile = None

    while True:
        # ── Profile change check ──────────────────────────────
        try:
            profile = _get_network_profile()
            if profile and profile != last_profile:
                data = {"profile": profile}
                write_log("network_profile_changed", data, "network")
                last_profile = profile
        except Exception:
            pass

        time.sleep(10)
