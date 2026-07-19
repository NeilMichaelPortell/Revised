import time
import subprocess

from core.logger import write_log

CREATE_NO_WINDOW = 0x08000000


def _defender_realtime_disabled() -> bool:
    """Return True if Defender real-time monitoring is off."""
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring"],
            creationflags=CREATE_NO_WINDOW,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return "True" in result
    except Exception:
        return False


def _defender_definitions_stale() -> bool:
    """Return True if Defender signatures haven't been updated in > 3 days."""
    try:
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "(Get-MpComputerStatus).AntivirusSignatureLastUpdated"],
            creationflags=CREATE_NO_WINDOW,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if not result:
            return False
        from datetime import datetime, timezone
        # PowerShell returns something like: 14/03/2026 09:15:00
        for fmt in ("%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                last_update = datetime.strptime(result, fmt)
                delta = datetime.now() - last_update
                return delta.days > 3
            except ValueError:
                continue
        return False
    except Exception:
        return False


def run(session):
    """
    Polls Windows Defender status.
    Fires an event when real-time protection is turned off,
    or when signatures are stale (> 3 days old).
    """
    print("[SecurityMonitor] Monitoring Windows Defender status...")

    last_disabled     = False
    last_stale_alert  = False

    while True:
        try:
            # ── Defender disabled ─────────────────────────────
            disabled = _defender_realtime_disabled()
            if disabled and not last_disabled:
                write_log(
                    "defender_disabled",
                    {"message": "Windows Defender real-time monitoring was disabled."},
                    "security",
                )
            last_disabled = disabled

            # ── Stale signatures ──────────────────────────────
            stale = _defender_definitions_stale()
            if stale and not last_stale_alert:
                write_log(
                    "defender_definitions_stale",
                    {"message": "Windows Defender signatures have not been updated in over 3 days."},
                    "security",
                )
            last_stale_alert = stale

        except Exception:
            pass

        time.sleep(15)
