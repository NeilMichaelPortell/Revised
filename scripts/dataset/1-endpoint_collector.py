#!/usr/bin/env python3
"""
endpoint_collector.py  (revised: precise, contamination-aware, privacy-conscious)
=================================================================================
Observe-only endpoint behaviour collector for the dissertation dataset. Writes
one JSONL file per day to raw_daily_logs/YYYY-MM-DD.jsonl and supports manual
scenario markers.

DESIGN RULE: precision, not surveillance. Reads state, writes logs. Never
disables Defender, changes services/tasks, or edits files. Never collects:
keystrokes, screenshots, passwords, clipboard, file contents, private messages,
full browser history, tokens, cookies, packet captures, or document contents.

Command lines are captured ONLY for the monitored shortlist below.

CONTAMINATION RULE: the collector runs PowerShell to read state. Those self-
generated commands (Get-MpComputerStatus, Get-WinEvent, etc.) and any shell
whose parent is this Python process are tagged so the segmenter can exclude
them from scenario evidence.

Markers: START_SCENARIO <ID>  END_SCENARIO <ID>  NOTE <text>  quit
Requires (Windows, admin recommended): pip install psutil pywin32 wmi
"""

from __future__ import annotations

import os
import sys
import json
import time
import queue
import ctypes
import datetime
import threading
import subprocess
from pathlib import Path

try:
    import psutil
    import win32evtlog
    import win32gui
    import win32process
    import wmi
    WINDOWS_OK = True
except ImportError:
    WINDOWS_OK = False

CREATE_NO_WINDOW = 0x08000000
COLLECTOR_PID = os.getpid()

# --- paths -------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
RAW_LOG_DIR = PROJECT_ROOT / "raw_daily_logs"
RAW_LOG_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOADS_DIR = Path.home() / "Downloads"

# --- options -----------------------------------------------------------------
LOG_USB_TOPLEVEL_FILENAMES = False  # default OFF; only names, never contents

# --- vocabulary --------------------------------------------------------------
MONITORED_PROCESSES = {
    "powershell.exe", "cmd.exe", "windowsterminal.exe", "python.exe",
    "nmap.exe", "reg.exe", "schtasks.exe", "net.exe", "netsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "certutil.exe", "curl.exe", "bitsadmin.exe",
}
RISKY_PROCESS_NAMES = MONITORED_PROCESSES | {
    "mimikatz.exe", "psexec.exe", "nc.exe", "ncat.exe", "masscan.exe",
    "vssadmin.exe", "wbadmin.exe", "metasploit.exe", "cobaltstrike.exe",
    "quasar.exe", "asyncrat.exe", "xmrig.exe",
}
SYSTEM_PROCESS_NAMES = {
    "explorer.exe", "svchost.exe", "csrss.exe", "winlogon.exe", "lsass.exe",
    "services.exe", "smss.exe", "wininit.exe", "taskhostw.exe", "dwm.exe",
    "conhost.exe", "dllhost.exe", "searchindexer.exe", "spoolsv.exe",
    "audiodg.exe", "runtimebroker.exe", "sihost.exe", "fontdrvhost.exe",
    "textinputhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "searchhost.exe", "widgets.exe", "systemsettings.exe", "applicationframehost.exe",
    "backgroundtaskhost.exe", "ctfmon.exe", "wmiprvse.exe",
}
RISKY_DOWNLOAD_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".com", ".pif", ".reg", ".hta", ".wsf", ".zip", ".torrent",
}
PARTIAL_DOWNLOAD_EXTENSIONS = {".crdownload", ".part", ".tmp", ".download"}

# Substrings that identify the collector's OWN monitoring commands.
COLLECTOR_COMMAND_MARKERS = (
    "Get-NetConnectionProfile", "Get-MpComputerStatus", "Get-WinEvent",
    "Get-CimInstance Win32_LogicalDisk", "Get-NetFirewallProfile",
)

SECURITY_EVENT_IDS = {
    4625: "failed_login",
    4698: "scheduled_task_changed", 4702: "scheduled_task_changed",
    4699: "scheduled_task_changed",
}
SYSTEM_EVENT_IDS = {7040: "service_changed"}
DEFENDER_EVENT_IDS = {
    5001: ("defender_status_changed", "realtime_protection_disabled"),
    5000: ("defender_status_changed", "realtime_protection_enabled"),
    5010: ("defender_status_changed", "scanning_disabled"),
    5012: ("defender_status_changed", "scanning_disabled"),
    5007: ("defender_status_changed", "configuration_changed"),
    1116: ("defender_status_changed", "malware_detected"),
    1117: ("defender_status_changed", "malware_action_taken"),
}
EVENT_ID_LABELS = {
    4625: "logon failure", 4698: "scheduled task created",
    4702: "scheduled task updated", 4699: "scheduled task deleted",
    7040: "service start type changed",
}

# --- shared state ------------------------------------------------------------
stop_event = threading.Event()
write_q: "queue.Queue[dict]" = queue.Queue()
seen_records: set = set()
seen_processes: set = set()
seen_apps: set = set()
download_seen: dict = {}
active_monitors: list = []
_state_lock = threading.Lock()
_current_network_profile = {"profile": None}
_current_removable = {"drives": []}
_dedup_lock = threading.Lock()
active_scenario = {"id": None}


def reset_scenario_dedup() -> None:
    with _dedup_lock:
        seen_processes.clear()
        seen_apps.clear()


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def now_iso() -> str:
    return datetime.datetime.now().isoformat()


def daily_log_path() -> Path:
    return RAW_LOG_DIR / f"{datetime.date.today().isoformat()}.jsonl"


def emit(event_type: str, source: str, details: dict) -> None:
    write_q.put({"timestamp": now_iso(), "event_type": event_type,
                 "source": source, "details": details})


def writer_loop() -> None:
    while not stop_event.is_set() or not write_q.empty():
        try:
            event = write_q.get(timeout=0.5)
        except queue.Empty:
            continue
        with daily_log_path().open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
            f.flush()
        et = event["event_type"]
        if et == "session_marker":
            print(f"  [marker] {event['details'].get('marker')} "
                  f"{event['details'].get('scenario_id','')}")
        elif et == "operator_note":
            print(f"  [note]   {event['details'].get('text','')}")
        elif et == "scenario_state_snapshot":
            print(f"  [snapshot] {event['details'].get('phase','')} state captured")
        else:
            print(f"  [event]  {et} :: {event['details']}")


# --- elevation ---------------------------------------------------------------
def process_is_elevated(p) -> str:
    """Return 'true'/'false'/'unknown' for a psutil process. Read-only."""
    try:
        # Heuristic: processes owned by SYSTEM/Administrators typically run
        # elevated. We avoid opening privileged tokens; instead we treat access
        # denial as 'unknown' rather than guessing.
        username = p.username()
        if username is None:
            return "unknown"
        u = username.lower()
        if u.endswith("system") or u.endswith("administrator"):
            return "true"
        return "unknown"
    except Exception:
        return "unknown"


COLLECTOR_ELEVATED = "true" if is_admin() else "false"


# --- helpers -----------------------------------------------------------------
def _event_strings(e) -> list:
    try:
        return list(e.StringInserts or [])
    except Exception:
        return []


def _is_collector_command(cmdline: str, parent_pid) -> bool:
    """True if this process is one of the collector's own monitoring shells."""
    if cmdline:
        for marker in COLLECTOR_COMMAND_MARKERS:
            if marker in cmdline:
                return True
    if parent_pid == COLLECTOR_PID:
        return True
    return False


def _proc_details(p) -> dict:
    name = (p.info.get("name") or "").lower()
    details = {"process_name": name}
    parent_pid = None
    try:
        details["pid"] = p.pid
    except Exception:
        pass
    try:
        details["exe_path"] = p.exe()
    except Exception:
        pass
    if name in MONITORED_PROCESSES:
        try:
            cl = p.cmdline()
            if cl:
                details["command_line"] = " ".join(cl)[:400]
        except Exception:
            pass
    try:
        parent = p.parent()
        if parent:
            parent_pid = parent.pid
            details["parent_process_name"] = (parent.name() or "").lower()
            details["parent_pid"] = parent_pid
    except Exception:
        pass
    try:
        details["start_time"] = datetime.datetime.fromtimestamp(
            p.create_time()).isoformat()
    except Exception:
        pass
    details["is_elevated"] = process_is_elevated(p)
    # contamination flag (segmenter uses this to exclude)
    if _is_collector_command(details.get("command_line", ""), parent_pid):
        details["collector_generated"] = True
    return details


def get_network_profile() -> dict:
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetConnectionProfile | Select-Object InterfaceAlias,"
             "NetworkCategory,IPv4Connectivity | ConvertTo-Json -Compress"],
            creationflags=CREATE_NO_WINDOW, stderr=subprocess.DEVNULL, text=True,
        ).strip()
        if not out:
            return {}
        data = json.loads(out)
        if isinstance(data, list):
            data = data[0] if data else {}
        cat = str(data.get("NetworkCategory", "")).lower()
        return {
            "profile": "public" if "public" in cat else ("private" if cat else "none"),
            "network_category": data.get("NetworkCategory", ""),
            "interface_alias": data.get("InterfaceAlias", ""),
            "ipv4_connectivity": data.get("IPv4Connectivity", ""),
        }
    except Exception:
        return {}


def get_defender_status() -> dict:
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,"
             "AntivirusEnabled,AMServiceEnabled | ConvertTo-Json -Compress"],
            creationflags=CREATE_NO_WINDOW, stderr=subprocess.DEVNULL, text=True,
        ).strip()
        if not out:
            return {}
        data = json.loads(out)
        return {
            "realtime_protection_enabled": bool(data.get("RealTimeProtectionEnabled", False)),
            "antivirus_enabled": bool(data.get("AntivirusEnabled", False)),
            "am_service_enabled": bool(data.get("AMServiceEnabled", False)),
        }
    except Exception:
        return {}


def get_firewall_status() -> dict:
    """Read (not change) firewall profile enabled state."""
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetFirewallProfile | Select-Object Name,Enabled |"
             " ConvertTo-Json -Compress"],
            creationflags=CREATE_NO_WINDOW, stderr=subprocess.DEVNULL, text=True,
        ).strip()
        if not out:
            return {}
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return {str(d.get("Name", "")): bool(d.get("Enabled", False)) for d in data}
    except Exception:
        return {}


def get_removable_drives() -> list:
    drives = []
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' |"
             " Select-Object DeviceID,VolumeName,FileSystem | ConvertTo-Json -Compress"],
            creationflags=CREATE_NO_WINDOW, stderr=subprocess.DEVNULL, text=True,
        ).strip()
        if not out:
            return []
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        for d in data:
            entry = {"drive_letter": d.get("DeviceID", ""),
                     "volume_name": d.get("VolumeName", ""),
                     "filesystem": d.get("FileSystem", "")}
            if LOG_USB_TOPLEVEL_FILENAMES and entry["drive_letter"]:
                try:
                    root = Path(entry["drive_letter"] + "\\")
                    entry["top_level_names"] = sorted(p.name for p in root.iterdir())[:50]
                except Exception:
                    pass
            drives.append(entry)
    except Exception:
        pass
    return drives


# --- monitors ----------------------------------------------------------------
def monitor_processes() -> None:
    print("[proc] monitoring application activity...")
    while not stop_event.is_set():
        try:
            hwnd = win32gui.GetForegroundWindow()
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid:
                p = psutil.Process(pid)
                name = (p.name() or "").lower()
                if name and name not in SYSTEM_PROCESS_NAMES:
                    with _dedup_lock:
                        is_new = name not in seen_apps
                        if is_new:
                            seen_apps.add(name)
                    if is_new:
                        title = win32gui.GetWindowText(hwnd) or ""
                        d = {"process_name": name,
                             "is_elevated": process_is_elevated(p)}
                        if title:
                            d["window_title"] = title[:120]
                        emit("app_opened", "process_monitor", d)
        except Exception:
            pass
        try:
            for p in psutil.process_iter(["name"]):
                name = (p.info.get("name") or "").lower()
                if name not in RISKY_PROCESS_NAMES:
                    continue
                d = _proc_details(p)
                key = (name, d.get("command_line", ""))
                with _dedup_lock:
                    is_new = key not in seen_processes
                    if is_new:
                        seen_processes.add(key)
                if is_new:
                    emit("process_seen", "process_monitor", d)
        except Exception:
            pass
        time.sleep(2)


def monitor_network_profile() -> None:
    print("[net] monitoring network connection profile...")
    last = None
    while not stop_event.is_set():
        info = get_network_profile()
        prof = info.get("profile")
        if prof and prof != last:
            with _state_lock:
                _current_network_profile.update(info)
            emit("network_profile_changed", "network_monitor", info)
            last = prof
        elif prof:
            with _state_lock:
                _current_network_profile.update(info)
        time.sleep(10)


def monitor_defender() -> None:
    print("[def] monitoring Defender (operational log + status polling)...")
    start_time = datetime.datetime.now()
    seen_def: set = set()
    wanted = ",".join(str(i) for i in DEFENDER_EVENT_IDS)
    last_rtp = None
    poll = 0
    while not stop_event.is_set():
        for _ in range(5):
            if stop_event.is_set():
                return
            time.sleep(1)
        try:
            after = start_time.strftime("%Y-%m-%dT%H:%M:%S")
            ps = ("$ErrorActionPreference='SilentlyContinue';"
                  "Get-WinEvent -FilterHashtable @{"
                  "LogName='Microsoft-Windows-Windows Defender/Operational';"
                  f"Id={wanted};StartTime='{after}'"
                  "} | Select-Object Id,RecordId | ConvertTo-Json -Compress")
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", ps],
                creationflags=CREATE_NO_WINDOW, stderr=subprocess.DEVNULL, text=True,
            ).strip()
            if out:
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for rec in data:
                    rid = rec.get("RecordId")
                    eid = rec.get("Id")
                    if rid in seen_def:
                        continue
                    seen_def.add(rid)
                    mapped = DEFENDER_EVENT_IDS.get(eid)
                    if mapped:
                        etype, kind = mapped
                        emit(etype, "defender_log",
                             {"event_id": eid, "kind": kind, "log": "Defender/Operational"})
        except Exception:
            pass
        poll += 1
        if poll % 6 == 0:
            status = get_defender_status()
            if status:
                rtp = status.get("realtime_protection_enabled")
                if rtp != last_rtp:
                    emit("defender_status_snapshot", "defender_status", status)
                    last_rtp = rtp


def monitor_event_logs() -> None:
    print("[evt] monitoring Security + System event logs...")
    handles = {}
    for name in ("Security", "System"):
        try:
            handles[name] = win32evtlog.OpenEventLog("localhost", name)
        except Exception as e:
            print(f"[evt] cannot open {name}: {e}")
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    baselined = 0
    for log_name, handle in handles.items():
        while True:
            try:
                events = win32evtlog.ReadEventLog(handle, flags, 0) or []
            except Exception:
                events = []
            if not events:
                break
            for e in events:
                seen_records.add((log_name, e.RecordNumber))
                baselined += 1
    print(f"[evt] baselined {baselined} existing record(s).")
    while not stop_event.is_set():
        for log_name, handle in handles.items():
            try:
                events = win32evtlog.ReadEventLog(handle, flags, 0) or []
            except Exception:
                events = []
            for e in events:
                key = (log_name, e.RecordNumber)
                if key in seen_records:
                    continue
                seen_records.add(key)
                eid = e.EventID & 0xFFFF
                mapping = SECURITY_EVENT_IDS if log_name == "Security" else SYSTEM_EVENT_IDS
                etype = mapping.get(eid)
                if not etype:
                    continue
                details = {"event_id": eid, "event": EVENT_ID_LABELS.get(eid, "unknown"),
                           "log": log_name}
                s = _event_strings(e)
                if eid == 7040 and s:
                    details["object_name"] = s[0]
                    if len(s) >= 3:
                        details["old_value"] = s[1]
                        details["new_value"] = s[2]
                elif eid in (4698, 4702, 4699) and s:
                    task = next((x for x in s if x and str(x).startswith("\\")), None)
                    if task:
                        details["object_name"] = task
                    if eid == 4699:
                        details["action"] = "deleted"
                    elif eid == 4698:
                        details["action"] = "created"
                    else:
                        details["action"] = "updated"
                elif eid == 4625 and s:
                    if len(s) > 5 and s[5]:
                        details["target_account"] = s[5]
                    if len(s) > 8 and s[8]:
                        details["logon_type"] = s[8]
                    if len(s) > 19 and s[19]:
                        details["source_network_address"] = s[19]
                emit(etype, "event_log", details)
        time.sleep(3)


def monitor_usb() -> None:
    print("[usb] monitoring USB + removable drives...")
    try:
        c = wmi.WMI()
        watcher = c.watch_for(notification_type="Creation",
                              wmi_class="Win32_USBControllerDevice")
    except Exception as e:
        print(f"[usb] watcher unavailable: {e}")
        watcher = None
    known = {d["drive_letter"] for d in get_removable_drives()}
    while not stop_event.is_set():
        if watcher:
            try:
                watcher(timeout_ms=2000)
                emit("usb_connected", "usb_monitor", {})
                current = get_removable_drives()
                with _state_lock:
                    _current_removable["drives"] = current
                for d in current:
                    if d["drive_letter"] not in known:
                        known.add(d["drive_letter"])
                        emit("removable_drive_seen", "usb_monitor", d)
            except Exception:
                pass
        else:
            time.sleep(2)


def monitor_downloads() -> None:
    print(f"[dl] monitoring downloads: {DOWNLOADS_DIR}")
    if not DOWNLOADS_DIR.exists():
        print("[dl] downloads folder not found; skipping.")
        return
    baseline = 0
    try:
        for entry in DOWNLOADS_DIR.iterdir():
            if entry.is_file() and entry.suffix.lower() in RISKY_DOWNLOAD_EXTENSIONS:
                download_seen[entry.name] = entry.stat().st_size
                baseline += 1
    except Exception as e:
        print(f"[dl] baseline error: {e}")
    print(f"[dl] baselined {baseline} existing file(s).")
    pending: dict = {}
    while not stop_event.is_set():
        try:
            for entry in DOWNLOADS_DIR.iterdir():
                if not entry.is_file():
                    continue
                ext = entry.suffix.lower()
                if ext in PARTIAL_DOWNLOAD_EXTENSIONS or ext not in RISKY_DOWNLOAD_EXTENSIONS:
                    continue
                name = entry.name
                if name in download_seen:
                    continue
                size = entry.stat().st_size
                if pending.get(name) == size and size > 0:
                    download_seen[name] = size
                    st = entry.stat()
                    emit("file_downloaded", "downloads_monitor", {
                        "filename": name, "extension": ext, "size_bytes": size,
                        "created_time": datetime.datetime.fromtimestamp(st.st_ctime).isoformat(),
                        "full_path": str(entry)})
                    pending.pop(name, None)
                else:
                    pending[name] = size
        except Exception as e:
            print(f"[dl] error: {e}")
        time.sleep(3)


# --- snapshots + markers -----------------------------------------------------
def build_scenario_snapshot(phase: str, scenario_id: str) -> dict:
    with _state_lock:
        net = dict(_current_network_profile)
    running = []
    if WINDOWS_OK:
        try:
            for p in psutil.process_iter(["name"]):
                name = (p.info.get("name") or "").lower()
                if name in RISKY_PROCESS_NAMES:
                    running.append(name)
        except Exception:
            pass
    return {
        "phase": phase, "scenario_id": scenario_id,
        "network_profile": net.get("profile", "none"),
        "network_category": net.get("network_category", ""),
        "defender": get_defender_status() if WINDOWS_OK else {},
        "firewall": get_firewall_status() if WINDOWS_OK else {},
        "running_monitored_processes": sorted(set(running)),
        "removable_drives": get_removable_drives() if WINDOWS_OK else [],
        "collector_is_admin": is_admin(),
    }


def marker_loop() -> None:
    print("\n" + "=" * 64)
    print("  MARKER CONSOLE")
    print("  START_SCENARIO <ID>   END_SCENARIO <ID>   NOTE <text>   quit")
    print("=" * 64 + "\n")
    while not stop_event.is_set():
        try:
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            stop_event.set()
            break
        if not line:
            continue
        low = line.lower()
        if low in ("quit", "q", "exit", "stop"):
            stop_event.set()
            break
        parts = line.split(maxsplit=1)
        cmd = parts[0].upper()
        if cmd == "NOTE":
            emit("operator_note", "operator", {"text": parts[1] if len(parts) > 1 else ""})
        elif cmd in ("START_SCENARIO", "END_SCENARIO") and len(parts) == 2:
            sid = parts[1].strip()
            if cmd == "START_SCENARIO":
                if active_scenario["id"] is not None:
                    print(f"  ! START {sid} while {active_scenario['id']} still active. "
                          f"End it first; overlapping windows are discouraged.")
                reset_scenario_dedup()
                active_scenario["id"] = sid
                emit("scenario_state_snapshot", "operator",
                     build_scenario_snapshot("start", sid))
                emit("session_marker", "operator",
                     {"marker": "START_SCENARIO", "scenario_id": sid})
            else:
                if active_scenario["id"] is None:
                    print(f"  ! END {sid} but no scenario is active. Ignored.")
                    continue
                if sid != active_scenario["id"]:
                    print(f"  ! END {sid} does not match active '{active_scenario['id']}'. Ignored.")
                    continue
                emit("scenario_state_snapshot", "operator",
                     build_scenario_snapshot("end", sid))
                emit("session_marker", "operator",
                     {"marker": "END_SCENARIO", "scenario_id": sid})
                active_scenario["id"] = None
                reset_scenario_dedup()
        else:
            print("  ! Use START_SCENARIO <ID> / END_SCENARIO <ID> / NOTE <text> / quit")


def main() -> None:
    print("=" * 64)
    print("  ENDPOINT BEHAVIOUR COLLECTOR (observe-only, precision-focused)")
    print("=" * 64)
    admin = is_admin()
    print(f"  Project root : {PROJECT_ROOT}")
    print(f"  Daily logs   : {RAW_LOG_DIR}")
    print(f"  Admin        : {'YES' if admin else 'NO'}")
    print(f"  Windows mods : {'available' if WINDOWS_OK else 'MISSING'}")
    print(f"  USB filenames: {'ENABLED' if LOG_USB_TOPLEVEL_FILENAMES else 'disabled (default)'}")
    print(f"  Collector PID: {COLLECTOR_PID} (used to exclude self-generated commands)")
    if not admin:
        print("  [warn] Not Administrator: failed_login / service / USB event")
        print("         capture limited. Re-run elevated for full coverage.")
    print("=" * 64)

    threading.Thread(target=writer_loop, daemon=True).start()
    if WINDOWS_OK:
        threading.Thread(target=monitor_processes, daemon=True).start(); active_monitors.append("processes")
        threading.Thread(target=monitor_network_profile, daemon=True).start(); active_monitors.append("network")
        threading.Thread(target=monitor_downloads, daemon=True).start(); active_monitors.append("downloads")
        threading.Thread(target=monitor_defender, daemon=True).start(); active_monitors.append("defender")
        if admin:
            threading.Thread(target=monitor_event_logs, daemon=True).start(); active_monitors.append("event_logs")
            threading.Thread(target=monitor_usb, daemon=True).start(); active_monitors.append("usb")
        else:
            print("[warn] event_logs + usb monitors DISABLED (need admin).")
    else:
        print("[warn] marker-only mode: pip install psutil pywin32 wmi for monitors.")
    print(f"[info] active monitors: {', '.join(active_monitors) or 'none'}")

    marker_loop()
    print("\n[main] stopping; flushing events...")
    stop_event.set()
    time.sleep(1.5)
    print("[main] done.")


if __name__ == "__main__":
    main()