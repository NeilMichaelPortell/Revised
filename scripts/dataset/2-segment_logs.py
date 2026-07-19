#!/usr/bin/env python3
"""
segment_daily_logs.py  (revised: full schema, contamination filtering)
======================================================================
Cut daily JSONL logs into per-scenario summary JSONs using START/END markers.
Observe-and-summarise only. Ground truth loaded solely from
dataset/scenarios_revised.csv, else left blank.

Highlights:
  * Only within-window events summarised; out-of-window -> unassigned_events.jsonl
  * scenario_state_snapshot (start) -> context_state; a snapshot immediately
    before its START marker is pulled into the window.
  * Excludes collector-generated process events (contamination rule) and counts
    how many were filtered, warning when any were.
  * Defender: defender_disabled true ONLY for a genuine disable / RTP-off state.
  * USB debounce; process dedup by (name, cmdline); app dedup by name.
  * Full event_summary schema incl. apps_opened, elevated_processes,
    firewall_events, web_domains, removable_drive_details.
  * Warnings + summary table.
"""

from __future__ import annotations

import sys
import csv
import json
import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
RAW_LOG_DIR = PROJECT_ROOT / "raw_daily_logs"
SUMMARY_DIR = PROJECT_ROOT / "scenario_summaries"
DATASET_CSV = PROJECT_ROOT / "dataset" / "scenarios_revised.csv"
UNASSIGNED_PATH = RAW_LOG_DIR / "unassigned_events.jsonl"
SUMMARY_DIR.mkdir(parents=True, exist_ok=True)

USB_DEBOUNCE_SECONDS = 5.0
POTENTIALLY_RELEVANT = {"powershell.exe", "cmd.exe"}
KNOWN_CATEGORIES = {"NORMAL", "AUTH", "USB", "SEC", "PROC", "NET", "PERSIST"}
DEFENDER_DISABLE_KINDS = {"realtime_protection_disabled", "scanning_disabled"}

# Everyday user applications: kept as benign background context, never risky.
BENIGN_APPS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
    "opera.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "code.exe", "notepad.exe", "notepad++.exe", "teams.exe", "ms-teams.exe",
    "slack.exe", "discord.exe", "spotify.exe", "acrobat.exe", "acrord32.exe",
    "vlc.exe", "zoom.exe", "obsidian.exe", "sumatrapdf.exe",
}
# Browser / password-manager helper processes: benign background, never risky.
BROWSER_HELPER_PROCESSES = {
    "1password-browsersupport.exe", "mbambgnativemsg.exe",
    "chrome.nativemessaging", "chrome_nativemessaging",
    "msedgewebview2.exe", "opera_crashreporter.exe",
    "1passwordnativemessaginghost.exe", "keepasshelper.exe",
}
BENIGN_BACKGROUND = BENIGN_APPS | BROWSER_HELPER_PROCESSES

# Some browser native-messaging / password-manager helpers are launched via a
# cmd.exe wrapper, so they surface as process_name "cmd.exe" with the helper
# named in the command line. These command-line substrings identify that case
# so the wrapper is treated as benign background context, NOT as user-launched
# CMD. Genuine user CMD (no helper substring) still counts as risky evidence.
BENIGN_HELPER_CMDLINE_MARKERS = (
    "1Password-BrowserSupport.exe", "mbambgnativemsg.exe",
    "chrome.nativeMessaging",
)


def parse_ts(ts: str):
    try:
        return datetime.datetime.fromisoformat(ts)
    except Exception:
        return None


def load_events(path: Path) -> list:
    events = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"  ! {path.name} line {i}: invalid JSON, skipped")
    return events


def load_csv_metadata() -> dict:
    if not DATASET_CSV.exists():
        return {}
    meta = {}
    with DATASET_CSV.open("r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            sid = (r.get("scenario_id") or "").strip()
            if sid:
                meta[sid] = r
    return meta


def extract_windows(events: list, day: str):
    windows, unassigned, open_windows = [], [], {}
    pending_snapshot = None
    for ev in events:
        et = ev.get("event_type")
        det = ev.get("details", {})
        if et == "scenario_state_snapshot" and det.get("phase") == "start" and not open_windows:
            pending_snapshot = ev
            continue
        if et == "session_marker":
            marker = det.get("marker")
            sid = det.get("scenario_id", "")
            ts = ev.get("timestamp")
            if marker == "START_SCENARIO":
                if sid in open_windows:
                    print(f"  ! [{day}] START {sid} already open (overlap). Restarting.")
                if open_windows:
                    print(f"  ! [{day}] START {sid} while {', '.join(open_windows)} "
                          f"still open. Windows should not overlap.")
                open_windows[sid] = {"scenario_id": sid, "start_ts": ts, "events": []}
                if pending_snapshot is not None:
                    snap = pending_snapshot.get("details", {})
                    if snap.get("scenario_id") in (sid, "", None):
                        open_windows[sid]["events"].append(pending_snapshot)
                    pending_snapshot = None
            elif marker == "END_SCENARIO":
                if sid not in open_windows:
                    print(f"  ! [{day}] END {sid} with no matching START. Ignored.")
                    continue
                w = open_windows.pop(sid)
                w["end_ts"] = ts
                windows.append(w)
            continue
        if open_windows:
            for w in open_windows.values():
                w["events"].append(ev)
        else:
            unassigned.append(ev)
    for sid in open_windows:
        print(f"  ! [{day}] START {sid} never closed (missing END). Skipped.")
    if pending_snapshot is not None:
        unassigned.append(pending_snapshot)
    return windows, unassigned


def summarise_window(w: dict) -> tuple:
    events = w["events"]
    failed_logins = 0
    usb_ts = []
    removable_details = []
    risky = set()
    process_details = []
    elevated_processes = []
    seen_proc_keys = set()
    apps = []
    benign_background = set()
    collector_generated_events_filtered = 0
    defender_disabled = False
    defender_events = []
    firewall_events = []
    net_in_window = None
    sched_change = False
    sched_details = []
    svc_change = False
    svc_details = []
    file_downloaded = False
    download_details = []
    web_domains = []
    operator_notes = []
    context_state = {}

    for ev in events:
        et = ev.get("event_type")
        det = ev.get("details", {})
        if et == "failed_login":
            failed_logins += 1
        elif et == "usb_connected":
            ts = parse_ts(ev.get("timestamp", ""))
            if ts:
                usb_ts.append(ts)
        elif et == "removable_drive_seen":
            removable_details.append({k: det.get(k) for k in
                                      ("drive_letter", "volume_name", "filesystem")
                                      if det.get(k)})
        elif et == "process_seen":
            # 1) contamination rule: drop the collector's own monitoring shells
            if det.get("collector_generated"):
                collector_generated_events_filtered += 1
                continue
            name = (det.get("process_name") or "").lower()
            if not name:
                continue
            cmdline = det.get("command_line", "") or ""
            parent = (det.get("parent_process_name") or "").lower()
            # 1b) the collector's own python process and VS Code's PowerShell
            # shell-integration script are the collector/development environment,
            # not user activity. Excluding them prevents contaminating non-process
            # scenarios (e.g. USB_001) with the tooling used to run the study.
            if name == "python.exe" and (
                    "endpoint_collector.py" in cmdline
                    or "1-endpoint_collector.py" in cmdline):
                collector_generated_events_filtered += 1
                continue
            if (name == "powershell.exe" and parent == "code.exe"
                    and "shellIntegration.ps1" in cmdline):
                # VS Code terminal shell-integration bootstrap: development
                # context, not a user-launched shell. Genuine user PowerShell
                # (any other command line / parent) still counts as risky below.
                benign_background.add("powershell.exe (vscode shell integration)")
                continue
            # 2) browser/password-manager helpers: benign background, not risky
            if name in BENIGN_BACKGROUND:
                benign_background.add(name)
                continue
            # 2b) some helpers are launched via a cmd.exe wrapper and appear as
            # cmd.exe with the helper named in the command line — treat those as
            # benign background too, while genuine user CMD stays risky.
            if name == "cmd.exe" and any(m in cmdline for m in BENIGN_HELPER_CMDLINE_MARKERS):
                helper = next((m for m in BENIGN_HELPER_CMDLINE_MARKERS if m in cmdline), None)
                if helper:
                    benign_background.add(helper.lower())
                continue
            # 3) genuine monitored/suspicious activity: risky evidence
            risky.add(name)
            key = (name, det.get("command_line", ""))
            if key not in seen_proc_keys:
                seen_proc_keys.add(key)
                process_details.append(det)
                if det.get("is_elevated") == "true":
                    elevated_processes.append(name)
        elif et == "app_opened":
            name = (det.get("process_name") or "").lower()
            if not name:
                continue
            # everyday apps and helpers are benign background context
            if name in BENIGN_BACKGROUND:
                benign_background.add(name)
            if name not in apps:
                apps.append(name)
                if det.get("is_elevated") == "true" and name not in elevated_processes:
                    elevated_processes.append(name)
        elif et == "defender_status_changed":
            kind = det.get("kind", "")
            defender_events.append({"kind": kind, "event_id": det.get("event_id")})
            if kind in DEFENDER_DISABLE_KINDS:
                defender_disabled = True
        elif et == "defender_status_snapshot":
            if det.get("realtime_protection_enabled") is False:
                defender_disabled = True
            defender_events.append({"kind": "status_snapshot",
                                    "realtime_protection_enabled":
                                        det.get("realtime_protection_enabled")})
        elif et == "network_profile_changed":
            net_in_window = det.get("profile", net_in_window)
        elif et == "scheduled_task_changed":
            sched_change = True
            sched_details.append({k: det.get(k) for k in
                                  ("event_id", "object_name", "action") if det.get(k)})
        elif et == "service_changed":
            svc_change = True
            svc_details.append({k: det.get(k) for k in
                                ("object_name", "old_value", "new_value") if det.get(k)})
        elif et == "file_downloaded":
            file_downloaded = True
            download_details.append({k: det.get(k) for k in
                                     ("filename", "extension", "size_bytes",
                                      "created_time", "full_path") if det.get(k)})
        elif et == "web_visited":
            # privacy-preserving: domain + scheme only, never paths/queries
            dom = det.get("domain", "")
            if dom:
                entry = {"domain": dom, "scheme": det.get("scheme", ""),
                         "browser": det.get("browser", "")}
                if entry not in web_domains:
                    web_domains.append(entry)
        elif et == "operator_note":
            txt = det.get("text", "")
            if txt:
                operator_notes.append(txt)
        elif et == "scenario_state_snapshot":
            if det.get("phase") == "start":
                context_state = {
                    "network_profile": det.get("network_profile", "none"),
                    "network_category": det.get("network_category", ""),
                    "defender": det.get("defender", {}),
                    "firewall": det.get("firewall", {}),
                    "running_monitored_processes": det.get("running_monitored_processes", []),
                    "removable_drives": det.get("removable_drives", []),
                    "collector_is_admin": det.get("collector_is_admin"),
                }

    usb_ts.sort()
    usb_count, last = 0, None
    for ts in usb_ts:
        if last is None or (ts - last).total_seconds() > USB_DEBOUNCE_SECONDS:
            usb_count += 1
            last = ts

    if net_in_window is not None:
        network_profile = net_in_window
        net_from_ctx = False
    elif context_state.get("network_profile"):
        network_profile = context_state["network_profile"]
        net_from_ctx = True
    else:
        network_profile = "none"
        net_from_ctx = False

    observed = []
    if apps:
        observed.append("Applications used: " + ", ".join(apps) + ".")
    if failed_logins:
        observed.append(f"{failed_logins} failed login event(s) recorded.")
    if usb_count:
        observed.append(f"{usb_count} USB connection(s) recorded (after debounce).")
    if risky:
        observed.append("Monitored-list processes observed: " + ", ".join(sorted(risky)) + ".")
    pr = risky & POTENTIALLY_RELEVANT
    if pr:
        observed.append("Note: " + ", ".join(sorted(pr)) + " are common in normal "
                        "work and are not judged here; classification is manual.")
    if elevated_processes:
        observed.append("Elevated processes observed: " + ", ".join(sorted(set(elevated_processes))) + ".")
    if defender_disabled:
        observed.append("Defender real-time protection was recorded as disabled.")
    elif defender_events:
        observed.append("Defender event(s) recorded (not a disable): "
                        + ", ".join(sorted({d['kind'] for d in defender_events})) + ".")
    if firewall_events:
        observed.append("Firewall event(s) recorded.")
    if net_from_ctx:
        observed.append(f"Network profile (context at scenario start): {network_profile}.")
    elif network_profile != "none":
        observed.append(f"Network profile changed to {network_profile} during the window.")
    if sched_change:
        observed.append("A scheduled task change was recorded.")
    if svc_change:
        observed.append("A service change was recorded.")
    if file_downloaded:
        names = [d.get("filename", "") for d in download_details]
        observed.append("File(s) downloaded: " + ", ".join(n for n in names if n) + ".")
    if web_domains:
        observed.append("Web domains (redacted): " + ", ".join(d["domain"] for d in web_domains) + ".")
    if benign_background:
        observed.append("Benign background activity present (context, not risky): "
                        + ", ".join(sorted(benign_background)) + ".")
    if collector_generated_events_filtered:
        observed.append(f"{collector_generated_events_filtered} collector-generated "
                        f"process event(s) were excluded from this scenario.")
    if not observed:
        observed.append("No monitored security-relevant events were recorded.")

    sid = w["scenario_id"]
    category = sid.split("_")[0] if "_" in sid else ""

    summary = {
        "scenario_id": sid, "category": category, "scenario_name": "",
        "scenario_source": "collected", "collection_date": w.get("_day", ""),
        "window_start": w.get("start_ts", ""), "window_end": w.get("end_ts", ""),
        "event_summary": {
            "apps_opened": apps,
            "benign_background_processes": sorted(benign_background),
            "failed_logins": failed_logins,
            "usb_connection_count": usb_count,
            "removable_drive_details": removable_details,
            "risky_processes": sorted(risky),
            "process_details": process_details,
            "elevated_processes": sorted(set(elevated_processes)),
            "defender_disabled": defender_disabled,
            "defender_events": defender_events,
            "firewall_events": firewall_events,
            "network_profile": network_profile,
            "scheduled_task_change": sched_change,
            "scheduled_task_details": sched_details,
            "service_change": svc_change,
            "service_change_details": svc_details,
            "file_downloaded": file_downloaded,
            "download_details": download_details,
            "web_domains": web_domains,
            "collector_generated_events_filtered": collector_generated_events_filtered,
            "operator_notes": operator_notes,
        },
        "observed_events": observed,
        "context_state": context_state,
        "ground_truth": {"classification": "", "risk_level": "",
                         "expected_indicators": [], "label_reason": ""},
    }
    return summary, collector_generated_events_filtered


def apply_csv_metadata(summary: dict, meta: dict) -> list:
    warnings = []
    sid = summary["scenario_id"]
    row = meta.get(sid)
    if row is None:
        warnings.append("not in CSV")
        print(f"  ! {sid} not found in scenarios_revised.csv (ground truth blank).")
        return warnings
    if row.get("scenario_name"):
        summary["scenario_name"] = row["scenario_name"]
    if row.get("scenario_source"):
        summary["scenario_source"] = row["scenario_source"]
    if row.get("category"):
        summary["category"] = row["category"]
    gt = summary["ground_truth"]
    gt["classification"] = row.get("ground_truth_class", "") or ""
    gt["risk_level"] = row.get("ground_truth_risk", "") or ""
    ind = row.get("expected_indicators", "") or ""
    gt["expected_indicators"] = [s.strip() for s in ind.split(";") if s.strip()]
    gt["label_reason"] = row.get("label_reason", "") or ""
    return warnings


def check_warnings(summary: dict, extra: list, filtered: int) -> list:
    warnings = list(extra)
    sid = summary["scenario_id"]
    prefix = sid.split("_")[0] if "_" in sid else ""
    cat = summary["category"]
    if prefix and cat and prefix != cat:
        warnings.append(f"category '{cat}' != prefix '{prefix}'")
        print(f"  ! {sid}: category '{cat}' does not match id prefix '{prefix}'.")
    if filtered:
        warnings.append(f"{filtered} collector cmd(s) filtered")
    es = summary["event_summary"]
    meaningful = (es["failed_logins"] or es["usb_connection_count"] or es["risky_processes"]
                  or es["defender_disabled"] or es["scheduled_task_change"]
                  or es["service_change"] or es["file_downloaded"]
                  or es["apps_opened"] or es["web_domains"]
                  or es["network_profile"] not in ("none", ""))
    if not meaningful:
        warnings.append("no meaningful events")
    return warnings


def print_table(rows: list) -> None:
    if not rows:
        return
    print("\n" + "=" * 118)
    print("  SEGMENTATION SUMMARY")
    print("=" * 118)
    hdr = "  {:<12}{:<8}{:>5}{:>5}{:>4}{:<18}{:>5}{:>7}{:>6}{:>4}{:>5}  {}".format(
        "scenario", "cat", "apps", "fail", "usb", " risky_procs", "elev",
        "defoff", "sched", "svc", "dl", "warnings")
    print(hdr)
    print("  " + "-" * 114)
    for r in rows:
        print("  {:<12}{:<8}{:>5}{:>5}{:>4}{:<18}{:>5}{:>7}{:>6}{:>4}{:>5}  {}".format(
            r["scenario_id"][:12], r["category"][:8], len(r["apps"]),
            r["failed_logins"], r["usb"], " " + (";".join(r["risky"]) or "-")[:17],
            len(r["elevated"]), "yes" if r["defoff"] else "no",
            "yes" if r["sched"] else "no", "yes" if r["svc"] else "no",
            "yes" if r["dl"] else "no", "; ".join(r["warnings"]) if r["warnings"] else "-"))
    print("=" * 118)


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    files = ([RAW_LOG_DIR / f"{args[0]}.jsonl"] if args else
             sorted(p for p in RAW_LOG_DIR.glob("*.jsonl") if p.name != UNASSIGNED_PATH.name))
    if not files:
        print(f"No daily logs found in {RAW_LOG_DIR}")
        return

    meta = load_csv_metadata()
    print(f"{'Loaded ' + str(len(meta)) + ' CSV row(s)' if meta else 'No CSV; ground truth blank'}.")

    all_ids, all_unassigned, table_rows, written = {}, [], [], 0
    for path in files:
        if not path.exists():
            print(f"! {path} missing, skipping")
            continue
        day = path.stem
        print(f"\nProcessing {path.name} ...")
        events = load_events(path)
        windows, unassigned = extract_windows(events, day)
        for ev in unassigned:
            ev = dict(ev); ev["_source_day"] = day
            all_unassigned.append(ev)
        for w in windows:
            w["_day"] = day
            sid = w["scenario_id"]
            if sid in all_ids:
                print(f"  ! duplicate {sid} (also {all_ids[sid]}); overwriting.")
            all_ids[sid] = day
            summary, filtered = summarise_window(w)
            warns = apply_csv_metadata(summary, meta)
            warns = check_warnings(summary, warns, filtered)
            if "no meaningful events" in warns:
                print(f"  ! {sid} window has no meaningful events (review).")
            out = SUMMARY_DIR / f"{sid}.json"
            with out.open("w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
            written += 1
            print(f"  -> wrote {out.name}")
            es = summary["event_summary"]
            table_rows.append({
                "scenario_id": sid, "category": summary["category"],
                "apps": es["apps_opened"], "failed_logins": es["failed_logins"],
                "usb": es["usb_connection_count"], "risky": es["risky_processes"],
                "elevated": es["elevated_processes"], "defoff": es["defender_disabled"],
                "sched": es["scheduled_task_change"], "svc": es["service_change"],
                "dl": es["file_downloaded"], "warnings": warns})

    if all_unassigned:
        with UNASSIGNED_PATH.open("w", encoding="utf-8") as f:
            for ev in all_unassigned:
                f.write(json.dumps(ev) + "\n")
        print(f"\n{len(all_unassigned)} out-of-window event(s) -> {UNASSIGNED_PATH.name}")

    print_table(table_rows)
    print(f"\nDone. {written} summaries written to {SUMMARY_DIR}")
    print("Ground truth blank unless loaded from CSV. Review and freeze before models.")


if __name__ == "__main__":
    main()