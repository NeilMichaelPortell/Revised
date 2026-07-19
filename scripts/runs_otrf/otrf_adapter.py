#!/usr/bin/env python3
"""
otrf_adapter.py
===============

Deterministic adapter that converts OTRF (Open Threat Research Forge)
Security-Datasets Windows host-event captures into the project's NEUTRAL
endpoint-behaviour summary schema.

Design principles (all enforced, all testable offline):
  * Extract ONLY evidence actually present in the source events, and only when
    the specific event ID / channel genuinely supports the conclusion drawn
    (e.g. Defender EventID 5001 supports "real-time protection disabled";
    "any event whose Channel contains the word defender" does NOT support any
    specific conclusion and is therefore no longer treated as evidence).
  * Never invent telemetry. A missing event is NOT positive evidence.
  * Telemetry AVAILABILITY is tracked separately from telemetry OBSERVATION.
    If the source file never contains any event belonging to a given
    channel/event-ID family (e.g. no Windows Defender operational-log events
    at all), the corresponding field is set to the sentinel string
    "not_available" rather than being asserted `false`/`0`. A field is only
    ever `false`/`0` when its channel family WAS present in the source but no
    matching positive event occurred there. This is the project's documented
    equivalent of a null/not-available marker (see otrf_common.ADAPTER_VERSION
    and README section 6).
  * Free text that could leak the answer (command lines, script blocks, dataset
    titles, ATT&CK identifiers, file paths) is NEVER placed in the model input.
    Structured booleans / counts / categoricals are used instead. Full (PII-
    scrubbed) provenance is kept separately, outside the model input.
  * Usernames, hostnames and IP addresses are neutralised.
  * The transformation is deterministic: same input bytes -> same neutral output.
  * Malformed lines, zero-valid-event files and files with zero SUPPORTED
    events (every parsed event falls outside every recognised family) are
    rejected loudly rather than silently producing a misleadingly "quiet"
    neutral input.

Supported source formats (see SUPPORTED_FORMATS):
  * .json / .jsonl  : one JSON event per line (OTRF host log export)
  * .json.gz / .jsonl.gz / .gz : gzip-compressed JSON lines
  * .zip            : a zip archive containing exactly one JSON-lines member

Unsupported formats are rejected explicitly (never silently guessed).
"""

from __future__ import annotations

import gzip
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any

SUPPORTED_FORMATS = [".json", ".jsonl", ".json.gz", ".jsonl.gz", ".gz", ".zip"]

# Offensive / monitored process basenames treated as risky-process evidence.
# These are genuine endpoint telemetry (process image names), consistent with
# how the primary 120-scenario inputs represent risky processes. They are NOT
# OTRF labels or ATT&CK identifiers.
RISKY_PROCESS_BASENAMES = {
    "mimikatz.exe", "nmap.exe", "psexec.exe", "psexec64.exe", "procdump.exe",
    "procdump64.exe", "wce.exe", "pwdump.exe", "lazagne.exe", "rubeus.exe",
    "sharphound.exe", "bloodhound.exe", "cobaltstrike.exe", "ntdsutil.exe",
    "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "certutil.exe",
}
# Command-line interpreters recorded as command_activity context (NOT auto-risky).
COMMAND_INTERPRETERS = {
    "powershell.exe": "powershell", "pwsh.exe": "powershell",
    "cmd.exe": "cmd", "wscript.exe": "script_host", "cscript.exe": "script_host",
    "mshta.exe": "script_host", "rundll32.exe": "rundll32", "regsvr32.exe": "regsvr32",
}

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Format detection + parsing                                                   #
# --------------------------------------------------------------------------- #
def detect_format(path: Path) -> str:
    name = path.name.lower()
    for suffix in (".jsonl.gz", ".json.gz"):
        if name.endswith(suffix):
            return suffix
    if name.endswith(".zip"):
        return ".zip"
    if name.endswith(".gz"):
        return ".gz"
    if name.endswith(".jsonl"):
        return ".jsonl"
    if name.endswith(".json"):
        return ".json"
    return "unsupported"


class UnsupportedFormatError(ValueError):
    """Raised for a file extension outside SUPPORTED_FORMATS."""


class EmptyDatasetError(ValueError):
    """Raised when a source file yields zero parseable (valid JSON) events,
    including files that are completely invalid JSON/JSONL."""


class UnsupportedTelemetryError(ValueError):
    """Raised when every parsed event in the selected window falls outside
    every event-ID/channel family this adapter recognises (zero SUPPORTED
    events). Distinct from EmptyDatasetError: the file parsed fine, but it
    carries no telemetry this adapter can turn into evidence."""


def _iter_json_lines(text: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Parse JSON-lines text (also tolerates a single top-level JSON array).

    Returns (events, parse_stats). parse_stats always contains:
      total_lines      - non-blank lines considered (or 1 for a whole-file array)
      blank_lines       - blank lines skipped
      malformed_lines   - lines/elements that failed to parse as a JSON object

    A malformed line is recorded, not silently dropped: callers use these
    counts to reject empty/near-empty/fully-malformed datasets explicitly
    rather than treating them as legitimately quiet telemetry.
    """
    text = text.strip()
    stats = {"total_lines": 0, "blank_lines": 0, "malformed_lines": 0}
    if not text:
        return [], stats
    if text[0] == "[":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            stats["total_lines"] = 1
            stats["malformed_lines"] = 1
            return [], stats
        if isinstance(data, list):
            events = [e for e in data if isinstance(e, dict)]
            stats["total_lines"] = len(data) if data else 1
            stats["malformed_lines"] = len(data) - len(events)
            return events, stats
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            stats["blank_lines"] += 1
            continue
        stats["total_lines"] += 1
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            stats["malformed_lines"] += 1
            continue
        if isinstance(obj, dict):
            events.append(obj)
        else:
            stats["malformed_lines"] += 1
    return events, stats


def parse_source_events(path: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Load raw Windows events from a supported OTRF export. Raises
    UnsupportedFormatError for anything not in SUPPORTED_FORMATS. Returns
    (events, parse_stats); does NOT raise on zero events -- callers decide
    (adapt_source_file raises EmptyDatasetError so the reason is explicit)."""
    fmt = detect_format(path)
    if fmt == "unsupported":
        raise UnsupportedFormatError(
            f"Unsupported source format for '{path.name}'. "
            f"Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    if fmt in (".json", ".jsonl"):
        return _iter_json_lines(path.read_text(encoding="utf-8", errors="replace"))
    if fmt in (".json.gz", ".jsonl.gz", ".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            return _iter_json_lines(fh.read())
    if fmt == ".zip":
        with zipfile.ZipFile(path) as zf:
            # Exclude macOS AppleDouble resource-fork junk entries
            # (__MACOSX/._name.json), which some published archives carry
            # alongside the real member and which are never real telemetry
            # (their basename always starts with "._"). This is a real-data
            # gap, not a hypothetical: at least one genuine OTRF Security-
            # Datasets zip ships exactly this junk entry, which previously
            # made a perfectly good single-member archive look like it had
            # two members and get rejected.
            members = [m for m in zf.namelist()
                       if m.lower().endswith((".json", ".jsonl"))
                       and not m.endswith("/")
                       and not m.startswith("__MACOSX/")
                       and not m.rsplit("/", 1)[-1].startswith("._")]
            if len(members) != 1:
                raise UnsupportedFormatError(
                    f"Zip '{path.name}' must contain exactly one .json/.jsonl member "
                    f"(excluding __MACOSX/ resource-fork entries); found {len(members)}."
                )
            with zf.open(members[0]) as fh:
                raw = io.TextIOWrapper(fh, encoding="utf-8", errors="replace").read()
            return _iter_json_lines(raw)
    raise UnsupportedFormatError(f"Unhandled format '{fmt}'.")


# --------------------------------------------------------------------------- #
# Field access helpers (OTRF host logs vary in field naming)                   #
# --------------------------------------------------------------------------- #
def _get(ev: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in ev and ev[k] not in (None, ""):
            return ev[k]
    return None


def _event_id(ev: dict[str, Any]) -> int | None:
    v = _get(ev, "EventID", "event_id", "EventId", "Id")
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _timestamp(ev: dict[str, Any]) -> str | None:
    return _get(ev, "@timestamp", "TimeCreated", "EventTime", "UtcTime", "timestamp")


def _channel(ev: dict[str, Any]) -> str:
    return str(_get(ev, "Channel", "channel", "SourceName", "Provider") or "").lower()


def _basename(image: Any) -> str:
    if not image:
        return ""
    return re.split(r"[\\/]", str(image))[-1].strip().lower()


# --------------------------------------------------------------------------- #
# Deterministic time-window selection                                          #
# --------------------------------------------------------------------------- #
def select_window(events: list[dict[str, Any]], max_events: int) -> dict[str, Any]:
    """Deterministically order events and cap to max_events.

    Ordering key: (timestamp string, original index). Timestamps are compared as
    strings; OTRF host logs use ISO-8601 UTC which sorts correctly lexically.
    Events with no timestamp keep file order after timestamped ones. The window
    is the earliest max_events after ordering."""
    indexed = list(enumerate(events))
    indexed.sort(key=lambda t: (_timestamp(t[1]) or "~", t[0]))
    ordered = [ev for _, ev in indexed]
    windowed = ordered[:max_events] if max_events and max_events > 0 else ordered
    ts = [t for t in (_timestamp(e) for e in windowed) if t]
    return {
        "events": windowed,
        "window_start_utc": min(ts) if ts else "not_available",
        "window_end_utc": max(ts) if ts else "not_available",
        "event_count_total": len(events),
        "event_count_window": len(windowed),
    }


# --------------------------------------------------------------------------- #
# Leakage scrubbing (for provenance only; never used in model input)           #
# --------------------------------------------------------------------------- #
def scrub_text(text: Any) -> str:
    s = str(text or "")
    s = _URL_RE.sub("<url>", s)
    s = _IP_RE.sub("<ip>", s)
    return s.strip()


# --------------------------------------------------------------------------- #
# Telemetry-channel-family availability (drives not_available gating)          #
# --------------------------------------------------------------------------- #
# A "family" is present if we saw ANY event that plausibly belongs to that
# telemetry channel, regardless of whether that specific event triggered a
# positive evidence flag. Availability is assessed over the FULL parsed event
# set for the file (not the capped window), because the window only limits
# volume for evidence extraction; whether a channel was captured at all is a
# property of the source file, not of the window.
def _detect_channel_families(events: list[dict[str, Any]]) -> dict[str, bool]:
    fam = {
        "security_channel": False, "sysmon_channel": False,
        "powershell_channel": False, "defender_channel": False,
        "firewall_channel": False, "taskscheduler_channel": False,
        "usb_channel": False, "system_channel": False,
    }
    for ev in events:
        chan = _channel(ev)
        eid = _event_id(ev)
        if chan == "security" or eid in (4624, 4625, 4688, 4698, 4699, 4700,
                                          4701, 4702, 4697, 6416, 4657):
            fam["security_channel"] = True
        if "sysmon" in chan:
            fam["sysmon_channel"] = True
        if "powershell" in chan or eid in (4103, 4104):
            fam["powershell_channel"] = True
        if "defender" in chan:
            fam["defender_channel"] = True
        if "firewall" in chan:
            fam["firewall_channel"] = True
        if "taskscheduler" in chan:
            fam["taskscheduler_channel"] = True
        if "driverframeworks" in chan or "usb" in chan:
            fam["usb_channel"] = True
        if chan == "system" or eid in (7045, 7040):
            fam["system_channel"] = True
    return fam


def _availability_map(fam: dict[str, bool]) -> dict[str, bool]:
    """One availability flag per evidence category used by build_neutral_input.
    True means the relevant channel/event family was present in the SOURCE FILE
    (so a false/0 evidence value is a genuine negative observation); False means
    the dataset never carried that telemetry at all (so the field must be the
    'not_available' sentinel rather than an asserted false/0)."""
    return {
        "authentication": fam["security_channel"],
        "process_execution": fam["sysmon_channel"] or fam["security_channel"],
        "script_execution": fam["powershell_channel"] or fam["sysmon_channel"],
        "defender": fam["defender_channel"],
        "firewall": fam["firewall_channel"],
        "scheduled_task": fam["security_channel"] or fam["taskscheduler_channel"],
        "service": fam["security_channel"] or fam["system_channel"],
        "startup_persistence": fam["sysmon_channel"] or fam["security_channel"],
        "file_download": fam["sysmon_channel"],
        "usb": fam["usb_channel"] or fam["security_channel"],
    }


# --------------------------------------------------------------------------- #
# Deterministic evidence extraction                                            #
# --------------------------------------------------------------------------- #
def extract_evidence(window_events: list[dict[str, Any]],
                      full_events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Scan the WINDOWED events and derive structured endpoint evidence.
    Availability of each telemetry family is assessed from full_events (the
    complete parsed event set before the window cap); if full_events is not
    given, window_events is used for availability too (test convenience).

    Positive booleans/counts are set ONLY on direct observation within the
    window. Fields whose channel family never appeared anywhere in the source
    are the sentinel string "not_available", never false/0 (see module
    docstring). Mappings only trigger on specific, well-attested event IDs; no
    catch-all "any event in a channel whose name contains X" matching remains,
    because that inferred behaviour the actual event did not support.
    """
    availability = _availability_map(_detect_channel_families(
        full_events if full_events is not None else window_events))

    failed_logins = 0
    successful_login = False
    usb_count = 0
    risky_processes: list[str] = []
    command_activity = "none"
    script_execution = False
    defender_disabled = False
    defender_config_changed = False
    malware_detected = False
    firewall_changed = False
    scheduled_task_change = False
    service_change = False
    startup_item_change = False
    file_downloaded = False
    lsass_access_detected = False

    process_images: list[str] = []
    provenance: list[dict[str, Any]] = []
    unmapped_event_ids: dict[str, int] = {}

    def note(kind: str, ev: dict[str, Any], detail: str = "") -> None:
        provenance.append({
            "evidence": kind,
            "event_id": _event_id(ev),
            "channel": _channel(ev),
            "detail": scrub_text(detail)[:300],
        })

    for ev in window_events:
        eid = _event_id(ev)
        chan = _channel(ev)

        # ---- authentication ----
        if eid == 4625:
            failed_logins += 1
            note("failed_login", ev)
            continue
        if eid == 4624:
            successful_login = True
            note("successful_login", ev)
            continue

        # ---- process execution (Sysmon 1 / Security 4688) ----
        if eid == 4688 or (eid == 1 and "sysmon" in chan):
            image = _get(ev, "Image", "NewProcessName", "ProcessName")
            base = _basename(image)
            if base:
                process_images.append(base)
                if base in RISKY_PROCESS_BASENAMES and base not in risky_processes:
                    risky_processes.append(base)
                    note("risky_process", ev, base)
                elif base in COMMAND_INTERPRETERS:
                    command_activity = COMMAND_INTERPRETERS[base]
                    note("command_activity", ev, base)
            continue

        # ---- process access targeting LSASS (Sysmon 10 ProcessAccess).
        # ProcessAccess fires for many benign target processes; the field that
        # actually supports a credential-access conclusion is TargetImage ==
        # lsass.exe specifically (the classic Mimikatz/procdump/comsvcs.dll
        # LSASS-dumping indicator), not the mere occurrence of a Sysmon 10
        # event. GrantedAccess is not evaluated (kept conservative: this flags
        # that LSASS was targeted, not that access succeeded maliciously). ----
        if eid == 10 and "sysmon" in chan:
            target = _basename(_get(ev, "TargetImage"))
            if target == "lsass.exe":
                lsass_access_detected = True
                note("lsass_access_detected", ev, target)
            continue

        # ---- PowerShell content-execution evidence. EventID 4103 =
        # "Executing Pipeline" (module logging), 4104 = "Creating Scriptblock
        # text" (script block logging) -- both from the modern
        # Microsoft-Windows-PowerShell/Operational channel. EventID 800 =
        # "Pipeline execution details" from the CLASSIC "Windows PowerShell"
        # log -- the legacy log's equivalent execution-content event, so it is
        # gated to a channel containing "powershell" (the numeric ID alone is
        # too generic to trust from an arbitrary provider). All three are
        # genuine execution-content events. Session lifecycle events (e.g. 400
        # engine started, 403 engine stopped) are deliberately NOT matched:
        # they occur whenever PowerShell starts at all and do not, by
        # themselves, support "a script executed". A bare "powershell in
        # channel name" catch-all is likewise deliberately not used. ----
        if eid in (4103, 4104) or (eid == 800 and "powershell" in chan):
            script_execution = True
            command_activity = "powershell" if command_activity == "none" else command_activity
            note("script_execution", ev)
            continue

        # ---- scheduled tasks (Security 4698-4702 / TaskScheduler operational
        # 106 registered, 140 updated, 141 deleted) ----
        if eid in (4698, 4699, 4700, 4701, 4702) or ("taskscheduler" in chan and eid in (106, 140, 141)):
            scheduled_task_change = True
            note("scheduled_task_change", ev)
            continue

        # ---- services (Security 4697 service installed, System 7045 service
        # installed, 7040 start-type changed) ----
        if eid in (4697, 7045, 7040):
            service_change = True
            note("service_change", ev)
            continue

        # ---- Windows Defender: only specific, well-attested event IDs.
        # 5001/5010/5012 = real-time/spyware/virus-scanning protection
        # disabled. 5007 = Defender configuration changed. 1116 = malware
        # detected, 1117 = action taken on malware -- these are DETECTION
        # events, not configuration changes, and are recorded as their own
        # 'malware_detected' evidence rather than folded into
        # defender_config_changed. A bare "defender in channel name"
        # catch-all (which would also match routine signature-update / scan-
        # completed events) is deliberately NOT used. ----
        if eid in (5001, 5010, 5012):
            defender_disabled = True
            note("defender_disabled", ev)
            continue
        if eid == 5007:
            defender_config_changed = True
            note("defender_config_changed", ev)
            continue
        if eid in (1116, 1117):
            malware_detected = True
            note("malware_detected", ev)
            continue

        # ---- firewall: only specific rule/settings-change event IDs.
        # 2003 settings changed, 2004 rule added, 2005 rule changed,
        # 2006 rule deleted. A bare "firewall in channel name" catch-all
        # (which would also match connection-block/allow log events that are
        # not configuration changes) is deliberately NOT used. ----
        if eid in (2003, 2004, 2005, 2006):
            firewall_changed = True
            note("firewall_changed", ev)
            continue

        # ---- registry / startup persistence (Sysmon 12/13/14, Security 4657) ----
        if eid in (12, 13, 14, 4657):
            target = str(_get(ev, "TargetObject", "ObjectName") or "").lower()
            if "\\run" in target or "currentversion\\run" in target or "startup" in target:
                startup_item_change = True
                note("startup_item_change", ev, target)
            continue

        # ---- downloads (Sysmon 15 FileCreateStreamHash - Zone.Identifier) ----
        if eid == 15:
            file_downloaded = True
            note("file_downloaded", ev)
            continue

        # ---- USB / removable media: only the well-attested Security 6416
        # "a new external device was recognized" event. The previous
        # "any DriverFrameworks-UserMode event" catch-all is removed: that
        # channel logs many unrelated device events and its mere presence did
        # not support a USB-connection conclusion. ----
        if eid == 6416:
            usb_count += 1
            note("usb_connection", ev)
            continue

        # ---- record unmapped IDs (honest: pipeline saw them, no representation) ----
        key = f"{chan or 'unknown'}:{eid if eid is not None else 'none'}"
        unmapped_event_ids[key] = unmapped_event_ids.get(key, 0) + 1

    def band(n: int) -> str:
        if n == 0:
            return "none"
        if n <= 2:
            return "low"
        if n <= 9:
            return "medium"
        return "high"

    def gate_bool(value: bool, key: str) -> Any:
        return value if availability[key] else "not_available"

    def gate_int(value: int, key: str) -> Any:
        return value if availability[key] else "not_available"

    evidence = {
        "failed_logins": gate_int(failed_logins, "authentication"),
        "failed_login_activity": gate_bool(failed_logins > 0, "authentication"),
        "failed_login_count_band": (band(failed_logins) if availability["authentication"]
                                     else "not_available"),
        "successful_login": gate_bool(successful_login, "authentication"),
        "usb_connection_count": gate_int(usb_count, "usb"),
        "risky_processes": sorted(set(risky_processes)),
        "command_activity": (command_activity
                              if (availability["process_execution"] or availability["script_execution"])
                              else "not_available"),
        "script_execution": gate_bool(script_execution, "script_execution"),
        "lsass_access_detected": gate_bool(lsass_access_detected, "process_execution"),
        "defender_disabled": gate_bool(defender_disabled, "defender"),
        "defender_config_changed": gate_bool(defender_config_changed, "defender"),
        "malware_detected": gate_bool(malware_detected, "defender"),
        "firewall_changed": gate_bool(firewall_changed, "firewall"),
        "scheduled_task_change": gate_bool(scheduled_task_change, "scheduled_task"),
        "service_change": gate_bool(service_change, "service"),
        "startup_item_change": gate_bool(startup_item_change, "startup_persistence"),
        "file_downloaded": gate_bool(file_downloaded, "file_download"),
        "_provenance": provenance,
        "_process_images_observed": sorted(set(process_images)),
        "_unmapped_event_ids": unmapped_event_ids,
        "_telemetry_availability": availability,
    }
    return evidence


# --------------------------------------------------------------------------- #
# Neutral model-input construction (leakage-safe)                              #
# --------------------------------------------------------------------------- #
def build_neutral_input(evidence: dict[str, Any]) -> dict[str, Any]:
    """Assemble a leakage-safe neutral endpoint summary in the project's schema
    shape. Context fields that OTRF host logs do not provide are represented as
    'not_available' / omitted rather than asserted. No raw commands, script
    contents, identifiers, or network addresses are included.

    Lists such as verified_commands / download_details / process_details are kept
    EMPTY in the model input by design (their contents could leak the technique);
    the corresponding boolean/categorical summary fields carry the evidence.

    A top-level 'telemetry_availability' block records, honestly, which
    channel families were present in the source file at all (see
    otrf_adapter.extract_evidence). It is retrieval- and leakage-safe: it
    contains only channel-family booleans, no identifiers."""
    command_activity = evidence["command_activity"]
    context_state = {
        # OTRF host captures do not reliably record ambient config; do not assert.
        "collector_is_admin": "not_available",
        "defender": {
            "realtime_protection_enabled": (False if evidence["defender_disabled"] is True
                                             else "not_available"),
        },
        "network_profile": "not_available",
        "removable_drives": [],
        "running_monitored_processes": [],
    }
    event_summary = {
        "failed_logins": evidence["failed_logins"],
        "failed_login_activity": evidence["failed_login_activity"],
        "failed_login_count_band": evidence["failed_login_count_band"],
        "defender_disabled": evidence["defender_disabled"],
        "defender_config_changed": evidence["defender_config_changed"],
        "malware_detected": evidence["malware_detected"],
        "defender_events": [],
        "firewall_changed": evidence["firewall_changed"],
        "firewall_events": [],
        "usb_connection_count": evidence["usb_connection_count"],
        "removable_drive_details": [],
        "risky_processes": evidence["risky_processes"],
        "process_details": [],
        "scheduled_task_change": evidence["scheduled_task_change"],
        "scheduled_task_details": [],
        "service_change": evidence["service_change"],
        "service_change_details": [],
        "startup_item_change": evidence["startup_item_change"],
        "startup_item_details": [],
        "file_downloaded": evidence["file_downloaded"],
        "download_details": [],
        "network_profile": "not_available",
        "web_domains": [],
        "verified_activity_context": {
            "command_activity": command_activity,
            "script_execution": evidence["script_execution"],
            "successful_login": evidence["successful_login"],
            "lsass_access_detected": evidence["lsass_access_detected"],
            "verified_commands": [],
        },
    }
    return {
        "context_state": context_state,
        "event_summary": event_summary,
        "telemetry_availability": dict(evidence["_telemetry_availability"]),
    }


LEAK_KEYS = {
    "hostname", "computer", "computername", "subjectusername", "targetusername",
    "accountname", "user", "username", "commandline", "processcommandline",
    "scriptblocktext", "image", "parentimage", "targetimage", "servicefilename",
    "taskname", "targetobject", "message", "destinationip", "sourceip", "url",
}


def assert_no_leakage(neutral_input: dict[str, Any]) -> list[str]:
    """Return a list of leakage violations found in a neutral model input.
    Empty list == clean. Used by the preparer and by tests."""
    violations: list[str] = []
    blob = json.dumps(neutral_input, ensure_ascii=False)

    def walk(obj: Any, path: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in LEAK_KEYS and v not in ([], "", "none", "not_available", False):
                    violations.append(f"{path}.{k}")
                walk(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")

    walk(neutral_input)
    if _IP_RE.search(blob):
        violations.append("ip_address_present")
    if _URL_RE.search(blob):
        violations.append("url_present")
    return violations


def adapt_source_file(path: Path, max_events: int) -> dict[str, Any]:
    """Full deterministic pipeline for one source file:
    parse -> reject empty/unsupported-telemetry -> window -> extract -> build
    neutral input. Returns everything the preparer needs (neutral input +
    provenance + window metadata + parser/telemetry accounting).

    Raises EmptyDatasetError if the file yields zero valid events (including
    completely malformed JSON/JSONL), and UnsupportedTelemetryError if every
    parsed event in the selected window falls outside every recognised
    event-ID/channel family (zero SUPPORTED events). Both are caught by the
    preparer and recorded as an explicit skip reason -- never silently turned
    into a quiet, all-'normal'-looking neutral input."""
    events, parse_stats = parse_source_events(path)
    if not events:
        raise EmptyDatasetError(
            f"'{path.name}' produced zero valid events "
            f"(total_lines={parse_stats['total_lines']}, "
            f"malformed_lines={parse_stats['malformed_lines']})."
        )
    window = select_window(events, max_events)
    evidence = extract_evidence(window["events"], events)
    ignored_event_count = sum(evidence["_unmapped_event_ids"].values())
    supported_event_count = window["event_count_window"] - ignored_event_count
    if supported_event_count <= 0:
        raise UnsupportedTelemetryError(
            f"'{path.name}' has {window['event_count_window']} parsed events in "
            f"the selected window but none map to a supported evidence family."
        )
    neutral_input = build_neutral_input(evidence)
    return {
        "neutral_input": neutral_input,
        "provenance": evidence["_provenance"],
        "process_images_observed": evidence["_process_images_observed"],
        "unmapped_event_ids": evidence["_unmapped_event_ids"],
        "window_start_utc": window["window_start_utc"],
        "window_end_utc": window["window_end_utc"],
        "event_count_total": window["event_count_total"],
        "event_count_window": window["event_count_window"],
        "parsed_line_total": parse_stats["total_lines"],
        "malformed_line_count": parse_stats["malformed_lines"],
        "supported_event_count": supported_event_count,
        "ignored_event_count": ignored_event_count,
        "telemetry_availability": evidence["_telemetry_availability"],
    }
