import os
from config import TRUSTED_DOMAINS, RISKY_EXTENSIONS, SUSPICIOUS_KEYWORDS, KNOWN_SAFE_PROCESSES


# Maps each threat "type" this detector can raise onto ONE of the seven revised
# endpoint behaviour categories used throughout the dissertation:
#   NORMAL, AUTH, USB, SEC, PROC, NET, PERSIST
# This keeps the real-time feedback prototype, the alert log, and the offline
# evaluation dataset using a single shared vocabulary. The category is used for
# labelling and display only; it does NOT feed the offline metrics (those come
# from the controlled runner against frozen ground truth).
THREAT_CATEGORY = {
    "http_browsing"          : "NET",
    "public_network"         : "NET",
    "unknown_source_download": "PROC",
    "risky_download"         : "PROC",
    "torrent_download"       : "PROC",
    "suspicious_process"     : "PROC",
    "usb_connected"          : "USB",
    "login_failed"           : "AUTH",
    "defender_disabled"      : "SEC",
    "defender_definitions_stale": "SEC",
    "security_log_cleared"   : "SEC",
    "audit_policy_changed"   : "SEC",
    "scheduled_task_created" : "PERSIST",
    "scheduled_task_updated" : "PERSIST",
    "service_start_changed"  : "PERSIST",
}


def _tag_category(threat: dict | None) -> dict | None:
    """Stamp the seven-category label onto a threat dict (or pass None through)."""
    if threat is not None:
        threat["category"] = THREAT_CATEGORY.get(threat.get("type", ""), "NORMAL")
    return threat


def evaluate_threat(event_type: str, data: dict, session=None) -> dict | None:
    """
    Inspect one event. Return a threat dict with rich context, or None.

    'context' is passed verbatim into the AI prompt — the more specific
    the values, the more specific the AI explanation will be.

    Every returned threat carries a 'category' field (one of the seven revised
    categories) via _tag_category, so downstream feedback and logging stay
    consistent with the dissertation dataset vocabulary.
    """
    return _tag_category(_evaluate_threat(event_type, data, session))


def _evaluate_threat(event_type: str, data: dict, session=None) -> dict | None:

    # ── Website visited ───────────────────────────────────────
    if event_type == "website_visited":
        scheme = data.get("scheme", "https")
        domain = data.get("domain", "unknown")

        # Always log to session — but only alert on HTTP
        if scheme == "http":
            http_count = (session.http_visit_count() if session else 1)
            return {
                "type"    : "http_browsing",
                "severity": "low",
                "summary" : f"You just visited {domain} using an unencrypted connection.",
                "context" : {
                    "website_you_visited"     : domain,
                    "connection_type"         : "HTTP — unencrypted (not secure)",
                    "http_visits_this_session": http_count,
                    "what_this_means"         : "Anyone on the same network can see your activity on this site",
                },
            }
        # HTTPS — not a threat, return None (session still records it)
        return None

    # ── File downloaded ───────────────────────────────────────
    elif event_type == "file_downloaded":
        fname   = (data.get("filename") or data.get("file_name") or
                   data.get("url", "")).lower()
        ext     = os.path.splitext(fname)[1]
        base    = os.path.basename(fname) or fname
        domain  = data.get("source_domain", "") or _domain(data.get("url", ""))
        trusted = any(t in domain for t in TRUSTED_DOMAINS)

        if ".torrent" in fname:
            return {
                "type"    : "torrent_download",
                "severity": "high",
                "summary" : f"You downloaded a torrent file: {base}",
                "context" : {
                    "file_you_downloaded": base,
                    "file_type"          : ".torrent",
                    "downloaded_from"    : domain or "unknown website",
                    "why_flagged"        : "Torrents are used to share pirated content and often bundle malware",
                },
            }

        if ext in RISKY_EXTENSIONS:
            return {
                "type"    : "risky_download",
                "severity": "low" if trusted else "high",
                "summary" : f"You downloaded {base} ({ext}) from {domain or 'an unknown site'}",
                "context" : {
                    "file_you_downloaded": base,
                    "file_type"          : ext,
                    "downloaded_from"    : domain or "unknown website",
                    "source_trusted"     : "yes — known safe publisher" if trusted else "no — unfamiliar website",
                    "why_flagged"        : f"{ext} files can run code on your computer when opened",
                },
            }

        if domain and not trusted:
            return {
                "type"    : "unknown_source_download",
                "severity": "medium",
                "summary" : f"You downloaded a file from an unfamiliar website: {domain}",
                "context" : {
                    "file_you_downloaded": base,
                    "downloaded_from"    : domain,
                    "why_flagged"        : "This website is not in the list of trusted publishers",
                },
            }

    # ── Application / process started ─────────────────────────
    elif event_type in ("application_started", "process_started"):
        name  = (data.get("process_name") or "").lower()
        exe   = (data.get("exe") or "").lower()
        if name in KNOWN_SAFE_PROCESSES:
            return None
        match = next(
            (kw for kw in SUSPICIOUS_KEYWORDS if kw in name or kw in exe), None
        )
        if match:
            return {
                "type"    : "suspicious_process",
                "severity": "high",
                "summary" : f"A suspicious program started on your computer: {data.get('process_name')}",
                "context" : {
                    "program_that_started": data.get("process_name"),
                    "full_path"           : data.get("exe", "unknown"),
                    "matched_keyword"     : match,
                    "why_flagged"         : f"The name contains '{match}' which is associated with hacking tools or malware",
                },
            }

    # ── USB ───────────────────────────────────────────────────
    elif event_type == "usb_connected":
        device_name = data.get("device_name", data.get("device", "unknown device"))
        # session.record_event() already incremented usb_connections for THIS
        # event before evaluate_threat() runs, so the current value is the true
        # observed count. The previous "+ 1" here double-counted (see §11).
        usb_count   = (session.usb_connections if session else 1)
        return {
            "type"    : "usb_connected",
            "severity": "medium",
            "summary" : f"A USB device was just plugged in: {device_name}",
            "context" : {
                "device_name"           : device_name,
                "device_id"             : data.get("device_id", ""),
                "usb_plugged_in_today"  : usb_count,
                "why_flagged"           : "USB devices can introduce malware or be used to steal files",
            },
        }

    # ── Security monitor ──────────────────────────────────────
    elif event_type == "defender_disabled":
        return {
            "type"    : "defender_disabled",
            "severity": "critical",
            "summary" : "Windows Defender real-time protection was just turned off",
            "context" : {
                "what_was_disabled" : "Windows Defender real-time protection",
                "why_this_is_serious": "Your computer is now unprotected from viruses and malware",
                "message"           : data.get("message", ""),
            },
        }

    elif event_type == "defender_definitions_stale":
        return {
            "type"    : "defender_definitions_stale",
            "severity": "medium",
            "summary" : "Windows Defender virus definitions are out of date (3+ days)",
            "context" : {
                "what_is_outdated" : "Virus definition database",
                "why_this_matters" : "Defender cannot detect threats discovered in the last few days",
            },
        }

    # ── Event log events ──────────────────────────────────────
    elif event_type == "login_failed":
        return {
            "type"    : "login_failed",
            "severity": "medium",
            "summary" : "Someone just failed to log into this computer",
            "context" : {
                "event_id"      : data.get("event_id"),
                "log"           : data.get("log", "Security"),
                "what_happened" : "A Windows login attempt was rejected — wrong password or unknown user",
            },
        }

    elif event_type == "security_log_cleared":
        return {
            "type"    : "security_log_cleared",
            "severity": "high",
            "summary" : "The Windows Security event log was just cleared",
            "context" : {
                "event_id"   : data.get("event_id"),
                "why_serious": "Attackers clear the security log to hide their activity — this is a major red flag",
            },
        }

    elif event_type == "audit_policy_changed":
        return {
            "type"    : "audit_policy_changed",
            "severity": "high",
            "summary" : "Windows audit policy was changed — controls what gets recorded",
            "context" : {
                "event_id"   : data.get("event_id"),
                "why_serious": "Changing audit policy can make malicious activity invisible in the logs",
            },
        }

    elif event_type in ("scheduled_task_created", "scheduled_task_updated"):
        action = "created" if "created" in event_type else "modified"
        return {
            "type"    : event_type,
            "severity": "high",
            "summary" : f"A scheduled task was {action} on your computer",
            "context" : {
                "event_id"   : data.get("event_id"),
                "what_it_is" : "A scheduled task runs programs automatically at set times",
                "why_flagged": "Malware commonly creates scheduled tasks to persist after reboot",
            },
        }

    elif event_type == "service_start_changed":
        return {
            "type"    : "service_start_changed",
            "severity": "high",
            "summary" : "A Windows service start type was changed",
            "context" : {
                "event_id"   : data.get("event_id"),
                "why_flagged": "Attackers disable security services by changing their startup type to 'disabled'",
            },
        }

    # ── Network ───────────────────────────────────────────────
    elif event_type == "network_profile_changed":
        profile = data.get("profile", "").lower()
        if "public" in profile:
            return {
                "type"    : "public_network",
                "severity": "medium",
                "summary" : f"Your computer just connected to a Public network",
                "context" : {
                    "network_type"   : data.get("profile"),
                    "what_this_means": "Public networks treat you like a stranger — other people on this network can attempt to access your computer",
                    "common_places"  : "Coffee shops, airports, hotels, shopping centres",
                },
            }

    return None


def _domain(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""
