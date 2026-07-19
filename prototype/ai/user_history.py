"""
User Risk History
─────────────────
Persists the user's past risky actions to disk so that the LLM can give
adaptive, personalised feedback even after restarts.

Storage: outputs/user_history.json
Schema:
{
  "events": [
    {
      "ts":          "2026-03-17T09:32:00",
      "threat_type": "torrent_download",
      "severity":    "high",
      "summary":     "Downloaded 611496bad.torrent",
      "repeat":      false
    },
    ...
  ]
}

Only the last MAX_HISTORY events are kept to bound file growth.
"""

import json
import os
import datetime
import threading
from collections import Counter

from config import BASE_DIR

HISTORY_FILE = os.path.join(BASE_DIR, "outputs", "user_history.json")
MAX_HISTORY  = 100   # cap stored events
RECENT_N     = 10    # how many recent events to include in prompts


_lock = threading.Lock()


# ─── Internal helpers ────────────────────────────────────────────────────────

def _load() -> list:
    """Load history list from disk; return [] on any error."""
    try:
        if not os.path.exists(HISTORY_FILE):
            return []
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("events", [])
    except Exception:
        return []


def _save(events: list) -> None:
    """Write history list to disk, keeping only the last MAX_HISTORY entries."""
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump({"events": events[-MAX_HISTORY:]}, f, indent=2)


# ─── Public API ──────────────────────────────────────────────────────────────

def record(threat_type: str, severity: str, summary: str) -> None:
    """
    Append one threat event to the persistent history.
    Called by EventPipeline after a threat is confirmed.
    """
    with _lock:
        events = _load()

        # Flag if this threat type has been seen before (makes prompt adaptive)
        seen_before = any(e["threat_type"] == threat_type for e in events)

        events.append({
            "ts":          datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "threat_type": threat_type,
            "severity":    severity,
            "summary":     summary,
            "repeat":      seen_before,
        })

        _save(events)


def get_recent(n: int = RECENT_N) -> list:
    """Return the last n history entries (newest first)."""
    with _lock:
        events = _load()
    return list(reversed(events[-n:]))


def reset_history() -> dict:
    """
    Clear the persistent adaptive history (used by independent_validation mode
    so every repetition starts from an equivalent state). Returns a small record
    of what was cleared for the audit trail. Does NOT delete validation output.
    """
    with _lock:
        events = _load()
        count = len(events)
        _save([])
    return {"cleared_adaptive_history_events": count}


def get_repeat_offenses() -> dict:
    """
    Return a dict of threat_type → count for types that have occurred more
    than once.  Used to tailor the 'Learning tip' in the prompt.
    """
    with _lock:
        events = _load()
    counts = Counter(e["threat_type"] for e in events)
    return {t: c for t, c in counts.items() if c > 1}


def format_history_for_prompt() -> str:
    """
    Return a compact history block for inclusion in the LLM prompt.
    Limited to RECENT_N events to keep the prompt short for small models.
    """
    recent = get_recent(RECENT_N)
    repeats = get_repeat_offenses()

    if not recent:
        return "No previous risky events recorded for this user."

    lines = []
    for e in recent:
        repeat_tag = " [REPEATED BEHAVIOUR]" if e.get("repeat") else ""
        lines.append(
            f"  [{e['ts']}] {e['severity'].upper()} — "
            f"{e['threat_type'].replace('_', ' ')}: {e['summary']}{repeat_tag}"
        )

    history_block = "\n".join(lines)

    # Add a pattern summary if repeated offences exist
    if repeats:
        pattern_lines = ", ".join(
            f"{t.replace('_', ' ')} ({c}x)" for t, c in repeats.items()
        )
        history_block += f"\n\n  Recurring patterns: {pattern_lines}"

    return history_block
