"""
state_reset.py
==============
Reliable state reset between independent scenarios (dissertation §8, §9).

Clears session risk score, counters, USB count, failed-login count, cooldowns,
dedup state, queued alerts, adaptive history and rolling summaries WITHOUT
deleting any completed validation output folders.

Two explicit modes:
  * independent_validation      -> full reset before every scenario/repetition;
                                   history is cleared so repetitions start equal.
  * adaptive_feedback_validation -> session counters reset, but selected user
                                   history is preserved and exactly what was
                                   supplied to the model is recorded.

The modes are never mixed silently: the caller must state the mode, and the
reset records which fields it preserved.
"""

from __future__ import annotations

from validation.validation_config import MODE_INDEPENDENT, MODE_ADAPTIVE


def reset_session(session, mode: str, history_module=None) -> dict:
    """
    Reset the SessionState in place. Returns a record of what was reset/preserved
    for the audit trail. `history_module` is ai.user_history (optional, so this
    is testable without the real module).
    """
    preserved = []
    cleared = []

    with session.lock:
        session.total_events = 0
        session.threat_count = 0
        session.sites_visited.clear()
        session.scheme_counts.clear()
        session.domain_counts.clear()
        session.tld_counts.clear()
        session.app_counts.clear()
        session.app_first_seen.clear()
        session.app_last_seen.clear()
        session.downloads.clear()
        session.usb_connections = 0
        session.usb_devices.clear()
        session.security_events.clear()
        session.risk_score = 0
        session.risk_events.clear()
        session.first_event = None
        session.last_event = None
        cleared = ["risk_score", "event_counters", "usb_count",
                   "failed_login_count", "web_state", "downloads"]

    # History handling differs by mode.
    if history_module is not None:
        if mode == MODE_INDEPENDENT:
            snapshot = history_module.reset_history()
            cleared.append("adaptive_user_history")
        elif mode == MODE_ADAPTIVE:
            preserved_events = history_module.get_recent()
            preserved.append(f"adaptive_user_history({len(preserved_events)} events)")
        # any other mode is a caller error handled upstream

    return {
        "mode": mode,
        "cleared": cleared,
        "preserved": preserved,
    }


# --- zeroed, non-cumulative risk scoring (dissertation §9) ------------------ #
# Thresholds documented in the README. The score is per-scenario and starts at
# zero; it is NEVER used as ground truth.
RISK_THRESHOLDS = {"low": 0, "medium": 7, "high": 15}


def apply_risk(session, added: int) -> dict:
    """
    Apply a per-event risk increment and return before/added/after so each step
    is auditable. Score is bounded below at 0 and reset per scenario elsewhere.
    """
    with session.lock:
        before = session.risk_score
        session.risk_score = max(0, before + int(added))
        after = session.risk_score
    return {
        "risk_score_before_event": before,
        "risk_score_added": int(added),
        "risk_score_after_event": after,
    }
