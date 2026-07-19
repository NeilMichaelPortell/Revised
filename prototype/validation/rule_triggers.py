"""
rule_triggers.py
================
Defensible rule-based trigger layer for the validation study (dissertation §10).

This layer decides (a) whether an event should raise an alert and (b) the rule's
PROVISIONAL severity. It is deliberately conservative and evidence-combining.

It is kept STRICTLY SEPARATE from the LLM classification. The rule severity is
NOT ground truth; it is the trigger the prototype uses to decide whether to ask
the LLM for user-facing feedback, and it is recorded verbatim for audit.

Design principles (from the brief):
  * A single failed login is not automatically medium.
  * One USB connection is not automatically abnormal.
  * A public network alone is not abnormal.
  * Opening PowerShell/CMD is not automatically suspicious.
  * Viewing a security/persistence UI is not the same as changing it.
  * Severity escalates only when evidence COMBINES.

Each decision records the exact rule id that fired, so alerts are auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScenarioEvidence:
    """
    Lightweight accumulator of evidence seen SO FAR within one scenario.
    Populated from raw events by the validation runner. Reset per scenario in
    independent mode.
    """
    failed_logins: int = 0
    usb_connections: int = 0
    usb_exec_visible: bool = False
    usb_exec_accessed: bool = False
    defender_disabled: bool = False
    defender_changed_restored: bool = False
    security_controls_changed: int = 0
    public_network: bool = False
    process_enumeration: bool = False
    script_execution: bool = False
    encoded_command: bool = False
    scheduled_task_created: bool = False
    persistence_plus_weakening: bool = False
    extras: dict = field(default_factory=dict)


@dataclass
class RuleDecision:
    alert: bool
    severity: str            # informational|low|medium|high|critical
    category: str            # NORMAL|AUTH|USB|SEC|PROC|NET|PERSIST
    rule_id: str             # exact rule that fired (audit)
    rationale: str


def _d(alert, severity, category, rule_id, rationale) -> RuleDecision:
    return RuleDecision(alert=alert, severity=severity, category=category,
                        rule_id=rule_id, rationale=rationale)


# --- per-category rule functions -------------------------------------------- #

def _auth(ev: ScenarioEvidence, combined_risky: bool) -> RuleDecision:
    n = ev.failed_logins
    if combined_risky and n >= 1:
        return _d(True, "high", "AUTH", "AUTH_FAIL_COMBINED",
                  "Failed logins combined with another risky signal.")
    if n >= 10:
        return _d(True, "high", "AUTH", "AUTH_FAIL_HIGH_FREQ",
                  f"{n} failed logins (high frequency).")
    if n >= 3:
        return _d(True, "medium", "AUTH", "AUTH_FAIL_REPEATED",
                  f"{n} repeated failed logins.")
    if n == 1:
        # informational; optionally no popup (runner may suppress)
        return _d(False, "informational", "AUTH", "AUTH_FAIL_SINGLE",
                  "Single isolated failed login (informational).")
    return _d(False, "normal", "AUTH", "AUTH_NONE", "No authentication anomaly.")


def _usb(ev: ScenarioEvidence, authorised: bool) -> RuleDecision:
    if ev.usb_connections and (ev.defender_disabled or ev.script_execution):
        return _d(True, "critical", "USB", "USB_PLUS_WEAKENING",
                  "USB combined with disabled protection or suspicious execution.")
    if ev.usb_exec_accessed:
        return _d(True, "high", "USB", "USB_EXEC_ACCESSED",
                  "Script/executable on USB accessed or executed.")
    if ev.usb_exec_visible:
        return _d(True, "medium", "USB", "USB_EXEC_VISIBLE",
                  "Script/executable visible on removable media.")
    if authorised:
        return _d(False, "low", "USB", "USB_AUTHORISED",
                  "Authorised USB device.")
    if ev.usb_connections:
        return _d(True, "medium", "USB", "USB_UNKNOWN",
                  "Unknown USB connected without file execution.")
    return _d(False, "normal", "USB", "USB_NONE", "No USB activity.")


def _net(ev: ScenarioEvidence) -> RuleDecision:
    if ev.public_network and (ev.failed_logins >= 3 or ev.process_enumeration
                              or ev.defender_disabled):
        return _d(True, "high", "NET", "NET_PUBLIC_COMBINED",
                  "Public network plus failed logins, scanning or disabled protection.")
    if ev.public_network:
        return _d(False, "low", "NET", "NET_PUBLIC_ALONE",
                  "Public network alone (informational/low).")
    return _d(False, "normal", "NET", "NET_PRIVATE", "Private network / normal.")


def _proc(ev: ScenarioEvidence, shell_opened: bool, basic_cmd: bool) -> RuleDecision:
    if ev.script_execution and ev.defender_disabled:
        return _d(True, "critical", "PROC", "PROC_PLUS_WEAKENING",
                  "Process activity combined with disabled protection.")
    if ev.encoded_command:
        return _d(True, "high", "PROC", "PROC_ENCODED",
                  "Unusual or encoded-looking command.")
    if ev.script_execution:
        return _d(True, "high", "PROC", "PROC_SCRIPT_EXEC",
                  "Script execution observed.")
    if ev.process_enumeration:
        return _d(True, "medium", "PROC", "PROC_ENUM",
                  "Process enumeration observed.")
    if basic_cmd:
        return _d(False, "low", "PROC", "PROC_BASIC_CMD",
                  "Basic directory/system-information command.")
    if shell_opened:
        return _d(False, "normal", "PROC", "PROC_SHELL_OPEN",
                  "PowerShell/CMD opened (not automatically abnormal).")
    return _d(False, "normal", "PROC", "PROC_NONE", "No suspicious process activity.")


def _sec(ev: ScenarioEvidence, settings_viewed: bool) -> RuleDecision:
    if ev.security_controls_changed >= 2:
        return _d(True, "critical", "SEC", "SEC_MULTI_CHANGED",
                  "Multiple security controls changed.")
    if ev.defender_disabled:
        return _d(True, "high", "SEC", "SEC_DEFENDER_DISABLED",
                  "Defender disabled.")
    if ev.defender_changed_restored:
        return _d(True, "medium", "SEC", "SEC_DEFENDER_CHANGED_RESTORED",
                  "Defender configuration changed and restored.")
    if settings_viewed:
        return _d(False, "normal", "SEC", "SEC_SETTINGS_VIEWED",
                  "Security settings viewed (normal).")
    return _d(False, "normal", "SEC", "SEC_NONE", "No security-control change.")


def _persist(ev: ScenarioEvidence, ui_viewed: bool, artefact_removed: bool) -> RuleDecision:
    if ev.persistence_plus_weakening:
        return _d(True, "critical", "PERSIST", "PERSIST_PLUS_WEAKENING",
                  "Persistence combined with security weakening.")
    if ev.scheduled_task_created:
        return _d(True, "high", "PERSIST", "PERSIST_TASK_CREATED",
                  "Scheduled task created or modified.")
    if artefact_removed:
        return _d(False, "normal", "PERSIST", "PERSIST_CLEANUP",
                  "Test artefact removed (cleanup, not persistence creation).")
    if ui_viewed:
        return _d(False, "normal", "PERSIST", "PERSIST_UI_VIEWED",
                  "Task Scheduler/Services viewed (normal).")
    return _d(False, "normal", "PERSIST", "PERSIST_NONE", "No persistence change.")


# Dispatch table so the runner can call one function by category.
CATEGORY_RULES = {
    "AUTH": _auth,
    "USB": _usb,
    "NET": _net,
    "PROC": _proc,
    "SEC": _sec,
    "PERSIST": _persist,
}
