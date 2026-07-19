"""
Display
───────
Formats alert dicts for two output channels:

  format_alert()  — full terminal block written to security_alerts.txt
  popup_body()    — compact text for the Windows MessageBox popup

Both handle the new 5-section JSON format:
  title / what_happened / why_risky / how_to_prevent / learning_tip

And gracefully fall back to the legacy format or raw_response if needed.
"""

import textwrap
import datetime

SEV_BANNERS = {
    "low"     : "🟡  LOW",
    "medium"  : "🟠  MEDIUM",
    "high"    : "🔴  HIGH — Action required",
    "critical": "🚨  CRITICAL — Act immediately",
}


def _wrap(text: str, width: int = 64, indent: str = "  ") -> list:
    if not text:
        return [indent + "(no information)"]
    return [indent + ln for ln in textwrap.wrap(str(text), width)]


def _fmt_prevent(items) -> list:
    """Format how_to_prevent whether it's a list or a string."""
    if isinstance(items, list):
        return [f"  • {item}" for item in items if item]
    if isinstance(items, str) and items:
        return [f"  {items}"]
    return ["  (no prevention steps available)"]


# ─── Full terminal / file format ─────────────────────────────────────────────

def format_alert(alert: dict) -> str:
    num    = alert["alert_number"]
    sev    = alert["severity"]
    banner = SEV_BANNERS.get(sev, sev.upper())
    ai     = alert.get("ai_response", {})
    ctx    = alert.get("context", {})

    try:
        dt = datetime.datetime.fromisoformat(alert["timestamp"])
        ts = dt.strftime("%A, %d %B %Y at %H:%M:%S")
    except Exception:
        ts = alert["timestamp"]

    HR = "═" * 70
    hr = "─" * 70

    lines = [
        "",
        HR,
        f"  Alert #{num}   {banner}",
        f"  {ts}",
        HR,
        f"  {alert.get('summary', alert['threat_type'].replace('_', ' ').title())}",
        "",
    ]

    # ── What was detected ────────────────────────────────────────
    if ctx:
        lines += [hr, "  📋  WHAT WAS DETECTED", hr]
        for k, v in ctx.items():
            label   = k.replace("_", " ").title()
            val_str = str(v)
            if len(val_str) > 50:
                lines.append(f"  {label}:")
                lines += _wrap(val_str, indent="      ")
            else:
                lines.append(f"  {label:<28}: {val_str}")
        lines.append("")

    # ── AI response (raw text fallback) ──────────────────────────
    if "raw_response" in ai:
        lines += [hr, "  💬  Security Coach:", ""]
        for ln in ai["raw_response"].splitlines():
            lines.append(f"     {ln}")
        lines.append("")

    # ── New 5-section format ─────────────────────────────────────
    elif "title" in ai:
        title = ai.get("title", "")
        if title:
            lines += [hr, f"  📌  {title}", ""]

        sections = [
            ("🔍  WHAT HAPPENED",       "what_happened"),
            ("⚠   WHY THIS IS RISKY",   "why_risky"),
            ("✅  HOW TO PREVENT THIS",  None),           # special — list field
            ("💡  LEARNING TIP",         "learning_tip"),
        ]

        for heading, key in sections:
            if key is None:
                # how_to_prevent is a list
                items = ai.get("how_to_prevent", [])
                prevent_lines = _fmt_prevent(items)
                if prevent_lines:
                    lines += [hr, f"  {heading}", hr]
                    lines += prevent_lines
                    lines.append("")
            else:
                val = ai.get(key, "")
                if not val:
                    continue
                lines += [hr, f"  {heading}", hr]
                lines += _wrap(val)
                lines.append("")

    # ── Legacy format fallback ───────────────────────────────────
    elif any(k in ai for k in ("headline", "what_happened", "do_this_now")):
        headline = ai.get("headline", "")
        if headline:
            lines += [hr, f"  📌  {headline}", ""]

        legacy_sections = [
            ("🔍  WHAT HAPPENED",        "what_happened"),
            ("⚠   WHY THIS MATTERS",     "why_it_matters"),
            ("🏠  THINK OF IT LIKE THIS","real_world_comparison"),
            ("✅  DO THIS RIGHT NOW",     "do_this_now"),
            ("🛡   STAY SAFE NEXT TIME",  "stay_safe_tip"),
            ("💬  COACH'S NOTE",          "reassurance"),
        ]
        for heading, key in legacy_sections:
            val = ai.get(key, "")
            if not val:
                continue
            lines += [hr, f"  {heading}", hr]
            lines += _wrap(val)
            lines.append("")

    lines += [
        f"  Risk score: {alert.get('risk_score', '?')}  │  Source: {alert.get('source', '?')}",
        HR,
        "",
    ]
    return "\n".join(lines)


# ─── Popup body (compact, for MessageBox) ────────────────────────────────────

def popup_body(alert: dict) -> str:
    """
    Structured 5-section text for the Windows MessageBox popup.
    Designed to be readable at a glance — each section clearly labelled.
    """
    ai  = alert.get("ai_response", {})
    ctx = alert.get("context", {})

    # Detected details summary (top 4 fields)
    ctx_lines = "\n".join(
        f"  {k.replace('_', ' ').title()}: {v}"
        for k, v in list(ctx.items())[:4]
    )

    # ── Raw response fallback ────────────────────────────────────
    if "raw_response" in ai:
        body = f"{alert.get('summary', '')}\n\n{ai['raw_response'][:500]}"

    # ── New 5-section format ─────────────────────────────────────
    elif "title" in ai:
        prevent = ai.get("how_to_prevent", [])
        if isinstance(prevent, list):
            prevent_text = "\n".join(f"  • {p}" for p in prevent if p)
        else:
            prevent_text = f"  {prevent}"

        body = (
            f"📌  {ai.get('title', alert.get('summary', ''))}\n"
            f"{'─' * 50}\n\n"
            f"🔍  What happened:\n"
            f"  {ai.get('what_happened', '')}\n\n"
            f"⚠   Why this is risky:\n"
            f"  {ai.get('why_risky', '')}\n\n"
            f"✅  How to prevent this:\n"
            f"{prevent_text}\n\n"
            f"💡  Learning tip:\n"
            f"  {ai.get('learning_tip', '')}"
        )

    # ── Legacy format fallback ───────────────────────────────────
    else:
        body = (
            f"📌  {ai.get('headline', alert.get('summary', ''))}\n"
            f"{'─' * 50}\n\n"
            f"🔍  What happened:\n  {ai.get('what_happened', '')}\n\n"
            f"⚠   Why it matters:\n  {ai.get('why_it_matters', '')}\n\n"
            f"✅  Do this now:\n  {ai.get('do_this_now', '')}\n\n"
            f"🛡   Stay safe:\n  {ai.get('stay_safe_tip', '')}\n\n"
            f"💬  {ai.get('reassurance', '')}"
        )

    # Prepend detected details
    if ctx_lines:
        body = f"DETECTED:\n{ctx_lines}\n\n{'─' * 50}\n\n" + body

    body += "\n\n" + "─" * 50 + "\nFull report → outputs/security_alerts.txt"
    return body
