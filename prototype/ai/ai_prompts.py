"""
Prompt Builder  —  tuned for qwen3:8b
───────────────────────────────────────
Qwen3 tuning notes applied here:

  • System prompt uses Qwen3's preferred direct instruction style.
    No fluff — Qwen3 is instruction-tuned and responds better to
    "You must" / "Output only" than to soft suggestions.

  • /nothink is prepended in ollama_client.py (not here) so this module
    stays clean and reusable if the model is changed later.

  • JSON schema is repeated in both system and user turns.
    Qwen3 benefits from schema reinforcement at the end of the user turn.

  • Context section is concrete — Qwen3 excels at grounding responses in
    specific facts when those facts are clearly labelled.
"""

import datetime
from ai.threat_knowledge import format_knowledge_for_prompt
from ai.user_history import format_history_for_prompt


# ─── System Prompt ───────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a cybersecurity awareness assistant built into a real-time Windows security monitor.
A threat has been detected on the user's computer. Your job is to explain it clearly.

The user is NOT a technical person. Write as if explaining to a friend — plain English only.

OUTPUT RULES (non-negotiable):
- Output ONLY a single valid JSON object. Nothing before it. Nothing after it.
- No markdown. No code fences. No <think> blocks. No commentary.
- All 5 fields are required.
- Total word count across all 5 fields: 80–130 words.

JSON SCHEMA:
{
  "title": "One sentence — exactly what happened, naming the specific file/site/device.",
  "what_happened": "2–3 sentences describing what was detected. Use the exact name from the event details.",
  "why_risky": "2 sentences explaining the real personal danger this creates for this user.",
  "how_to_prevent": ["Step 1", "Step 2", "Step 3"],
  "learning_tip": "One sentence. If this is a repeated behaviour, say so explicitly."
}

FIELD RULES:
- title: must name the exact file, domain, or device. Never generic.
- what_happened: must reference the specific event details given. Never say "a file" if you know the filename.
- why_risky: explain THIS user's personal risk, not a generic threat description.
- how_to_prevent: 2–4 items. Each item is one short actionable sentence.
- learning_tip: personalised to the user's history. Mention repeat patterns if present.\
"""


# ─── Prompt builder ──────────────────────────────────────────────────────────

def build_prompt(threat: dict, session=None) -> tuple:
    """
    Return (system_prompt, user_prompt) for the Ollama /api/chat endpoint.
    The /nothink directive is prepended in ollama_client.py.
    """
    threat_type = threat.get("type", "unknown")
    severity    = threat.get("severity", "medium").upper()
    summary     = threat.get("summary", "A security event was detected.")
    ctx         = threat.get("context", {})
    timestamp   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── Event details ────────────────────────────────────────────
    ctx_lines = (
        "\n".join(
            f"  {k.replace('_', ' ').title()}: {v}"
            for k, v in ctx.items()
        )
        if ctx else "  (no additional details)"
    )

    # ── Session stats (brief) ────────────────────────────────────
    if session:
        try:
            http_count   = session.http_visit_count()
            total_web    = session.https_visit_count() + http_count
            with session.lock:
                threat_count = session.threat_count
                risk_score   = session.risk_score
            session_note = (
                f"  {threat_count} threats this session (score: {risk_score}) | "
                f"{total_web} web visits ({http_count} unencrypted HTTP)"
            )
        except Exception:
            session_note = "  (session stats unavailable)"
    else:
        session_note = "  (no session data)"

    # ── Threat knowledge (grounding data) ───────────────────────
    knowledge_block = format_knowledge_for_prompt(threat_type)

    # ── Persistent user history ──────────────────────────────────
    history_block = format_history_for_prompt()

    # ── User-turn prompt ─────────────────────────────────────────
    # Schema is repeated at the end — Qwen3 benefits from this reinforcement.
    user_prompt = f"""\
SECURITY EVENT DETECTED:
  Type     : {threat_type.replace("_", " ").title()}
  Severity : {severity}
  Summary  : {summary}
  Time     : {timestamp}

SPECIFIC DETAILS (use these exact values in your response):
{ctx_lines}

SESSION CONTEXT:
{session_note}

USER'S PAST RISK HISTORY (most recent first):
{history_block}

THREAT KNOWLEDGE BASE — {threat_type.replace("_", " ").upper()}:
{knowledge_block}

─────────────────────────────────────────
OUTPUT: Reply with ONLY this JSON object. No other text.
{{
  "title": "...",
  "what_happened": "...",
  "why_risky": "...",
  "how_to_prevent": ["...", "...", "..."],
  "learning_tip": "..."
}}\
"""

    return SYSTEM_PROMPT, user_prompt


def build_combined_prompt(threat: dict, session=None) -> str:
    """
    Single-string prompt for the subprocess fallback path.
    System and user sections are clearly separated so Qwen3
    treats them correctly even without message-role tagging.
    """
    system, user = build_prompt(threat, session)
    sep = "─" * 60
    return f"[SYSTEM]\n{system}\n\n{sep}\n\n[USER]\n{user}"
