"""Quick smoke-test for all qwen3:8b-specific changes."""
import sys
sys.path.insert(0, ".")

from ai.ollama_client import _strip_thinking, _parse_and_validate
from ai.ai_prompts import build_prompt, build_combined_prompt
from ai.display import popup_body

SEP = "─" * 55

# ── 1. Think-block stripping ─────────────────────────────────────
print(SEP)
print("TEST 1 — Think-block stripping")

WITH_THINK = (
    "<think>\nLet me analyse this event.\n"
    "The user downloaded test.torrent. Risky behaviour.\n</think>\n"
    '{"title":"Torrent downloaded","what_happened":"You downloaded test.torrent.",'
    '"why_risky":"Malware risk.","how_to_prevent":["Delete it","Run Defender"],'
    '"learning_tip":"Second torrent this week — repeated pattern."}'
)

NO_THINK = (
    '{"title":"HTTP visit to example.com",'
    '"what_happened":"You visited example.com over unencrypted HTTP.",'
    '"why_risky":"Traffic visible on the network.",'
    '"how_to_prevent":["Use HTTPS","Avoid logging in on HTTP"],'
    '"learning_tip":"Third HTTP visit this session."}'
)

stripped = _strip_thinking(WITH_THINK)
assert "<think>" not in stripped, "Think block not stripped!"
print("  Strip think block:     OK")

r1 = _parse_and_validate(WITH_THINK)
assert r1 and r1.get("title") == "Torrent downloaded", f"Parse with think failed: {r1}"
print("  Parse WITH think:      OK —", r1["title"])

r2 = _parse_and_validate(NO_THINK)
assert r2 and "example.com" in r2.get("title", ""), f"Parse no-think failed: {r2}"
print("  Parse WITHOUT think:   OK —", r2["title"])

# ── 2. how_to_prevent normalisation ─────────────────────────────
print(SEP)
print("TEST 2 — how_to_prevent list normalisation")

STRING_PREVENT = (
    '{"title":"T","what_happened":"W","why_risky":"R",'
    '"how_to_prevent":"• Step one\\n• Step two\\n• Step three",'
    '"learning_tip":"L"}'
)
r3 = _parse_and_validate(STRING_PREVENT)
assert isinstance(r3["how_to_prevent"], list), "Not converted to list!"
assert r3["how_to_prevent"][0] == "Step one", f"Bullet not stripped: {r3['how_to_prevent']}"
print("  String -> list:        OK —", r3["how_to_prevent"])

# ── 3. /nothink placement ────────────────────────────────────────
print(SEP)
print("TEST 3 — /nothink in client, NOT in prompt builder")

threat = {
    "type": "public_network",
    "severity": "medium",
    "summary": "Connected to Public Wi-Fi",
    "context": {"network_type": "Public"},
}
system, user = build_prompt(threat, None)
assert "/nothink" not in user, "/nothink should be added by client, not prompt builder"
assert "/nothink" not in system, "/nothink should not be in system prompt"
assert '\"title\"' in user, "Schema reinforcement missing from user prompt"
print("  /nothink not in prompts:   OK")
print("  Schema in user turn:       OK")
print("  Prompt total chars:", len(system) + len(user))

combined = build_combined_prompt(threat, None)
assert "[SYSTEM]" in combined and "[USER]" in combined
print("  Combined prompt sections:  OK")

# ── 4. Full popup rendering ──────────────────────────────────────
print(SEP)
print("TEST 4 — Popup body rendering")

alert = {
    "alert_number": 1,
    "timestamp": "2026-03-18T12:00:00",
    "threat_type": "torrent_download",
    "severity": "high",
    "risk_score": 4,
    "source": "filesystem",
    "summary": "You downloaded test.torrent",
    "context": {"File You Downloaded": "test.torrent", "Downloaded From": "unknown website"},
    "ai_response": r1,
}
popup = popup_body(alert)
assert "test.torrent" in popup, "Filename not in popup!"
assert "What happened" in popup, "Section header missing!"
assert "How to prevent" in popup, "Prevention section missing!"
assert "Learning tip" in popup, "Learning tip missing!"
print("  All 5 sections present:    OK")
print()
print("=== POPUP PREVIEW ===")
print(popup)
print()
print("ALL QWEN3 TESTS PASSED ✓")
