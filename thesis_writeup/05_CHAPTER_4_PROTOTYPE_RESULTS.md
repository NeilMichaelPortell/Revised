# 05 — Chapter 4: Prototype Feasibility Result

Source: `prototype/validation_results.csv`, `prototype/validation_summary.txt`,
`prototype/validation_implementation_report.txt`,
`prototype/tests/test_validation.py`. This is a **standalone, supplementary**
result — never merged with, and does not affect, the frozen 120-scenario
baseline/RAG comparison, the consistency study, or OTRF.

## What was built and unit-tested

A real-time Windows prototype: existing endpoint monitors feed a rule-based
trigger layer (`prototype/validation/rule_triggers.py`, evidence-combining,
category-tagged), which — when it fires — asks a locally hosted LLM (Ollama)
for plain-English feedback. A supplementary validation-run harness
instruments five latency segments, JSON/schema validity vs fallback, retries,
duplicate-event and cooldown suppression, and writes per-run metrics.

**15 of 15 automated unit tests pass**
(`python -m unittest tests.test_validation`,
`prototype/validation_implementation_report.txt`), covering: run/scenario-id
propagation, output-directory isolation, independent vs adaptive state/history
reset, the USB double-count regression fix, process deduplication, cooldown
logging, browser-URL sanitisation (scheme+domain only), JSON-parse vs
strict-schema validation, fallback-never-counted-as-success, latency-field
generation, and two rule-non-trigger checks (public network alone, single
failed login alone -> no alert).

## What the one completed live run actually shows

`prototype/validation_results.csv` contains **exactly one** completed live
validation run (`LIVE_AUTH_001_R1`, AUTH scenario type, `independent_validation`
mode):

| Field | Value |
|---|---|
| Events captured | 190 |
| Duplicate events (deduplicated) | 209 |
| Cooldown suppressions | 5 |
| Alerts expected | 1 |
| Alerts generated | **0** |
| Missed alerts | **1** |
| LLM calls | **0** |
| JSON parse / strict schema validity rate | 0.0 / 0.0 (no calls made) |
| Detection / LLM / end-to-end latency | all 0.0 (no alert reached the LLM stage) |

**This must be reported honestly, not oversold.** The single completed run
demonstrates that the *data-capture and harness* layer works end-to-end on a
real Windows machine — 190 real events were captured, deduplicated (209
duplicates correctly suppressed) and 5 cooldown suppressions correctly
logged, all with an isolated, auditable per-run output folder. It does
**not** demonstrate that the detection-to-LLM-feedback pipeline works
end-to-end in a live session: the one alert that was expected did not fire,
so the LLM layer was never exercised (0 calls), and no latency or
schema-reliability figure exists yet for a live LLM call.

## What this result supports, and what it does not

**Supports:** operational feasibility of the capture/harness/logging
architecture on a real endpoint (event capture, deduplication, cooldown
logic, isolated per-run auditability, privacy-preserving telemetry
sanitisation), and correctness of the underlying rule/schema/latency logic
via the unit-test suite.

**Does NOT support:** any claim about live detection accuracy, live LLM
output reliability, or live end-to-end latency — those require additional
completed runs in which the trigger layer actually fires and reaches the
LLM. With n=1 and 0 LLM calls, no live detection-rate, false-positive-rate or
LLM-reliability number should appear in the dissertation as a prototype
"result"; if the underlying implementation report's other unit-test-verified
capabilities (dedup, cooldown, schema validation, latency instrumentation)
are cited, they should be attributed to the unit-test suite, not to this one
live run. Additional live runs across more scenario types would be needed to
make a substantive live-detection claim (see `07_THREATS_TO_VALIDITY.md` and
`10_UNSUPPORTED_CLAIMS.md`).

Per the prototype's own documented limitation
(`validation_implementation_report.txt`): "These controlled live sessions
improve evidence of operational feasibility and ecological validity but do
NOT constitute independent organisational or population-level real-world
validation."
