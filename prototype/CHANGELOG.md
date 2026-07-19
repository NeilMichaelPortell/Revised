# Changelog

## Validation-Ready build

Adds a supplementary real-time validation study layer. The offline experiment
(120 scenarios, five models, baseline/RAG) is untouched and not present in this
project.

### Added
- `validation/` package:
  - `validation_config.py` — modes, schema tokens, severity ladder, latency
    percentile/summary helpers.
  - `schema_validation.py` — JSON-parse / required-field / semantic / fallback
    validity, with raw-value preservation before `risky`→`abnormal`.
  - `rule_triggers.py` — defensible, evidence-combining rule layer (AUTH, USB,
    NET, PROC, SEC, PERSIST), separate from LLM classification.
  - `validation_run.py` — one isolated output folder per run; raw/alert/llm
    writers; monotonic latency capture; process dedup; cooldown logging;
    per-run metrics and readable report.
  - `state_reset.py` — mode-aware reset (independent vs adaptive) and zeroed,
    auditable per-scenario risk scoring.
  - `validation_llm.py` — instrumented LLM call: five latency segments, schema
    validation, explicit fallback marking, limited retry.
  - `scenario_runner.py` — ties plan + run + reset + rules + LLM together;
    testable with injected events and mocked `ask_ai`.
- `run_validation.py` — CLI launcher for one live scenario (start/stop),
  bridges existing monitors to the validation runner.
- `tools/analyse_validation_runs.py` — aggregates all completed runs into
  `validation_results.csv` and `validation_summary.txt`.
- `tests/test_validation.py` — 15 automated tests (stdlib unittest), mocked
  Windows events and Ollama responses.
- `validation_plan_template.csv`, `example_validation_plan.csv` (~12 scenarios).
- `CHANGELOG.md`, `validation_implementation_report.txt`.

### Changed
- `core/threat_detection.py` — **USB double-count bug fixed** (§11): report the
  actual observed connection count instead of `count + 1`.
- `monitors/browser_endpoint.py` — **privacy** (§7): removed `original_url` and
  full download URL; store scheme + domain only; sensitive paths drop the domain
  entirely.
- `ai/ollama_client.py` — preserve raw model text (`_raw_text`) so JSON-vs-schema
  validity can be measured; display path unchanged.
- `ai/user_history.py` — added `reset_history()` for independent-mode resets.

### Not changed
- Existing monitors, GUI/interface, local Ollama execution, overall
  architecture. No cloud dependencies introduced.
