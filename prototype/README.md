# Endpoint Feedback Prototype — Validation-Ready Build

Real-time, single-machine proof-of-concept for the revised MCAST dissertation
*"Real-Time Detection and Adaptive Analysis of Risky User Actions on Endpoints."*

The prototype watches live Windows endpoint behaviour; when its rule-based
trigger layer flags a risky user action it asks a **locally deployed LLM (via
Ollama)** for plain-English, user-facing feedback. This build adds a
**supplementary real-time validation study** layer that produces auditable
research data.

> **Scope.** The prototype validation study is **supplementary and separate**
> from the frozen offline evaluation (120 scenarios, five models, baseline/RAG).
> It does not modify, replace or recalculate any frozen dataset, baseline
> output, RAG output or evaluation script.

---

## 1. Purpose

* Demonstrate the real-time feedback layer end-to-end on a controlled Windows
  test machine.
* Produce auditable evidence for: live-action capture, expected-alert
  generation, benign false alerts, JSON/schema reliability, detection latency,
  LLM latency, end-to-end latency, duplicate-alert behaviour, feedback
  grounding, and adaptive feedback for repeated actions.

## 2. Supported event sources

Existing monitors are preserved: browser endpoint (domain-only), application
and process monitors, file/download monitor, network-profile monitor, USB
monitor, Windows event-log monitor, and the Defender/security monitor. Monitors
are best-effort: if one cannot start (e.g. no admin, non-Windows), it is logged
and skipped — the run still proceeds.

## 3. Privacy boundaries

The prototype never stores passwords, keystrokes, clipboard contents,
screenshots, file contents, authentication tokens, or full browser URLs.

**Browser information retained:** scheme + domain only.

* Path, query string, fragment and the full original URL are discarded and
  never written.
* If a URL path matches a sensitive keyword (login, account, bank, wallet, ...)
  the visit is dropped entirely — not even the domain is stored.
* Page titles are not collected.
* Coarse domain grouping is done locally; **no external lookup service** is used
  during the experiment.

## 4. Rule-trigger vs LLM-prediction (important distinction)

The prototype has two clearly separated layers:

* **Rule-trigger layer** (`validation/rule_triggers.py`) decides *whether* to
  raise an alert and assigns a **provisional** severity. It is conservative and
  evidence-combining. Its severity is **not ground truth** and is **not** the
  LLM's classification. The exact rule that fired is recorded on every alert.
* **LLM prediction** is the model's own classification and user-facing feedback,
  produced only after the rule decides an alert is warranted.

The defensible trigger ladder (summary):

| Category | Not automatically abnormal | Escalates when... |
|----------|----------------------------|-----------------|
| AUTH     | one isolated failed login  | repeated (medium) -> high-frequency (high) -> combined with another risky signal (high/critical) |
| USB      | one authorised USB         | unknown USB (medium) -> executable visible (medium/high) -> accessed/executed (high) -> with disabled protection (critical) |
| NET      | public network alone (low) | public + failed logins/scanning/disabled protection (medium/high) |
| PROC     | opening PowerShell/CMD      | enumeration (medium) -> script execution (high) -> encoded command (high) -> with disabled protection (critical) |
| SEC      | viewing security settings   | changed-and-restored (medium) -> disabled (high) -> multiple controls changed (critical) |
| PERSIST  | viewing Task Scheduler/Services | task created/modified (high); artefact removal is cleanup; persistence + weakening (critical) |

## 5. Validation-run workflow

1. Choose or edit a scenario in a validation plan CSV
   (`example_validation_plan.csv`; template: `validation_plan_template.csv`).
2. Run one scenario:

   ```
   ollama serve                     # separate terminal
   python run_validation.py --scenario LIVE_AUTH_001 --model deepseek-r1:8b
   ```

3. Perform the described actions on the test machine.
4. Type `stop` (or Ctrl+C) to finalise. The run's metrics and report are
   written to its isolated folder.
5. After several runs, aggregate them:

   ```
   python tools/analyse_validation_runs.py
   ```

Only **one model runs at a time**, chosen at startup — matching the
single-machine, manual model-comparison design.

## 6. Independent vs adaptive validation modes

Set per scenario in the plan (`validation_mode`). The two modes are never mixed
silently.

* **independent_validation** — full state reset before every scenario and
  repetition; adaptive history is cleared so each repetition starts from an
  equivalent state.
* **adaptive_feedback_validation** — session counters reset, but selected user
  history is preserved and **exactly what history was supplied to the model is
  recorded** in `run_metadata.json` (`adaptive_history_supplied`).

## 7. Output folder structure

```
validation_outputs/
└── LIVE_AUTH_001_R1/
    ├── run_metadata.json          # test plan + session ids + reset record
    ├── raw_events.jsonl           # raw evidence (never overwritten)
    ├── alerts.jsonl               # one record per generated alert
    ├── llm_calls.jsonl            # one record per LLM call incl. latency
    ├── session_summary.json
    ├── prototype_metrics.json     # per-run aggregated metrics
    └── run_validation_report.txt  # readable summary
```

Independent sessions are never mixed in one cumulative log.

## 8. Latency definitions

Durations use a monotonic high-resolution timer; audit timestamps are UTC.

```
detection_latency_ms      = detection_ts        - event_ts
queue_delay_ms            = llm_request_start    - queue_ts
llm_generation_latency_ms = response_received    - llm_request_start
popup_delay_ms            = popup_displayed      - response_received
end_to_end_latency_ms     = popup_displayed      - event_ts
```

Each run aggregates count / mean / median / min / max / p95. Only observed
values are reported; nothing is precomputed or estimated.

## 9. JSON validity vs schema validity vs fallback

Four distinct concepts are measured separately:

* **JSON parse validity** — did the text parse as a JSON object?
* **Required-field validity** — are all required fields present?
* **Semantic/schema validity** — do the values satisfy the rules
  (`classification` in {normal, abnormal, risky}, `risk_level` in {low, medium,
  high, critical}, `indicators` a list of strings, non-empty `explanation` and
  `recommended_action`)?
* **Fallback response** — the client's hard-coded offline message. A fallback is
  **never** counted as a successful or schema-valid LLM response.

The raw `classification` value is preserved before `risky` is normalised to
`abnormal`. First-attempt and post-retry validity are both recorded; retries are
limited (`MAX_LLM_RETRIES`) and documented.

## 10. How to reset state

State reset is automatic at the start of each scenario (mode-aware, section 6).
It clears session risk score, counters, USB count, failed-login count,
cooldowns, deduplication state, queued alerts, rolling summaries and (in
independent mode) adaptive history. **It never deletes completed validation
output folders.**

## 11. Risk scoring

The per-scenario risk score starts at **zero** and is non-cumulative across
scenarios, so longer sessions no longer look more severe. Each event records
`risk_score_before_event`, `risk_score_added`, `risk_score_after_event`.
Thresholds: `medium >= 7`, `high >= 15` (documented in `state_reset.py`). The
risk score is **not** ground truth.

## 12. How to analyse completed runs

```
python tools/analyse_validation_runs.py
```

Produces `validation_results.csv` (one row per run) and `validation_summary.txt`
(event-capture rate, alert-detection rate, benign false-alert rate, JSON
validity rate, strict schema-compliance rate, fallback rate, timeout rate,
duplicate-alert rate, latency summaries, and breakdowns by scenario type and
validation mode). These are **not merged** with the frozen offline metrics.

## 13. Running the original real-time prototype

The original interactive monitor (`main.py`) is unchanged and still works for
demonstrations. The validation study uses `run_validation.py`.

## 14. Requirements

Python 3.10+. Live monitoring requires Windows with `psutil`, `pywin32`, `wmi`
(see `requirements.txt`); run elevated for full event-log/USB coverage. The
validation layer, tests and analysis tool are **standard-library only** and run
on any platform for dry runs and testing.

## 15. Tests

```
python -m unittest tests.test_validation -v
```

Tests use mocked Windows events and mocked Ollama responses; they do not require
disabling any security control.

## 16. Known limitations

* Live capture requires a Windows test machine; on other platforms the run
  folder and pipeline are created but no live events are captured.
* Rule severity is a conservative provisional trigger, not validated ground
  truth.
* The validation plan is a **test plan**, not an answer key, and is never added
  to the LLM prompt.

> **Methodological limitation.**
> The live validation sessions are controlled tests performed on a limited
> Windows environment. They improve evidence of operational feasibility and
> ecological validity, but they do not constitute independent organisational
> or population-level real-world validation.
