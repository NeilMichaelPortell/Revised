# Diagnosis: `LIVE_AUTH_001_R1`

## Scope and phase boundary

This diagnosis uses only the live-validation artifacts in
`validation_outputs/LIVE_AUTH_001_R1/` and the live validation/monitoring code.
The frozen offline experiment was not used. This file was written before any
implementation or test changes.

## Run evidence

`raw_events.jsonl` contains 399 records in total. The report's 190 "events
captured" count excludes records marked as duplicates; the other 209 JSONL
records are retained as auditable duplicate observations.

| Event type | Accepted | Duplicate | JSONL total |
|---|---:|---:|---:|
| `process_started` | 180 | 208 | 388 |
| `application_started` | 6 | 1 | 7 |
| `login_failed` | 2 | 0 | 2 |
| `network_profile_changed` | 1 | 0 | 1 |
| `usb_connected` | 1 | 0 | 1 |
| **Total** | **190** | **209** | **399** |

The two accepted `login_failed` records came from
`eventlog:Security:4625`. They have distinct Security log record numbers
(`3807492` and `3807495`) and timestamps approximately two milliseconds apart.
Neither was marked duplicate.

`run_validation_report.txt` says the only expected type, `login_failed`, was
present. It lists `application_started`, `network_profile_changed`,
`process_started`, and `usb_connected` as unexpected captured types. Thus
"expected type present" means at least one such event was captured; it does not
mean the scenario captured enough instances to satisfy its rule.

## Event path

1. Each monitor calls `core.logger.write_log(event_type, data, source)`.
2. `core/logger.py` appends the event to `outputs/usage_logs.jsonl`, enriches its
   source, then calls the installed pipeline's `process(entry)` method.
3. `_try_start_live_monitors()` in `run_validation.py` installs `_Bridge` as that
   pipeline. `_Bridge.process()` calls `ScenarioRunner.handle_event()` with the
   event type, raw `data`, and enriched source.
4. `ScenarioRunner.handle_event()` first calls
   `ValidationRun.record_raw_event()`. Process/application observations can be
   marked duplicate there. Collector-generated or duplicate records return
   before evidence accumulation.
5. For every accepted `login_failed`, `_update_evidence()` increments
   `ScenarioEvidence.failed_logins` by one. It then evaluates the selected rule.
   Cooldown is checked only after a rule has already returned `alert=True`, so
   cooldown cannot prevent a login event from incrementing evidence.
6. The AUTH rule alerts at three failed logins (`AUTH_FAIL_REPEATED`, medium), at
   ten (`AUTH_FAIL_HIGH_FREQ`, high), or at one or more failures combined with
   another risky signal (`AUTH_FAIL_COMBINED`, high). One failure is
   informational; two failures do not alert without a combined signal.

For this run, both accepted 4625 events reached `handle_event()` and incremented
AUTH evidence. The resulting `failed_logins` value was 2, not the threshold of
3. The threshold itself is implemented correctly and must not be weakened.

## Hypothesis assessment

### Security event 4625 was not being read because of audit policy or privilege

**Rejected for this run.** Two new, distinct Security/4625 records were captured
through the event-log monitor and bridge. That proves the monitor could open and
read the Security log during this run and that failure auditing produced at
least two records. It does not prove that the operator performed three
qualifying failed-logon actions: only two are present in the authoritative raw
evidence.

The environmental requirements remain: Windows Advanced Audit Policy must have
**Logon failure auditing** enabled so failed attempts create Event ID 4625, and
the process must have permission to read the Windows Security event log
(normally an elevated Administrator token or an appropriately delegated Event
Log Readers setup). A future run should surface these requirements explicitly
at startup rather than relying on a generic monitor message.

### Process/application monitors flooded the pipeline

**Supported.** `process_started` accounts for 388 of 399 JSONL records and 208
of 209 duplicates. `application_started` contributes the remaining duplicate.
The process monitor takes an initial snapshot and emits each PID it has not seen,
which naturally creates a burst. More importantly, it reads `pid` from psutil
but omits it from the emitted `data`. Validation deduplication is documented and
implemented as `(process_name, pid, exe)` within three seconds; because the PID
is absent, every emitted process has an empty PID component. Concurrent,
legitimate processes with the same name and executable are therefore collapsed
together. All 388 process records in this run lack PID, and the 208 duplicates
refer to only 32 accepted targets (for example, 47 `svchost.exe` observations
refer to one target). The dedup window is operating as coded, but it is receiving
an incomplete identity key from the process monitor.

Duplicate count exceeding accepted count is not arithmetically invalid: the
metrics count observations, not unique keys, and duplicate records are retained.
Here, however, the magnitude is inflated by the missing PID.

### Deduplication or cooldown swallowed the failed-login evidence

**Rejected.** Deduplication applies only to process/application event types, and
both `login_failed` records are accepted. Evidence is incremented before the
rule and before cooldown. Cooldown therefore did not swallow either login.

The five cooldown suppressions expose a different bug. Rule selection currently
uses the plan's `expected_category` for **every** accepted event. In an AUTH run,
an unrelated `usb_connected` event is therefore evaluated by the AUTH rule. At
17:37:24, after two failed logins, the USB event set `usb_connections`, making
`combined_risky=True`; it consequently selected `AUTH_FAIL_COMBINED`. Five
accepted process events arrived after that USB event and before completion,
matching the five suppressions of the same AUTH rule. Unrelated process/app/USB
events should retain context where rules intentionally combine evidence, but
they must not masquerade as the plan's expected event category.

### Monitor-to-runner bridge wiring lost the failed-login events

**Rejected.** The raw records contain the exact monitor source
`eventlog:Security:4625`, event ID 4625, and Security record numbers. Since raw
recording is the first action inside `ScenarioRunner.handle_event()`, these
fields demonstrate the complete monitor -> logger -> bridge -> runner path for
both failures.

### The AUTH threshold or evidence counter is wrong

**Rejected.** The intended repeated-login threshold is three, and
`_update_evidence()` increments once for each accepted `login_failed`. With two
accepted failures, the observed no-alert AUTH result is correct.

### Zero LLM records proves no call was attempted

**Not supported.** This run strongly indicates one call was started but had not
finished when the run was finalized. The USB event described above is the first
event that could select `AUTH_FAIL_COMBINED`; the next five accepted events are
accounted for exactly by the five cooldown suppressions, which require a prior
successful `cooldown_ok()` for that rule. `llama-server.exe` was then captured
six seconds after the USB trigger, consistent with Ollama starting/loading.

`run_llm_for_event()` is synchronous, and `record_llm_call()` and
`record_alert()` happen only after `ask_ai_fn()` returns. Monitor callbacks run
on daemon threads, while `runner.complete()` neither stops intake nor waits for
an in-flight handler. The run was completed about nine seconds after the USB
event, while the Ollama client permits up to 120 seconds. Therefore the metrics
could be finalized with zero LLM calls/alerts/latencies even though an unintended
call was in flight. This is an evidence-backed inference because there is no
pre-request audit record in the current format.

## Root cause and genuine additional defects

The **single most likely root cause of the expected AUTH miss** is that the live
run produced only **two auditable failed-login events**, below the correct
three-event threshold. It is not a 4625 capture failure, deduplication loss,
cooldown loss, bridge loss, or threshold bug. The validation result must remain
a miss; no telemetry may be backfilled and the threshold must remain unchanged.

Three genuine code defects distorted the same run and should be fixed
separately:

1. `process_monitor.py` omits PID, making the intended process identity dedup key
   incomplete and inflating duplicates.
2. `scenario_runner.py` routes every event through the plan category, allowing
   unrelated USB/process events to trigger and suppress an AUTH rule.
3. Finalization races active monitor callbacks, so an in-flight Ollama call can
   be absent from finalized metrics and audit output.

The environmental fix for the primary miss is procedural: enable failure
auditing, run with Security-log read access, perform at least three actions that
actually generate distinct new 4625 records after the monitor reports it is
positioned at the end of the log, and verify the live captured count. Code should
add an explicit startup warning/preflight message for these requirements; it
must not fabricate a third event.

## Phase 2 corrections applied

The following corrections were made after the Phase 1 diagnosis was completed:

1. `monitors/process_monitor.py` now includes the PID it already obtains from
   psutil in each process event. This supplies the existing three-part dedup key
   and prevents different same-name processes in the initial snapshot from
   being collapsed solely because PID was blank.
2. `validation/scenario_runner.py` now applies the plan category only to event
   types explicitly listed by that scenario. Unexpected events remain in raw
   evidence and may update the shared context, but cannot directly invoke the
   scenario's rule. This preserves planned combined scenarios (where both event
   types are explicit) while preventing the unexpected USB in `LIVE_AUTH_001`
   from firing `AUTH_FAIL_COMBINED`.
3. The runner now tracks active handlers. Completion first stops accepting new
   events, then waits a bounded period for handlers already inside the pipeline
   before writing the summary and metrics. The launcher derives the bound from
   the two possible Ollama client paths. Drain status is stored in run metadata,
   and the report warns if the bound is exceeded.
4. `run_validation.py` prints an AUTH preflight warning explaining failure-audit
   policy, Security-log read permission, and the repeated-login count. The event
   log monitor prints a specific AUTH-capture warning when it cannot open the
   Security log.

No threshold, telemetry, timestamp, latency, cooldown, fallback, or prior run
artifact was changed or backfilled. `LIVE_AUTH_001_R1` correctly remains a miss.

## Regression coverage and verification

Two tests were added to `tests/test_validation.py` because the corrected behavior
was previously untested:

- `test_unexpected_usb_does_not_trigger_auth_rule` injects two
  `login_failed` events followed by an unexpected USB event through
  `ScenarioRunner.handle_event()`. It verifies no AUTH call, alert, or cooldown
  is produced. Before the routing fix, the USB event invoked
  `AUTH_FAIL_COMBINED`.
- `test_complete_waits_for_inflight_llm_call` injects three `login_failed`
  events, blocks the mocked LLM on the third, and calls `complete()`. It verifies
  completion waits and final metrics contain the genuine completed call and
  alert. Before the drain fix, metrics finalized at zero while the handler was
  still active.

The required suite was run with the project's virtual-environment interpreter
because the shell's bare `python` resolves to a broken Windows Store alias:

```text
..\venv\Scripts\python.exe -m unittest tests.test_validation -v
Ran 17 tests in 0.256s
OK
```

The changed Python files were also compiled with `py_compile` before the test
run. All compilation checks passed.
