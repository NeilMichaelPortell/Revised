# OTRF External Validation (Supplementary)

This folder contains a **supplementary external-validation workflow** that runs the
same locally deployed LLMs, the same prompt modes, and the same evaluation logic as
the primary 120-scenario experiment, but over **independent, third-party Windows
endpoint telemetry** drawn from the Open Threat Research Forge (OTRF)
Security-Datasets project.

Its only purpose is to check whether the pipeline **transports** to endpoint data
that the researcher did not design: can the adapter read externally produced host
telemetry, build leakage-safe structured behaviour summaries, and can the local
models still identify risky endpoint activity under baseline and knowledge-augmented
prompting.

> **What this is not.** OTRF datasets are controlled, publicly released
> adversary-simulation captures, not production enterprise logs and not real
> organisational incidents. Results here demonstrate **technical transportability of
> the pipeline**, not real-world deployment performance, and are not claimed to
> generalise to live environments.

The primary experiment is **frozen and untouched**. Nothing in this workflow reads,
writes, or depends on the frozen 120-scenario dataset, its ground truth, or any
primary/consistency output. The external answer key lives in its own file and is
loaded **only** by the evaluator, never by the model runners.

---

## 1. Folder layout

```
external_validation/
  config/
    otrf_external_config.json      # run configuration (paths, models, window, seed)
    otrf_dataset_manifest.csv       # YOU fill this: one row per OTRF file you download
  source/                           # YOU place downloaded OTRF telemetry files here
  prepared/
    neutral_inputs/EXT_###.json     # leakage-safe structured summaries (generated)
    frozen_external_manifest.csv    # frozen record of inputs + source/neutral hashes
    external_ground_truth.csv       # SEPARATE answer key (attack/benign + technique)
    adapter_audit.csv               # what evidence was extracted per scenario
    unsupported_fields.csv          # unmapped event IDs / rejected files (honest record)
    preparation_summary.json
  retrieval/
    frozen_otrf_retrieval_plan.jsonl  # frozen deterministic top-k plan (generated)
  outputs_baseline/<model>/...      # raw model outputs, baseline prompting
  outputs_rag/<model>/...           # raw model outputs, knowledge-augmented prompting
  evaluation/                       # all metric tables + report (generated)
  logs/
  archive/<UTC_TIMESTAMP>/          # backups made before a frozen artefact is reset (generated)
  tests/                            # offline test suite + synthetic fixtures
```

## 2. What you need to do manually

The pipeline cannot fabricate datasets. You must:

1. **Download real OTRF Security-Datasets Windows host files** (host/endpoint event
   logs, e.g. Security / Sysmon / PowerShell / Defender channels in JSON or JSONL,
   optionally gzip-compressed) from the OTRF Security-Datasets project.
2. **Place each downloaded file** under `external_validation/source/` (subfolders are
   fine).
3. **Fill in `config/otrf_dataset_manifest.csv`** — one row per file. Replace every
   `FILL_IN_*` / `PUT_THE_DATASET_FILE_HERE` placeholder. Template rows that still
   contain placeholders, or that repeat an `external_scenario_id` already used, are
   skipped automatically, so nothing is invented and nothing is silently duplicated.
4. *(Optional)* `pip install scipy` for the Wilcoxon path in the wider toolchain; the
   external evaluator's own statistics (bootstrap CIs, exact McNemar, Holm) are pure
   Python and need no third-party packages.

### Manifest columns

| column | meaning |
|---|---|
| `external_scenario_id` | your ID, e.g. `EXT_001` (must be unique in the manifest) |
| `source_dataset_id` | OTRF dataset identifier |
| `source_title` | short human title |
| `source_relative_path` | path **relative to `external_validation/source/`** (or the config's `source_dir`), e.g. `EXT_001/apt29_host.jsonl`. An **absolute** path is used as-is; anything else is NOT resolved relative to the repository root. |
| `source_url_if_known` | provenance URL (optional) |
| `platform` | `windows` |
| `attack_or_benign_label` | `attack` or `benign` — the OTRF-provided label |
| `attack_technique_if_provided` | e.g. `T1059.001` (optional) |
| `severity_if_provided` | only if OTRF states one; otherwise leave blank |
| `selection_reason` | why you chose this file |
| `telemetry_format` | `json` / `jsonl` / `json.gz` / `jsonl.gz` / `zip` |

The raw label is preserved verbatim in `external_ground_truth.csv`
(`external_label_raw`), alongside a normalised binary `external_class`
(`abnormal`/`benign`/**`unknown`**) used only for scoring. A label that does not map
to a recognised attack/benign synonym is `unknown` and is **excluded** from the
abnormal/benign detection metrics and from the baseline-vs-RAG comparison — it is
never defaulted to `abnormal`. No 7-category label and no severity are invented.

## 3. Supported source formats

`.json` (single object or array), `.jsonl` (one event per line), and gzip / zip
variants (`.json.gz`, `.jsonl.gz`, `.gz`, single-member `.zip`). Anything else fails
loudly and is recorded in `unsupported_fields.csv` rather than being silently
guessed.

**Malformed / empty / zero-supported-event files are rejected, not silently
accepted.** The adapter tracks, per file: total parsed lines, malformed line count,
and how many parsed events mapped to a recognised evidence family ("supported")
versus fell outside every recognised family ("ignored"). A file that parses to zero
events (including a completely invalid JSON/JSONL file) or that parses fine but has
zero *supported* events is skipped with an explicit reason
(`rejected_zero_valid_events` / `rejected_zero_supported_events`) in
`adapter_audit.csv` and `unsupported_fields.csv` — it is never silently turned into a
quiet, misleadingly "normal-looking" neutral input.

## 4. Telemetry availability vs. observation

Each evidence field distinguishes **"this channel was never captured in the source
file"** from **"this channel was captured and showed nothing"**:

- If a source file never contains any event belonging to a given channel/event-ID
  family (e.g. no Windows Defender operational-log events at all), the corresponding
  `event_summary` field is the sentinel string `"not_available"`.
- A field is only ever `false` / `0` when its channel family **was** present in the
  source but no matching positive event occurred there.

This means downstream consumers (the model prompt, the retrieval query builder) can
never mistake "we never looked" for "we looked and it was fine". The neutral input
also carries a `telemetry_availability` block (channel-family booleans only — no
identifiers) recording exactly which families were present, for audit purposes.

## 5. Corrected, narrow telemetry mappings

Every mapping from a raw event to a piece of evidence requires a **specific,
well-attested event ID** (or, for scheduled tasks/services, a specific ID *within* a
specific channel). Broad "any event whose channel name contains X" catch-alls have
been removed for Defender, Firewall, PowerShell and USB, because the mere presence
of an event in that channel did not support the conclusion previously drawn from it
(e.g. a routine Defender signature-update event does not support "Defender was
disabled"; a PowerShell engine-start event does not support "a script executed").
See `otrf_adapter.py::extract_evidence` for the exact ID list and the reasoning
comment above each mapping. Defender malware-detection events (1116/1117) are now
recorded as their own `malware_detected` evidence rather than folded into
`defender_config_changed` (they are detections, not configuration changes).

## 6. Running the workflow

Run from `scripts/runs_otrf/`. Config paths inside the JSON are **repository-root
relative**, so the same commands work regardless of the current directory.

**Windows (PowerShell / cmd), from `scripts\runs_otrf\`:**

```
python 8-prepare-otrf-external.py        --config ..\..\external_validation\config\otrf_external_config.json
python 8-freeze-otrf-retrieval-plan.py   --config ..\..\external_validation\config\otrf_external_config.json
python 9-run-otrf-baseline.py            --config ..\..\external_validation\config\otrf_external_config.json
python 10-run-otrf-rag.py                --config ..\..\external_validation\config\otrf_external_config.json
python 11-evaluate-otrf-external.py      --config ..\..\external_validation\config\otrf_external_config.json
```

**macOS / Linux, from `scripts/runs_otrf/`:** identical, with `../../` separators.

Steps 9 and 10 require a local Ollama server with the five models pulled
(`llama3`, `deepseek-r1:8b`, `gemma3:12b`, `qwen3:8b`, `gpt-oss:20b`). Steps 8 and 11
need no Ollama.

### Order matters

`prepare` → `freeze-retrieval-plan` → `baseline` and `rag` (any order) → `evaluate`.
The RAG runner **refuses to run** unless the frozen retrieval plan exists, so
retrieval can never silently drift between runs.

### Resume, overwrite and duplicate protection

- Model runners are resumable: re-running continues from where a `..._raw.jsonl`
  stopped and never duplicates a completed scenario (`completed_ids()` is checked
  before every write). Use `--overwrite` to discard and regenerate a model's outputs.
- `prepare` and `freeze-retrieval-plan` refuse to clobber an existing frozen artefact
  unless `--overwrite` is given, protecting a completed external run the same way the
  primary experiment is protected.
- `prepare --overwrite` **reconciles `neutral_inputs/` strictly against the active
  manifest**: any `EXT_*.json` whose scenario id is no longer in the manifest is
  printed and removed. No stale scenario file can survive an overwrite.
- Runners (`9`, `10`) and the retrieval freezer load scenario ids **only from the
  frozen manifest**, never from a directory listing of `neutral_inputs/` — a stray
  leftover file can never silently get processed.
- The evaluator fails by default if any model produced **duplicate** records for the
  same scenario id (`--allow-duplicates` overrides, evaluating on the first record
  only — not recommended).

## 7. Integrity enforcement (SHA-256, fail-by-default)

SHA-256 hashes are recorded at prepare/freeze time and **re-verified, failing by
default on drift**, for:

- every source dataset file (`source_hash` in the frozen manifest);
- every neutral input (`neutral_input_hash` in the frozen manifest);
- the knowledge-base documents and the prepared neutral inputs, as recorded in the
  frozen retrieval plan header (`kb_documents_hash` / `neutral_inputs_hash`);
- the run configuration (`config_hash`, recorded in the preparation summary and the
  retrieval plan header).

`9-run-otrf-baseline.py`, `10-run-otrf-rag.py`, `8-freeze-otrf-retrieval-plan.py` and
`11-evaluate-otrf-external.py` all run this check before doing anything else, and
**raise and stop** if a hash no longer matches, or if the RAG runner's frozen plan
references a knowledge-base document that no longer exists. Every one of these
scripts accepts `--allow-hash-drift` to proceed anyway (never silent: the violations
are always printed first).

## 8. Retrieval: exact match with the primary implementation, one documented difference

`otrf_common.py`'s `retrieve()`, `build_query_features()` scoring, `parse_kb_document()`
and `load_knowledge_base()` are transcribed **verbatim** from
`scripts/runs/3-run_rag.py`. There is exactly **one** intentional difference,
explicitly versioned (`otrf_common.RETRIEVAL_IMPLEMENTATION_VERSION`) and documented
in `otrf_common.RETRIEVAL_DIFFERENCES_FROM_PRIMARY`:

> `_INACTIVE_STRINGS` here additionally excludes the sentinel string
> `"not_available"` from becoming a retrieval feature. The primary pipeline's neutral
> inputs never contain that literal string in `event_summary`; only the OTRF adapter
> emits it (see section 4). Without this addition, the availability sentinel would be
> treated as an active query word/field, biasing retrieval toward documents that
> happen to share vocabulary with "not available" — an artefact of the OTRF-specific
> sentinel, not a real behavioural signal.

No other functional difference exists between the two retrieval implementations.

## 9. Evaluator denominators (fixed)

- **Missing output is not a fallback.** A scenario with no model record at all is
  counted as `missing_output`, reported separately (`missing_output_rate`,
  `output_coverage_rate`) from `fallback_rate` (present-but-schema-invalid records).
  Both still count as an abnormal miss / benign non-true-negative where applicable,
  and both remain in every denominator.
- **Unknown ground truth is not abnormal.** Scenarios whose manifest label mapped to
  `unknown` are excluded from `n_abnormal`/`n_benign` and from the paired
  baseline-vs-RAG correctness used for McNemar; they are never defaulted to
  abnormal.
- **Duplicate outputs fail evaluation by default** (`--allow-duplicates` overrides).
- **Hash mismatches fail evaluation by default** (`--allow-hash-drift` overrides).
- **Invalid and missing predictions remain in the expected denominator** (the full
  frozen-manifest scenario count), never dropped.
- **Benign invalid/missing outputs count as unsuccessful predictions** against
  specificity whenever specificity is estimable (they are not silently excluded from
  the benign subset the way "only usable predictions count" would do).
- **Output coverage is reported separately** (`output_coverage_rate` in
  `output_reliability.csv` and `model_condition_metrics.csv`) from validity/
  correctness rates, so a low coverage rate can never be mistaken for a correctness
  result.

## 10. Metrics reported

Because OTRF host captures are **abnormal-dominated**, the evaluator leads with the
metrics that are defensible on such a sample and marks the rest `not_estimable`:

- **Primary:** abnormal-class **recall** and **false-negative rate** (with bootstrap
  CIs, seed 2026), because a missed genuine risk is the costly error; JSON validity
  and other operational-reliability rates; output coverage; latency; and indicator
  vocabulary (in-vocabulary vs out-of-vocabulary rates, exact canonical-token
  matching only).
- **Conditional:** precision, specificity, and balanced accuracy are computed **only**
  if a defensible benign subset is present; otherwise `not_estimable`.
- **Severity accuracy** is `not_estimable` unless OTRF provides a defensible severity
  key.
- **Indicator grounding against an expected-indicator list** is `not_estimable`
  because OTRF captures carry no researcher-defined expected indicators; only
  in-vocabulary/out-of-vocabulary behaviour is reported.
- Invalid or missing model outputs are **kept in the denominator** and counted as
  abnormal misses (conservative), never dropped.
- Baseline vs RAG is compared per model with an **exact McNemar test** and **Holm**
  correction across models; small discordant counts are reported as descriptive.

## 11. Integrity and reproducibility guarantees

- Model inputs are **leakage-safe**: only structured booleans, counts, and
  categoricals. No raw command lines, script text, filenames, paths, usernames,
  hostnames, IPs, dataset titles, or ATT&CK IDs reach the model. A leakage gate blocks
  any scenario that would violate this.
- The **answer key is physically separate** and is never read by the runners
  (enforced and tested).
- Source and neutral-input **SHA-256 hashes** are frozen in the manifest and
  re-verified, failing by default on drift, before every run/evaluate step (section 7).
- Retrieval is **deterministic** and frozen to a plan file; identical inputs always
  produce an identical plan; the plan's own KB/inputs hashes are re-verified too.
- All randomness (bootstrap) is **seeded** (2026).
- Absent evidence is recorded as `false`/empty/`not_available`, never asserted as a
  positive signal, and telemetry **availability** is tracked separately from
  telemetry **observation** (section 4).

## 12. Safe folder cleanup

`scripts/runs_otrf/12-cleanup-otrf-workspace.py` cleans **only** a fixed allowlist of
generated/temporary OTRF paths (`prepared/neutral_inputs/`, `outputs_baseline/`,
`outputs_rag/`, `evaluation/`, `logs/`, `retrieval/`, test tmp dirs, and OTRF-scoped
`__pycache__`/`.pytest_cache`). It never walks or deletes anything outside that list,
never touches `external_validation/source/` or `config/`, and never touches the
frozen 120-scenario primary experiment.

```
python 12-cleanup-otrf-workspace.py --dry-run
python 12-cleanup-otrf-workspace.py --confirm-clean
python 12-cleanup-otrf-workspace.py --confirm-clean --targets outputs_baseline outputs_rag
```

- Without `--confirm-clean`, the script always behaves as a dry run (prints what it
  would remove, deletes nothing), regardless of `--dry-run`.
- Every path selected for deletion is printed before deletion, in both modes.
- The frozen manifest / ground truth / retrieval plan are **only** touched via the
  separate `--reset-frozen` flag, which **always** copies them to
  `external_validation/archive/<UTC_TIMESTAMP>/` first.

## 13. Offline tests

```
python -m pytest external_validation/tests/ -q          # if pytest is installed
python external_validation/tests/test_otrf_external.py  # no pytest needed
```

The suite runs without Ollama and without network access. It covers leakage removal,
answer-key exclusion from inputs, unsupported-format handling, malformed/empty/
zero-supported-event rejection, telemetry-availability gating, exact canonical-token
matching (and substring getting no credit), out-of-vocabulary retention, parse-vs-strict
validity, placeholder-echo rejection, hash and retrieval determinism and drift
detection, seeded bootstrap reproducibility, exact McNemar counts, resume/overwrite/
duplicate-protection behaviour, source-path resolution, manifest-only scenario
processing, evaluator denominator corrections, cleanup dry-run/confirm/archive
behaviour, and confirmation that the new code never writes to the frozen primary
experiment.

**These offline tests use small synthetic fixtures only.** They verify the pipeline's
mechanics (parsing, hashing, matching, denominators); they are not dissertation
evidence and are never a substitute for running real OTRF telemetry through the
prepare → freeze → baseline/RAG → evaluate workflow.

---

## Dissertation methodology note (draft)

> To test whether the evaluation pipeline transports beyond the researcher-constructed
> scenarios, a supplementary external-validation study was conducted using independent
> Windows host telemetry from the Open Threat Research Forge (OTRF) Security-Datasets
> project. Each downloaded capture was converted, through the same adapter used for the
> primary experiment, into a leakage-safe structured behaviour summary containing only
> derived counts, boolean signals, and categorical fields; no raw command lines, script
> contents, identifiers, or network addresses were exposed to the models. Fields whose
> underlying telemetry channel was absent from a given capture were marked "not
> available" rather than asserted false, so that channel coverage gaps could never be
> mistaken for a negative observation. The five locally deployed models were evaluated
> under both baseline and knowledge-augmented prompting, using a deterministic frozen
> retrieval plan and the identical output schema, JSON-validity checks, and exact
> canonical-token indicator matching applied in the primary study. Ground-truth labels
> were taken from the OTRF-provided attack/benign annotations, held in a separate
> answer key that the model runners never access, and were mapped to the binary
> abnormal/normal decision only at evaluation time; labels that did not map cleanly to
> either class were excluded from the detection metrics rather than assumed abnormal.

## Dissertation limitations note (draft)

> The external-validation sample is abnormal-dominated and modest in size, so precision,
> specificity, balanced accuracy, and severity accuracy are reported only where a
> defensible subset exists and are otherwise marked as not estimable; the analysis
> therefore leads with abnormal-class recall and false-negative rate, which are the
> operationally important quantities for a risk-detection aid. OTRF captures are
> controlled adversary-simulation datasets rather than production logs, and they carry
> no researcher-defined expected-indicator lists, so indicator quality is assessed only
> as in-vocabulary versus out-of-vocabulary behaviour. Invalid and missing outputs are
> retained in all denominators as conservative misses, and output coverage is reported
> separately from correctness so the two are never conflated. The adapter's
> event-to-evidence mappings are deliberately conservative (specific event IDs only,
> no channel-wide inference), which means some genuinely risky behaviour that a
> broader heuristic might have flagged is instead recorded as "not available" or left
> unmapped; this trades recall of the ADAPTER for precision of the EVIDENCE it does
> report, and is a deliberate, documented choice rather than an oversight. Accordingly,
> the external results should be read as evidence that the pipeline and the local
> models transport to independently produced endpoint telemetry, not as evidence of
> real-world deployment effectiveness or of general organisational applicability.
