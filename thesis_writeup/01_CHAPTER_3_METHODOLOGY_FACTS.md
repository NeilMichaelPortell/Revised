# 01 — Chapter 3 Methodology Facts

Documents only what was actually implemented. No performance findings appear
here except where needed to explain a validation rule (e.g. why a placeholder
classification fails validation). Results belong in the Chapter 4 files.

## Research design

A within-subjects, paired comparison: five locally-hosted LLMs (`llama3`,
`deepseek-r1:8b`, `gemma3:12b`, `qwen3:8b`, `gpt-oss:20b`) each classify the
identical 120 neutral scenario inputs under two conditions — **baseline**
(schema + scenario only) and **knowledge-augmented / RAG** (baseline prompt +
top-3 deterministically retrieved knowledge-base documents) — so every
baseline-vs-RAG comparison is exactly paired per scenario, per model.
Supplementary studies: a **consistency study** (repeated-measures reliability)
and an **OTRF external-validation study** (independently sourced public
telemetry), plus a standalone **prototype** feasibility check. Source:
`scripts/runs/1-run_baseline.py`, `3-run_rag.py`.

## 120-scenario composition

120 scenarios: **62 normal / 58 abnormal** (`Dataset/ground_truth_FINAL.csv`).
**Seven evaluation strata** (categories): NORMAL, AUTH, USB, SEC, PROC, NET,
PERSIST. **108 collector-supported** (captured live via the endpoint
collector/browser extension) and **12 augmented** (constructed, not collected
live — `Dataset/provenance_report.csv`). Per-category composition, including
the collected/augmented split, is in
`thesis_writeup/excel_source/dataset_composition.csv`.

## Frozen ground truth

`Dataset/ground_truth_FINAL.csv` is the single authoritative label source
(`scenario_id`, `category`, `ground_truth_class`, `ground_truth_risk`,
`expected_indicators`, `label_reason`, `scenario_source`,
`evaluation_status`, `evidence_basis`). Every evaluator re-joins to this file
by `scenario_id` rather than trusting any label copied into a per-model
review CSV, so scoring has one source of truth that cannot drift between
scripts.

## Controlled indicator vocabulary

`Dataset/controlled_indicator_vocabulary.csv` — 62 canonical indicator
tokens. Every "Expected indicators" entry in the active knowledge base is
drawn from this vocabulary (`knowledge_base/README.md`); model-produced
indicators are canonicalised by **case-folding and trimming outer whitespace
ONLY** — no space-to-underscore folding, no hyphen-to-underscore folding, and
no synonym mapping — and matched by **exact token membership**, never
substring matching. A token that only matches after some other normalisation
(e.g. `"failed login"` or `"failed-login"` against the canonical
`failed_login`) is retained as **out-of-vocabulary**, not silently credited.
This makes in-vocabulary vs out-of-vocabulary indicator use a well-defined,
exact measurement rather than a fuzzy heuristic.

## Active knowledge-base documents

**34 active category documents**: NORMAL 4, AUTH 5, USB 5, SEC 5, PROC 5,
NET 5, PERSIST 5 (`knowledge_base/{category}/*.md`, listed in
`thesis_writeup/excel_source/knowledge_base_composition.csv`). Three
`GLOBAL/` documents and 20 `_archive_not_indexed/` documents exist on disk but
are **not indexed for retrieval** — confirmed structurally in
`3-run_rag.py`'s `CATEGORY_FOLDERS` list, which never includes `GLOBAL`, and
`_archive_not_indexed` is not a category folder.

## Baseline condition

Prompt = fixed output schema (`classification`, `risk_level`, `indicators`,
`explanation`, `recommended_action`) + the leakage-safe neutral scenario
input only. No knowledge-base content, no category hint, no ground truth.

## RAG (knowledge-augmented) condition

The **exact baseline prompt** with a retrieved-context block inserted before
the scenario data — nothing else differs between conditions. Retrieval is
**deterministic, ML-free, weighted keyword/token scoring**: for each
scenario, a query is built only from *active* evidence in the neutral input
(booleans that are true, non-zero numbers, non-empty/non-"none" strings and
lists), prioritising `event_summary` over the always-present ambient
`context_state`. Each of the 34 documents is scored (expected-indicator match
weight 6, Applies-when value match weight 5, Applies-when field match weight
3, title-word match weight 2, body-word match weight 1); the top 3
positive-scoring documents are retrieved; zero-scoring documents are never
injected. Ties break deterministically by document ID. The full plan is
precomputed **once** and reused identically for all five models
(`results/rag/retrieval_plan.json`), so every model sees byte-identical
retrieved context for a given scenario.

## Model settings

All models: `temperature = 0` (deterministic decoding). Context/output budget
is per-model: default `num_ctx=4096, num_predict=1024`; `gpt-oss:20b` gets
`num_ctx=8192, num_predict=4096` and `deepseek-r1:8b` / `qwen3:8b` get
`num_ctx=4096, num_predict=2048`, because these reasoning models emit a
chain-of-thought before the JSON answer and are truncated mid-thought on a
small budget. `format: "json"` constrains every model except `gpt-oss:20b`
(constraining it produced malformed output in practice; its JSON is instead
recovered from free-form prose by a brace-matching extractor). Up to 2
retries on a schema-invalid response. All inference is local via the Ollama
HTTP API on `localhost:11434` — no cloud call is made, and the run works with
the network disconnected. Source: `scripts/runs/1-run_baseline.py`,
`3-run_rag.py`.

## Output parsing and schema validation

Two validity tiers, computed identically for both conditions:

- **Basic schema validity** (`json_valid`): the parsed response is a JSON
  object containing the three required keys `classification`, `risk_level`,
  `indicators`. This drives the retry loop.
- **Strict schema validity**: basic validity **and** `classification` is one
  of `{normal, risky, abnormal}` (excluding placeholders), `risk_level` is one
  of `{low, medium, high, critical}` (excluding placeholders), and
  `indicators` is a list of strings. Logged separately; does **not** change
  the retry rule (fairness across models/conditions).

**Placeholder classifications** such as `"normal or risky"`,
`"normal or abnormal"`, or `"low, medium, high, or critical"` are the model
echoing the schema's own example text back — they pass basic schema validity
(the keys are present) but must **fail** strict/classification validity. This
is why "parseable JSON is not necessarily a valid classification": a response
can be well-formed JSON and still commit to nothing.

## Primary metrics (corrected 2026-07-19)

Every one of the 120 expected scenarios is classified into exactly one of:
**valid_correct**, **valid_incorrect**, **invalid** (schema-valid but a
non-committal/placeholder classification value), **missing** (no record at
all for that scenario), **fallback** (a record exists but never reached basic
schema validity after every retry). Invalid, missing and fallback outputs are
never excluded from a denominator. Full metric definitions, and why the
previous evaluator's exclusion of these categories inflated apparent
reliability, are documented in `results/comparison/COMPARISON_REPORT.md`.
Primary metric: `all_scenario_accuracy` (correct / 120) and
**coverage-adjusted** recall/specificity/F1 (denominators are the full
ground-truth abnormal/normal counts, 58/62). Secondary (diagnostic only):
`valid_output_accuracy`, `committed_output_precision`, `valid_output_recall`,
`valid_output_f1`, `cohens_kappa_valid_outputs` — computed over committed
classifications only.

## Statistical methods

- **Wilson 95% CI** on primary (all-scenario) accuracy.
- **Cohen's kappa** (chance-corrected agreement vs ground truth) over valid
  (committed) classifications only.
- **McNemar's exact test** (paired, per model): of the 120 scenarios, how many
  did only baseline get right vs only RAG (invalid/missing/fallback scored as
  incorrect for both conditions).
- **Holm-Bonferroni step-down correction** applied across the 5 per-model
  McNemar comparisons.
- p-values are never displayed as `0.000`; values below 0.001 are reported as
  `< 0.001`.

## Consistency study

20 scenarios (fixed subset, deterministic selection seed 2026) x 5 repetitions
x 5 models x 2 conditions = **1,000 records**. Measures, kept explicitly
separate: classification stability (agreement rate across repetitions) vs
classification correctness (accuracy vs ground truth across repetitions);
risk-level stability vs correctness; indicator-set consistency (pairwise
Jaccard); explanation similarity (token-set Jaccard); strict schema
reliability; missing/duplicate repetitions (integrity audit); retries and
timeouts; latency variation (coefficient of variation). Invalid output
(`INVALID_CLASSIFICATION`) is retained as an explicit classification value
rather than dropped, so an evaluator computing "agreement" can register a
model as consistently non-committal, not silently exclude it. Holm correction
is applied **per metric family, across the 5 models**, using a Wilcoxon
signed-rank test where SciPy is available, else an exact sign test. Source:
`scripts/runs/5-run_consistency_baseline.py`, `6-run_consistency_rag.py`,
`7-evaluate_consistency.py`.

## OTRF supplementary external validation

18 independently sourced Windows adversary-simulation captures from the
OTRF/Security-Datasets public corpus (all 18 are ground-truth **abnormal** by
construction — atomic-technique emulations). The same baseline/RAG prompts,
model settings, parsing and deterministic retrieval as the primary experiment
are applied verbatim (`scripts/runs_otrf/otrf_common.py` is transcribed from
the primary runners; the one documented divergence is an additional inactive-
value sentinel needed for the OTRF telemetry-availability marker). A frozen
manifest records the SHA-256 of every source file and every derived neutral
input; the evaluator fails by default on any hash drift (`--allow-hash-drift`
exists only to produce an explicitly separate diagnostic report, never the
final evaluation). **As of 2026-07-19 this study is COMPLETE**: all 18/18
source captures and all 18/18 neutral-input hashes are verified against the
frozen manifest (two of the eighteen, EXT_010 and EXT_014, resolve from a
local, untracked OTRF clone via `--source-root` / `OTRF_SOURCE_ROOT` rather
than the tracked `external_validation/source/` tree; both are byte-verified
against the manifest hash before use). The strict evaluation ran with no
override flag (no `--allow-hash-drift`, no `--allow-duplicates`); the
certificate verdict is `PASS`
(`external_validation/evaluation/source_verification_certificate.json`). Raw
OTRF source archives remain **local and untracked** — they are gitignored and
are never committed, staged, or pushed to GitHub; see
`external_validation/source/README.md`. See
`04_CHAPTER_4_EXTERNAL_VALIDATION_RESULTS.md`.

## Prototype validation

A standalone real-time Windows prototype (rule-trigger layer + local LLM
feedback) with a supplementary validation-run harness, entirely separate from
the frozen offline experiment. 15/15 automated unit tests pass
(`prototype/tests/test_validation.py`). One completed live validation run
exists (`prototype/validation_results.csv`); see
`05_CHAPTER_4_PROTOTYPE_RESULTS.md` for what it does and does not demonstrate.

## Privacy and ethics

All inference is local (Ollama on `localhost`); no scenario, prompt or
prediction is sent to any external service, and both the primary and OTRF
pipelines are documented as working with the network disconnected. The
prototype never stores passwords, keystrokes, clipboard contents,
screenshots, file contents or authentication tokens; browser telemetry
retains scheme + domain only, and sensitive-path visits are dropped entirely
before storage (`prototype/README.md`).

## Threats to validity

Summarised in full in `07_THREATS_TO_VALIDITY.md`; referenced here only
because two threats affect how the metrics above must be read: (1) the 12
augmented (non-collected) scenarios are a construct-validity limitation for
generalising to purely organically observed behaviour; (2) the OTRF sample is
abnormal-dominated by construction, so precision/specificity/balanced
accuracy are marked **not estimable** there rather than computed on a
non-representative negative class.
