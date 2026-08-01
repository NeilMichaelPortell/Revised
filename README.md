# Real-Time Detection and Adaptive Analysis of Risky User Actions on Endpoints

Research repository for an MCAST dissertation investigating whether **locally
deployed large language models** can classify risky Windows endpoint behaviour
from structured, privacy-preserving activity summaries, and whether adding a
curated knowledge base to the prompt changes that behaviour.

All model inference runs **entirely on the local machine** through
[Ollama](https://ollama.com). No endpoint data, prompt or scenario is ever sent
to a cloud or external service.

---

## 1. Project overview

The repository contains a controlled, offline experiment and its supporting
artefacts:

* A **frozen dataset** of 120 Windows endpoint scenarios, reduced to
  leakage-safe structured summaries.
* A **curated knowledge base** of 34 indexed analyst records used for
  knowledge-augmented (RAG) prompting.
* **Five locally deployed LLMs** run over every scenario under two prompt
  conditions (baseline and knowledge-augmented).
* **Evaluation, comparison and consistency pipelines** that write canonical
  result tables under [results/](results/).
* A **supplementary external-validation study** over independent third-party
  telemetry from the Open Threat Research Forge (OTRF) Security-Datasets
  project, under [external_validation/](external_validation/).
* A **real-time endpoint prototype** under [prototype/](prototype/) that
  demonstrates the feedback layer end-to-end on a live Windows machine.

The prototype is a proof-of-concept demonstration. **The main evaluation in this
dissertation is the controlled offline experiment**, not the prototype.

## 2. Research objectives

1. Determine whether locally deployed LLMs can distinguish normal from abnormal
   endpoint activity when given only structured, non-identifying behaviour
   summaries.
2. Measure how reliably each model produces machine-usable, schema-valid output.
3. Test whether injecting retrieved analyst guidance (knowledge-augmented
   prompting) changes classification behaviour relative to a baseline prompt,
   and whether any change is statistically supportable.
4. Measure whether models return **stable** answers when the same input is
   repeated under fixed inference settings.
5. Check whether the pipeline **transports** to endpoint telemetry the
   researcher did not design.

## 3. Experimental design

The design is a **paired, within-subject comparison**: every model sees every
scenario under both prompt conditions, so baseline and knowledge-augmented
results are directly comparable per scenario.

| Property | Value |
|---|---|
| Scenarios | 120 (`R001`–`R120`) |
| Models | 5, all local via Ollama |
| Conditions | `baseline`, `rag` (knowledge-augmented) |
| Temperature | 0 (deterministic decoding) |
| Context window | 4096 (8192 for `gpt-oss:20b`) |
| Output budget | 1024–4096 tokens, per model |
| Per-call timeout | 300 s |
| Retries on unusable JSON | 2 |
| Retrieval | deterministic weighted keyword scoring, `top_k = 3` |
| Consistency sub-study | 20 scenarios × 5 repetitions × 5 models × 2 conditions |
| Selection / bootstrap seed | 2026 |

**Leakage safety.** Models only ever receive `Dataset/llm_inputs/R###.json`,
which contains `context_state` and `event_summary` only — no scenario ID, no
category, no scenario name, no ground-truth label, no expected indicators. The
ground truth is joined in **after** inference, purely for scoring.

Each model is fully unloaded and warm-reloaded between runs so that latency
figures are not distorted by a cold or shared VRAM state.

Models return a fixed JSON schema: `classification`, `risk_level`, `indicators`,
`explanation`, `recommended_action`.

## 4. Dataset

Located in [Dataset/](Dataset/). The dataset was collected observe-only on a
Windows test machine using [scripts/dataset/1-endpoint_collector.py](scripts/dataset/1-endpoint_collector.py),
then segmented into per-scenario summaries by
[scripts/dataset/2-segment_logs.py](scripts/dataset/2-segment_logs.py).

* **120 scenarios**, balanced between classes: **62 normal / 58 abnormal**.
* Provenance: 108 collected live, 12 augmented (constructed rather than
  captured); recorded in `provenance_report.csv`.
* Seven categories:

  | Code | Category | Scenarios |
  |---|---|---|
  | `AUTH` | Authentication | 17 |
  | `NET` | Network | 17 |
  | `NORMAL` | Normal activity | 18 |
  | `PERSIST` | Persistence | 17 |
  | `PROC` | Process activity | 17 |
  | `SEC` | Security controls | 17 |
  | `USB` | USB activity | 17 |

Key files:

| File | Purpose |
|---|---|
| `llm_inputs/R001.json` … `R120.json` | Leakage-safe model inputs |
| `llm_inputs_120.jsonl` | The same inputs as a single JSONL file |
| `runner_mapping.csv` | Maps record IDs back to scenario IDs (scoring only) |
| `ground_truth_FINAL.csv` | Frozen labels — **never** placed in a prompt |
| `scenario_summaries/` | Full reviewed evidence (provenance record, not model input) |
| `controlled_indicator_vocabulary.csv` | Canonical indicator token list |
| `schema_definition.json` | Scenario schema |
| `validation_report.*`, `*_audit.csv` | Dataset integrity audits |

The collector never records keystrokes, screenshots, passwords, clipboard
contents, file contents, tokens, cookies, packet captures or full browser
history.

## 5. Models evaluated

Five locally deployed models, pulled with `ollama pull`:

| Model | Ollama tag |
|---|---|
| Llama 3 | `llama3` |
| DeepSeek R1 8B | `deepseek-r1:8b` |
| Gemma 3 12B | `gemma3:12b` |
| GPT-OSS 20B | `gpt-oss:20b` |
| Qwen 3 8B | `qwen3:8b` |

Reasoning-heavy models (`deepseek-r1:8b`, `qwen3:8b`, `gpt-oss:20b`) are given a
larger output budget so their chain-of-thought can complete *and* still reach a
closing JSON object. `gpt-oss:20b` is deliberately **not** constrained with
Ollama's `format: json`, because that constraint corrupts its output; its JSON is
extracted from surrounding prose instead.

The runs recorded in this repository were executed on Windows with an NVIDIA
GeForce RTX 4060 Laptop GPU (see `results/consistency/reports/run_manifest.json`).

## 6. Baseline versus knowledge-augmented prompting

**Baseline.** The model receives the neutral scenario JSON and the required
output schema. Nothing else — no category hint, no guidance, no examples.

**Knowledge-augmented (RAG).** The identical baseline prompt, plus up to three
retrieved documents from [knowledge_base/](knowledge_base/).

* Retrieval is **deterministic weighted keyword/token scoring** — no embeddings,
  no neural retriever, no ML component.
* The query is built only from *active* evidence in the neutral input; ambient
  normal context is excluded. No scenario ID, category, name, ground truth,
  expected indicators or label reason ever enters the query.
* `top_k = 3`; zero-scoring documents are not injected.
* The retrieval plan is **computed once and frozen**
  (`results/rag/retrieval_plan.json`), then reused identically for all five
  models, so retrieval cannot drift between models or runs.
* Only the seven category folders are indexed (34 records: NORMAL 4, AUTH 5,
  USB 5, SEC 5, PROC 5, NET 5, PERSIST 5). `GLOBAL/`, `audits/` and
  `_archive_not_indexed/` are **not** retrieved.

**The effect of RAG is model-dependent.** It is not a universal improvement.
The paired analysis in
[results/comparison/COMPARISON_REPORT.md](results/comparison/COMPARISON_REPORT.md)
reports, per model, exact McNemar tests with Holm–Bonferroni correction across
the five models: one model improves significantly, one deteriorates
significantly, and three show no statistically significant change. Any claim
about RAG in this project must be made **per model**, with the direction and the
corrected p-value stated. Consult the canonical report rather than assuming a
direction.

## 7. Evaluation metrics

Generated by [scripts/runs/2-evaluate_results.py](scripts/runs/2-evaluate_results.py)
and [scripts/runs/4-compare_baseline_vs_rag.py](scripts/runs/4-compare_baseline_vs_rag.py).

**Recall is the metric of primary interest.** A false negative means a genuinely
risky endpoint action was *not* flagged — abnormal activity that the system
missed and that no downstream control or user prompt would ever see. In an
endpoint-security aid, a missed risk is the costly error. Precision matters as an
alert-fatigue guard, but recall is what the design is judged on.

Every one of the 120 expected scenarios falls into exactly one mutually
exclusive category, per model, per condition:

| Category | Meaning |
|---|---|
| `valid_correct` | Schema-valid, committed classification, matches ground truth |
| `valid_incorrect` | Schema-valid, committed classification, wrong |
| `invalid` | Parseable JSON but a non-committal / placeholder classification |
| `missing` | No record exists at all |
| `fallback` | A record exists but never reached basic schema validity |

**Invalid, missing and fallback outputs are never dropped from a denominator.**
They count as unsuccessful, and abnormal scenarios in those buckets count as
missed detections. This is deliberate: an earlier design that scored only
"classifiable" responses silently rewarded a model for refusing to commit.

* **Primary metrics:** all-scenario accuracy (correct / 120) and
  coverage-adjusted recall, false-negative rate, specificity, balanced accuracy
  and F1, with denominators fixed to the full ground-truth counts (58 abnormal /
  62 normal).
* **Secondary (diagnostic only):** valid-output accuracy, committed-output
  precision, valid-output recall/F1 and Cohen's κ over committed outputs. These
  answer "how good is it *when* it commits" and must never be quoted as the
  headline result.
* **Also reported:** risk-level accuracy, indicator overlap against the expected
  indicator list (strict exact-token and lenient), JSON validity rate, and
  latency.
* **Significance:** exact McNemar per model on paired correctness, with
  Holm–Bonferroni correction across the five models.

### Consistency

[scripts/runs/7-evaluate_consistency.py](scripts/runs/7-evaluate_consistency.py)
measures **stability**: classification and risk agreement rates across
repetitions, mean pairwise indicator Jaccard, explanation similarity, schema
validity, retry/timeout/empty rates, and latency coefficient of variation, with
bootstrap confidence intervals (10 000 iterations, seed 2026) and Wilcoxon
signed-rank tests with Holm correction.

> **Consistency is not correctness.** Stability and accuracy are separate
> properties: a model can be *consistently wrong* or *inconsistently correct*.
> Agreement rates in `results/consistency/` must never be read as evidence that
> a model classified anything correctly. Correctness across repetitions is
> reported separately as `classification_accuracy_across_repetitions`.

## 8. Repository structure

```text
.
|-- Dataset/                  Frozen 120-scenario dataset, ground truth, audits
|   |-- llm_inputs/           Leakage-safe model inputs (R001-R120)
|   `-- scenario_summaries/   Full reviewed evidence (provenance record)
|-- knowledge_base/           Curated analyst records for the RAG condition
|   |-- AUTH/ NET/ NORMAL/ PERSIST/ PROC/ SEC/ USB/   Indexed for retrieval
|   |-- GLOBAL/ audits/       Not indexed
|   `-- _archive_not_indexed/ Superseded drafts, retained for provenance
|-- scripts/
|   |-- dataset/              Endpoint collector + log segmenter
|   |-- runs/                 Main experiment pipeline (0-7) + tests/
|   `-- runs_otrf/            External OTRF validation pipeline (8-12)
|-- results/                  CANONICAL experiment outputs
|   |-- baseline/             Baseline outputs + baseline-only evaluation
|   |-- rag/                  Knowledge-augmented outputs + frozen retrieval plan
|   |-- comparison/           Paired baseline-vs-RAG analysis
|   `-- consistency/          Repeated-run outputs and consistency reports
|-- external_validation/      Supplementary OTRF study (see section 12)
|-- prototype/                Real-time Windows endpoint prototype
|-- docs/
|   |-- final_audit/          Canonical paths, evidence inventory, frozen hashes
|   `-- evidence/             Manually captured experiment transcripts
`-- commands.txt              Quick command reference
```

`results/` is authoritative. Legacy root-level output directories that once
shadowed it have been removed from version control; see
[docs/final_audit/CANONICAL_ARTIFACT_PATHS.md](docs/final_audit/CANONICAL_ARTIFACT_PATHS.md)
for exactly which copy was authoritative and what happened to each.

## 9. Installation

Developed and run on **Windows 11 with Python 3.13**. Commands below are Windows
PowerShell.

```powershell
# Clone
git clone https://github.com/NeilMichaelPortell/Revised.git
cd Revised

# Virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1
```

The experiment pipeline, the evaluators, the consistency runners and every test
suite use **only the Python standard library**. Nothing needs to be installed to
reproduce the evaluation from the stored outputs.

Optional extras:

```powershell
# Only if you want to re-run the LIVE prototype on a Windows machine
pip install -r prototype\requirements.txt        # psutil, pywin32, wmi

# Only if you want pytest's runner (the suites also run as plain scripts)
pip install pytest

# Optional: the Wilcoxon path in the wider toolchain
pip install scipy
```

To re-run model inference you additionally need a local Ollama server with the
five models pulled:

```powershell
ollama pull llama3
ollama pull deepseek-r1:8b
ollama pull gemma3:12b
ollama pull qwen3:8b
ollama pull gpt-oss:20b
```

Ollama is reached at `http://localhost:11434`; override with the `OLLAMA_HOST`
environment variable. `localhost` is this computer only and is not reachable
from the internet — the runs work with the network disconnected, which can be
used to verify the privacy claim.

## 10. Running the main experiments

Re-running steps 1, 3, 5 and 6 performs **hours of local model inference** and
overwrites canonical outputs under `results/`. Steps 2, 4 and 7 are pure
analysis and need no Ollama.

```powershell
.\venv\Scripts\Activate.ps1
cd scripts\runs

python 0-test.py                        # smoke test: 3 scenarios, all models
python 1-run_baseline.py                # BASELINE inference   (needs Ollama)
python 2-evaluate_results.py            # baseline evaluation  (analysis only)
python 3-run_rag.py                     # RAG inference        (needs Ollama)
python 4-compare_baseline_vs_rag.py     # paired comparison    (analysis only)
```

Useful flags on the runners:

```powershell
python 1-run_baseline.py --limit 3      # first 3 scenarios only
python 1-run_baseline.py --models llama3
```

Dataset regeneration (Windows test machine, admin recommended) is separate and
is **not** part of reproducing the evaluation:

```powershell
cd scripts\dataset
python 1-endpoint_collector.py
python 2-segment_logs.py
```

## 11. Running the consistency experiments

The consistency study repeats a seeded 20-scenario selection five times per
model per condition. It writes **only** to `results/consistency/` and never
touches `results/baseline/` or `results/rag/`.

```powershell
cd scripts\runs

python 5-run_consistency_baseline.py    # needs Ollama
python 6-run_consistency_rag.py         # needs Ollama
python 7-evaluate_consistency.py        # analysis only
```

```powershell
# Options
python 5-run_consistency_baseline.py --models llama3
python 5-run_consistency_baseline.py --repetitions 5
python 5-run_consistency_baseline.py --limit 2 --repetitions 2
python 5-run_consistency_baseline.py --resume
python 5-run_consistency_baseline.py --overwrite
```

An existing `consistency_selection.csv` is reused rather than regenerated, so
the scenario selection cannot drift between the baseline and RAG halves of the
study.

## 12. External OTRF validation

[external_validation/](external_validation/) holds a **supplementary** study that
runs the same models, prompt modes and evaluation logic over **independent
third-party Windows endpoint telemetry** from the OTRF Security-Datasets
project. Its purpose is to check whether the pipeline *transports* to endpoint
data the researcher did not design.

* **18 prepared OTRF-derived scenarios** (`EXT_001`–`EXT_018`), listed in
  `external_validation/prepared/frozen_external_manifest.csv`.
* **Raw OTRF captures are intentionally excluded from Git.** They are
  third-party data, downloaded locally. Only
  `external_validation/source/README.md` is tracked; `.gitignore` blocks
  everything else under `source/`, and the raw OTRF checkout
  (`Security-Datasets-master/`) is ignored entirely.
* **Source URLs and SHA-256 hashes are preserved** in the frozen manifest
  (`source_url_if_known`, `source_hash`, `neutral_input_hash`), so every input is
  independently re-obtainable and verifiable without redistributing the data.
* **The neutral external-validation inputs are tracked**
  (`external_validation/prepared/neutral_inputs/EXT_###.json`). These are
  leakage-safe derived summaries — booleans, counts and categoricals only — with
  no raw command lines, filenames, paths, usernames, hostnames, IP addresses,
  dataset titles or ATT&CK IDs.
* Telemetry **availability** is tracked separately from telemetry
  **observation**: a channel that was never captured is marked `not_available`,
  never `false`, so "we never looked" cannot be mistaken for "we looked and it
  was fine".
* The answer key (`external_ground_truth.csv`) is physically separate and is
  never read by the model runners.

```powershell
.\venv\Scripts\Activate.ps1
cd scripts\runs_otrf

python 8-prepare-otrf-external.py      --config ..\..\external_validation\config\otrf_external_config.json
python 8-freeze-otrf-retrieval-plan.py --config ..\..\external_validation\config\otrf_external_config.json
python 9-run-otrf-baseline.py          --config ..\..\external_validation\config\otrf_external_config.json   # needs Ollama
python 10-run-otrf-rag.py              --config ..\..\external_validation\config\otrf_external_config.json   # needs Ollama
python 11-evaluate-otrf-external.py    --config ..\..\external_validation\config\otrf_external_config.json
```

Order matters: `prepare` → `freeze-retrieval-plan` → `baseline`/`rag` →
`evaluate`. The RAG runner refuses to start without a frozen retrieval plan.
Steps 8 and 11 need no Ollama.

Because OTRF host captures are abnormal-dominated, the external evaluator leads
with **abnormal-class recall and false-negative rate** and marks precision,
specificity, balanced accuracy and severity accuracy `not_estimable` unless a
defensible benign subset exists. See
[external_validation/README.md](external_validation/README.md) for the full
contract, including the single documented retrieval difference from the primary
implementation.

> OTRF datasets are controlled, publicly released adversary-simulation captures,
> not production enterprise logs. Results demonstrate **technical
> transportability of the pipeline**, not real-world deployment performance.

## 13. Reproducibility and frozen artefacts

* **Deterministic decoding.** Temperature 0 for every model, every run.
* **Seeded selection and statistics.** Selection seed 2026; bootstrap seed 2026;
  dataset shuffle seed 20260710.
* **Frozen retrieval.** `results/rag/retrieval_plan.json` and
  `external_validation/retrieval/frozen_otrf_retrieval_plan.jsonl` are computed
  once and reused, so retrieval can never silently drift.
* **Run manifest.** `results/consistency/reports/run_manifest.json` records
  timestamps, seeds, per-model context and prediction limits, timeout, retry
  policy, GPU, and truncated SHA-256 hashes of the ground truth, dataset,
  knowledge base, controlled vocabulary, evaluator, runners and every prompt.
* **Frozen hash ledger.** `docs/final_audit/FROZEN_ARTIFACT_HASHES.csv` records
  237 artefacts with repository, canonical-text and original-CRLF SHA-256
  digests, size, line count and newline style, so line-ending normalisation
  cannot be mistaken for content change.
* **Hash enforcement in the external pipeline.** Source, neutral-input,
  knowledge-base, prepared-input and config hashes are re-verified before every
  run and evaluate step, and **fail by default** on drift
  (`--allow-hash-drift` overrides, never silently).
* **Canonical path resolution.** `docs/final_audit/CANONICAL_ARTIFACT_PATHS.md`
  and `EVIDENCE_INVENTORY.md` document which copy of each artefact is
  authoritative.

Reproducing the *evaluation* from stored outputs requires no Ollama, no network
and no third-party packages: run steps 2, 4, 7 and 11 above.

## 14. Privacy, ethics and safety

* **Fully local inference.** Every model runs on the local machine via Ollama at
  `http://localhost:11434`. No scenario, prompt or endpoint observation leaves
  the device. The pipeline works with the network disconnected.
* **Observe-only collection.** The collector reads state and writes logs. It
  never disables Defender, changes services or scheduled tasks, or edits files.
* **Never collected.** Keystrokes, screenshots, passwords, clipboard contents,
  file contents, authentication tokens, cookies, packet captures, private
  messages, document contents, or full browser history.
* **Browser data.** Scheme and domain only. Path, query string, fragment and the
  full URL are discarded. If a URL path matches a sensitive keyword (login,
  account, bank, wallet, …) the visit is dropped entirely — not even the domain
  is retained. Page titles are not collected. Domain grouping is local; no
  external lookup service is used.
* **Leakage gates.** Model inputs in both the primary and external pipelines are
  structured summaries only. A leakage gate blocks any external scenario that
  would expose raw identifiers.
* **Contamination control.** The collector's own PowerShell probes are tagged and
  excluded from scenario evidence, and the count of filtered events is reported.
* **Third-party data.** Raw OTRF captures are not redistributed here; only their
  URLs and hashes are recorded.
* **Self-collected data.** The dataset was collected by the author on the
  author's own controlled Windows test machine. Generated prototype evidence
  that may embed workstation-specific detail is excluded from version control
  via `.gitignore`.

## 15. Limitations

* **Controlled scenarios, not production traffic.** The 120 scenarios were
  designed and collected by the author on a single Windows test machine. They are
  not a random sample of real endpoint activity, and 12 of the 120 are
  constructed rather than captured.
* **Single machine, single OS.** One hardware configuration, one Windows build,
  one user. Latency figures in particular are hardware-specific.
* **Structured summaries, not raw telemetry.** Models never see raw command
  lines or event logs. Results measure reasoning over *derived evidence*, and
  depend on the quality of the segmenter's extraction.
* **Modest sample size.** 120 scenarios, 5 models. Per-category cells contain
  17–18 scenarios each, so category-level metrics are indicative only.
* **RAG effects are model-dependent** and are not evidence of a general
  property of knowledge-augmented prompting.
* **Consistency is not correctness.** High agreement across repetitions does not
  imply the answers were right.
* **Deterministic keyword retrieval.** No embeddings or learned retriever were
  used; a different retrieval method could produce a different RAG result.
* **The external validation is supplementary.** The OTRF sample is
  abnormal-dominated and modest, so several metrics are reported as
  `not_estimable`; it evidences pipeline transportability, not deployment
  effectiveness.
* **The prototype is a proof of concept.** Its validation runs are supplementary
  and separate from the frozen offline evaluation. Nothing in this repository
  claims production readiness.
* **Ollama and model versions were not captured** in the run manifest
  (`not_available`), so exact model-build reproduction cannot be guaranteed from
  the manifest alone.

## 16. Author

**Neil Michael Portelli**

MCAST dissertation — *Real-Time Detection and Adaptive Analysis of Risky User
Actions on Endpoints*.

Third-party datasets referenced by the supplementary external validation belong
to the [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)
project and are subject to their own licence; they are not redistributed here.
