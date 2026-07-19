# 04 — Chapter 4: OTRF External Validation Results

**STATUS: COMPLETED (strict mode) — 2026-07-19.** All 18 raw OTRF source
captures were located in a local, untracked OTRF clone, hash-verified against
the frozen manifest (18/18 source hashes + 18/18 neutral-input hashes match),
and the evaluator ran to completion **without** `--allow-hash-drift` or
`--allow-duplicates`. Certificate: `external_validation/evaluation/
source_verification_certificate.json` (verdict PASS).

Source CSVs: `external_validation/evaluation/model_condition_metrics.csv`,
`abnormal_detection_results.csv`, `output_reliability.csv`,
`indicator_results.csv`, `out_of_vocabulary_indicators.csv`,
`latency_results.csv`, `baseline_vs_rag_comparison.csv`,
`external_validation_report.md`, `validation_summary.json`. Excel-ready copies:
`thesis_writeup/excel_source/otrf_model_condition_metrics.csv`,
`otrf_reliability.csv`.

**Framing (mandatory):** OTRF is controlled, independently sourced public
adversary-simulation telemetry. These results demonstrate **technical
transportability** of the implemented pipeline to independently sourced
controlled public telemetry — **not** organisational real-world
generalisability. All 18 selected scenarios are ground-truth **abnormal** by
construction (atomic-technique emulations), so precision, specificity,
balanced accuracy, benign false-positive rate and severity accuracy are
reported as **not estimable** (no defensibly benign subset, no defensible
external severity key).

## Sample composition

- External scenarios: 18 (all abnormal), 0 benign, 0 unknown ground truth.
- Missing outputs: 0. Duplicate outputs: 0. Manifest hash mismatches: 0.
- Output coverage: 1.000 for every model/condition (all 180 records present).

## 1. Abnormal detection (recall + false-negative rate)

Invalid, missing and fallback outputs are counted as misses (conservative).
Source: `abnormal_detection_results.csv`. n_abnormal = 18 per cell.

| Model | Condition | TP | FN | Abnormal recall | 95% CI | FN rate |
|---|---|---|---|---|---|---|
| llama3 | baseline | 12 | 6 | 0.667 | [0.444, 0.889] | 0.333 |
| llama3 | rag | 14 | 4 | 0.778 | [0.556, 0.944] | 0.222 |
| deepseek-r1:8b | baseline | 12 | 6 | 0.667 | [0.444, 0.889] | 0.333 |
| deepseek-r1:8b | rag | 13 | 5 | 0.722 | [0.500, 0.889] | 0.278 |
| gemma3:12b | baseline | 15 | 3 | 0.833 | [0.667, 1.000] | 0.167 |
| gemma3:12b | rag | 14 | 4 | 0.778 | [0.556, 0.944] | 0.222 |
| qwen3:8b | baseline | 8 | 10 | 0.444 | [0.222, 0.667] | 0.556 |
| qwen3:8b | rag | 13 | 5 | 0.722 | [0.500, 0.889] | 0.278 |
| gpt-oss:20b | baseline | 12 | 6 | 0.667 | [0.444, 0.889] | 0.333 |
| gpt-oss:20b | rag | 15 | 3 | 0.833 | [0.667, 1.000] | 0.167 |

Recall improved under RAG for 4 of 5 models (llama3, deepseek-r1:8b, qwen3:8b,
gpt-oss:20b) and dipped slightly for gemma3:12b; the largest gain is qwen3:8b
(0.444 -> 0.722). CIs are wide (n=18) — read directionally, not as precise
point estimates.

## 2. Output reliability

Source: `output_reliability.csv`. JSON-parse validity, classification
validity, risk-level validity, indicator-list validity and strict-schema
validity are **1.000** for every model/condition **except** deepseek-r1:8b
under RAG, whose required-field / classification / strict-schema validity is
0.944 (17/18) with a fallback rate of 0.056 (1/18) and retry rate 0.056 — the
single OTRF fallback record. Timeout rate is 0.000 everywhere. This mirrors,
on independent public telemetry, the DeepSeek-under-RAG output-reliability
regression seen in the primary and consistency studies (§`02`, §`03`).

## 3. Indicator alignment (exact canonical-token matching)

Source: `indicator_results.csv`, `out_of_vocabulary_indicators.csv`. Indicators
are scored by **exact** controlled-vocabulary-token membership (case-fold +
outer-trim only; no substring, no space/hyphen folding, no synonym mapping),
and out-of-vocabulary tokens are retained, never discarded. In-vocabulary
rate rises sharply under RAG for every model:

| Model | Baseline in-vocab | RAG in-vocab |
|---|---|---|
| llama3 | 0.000 | 0.684 |
| deepseek-r1:8b | 0.000 | 0.400 |
| gemma3:12b | 0.161 | 0.543 |
| qwen3:8b | 0.146 | 0.436 |
| gpt-oss:20b | 0.057 | 0.282 |

Per-scenario expected-indicator grounding is `not_estimable` (OTRF provides no
per-scenario expected-indicator key); in-vocabulary vs out-of-vocabulary rate
is reported instead, consistent with the primary and consistency studies'
finding that retrieval improves indicator-vocabulary alignment across all
models.

## 4. Latency

Source: `latency_results.csv`. Additional retrieved context increased mean
latency for **all five** models on OTRF (e.g. gpt-oss:20b 14.48s -> 22.23s,
gemma3:12b 10.56s -> 13.86s, deepseek-r1:8b 4.78s -> 5.58s) — unlike the
primary study where DeepSeek was a latency exception; on this abnormal-only
sample DeepSeek's RAG latency rose.

## 5. Baseline vs RAG (exact McNemar + Holm)

Source: `baseline_vs_rag_comparison.csv`. Discordant-pair counts are small
(1–7), so these are **descriptive only** — no comparison reaches Holm
significance (smallest Holm-adjusted p = 0.625, qwen3:8b). p-values are never
rendered as `0.000`.

| Model | Base-only | RAG-only | Discordant | Raw p | Holm p |
|---|---|---|---|---|---|
| llama3 | 0 | 2 | 2 | 0.500 | 1.000 |
| deepseek-r1:8b | 2 | 3 | 5 | 1.000 | 1.000 |
| gemma3:12b | 1 | 0 | 1 | 1.000 | 1.000 |
| qwen3:8b | 1 | 6 | 7 | 0.125 | 0.625 |
| gpt-oss:20b | 0 | 3 | 3 | 0.250 | 1.000 |

## 6. Not estimable (structural, not a gap to be filled)

Representative precision, specificity, balanced accuracy, benign
false-positive rate and severity accuracy are **not estimable** from this
sample and are marked as such in every output table — the sample is 100%
abnormal by construction with no defensible benign or severity key.

## Reproducibility note

The raw OTRF source archives are third-party and kept **local and untracked**
(`external_validation/source/README.md`, `.gitignore`). The evaluator resolves
them from a user-supplied `--source-root` / `OTRF_SOURCE_ROOT`, hash-checking
every file against the frozen manifest; the local source path is never written
into any report or certificate. To reproduce:

```
python scripts/runs_otrf/11-evaluate-otrf-external.py \
  --config external_validation/config/otrf_external_config.json \
  --source-root "<LOCAL_OTRF_SOURCE_DIRECTORY>"
```
