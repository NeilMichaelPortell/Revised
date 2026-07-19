# 02 — Chapter 4: Primary Baseline vs RAG Results

Source CSVs: `results/comparison/overall_comparison.csv` (also
`thesis_writeup/excel_source/primary_model_condition_metrics.csv`),
`output_reliability.csv`, `confusion_and_invalid_counts.csv`,
`per_category_comparison.csv`, `mcnemar_tests.csv`, `scenario_level_changes.csv`.
Full narrative: `results/comparison/COMPARISON_REPORT.md`. All numbers below
are regenerated from the frozen raw outputs by the corrected evaluator
(`scripts/runs/4-compare_baseline_vs_rag.py`) — see `01_CHAPTER_3_
METHODOLOGY_FACTS.md` for the metric definitions.

**Do not claim universal RAG improvement.** The effect is model-dependent:
one model improved significantly, one deteriorated significantly, three
showed no statistically significant change.

## 1. Primary all-scenario accuracy + coverage-adjusted recall

Table source: `overall_comparison.csv`.

| Model | Condition | All-scenario accuracy | 95% CI | Coverage-adj. recall | Coverage-adj. specificity | Coverage-adj. F1 | Invalid outputs |
|---|---|---|---|---|---|---|---|
| llama3 | baseline | 0.758 | [0.675, 0.826] | 0.845 | 0.677 | 0.772 | 0 |
| llama3 | rag | **0.875** | [0.804, 0.923] | 0.966 | 0.790 | 0.882 | 0 |
| deepseek-r1:8b | baseline | 0.850 | [0.775, 0.903] | 0.879 | 0.823 | 0.857 | 1 |
| deepseek-r1:8b | rag | **0.625** | [0.536, 0.707] | 0.500 | 0.742 | 0.652 | **38** |
| gemma3:12b | baseline | 0.833 | [0.757, 0.889] | 1.000 | 0.677 | 0.853 | 0 |
| gemma3:12b | rag | 0.883 | [0.814, 0.929] | 0.897 | 0.871 | 0.881 | 0 |
| qwen3:8b | baseline | 0.850 | [0.775, 0.903] | 0.759 | 0.936 | 0.830 | 0 |
| qwen3:8b | rag | 0.833 | [0.757, 0.889] | 0.707 | 0.952 | 0.804 | 0 |
| gpt-oss:20b | baseline | 0.817 | [0.738, 0.876] | 0.707 | 0.919 | 0.788 | 0 |
| gpt-oss:20b | rag | 0.842 | [0.766, 0.896] | 0.810 | 0.871 | 0.832 | 0 |

## 2. McNemar's exact test + Holm-Bonferroni correction

Table source: `mcnemar_tests.csv`.

| Model | Baseline-only correct | RAG-only correct | Discordant pairs | Raw p | Holm p | Verdict |
|---|---|---|---|---|---|---|
| llama3 | 6 | 20 | 26 | 0.009 | 0.037 | **Significant improvement** |
| deepseek-r1:8b | 28 | 1 | 29 | < 0.001 | < 0.001 | **Significant deterioration** |
| gemma3:12b | 6 | 12 | 18 | 0.238 | 0.714 | Not significant |
| qwen3:8b | 6 | 4 | 10 | 0.754 | 1.000 | Not significant |
| gpt-oss:20b | 5 | 8 | 13 | 0.581 | 1.000 | Not significant |

McNemar treats invalid, missing and fallback outputs as incorrect for both
conditions — a model that stops committing under RAG is scored as having
gotten those scenarios wrong, not left unscored.

## 3. Output reliability (why DeepSeek's RAG numbers collapse)

Table source: `output_reliability.csv`, `confusion_and_invalid_counts.csv`.

DeepSeek-R1:8B is the only model with any invalid outputs in the primary
comparison: 1/120 under baseline, **38/120 under RAG** (24 of the 38 on
abnormal-truth scenarios, 14 on normal-truth scenarios — all template-echo
`"normal or risky"` responses). Its **secondary** (valid-output-only) accuracy
under RAG is 0.915 — nearly as good as baseline — while its **primary**
all-scenario accuracy is 0.625. The ~29-point gap between these two numbers
is an output-reliability regression under the longer RAG prompt, not a
reasoning regression: on the 82 scenarios where DeepSeek still committed to
an answer, it reasoned about as well as ever.

### DeepSeek RAG acceptance check (verifies the corrected evaluator against
the task's documented expected values — see `results/comparison/
COMPARISON_REPORT.md`, section "DeepSeek RAG acceptance check")

| Quantity | Value |
|---|---|
| Expected scenarios | 120 |
| Correct classifications | 75 |
| All-scenario accuracy | 0.625 |
| Invalid/non-committal outputs | 38 |
| Invalid abnormal outputs | 24 |
| True-positive abnormal detections | 29 |
| Ground-truth abnormal scenarios | 58 |
| Coverage-adjusted abnormal recall | 29/58 = 0.500 |

**Status: PASSED** (`comparison_summary.json` -> `deepseek_rag_acceptance_check: true`).

## 4. Per-category results

Table source: `per_category_comparison.csv` (35 rows: 5 models x 7 categories).
Every category is all-scenario accuracy (invalid/missing/fallback counted
wrong). DeepSeek's RAG collapse is concentrated in USB (0.824 -> 0.353,
Δ −0.471) and AUTH (0.765 -> 0.529, Δ −0.235) — the categories whose
retrieved documents produce the longest injected context for this model.

## 5. Latency

Table source: `overall_comparison.csv` (`mean_latency_seconds`), consolidated
across studies in `thesis_writeup/excel_source/latency_comparison.csv`.
Additional retrieved context generally increased latency (llama3 5.14s ->
5.54s; gemma3:12b 11.05s -> 13.62s; gpt-oss:20b 12.15s -> 17.28s). DeepSeek is
the exception (6.04s -> 5.52s) — its RAG latency is *lower*, but this must be
read alongside its 38 short, non-committal outputs, which take less time to
generate than a fully reasoned answer; the lower latency is not evidence of
efficiency gain, it is an artefact of the model giving up early.

## 6. Indicator alignment (EXACT canonical-token matching)

Table source: `overall_comparison.csv`
(`exact_indicator_overlap_all_scenarios`, `exact_indicator_overlap_valid_outputs`).
**Corrected 2026-07-19 (two-metric split)**: the underlying per-scenario
overlap is the proportion of a scenario's expected (controlled-vocabulary)
indicators that appear **verbatim** among the model's predicted indicators —
exact matching after case-folding and outer-whitespace trimming only, with
**no** substring credit, **no** space/hyphen -> underscore folding, and **no**
synonym mapping (recomputed from the frozen model responses; the previous
substring heuristic is retired). This is now reported as two separate,
named metrics rather than one blended number:

- **`exact_indicator_overlap_all_scenarios` (PRIMARY, the dissertation
  headline value)** — averaged over all 120 expected scenarios; every
  invalid/missing/fallback output receives **0** in this average, so a model
  cannot inflate its apparent indicator grounding by refusing to commit to a
  classification.
- **`exact_indicator_overlap_valid_outputs` (secondary diagnostic)** —
  averaged over valid (committed) outputs only, i.e. "how well does the model
  ground its indicators on the scenarios it actually answered".

For every model except DeepSeek-R1:8B RAG the two values are identical,
because that model/condition is the only one with any invalid outputs in the
primary comparison (see §3). Values (baseline -> RAG, all-scenario/PRIMARY):
llama3 0.004 -> 0.247, gemma3:12b 0.053 -> 0.317, qwen3:8b 0.069 -> 0.213,
gpt-oss:20b 0.004 -> 0.181, DeepSeek-R1:8B 0.000 -> **0.104** (all-scenario,
primary; the 38 invalid RAG outputs count as 0 in this average) vs **0.152**
(valid-outputs-only, secondary; computed over just the 82 scenarios it still
committed to). Report the all-scenario value as *the* result; the
valid-outputs-only value is a diagnostic for explaining the gap, not a
substitute headline number. Under the primary metric, indicator overlap still
improves for every model under RAG. Indicator alignment is a distinct
dimension from classification correctness — see
`06_CHAPTER_5_DISCUSSION_POINTS.md`.

## 7. Scenario-level error analysis

Full per-scenario detail (what changed, per model): `scenario_level_changes.csv`
(600 rows: 5 models x 120 scenarios), including each scenario's RAG-retrieved
document IDs for tracing a specific classification change back to the
context that was injected.
