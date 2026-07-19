# 03 — Chapter 4: Consistency Study Results

Source: `results/consistency/reports/baseline/per_model_consistency.csv`,
`rag/per_model_consistency.csv` (combined in `thesis_writeup/excel_source/
consistency_model_condition_metrics.csv`), `baseline_vs_rag_consistency.csv`,
`repetition_integrity_audit.csv`, `retrieval_consistency_audit.csv`,
`validation_report.txt`. Regenerated 2026-07-19 by the corrected
`scripts/runs/7-evaluate_consistency.py` (p-value display fix; see
`00_EVIDENCE_AND_ARTIFACT_MAP.md`).

**Design**: 20 fixed scenarios x 5 repetitions x 5 models x 2 conditions =
**1,000 records** (500 baseline + 500 RAG), confirmed by
`docs/final_audit/EVIDENCE_INVENTORY.md` §1 with zero malformed lines,
duplicate or missing repetitions across all 1,000 records
(`repetition_integrity_audit.csv`: 200/200 complete repetition groups).

## Stability vs correctness — these are different questions

A model can be **consistently wrong** (same wrong answer every repetition) or
**inconsistently correct** (right most of the time but not always). The
evaluator reports them as separate metrics on purpose:

| Metric | What it measures |
|---|---|
| `classification_agreement_rate` | Do the 5 repetitions agree with **each other**? |
| `classification_accuracy_across_repetitions` | Do the repetitions agree with **ground truth**? |

`INVALID_CLASSIFICATION` is retained as an explicit classification value in
agreement calculations — a model that gives the same non-committal
placeholder on every repetition registers as perfectly "agreeing" with
itself. This is a real limitation of agreement-as-stability rather than a
bug: it is exactly why the two metrics must be read together, never one
without the other.

## 1. Classification stability

`classification_agreement_rate` is at or near 1.0 for every model in both
conditions (deepseek-r1:8b, gpt-oss:20b, llama3, qwen3:8b all = 1.0 both
conditions; gemma3:12b 0.99 baseline -> 1.00 RAG). None of these differences
reach Holm significance. Stability alone therefore tells us almost nothing
about which condition is better — it must be read against strict-schema
reliability below.

## 2. Strict-schema reliability — the one significant reliability change

Source: `baseline_vs_rag_consistency.csv`, metric
`strict_schema_validity_rate`.

| Model | Baseline | RAG | Δ | Raw p | Holm p |
|---|---|---|---|---|---|
| deepseek-r1:8b | 0.95 | **0.60** | **−0.35** | 0.008 | **0.041 (significant)** |
| gemma3:12b | 1.00 | 1.00 | 0.00 | 1.000 | 1.000 |
| gpt-oss:20b | 1.00 | 1.00 | 0.00 | 1.000 | 1.000 |
| llama3 | 1.00 | 1.00 | 0.00 | 1.000 | 1.000 |
| qwen3:8b | 1.00 | 1.00 | 0.00 | 1.000 | 1.000 |

This corroborates the primary-study finding independently: DeepSeek-R1:8B is
the only model whose output-reliability degrades significantly under RAG, on
a completely separate 20-scenario x 5-repetition sample. `retry_rate` for
DeepSeek jumps from 0.0 (baseline) to 0.44 (RAG) in the same table.

## 3. Indicator vocabulary compliance — improves significantly for every model

Source: `baseline_vs_rag_consistency.csv`, metric
`indicator_vocabulary_compliance_rate` (a response is "compliant" if every
indicator it lists is an exact controlled-vocabulary token and it lists at
least one).

| Model | Baseline | RAG | Δ | Holm p |
|---|---|---|---|---|
| llama3 | 0.00 | 0.51 | +0.51 | 0.004 |
| gemma3:12b | 0.00 | 0.84 | +0.84 | < 0.001 |
| qwen3:8b | 0.00 | 0.75 | +0.75 | < 0.001 |
| gpt-oss:20b | 0.00 | 0.45 | +0.45 | 0.007 |
| deepseek-r1:8b | 0.00 | 0.44 | +0.44 | 0.007 |

**Every model's compliance improves significantly.** Baseline compliance is
0.00 across the board (no controlled-vocabulary exposure without retrieved
context); RAG exposes the model to the exact vocabulary via retrieved
documents. This is the most consistent effect of knowledge augmentation
found anywhere in this dissertation — stronger and more uniform than the
classification-accuracy effect. `indicator_vocabulary_audit.csv` records 230
distinct out-of-vocabulary tokens found across the full 1,000-record corpus.

## 4. Classification correctness across repetitions — no significant change

Source: `baseline_vs_rag_consistency.csv`, metric
`classification_accuracy_across_repetitions`. No model reaches Holm
significance on this 20-scenario subsample (llama3 +0.15 holm p=0.719;
gpt-oss:20b +0.10 holm p=0.952; deepseek-r1:8b −0.20 holm p=0.228; gemma3:12b
+0.01 holm p=0.952; qwen3:8b −0.05 holm p=0.952). This is expected: the
20-scenario consistency subsample has far less statistical power than the
full 120-scenario primary comparison (`02_CHAPTER_4_PRIMARY_RESULTS.md`),
which is where the model-dependent classification-accuracy effects are
established with adequate power. The consistency study's role is reliability
and stability, not a replacement for the primary accuracy comparison.

## 5. Indicator-set and explanation similarity

`mean_pairwise_indicator_jaccard` and `mean_pairwise_explanation_similarity`
(per-model, per-condition means in `consistency_model_condition_metrics.csv`)
are both high (>0.77) for every model in both conditions, indicating the
repeated calls at temperature 0 produce substantively similar indicator sets
and explanations, not just similar top-line labels.

## 6. Retrieval determinism (RAG only)

`retrieval_consistency_audit.csv`: retrieved document IDs, order, scores and
the retrieval-plan hash are checked identical across all 5 repetitions for
every (model, scenario) pair. Zero mismatches recorded
(`validation_report.txt`: "Retrieval mismatches: 0"), confirming the
precomputed retrieval plan is genuinely deterministic and reused unchanged.

## 7. Latency variation

`latency_coefficient_of_variation` (per model/condition,
`consistency_model_condition_metrics.csv` and `thesis_writeup/excel_source/
latency_comparison.csv`) is low for every model (0.044–0.121), i.e. latency
is stable across repetitions of the same scenario; RAG's CVs are slightly
higher than baseline's for every model, consistent with the added variability
of longer, context-dependent prompts.
