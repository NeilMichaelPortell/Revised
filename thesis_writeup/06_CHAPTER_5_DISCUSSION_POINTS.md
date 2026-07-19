# 06 — Chapter 5 Discussion Points (evidence-grounded)

Each point states the claim, the evidence backing it, and the exact source.
Use `08_CLAIM_EVIDENCE_MATRIX.csv` for the formal per-claim ledger.

## 1. Knowledge augmentation had model-dependent effects, not a uniform one

Holm-corrected McNemar across the 5 models produced 3 different verdicts, not
1: significant improvement (llama3), significant deterioration
(deepseek-r1:8b), and no significant change (gemma3:12b, qwen3:8b,
gpt-oss:20b). Source: `results/comparison/mcnemar_tests.csv`. This is the
central Chapter 5 claim and should frame every other discussion point below.

## 2. Llama 3 improved substantially and significantly

All-scenario accuracy 0.758 -> 0.875 (+0.117); coverage-adjusted recall 0.845
-> 0.966; McNemar raw p=0.009, Holm p=0.037 (significant at 0.05). Source:
`results/comparison/overall_comparison.csv`, `mcnemar_tests.csv`.

## 3. DeepSeek deteriorated significantly because of output reliability, not reasoning

All-scenario accuracy 0.850 -> 0.625; McNemar Holm p < 0.001 (significant
deterioration). The mechanism is reliability, not reasoning: 38/120 RAG
outputs were invalid (non-committal placeholder), driving the primary
accuracy down, while its **secondary** valid-output accuracy remained 0.915
— close to baseline. The consistency study corroborates this on an
independent 20-scenario sample: DeepSeek's strict-schema validity dropped
0.95 -> 0.60 under RAG (Holm p=0.041, the only significant reliability change
found anywhere in the consistency study). Source: `results/comparison/
overall_comparison.csv`, `COMPARISON_REPORT.md`; `results/consistency/
reports/baseline_vs_rag_consistency.csv`.

## 4. Gemma and GPT-OSS improved modestly without significant classification changes

Gemma3:12b 0.833 -> 0.883 (Holm p=0.714); GPT-OSS:20b 0.817 -> 0.842 (Holm
p=1.000). Both are directionally positive but not statistically
distinguishable from chance at this sample size. Source: `mcnemar_tests.csv`.

## 5. Qwen showed a small classification decrease

Qwen3:8b 0.850 -> 0.833 (Holm p=1.000, not significant). Source:
`mcnemar_tests.csv`.

## 6. Indicator alignment improved more consistently than classification

Indicator overlap (primary study) improved for **all five models** under RAG,
including the two with no significant classification change and even
DeepSeek on its still-valid outputs. Indicator-vocabulary compliance
(consistency study) improved **significantly for all five models** (Holm p
from < 0.001 to 0.007) — the single most consistent effect of knowledge
augmentation measured anywhere in this dissertation, stronger than the
classification-accuracy effect. Source: `results/comparison/
overall_comparison.csv` (`indicator_overlap`); `results/consistency/reports/
baseline_vs_rag_consistency.csv` (`indicator_vocabulary_compliance_rate`).

## 7. Additional context generally increased latency

4 of 5 models were slower under RAG (llama3 +0.40s, gemma3:12b +2.57s,
qwen3:8b +0.37s, gpt-oss:20b +5.13s mean latency). Source:
`results/comparison/overall_comparison.csv` (`mean_latency_seconds`).

## 8. DeepSeek's latency exception must be interpreted alongside short non-committal outputs

DeepSeek is the one model that got *faster* under RAG (6.04s -> 5.52s), but
this coincides with 38/120 short, non-committal responses that terminate
generation early rather than completing full reasoning — the lower mean
latency is an artefact of giving up early, not an efficiency gain. Source:
`results/comparison/overall_comparison.csv`; corroborated by the retry-rate
jump to 0.44 in the consistency study (`baseline_vs_rag_consistency.csv`).

## 9. Recall is critical because false negatives represent missed abnormal behaviour

This is why the corrected evaluator's coverage-adjusted recall (denominator =
all 58 ground-truth-abnormal scenarios, invalid/missing/fallback counted as
misses) is the headline metric, not the previous evaluator's valid-output-only
recall, which could be inflated by non-committal refusal. Source:
`results/comparison/COMPARISON_REPORT.md` ("Primary vs secondary metrics").

## 10. Precision remains operationally relevant because false positives create alert fatigue

Coverage-adjusted specificity is reported alongside recall for the same
reason (e.g. qwen3:8b trades recall for specificity in both conditions:
0.759/0.936 baseline, 0.707/0.952 RAG) — a detector's operational cost is not
fully captured by recall alone. Source: `results/comparison/
overall_comparison.csv`.

## 11. Consistency and correctness are separate

A model can be consistently wrong (perfect agreement on a repeated wrong or
non-committal answer) or inconsistently correct. `classification_agreement_
rate` stayed near-1.0 for every model regardless of what happened to
`classification_accuracy_across_repetitions` or the primary study's accuracy
— agreement alone says nothing about correctness. Source:
`01_CHAPTER_3_METHODOLOGY_FACTS.md`, `03_CHAPTER_4_CONSISTENCY_RESULTS.md`.

## 12. OTRF demonstrates technical transportability but not production generalisability

Even once the two missing source files are recovered and the evaluation is
re-certified, the framing must stay limited: an abnormal-dominated public
research corpus supports a transportability claim (the pipeline processes
independently sourced telemetry), not an organisational real-world
generalisability claim (no benign subset, no organisation-specific
telemetry, no defensible severity key). Source: `04_CHAPTER_4_EXTERNAL_
VALIDATION_RESULTS.md`; `scripts/runs_otrf/11-evaluate-otrf-external.py`.

## 13. The controlled prototype demonstrates feasibility but not independent organisational validation

The prototype's unit-test suite (15/15) demonstrates the harness's internal
correctness; its one completed live run demonstrates capture/dedup/cooldown
feasibility but never exercised the LLM layer (0 calls, the one expected
alert was missed). Neither constitutes independent, organisational,
population-level validation. Source: `05_CHAPTER_4_PROTOTYPE_RESULTS.md`.
