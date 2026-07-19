# Baseline vs Knowledge-Augmented (RAG) — Comparison Report

All metrics are recomputed from the per-scenario review files using one identical definition for both conditions. Primary accuracy is over all 120 scenarios (invalid outputs counted as wrong); valid-only accuracy excludes invalid outputs. Positive class = abnormal/risky; recall is the priority metric.

## Overall (primary all-120 accuracy)

| Model | Baseline acc | RAG acc | Baseline F1 | RAG F1 | Baseline recall | RAG recall | RAG invalid | McNemar p | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| deepseek-r1_8b | 0.850 | 0.625 | 0.857 | 0.892 | 0.879 | 0.853 | 38 | 0.000 | baseline better (sig.) |
| gemma3_12b | 0.833 | 0.883 | 0.853 | 0.881 | 1.000 | 0.897 | 0 | 0.238 | no sig. difference |
| gpt-oss_20b | 0.817 | 0.842 | 0.788 | 0.832 | 0.707 | 0.810 | 0 | 0.581 | no sig. difference |
| llama3 | 0.758 | 0.875 | 0.772 | 0.882 | 0.845 | 0.966 | 0 | 0.009 | RAG better (sig.) |
| qwen3_8b | 0.850 | 0.833 | 0.830 | 0.804 | 0.759 | 0.707 | 0 | 0.754 | no sig. difference |

## How to read this

- **McNemar's test** compares the two conditions on the SAME 120 scenarios. It counts how many scenarios only baseline got right versus only RAG, and tests whether that split is beyond chance. A significant result (p < 0.05) means the change in that model's accuracy is unlikely to be random.
- **Invalid outputs** are responses that were not classifiable (malformed JSON, or a non-committal class such as echoing the schema example 'normal or risky'). These are counted as wrong in the primary accuracy and reported separately so a reliability problem is not hidden inside the accuracy number.
- **Valid-only accuracy** shows how the model did on the responses it actually committed to; a large gap between all-120 and valid-only accuracy points to an output-reliability issue rather than a reasoning one.

## Per-model notes

### deepseek-r1_8b
- acc 0.850→0.625, recall 0.879→0.853, precision 0.836→0.935, indicator overlap 0.079→0.143.
- McNemar: baseline-only-correct=28, rag-only-correct=1, p=0.000 (significant).
- **Output-reliability flag:** 38 RAG outputs were invalid/non-committal. Valid-only accuracy is 0.915 vs all-120 0.625 (gap 0.290). The longer prompt appears to have harmed structured-output reliability rather than reasoning; the model reasoned acceptably on the responses it committed to.

### gemma3_12b
- acc 0.833→0.883, recall 1.000→0.897, precision 0.744→0.867, indicator overlap 0.104→0.354.
- McNemar: baseline-only-correct=6, rag-only-correct=12, p=0.238 (not significant).

### gpt-oss_20b
- acc 0.817→0.842, recall 0.707→0.810, precision 0.891→0.855, indicator overlap 0.040→0.249.
- McNemar: baseline-only-correct=5, rag-only-correct=8, p=0.581 (not significant).

### llama3
- acc 0.758→0.875, recall 0.845→0.966, precision 0.710→0.812, indicator overlap 0.032→0.301.
- McNemar: baseline-only-correct=6, rag-only-correct=20, p=0.009 (significant).

### qwen3_8b
- acc 0.850→0.833, recall 0.759→0.707, precision 0.917→0.932, indicator overlap 0.117→0.258.
- McNemar: baseline-only-correct=6, rag-only-correct=4, p=0.754 (not significant).

## Suggested overall framing

Report the effect of knowledge augmentation as model-dependent rather than uniformly positive: state per-model direction, whether it is statistically significant (McNemar), and treat JSON/schema validity as a first-class result so that any output-reliability regression is reported openly rather than absorbed into accuracy.
