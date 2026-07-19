# Baseline vs Knowledge-Augmented (RAG) -- Comparison Report

All metrics are recomputed from the per-scenario review files, re-joined to the frozen ground truth (`Dataset/ground_truth_FINAL.csv`), using one identical definition for both conditions. Every one of the 120 expected scenarios is classified into exactly one output category: **valid_correct**, **valid_incorrect**, **invalid** (parseable but a non-committal/placeholder classification), **missing** (no record at all), or **fallback** (a record exists but never reached basic schema validity). Invalid, missing and fallback outputs are never dropped from a denominator -- they count as unsuccessful.

## Primary vs secondary metrics

- **PRIMARY**: `all_scenario_accuracy` (correct / 120, every non-valid response counted wrong) and the **coverage-adjusted** recall / false-negative-rate / specificity / balanced-accuracy / F1 (denominators are the full ground-truth abnormal/normal counts, 58/62; invalid, missing and fallback abnormal outputs count as missed detections). These are the numbers that should be quoted as *the* result.
- **SECONDARY**: `valid_output_accuracy`, `committed_output_precision`, `valid_output_recall`, `valid_output_f1` and `cohens_kappa_valid_outputs` are computed over valid (committed) classifications only. They answer "how good is the model when it commits to an answer", which is a useful diagnostic but must never be quoted as the headline result, because it is not adjusted for how often the model failed to commit.

## Overall (PRIMARY: all-scenario accuracy + coverage-adjusted recall)

| Model | Cond | All-scenario acc | Cov-adj recall | Cov-adj specificity | Cov-adj F1 | Invalid | Missing | Fallback |
|---|---|---|---|---|---|---|---|---|
| llama3 | baseline | 0.7583 | 0.8448 | 0.6774 | 0.7717 | 0 | 0 | 0 |
| llama3 | rag | 0.8750 | 0.9655 | 0.7903 | 0.8819 | 0 | 0 | 0 |
| deepseek-r1_8b | baseline | 0.8500 | 0.8793 | 0.8226 | 0.8571 | 1 | 0 | 0 |
| deepseek-r1_8b | rag | 0.6250 | 0.5000 | 0.7419 | 0.6517 | 38 | 0 | 0 |
| gemma3_12b | baseline | 0.8333 | 1.0000 | 0.6774 | 0.8529 | 0 | 0 | 0 |
| gemma3_12b | rag | 0.8833 | 0.8966 | 0.8710 | 0.8814 | 0 | 0 | 0 |
| qwen3_8b | baseline | 0.8500 | 0.7586 | 0.9355 | 0.8302 | 0 | 0 | 0 |
| qwen3_8b | rag | 0.8333 | 0.7069 | 0.9516 | 0.8039 | 0 | 0 | 0 |
| gpt-oss_20b | baseline | 0.8167 | 0.7069 | 0.9194 | 0.7885 | 0 | 0 | 0 |
| gpt-oss_20b | rag | 0.8417 | 0.8103 | 0.8710 | 0.8319 | 0 | 0 | 0 |

## McNemar's exact test + Holm-Bonferroni correction (5 models)

| Model | Baseline-only correct | RAG-only correct | Discordant | Raw p | Holm p | Verdict |
|---|---|---|---|---|---|---|
| llama3 | 6 | 20 | 26 | 0.009 | 0.037 | **statistically significant improvement** |
| deepseek-r1_8b | 28 | 1 | 29 | < 0.001 | < 0.001 | **statistically significant deterioration** |
| gemma3_12b | 6 | 12 | 18 | 0.238 | 0.714 | not statistically significant |
| qwen3_8b | 6 | 4 | 10 | 0.754 | 1.000 | not statistically significant |
| gpt-oss_20b | 5 | 8 | 13 | 0.581 | 1.000 | not statistically significant |

McNemar treats invalid, missing and fallback outputs as incorrect for the paired correctness used above (a model that stops committing to a classification under RAG is scored as having gotten those scenarios wrong, not as unscored). Holm-Bonferroni is applied across the 5 per-model comparisons; p-values below 0.001 are reported as `< 0.001` rather than `0.000`.

## DeepSeek RAG acceptance check

Status: **PASSED**

| Quantity | Expected (approx.) | Observed |
|---|---|---|
| Expected scenarios | 120 | 120 |
| Correct classifications (valid_correct) | 75 | 75 |
| All-scenario accuracy | 0.625 | 0.6250 |
| Invalid/non-committal outputs | 38 | 38 |
| Invalid abnormal outputs | 24 | 24 |
| True-positive abnormal detections | 29 | 29 |
| Ground-truth abnormal scenarios | 58 | 58 |
| Coverage-adjusted abnormal recall | 0.500 | 0.5000 |
| Exact indicator overlap (all-scenario, PRIMARY) | ~0.1042 | 0.1042 |
| Exact indicator overlap (valid-outputs-only, secondary) | ~0.1524 | 0.1524 |

## Per-model notes

### llama3
- All-scenario accuracy: 0.7583 -> 0.8750. Coverage-adjusted recall: 0.8448 -> 0.9655. Coverage-adjusted specificity: 0.6774 -> 0.7903.
- McNemar: baseline-only-correct=6, rag-only-correct=20, raw p=0.009, Holm p=0.037.

### deepseek-r1_8b
- All-scenario accuracy: 0.8500 -> 0.6250. Coverage-adjusted recall: 0.8793 -> 0.5000. Coverage-adjusted specificity: 0.8226 -> 0.7419.
- McNemar: baseline-only-correct=28, rag-only-correct=1, raw p=< 0.001, Holm p=< 0.001.
- **Output-reliability flag:** 38 RAG outputs were invalid (non-committal placeholder classification), vs 1 under baseline. Valid-output accuracy is 0.9146 (secondary; excludes invalid outputs) vs all-scenario accuracy 0.6250 (primary; invalid counted wrong) -- the gap shows the longer RAG prompt harmed structured-output reliability more than it harmed reasoning on the scenarios the model still committed to.

### gemma3_12b
- All-scenario accuracy: 0.8333 -> 0.8833. Coverage-adjusted recall: 1.0000 -> 0.8966. Coverage-adjusted specificity: 0.6774 -> 0.8710.
- McNemar: baseline-only-correct=6, rag-only-correct=12, raw p=0.238, Holm p=0.714.

### qwen3_8b
- All-scenario accuracy: 0.8500 -> 0.8333. Coverage-adjusted recall: 0.7586 -> 0.7069. Coverage-adjusted specificity: 0.9355 -> 0.9516.
- McNemar: baseline-only-correct=6, rag-only-correct=4, raw p=0.754, Holm p=1.000.

### gpt-oss_20b
- All-scenario accuracy: 0.8167 -> 0.8417. Coverage-adjusted recall: 0.7069 -> 0.8103. Coverage-adjusted specificity: 0.9194 -> 0.8710.
- McNemar: baseline-only-correct=5, rag-only-correct=8, raw p=0.581, Holm p=1.000.

## Suggested overall framing

Report the effect of knowledge augmentation as **model-dependent**, not uniformly positive or negative: state each model's direction, whether it is statistically significant after Holm correction, and always quote the coverage-adjusted / all-scenario (primary) numbers rather than the valid-output-only (secondary) numbers as the headline result.
