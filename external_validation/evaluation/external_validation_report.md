# OTRF External Validation Report (Supplementary)

Generated (UTC): 2026-07-19T18:13:17.469699+00:00

This is a supplementary external validation using controlled public OTRF Windows adversary-simulation telemetry. It demonstrates that the implemented analysis pipeline can process independently sourced Windows security data after deterministic normalisation. It is **not** a comparison with the 120-scenario accuracy results and **not** evidence of organisational real-world performance.

## Sample composition

- External scenarios: 18
- Abnormal: 18
- Defensibly benign: 0
- Unknown ground truth (excluded from detection metrics): 0
- Missing outputs: 0; Duplicate outputs: 0; Manifest hash mismatches: 0

## Metrics not estimable from this sample

- Precision, specificity and balanced accuracy are **not estimable** (no defensibly benign subset).
- Severity accuracy is **not estimable** (no defensible severity answer key).
- Indicator grounding against expected indicators is **not estimable** (OTRF provides no per-scenario expected-indicator list); in-vocabulary vs out-of-vocabulary rates are reported instead.

## Abnormal detection (invalid AND missing outputs counted as misses)

| Model | Condition | N abn | TP | FN | Recall | CI low | CI high | FN rate |
|---|---|---|---|---|---|---|---|---|
| llama3 | baseline | 18 | 12 | 6 | 0.6667 | 0.4444 | 0.8889 | 0.3333 |
| llama3 | rag | 18 | 14 | 4 | 0.7778 | 0.5556 | 0.9444 | 0.2222 |
| deepseek-r1:8b | baseline | 18 | 12 | 6 | 0.6667 | 0.4444 | 0.8889 | 0.3333 |
| deepseek-r1:8b | rag | 18 | 13 | 5 | 0.7222 | 0.5 | 0.8889 | 0.2778 |
| gemma3:12b | baseline | 18 | 15 | 3 | 0.8333 | 0.6667 | 1.0 | 0.1667 |
| gemma3:12b | rag | 18 | 14 | 4 | 0.7778 | 0.5556 | 0.9444 | 0.2222 |
| qwen3:8b | baseline | 18 | 8 | 10 | 0.4444 | 0.2222 | 0.6667 | 0.5556 |
| qwen3:8b | rag | 18 | 13 | 5 | 0.7222 | 0.5 | 0.8889 | 0.2778 |
| gpt-oss:20b | baseline | 18 | 12 | 6 | 0.6667 | 0.4444 | 0.8889 | 0.3333 |
| gpt-oss:20b | rag | 18 | 15 | 3 | 0.8333 | 0.6667 | 1.0 | 0.1667 |

## Output reliability and coverage (all scenarios in denominator)

| Model | Cond | Coverage | Parse | Strict | Timeout | Fallback | Retry |
|---|---|---|---|---|---|---|---|
| llama3 | baseline | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 |
| llama3 | rag | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 |
| deepseek-r1:8b | baseline | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 |
| deepseek-r1:8b | rag | 1.0 | 1.0 | 0.9444 | 0.0 | 0.0556 | 0.0556 |
| gemma3:12b | baseline | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 |
| gemma3:12b | rag | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 |
| qwen3:8b | baseline | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 |
| qwen3:8b | rag | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 |
| gpt-oss:20b | baseline | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 |
| gpt-oss:20b | rag | 1.0 | 1.0 | 1.0 | 0.0 | 0.0 | 0.0 |

## Latency (seconds, total across attempts)

| Model | Cond | n | Mean | Median | Std | CI low | CI high |
|---|---|---|---|---|---|---|---|
| llama3 | baseline | 18 | 4.0807 | 4.098 | 0.2171 | 3.9817 | 4.1804 |
| llama3 | rag | 18 | 4.6066 | 4.7085 | 0.5012 | 4.3714 | 4.831 |
| deepseek-r1:8b | baseline | 18 | 4.7834 | 4.684 | 0.3067 | 4.6469 | 4.9279 |
| deepseek-r1:8b | rag | 18 | 5.5811 | 5.175 | 1.7866 | 5.0175 | 6.4979 |
| gemma3:12b | baseline | 18 | 10.5579 | 10.1445 | 1.4179 | 9.9288 | 11.2149 |
| gemma3:12b | rag | 18 | 13.8567 | 14.4975 | 3.1367 | 12.423 | 15.3029 |
| qwen3:8b | baseline | 18 | 4.2927 | 4.228 | 0.2792 | 4.1667 | 4.4238 |
| qwen3:8b | rag | 18 | 4.9209 | 4.9025 | 0.4472 | 4.7145 | 5.1277 |
| gpt-oss:20b | baseline | 18 | 14.4776 | 12.334 | 6.0501 | 12.0256 | 17.4882 |
| gpt-oss:20b | rag | 18 | 22.2321 | 21.0755 | 7.1563 | 19.0669 | 25.6378 |

## Indicator vocabulary compliance (exact canonical-token match)

| Model | Cond | Canonical | OOV | OOV rate | In-vocab rate |
|---|---|---|---|---|---|
| llama3 | baseline | 0 | 14 | 1.0 | 0.0 |
| llama3 | rag | 13 | 6 | 0.3158 | 0.6842 |
| deepseek-r1:8b | baseline | 0 | 29 | 1.0 | 0.0 |
| deepseek-r1:8b | rag | 8 | 12 | 0.6 | 0.4 |
| gemma3:12b | baseline | 5 | 26 | 0.8387 | 0.1613 |
| gemma3:12b | rag | 19 | 16 | 0.4571 | 0.5429 |
| qwen3:8b | baseline | 7 | 41 | 0.8542 | 0.1458 |
| qwen3:8b | rag | 17 | 22 | 0.5641 | 0.4359 |
| gpt-oss:20b | baseline | 2 | 33 | 0.9429 | 0.0571 |
| gpt-oss:20b | rag | 11 | 28 | 0.7179 | 0.2821 |

## Baseline vs RAG (exact McNemar, Holm across models)

Paired only over scenarios with known ground truth where a correctness verdict could be assigned. Small discordant counts mean differences are descriptive.

| Model | Base-only | RAG-only | Discordant | p | Holm p |
|---|---|---|---|---|---|
| llama3 | 0 | 2 | 2 | 0.500 | 1.000 |
| deepseek-r1:8b | 2 | 3 | 5 | 1.000 | 1.000 |
| gemma3:12b | 1 | 0 | 1 | 1.000 | 1.000 |
| qwen3:8b | 1 | 6 | 7 | 0.125 | 0.625 |
| gpt-oss:20b | 0 | 3 | 3 | 0.250 | 1.000 |


## Interpretation guidance

- Recall is the primary metric here: a false negative means genuine risky endpoint behaviour was missed. It is reported conservatively (invalid or missing outputs are treated as misses).
- Because the sample is abnormal-dominated, precision-style metrics are only reported if a defensible benign subset exists; otherwise they are marked not estimable.
- Output coverage is reported separately from validity/correctness rates so a low coverage rate (missing outputs) cannot be mistaken for a model correctness result.
- This evaluation supports a limited claim of **technical transportability** and supplementary external validation only.