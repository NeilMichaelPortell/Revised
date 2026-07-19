# 10 — Unsupported Claims (do not write these into the dissertation as-is)

Every item below is a claim that the evidence in this repository does **not**
support, phrased as it might tempt someone to write it, followed by why it
fails and what would be needed to support it.

## 1. "RAG improves classification accuracy" (unqualified)

**Unsupported as a blanket statement.** Only 1 of 5 models improved
significantly (llama3); 1 deteriorated significantly (deepseek-r1:8b); 3
showed no significant change. Write the model-dependent finding instead (see
`06_CHAPTER_5_DISCUSSION_POINTS.md` point 1).

## 2. OTRF numeric results — now AVAILABLE, but only with the correct framing

The strict OTRF evaluation completed on 2026-07-19 (18/18 source + neutral
hashes verified, no override flags), so abnormal recall, false-negative rate,
output coverage, JSON/field/classification/risk/indicator/strict-schema
validity, retry/timeout/fallback counts, latency, in-vocabulary indicator rate
and exact McNemar/Holm results ARE reportable — see
`04_CHAPTER_4_EXTERNAL_VALIDATION_RESULTS.md`. What remains **unsupported**:
(a) any OTRF **precision / specificity / balanced accuracy / benign
false-positive rate / severity accuracy** — structurally `not_estimable`
(100%-abnormal sample, no benign or severity key); (b) any claim that OTRF
demonstrates **organisational real-world** performance — it demonstrates
technical **transportability** only; (c) treating the small-n baseline-vs-RAG
McNemar results as anything but **descriptive** (discordant pairs 1–7).

## 3. "The prototype demonstrates real-time detection performance / live LLM reliability"

**Unsupported.** The single completed live run made **zero** LLM calls and
missed its one expected alert. It demonstrates capture/dedup/cooldown-harness
feasibility only. See `05_CHAPTER_4_PROTOTYPE_RESULTS.md`.

## 4. "This system generalises to organisational / production environments"

**Unsupported by any evidence in this repository.** The primary study is a
120-scenario constructed/collected dataset (10% augmented); OTRF is a public,
abnormal-dominated research corpus; the prototype has one live run. None of
these constitute organisational-scale, real-world validation. State the
transportability/feasibility framing instead (`06_CHAPTER_5_DISCUSSION_
POINTS.md` points 12–13).

## 5. Any claim requiring scholarly literature (e.g. "consistent with prior work on LLM output reliability," "RAG grounding has been shown to reduce hallucination in security contexts")

**[REFERENCE REQUIRED].** This repository contains no bibliography or cited
literature; any such statement needs an external citation added by the
author before submission. Do not fabricate a reference. See
`08_CLAIM_EVIDENCE_MATRIX.csv` row C25.

## 6. "DeepSeek got worse at reasoning under RAG"

**Unsupported as stated — the mechanism is reliability, not reasoning.** Its
secondary (valid-output-only) accuracy under RAG (0.915) is close to
baseline (0.857); the drop in primary accuracy (0.850 -> 0.625) is explained
by 38/120 non-committal outputs, not degraded judgement on the outputs it
did commit to. See `06_CHAPTER_5_DISCUSSION_POINTS.md` point 3.

## 7. "Gemma3:12b / Qwen3:8b / GPT-OSS:20b show no effect from RAG"

**Overstated.** The correct statement is "no *statistically significant*
change was detected at this sample size" (10–18 discordant pairs each) — not
"no effect exists." See `07_THREATS_TO_VALIDITY.md` (Internal validity).

## 8. Precision, specificity, balanced accuracy, or benign false-positive rate for OTRF

**Not estimable, even though the strict OTRF evaluation has completed.** The OTRF sample is
100% ground-truth abnormal by construction; there is no defensible benign
subset. This is a structural property of the sample, not a fixable gap. See
`04_CHAPTER_4_EXTERNAL_VALIDATION_RESULTS.md`.

## 9. Severity accuracy for OTRF

**Not estimable** — OTRF provides no defensible external severity answer key
matching this project's severity ladder. Do not construct one post hoc.

## 10. "The consistency study confirms the primary study's accuracy findings"

**Imprecise.** The consistency study's classification-accuracy comparison
(20 scenarios) found no Holm-significant change for any model — it is
under-powered relative to the 120-scenario primary comparison, not a
replication of it. What the consistency study *does* independently confirm
is DeepSeek's output-reliability regression under RAG (strict-schema
validity 0.95 -> 0.60, Holm p=0.041) — cite that specific corroboration, not
a general "confirms the primary findings" statement. See
`03_CHAPTER_4_CONSISTENCY_RESULTS.md`.

## 11. Any claim about the legacy/duplicate raw-output directories (`outputs_rag/`, `outputs_consistency_baseline/`, `outputs_consistency_rag/`)

**Do not cite these as a separate or additional evidence source.** They are
raw-output duplicates confirmed byte-for-byte identical to the canonical
`results/` tree and are documented as legacy in `docs/final_audit/
CANONICAL_ARTIFACT_PATHS.md`. All dissertation numbers must cite the
canonical paths only. (Two further duplicate **derived-report** directories,
`comparison/` and `consistency_results/`, existed at an earlier point in this
audit but had diverged from the canonical tree by the time of the 2026-07-19
indicator-overlap correction pass — they were archived under
`results/archive/` and removed rather than left in place stale; see
`CANONICAL_ARTIFACT_PATHS.md` for the removal record. They no longer exist in
the working tree and must not be cited at all.)
