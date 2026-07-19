# 07 — Threats to Validity

Organised by validity type. Each threat states the concrete mechanism and the
evidence file that lets a reader verify it directly, rather than a generic
disclaimer.

## Construct validity

- **12 of 120 primary scenarios (10%) are augmented, not collected live**
  (`Dataset/provenance_report.csv`; concentrated in PROC/NET/PERSIST, 4 each
  — `thesis_writeup/excel_source/dataset_composition.csv`). These extend
  category coverage but are constructed rather than observed, so results are
  not purely a measurement of organically occurring behaviour.
- **"Coverage-adjusted" metrics are a deliberate construct choice.** Folding
  invalid/missing/fallback outputs into recall/specificity as failures is the
  methodologically defensible choice for a security-relevant classifier (a
  refusal to classify a genuine risk is operationally equivalent to missing
  it), but it is a construct decision, not the only possible one — the
  secondary valid-output-only metrics are reported alongside specifically so
  a reader can see both. See `results/comparison/COMPARISON_REPORT.md`.
- **Indicator overlap (primary study) vs indicator vocabulary compliance
  (consistency study) measure related but distinct things** (substring/label
  match against expected indicators vs exact controlled-vocabulary-token
  membership) — they should not be conflated as the same construct across
  chapters.

## Internal validity

- **DeepSeek's RAG reliability collapse is a within-study threat to reading
  the RAG condition as uniformly beneficial.** Without separating primary
  (all-scenario) from secondary (valid-output-only) accuracy, a reader could
  wrongly conclude DeepSeek "reasons worse" under RAG, when the evidence
  (`results/comparison/COMPARISON_REPORT.md`) points to output-format
  reliability, not reasoning, as the mechanism.
- **Small discordant-pair counts limit statistical power for 3 of 5 models.**
  Gemma3:12b (18 discordant pairs), qwen3:8b (10) and gpt-oss:20b (13) have
  few enough discordant scenarios that a true small effect could exist but
  not reach significance after Holm correction. "Not significant" should be
  read as "not detected at this sample size," not "no effect exists."
  Source: `results/comparison/mcnemar_tests.csv`.
- **The consistency study's classification-accuracy comparison is
  under-powered by design** (20 scenarios vs the primary study's 120) and
  found no Holm-significant change for any model
  (`results/consistency/reports/baseline_vs_rag_consistency.csv`) — this must
  not be read as contradicting the primary study's significant findings for
  llama3/deepseek-r1:8b; it is a different, smaller sample answering a
  different question (stability), not a replication attempt.
- **Retrieval determinism was verified only for the frozen retrieval plan
  actually used** (`retrieval_consistency_audit.csv`, 0 mismatches across
  1,000 records) — this confirms internal reproducibility of *this specific*
  deterministic keyword retriever, not that any RAG retriever would behave
  identically.

## External validity

- **OTRF external validation is currently blocked** (two of eighteen source
  captures missing — `docs/final_audit/MISSING_EVIDENCE.csv`,
  `04_CHAPTER_4_EXTERNAL_VALIDATION_RESULTS.md`) and, even once unblocked,
  supports only technical transportability, not organisational
  generalisability: the OTRF sample is 100% abnormal by construction (public
  atomic-technique emulations), so precision, specificity, balanced accuracy
  and benign false-positive rate are not estimable, and there is no
  defensible external severity key.
- **The prototype's live validation evidence is a single run with zero LLM
  calls** (`prototype/validation_results.csv`) — it demonstrates harness
  feasibility, not live detection or live LLM-reliability performance, and
  cannot be generalised even within the prototype's own intended deployment
  context, let alone to another organisation.
- **All five models are open-weight/local models run via Ollama at a fixed
  point in time and a fixed quantisation/build** — findings may not transfer
  to newer versions of the same model families or to closed/hosted models.
- **The 34-document knowledge base was authored specifically for this seven-
  category taxonomy**; RAG effects measured here are conditioned on this
  particular knowledge base's coverage and phrasing, not a general property
  of retrieval augmentation.

## Statistical / conclusion validity

- **Holm-Bonferroni correction is applied across exactly 5 comparisons per
  family** (5 models for the primary McNemar family; 5 models per metric
  family in the consistency study) — the correction's stringency is
  calibrated to that family size and would need to be recalculated if the
  model set changes.
- **McNemar's exact test requires discordant pairs; models with very few
  discordant scenarios have limited resolving power** (see Internal validity
  above) — this is a conclusion-validity threat, not a data-quality issue.
- **The bootstrap confidence intervals in the consistency comparison use a
  fixed seed (2026, 10,000 iterations)** for reproducibility
  (`scripts/runs/7-evaluate_consistency.py`); this makes the specific
  interval reported exactly reproducible but does not itself increase or
  decrease the statistical power of the underlying comparison.
- **All p-values below 0.001 are displayed as `< 0.001` rather than a spurious
  `0.000`**, avoiding the false impression of an exactly-zero probability
  (`results/comparison/mcnemar_tests.csv`, `results/consistency/reports/
  baseline_vs_rag_consistency.csv`).

## Reproducibility / evidence-integrity threats specific to this pass

- **Two OTRF source captures (EXT_010, EXT_014) are missing from the working
  tree** (removed by a committed change, `79b8c0d "Removing Harmful Files"` —
  see `docs/final_audit/MISSING_EVIDENCE.csv`), blocking end-to-end OTRF
  reproducibility certification until recovered and hash-verified.
- **All other frozen artefacts audited in this pass are hash-stable and
  complete**: zero malformed JSONL lines, zero duplicate or missing scenario
  records, correct model names, across all primary (600+600), consistency
  (500+500) and OTRF (90+90) raw output files
  (`docs/final_audit/EVIDENCE_INVENTORY.md`).

## Privacy / ethics

All inference is local (no cloud dependency, verified by design to work
offline); the prototype's telemetry sanitisation (scheme+domain only,
sensitive-path visits dropped entirely) limits what could be exposed even in
a live deployment, but was validated only via unit tests and one live run,
not an independent privacy audit.
