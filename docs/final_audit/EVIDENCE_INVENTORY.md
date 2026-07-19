# Evidence Inventory — Preflight Audit

Generated 2026-07-19 as part of the final evidence-integrity pass. This report
covers the checks required before any evaluator was touched: expected counts,
malformed JSONL, duplicate/missing records, unexpected scenario IDs, model
names, and record-count drift. Full per-file SHA-256 hashes are in
`FROZEN_ARTIFACT_HASHES.csv`; canonical-vs-legacy path resolution is in
`CANONICAL_ARTIFACT_PATHS.md`; unresolved gaps are in `MISSING_EVIDENCE.csv`.

Audit method: every raw JSONL file was parsed line-by-line (malformed lines
recorded by line number, not silently skipped); every review CSV/JSONL's
scenario/record identifiers were compared against the frozen ground truth
(`Dataset/ground_truth_FINAL.csv`, 120 rows, 62 normal / 58 abnormal, no
duplicate `scenario_id`) or the frozen OTRF manifest (18 rows). No file was
modified during this audit.

## 1. Expected counts — all confirmed exactly as specified

| Artefact | Expected | Observed | Status |
|---|---|---|---|
| Primary baseline raw (5 models x 120) | 600 | 600 (120 x 5, exact per model) | OK |
| Primary RAG raw (5 models x 120) | 600 | 600 (120 x 5, exact per model) | OK |
| Consistency baseline raw (5 models x 20 scenarios x 5 reps) | 500 | 500 (100 x 5, exact per model) | OK |
| Consistency RAG raw (5 models x 20 scenarios x 5 reps) | 500 | 500 (100 x 5, exact per model) | OK |
| OTRF baseline raw (5 models x 18 scenarios) | 90 | 90 (18 x 5, exact per model) | OK |
| OTRF RAG raw (5 models x 18 scenarios) | 90 | 90 (18 x 5, exact per model) | OK |
| OTRF neutral inputs (EXT_001-EXT_018) | 18 | 18 present on disk | OK |
| OTRF selected source datasets (EXT_001-EXT_018 zips) | 18 | 18 hash-verified (16 in tracked source dir; EXT_010, EXT_014 recovered 2026-07-19 from a local untracked OTRF clone) | RESOLVED — all 18 SHA-256 match the frozen manifest; raw archives kept local + untracked (see MISSING_EVIDENCE.csv, source/README.md) |

No file in any of the eight raw-output categories contained fewer or more
records than the counts above.

## 2. Malformed JSONL lines

**Zero** malformed lines found across all 20 primary raw files (10), all 10
consistency raw files, and all 10 OTRF raw files (40 files, ~1,780 lines
total parsed). Every line parsed as valid JSON.

## 3. Duplicate scenario records

**Zero** duplicate `scenario_id` values within any primary baseline/RAG raw
or review file. **Zero** duplicate `(scenario_id, repetition)` keys within any
consistency raw file. **Zero** duplicate `external_scenario_id` values within
any OTRF raw file.

## 4. Missing scenario records

**Zero.** Every primary raw/review file contains all 120 `scenario_id` values
from the frozen ground truth, no more and no fewer. Every consistency raw file
contains exactly 20 distinct scenarios x 5 repetitions (reps 1-5, no gaps).
Every OTRF raw file contains all 18 `EXT_00x` scenario IDs from the frozen
manifest.

Cross-check: the 20 scenarios used for the consistency study are identical
across all 5 models, identical between the baseline and RAG condition, and
form a fixed subset selected once (see `results/consistency/reports/
consistency_selection.csv`, deterministic seed 2026).

## 5. Unexpected scenario IDs

**Zero.** No file contains a `scenario_id` / `external_scenario_id` outside
its respective frozen id set.

## 6. Model names

**Zero incorrect model names.** Every raw record's `model` field matches one
of the five expected Ollama tags exactly: `llama3`, `deepseek-r1:8b`,
`gemma3:12b`, `qwen3:8b`, `gpt-oss:20b`. (Directory names use the
filesystem-safe form, e.g. `deepseek-r1_8b/`; this is a path-safety
transliteration done by `safe_model_dir()` in the runners, not a naming
error — the field inside every record is the real model tag.)

## 7. Output files with more/fewer records than expected

**None found.** See table in section 1 — every file matches its expected
count exactly.

## 8. Non-committal / invalid outputs already present in the frozen data

These are not integrity problems — they are genuine model behaviour, frozen
and unchanged. Recorded here because they directly explain why the primary
comparison evaluator (Phase 3) needed correcting, and they anchor the
DeepSeek RAG acceptance check:

| Location | Placeholder value | Count |
|---|---|---|
| `results/baseline/deepseek-r1_8b/deepseek-r1_8b_baseline_review.csv` | `"normal or risky"` (template echo) | 1 / 120 |
| `results/rag/deepseek-r1_8b/deepseek-r1_8b_rag_review.csv` | `"normal or risky"` (template echo) | 38 / 120 |
| `results/consistency/baseline/*` (all models combined) | `INVALID_CLASSIFICATION` | 5 / 500 |
| `results/consistency/rag/*` (all models combined) | `INVALID_CLASSIFICATION` | 40 / 500 |
| `external_validation/outputs_rag/deepseek-r1_8b/...` | `fallback: true` (never reached basic schema validity) | 1 / 18 |

All other model/condition combinations in the primary comparison have 0
invalid outputs (json-valid and a committed `normal`/`abnormal` value on every
one of their 120 scenarios). This means the "missing output" and "fallback
output" categories required by the corrected evaluator (Phase 3) are
genuinely zero everywhere in the primary 120-scenario comparison — the
corrected evaluator implements those categories structurally (so they would
be caught if they occurred), but they do not occur in this frozen dataset
except for the one OTRF fallback noted above.

## 9. Dataset composition (context, not a defect)

- `Dataset/ground_truth_FINAL.csv`: 120 scenarios, 62 normal / 58 abnormal, 7
  categories (NORMAL, AUTH, USB, SEC, PROC, NET, PERSIST).
- `Dataset/provenance_report.csv`: 108 scenarios collected from the browser
  extension + endpoint collector, 12 constructed/augmented (not collected
  live) — matches the frozen 120-scenario total exactly.
- `knowledge_base/`: 34 active category documents across the 7 categories
  (5 AUTH, 4 NORMAL, 5 NET, 5 PERSIST, 5 PROC, 5 SEC, 5 USB); 3 `GLOBAL/`
  documents and 20 `_archive_not_indexed/` documents exist on disk but are
  intentionally excluded from retrieval (confirmed in `3-run_rag.py` and
  `otrf_common.py`: `CATEGORY_FOLDERS` never includes `GLOBAL`, and
  `_archive_not_indexed` is not a category folder at all).

## Conclusion

The frozen evidence base for the primary 120-scenario study, the 1,000-record
consistency study, and the OTRF model-output side are **complete and
internally consistent** — no malformed, duplicate, missing, or misattributed
records anywhere. The two OTRF **source** capture files (EXT_010, EXT_014)
that were missing from the tracked tree at preflight were subsequently
recovered from a local untracked OTRF clone and hash-verified against the
frozen manifest (18/18 source hashes now match), enabling the strict OTRF
evaluation to complete without any override flag. The raw source archives are
kept local and untracked (not committed to GitHub); see `MISSING_EVIDENCE.csv`,
`external_validation/source/README.md`, and
`../../thesis_writeup/04_CHAPTER_4_EXTERNAL_VALIDATION_RESULTS.md`.
