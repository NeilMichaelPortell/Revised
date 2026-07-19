# Canonical Artefact Paths

Generated during the final evidence-integrity pass (2026-07-19); updated the
same day during a follow-up code-correction pass (indicator-overlap metric
split, portable hash ledger, stale-folder cleanup). This document resolves
the "duplicate-looking" directories the task flagged: which copy is
authoritative, which is legacy, and what happened to each.

## Method

Every root-level directory that shadows a path under `results/` or
`external_validation/` was byte-compared (`diff -rq`) against its canonical
counterpart. **Raw-output** duplicates (unchanged since Phase 0) were found
to be exact byte-for-byte copies. **Derived-report** duplicates
(`comparison/`, `consistency_results/`) were re-checked after the
indicator-overlap metric correction and other Phase-1 fixes regenerated their
canonical counterparts under `results/` — at that point they were **no
longer identical**: `comparison/` still held the single-column
`indicator_overlap` metric and pre-correction McNemar/scenario-change output
(and two files, `confusion_matrices.txt` / `indicator_overlap_note.txt`, that
never existed under `results/comparison/` at all); `consistency_results/`
still held the pre-Ollama-probe-fix `run_manifest.json` and pre-`fmt_p`
`baseline_vs_rag_consistency.csv`/`baseline_vs_rag_summary.txt`. These two
stale derived-report folders were archived in full (with their nested
`baseline/`/`rag/` per-model-condition subfolders) to
`results/archive/stale_root_comparison_<timestamp>/` and
`results/archive/stale_root_consistency_results_<timestamp>/`, then removed
from the working tree and from version control (`git rm -r`) — do not claim
in any dissertation text that these two folders were byte-identical to the
canonical tree; they were not, by the time of removal.

| Legacy path (root-level) | Canonical path | Status |
|---|---|---|
| `outputs_rag/` | `results/rag/` | Retained; raw output, spot-checked byte-identical (`llama3_rag_raw.jsonl`) |
| `outputs_consistency_baseline/` | `results/consistency/baseline/` | Retained; raw output, spot-checked byte-identical |
| `outputs_consistency_rag/` | `results/consistency/rag/` | Retained; raw output, spot-checked byte-identical |
| `comparison/` | `results/comparison/` | **Removed 2026-07-19** (was stale/diverged, not identical); archived under `results/archive/stale_root_comparison_<timestamp>/` |
| `consistency_results/` | `results/consistency/reports/` | **Removed 2026-07-19** (was stale/diverged, not identical); archived under `results/archive/stale_root_consistency_results_<timestamp>/` |

No root-level `baseline/` directory exists (i.e. `results/baseline/` has no
legacy shadow copy). The raw-output duplicates (`outputs_rag/`,
`outputs_consistency_baseline/`, `outputs_consistency_rag/`) were left in
place: unlike the two derived-report folders above, nothing in this pass
regenerated their canonical counterparts, so their prior byte-identical
spot-check still holds. They remain candidates for a future manual
housekeeping pass.

## Canonical paths for all downstream work

These are the paths this audit, the corrected evaluators, and the thesis
write-up pack treat as authoritative. All commands in this pass read from and
write to these paths only.

```
results/baseline/                        primary baseline raw + review + summary (5 models)
results/rag/                             primary RAG raw + review + summary (5 models) + retrieval_plan.json
results/comparison/                      primary baseline-vs-RAG derived reports (regenerated this pass)
results/consistency/baseline/            consistency baseline raw (5 models x 100 records)
results/consistency/rag/                 consistency RAG raw (5 models x 100 records)
results/consistency/reports/             consistency derived reports (regenerated this pass)
external_validation/outputs_baseline/    OTRF baseline raw (5 models x 18 scenarios)
external_validation/outputs_rag/         OTRF RAG raw (5 models x 18 scenarios)
external_validation/evaluation/          OTRF evaluator output (regenerated this pass, see Phase 7)
external_validation/prepared/            OTRF frozen manifest, external ground truth, neutral inputs
external_validation/retrieval/           OTRF frozen retrieval plan
Dataset/                                 frozen 120-scenario dataset + ground_truth_FINAL.csv
knowledge_base/{AUTH,NET,NORMAL,PERSIST,PROC,SEC,USB}/   34 active knowledge-base documents
```

## Non-canonical (legacy) paths — retained, not authoritative

These raw-output directories are **not deleted**. They are stale copies, most
likely left over from an earlier output-path convention before results were
consolidated under `results/` and `external_validation/`. Nothing downstream
(evaluators, tests, thesis write-up) reads from them. They should be
considered for manual removal in a future housekeeping pass, once the
dissertation is filed, but that decision is left to the author.

```
outputs_rag/                     legacy duplicate of results/rag/
outputs_consistency_baseline/    legacy duplicate of results/consistency/baseline/
outputs_consistency_rag/         legacy duplicate of results/consistency/rag/
```

## Removed (2026-07-19, follow-up code-correction pass)

Unlike the raw-output duplicates above, these two **derived-report**
directories were diverging (not identical) from their canonical counterpart
once the indicator-overlap metric split and other Phase-1 fixes regenerated
`results/comparison/` and were previously regenerated under
`results/consistency/reports/`. They were archived in full, then removed from
the working tree and from version control (`git rm -r`) rather than left in
place stale:

```
comparison/               was: legacy duplicate of results/comparison/ (pre-correction copy;
                          diverged after the indicator-overlap metric correction). Archived to
                          results/archive/stale_root_comparison_<timestamp>/, then removed.
consistency_results/      was: legacy duplicate of results/consistency/reports/ (diverged after
                          the p-value-formatting / Ollama-probe fixes to 7-evaluate_consistency.py).
                          Included a nested consistency_results/{baseline,rag}/ per-model-condition
                          report subfolder. Archived to
                          results/archive/stale_root_consistency_results_<timestamp>/, then removed.
                          (consistency_results/consistency_selection.csv had matched
                          results/consistency/reports/consistency_selection.csv; a further-legacy
                          selection file remains at
                          results/consistency/archive/legacy_consistency_selection.csv.)
```

## Also present, not part of the evaluation evidence chain

```
prototype/            standalone prototype application (Chapter 4 "prototype feasibility" result;
                       not part of the 120-scenario / consistency / OTRF evidence)
docs/evidence/         raw manual scenario-construction notes (provenance, not model output)
docs/review/           reviewer feedback notes
commands.txt           ad hoc command scratch notes (repo root)
Security-Datasets-master/ (gitignored) third-party OTRF clone the source pool is drawn from;
                       not authored content, correctly excluded from version control
```
