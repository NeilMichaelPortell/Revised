# Canonical Artefact Paths

Generated during the final evidence-integrity pass (2026-07-19). This document
resolves the "duplicate-looking" directories the task flagged: which copy is
authoritative, which is legacy, and why nothing was deleted.

## Method

Every root-level directory that shadows a path under `results/` or
`external_validation/` was byte-compared (`diff -q`) against its canonical
counterpart before being classified below. Root-level copies were found to be
**exact byte-for-byte duplicates** of the canonical tree (see spot-checks in
the table). No divergent, unique evidence was found in any legacy directory.

| Legacy path (root-level) | Canonical path | Spot-check result |
|---|---|---|
| `outputs_rag/` | `results/rag/` | `outputs_rag/llama3/llama3_rag_raw.jsonl` identical to `results/rag/llama3/llama3_rag_raw.jsonl` |
| `outputs_consistency_baseline/` | `results/consistency/baseline/` | `.../llama3_baseline_consistency_raw.jsonl` identical |
| `outputs_consistency_rag/` | `results/consistency/rag/` | identical (spot-checked llama3) |
| `comparison/` | `results/comparison/` | `overall_comparison.csv` identical |
| `consistency_results/` | `results/consistency/reports/` | `per_model_consistency.csv` (baseline) identical |

No root-level `baseline/` directory exists (i.e. `results/baseline/` has no
legacy shadow copy).

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

These directories are **not deleted** (per instruction: "do not delete them
automatically"). They are stale copies, most likely left over from an earlier
output-path convention before results were consolidated under `results/` and
`external_validation/`. Nothing downstream (evaluators, tests, thesis
write-up) reads from them. They should be considered for manual removal in a
future housekeeping pass, once the dissertation is filed, but that decision is
left to the author.

```
outputs_rag/                     legacy duplicate of results/rag/
outputs_consistency_baseline/    legacy duplicate of results/consistency/baseline/
outputs_consistency_rag/         legacy duplicate of results/consistency/rag/
comparison/                      legacy duplicate of results/comparison/ (pre-correction copy)
consistency_results/             legacy duplicate of results/consistency/reports/ (includes
                                  consistency_results/consistency_selection.csv, which matches
                                  results/consistency/reports/consistency_selection.csv; a
                                  further-legacy selection file already lives at
                                  results/consistency/archive/legacy_consistency_selection.csv)
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
