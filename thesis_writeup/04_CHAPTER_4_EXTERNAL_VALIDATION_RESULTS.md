# 04 — Chapter 4: OTRF External Validation Results

**STATUS: BLOCKED — no certified metrics exist as of 2026-07-19.** Do not
write a results subsection with numeric OTRF findings until this is resolved.
This file documents what is and is not available, so the gap is visible and
traceable rather than silently absent from the dissertation.

## What happened

`scripts/runs_otrf/11-evaluate-otrf-external.py` fails its integrity gate by
design:

```
Integrity check failed (frozen manifest vs. current source/neutral inputs): 2 violation(s):
  EXT_010: source file hash drift (external_validation/source/EXT_010/empire_schtasks_creation_standard_user.zip)
  EXT_014: source file hash drift (external_validation/source/EXT_014/empire_shell_samr_EnumDomainUsers.zip)
```

Two of the eighteen raw OTRF source captures
(`external_validation/source/EXT_010/`, `EXT_014/`) are missing from disk —
confirmed in `docs/final_audit/MISSING_EVIDENCE.csv`. `sha256_file()` returns
the sentinel `not_available` for a missing file, which never equals the
frozen hash recorded in `external_validation/prepared/
frozen_external_manifest.csv`, so the evaluator correctly refuses to proceed.
The evaluator supports `--allow-hash-drift` to produce a **separate
diagnostic report**, explicitly never the final dissertation evaluation; that
diagnostic run was not performed in this pass. See
`external_validation/evaluation/README_BLOCKED.md`.

## What IS available and verified

- All **18 neutral inputs** (`external_validation/prepared/neutral_inputs/
  EXT_001.json`–`EXT_018.json`) are present and their SHA-256 hashes match
  `frozen_external_manifest.csv`'s `neutral_input_hash` column exactly, 18/18
  (recomputed during this pass; see `docs/final_audit/EVIDENCE_INVENTORY.md`).
- All **180 OTRF model output records** (5 models x 18 scenarios x 2
  conditions = 90 + 90) exist, are hash-stable across this entire pass
  (`docs/final_audit/FROZEN_ARTIFACT_HASHES.csv`), contain zero malformed
  lines, zero duplicate/missing scenario IDs, and correct model names.
  `external_validation/outputs_rag/deepseek-r1_8b/...` contains exactly 1
  `fallback: true` record (out of 18) — the only OTRF output that never
  reached basic schema validity; every other model/condition combination has
  zero.
- 16 of 18 raw source captures are present and hash-match the frozen
  manifest.

## What is NOT available

- No abnormal recall, false-negative rate, output coverage, JSON/schema
  validity rates, retry/timeout/fallback rates, latency, OOV indicator rate,
  or McNemar/Holm comparison for the OTRF sample can be reported as
  **certified** results, because the evaluator that produces them refuses to
  run end-to-end while EXT_010/EXT_014 are missing.
- `thesis_writeup/excel_source/otrf_model_condition_metrics.csv` and
  `otrf_reliability.csv` are intentionally left as placeholder files with a
  status note, not fabricated numbers.

## What to write in the dissertation now

State plainly that the OTRF supplementary validation was designed and
partially executed (180/180 model output records completed and hash-verified
before the source-file loss), but final certified metrics are pending
recovery of the two missing source captures, which must hash-match
`b073a18420c90394cd2b6ad7589c78d90eba32dc155ed04b12ac824a8fc591b4` (EXT_010)
and `b37c022ce7aa5fed3ad7087e2ec1f37d7b1089ec9bfe7b196f974295d255506b`
(EXT_014) respectively before being accepted (`docs/final_audit/
MISSING_EVIDENCE.csv`). Do not substitute a different OTRF capture for either
scenario.

## Framing to use once unblocked

Even once re-run cleanly, OTRF results support only a **limited, specific**
claim: **technical transportability** — that the implemented pipeline can
process independently sourced, publicly available Windows security telemetry
after deterministic normalisation. They do **not** support a claim of
**organisational real-world generalisability**: the sample is a
controlled, abnormal-dominated public research corpus (all 18 scenarios are
ground-truth abnormal by construction), not production telemetry from a real
organisation, so precision, specificity, balanced accuracy and a benign
false-positive rate are not estimable from it, and severity accuracy is not
estimable without a defensible external severity key. This framing is
already built into the evaluator itself
(`scripts/runs_otrf/11-evaluate-otrf-external.py`, `NOT_ESTIMABLE` markers)
and must be preserved regardless of when the two source files are recovered.
