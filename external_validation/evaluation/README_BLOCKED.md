# OTRF external evaluation — BLOCKED (2026-07-19)

This directory is intentionally empty.

Running `scripts/runs_otrf/11-evaluate-otrf-external.py --config
external_validation/config/otrf_external_config.json` fails its integrity
gate by design:

```
Integrity check failed (frozen manifest vs. current source/neutral inputs): 2 violation(s):
  EXT_010: source file hash drift (external_validation/source/EXT_010/empire_schtasks_creation_standard_user.zip)
  EXT_014: source file hash drift (external_validation/source/EXT_014/empire_shell_samr_EnumDomainUsers.zip)

Failing by default. Re-run with --allow-hash-drift only if this drift is expected and understood.
```

Both files are genuinely missing from `external_validation/source/` (see
`docs/final_audit/MISSING_EVIDENCE.csv`), not corrupted — they show as
`deleted` in `git status` for this working tree. The evaluator's
`sha256_file()` returns the sentinel `"not_available"` for a missing file,
which never equals the frozen hash, so the integrity check fails exactly as
intended.

The evaluator does support `--allow-hash-drift` to proceed anyway, explicitly
for producing a **separate diagnostic report** (per the evaluator's own
docstring); it must never be used to produce the final dissertation
evaluation. That diagnostic run was not performed in this pass (the action
was declined). The 180 already-completed OTRF model output records
(`external_validation/outputs_baseline/`, `external_validation/outputs_rag/`)
remain untouched, hash-verified, and available — only the end-to-end
source-to-output reproducibility check for these two scenarios cannot be
re-certified until the two files are recovered and re-verified against the
hashes recorded in `external_validation/prepared/frozen_external_manifest.csv`.

**Status: do not report OTRF external-validation metrics as final/certified
until EXT_010 and EXT_014 are recovered and this evaluator runs clean without
`--allow-hash-drift`.**
