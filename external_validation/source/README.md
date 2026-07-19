# OTRF source captures — LOCAL ONLY, intentionally not committed

This directory holds the raw third-party OTRF (Open Threat Research Forge)
`Security-Datasets` capture archives used as the source evidence for the 18
external-validation scenarios (`EXT_001`–`EXT_018`). **These raw archives are
deliberately NOT committed to Git** and are ignored via `.gitignore`.

## Why they are not committed

- They are **not authored dissertation content** — they are unmodified,
  independently published third-party security-telemetry archives.
- They are named after and contain records of real offensive tooling (Empire,
  Mimikatz, Metasploit, LSASS/NTDS dumping, etc.), which trips GitHub's and
  antivirus heuristic malware scanners even though the archives contain only
  JSON/EVTX **event-log data** — static evidence, not executables.
- They are large.

Only this `README.md` is tracked in this directory.

## What IS preserved in the repository (so the work stays reproducible)

- **Official source URLs** for every scenario — `source_url_if_known` column of
  `external_validation/prepared/frozen_external_manifest.csv`.
- **Expected SHA-256 hashes** of every source archive — `source_hash` column of
  the same frozen manifest.
- The **leakage-safe neutral inputs** derived from these sources —
  `external_validation/prepared/neutral_inputs/EXT_*.json` (tracked,
  hash-verified against the manifest's `neutral_input_hash`).
- The **frozen retrieval plan** and the **completed model outputs** — tracked
  under `external_validation/retrieval/` and `external_validation/outputs_*/`.

## How the evaluator finds the raw sources

The evaluator (`scripts/runs_otrf/11-evaluate-otrf-external.py`) requires **you**
to provide the local source directory. Supply it either way:

```powershell
python scripts\runs_otrf\11-evaluate-otrf-external.py `
  --config external_validation\config\otrf_external_config.json `
  --source-root "C:\path\to\your\local\OTRF\Security-Datasets"
```

or via an environment variable:

```powershell
$env:OTRF_SOURCE_ROOT = "C:\path\to\your\local\OTRF\Security-Datasets"
python scripts\runs_otrf\11-evaluate-otrf-external.py --config external_validation\config\otrf_external_config.json
```

Resolution order per scenario: the tracked per-`EXT` layout in this folder (if a
copy is present locally); then, under `--source-root`, the manifest-URL-
reconstructed OTRF path (authoritative — disambiguates a basename that occurs
in more than one OTRF folder); then a SHA-256-verified recursive search. Every
resolved file is hash-checked against the frozen manifest, so a wrong version
or a substituted capture is rejected. The local source path is never written
into any report, CSV or certificate — reports refer to it only as the
"local untracked OTRF source directory".

## Handling rules

- **Do not execute any script** contained inside these datasets. They are used
  **only** as static security-event evidence (parsed as data by the adapter).
- **Do not disable antivirus or any security control** to work with them.
- **Do not commit, stage, or push** the raw archives.
- **Do not substitute** a different capture for a scenario: the SHA-256 must
  match the frozen manifest or the evaluator fails by default (no
  `--allow-hash-drift` for the final dissertation evaluation).
