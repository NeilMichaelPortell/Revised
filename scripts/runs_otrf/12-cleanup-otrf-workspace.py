#!/usr/bin/env python3
"""
12-cleanup-otrf-workspace.py
=============================

Safe cleanup for the SUPPLEMENTARY OTRF external-validation workspace only.
Never touches the frozen 120-scenario primary experiment, Dataset/,
knowledge_base/, results/, or anything outside a small, explicit allowlist of
OTRF-generated paths.

Hard rules enforced by this script (see README section "Safe folder cleanup"):
  1. Never deletes external_validation/source/ (source datasets).
  2. Never deletes external_validation/config/* (manifests/config are manually
     maintained, not generated).
  3. Frozen artefacts (frozen_external_manifest.csv, external_ground_truth.csv,
     frozen_otrf_retrieval_plan.jsonl) are only ever touched via --reset-frozen,
     which ALWAYS archives them first.
  4. Anything replaced under rule 3 is copied to
     external_validation/archive/<UTC_TIMESTAMP>/ before removal.
  5. Only the fixed allowlist below is ever considered; the whole repository
     is never walked or cleaned.
  6. Every target is a specific, named path -- never a recursive delete of an
     arbitrary/unknown folder discovered at runtime.
  7. Every path selected for deletion is printed BEFORE deletion, in both
     dry-run and confirmed modes.
  8. --dry-run reports exactly what would be removed and removes nothing.
  9. Deleting anything requires the explicit --confirm-clean flag; without it
     the script always behaves as a dry run (prints and exits 0).

Usage:
    python 12-cleanup-otrf-workspace.py --dry-run
    python 12-cleanup-otrf-workspace.py --confirm-clean
    python 12-cleanup-otrf-workspace.py --confirm-clean --targets outputs_baseline outputs_rag
    python 12-cleanup-otrf-workspace.py --confirm-clean --reset-frozen   # archives + resets
                                                                         # the frozen manifest/
                                                                         # ground truth/plan
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import otrf_common as oc  # noqa: E402

# --------------------------------------------------------------------------- #
# Fixed allowlist of generated/temporary OTRF artefact locations. Nothing      #
# outside this list is ever considered, satisfying "no recursive delete of    #
# unknown folders" and "never clean the entire repository".                   #
# --------------------------------------------------------------------------- #
GENERATED_TARGETS: dict[str, Path] = {
    "neutral_inputs": oc.NEUTRAL_INPUTS_DIR,
    "outputs_baseline": oc.OUTPUTS_BASELINE_DIR,
    "outputs_rag": oc.OUTPUTS_RAG_DIR,
    "evaluation": oc.EVALUATION_DIR,
    "logs": oc.LOGS_DIR,
    "retrieval": oc.RETRIEVAL_DIR,
    "tests_tmp": oc.EXTERNAL_DIR / "tests" / "tmp",
    "tests_tmp_underscore": oc.EXTERNAL_DIR / "tests" / "_tmp",
    "pycache_scripts": Path(__file__).resolve().parent / "__pycache__",
    "pycache_tests": oc.EXTERNAL_DIR / "tests" / "__pycache__",
    "pytest_cache_root": oc.ROOT_DIR / ".pytest_cache",
    "pytest_cache_external": oc.EXTERNAL_DIR / ".pytest_cache",
    "pytest_cache_tests": oc.EXTERNAL_DIR / "tests" / ".pytest_cache",
}

# Paths this script must NEVER remove, even by accident (defence in depth on
# top of the allowlist itself only naming generated locations).
PROTECTED_PATHS = [
    oc.SOURCE_DIR,
    oc.CONFIG_DIR,
    oc.ROOT_DIR / "Dataset",
    oc.ROOT_DIR / "knowledge_base",
    oc.ROOT_DIR / "results",
]

FROZEN_ARTEFACTS = {
    "frozen_external_manifest": oc.FROZEN_MANIFEST_PATH,
    "external_ground_truth": oc.EXTERNAL_GROUND_TRUTH_PATH,
    "frozen_otrf_retrieval_plan": oc.FROZEN_RETRIEVAL_PLAN_PATH,
}


def _is_protected(path: Path) -> bool:
    try:
        rp = path.resolve()
    except OSError:
        return False
    for prot in PROTECTED_PATHS:
        try:
            prp = prot.resolve()
        except OSError:
            continue
        if rp == prp or prp in rp.parents:
            return True
    return False


def list_paths_under(dir_path: Path) -> list[Path]:
    """List every file and directory under dir_path (top-down), for printing
    before deletion. Empty if dir_path does not exist."""
    if not dir_path.exists():
        return []
    return sorted(dir_path.rglob("*"))


def clean_target(label: str, dir_path: Path, dry_run: bool) -> dict:
    """Remove the CONTENTS of dir_path (the directory itself is recreated
    empty, never left missing, so downstream scripts' mkdir(exist_ok=True)
    keeps working). Returns a small report dict."""
    if _is_protected(dir_path):
        raise SystemExit(f"Refusing to clean protected path: {dir_path}")
    entries = list_paths_under(dir_path)
    print(f"\n[{label}] {dir_path}")
    if not entries:
        print("  (nothing to remove)")
        return {"target": label, "path": str(dir_path), "removed": 0}
    for p in entries:
        verb = "would remove" if dry_run else "removing"
        print(f"  {verb}: {p}")
    if not dry_run:
        shutil.rmtree(dir_path, ignore_errors=True)
        dir_path.mkdir(parents=True, exist_ok=True)
    return {"target": label, "path": str(dir_path), "removed": len(entries)}


def archive_and_reset_frozen(dry_run: bool) -> list[str]:
    """Copy every existing frozen artefact into
    external_validation/archive/<UTC_TIMESTAMP>/ and then remove the
    originals. ALWAYS archives before removing (rule 4). Returns the list of
    archived file paths (as strings)."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive_dir = oc.EXTERNAL_DIR / "archive" / ts
    archived: list[str] = []
    existing = {name: p for name, p in FROZEN_ARTEFACTS.items() if p.exists()}
    if not existing:
        print("\n[reset-frozen] no frozen manifest/ground-truth/retrieval-plan files exist; nothing to archive.")
        return archived
    print(f"\n[reset-frozen] archiving {len(existing)} frozen artefact(s) to {archive_dir} before removal:")
    for name, p in existing.items():
        dest = archive_dir / p.name
        print(f"  archive: {p} -> {dest}")
        if not dry_run:
            archive_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dest)
        archived.append(str(dest))
    for name, p in existing.items():
        verb = "would remove" if dry_run else "removing"
        print(f"  {verb} (post-archive): {p}")
        if not dry_run:
            p.unlink()
    return archived


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Safe cleanup for the OTRF external-validation workspace.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Report exactly what would be removed; remove nothing.")
    ap.add_argument("--confirm-clean", action="store_true",
                    help="Required to actually delete anything. Without this flag the "
                         "script always behaves as --dry-run regardless of this flag's absence.")
    ap.add_argument("--targets", nargs="+", choices=sorted(GENERATED_TARGETS.keys()),
                    default=None,
                    help="Restrict cleanup to specific generated targets (default: all).")
    ap.add_argument("--reset-frozen", action="store_true",
                    help="ALSO archive (to external_validation/archive/<UTC_TIMESTAMP>/) and "
                         "then remove the frozen manifest, external ground truth, and frozen "
                         "retrieval plan. Off by default; use only when these are confirmed "
                         "invalid/stale and need regenerating from scratch.")
    args = ap.parse_args(argv)

    # Absence of --confirm-clean means dry-run behaviour no matter what.
    effective_dry_run = args.dry_run or not args.confirm_clean
    if effective_dry_run and not args.dry_run:
        print("NOTE: --confirm-clean not given; running in dry-run mode. "
              "Pass --confirm-clean to actually delete anything.\n")

    targets = args.targets or sorted(GENERATED_TARGETS.keys())
    report = []
    for label in targets:
        report.append(clean_target(label, GENERATED_TARGETS[label], effective_dry_run))

    archived: list[str] = []
    if args.reset_frozen:
        archived = archive_and_reset_frozen(effective_dry_run)

    total_removed = sum(r["removed"] for r in report)
    print(f"\n{'DRY RUN: ' if effective_dry_run else ''}"
          f"{total_removed} path(s) {'would be' if effective_dry_run else ''} removed "
          f"across {len(targets)} target(s).")
    if args.reset_frozen:
        print(f"{'DRY RUN: ' if effective_dry_run else ''}"
              f"{len(archived)} frozen artefact(s) {'would be' if effective_dry_run else ''} "
              f"archived and reset.")


if __name__ == "__main__":
    main()
