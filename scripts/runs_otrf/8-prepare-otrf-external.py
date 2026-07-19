#!/usr/bin/env python3
"""
8-prepare-otrf-external.py
==========================

SUPPLEMENTARY external-validation preparer. Converts user-supplied OTRF Windows
host-event datasets into leakage-safe neutral model inputs, a SEPARATE external
answer key, a frozen manifest and adapter audits. Performs NO model inference.

This never touches the frozen 120-scenario dataset, its ground truth, or any
primary/consistency output.

Path handling: `source_relative_path` in the manifest resolves relative to
`external_validation/source/` (or the config's `source_dir`, if set) UNLESS it
is an absolute path. It is NOT relative to the repository root.

Malformed/empty/zero-supported-event source files are rejected explicitly and
recorded (never silently turned into a quiet, misleadingly "normal" scenario).

Usage (run from scripts/runs/ or repo root):
    python 8-prepare-otrf-external.py --config external_validation/config/otrf_external_config.json
    python 8-prepare-otrf-external.py --config <cfg> --overwrite   # regenerate a frozen prep
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import otrf_common as oc          # noqa: E402
import otrf_adapter as oa         # noqa: E402


def load_config(config_path: Path) -> dict:
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    return cfg


def resolve(root: Path, rel: str) -> Path:
    """Repo-root-relative resolution, used ONLY for the manifest CSV path
    itself (a config path, not a per-row source dataset path)."""
    p = Path(rel)
    return p if p.is_absolute() else (root / rel)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Prepare OTRF external validation dataset.")
    ap.add_argument("--config", default=str(oc.DEFAULT_CONFIG_PATH),
                    help="Path to the run config JSON. Defaults to "
                         f"{oc.DEFAULT_CONFIG_PATH} if omitted.")
    ap.add_argument("--overwrite", action="store_true",
                    help="Regenerate even if a frozen manifest already exists. Also "
                         "reconciles neutral_inputs/ strictly against the active "
                         "manifest: any EXT_*.json for a scenario id no longer in "
                         "the manifest is deleted.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Report what would be prepared/removed without writing anything.")
    args = ap.parse_args(argv)

    cfg = load_config(Path(args.config))
    root = oc.ROOT_DIR
    manifest_csv = resolve(root, cfg["dataset_manifest_csv"])
    max_events = int(cfg.get("window", {}).get("max_events_per_scenario", 5000))
    source_dir = resolve(root, cfg.get("source_dir", "external_validation/source"))

    # ---- freeze protection --------------------------------------------------
    if oc.FROZEN_MANIFEST_PATH.exists() and not args.overwrite:
        raise SystemExit(
            f"A frozen manifest already exists at {oc.FROZEN_MANIFEST_PATH}.\n"
            f"Refusing to regenerate. Re-run with --overwrite to replace it."
        )

    manifest_rows = oc.read_csv(manifest_csv)
    if not manifest_rows:
        raise SystemExit(f"No manifest rows found in {manifest_csv}. Fill in the template first.")

    if not args.dry_run:
        for d in (oc.PREPARED_DIR, oc.NEUTRAL_INPUTS_DIR, oc.LOGS_DIR):
            d.mkdir(parents=True, exist_ok=True)

    frozen_rows: list[dict] = []
    ground_truth_rows: list[dict] = []
    audit_rows: list[dict] = []
    unsupported_rows: list[dict] = []
    prepared_ids: set[str] = set()
    prepared_count = 0
    skipped_count = 0
    seen_ids: dict[str, int] = {}

    for row in manifest_rows:
        ext_id = (row.get("external_scenario_id") or "").strip()
        rel_path = (row.get("source_relative_path") or "").strip()

        if ext_id:
            seen_ids[ext_id] = seen_ids.get(ext_id, 0) + 1
            if seen_ids[ext_id] > 1:
                skipped_count += 1
                audit_rows.append({"external_scenario_id": ext_id, "status": "duplicate_manifest_id",
                                   "detail": "external_scenario_id repeated in manifest; row skipped"})
                continue

        if not ext_id or not rel_path or "FILL_IN" in rel_path or "PUT_THE_DATASET_FILE_HERE" in rel_path:
            skipped_count += 1
            audit_rows.append({"external_scenario_id": ext_id or "(blank)",
                               "status": "skipped_template_row",
                               "detail": "manifest row not filled in"})
            continue

        src = oc.resolve_source_path(rel_path, source_dir)
        if not src.exists():
            skipped_count += 1
            unsupported_rows.append({"external_scenario_id": ext_id, "source_path": str(src),
                                     "reason": "source_file_missing"})
            audit_rows.append({"external_scenario_id": ext_id, "status": "missing_source",
                               "detail": str(src)})
            continue

        fmt = oa.detect_format(src)
        if fmt == "unsupported":
            skipped_count += 1
            unsupported_rows.append({"external_scenario_id": ext_id, "source_path": str(src),
                                     "reason": f"unsupported_format ({src.suffix})"})
            audit_rows.append({"external_scenario_id": ext_id, "status": "unsupported_format",
                               "detail": src.name})
            continue

        try:
            adapted = oa.adapt_source_file(src, max_events)
        except oa.EmptyDatasetError as exc:
            skipped_count += 1
            unsupported_rows.append({"external_scenario_id": ext_id, "source_path": str(src),
                                     "reason": f"zero_valid_events: {exc}"})
            audit_rows.append({"external_scenario_id": ext_id, "status": "rejected_zero_valid_events",
                               "detail": str(exc)})
            continue
        except oa.UnsupportedTelemetryError as exc:
            skipped_count += 1
            unsupported_rows.append({"external_scenario_id": ext_id, "source_path": str(src),
                                     "reason": f"zero_supported_events: {exc}"})
            audit_rows.append({"external_scenario_id": ext_id, "status": "rejected_zero_supported_events",
                               "detail": str(exc)})
            continue
        except oa.UnsupportedFormatError as exc:
            skipped_count += 1
            unsupported_rows.append({"external_scenario_id": ext_id, "source_path": str(src),
                                     "reason": str(exc)})
            audit_rows.append({"external_scenario_id": ext_id, "status": "parse_rejected",
                               "detail": str(exc)})
            continue

        neutral_input = adapted["neutral_input"]

        # ---- leakage gate: never write a neutral input that leaks -----------
        violations = oa.assert_no_leakage(neutral_input)
        if violations:
            skipped_count += 1
            audit_rows.append({"external_scenario_id": ext_id, "status": "leakage_blocked",
                               "detail": "; ".join(violations)})
            continue

        prepared_ids.add(ext_id)
        neutral_text = json.dumps(neutral_input, indent=2, ensure_ascii=False)
        neutral_path = oc.NEUTRAL_INPUTS_DIR / f"{ext_id}.json"
        if args.dry_run:
            print(f"[dry-run] would write {neutral_path}")
        else:
            neutral_path.write_text(neutral_text, encoding="utf-8")
        prepared_count += 1

        source_hash = oc.sha256_file(src)
        neutral_hash = oc.sha256_text(neutral_text)

        # ---- frozen manifest (provenance, kept OUT of model input) ----------
        frozen_rows.append({
            "external_scenario_id": ext_id,
            "source_project": "OTRF/Security-Datasets",
            "source_dataset_id": row.get("source_dataset_id", ""),
            "source_title": row.get("source_title", ""),
            "source_path": rel_path,
            "source_url_if_known": row.get("source_url_if_known", ""),
            "source_hash": source_hash,
            "neutral_input_hash": neutral_hash,
            "platform": row.get("platform", "windows"),
            "attack_or_benign_label": (row.get("attack_or_benign_label") or "").strip().lower(),
            "attack_technique_if_provided": row.get("attack_technique_if_provided", ""),
            "selection_reason": row.get("selection_reason", ""),
            "telemetry_format": fmt,
            "event_count_total": adapted["event_count_total"],
            "event_count_window": adapted["event_count_window"],
            "parsed_line_total": adapted["parsed_line_total"],
            "malformed_line_count": adapted["malformed_line_count"],
            "supported_event_count": adapted["supported_event_count"],
            "ignored_event_count": adapted["ignored_event_count"],
            "window_start_utc": adapted["window_start_utc"],
            "window_end_utc": adapted["window_end_utc"],
            "adapter_version": oc.ADAPTER_VERSION,
            "manifest_version": oc.MANIFEST_VERSION,
        })

        # ---- external answer key (SEPARATE; joined only at evaluation) ------
        sev = (row.get("severity_if_provided") or "").strip().lower()
        raw_label = (row.get("attack_or_benign_label") or "").strip().lower()
        # Standard, documented binary mapping for evaluation only. The raw OTRF
        # label is preserved verbatim in external_label_raw; no 7-category label
        # and no severity are invented here. Anything that does not map to a
        # known attack/benign synonym is "unknown" and is EXCLUDED from the
        # abnormal/benign denominators at evaluation time (never defaulted to
        # abnormal or benign).
        if raw_label in {"attack", "abnormal", "malicious", "adversary", "adversarial"}:
            external_class = "abnormal"
        elif raw_label in {"benign", "normal", "clean"}:
            external_class = "benign"
        else:
            external_class = "unknown"
        ground_truth_rows.append({
            "external_scenario_id": ext_id,
            "external_class": external_class,
            "external_label_raw": raw_label,
            "attack_technique_if_provided": row.get("attack_technique_if_provided", ""),
            "severity_if_provided": sev if sev in {"low", "medium", "high", "critical"} else "not_provided",
            "source_title": row.get("source_title", ""),
        })

        # ---- adapter audit: what evidence was extracted / what was unmapped --
        prov_kinds = sorted({p["evidence"] for p in adapted["provenance"]})
        audit_rows.append({
            "external_scenario_id": ext_id,
            "status": "prepared",
            "event_count_total": adapted["event_count_total"],
            "event_count_window": adapted["event_count_window"],
            "parsed_line_total": adapted["parsed_line_total"],
            "malformed_line_count": adapted["malformed_line_count"],
            "supported_event_count": adapted["supported_event_count"],
            "ignored_event_count": adapted["ignored_event_count"],
            "evidence_extracted": "; ".join(prov_kinds) if prov_kinds else "(none)",
            "process_images_observed": "; ".join(adapted["process_images_observed"]),
            "unmapped_event_id_kinds": len(adapted["unmapped_event_ids"]),
            "telemetry_availability": json.dumps(adapted["telemetry_availability"]),
            "detail": "",
        })
        for key, cnt in sorted(adapted["unmapped_event_ids"].items()):
            unsupported_rows.append({"external_scenario_id": ext_id,
                                     "source_path": "(event within window)",
                                     "reason": f"unmapped_event {key} x{cnt}"})

    # ---- stale neutral-input reconciliation (--overwrite only) --------------
    # Requirement: preparation with --overwrite must remove stale neutral-input
    # files that no longer exist in the active manifest. Every path removed is
    # printed before deletion.
    stale_removed: list[str] = []
    if args.overwrite and oc.NEUTRAL_INPUTS_DIR.exists():
        for p in sorted(oc.NEUTRAL_INPUTS_DIR.glob("EXT_*.json")):
            if p.stem not in prepared_ids:
                stale_removed.append(str(p))
                print(f"[stale] {'would remove' if args.dry_run else 'removing'}: {p}")
                if not args.dry_run:
                    p.unlink()

    if args.dry_run:
        print(json.dumps({
            "dry_run": True,
            "would_prepare": prepared_count,
            "would_skip": skipped_count,
            "would_remove_stale": stale_removed,
        }, indent=2))
        return

    # ---- write outputs ------------------------------------------------------
    manifest_fields = ["external_scenario_id", "source_project", "source_dataset_id",
                       "source_title", "source_path", "source_url_if_known", "source_hash",
                       "neutral_input_hash", "platform", "attack_or_benign_label",
                       "attack_technique_if_provided", "selection_reason", "telemetry_format",
                       "event_count_total", "event_count_window", "parsed_line_total",
                       "malformed_line_count", "supported_event_count", "ignored_event_count",
                       "window_start_utc", "window_end_utc", "adapter_version", "manifest_version"]
    oc.write_csv(oc.FROZEN_MANIFEST_PATH, manifest_fields, frozen_rows)
    oc.write_csv(oc.EXTERNAL_GROUND_TRUTH_PATH,
                 ["external_scenario_id", "external_class", "external_label_raw",
                  "attack_technique_if_provided",
                  "severity_if_provided", "source_title"], ground_truth_rows)
    oc.write_csv(oc.PREPARED_DIR / "adapter_audit.csv",
                 ["external_scenario_id", "status", "event_count_total", "event_count_window",
                  "parsed_line_total", "malformed_line_count", "supported_event_count",
                  "ignored_event_count", "evidence_extracted", "process_images_observed",
                  "unmapped_event_id_kinds", "telemetry_availability", "detail"],
                 audit_rows)
    oc.write_csv(oc.PREPARED_DIR / "unsupported_fields.csv",
                 ["external_scenario_id", "source_path", "reason"], unsupported_rows)

    abnormal = sum(1 for r in ground_truth_rows if r["external_class"] == "abnormal")
    benign = sum(1 for r in ground_truth_rows if r["external_class"] == "benign")
    unknown = sum(1 for r in ground_truth_rows if r["external_class"] == "unknown")
    summary = {
        "prepared_scenarios": prepared_count,
        "skipped_rows": skipped_count,
        "abnormal_scenarios": abnormal,
        "defensibly_benign_scenarios": benign,
        "unknown_label_scenarios": unknown,
        "stale_neutral_inputs_removed": stale_removed,
        "adapter_version": oc.ADAPTER_VERSION,
        "manifest_version": oc.MANIFEST_VERSION,
        "max_events_per_scenario": max_events,
        "config_hash": oc.sha256_config(Path(args.config)),
        "generated_utc": oc.utc_now(),
        "frozen_manifest": str(oc.FROZEN_MANIFEST_PATH.relative_to(root)),
        "external_ground_truth": str(oc.EXTERNAL_GROUND_TRUTH_PATH.relative_to(root)),
        "note": "OTRF is controlled public adversary-simulation telemetry, not production data.",
    }
    (oc.PREPARED_DIR / "preparation_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    if prepared_count == 0:
        print("\nNo scenarios prepared. Fill in the manifest and place dataset files under "
              f"{source_dir} before re-running.")


if __name__ == "__main__":
    main()
