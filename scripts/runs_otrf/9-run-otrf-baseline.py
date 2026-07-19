#!/usr/bin/env python3
"""
9-run-otrf-baseline.py
======================

External BASELINE runner for the supplementary OTRF validation. Uses the exact
frozen baseline prompt and exact frozen model settings on the leakage-safe
neutral OTRF inputs. Never reads the external answer key.

Outputs go to external_validation/outputs_baseline/<model>/ and are kept fully
separate from the primary and RAG outputs.

Usage:
    python 9-run-otrf-baseline.py --config external_validation/config/otrf_external_config.json
    python 9-run-otrf-baseline.py --config <cfg> --resume
    python 9-run-otrf-baseline.py --config <cfg> --overwrite
    python 9-run-otrf-baseline.py --config <cfg> --models llama3 --no-cycle
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import otrf_common as oc  # noqa: E402


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="OTRF external baseline runner.")
    ap.add_argument("--config", default=str(oc.DEFAULT_CONFIG_PATH),
                    help="Path to the run config JSON. Defaults to "
                         f"{oc.DEFAULT_CONFIG_PATH} if omitted.")
    ap.add_argument("--models", nargs="+", default=None)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--no-cycle", action="store_true",
                    help="Skip the model load/unload cycle (for quick single-model runs).")
    ap.add_argument("--allow-hash-drift", action="store_true",
                    help="Proceed even if source/neutral-input hashes have drifted since "
                         "preparation. Off by default: drift fails the run.")
    args = ap.parse_args(argv)

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    models = args.models or cfg.get("models", oc.MODELS)

    # Integrity pre-flight: fail by default on any source/neutral-input drift.
    manifest_rows = oc.read_csv(oc.FROZEN_MANIFEST_PATH)
    if not manifest_rows:
        raise SystemExit(f"No frozen manifest at {oc.FROZEN_MANIFEST_PATH}. "
                         f"Run 8-prepare-otrf-external.py first.")
    violations = oc.verify_manifest_integrity(manifest_rows)
    try:
        oc.require_no_violations(violations, "frozen manifest vs. current source/neutral inputs",
                                 args.allow_hash_drift)
    except oc.IntegrityError as exc:
        raise SystemExit(str(exc))

    # Scenarios come ONLY from the frozen manifest's scenario ids, never a
    # directory listing of neutral_inputs/.
    scenarios = oc.load_neutral_inputs()
    if not scenarios:
        raise SystemExit(f"No prepared neutral inputs under {oc.NEUTRAL_INPUTS_DIR}. "
                         f"Run 8-prepare-otrf-external.py first.")

    def prompt_for(ext_id, neutral_input):
        return oc.build_baseline_prompt(neutral_input), {}

    print(f"OTRF baseline: {len(scenarios)} scenarios x {len(models)} models "
          f"(answer key NOT loaded).")
    results = []
    for model in models:
        print(f"\n{'='*66}\nMODEL: {model} (baseline)\n{'='*66}")
        results.append(oc.run_model_over_scenarios(
            model, scenarios, prompt_for, "baseline",
            oc.OUTPUTS_BASELINE_DIR, args.resume, args.overwrite, cycle=not args.no_cycle))

    (oc.LOGS_DIR).mkdir(parents=True, exist_ok=True)
    (oc.LOGS_DIR / "baseline_run_summary.json").write_text(
        json.dumps({"generated_utc": oc.utc_now(), "runs": results}, indent=2), encoding="utf-8")
    print("\n" + json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
