#!/usr/bin/env python3
"""
10-run-otrf-rag.py
==================

External RAG (knowledge-augmented) runner for the supplementary OTRF validation.
Uses the exact frozen RAG prompt and model settings, and the FROZEN OTRF
retrieval plan produced by 8-freeze-otrf-retrieval-plan.py. It refuses to run if
the plan is missing and never recomputes retrieval silently. Never reads the
external answer key.

Outputs go to external_validation/outputs_rag/<model>/, separate from baseline
and from the primary experiment.

Usage:
    python 10-run-otrf-rag.py --config external_validation/config/otrf_external_config.json
    python 10-run-otrf-rag.py --config <cfg> --resume
    python 10-run-otrf-rag.py --config <cfg> --overwrite
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import otrf_common as oc  # noqa: E402


def missing_plan_documents(entry: dict, kb_by_id: dict) -> list[str]:
    """Document ids referenced by a frozen-plan entry that are no longer
    present in the current knowledge base. Extracted as a pure, network-free
    function so the fail-loud behaviour is directly testable offline."""
    return [d["document_id"] for d in entry["documents"] if d["document_id"] not in kb_by_id]


def load_frozen_plan() -> dict:
    if not oc.FROZEN_RETRIEVAL_PLAN_PATH.exists():
        raise SystemExit(
            f"Frozen retrieval plan not found at {oc.FROZEN_RETRIEVAL_PLAN_PATH}.\n"
            f"Run 8-freeze-otrf-retrieval-plan.py first. This runner will NOT "
            f"recompute retrieval."
        )
    plan: dict = {}
    for rec in oc.read_jsonl(oc.FROZEN_RETRIEVAL_PLAN_PATH):
        if rec.get("_meta"):
            plan["_meta"] = rec
        else:
            plan[rec["external_scenario_id"]] = rec
    return plan


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="OTRF external RAG runner.")
    ap.add_argument("--config", default=str(oc.DEFAULT_CONFIG_PATH),
                    help="Path to the run config JSON. Defaults to "
                         f"{oc.DEFAULT_CONFIG_PATH} if omitted.")
    ap.add_argument("--models", nargs="+", default=None)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--no-cycle", action="store_true")
    ap.add_argument("--allow-hash-drift", action="store_true",
                    help="Proceed even if source/neutral-input/KB hashes have drifted since "
                         "preparation or plan freezing. Off by default: drift fails the run.")
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

    scenarios = oc.load_neutral_inputs()
    if not scenarios:
        raise SystemExit(f"No prepared neutral inputs under {oc.NEUTRAL_INPUTS_DIR}.")

    plan = load_frozen_plan()
    kb = oc.load_knowledge_base()
    kb_by_id = {d["doc_id"]: d for d in kb}

    # Integrity pre-flight: the frozen plan's recorded KB/neutral-input hashes
    # must still match the CURRENT knowledge base and prepared inputs.
    plan_violations = oc.verify_retrieval_plan_integrity(
        plan.get("_meta", {}), kb, [oc.NEUTRAL_INPUTS_DIR / f"{sid}.json" for sid, _ in scenarios])
    try:
        oc.require_no_violations(plan_violations, "frozen retrieval plan vs. current KB/inputs",
                                 args.allow_hash_drift)
    except oc.IntegrityError as exc:
        raise SystemExit(str(exc))

    missing = [sid for sid, _ in scenarios if sid not in plan]
    if missing:
        raise SystemExit(f"Frozen plan is missing entries for: {missing[:10]}... "
                         f"Re-freeze after preparing all scenarios.")

    def prompt_for(ext_id, neutral_input):
        entry = plan[ext_id]
        # Fail loudly (rather than silently dropping) if the frozen plan
        # references a KB document that no longer exists: retrieval must never
        # silently run on fewer documents than were frozen.
        missing_docs = missing_plan_documents(entry, kb_by_id)
        if missing_docs and not args.allow_hash_drift:
            raise SystemExit(
                f"{ext_id}: frozen plan references KB document(s) {missing_docs} that are "
                f"no longer present in the knowledge base. Re-freeze the retrieval plan, or "
                f"pass --allow-hash-drift to proceed with the documents that remain.")
        retrieved = [
            {"doc": kb_by_id[d["document_id"]], "score": d["score"], "rank": d["rank"]}
            for d in entry["documents"] if d["document_id"] in kb_by_id
        ]
        prompt = oc.build_rag_prompt(neutral_input, retrieved)
        extra = {
            "retrieved_doc_ids": [r["doc"]["doc_id"] for r in retrieved],
            "retrieved_scores": [r["score"] for r in retrieved],
            "num_docs_retrieved": len(retrieved),
            "no_document_found": entry.get("no_document_found", len(retrieved) == 0),
        }
        return prompt, extra

    print(f"OTRF RAG: {len(scenarios)} scenarios x {len(models)} models "
          f"(frozen plan, answer key NOT loaded).")
    results = []
    for model in models:
        print(f"\n{'='*66}\nMODEL: {model} (rag)\n{'='*66}")
        results.append(oc.run_model_over_scenarios(
            model, scenarios, prompt_for, "rag",
            oc.OUTPUTS_RAG_DIR, args.resume, args.overwrite, cycle=not args.no_cycle))

    (oc.LOGS_DIR).mkdir(parents=True, exist_ok=True)
    (oc.LOGS_DIR / "rag_run_summary.json").write_text(
        json.dumps({"generated_utc": oc.utc_now(), "runs": results,
                    "plan_meta": plan.get("_meta", {})}, indent=2), encoding="utf-8")
    print("\n" + json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
