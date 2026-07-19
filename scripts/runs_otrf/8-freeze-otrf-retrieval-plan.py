#!/usr/bin/env python3
"""
8-freeze-otrf-retrieval-plan.py
===============================

Builds and FREEZES the deterministic OTRF retrieval plan, separately from the
RAG runner (retrieval-plan generation must not be hidden inside inference).

The plan indexes ONLY the active seven-category knowledge base (GLOBAL and
_archive_not_indexed excluded), uses the exact frozen retrieval method and the
exact frozen top-k, and is keyed by external_scenario_id. The RAG runner
(10-run-otrf-rag.py) REQUIRES this file and refuses to recompute retrieval
silently.

The plan never uses the external answer key: retrieval is built only from the
active evidence in each neutral input.

Usage:
    python 8-freeze-otrf-retrieval-plan.py --config external_validation/config/otrf_external_config.json
    python 8-freeze-otrf-retrieval-plan.py --config <cfg> --overwrite
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import otrf_common as oc  # noqa: E402


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Freeze the OTRF retrieval plan.")
    ap.add_argument("--config", default=str(oc.DEFAULT_CONFIG_PATH),
                    help="Path to the run config JSON. Defaults to "
                         f"{oc.DEFAULT_CONFIG_PATH} if omitted.")
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--allow-hash-drift", action="store_true",
                    help="Proceed even if manifest source/neutral-input hashes have drifted "
                         "since 8-prepare-otrf-external.py ran. Off by default: drift fails.")
    args = ap.parse_args(argv)

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    top_k = int(cfg.get("top_k", oc.TOP_K))

    if oc.FROZEN_RETRIEVAL_PLAN_PATH.exists() and not args.overwrite:
        raise SystemExit(
            f"A frozen retrieval plan already exists at {oc.FROZEN_RETRIEVAL_PLAN_PATH}.\n"
            f"Refusing to recompute. Re-run with --overwrite to replace it."
        )

    if not oc.FROZEN_MANIFEST_PATH.exists():
        raise SystemExit("No frozen manifest found. Run 8-prepare-otrf-external.py first.")

    manifest_rows = oc.read_csv(oc.FROZEN_MANIFEST_PATH)
    violations = oc.verify_manifest_integrity(manifest_rows)
    try:
        oc.require_no_violations(violations, "frozen manifest vs. current source/neutral inputs",
                                 args.allow_hash_drift)
    except oc.IntegrityError as exc:
        raise SystemExit(str(exc))

    ids = oc.frozen_manifest_scenario_ids()
    neutral_files = [oc.NEUTRAL_INPUTS_DIR / f"{i}.json" for i in ids]
    if not neutral_files:
        raise SystemExit(f"No scenarios in the frozen manifest {oc.FROZEN_MANIFEST_PATH}.")

    kb = oc.load_knowledge_base()
    if not kb:
        raise SystemExit("No active knowledge-base documents found.")

    oc.RETRIEVAL_DIR.mkdir(parents=True, exist_ok=True)
    kb_concat = "".join(sorted(d["full_text"] for d in kb))
    inputs_concat = "".join(p.read_text(encoding="utf-8") for p in neutral_files)

    # Header record with hashes for reproducibility auditing.
    header = {
        "_meta": True,
        "top_k": top_k,
        "kb_documents_hash": oc.sha256_text(kb_concat),
        "neutral_inputs_hash": oc.sha256_text(inputs_concat),
        "kb_document_count": len(kb),
        "record_count": len(neutral_files),
        "plan_version": "otrf-retrieval-plan-1.1.0",
        "retrieval_implementation_version": oc.RETRIEVAL_IMPLEMENTATION_VERSION,
        "retrieval_differences_from_primary": oc.RETRIEVAL_DIFFERENCES_FROM_PRIMARY,
        "config_hash": oc.sha256_config(Path(args.config)),
        "generated_utc": oc.utc_now(),
    }

    # Overwrite the file fresh (freeze is a single deterministic build).
    with oc.FROZEN_RETRIEVAL_PLAN_PATH.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(header, ensure_ascii=False) + "\n")
        no_doc = 0
        for path in neutral_files:
            ext_id = path.stem
            neutral_input = json.loads(path.read_text(encoding="utf-8"))
            features = oc.build_query_features(neutral_input)
            retrieved = oc.retrieve(features, kb, top_k)
            if not retrieved:
                no_doc += 1
            rec = {
                "external_scenario_id": ext_id,
                "query_fields": features["fields"],
                "query_values": features["values"],
                "documents": [
                    {"document_id": r["doc"]["doc_id"], "score": r["score"], "rank": r["rank"]}
                    for r in retrieved
                ],
                "num_docs_retrieved": len(retrieved),
                "no_document_found": len(retrieved) == 0,
            }
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(json.dumps({
        "frozen_retrieval_plan": str(oc.FROZEN_RETRIEVAL_PLAN_PATH.relative_to(oc.ROOT_DIR)),
        "records": len(neutral_files),
        "top_k": top_k,
        "kb_documents": len(kb),
        "scenarios_with_no_document": no_doc,
        "kb_documents_hash": header["kb_documents_hash"][:16],
        "neutral_inputs_hash": header["neutral_inputs_hash"][:16],
    }, indent=2))


if __name__ == "__main__":
    main()
