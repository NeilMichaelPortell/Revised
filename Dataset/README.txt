Dataset_FINAL_RUN_READY
=======================

Run the models on llm_inputs/ (R001-R120). These are leakage-safe: they contain
only event_summary + context_state, no IDs, categories, names, or labels.

runner_mapping.csv maps neutral record IDs back to scenario IDs for scoring.
NEVER include runner_mapping.csv or ground_truth_FINAL.csv in the model prompt.

Deterministic shuffle seed: 20260710

scenario_summaries/ = full reviewed evidence (provenance record, NOT model input).
ground_truth_FINAL.csv = frozen labels for scoring only.
Augmented scenarios (see provenance_report.csv) were constructed, not collected live.

Final verification amendments:
- viewed_interface is a schema-wide factual field with controlled values.
- 17 scenarios use structured manual verification; see manual_evidence_audit.csv.
- Unresolved contradictory duplicate-input groups after correction: 0.
- One evidence-identical pair remains with fully aligned ground truth.
