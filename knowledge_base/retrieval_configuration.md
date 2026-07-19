# Retrieval Configuration

## Method
Deterministic weighted keyword/token retrieval. No embeddings or ML; identical
results on every run.

## Query construction
Built only from ACTIVE evidence in the neutral input, prioritising event_summary
(what happened) over always-present context_state (ambient configuration).
Normal context (defender enabled, private network) is excluded; only abnormal
context deviations (defender disabled, firewall profile off, non-private
network) contribute. Excludes false, 0, none, empty lists/objects. Never uses
scenario ID, record ID, category, scenario name, ground truth, expected
indicators, or label reason.

## Scoring weights
- exact expected-indicator match: 6
- exact Applies-when field/value: 5
- exact Applies-when field: 3
- title word match: 2
- body keyword match: 1
Expected-indicator and Applies-when text are excluded from the body score to
avoid double counting. Stopwords are removed from the word signal.

## Parameters
- top_k = 3 maximum, fixed for every scenario and model.
- Zero-score documents are dropped; if none score positively, no context is
  injected and the scenario is logged as no_document_found.
- No ground-truth category filtering.

## Indexed folders
Only NORMAL, AUTH, USB, SEC, PROC, NET, PERSIST. GLOBAL, _documentation, audits,
and _archive_not_indexed are never retrieved.

## Reproducibility
Retrieval is precomputed once into retrieval_plan.json (with SHA-256 hashes of
the KB, dataset inputs, and runner script) and reused for all five models, so
every model receives byte-identical retrieved documents.

## Logging (per scenario)
Query fields/values, retrieved document IDs, ranks, scores, retrieval latency,
generation latency (summed across retry attempts), total latency, raw response,
parsed response, JSON validity, strict schema validity, errors, and
no_document_found.
