# Knowledge Base (Cleaned, Frozen)

Curated diagnostic guidance for the knowledge-augmented (RAG) condition. It is
interpretive guidance for classifying endpoint behaviour, not an external
dataset and not real-world validation.

## Active documents
34 category records are indexed for retrieval:
- NORMAL 4, AUTH 5, USB 5, SEC 5, PROC 5, NET 5, PERSIST 5.
Each record follows a concise analyst format: summary, observable conditions,
normal/benign reading, abnormal reading, a severity decision table, controlled
expected indicators, topic-specific false-positive checks, evidence
combinations, analyst notes, examples, and related record IDs.

## What is indexed vs not indexed
Indexed for retrieval: the seven category folders only (NORMAL, AUTH, USB, SEC,
PROC, NET, PERSIST). NOT indexed: `GLOBAL/`, `_documentation/`, `audits/`, and
`_archive_not_indexed/`. The runner globs `*.md` only inside the seven category
folders, so anything elsewhere is never loaded.

## Legacy documents
Earlier attack-oriented drafts (e.g. credential_spraying, suspicious_powershell,
registry_or_wmi_persistence) were moved to `_archive_not_indexed/`. They used
tokens outside the controlled vocabulary and referenced telemetry the collector
does not provide, so they are retained for provenance only and never retrieved.

## Controlled vocabulary
Every Expected-indicator token is from `controlled_indicator_vocabulary.csv`.
Validation confirms zero out-of-vocabulary tokens in active documents.

## Retrieval (matches 3-run_rag.py)
- Method: deterministic weighted keyword/token retrieval (no embeddings, no ML).
- Query: built only from active evidence in the neutral input, prioritising the
  event_summary; normal ambient context is excluded. No scenario ID, record ID,
  category, scenario name, ground truth, expected indicators, or label reason.
- top_k: maximum 3; zero-score documents are not injected.
- No ground-truth category filtering.
- Retrieval is precomputed once and reused identically for all five models.

## Experiment integrity
The KB was frozen before RAG results were examined and was not tuned on them.
The existing baseline is unchanged. The RAG condition adds only the retrieved
category records to the identical baseline prompt.

## Index file
`catalog.csv` lists exactly the 34 active documents (`manifest.csv` mirrors it).
