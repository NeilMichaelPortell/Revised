# Research results

This directory contains generated artifacts from the primary 120-scenario study.

```text
results/
|-- baseline/               Baseline model outputs
|   `-- evaluation/         Baseline-only evaluation tables
|-- rag/                    Knowledge-augmented outputs and retrieval plan
|-- comparison/             Paired baseline-versus-RAG analysis
`-- consistency/
    |-- baseline/           Repeated baseline responses
    |-- rag/                Repeated knowledge-augmented responses
    |-- archive/            Superseded artifacts retained for traceability
    `-- reports/            Consistency metrics, audits, and summaries
```

The supplementary OTRF study remains under `external_validation/` because it has
its own source manifest, prepared data, outputs, evaluation, tests, and cleanup
rules. The raw third-party OTRF checkout is not part of this repository and is
excluded through `.gitignore`.
