# CHANGELOG

## [0.1.0] - 2026-08-22
- Initial release of CodeSheriff RAG Context Agent.
- Vendored canonical `contracts.py` (v1.0.0).
- Implemented `LocalEmbedder` and persistent `VectorStore`.
- Implemented `create_hybrid_pr_document` ingestion module.
- Implemented Cold Start handling (PR #1 -> `Abstention(no_historical_prs)`).
- Implemented Anchor filtering and Cross-PR security regression evaluation (`reasoning/analyzer.py`).
- Built Typer CLI (`run`, `ingest`, `search`, `version`).
