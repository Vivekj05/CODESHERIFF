# CHANGELOG

## [0.2.0] - 2026-08-30 — Chapter 12

Rewritten. Closes `AUDIT.md` 0.2, 3.7 and 3.8; see `DECISIONS.md` D-070 … D-072.

### Added
- `controls.py` — the control surface of a function, read off the tree-sitter AST: decorators and
  called names, for a change unit and a precedent excerpt alike.
- `classify.py` — the fixed half of the reasoning: which control names are authorization controls,
  and which in-scope CWE each is about. CWE-862 and CWE-639 only.
- `regression.py` — the learned half: which controls this repository's merged history establishes,
  by same-symbol precedent or by two or more sibling symbols sharing one.
- `precedent.py` — `Precedent`, the `PrecedentRetriever` Protocol, `NoPrecedentRetriever`, and
  `RetrievalUnavailableError`.
- `tests/test_corpus_context.py` — measured on the calibration split: 5/5 recall, 0 false positives.

### Removed
- `rag/` — `LocalEmbedder`, `VectorStore`, `ingest`. The agent embeds nothing and stores nothing;
  `apps/worker` owns the model and the pgvector store. The MD5 fallback that made a normal install
  produce meaningless vectors is gone with it (`AUDIT.md` 3.8), and there is no fallback branch.
- `retrieval/search.py`, `reasoning/analyzer.py` and `reasoning/prompts/cross_pr_v1.md` — four
  hard-coded substring tests for `stripe_charge`, and a prompt referenced by no code
  (`AUDIT.md` 3.7).
- CLI `ingest` and `search`, with the local store they drove.
- `ContextConfig.chroma_db_dir` and `embedding_model` (D-016).

### Changed
- `ContextAgent(config, retriever)` — retrieval is injected. No retriever means abstain on every
  unit, never an in-process store of its own.
- `agent_id` and `agent_version` are module constants, not settings: an id that an environment
  variable can change is one that can be changed to a value fusion does not recognise.
- Repository scoping is the retriever's, and structural — the superseded store shared one global
  collection across every repository and never recorded which one a document came from
  (`AUDIT.md` 0.2).
- Declares `tree-sitter` and `tree-sitter-language-pack`, the libraries its analysis actually needs.

## [0.1.0] - 2026-08-22
- Initial release of CodeSheriff RAG Context Agent.
- Vendored canonical `contracts.py` (v1.0.0).
- Implemented `LocalEmbedder` and persistent `VectorStore`.
- Implemented `create_hybrid_pr_document` ingestion module.
- Implemented Cold Start handling (PR #1 -> `Abstention(no_historical_prs)`).
- Implemented Anchor filtering and Cross-PR security regression evaluation (`reasoning/analyzer.py`).
- Built Typer CLI (`run`, `ingest`, `search`, `version`).
