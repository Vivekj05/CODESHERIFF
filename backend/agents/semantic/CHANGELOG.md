# CHANGELOG

## [0.1.0] - 2026-08-22
- Initial release of CodeSheriff Semantic Agent.
- Vendored canonical `contracts.py` (v1.0.0).
- Implemented 3-stage universal intent prompt framework (`system_v1.md`, `user_v1.jinja`).
- Implemented Pydantic output schema (`LLMFinding`, `LLMResponse`).
- Implemented Hallucination Gate (line bounds, verbatim sink check, file match).
- Implemented $n=3$ self-consistency sampling and clustering.
- Implemented SQLite response caching and pre-call budget tracking.
- Implemented prompt injection boundaries and anti-sycophancy few-shot exemplars.
- Built CLI (`run`, `bench`, `replay`, `injection-test`, `version`).
