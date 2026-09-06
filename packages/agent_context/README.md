# CodeSheriff RAG Context Agent (`codesheriff-context-agent`)

RAG-powered security analyzer for CodeSheriff detecting cross-PR security regressions and security control bypasses.

## Overview
The Context Agent maintains a local vector database of previously accepted Pull Requests to evaluate whether a new incoming Pull Request:
1. Invalidates or bypasses security wrappers (e.g., `@require_csrf_token`, `@rate_limit`, authorization checks) established in historical PRs.
2. Re-introduces security flaws previously fixed in past PRs.

It operates with zero cloud costs using a local vector store and embeddings, handles PR #1 Cold Start gracefully, and emits canonical `Evidence` contracts.

## Usage
```bash
pip install -e .
context-agent run tests/fixtures/sample_unit.json
```
