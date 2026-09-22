"""FastAPI edge service.

Responsibility, and nothing beyond it (PROJECT_CONTEXT.md section 3):
verify the HMAC signature, enqueue the job, return 202. No analysis happens here.
It also serves the dashboard's REST surface - sign-in and repository listing.

The webhook lives in `webhooks.py` and is the reason this package exists. It replaced
`packages/engine/src/codesheriff_engine/github/webhook.py`, which performed no signature
verification at all (AUDIT.md 0.1) and ran the whole pipeline inline, with a blocking
`requests.get` inside an `async def` (AUDIT.md 4.3). Both files are gone as of Chapter 6.

Nothing in this package may import `codesheriff_worker`: `import-linter` puts the two apps on the
same layer. That is what keeps the analysis dependency tree - agents, the LLM client, tree-sitter -
out of the process that answers GitHub in under three seconds.
"""
