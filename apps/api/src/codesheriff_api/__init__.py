"""FastAPI edge service.

Responsibility, and nothing beyond it (PROJECT_CONTEXT.md section 3):
verify the HMAC signature, enqueue the job, return 202. No analysis happens here.

Currently NOT IMPLEMENTED. The live webhook still lives in
packages/engine/src/codesheriff_engine/github/webhook.py, where it:

  - performs NO signature verification at all (AUDIT.md 0.1 - live exposure;
    github_webhook_secret is defined and never read)
  - runs the entire pipeline inline, with a blocking requests.get inside an
    async def that stalls the event loop (AUDIT.md 4.3)

PLAN.md Chapter 6 moves it here and fixes both. Until then this package is a stub.
"""
