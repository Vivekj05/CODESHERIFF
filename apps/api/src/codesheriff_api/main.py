"""ASGI entrypoint.

Replaces the previous root-level main.py, which resolved the four standalone
packages by mutating sys.path. The uv workspace makes that unnecessary.

The webhook router is deliberately NOT wired up yet: the existing implementation
has no HMAC verification (AUDIT.md 0.1) and processes inline (AUDIT.md 4.3).
Wiring it here unchanged would carry a live security hole into the new layout.
PLAN.md Chapter 6 lands the verified, enqueueing version.
"""

from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(
    title="CodeSheriff",
    description="Bayesian multi-agent security review for GitHub pull requests",
    version="0.1.0",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "service": "CodeSheriff",
        "status": "online",
        "webhook": "not yet mounted - see PLAN.md Chapter 6",
    }
