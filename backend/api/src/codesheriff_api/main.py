"""ASGI entrypoint.

Replaces the previous root-level main.py, which resolved the four standalone packages by mutating
sys.path. The uv workspace makes that unnecessary.

Chapter 5 added sign-in and repository listing, Chapter 6 the webhook — the only route on
this app that GitHub itself calls — and Chapter 15 the dashboard's read side: audit history,
audit detail, overview statistics and the fitted calibration artifact. Route handlers are
synchronous `def`, which FastAPI runs in a threadpool — the database session and the GitHub
client are both synchronous (D-028), and a sync call inside an `async def` would block the event
loop for the whole process. The webhook is the one exception, and says why in its own module.

This process performs no analysis. It verifies a signature, writes a row and publishes an id; the
worker owns everything after that. Keeping the split means the edge holds no LLM credential and no
agent code, and there is no function here that could tempt anyone into running a pipeline inline
again (AUDIT.md 4.3).
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from codesheriff_api import (
    audits,
    auth,
    calibration,
    installations,
    repositories,
    stats,
    webhooks,
)
from codesheriff_api.config import ApiConfig

config = ApiConfig.load()

app = FastAPI(
    title="CodeSheriff",
    description="Bayesian multi-agent security review for GitHub pull requests",
    version="0.1.0",
)

# Exactly one origin. The caller is identified by a Better Auth JWT in the `Authorization` header
# (D-101), not by a cookie, so no credentials mode is needed; the header must be allowed, though,
# or every preflight fails before the token is ever read.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[config.dashboard_origin],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(auth.router)
app.include_router(installations.router)
app.include_router(repositories.router)
app.include_router(audits.router)
app.include_router(stats.router)
app.include_router(calibration.router)
app.include_router(webhooks.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/")
async def root() -> dict[str, object]:
    return {
        "service": "CodeSheriff",
        "status": "online",
        "auth": f"Better Auth tokens from {config.token_issuer}",
        "webhook": "ready" if config.github_webhook_secret else "unconfigured — see .env.example",
    }
