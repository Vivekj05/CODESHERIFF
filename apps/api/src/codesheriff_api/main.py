"""ASGI entrypoint.

Replaces the previous root-level main.py, which resolved the four standalone packages by mutating
sys.path. The uv workspace makes that unnecessary.

The webhook router is deliberately NOT wired up yet: the existing implementation has no HMAC
verification (AUDIT.md 0.1) and processes inline (AUDIT.md 4.3). Wiring it here unchanged would
carry a live security hole into the new layout. PLAN.md Chapter 6 lands the verified, enqueueing
version.

Chapter 5 adds sign-in and repository listing. Route handlers are synchronous `def`, which FastAPI
runs in a threadpool — the database session and the GitHub client are both synchronous (D-028), and
a sync call inside an `async def` would block the event loop for the whole process.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from codesheriff_api import auth, repositories
from codesheriff_api.config import ApiConfig

config = ApiConfig.load()

app = FastAPI(
    title="CodeSheriff",
    description="Bayesian multi-agent security review for GitHub pull requests",
    version="0.1.0",
)

# Exactly one origin, with credentials. `allow_origins=["*"]` cannot carry cookies at all, and a
# wildcard that did would let any page on the internet make authenticated calls with the user's
# session. The dashboard and the API must share a registrable domain in a deployment, or the
# session cookie is cross-site and needs SameSite=None.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[config.dashboard_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type"],
)

app.include_router(auth.router)
app.include_router(repositories.router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/")
async def root() -> dict[str, object]:
    return {
        "service": "CodeSheriff",
        "status": "online",
        "auth": "ready" if config.github_app_client_id else "unconfigured — see .env.example",
        "webhook": "not yet mounted - see PLAN.md Chapter 6",
    }
