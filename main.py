"""Root FastAPI service for CodeSheriff.

Routes PR webhooks directly to the Bayesian Fusion & Multi-Agent Orchestrator
and serves the CodeSheriff React Security Audit Dashboard.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

# Ensure local package paths are resolvable
_root = Path(__file__).parent
for pkg_dir in [
    _root / "codesheriff-engine" / "src",
    _root / "codesheriff-static-agent" / "src",
    _root / "codesheriff-semantic-agent" / "src",
    _root / "codesheriff-context-agent" / "src",
    _root / "codesheriff-runtime-agent" / "src",
    _root / "codesheriff-patch-verifier" / "src",
]:
    if str(pkg_dir) not in sys.path and pkg_dir.exists():
        sys.path.insert(0, str(pkg_dir))

load_dotenv()

from codesheriff_engine.github.webhook import router as webhook_router
from codesheriff_engine.api import router as api_router

app = FastAPI(
    title="CodeSheriff Security Review Engine",
    description="Multi-Agent Bayesian Security Reviewer for GitHub Pull Requests",
    version="0.1.0",
)

# Mount Static Files
static_dir = _root / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

react_dist_assets = _root / "dashboard" / "dist" / "assets"
if react_dist_assets.exists():
    app.mount("/assets", StaticFiles(directory=str(react_dist_assets)), name="react_assets")

app.include_router(webhook_router)
app.include_router(api_router)


@app.get("/")
@app.get("/dashboard")
async def dashboard():
    """Serves the Interactive CodeSheriff Web Dashboard (React or HTML)."""
    react_index = _root / "dashboard" / "dist" / "index.html"
    if react_index.exists():
        return FileResponse(str(react_index))
    
    dashboard_file = static_dir / "dashboard.html"
    if dashboard_file.exists():
        return FileResponse(str(dashboard_file))

    return {
        "service": "CodeSheriff Security Review Engine",
        "status": "online",
        "endpoints": {
            "dashboard": "/dashboard",
            "webhook": "/webhook (POST)",
            "audit_api": "/api/audit (POST)",
            "docs": "/docs",
        },
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "codesheriff-engine"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)