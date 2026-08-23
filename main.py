"""Root FastAPI service for CodeSheriff.

Routes PR webhooks directly to the Bayesian Fusion & Multi-Agent Orchestrator.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, Request

# Ensure local package paths are resolvable
_root = Path(__file__).parent
for pkg_dir in [
    _root / "codesheriff-engine" / "src",
    _root / "codesheriff-static-agent" / "src",
    _root / "codesheriff-semantic-agent" / "src",
    _root / "codesheriff-context-agent" / "src",
]:
    if str(pkg_dir) not in sys.path and pkg_dir.exists():
        sys.path.insert(0, str(pkg_dir))

load_dotenv()

from codesheriff_engine.github.webhook import router as webhook_router

app = FastAPI(
    title="CodeSheriff Security Review Engine",
    description="Multi-Agent Bayesian Security Reviewer for GitHub Pull Requests",
    version="0.1.0",
)

app.include_router(webhook_router)


@app.get("/")
async def root():
    return {
        "service": "CodeSheriff Security Review Engine",
        "status": "online",
        "endpoints": {
            "webhook": "/webhook (POST)",
            "docs": "/docs",
        },
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}