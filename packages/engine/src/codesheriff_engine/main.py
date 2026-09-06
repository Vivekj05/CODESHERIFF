"""FastAPI application entry point for CodeSheriff Fusion Engine."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from codesheriff_engine.github.webhook import router as webhook_router

app = FastAPI(
    title="CodeSheriff Fusion & Integration Engine",
    description="Multi-Agent Bayesian Security Reviewer for GitHub Pull Requests",
    version="0.1.0",
)

app.include_router(webhook_router)


@app.get("/")
async def root() -> dict[str, Any]:
    return {
        "service": "CodeSheriff Fusion Engine",
        "status": "running",
        "endpoints": {
            "webhook": "/webhook (POST)",
            "docs": "/docs",
        },
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy"}
