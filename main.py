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
    import argparse
    import threading
    import webbrowser
    import time

    parser = argparse.ArgumentParser(description="CodeSheriff Security Review Engine & Dashboard")
    parser.add_argument("--port", type=int, default=8000, help="Port to run server on (default: 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--no-browser", action="store_true", help="Disable automatic browser opening")
    args = parser.parse_args()

    dashboard_url = f"http://{args.host}:{args.port}/dashboard"

    if not args.no_browser:
        def _open_dashboard():
            time.sleep(1.2)
            print(f"\n========================================================")
            print(f"  [+] CodeSheriff Dashboard: {dashboard_url}")
            print(f"  [+] CodeSheriff API Docs:  http://{args.host}:{args.port}/docs")
            print(f"========================================================\n")
            webbrowser.open(dashboard_url)

        threading.Thread(target=_open_dashboard, daemon=True).start()

    print(f"[*] Starting CodeSheriff Engine on {args.host}:{args.port}...")
    uvicorn.run("main:app", host=args.host, port=args.port, reload=False)