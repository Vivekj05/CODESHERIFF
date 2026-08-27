"""FastAPI webhook endpoint for GitHub PR events."""

from __future__ import annotations

import logging
from typing import Any, Dict, List
from fastapi import APIRouter, Header, HTTPException, Request
import requests

from codesheriff_engine.config import EngineConfig
from codesheriff_engine.github.parser import parse_pr_files_to_change_units
from codesheriff_engine.github.reporter import format_github_comment, post_pr_review_comment
from codesheriff_engine.orchestrator import Orchestrator

logger = logging.getLogger(__name__)
router = APIRouter()


def fetch_pr_files(repo_full_name: str, pr_number: int, token: str | None, api_base: str) -> List[Dict[str, Any]]:
    """Fetch changed files for a pull request from GitHub API."""
    url = f"{api_base.rstrip('/')}/repos/{repo_full_name}/pulls/{pr_number}/files"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "CodeSheriff-Engine"}
    if token and "your_github" not in token.lower():
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = requests.get(url, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            return resp.json()
        logger.warning("Failed to fetch PR files: status %s %s", resp.status_code, resp.text)
        return []
    except Exception as e:
        logger.error("Error fetching PR files: %s", e)
        return []


@router.post("/webhook")
async def github_webhook(
    request: Request,
    x_github_event: str = Header(default="pull_request"),
) -> Dict[str, Any]:
    """Receive and process incoming GitHub Pull Request webhook events."""
    config = EngineConfig.load()
    payload = await request.json()

    # Handle ping / setup events
    if x_github_event == "ping":
        return {"status": "pong", "zen": payload.get("zen", "")}

    action = payload.get("action")
    if "pull_request" not in payload or action not in ["opened", "reopened", "synchronize"]:
        return {
            "status": "ignored",
            "message": f"Event '{x_github_event}:{action}' does not require PR review analysis.",
        }

    pr = payload["pull_request"]
    repo_full_name = payload["repository"]["full_name"]
    pr_number = pr["number"]
    pr_title = pr.get("title", "")
    base_sha = pr.get("base", {}).get("sha", "base_sha")
    head_sha = pr.get("head", {}).get("sha", "head_sha")

    logger.info("Processing PR #%s in '%s' (action: %s)", pr_number, repo_full_name, action)

    # 1. Fetch changed files
    pr_files = fetch_pr_files(repo_full_name, pr_number, config.github_token, config.github_api_base)
    if not pr_files:
        return {"status": "completed", "message": "No files found in PR diff."}

    # 2. Parse PR files into ChangeUnits
    change_units = parse_pr_files_to_change_units(
        repo_full_name=repo_full_name,
        pr_number=pr_number,
        pr_files=pr_files,
        base_sha=base_sha,
        head_sha=head_sha,
    )

    if not change_units:
        return {"status": "completed", "message": "No supported source code files modified in PR."}

    # 3. Run Multi-Agent Orchestration & Bayesian Fusion
    orchestrator = Orchestrator(config=config)
    fusion_results = await orchestrator.analyze_change_units(change_units, run_debate=config.enable_debate)

    # 4. Generate Markdown Comment
    comment_markdown = format_github_comment(fusion_results, pr_title=pr_title)

    # 5. Post comment back to GitHub PR
    post_result = post_pr_review_comment(
        repo_full_name=repo_full_name,
        pr_number=pr_number,
        comment_body=comment_markdown,
        token=config.github_token,
        api_base=config.github_api_base,
    )

    alert_count = len([f for f in fusion_results if f.is_alert_worthy])
    return {
        "status": "processed",
        "repo": repo_full_name,
        "pr_number": pr_number,
        "units_analyzed": len(change_units),
        "total_findings": len(fusion_results),
        "alert_count": alert_count,
        "github_post_status": post_result.get("status", "unknown"),
    }
