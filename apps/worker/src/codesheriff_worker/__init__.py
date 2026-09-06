"""Celery worker. Owns the audit pipeline and all agents.

Not yet built - PLAN.md Chapter 6. There is currently no queue anywhere in the
project: the webhook runs everything inline (AUDIT.md 4.3), which will exceed
GitHub's 10s limit on any non-trivial PR.

When built, this package owns orchestration. Two rules it must not break:

  - Agents run BLIND and in parallel - a plain asyncio.gather fan-out. No
    anchors. Running static first and passing its finding keys downstream
    correlates the agents and breaks the conditional independence the fusion
    math assumes (DECISIONS.md D-008).

  - A missing agent must fail LOUDLY. The previous orchestrator degraded a
    failed import to a DummyAgent abstention at INFO level, so agents could
    silently fail to load and the system would still post
    "No security vulnerabilities detected" (AUDIT.md 4.4).
"""
