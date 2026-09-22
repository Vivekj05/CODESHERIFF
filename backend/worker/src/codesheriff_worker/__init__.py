"""Celery worker. Owns the audit pipeline and all agents.

The webhook hands this process an audit id and nothing else (D-041); everything the pipeline needs
is a row in Postgres. `tasks.py` holds the lifecycle - claim, run, post one comment, close the row -
and Chapters 8 to 14 fill in the middle without changing the shape around it.

As of Chapter 6 the middle is empty on purpose. Five abstentions are rendered into the pull request
comment, which is the honest report of four agents that do not exist yet: an agent that could not
run reports that it could not run. It never reports that it found nothing.

Two rules this package must not break when the agents arrive:

  - Agents run BLIND and in parallel - a plain asyncio.gather fan-out. No anchors. Running static
    first and passing its finding keys downstream correlates the agents and breaks the conditional
    independence the fusion math assumes (DECISIONS.md D-008).

  - A missing agent must fail LOUDLY. The previous orchestrator degraded a failed import to a
    DummyAgent abstention at INFO level, so agents could silently fail to load and the system would
    still post "No security vulnerabilities detected" (AUDIT.md 4.4).

Nothing here may import `codesheriff_api`: `import-linter` puts the two apps on the same layer. The
API addresses this worker's task by name, which is the whole interface between them.
"""
