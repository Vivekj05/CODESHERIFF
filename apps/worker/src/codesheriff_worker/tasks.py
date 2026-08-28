"""The audit task.

One task, and the shape it will keep: claim the audit, do the work, post one comment, close the
row. Chapters 8 to 14 fill in the middle — extraction, four blind agents, fusion — and none of that
changes the lifecycle around it.

**Everything is driven off the database, not off the message.** The broker delivered an id (D-041);
the repository, the pull request number, the head SHA and the previous comment id are all read from
rows. A message that carried them would be a second copy that can disagree with the first.

**A claim can fail, and that is not an error.** Celery delivers at least once, and a push can
supersede an audit between the enqueue and the claim. Both arrive here as `claim_audit` returning
None, and both mean stop.

**Nothing is analysed yet.** The evidence is five abstentions built in `comment.py`, which is the
honest report of four agents that do not exist. It is deliberately not persisted: `evidence` rows
hang off a `change_units` row, and there are no change units until Chapter 8.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable

from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import sessionmaker

from codesheriff_storage import (
    Audit,
    StorageConfig,
    build_engine,
    build_session_factory,
    claim_audit,
    fail_audit,
    finish_audit,
    is_superseded,
    latest_comment_id,
    session_scope,
)
from codesheriff_worker.celery_app import app, config
from codesheriff_worker.comment import pending_evidence, render
from codesheriff_worker.github_gateway import GitHubGateway, GitHubKitGateway

logger = logging.getLogger(__name__)

RUN_AUDIT_TASK = "codesheriff.run_audit"
"""Must equal `codesheriff_api.queue.RUN_AUDIT_TASK`.

The API cannot import this module — `import-linter` puts the two apps on the same layer — so the
name is the entire interface between them, and `apps/api/tests/test_task_name_contract.py` asserts
the two constants match. A divergence would look exactly like a worker that is not running.
"""

_session_factory: sessionmaker[DbSession] | None = None


def session_factory() -> sessionmaker[DbSession]:
    """One engine per worker process, built on first use.

    Lazily, because importing this module must not require a reachable database: `celery -A ...`
    imports it to register the task, and a worker that cannot start is harder to diagnose than a
    task that fails with a connection error.
    """
    global _session_factory
    if _session_factory is None:
        _session_factory = build_session_factory(build_engine(StorageConfig.load()))
    return _session_factory


def build_gateway() -> GitHubGateway:
    return GitHubKitGateway(config)


def dashboard_url_for(audit_id: uuid.UUID) -> str:
    return f"{config.dashboard_base_url.rstrip('/')}/audits/{audit_id}"


# Celery ships no py.typed marker, so `app.task` is untyped and strict mode refuses to let it wrap
# an annotated function. The ignore is on the decorator alone; the body below is fully checked.
@app.task(name=RUN_AUDIT_TASK)  # type: ignore[untyped-decorator]
def run_audit(audit_id: str) -> str:
    """Entry point. Everything real happens in `execute_audit`, which takes its dependencies.

    The split exists so the pipeline can be tested without Celery and without a broker: this
    wrapper resolves a session factory and a GitHub gateway, and that is all it does.
    """
    return execute_audit(uuid.UUID(audit_id), session_factory(), build_gateway())


def execute_audit(
    audit_id: uuid.UUID,
    factory: sessionmaker[DbSession],
    gateway: GitHubGateway,
    url_for: Callable[[uuid.UUID], str] = dashboard_url_for,
) -> str:
    """Run one audit to completion. Returns the terminal state, for the log.

    Failures are recorded on the row *and* re-raised. The row is the system of record and a human
    reads it; the exception is what makes the failure visible to Celery's own monitoring. Recording
    only one of the two leaves the other saying the run succeeded.

    The failure is written in its own session, opened after the first has been rolled back and
    closed. A session that has just raised may be in a state where nothing more can be written, and
    reusing it is how "we could not record why it failed" becomes the failure.
    """
    try:
        with session_scope(factory) as db:
            audit = claim_audit(db, audit_id)
            if audit is None:
                logger.info("Audit %s was not claimable — already running, or superseded", audit_id)
                return "not_claimable"
            return _run_claimed_audit(db, audit, gateway, url_for)
    except Exception as exc:
        logger.exception("Audit %s failed", audit_id)
        _record_failure(factory, audit_id, exc)
        raise


def _record_failure(
    factory: sessionmaker[DbSession], audit_id: uuid.UUID, exc: BaseException
) -> None:
    """Mark the audit failed, and never let doing so replace the original exception.

    `fail_audit` only moves an audit out of `queued` or `running`, so an audit the rollback returned
    to `queued` still lands here, and one a push superseded is left alone — being overtaken is not
    a failure (D-039).
    """
    try:
        with session_scope(factory) as db:
            fail_audit(db, audit_id, f"{type(exc).__name__}: {exc}")
    except Exception:
        logger.exception("Could not record the failure of audit %s", audit_id)


def _run_claimed_audit(
    db: DbSession,
    audit: Audit,
    gateway: GitHubGateway,
    url_for: Callable[[uuid.UUID], str],
) -> str:
    """The body of an audit, once it is ours to run."""
    repository = audit.repository
    installation_id = repository.installation_id

    # ---- analysis would happen here (Chapters 8-14) ----
    evidence = pending_evidence(audit.id)

    # Checked immediately before writing to GitHub, not only at the start. The window between the
    # two is the whole pipeline, and a comment about a commit that is no longer at the head is
    # worse than no comment at all (D-034).
    db.commit()
    if is_superseded(db, audit.id):
        logger.info("Audit %s was superseded while running; posting nothing", audit.id)
        return "superseded"

    previous = latest_comment_id(db, repository_id=repository.id, pr_number=audit.pr_number)
    comment_id = gateway.post_or_update_comment(
        installation_id=installation_id,
        repo_full_name=repository.full_name,
        pr_number=audit.pr_number,
        body=render(audit.id, evidence, url_for(audit.id)),
        comment_id=previous,
    )

    finish_audit(db, audit.id, github_comment_id=comment_id)
    db.commit()
    logger.info(
        "Audit %s finished: %s#%s, comment %s",
        audit.id,
        repository.full_name,
        audit.pr_number,
        comment_id,
    )
    return "succeeded"
