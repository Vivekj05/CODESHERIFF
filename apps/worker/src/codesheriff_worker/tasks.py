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

**The analysis is wired in.** Chapter 9 closes the middle: every extracted unit goes to four
blind agents, their statements are persisted as `evidence` rows against the unit they are about,
and fusion turns them into posteriors. The hardcoded `pipeline_not_implemented` abstentions are
gone — what the comment reports now is what the agents actually said. Only the structural witness
does real work today; the other three abstain, which is the honest report of agents that are not
built (Chapters 11 to 13) and costs the posterior exactly nothing, since an abstention is LR 1.0.

**The audit row supplies the prior and the threshold, not the config (§6).** `apps/api` stamped
both onto the row when it opened the audit, along with the calibration run they came from. Reading
them back from configuration here would mean a worker restarted with different numbers silently
scored an audit against values the row does not record, and a finding whose stated threshold is not
the one it was judged by is not auditable.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable

from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import sessionmaker

from codesheriff_contracts import ChangeUnit, Evidence
from codesheriff_engine.config import EngineConfig
from codesheriff_engine.fusion import FusionResult, fuse_all_evidence
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
    persistable_findings,
    session_scope,
    to_change_unit_row,
    to_evidence_row,
    to_finding,
)
from codesheriff_worker.analysis import Agent, AgentDeps, analyse_unit, load_agents
from codesheriff_worker.celery_app import app, config
from codesheriff_worker.comment import render
from codesheriff_worker.github_gateway import GitHubGateway, GitHubKitGateway
from codesheriff_worker.pipeline import fetch_and_extract
from codesheriff_worker.precedent import PgVectorPrecedentRetriever, load_embedder

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
            return _run_claimed_audit(db, factory, audit, gateway, url_for)
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
    factory: sessionmaker[DbSession],
    audit: Audit,
    gateway: GitHubGateway,
    url_for: Callable[[uuid.UUID], str],
) -> str:
    """The body of an audit, once it is ours to run."""
    repository = audit.repository
    installation_id = repository.installation_id

    extraction = fetch_and_extract(
        gateway,
        installation_id=installation_id,
        repo_full_name=repository.full_name,
        pr_number=audit.pr_number,
        base_sha=audit.base_sha,
        head_sha=audit.head_sha,
    )
    evidence, findings = _analyse(db, factory, audit, extraction.units)

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
        body=render(
            audit.id,
            evidence,
            findings,
            url_for(audit.id),
            extraction,
            prior_probability=audit.prior_probability,
            alert_threshold=audit.alert_threshold,
        ),
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


def _deps_for(factory: sessionmaker[DbSession], audit: Audit) -> AgentDeps:
    """Infrastructure this audit's agents may use, bound to this audit's repository.

    The retriever is constructed against `audit.repository_id` and holds no way to name
    another repository (`AUDIT.md` 0.2). It is given the session *factory* rather than the
    audit's open session: agents run concurrently in a thread pool, a SQLAlchemy session is not
    thread-safe, and the audit's session is mid-transaction with unflushed evidence on it.
    """
    return AgentDeps(
        precedent_retriever=PgVectorPrecedentRetriever(
            session_factory=factory,
            repository_id=audit.repository_id,
            embedder=load_embedder(),
        )
    )


def _analyse(
    db: DbSession,
    factory: sessionmaker[DbSession],
    audit: Audit,
    units: list[ChangeUnit],
    agents: list[Agent] | None = None,
) -> tuple[list[Evidence], list[FusionResult]]:
    """Run the agents over every unit, persist what they said, and fuse it.

    Returns everything the comment needs, so the caller does not read it back out of the
    session. Rows are added but not committed: the audit commits once, immediately before it
    checks whether it has been superseded, so an audit overtaken mid-run leaves no half-written
    analysis behind.

    **A change unit row is written even when no unit produced a finding, and even when there are
    no units at all.** `change_units` records what this audit *looked at*; an audit with no rows
    is a legible statement that a pull request touched no analysable Python.
    """
    roster = load_agents(deps=_deps_for(factory, audit)) if agents is None else agents
    config = EngineConfig.load()

    all_evidence: list[Evidence] = []
    all_findings: list[FusionResult] = []

    for unit in units:
        unit_row = to_change_unit_row(audit.id, unit)
        db.add(unit_row)
        # Flushed per unit because an evidence row hangs off the change unit's generated id.
        # This is also what keeps a statement attached to the function it was made about —
        # the Chapter 6 abstentions were about the pipeline and had nowhere to attach.
        db.flush()

        evidence = analyse_unit(roster, unit)
        db.add_all([to_evidence_row(unit_row.id, item) for item in evidence])
        all_evidence.extend(evidence)

        # The prior and the threshold come off the audit row, which recorded them when the
        # audit was opened, together with the calibration run they belong to (§6).
        results = fuse_all_evidence(
            evidence,
            prior_p=audit.prior_probability,
            alert_threshold=audit.alert_threshold,
            ratios=config.ratios,
        )
        for result in results:
            result.file = unit.file

        for result in persistable_findings(results):
            db.add(
                to_finding(
                    audit.id,
                    result,
                    prior_probability=audit.prior_probability,
                    alert_threshold=audit.alert_threshold,
                    calibration_run_id=audit.calibration_run_id,
                    file=unit.file,
                    qualified_symbol=unit.qualified_symbol,
                )
            )
        all_findings.extend(results)

    all_findings.sort(key=lambda r: r.posterior_probability, reverse=True)
    logger.info(
        "Audit %s analysed %s unit(s): %s statement(s), %s finding(s)",
        audit.id,
        len(units),
        len(all_evidence),
        len(all_findings),
    )
    return all_evidence, all_findings
