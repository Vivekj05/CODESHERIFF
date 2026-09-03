"""The audit lifecycle: open, claim, supersede, finish.

Two processes share these rows and neither may assume it is alone. `apps/api` opens an audit on the
webhook path and enqueues its id; `apps/worker` claims it, runs it and closes it. GitHub delivers
at least once and developers push more than once, so both a duplicate delivery and a superseding
push are ordinary traffic rather than error cases.

Every state change here is a single conditional UPDATE rather than a read-then-write. A worker that
reads `status == 'queued'`, decides to proceed, and then writes `running` has a window in which a
second delivery of the same task does the same — and the audit runs twice. `claim()` moves the row
only if it is still where the caller thought it was, and reports whether it won.

Nothing in this module talks to GitHub or decides anything about analysis. It moves rows.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from codesheriff_engine.calibration import CalibrationArtifact
from codesheriff_storage.models import (
    OPEN_AUDIT_STATUSES,
    Audit,
    AuditStatus,
    CalibrationRun,
)


def calibration_run_for(db: DbSession, artifact: CalibrationArtifact) -> CalibrationRun:
    """The stored record of one fitted calibration artifact, created once and reused.

    Every audit points at a calibration run, and that run says on its face what it was fitted
    from (D-032). Before Chapter 14 there was nothing fitted, so this function's predecessor
    wrote a row with `is_provisional=True`, no corpus hash and no ECE — the honest record of
    hand-set numbers. `calibration.json` replaced them, so the provisional row is gone rather
    than kept as a fallback: a fallback would be reached the first time the artifact failed to
    load, and it would quietly re-introduce numbers nobody fitted.

    Matched on the artifact's own identity — the corpus and split it was fitted on, plus the
    prior and threshold it carries — so re-fitting produces a new row and a past audit still
    records the numbers it actually ran under. The `ck_calibration_fitted_is_reproducible`
    constraint holds the other half: a non-provisional row without both hashes cannot exist.
    """
    validation = artifact.metrics.get("validation")
    stmt = select(CalibrationRun).where(
        CalibrationRun.is_provisional.is_(False),
        CalibrationRun.contract_version == artifact.contract_version,
        CalibrationRun.corpus_hash == artifact.corpus_hash,
        CalibrationRun.split_hash == artifact.split_hash,
        CalibrationRun.prior_probability == artifact.base_rate,
        CalibrationRun.alert_threshold == artifact.alert_threshold,
    )
    existing = db.execute(stmt).scalars().first()
    if existing is not None:
        return existing

    run = CalibrationRun(
        contract_version=artifact.contract_version,
        is_provisional=False,
        corpus_hash=artifact.corpus_hash,
        split_hash=artifact.split_hash,
        fitted_likelihoods={
            witness: ratios.model_dump() for witness, ratios in artifact.table().items()
        },
        prior_probability=artifact.base_rate,
        alert_threshold=artifact.alert_threshold,
        ece=validation.ece if validation else None,
        brier=validation.brier if validation else None,
        n_cases=validation.n_claims if validation else None,
        notes=artifact.summary(),
    )
    db.add(run)
    db.flush()
    return run


def audit_for_delivery(db: DbSession, delivery_id: str) -> Audit | None:
    """The audit already opened for this `X-GitHub-Delivery`, if any."""
    if not delivery_id:
        return None
    stmt = select(Audit).where(Audit.delivery_id == delivery_id)
    return db.execute(stmt).scalar_one_or_none()


def open_audit(
    db: DbSession,
    *,
    repository_id: int,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    contract_version: str,
    calibration_run: CalibrationRun,
    delivery_id: str | None = None,
) -> Audit:
    """Insert a queued audit. The caller enqueues its id; the worker does the rest.

    Deliberately does not check for an existing audit on the same head. Re-analysing one commit
    under a new calibration artifact is how a recalibration gets evaluated (D-034), so the only
    duplicate this layer refuses is a repeat of the same *delivery*, and the unique constraint on
    `delivery_id` refuses that one.
    """
    audit = Audit(
        repository_id=repository_id,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        delivery_id=delivery_id,
        status=AuditStatus.QUEUED,
        contract_version=contract_version,
        calibration_run_id=calibration_run.id,
        prior_probability=calibration_run.prior_probability,
        alert_threshold=calibration_run.alert_threshold,
    )
    db.add(audit)
    db.flush()
    return audit


def supersede_open_audits(
    db: DbSession,
    *,
    repository_id: int,
    pr_number: int,
    superseding_head_sha: str,
    keep_audit_id: uuid.UUID,
) -> int:
    """Abandon every unfinished audit for this PR except the one just opened.

    D-034: a run for a superseded head is abandoned rather than finished, because its findings
    describe code that is no longer at the head of the branch. Marking them here rather than
    leaving them to time out means the worker's own check (`is_superseded`) is a second line of
    defence, not the only one.

    Finished audits are untouched — a `succeeded` run is a real record of what the code looked like
    at that commit, and rewriting history to say otherwise would corrupt every later evaluation.
    """
    stmt = (
        update(Audit)
        .where(
            Audit.repository_id == repository_id,
            Audit.pr_number == pr_number,
            Audit.id != keep_audit_id,
            Audit.status.in_(OPEN_AUDIT_STATUSES),
        )
        .values(
            status=AuditStatus.SUPERSEDED,
            finished_at=datetime.now(UTC),
            error_reason=f"superseded by head {superseding_head_sha}",
        )
        .returning(Audit)
    )
    moved = db.execute(stmt, execution_options={"populate_existing": True}).scalars().all()
    return len(moved)


def claim_audit(db: DbSession, audit_id: uuid.UUID) -> Audit | None:
    """Move a queued audit to running and return it, or None if it was not there to claim.

    None covers every reason a claim fails and the caller treats them identically: the task was
    delivered twice and another worker holds it, or a push superseded the audit between the enqueue
    and the claim. In both cases the correct action is to stop, and neither is an error.
    """
    stmt = (
        update(Audit)
        .where(Audit.id == audit_id, Audit.status == AuditStatus.QUEUED)
        .values(status=AuditStatus.RUNNING, started_at=datetime.now(UTC))
        .returning(Audit)
    )
    return db.execute(stmt, execution_options={"populate_existing": True}).scalar_one_or_none()


def is_superseded(db: DbSession, audit_id: uuid.UUID) -> bool:
    """Whether a push has abandoned this audit while it was running.

    Checked again before anything is posted to GitHub. The window between claiming an audit and
    finishing it is the whole pipeline, and a comment about a commit nobody can see any more is
    worse than no comment.
    """
    stmt = select(Audit.status).where(Audit.id == audit_id)
    status = db.execute(stmt).scalar_one_or_none()
    return status == AuditStatus.SUPERSEDED


def finish_audit(
    db: DbSession,
    audit_id: uuid.UUID,
    *,
    github_comment_id: int | None = None,
) -> Audit | None:
    """Close a running audit as succeeded, recording the comment it owns.

    `github_comment_id` is what makes the next push edit this comment instead of posting another
    (D-034). Only moves an audit out of `running`, so a superseded audit that finished its work
    anyway does not quietly resurrect itself as a result.
    """
    stmt = (
        update(Audit)
        .where(Audit.id == audit_id, Audit.status == AuditStatus.RUNNING)
        .values(
            status=AuditStatus.SUCCEEDED,
            finished_at=datetime.now(UTC),
            github_comment_id=github_comment_id,
        )
        .returning(Audit)
    )
    return db.execute(stmt, execution_options={"populate_existing": True}).scalar_one_or_none()


def fail_audit(db: DbSession, audit_id: uuid.UUID, reason: str) -> Audit | None:
    """Close an unfinished audit as failed, with a reason.

    A reason is mandatory — the CHECK constraint in migration 0001 enforces it — because a failed
    audit with no explanation is indistinguishable from a bug in the worker, and the two need
    different responses. Superseded audits are left alone: being overtaken is not a failure.
    """
    stmt = (
        update(Audit)
        .where(Audit.id == audit_id, Audit.status.in_(OPEN_AUDIT_STATUSES))
        .values(
            status=AuditStatus.FAILED,
            finished_at=datetime.now(UTC),
            error_reason=reason or "unspecified failure",
        )
        .returning(Audit)
    )
    return db.execute(stmt, execution_options={"populate_existing": True}).scalar_one_or_none()


def latest_comment_id(db: DbSession, *, repository_id: int, pr_number: int) -> int | None:
    """The comment this PR's previous audit posted, so the next one edits it (D-034).

    Read from the most recent audit that actually posted, not the most recent audit: a run that
    failed before posting must not erase the pointer to a comment that is still on the PR.
    """
    stmt = (
        select(Audit.github_comment_id)
        .where(
            Audit.repository_id == repository_id,
            Audit.pr_number == pr_number,
            Audit.github_comment_id.is_not(None),
        )
        .order_by(Audit.created_at.desc())
        .limit(1)
    )
    return db.execute(stmt).scalar_one_or_none()
