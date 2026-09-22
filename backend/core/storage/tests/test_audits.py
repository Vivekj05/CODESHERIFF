"""The audit lifecycle under the conditions it actually meets.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

The API tests drive these through HTTP. These exist separately because three of them are claims
about concurrency and idempotency that a single-threaded route test cannot make: a delivery cannot
open two audits, a queued audit can only be claimed once, and a superseded audit cannot come back.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from codesheriff_contracts import CONTRACT_VERSION
from codesheriff_engine.calibration import active_artifact
from codesheriff_storage.audits import (
    audit_for_delivery,
    calibration_run_for,
    claim_audit,
    fail_audit,
    finish_audit,
    is_superseded,
    latest_comment_id,
    open_audit,
    supersede_open_audits,
)
from codesheriff_storage.identity import upsert_installation, upsert_repository
from codesheriff_storage.models import Audit, AuditStatus, CalibrationRun

pytestmark = pytest.mark.db

REPO_ID = 5001
INSTALLATION_ID = 9001


@pytest.fixture
def repo_id(session: DbSession) -> int:
    upsert_installation(
        session,
        installation_id=INSTALLATION_ID,
        account_login="acme",
        account_type="Organization",
    )
    upsert_repository(
        session,
        repo_id=REPO_ID,
        installation_id=INSTALLATION_ID,
        full_name="acme/payments-api",
        default_branch="main",
        is_private=True,
    )
    session.flush()
    return REPO_ID


@pytest.fixture
def calibration(session: DbSession) -> CalibrationRun:
    return calibration_run_for(session, active_artifact())


def make_audit(
    session: DbSession,
    calibration: CalibrationRun,
    repo_id: int,
    *,
    pr_number: int = 7,
    head_sha: str = "a" * 40,
    delivery_id: str | None = None,
) -> Audit:
    return open_audit(
        session,
        repository_id=repo_id,
        pr_number=pr_number,
        base_sha="b" * 40,
        head_sha=head_sha,
        contract_version=CONTRACT_VERSION,
        calibration_run=calibration,
        delivery_id=delivery_id,
    )


def test_the_run_records_the_corpus_it_was_fitted_on_and_is_reused(session: DbSession) -> None:
    """Every audit cites a calibration artifact, and since Chapter 14 that artifact is fitted.

    The row is matched on the artifact's own identity, so two audits opened under one
    `calibration.json` share one row and a re-fit produces a new one.
    """
    artifact = active_artifact()
    first = calibration_run_for(session, artifact)
    second = calibration_run_for(session, artifact)

    assert first.id == second.id
    assert first.is_provisional is False
    assert first.corpus_hash == artifact.corpus_hash
    assert first.split_hash == artifact.split_hash
    assert first.fitted_likelihoods, "a fitted run with no ratios cannot explain a posterior"
    assert first.ece is not None and first.brier is not None


def test_a_refit_creates_a_new_run_rather_than_rewriting_the_old_one(
    session: DbSession,
) -> None:
    """A past audit must still record the numbers it actually ran under (§6).

    Re-fitting at a different base rate is the ordinary way that happens: the ratios are
    unchanged, the prior moves by a recorded factor, and the audits already closed keep
    pointing at the artifact that produced them.
    """
    artifact = active_artifact()
    rescaled = artifact.model_copy(
        update={"prior": artifact.prior.model_copy(update={"base_rate": 0.10})}
    )

    first = calibration_run_for(session, artifact)
    second = calibration_run_for(session, rescaled)

    assert first.id != second.id
    assert second.prior_probability == 0.10


def test_audit_copies_the_numbers_it_ran_under(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    """A threshold chosen later must not retroactively rewrite which past findings were alerts.

    Asserted against the artifact rather than against literals. The literals here were the
    pre-Chapter-14 provisional pair, and they went stale the moment the numbers were fitted —
    which is the same failure in miniature: a number written down in a second place, describing a
    run it did not come from. A re-fit changes both sides of these assertions together.
    """
    artifact = active_artifact()
    audit = make_audit(session, calibration, repo_id)

    assert audit.status is AuditStatus.QUEUED
    assert audit.calibration_run_id == calibration.id
    assert audit.prior_probability == pytest.approx(artifact.base_rate)
    assert audit.alert_threshold == pytest.approx(artifact.alert_threshold)


def test_one_delivery_cannot_open_two_audits(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    """GitHub delivers at least once. The constraint is what makes the retry harmless (D-038)."""
    make_audit(session, calibration, repo_id, delivery_id="delivery-1")

    with pytest.raises(IntegrityError):
        make_audit(session, calibration, repo_id, head_sha="c" * 40, delivery_id="delivery-1")


def test_audit_for_delivery_finds_the_first_one(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    audit = make_audit(session, calibration, repo_id, delivery_id="delivery-2")

    assert audit_for_delivery(session, "delivery-2") is not None
    assert audit_for_delivery(session, "delivery-2").id == audit.id  # type: ignore[union-attr]
    assert audit_for_delivery(session, "never-sent") is None
    assert audit_for_delivery(session, "") is None


def test_the_same_head_may_be_audited_twice(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    """Deliberately not unique on (repository_id, head_sha) — that is how recalibration is
    evaluated (D-034)."""
    first = make_audit(session, calibration, repo_id, delivery_id="d-1")
    second = make_audit(session, calibration, repo_id, delivery_id="d-2")

    assert first.id != second.id
    assert first.head_sha == second.head_sha


def test_a_push_supersedes_the_unfinished_run(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    old = make_audit(session, calibration, repo_id, head_sha="a" * 40, delivery_id="d-1")
    new = make_audit(session, calibration, repo_id, head_sha="f" * 40, delivery_id="d-2")

    moved = supersede_open_audits(
        session,
        repository_id=repo_id,
        pr_number=7,
        superseding_head_sha=new.head_sha,
        keep_audit_id=new.id,
    )

    session.refresh(old)
    assert moved == 1
    assert old.status is AuditStatus.SUPERSEDED
    assert old.finished_at is not None
    assert old.error_reason is not None and new.head_sha in old.error_reason
    assert is_superseded(session, old.id) is True
    assert is_superseded(session, new.id) is False


def test_superseding_leaves_finished_audits_alone(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    """A succeeded run is a real record of one commit. Rewriting it corrupts later evaluation."""
    done = make_audit(session, calibration, repo_id, head_sha="a" * 40, delivery_id="d-1")
    claim_audit(session, done.id)
    finish_audit(session, done.id, github_comment_id=555)

    new = make_audit(session, calibration, repo_id, head_sha="f" * 40, delivery_id="d-2")
    moved = supersede_open_audits(
        session,
        repository_id=repo_id,
        pr_number=7,
        superseding_head_sha=new.head_sha,
        keep_audit_id=new.id,
    )

    session.refresh(done)
    assert moved == 0
    assert done.status is AuditStatus.SUCCEEDED


def test_superseding_is_scoped_to_one_pull_request(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    other_pr = make_audit(session, calibration, repo_id, pr_number=8, delivery_id="d-1")
    new = make_audit(session, calibration, repo_id, pr_number=7, delivery_id="d-2")

    supersede_open_audits(
        session,
        repository_id=repo_id,
        pr_number=7,
        superseding_head_sha=new.head_sha,
        keep_audit_id=new.id,
    )

    session.refresh(other_pr)
    assert other_pr.status is AuditStatus.QUEUED


def test_an_audit_can_only_be_claimed_once(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    """The whole reason the claim is a conditional UPDATE: Celery delivers at least once too."""
    audit = make_audit(session, calibration, repo_id, delivery_id="d-1")

    first = claim_audit(session, audit.id)
    second = claim_audit(session, audit.id)

    assert first is not None
    assert first.status is AuditStatus.RUNNING
    assert first.started_at is not None
    assert second is None


def test_a_superseded_audit_cannot_be_claimed(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    old = make_audit(session, calibration, repo_id, head_sha="a" * 40, delivery_id="d-1")
    new = make_audit(session, calibration, repo_id, head_sha="f" * 40, delivery_id="d-2")
    supersede_open_audits(
        session,
        repository_id=repo_id,
        pr_number=7,
        superseding_head_sha=new.head_sha,
        keep_audit_id=new.id,
    )

    assert claim_audit(session, old.id) is None


def test_claiming_an_unknown_audit_returns_none(session: DbSession) -> None:
    assert claim_audit(session, uuid.uuid4()) is None


def test_finish_records_the_comment_it_owns(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    """`github_comment_id` is what makes the next push edit rather than duplicate (D-034)."""
    audit = make_audit(session, calibration, repo_id, delivery_id="d-1")
    claim_audit(session, audit.id)

    finished = finish_audit(session, audit.id, github_comment_id=12345)

    assert finished is not None
    assert finished.status is AuditStatus.SUCCEEDED
    assert finished.github_comment_id == 12345
    assert finished.finished_at is not None
    assert latest_comment_id(session, repository_id=repo_id, pr_number=7) == 12345


def test_a_later_run_that_never_posted_does_not_erase_the_pointer(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    """A failure before posting must not lose the comment that is still on the PR."""
    posted = make_audit(session, calibration, repo_id, delivery_id="d-1")
    claim_audit(session, posted.id)
    finish_audit(session, posted.id, github_comment_id=999)

    crashed = make_audit(session, calibration, repo_id, head_sha="f" * 40, delivery_id="d-2")
    claim_audit(session, crashed.id)
    fail_audit(session, crashed.id, "the worker fell over")

    assert latest_comment_id(session, repository_id=repo_id, pr_number=7) == 999


def test_a_queued_audit_cannot_be_finished_without_being_claimed(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    audit = make_audit(session, calibration, repo_id, delivery_id="d-1")

    assert finish_audit(session, audit.id, github_comment_id=1) is None


def test_failure_always_carries_a_reason(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    """The CHECK constraint from migration 0001 forbids a silent failure."""
    audit = make_audit(session, calibration, repo_id, delivery_id="d-1")
    claim_audit(session, audit.id)

    failed = fail_audit(session, audit.id, "")

    assert failed is not None
    assert failed.status is AuditStatus.FAILED
    assert failed.error_reason == "unspecified failure"


def test_being_overtaken_is_not_a_failure(
    session: DbSession, calibration: CalibrationRun, repo_id: int
) -> None:
    old = make_audit(session, calibration, repo_id, head_sha="a" * 40, delivery_id="d-1")
    new = make_audit(session, calibration, repo_id, head_sha="f" * 40, delivery_id="d-2")
    supersede_open_audits(
        session,
        repository_id=repo_id,
        pr_number=7,
        superseding_head_sha=new.head_sha,
        keep_audit_id=new.id,
    )

    assert fail_audit(session, old.id, "worker crashed") is None
    session.refresh(old)
    assert old.status is AuditStatus.SUPERSEDED
