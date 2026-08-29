"""The audit task, end to end against a real database and a fake GitHub.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

Chapter 6's acceptance criterion is that a pull request receives a comment from the *worker* rather
than from the request handler. These tests assert the whole of that path — claim, render, post,
close — plus the three ways it is allowed to stop early, which are the ones a queue makes ordinary:
delivered twice, superseded mid-run, and GitHub refusing.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import sessionmaker

from codesheriff_contracts import CONTRACT_VERSION
from codesheriff_storage import (
    claim_audit,
    finish_audit,
    open_audit,
    provisional_calibration_run,
    supersede_open_audits,
    upsert_installation,
    upsert_repository,
)
from codesheriff_storage.models import Audit, AuditStatus, ChangeUnitRow
from codesheriff_worker.github_gateway import PullRequestFile
from codesheriff_worker.tasks import _run_claimed_audit, execute_audit

from .conftest import FakeGitHubGateway

pytestmark = pytest.mark.db

INSTALLATION_ID = 9001
REPO_ID = 5001
REPO_FULL_NAME = "acme/payments-api"


def url_for(audit_id: uuid.UUID) -> str:
    return f"http://localhost:3000/audits/{audit_id}"


@pytest.fixture
def audit(db: DbSession) -> Audit:
    """A queued audit, as the webhook would have left it."""
    upsert_installation(
        db, installation_id=INSTALLATION_ID, account_login="acme", account_type="Organization"
    )
    upsert_repository(
        db,
        repo_id=REPO_ID,
        installation_id=INSTALLATION_ID,
        full_name=REPO_FULL_NAME,
        default_branch="main",
        is_private=True,
    )
    calibration = provisional_calibration_run(
        db,
        contract_version=CONTRACT_VERSION,
        prior_probability=0.05,
        alert_threshold=0.70,
    )
    row = open_audit(
        db,
        repository_id=REPO_ID,
        pr_number=7,
        base_sha="b" * 40,
        head_sha="a" * 40,
        contract_version=CONTRACT_VERSION,
        calibration_run=calibration,
        delivery_id="delivery-1",
    )
    db.commit()
    return row


def test_a_queued_audit_becomes_a_comment(
    db: DbSession,
    factory: sessionmaker[DbSession],
    gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    """The Chapter 6 seam: the worker posts, not the request handler."""
    state = execute_audit(audit.id, factory, gateway, url_for)

    assert state == "succeeded"
    assert len(gateway.posted) == 1
    posted = gateway.posted[0]
    assert posted.repo_full_name == REPO_FULL_NAME
    assert posted.pr_number == 7
    assert posted.installation_id == INSTALLATION_ID
    assert posted.comment_id is None


def test_the_audit_is_closed_with_the_comment_it_owns(
    db: DbSession,
    factory: sessionmaker[DbSession],
    gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    execute_audit(audit.id, factory, gateway, url_for)

    db.expire_all()
    row = db.get(Audit, audit.id)
    assert row is not None
    assert row.status is AuditStatus.SUCCEEDED
    assert row.started_at is not None
    assert row.finished_at is not None
    assert row.github_comment_id is not None and row.github_comment_id > 0


def test_no_probability_reaches_the_comment(
    db: DbSession,
    factory: sessionmaker[DbSession],
    gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    """D-032. Nothing is calibrated yet, so there is nothing a number could honestly mean."""
    execute_audit(audit.id, factory, gateway, url_for)

    body = gateway.posted[0].body
    assert "No analysis has run" in body
    # Not the prior, not the threshold, and no per-finding probability label of the kind the old
    # reporter emitted. The one "87%" in the body is the explanation of what calibration means,
    # which is the opposite of a claim about this pull request.
    assert "0.05" not in body
    assert "0.70" not in body
    assert "Probability" not in body
    assert "posterior" not in body.lower() or "calibrated" in body.lower()


def test_nothing_from_the_pull_request_is_echoed(
    db: DbSession,
    factory: sessionmaker[DbSession],
    gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    """AUDIT.md 0.4 is what happens when untrusted text reaches a markdown table.

    The comment names the repository, which GitHub itself supplied and routed the call to, and
    nothing else from the pull request — no title, no branch, no description, no source.
    """
    execute_audit(audit.id, factory, gateway, url_for)

    body = gateway.posted[0].body
    assert "feature" not in body
    assert audit.head_sha not in body


def test_every_backend_is_reported_as_having_abstained(
    db: DbSession,
    factory: sessionmaker[DbSession],
    gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    """Four agents that do not exist could not run. Reporting "clean" is AUDIT.md 4.4."""
    execute_audit(audit.id, factory, gateway, url_for)

    body = gateway.posted[0].body
    for agent_id in (
        "structural.taint",
        "structural.semgrep",
        "semantic.hosted",
        "context.rag",
        "runtime.sfi",
    ):
        assert agent_id in body
    assert "Abstained" in body
    assert "No security vulnerabilities detected" not in body


def test_a_second_delivery_of_the_same_task_does_nothing(
    db: DbSession,
    factory: sessionmaker[DbSession],
    gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    """Celery delivers at least once, and `task_acks_late` makes that more likely, not less."""
    execute_audit(audit.id, factory, gateway, url_for)
    state = execute_audit(audit.id, factory, gateway, url_for)

    assert state == "not_claimable"
    assert len(gateway.posted) == 1


def test_an_audit_superseded_before_the_claim_is_not_run(
    db: DbSession,
    factory: sessionmaker[DbSession],
    gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    supersede_open_audits(
        db,
        repository_id=REPO_ID,
        pr_number=7,
        superseding_head_sha="f" * 40,
        keep_audit_id=uuid.uuid4(),
    )
    db.commit()

    state = execute_audit(audit.id, factory, gateway, url_for)

    assert state == "not_claimable"
    assert gateway.posted == []


def test_an_audit_superseded_while_running_posts_nothing(
    db: DbSession, gateway: FakeGitHubGateway, audit: Audit
) -> None:
    """The second check, immediately before writing to GitHub.

    Driven through `_run_claimed_audit` rather than `execute_audit`, because the case it guards is
    a push that lands *after* the claim — which the outer check cannot see, and which the whole
    length of the pipeline makes likely. Reaching for the private function is deliberate: the
    alternative is a test that races two threads to prove a one-line guard.
    """
    claimed = claim_audit(db, audit.id)
    assert claimed is not None
    supersede_open_audits(
        db,
        repository_id=REPO_ID,
        pr_number=7,
        superseding_head_sha="f" * 40,
        keep_audit_id=uuid.uuid4(),
    )
    db.commit()

    state = _run_claimed_audit(db, claimed, gateway, url_for)

    assert state == "superseded"
    assert gateway.posted == []


def test_a_push_edits_the_comment_rather_than_adding_another(
    db: DbSession,
    factory: sessionmaker[DbSession],
    gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    """D-034: a developer who pushes six times gets one comment that changes, not six."""
    execute_audit(audit.id, factory, gateway, url_for)
    first_comment_id = gateway.posted[0].comment_id
    assert first_comment_id is None

    calibration = provisional_calibration_run(
        db, contract_version=CONTRACT_VERSION, prior_probability=0.05, alert_threshold=0.70
    )
    second = open_audit(
        db,
        repository_id=REPO_ID,
        pr_number=7,
        base_sha="b" * 40,
        head_sha="f" * 40,
        contract_version=CONTRACT_VERSION,
        calibration_run=calibration,
        delivery_id="delivery-2",
    )
    db.commit()

    execute_audit(second.id, factory, gateway, url_for)

    assert len(gateway.posted) == 2
    assert gateway.posted[1].comment_id is not None


def test_a_github_failure_is_recorded_on_the_row_and_raised(
    db: DbSession,
    factory: sessionmaker[DbSession],
    audit: Audit,
) -> None:
    """Both records have to agree. A row that says failed and a task that says succeeded is worse
    than either one alone."""
    gateway = FakeGitHubGateway(failing=True)

    with pytest.raises(RuntimeError):
        execute_audit(audit.id, factory, gateway, url_for)

    db.expire_all()
    row = db.get(Audit, audit.id)
    assert row is not None
    assert row.status is AuditStatus.FAILED
    assert row.error_reason is not None and "GitHub is unreachable" in row.error_reason


def test_an_unknown_audit_id_is_not_claimable(
    factory: sessionmaker[DbSession], gateway: FakeGitHubGateway
) -> None:
    assert execute_audit(uuid.uuid4(), factory, gateway, url_for) == "not_claimable"


def test_a_finished_audit_is_never_re_run(
    db: DbSession,
    factory: sessionmaker[DbSession],
    gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    claim_audit(db, audit.id)
    finish_audit(db, audit.id, github_comment_id=4242)
    db.commit()

    assert execute_audit(audit.id, factory, gateway, url_for) == "not_claimable"
    assert gateway.posted == []


# -- extraction reaches the database (Chapter 8) ----------------------------------------------

BEFORE_SRC = """import os


class Orders:
    @login_required
    def export(self, request):
        return dump(request.args["scope"])
"""

AFTER_SRC = """import os
import subprocess

EXPORT_KEY = "sk_live_51H8xY2"


class Orders:
    def export(self, request):
        return subprocess.run(dump(request.args["scope"]), shell=True)
"""


@pytest.fixture
def analysing_gateway() -> FakeGitHubGateway:
    """A pull request that changes one method and one module-scope constant."""
    return FakeGitHubGateway(
        files=[PullRequestFile("orders/api.py", "modified")],
        blobs={
            ("a" * 40, "orders/api.py"): AFTER_SRC,
            ("b" * 40, "orders/api.py"): BEFORE_SRC,
        },
    )


def units_of(db: DbSession, audit_id: uuid.UUID) -> list[ChangeUnitRow]:
    return list(
        db.execute(
            select(ChangeUnitRow)
            .where(ChangeUnitRow.audit_id == audit_id)
            .order_by(ChangeUnitRow.qualified_symbol)
        ).scalars()
    )


def test_the_changed_functions_are_recorded_against_the_audit(
    db: DbSession,
    factory: sessionmaker[DbSession],
    analysing_gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    """`change_units` is the record of what this audit looked at. Without it a finding can never
    be traced back to a function."""
    execute_audit(audit.id, factory, analysing_gateway, url_for)

    rows = units_of(db, audit.id)
    assert [r.qualified_symbol for r in rows] == ["<module>", "Orders.export"]
    assert [r.file for r in rows] == ["orders/api.py", "orders/api.py"]


def test_a_recorded_unit_carries_its_symbol_and_class_apart(
    db: DbSession,
    factory: sessionmaker[DbSession],
    analysing_gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    """AUDIT.md 4.1: every unit used to be a file with `symbol=None`, so `qualified_symbol` was
    always `<module>` and every finding in a file collapsed onto one key."""
    execute_audit(audit.id, factory, analysing_gateway, url_for)

    export = next(r for r in units_of(db, audit.id) if r.symbol == "export")
    assert (export.enclosing_class, export.language) == ("Orders", "python")
    assert export.start_line > 1
    assert export.changed_lines


def test_no_source_is_persisted_only_hashes(
    db: DbSession,
    factory: sessionmaker[DbSession],
    analysing_gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    """§6: findings, evidence and hashes only. The row has no column that could hold source, and
    this asserts the values that stand in for it are actually written."""
    execute_audit(audit.id, factory, analysing_gateway, url_for)

    export = next(r for r in units_of(db, audit.id) if r.symbol == "export")
    assert len(export.post_src_sha256) == 64
    assert export.pre_src_sha256 is not None, "the method existed before, with a decorator"
    assert export.post_src_bytes > 0 and export.post_src_lines > 0


def test_the_comment_reports_what_was_extracted(
    db: DbSession,
    factory: sessionmaker[DbSession],
    analysing_gateway: FakeGitHubGateway,
    audit: Audit,
) -> None:
    execute_audit(audit.id, factory, analysing_gateway, url_for)

    assert "Extracted **2** changed functions" in analysing_gateway.posted[0].body


def test_a_pull_request_with_no_analysable_python_records_no_units_and_still_comments(
    db: DbSession,
    factory: sessionmaker[DbSession],
    audit: Audit,
) -> None:
    """An audit with no rows is a legible statement, not a failure. Saying nothing at all would
    be indistinguishable from a worker that never ran."""
    gateway = FakeGitHubGateway(files=[PullRequestFile("README.md", "modified")])

    assert execute_audit(audit.id, factory, gateway, url_for) == "succeeded"
    assert units_of(db, audit.id) == []
    assert "Extracted **0** changed functions" in gateway.posted[0].body


def test_a_failure_while_fetching_is_recorded_on_the_row_and_raised(
    db: DbSession,
    factory: sessionmaker[DbSession],
    audit: Audit,
) -> None:
    """Extraction now runs before the comment, so it is a new way for an audit to fail. The row
    is the system of record and the exception is what Celery's monitoring sees; recording only
    one of the two leaves the other saying the run succeeded."""
    gateway = FakeGitHubGateway(failing=True)

    with pytest.raises(RuntimeError):
        execute_audit(audit.id, factory, gateway, url_for)

    db.expire_all()
    assert db.get(Audit, audit.id).status is AuditStatus.FAILED
