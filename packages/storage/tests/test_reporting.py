"""The dashboard's read queries, against a real database.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

Three claims here are the reason this file exists rather than only route tests. **Scope is a
property of the query**, so it is asserted at the layer that holds it — a session that can see no
installations gets nothing, and one that can see installation A gets nothing of installation B's.
**Counts must not multiply**: an audit with several units, several statements per unit and several
findings is the shape that turns a careless join into a plausible wrong number, so one is built
here on purpose. And **the keyset cursor is a pair**, because two audits opened by one push share
a `created_at` and a cursor on the timestamp alone would drop one of them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session as DbSession

from codesheriff_contracts import CONTRACT_VERSION, ChangeUnit, Evidence
from codesheriff_engine.calibration import active_artifact
from codesheriff_storage import reporting
from codesheriff_storage.audits import (
    calibration_run_for,
    claim_audit,
    finish_audit,
    open_audit,
)
from codesheriff_storage.identity import upsert_installation, upsert_repository
from codesheriff_storage.mapping import to_change_unit_row, to_evidence_row
from codesheriff_storage.models import Audit, CalibrationRun, Finding
from codesheriff_storage.reporting import audit_detail, list_audit_summaries, overview_stats

pytestmark = pytest.mark.db

OURS = 9001
THEIRS = 9002
OUR_REPO = 5001
THEIR_REPO = 5002


@pytest.fixture
def calibration(session: DbSession) -> CalibrationRun:
    return calibration_run_for(session, active_artifact())


@pytest.fixture
def repos(session: DbSession) -> tuple[int, int]:
    """Two repositories under two different installations.

    The second one exists in every test in this module, and is never expected in a result. A
    scoping test with only one tenant's data cannot fail.
    """
    for installation_id, repo_id, name in (
        (OURS, OUR_REPO, "acme/payments-api"),
        (THEIRS, THEIR_REPO, "rival/secret-thing"),
    ):
        upsert_installation(
            session,
            installation_id=installation_id,
            account_login=f"account-{installation_id}",
            account_type="Organization",
        )
        upsert_repository(
            session,
            repo_id=repo_id,
            installation_id=installation_id,
            full_name=name,
            default_branch="main",
            is_private=True,
        )
    session.flush()
    return OUR_REPO, THEIR_REPO


def make_audit(
    session: DbSession,
    calibration: CalibrationRun,
    repo_id: int,
    *,
    pr_number: int = 7,
    head_sha: str | None = None,
) -> Audit:
    audit = open_audit(
        session,
        repository_id=repo_id,
        pr_number=pr_number,
        base_sha="b" * 40,
        head_sha=head_sha or uuid.uuid4().hex[:40].ljust(40, "0"),
        contract_version=CONTRACT_VERSION,
        calibration_run=calibration,
    )
    session.flush()
    return audit


def make_unit(index: int) -> ChangeUnit:
    return ChangeUnit(
        unit_id=f"unit-{index}",
        repo="acme/payments-api",
        language="python",
        file=f"app/module_{index}.py",
        symbol=f"handler_{index}",
        start_line=index * 10,
        changed_lines=[index * 10 + 1],
        post_src=f"def handler_{index}(request):\n    return request\n",
        base_sha="b" * 40,
        head_sha="h" * 40,
    )


def add_unit_with_statements(
    session: DbSession, audit: Audit, unit: ChangeUnit, *, cwe: str = "CWE-89"
) -> None:
    """One unit and one statement per witness — a detection, a silence and two abstentions.

    All three evidence kinds on purpose. The counts this module asserts are per kind, and a
    fixture that only ever wrote detections would let a query that ignored `kind` pass.
    """
    row = to_change_unit_row(audit.id, unit)
    session.add(row)
    session.flush()
    statements = [
        Evidence.detection(
            agent_id="structural.taint",
            agent_version="1.0.0",
            unit_id=unit.unit_id,
            finding_key=unit.key_for(cwe),
            cwe=cwe,
            raw_score=0.7,
            explanation="Parameter reaches a SQL sink unsanitised.",
        ),
        Evidence.silence(
            agent_id="semantic.hosted",
            agent_version="1.0.0",
            unit_id=unit.unit_id,
            covered_cwes={cwe, "CWE-79"},
        ),
        Evidence.abstention(
            agent_id="runtime.sfi",
            agent_version="1.0.0",
            unit_id=unit.unit_id,
            reason="interpreter_unavailable",
        ),
        Evidence.abstention(
            agent_id="context.rag",
            agent_version="1.0.0",
            unit_id=unit.unit_id,
            reason="no_precedent",
        ),
    ]
    session.add_all([to_evidence_row(row.id, item) for item in statements])
    session.flush()


def add_finding(
    session: DbSession,
    audit: Audit,
    unit: ChangeUnit,
    *,
    cwe: str = "CWE-89",
    posterior: float = 0.9,
) -> Finding:
    finding = Finding(
        audit_id=audit.id,
        finding_key=unit.key_for(cwe),
        cwe=cwe,
        posterior_probability=posterior,
        is_alert_worthy=posterior >= audit.alert_threshold,
        severity="high",
        prior_probability=audit.prior_probability,
        alert_threshold=audit.alert_threshold,
        calibration_run_id=audit.calibration_run_id,
        file=unit.file,
        qualified_symbol=unit.qualified_symbol,
        line_numbers=list(unit.changed_lines),
        title=f"{cwe} in {unit.qualified_symbol}",
    )
    session.add(finding)
    session.flush()
    return finding


def test_an_audit_on_another_installation_is_not_listed(
    session: DbSession, calibration: CalibrationRun, repos: tuple[int, int]
) -> None:
    """The scope check, stated at the layer that holds it (D-035)."""
    ours, theirs = repos
    make_audit(session, calibration, ours, pr_number=1)
    make_audit(session, calibration, theirs, pr_number=2)

    listed = list_audit_summaries(session, installation_ids=[OURS])

    assert [row.pr_number for row in listed] == [1]


def test_an_empty_installation_list_returns_nothing_rather_than_everything(
    session: DbSession, calibration: CalibrationRun, repos: tuple[int, int]
) -> None:
    """The asymmetry that is the whole access check.

    A bare `SELECT *` would pass every other test in this file.
    """
    ours, _ = repos
    make_audit(session, calibration, ours)

    assert list_audit_summaries(session, installation_ids=[]) == []
    assert audit_detail(session, audit_id=uuid.uuid4(), installation_ids=[]) is None
    assert overview_stats(session, installation_ids=[]).audits == 0


def test_counts_do_not_multiply_across_units_findings_and_evidence(
    session: DbSession, calibration: CalibrationRun, repos: tuple[int, int]
) -> None:
    """Three units, four statements each, two findings — and the summary says 3, 2, 1.

    A join across all three tables and a `COUNT(*)` would report twelve units here. The number
    would look plausible, which is why this is asserted rather than eyeballed.
    """
    ours, _ = repos
    audit = make_audit(session, calibration, ours)
    units = [make_unit(index) for index in range(3)]
    for unit in units:
        add_unit_with_statements(session, audit, unit)
    add_finding(session, audit, units[0], posterior=0.91)
    add_finding(session, audit, units[1], cwe="CWE-79", posterior=0.05)

    summary = list_audit_summaries(session, installation_ids=[OURS])[0]

    assert summary.units == 3
    assert summary.findings == 2
    assert summary.alerts == 1
    assert summary.top_posterior == pytest.approx(0.91)


def test_the_history_pages_through_a_tie_on_created_at_without_losing_one(
    session: DbSession, calibration: CalibrationRun, repos: tuple[int, int]
) -> None:
    """Keyset paging on `(created_at, id)`, across a page boundary that falls inside a tie.

    Two audits opened by one push share a `created_at` to the microsecond often enough. The tie
    is placed deliberately at the boundary: with a cursor on the timestamp alone, the second of
    the tied pair is skipped — a lost audit, not a misordered one — and the totals below are what
    catch it.
    """
    ours, _ = repos
    stamp = datetime.now(UTC)
    audits = [make_audit(session, calibration, ours, pr_number=n) for n in range(5)]
    # Newest first: minutes 0, 1, 1, 3, 4 — so the tie straddles the first page boundary below.
    for offset, minutes in enumerate((0, 1, 1, 3, 4)):
        audits[offset].created_at = stamp - timedelta(minutes=minutes)
    session.flush()

    seen: list[uuid.UUID] = []
    before: tuple[datetime, uuid.UUID] | None = None
    for _ in range(4):
        page = list_audit_summaries(session, installation_ids=[OURS], limit=2, before=before)
        if not page:
            break
        seen.extend(row.id for row in page)
        before = (page[-1].created_at, page[-1].id)

    assert len(seen) == 5, "a page boundary dropped an audit"
    assert len(set(seen)) == 5, "a page boundary repeated an audit"
    assert seen[0] == audits[0].id, "the history is not newest first"


def test_the_detail_carries_units_statements_and_findings(
    session: DbSession, calibration: CalibrationRun, repos: tuple[int, int]
) -> None:
    ours, _ = repos
    audit = make_audit(session, calibration, ours)
    unit = make_unit(1)
    add_unit_with_statements(session, audit, unit)
    add_finding(session, audit, unit)
    # Claimed first: `finish_audit` only moves an audit out of `running`, so an audit closed
    # without being claimed would silently stay queued and the assertion below would be vacuous.
    claim_audit(session, audit.id)
    finish_audit(session, audit.id, github_comment_id=12345)
    session.flush()

    detail = audit_detail(session, audit_id=audit.id, installation_ids=[OURS])

    assert detail is not None
    assert detail.repository_full_name == "acme/payments-api"
    assert detail.unit_count == 1
    assert [row.unit_id for row in detail.units] == ["unit-1"]
    assert {item.kind.value for item in detail.units[0].evidence} == {
        "detection",
        "silence",
        "abstention",
    }
    assert [row.cwe for row in detail.findings] == ["CWE-89"]
    assert detail.audit.status.value == "succeeded"
    assert detail.audit.github_comment_id == 12345
    assert detail.calibration is not None
    assert detail.calibration.is_provisional is False


def test_a_detail_for_another_installation_is_none_not_a_partial_row(
    session: DbSession, calibration: CalibrationRun, repos: tuple[int, int]
) -> None:
    """Not "an audit with no findings" — nothing at all, so the route can 404 (D-035)."""
    _, theirs = repos
    audit = make_audit(session, calibration, theirs)

    assert audit_detail(session, audit_id=audit.id, installation_ids=[OURS]) is None


def test_a_capped_unit_list_still_reports_the_true_count(
    session: DbSession,
    calibration: CalibrationRun,
    repos: tuple[int, int],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An audit of 900 functions showing 200 must not read as an audit that analysed 200.

    The cap is lowered rather than 201 units created: the claim is that the two numbers come from
    different queries, and paying for 201 flushes to state it would make this the slowest test in
    the suite for no extra assurance.
    """
    ours, _ = repos
    monkeypatch.setattr(reporting, "MAX_UNITS_PER_AUDIT", 2)
    audit = make_audit(session, calibration, ours)
    for index in range(3):
        add_unit_with_statements(session, audit, make_unit(index))

    detail = audit_detail(session, audit_id=audit.id, installation_ids=[OURS])

    assert detail is not None
    assert len(detail.units) == 2, "the cap did not apply"
    assert detail.unit_count == 3, "a truncated list under-reported what was analysed"


def test_the_overview_counts_each_evidence_kind_separately(
    session: DbSession, calibration: CalibrationRun, repos: tuple[int, int]
) -> None:
    """Silence and abstention are counted apart, because they are different statements (§5).

    An overview that summed them into "found nothing" would report the runtime witness as a quiet
    agent on a machine where it could not run at all.
    """
    ours, theirs = repos
    audit = make_audit(session, calibration, ours)
    for index in range(2):
        unit = make_unit(index)
        add_unit_with_statements(session, audit, unit)
        add_finding(session, audit, unit, posterior=0.9 if index == 0 else 0.01)

    other = make_audit(session, calibration, theirs)
    add_unit_with_statements(session, other, make_unit(99))

    stats = overview_stats(session, installation_ids=[OURS])

    assert stats.repositories == 1
    assert stats.audits == 1
    assert stats.units_analysed == 2
    assert stats.findings == 2
    assert stats.alerts == 1
    assert [row.cwe for row in stats.by_cwe] == ["CWE-89"]
    by_agent = {row.agent_id: row for row in stats.witnesses}
    # Two of each, not three: the third unit belongs to the other installation's audit.
    assert by_agent["structural.taint"].detections == 2
    assert by_agent["structural.taint"].silences == 0
    assert by_agent["semantic.hosted"].silences == 2
    assert by_agent["semantic.hosted"].detections == 0
    assert by_agent["runtime.sfi"].abstentions == 2
    assert by_agent["runtime.sfi"].detections == 0
