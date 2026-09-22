"""The dashboard's read routes, driven through HTTP.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

`test_reporting.py` makes the claims about the queries. These make the claims about the edge: that
an unauthenticated caller gets 401 rather than a page, that an audit belonging to another
installation is 404 and not a redacted body, that the three evidence kinds survive serialisation
distinguishable from each other, and that a page cursor cannot be hand-built by the caller.
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session as DbSession

from codesheriff_contracts import CONTRACT_VERSION, ChangeUnit, Evidence
from codesheriff_engine.calibration import active_artifact
from codesheriff_storage.audits import calibration_run_for, open_audit
from codesheriff_storage.identity import upsert_installation, upsert_repository
from codesheriff_storage.mapping import to_change_unit_row, to_evidence_row
from codesheriff_storage.models import Audit, CalibrationRun, Finding

pytestmark = pytest.mark.db

# What `FakeGitHubGateway` grants the signed-in user.
OUR_REPO = 5001
# An installation the fake identity does not include, so nothing under it is ever visible.
OTHER_INSTALLATION = 9999
OTHER_REPO = 5999


def sign_in(client: TestClient) -> None:
    """Complete a whole OAuth sign-in, leaving the session cookie on the client."""
    response = client.get("/auth/login", params={"next": "/audits"})
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    callback = client.get("/auth/callback", params={"code": "good-code", "state": state})
    assert callback.status_code == 303, callback.text


@pytest.fixture
def calibration(db: DbSession) -> CalibrationRun:
    return calibration_run_for(db, active_artifact())


def make_audit(
    db: DbSession, calibration: CalibrationRun, repo_id: int, *, pr_number: int = 7
) -> Audit:
    audit = open_audit(
        db,
        repository_id=repo_id,
        pr_number=pr_number,
        base_sha="b" * 40,
        head_sha=uuid.uuid4().hex[:40].ljust(40, "0"),
        contract_version=CONTRACT_VERSION,
        calibration_run=calibration,
    )
    db.flush()
    return audit


def populate(db: DbSession, audit: Audit) -> ChangeUnit:
    """One unit carrying all three evidence kinds, plus the finding they fused into."""
    unit = ChangeUnit(
        unit_id="unit-1",
        repo="acme/payments-api",
        language="python",
        file="app/orders.py",
        symbol="search_orders",
        start_line=10,
        changed_lines=[12],
        post_src="def search_orders(term):\n    return db.execute(term)\n",
        base_sha="b" * 40,
        head_sha="h" * 40,
    )
    row = to_change_unit_row(audit.id, unit)
    db.add(row)
    db.flush()
    db.add_all(
        to_evidence_row(row.id, item)
        for item in (
            Evidence.detection(
                agent_id="structural.taint",
                agent_version="1.0.0",
                unit_id=unit.unit_id,
                finding_key=unit.key_for("CWE-89"),
                cwe="CWE-89",
                raw_score=0.72,
                explanation="`term` reaches `db.execute` with no sanitizer on the path.",
            ),
            Evidence.silence(
                agent_id="semantic.hosted",
                agent_version="1.0.0",
                unit_id=unit.unit_id,
                covered_cwes={"CWE-89", "CWE-79"},
            ),
            Evidence.abstention(
                agent_id="runtime.sfi",
                agent_version="1.0.0",
                unit_id=unit.unit_id,
                reason="interpreter_unavailable",
            ),
        )
    )
    db.add(
        Finding(
            audit_id=audit.id,
            finding_key=unit.key_for("CWE-89"),
            cwe="CWE-89",
            posterior_probability=0.88,
            is_alert_worthy=audit.alert_threshold <= 0.88,
            severity="high",
            prior_probability=audit.prior_probability,
            alert_threshold=audit.alert_threshold,
            calibration_run_id=audit.calibration_run_id,
            file=unit.file,
            qualified_symbol=unit.qualified_symbol,
            line_numbers=[12],
            title="SQL injection in search_orders",
        )
    )
    db.flush()
    return unit


def test_the_history_needs_a_session(client: TestClient) -> None:
    """401, not an empty list. An empty list would read as "you have no audits"."""
    assert client.get("/audits").status_code == 401
    assert client.get(f"/audits/{uuid.uuid4()}").status_code == 401
    assert client.get("/stats/overview").status_code == 401
    assert client.get("/calibration").status_code == 401


def test_the_history_lists_this_session_s_audits_with_their_counts(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    sign_in(client)
    audit = make_audit(db, calibration, OUR_REPO, pr_number=42)
    populate(db, audit)

    body: dict[str, Any] = client.get("/audits").json()

    assert body["next_cursor"] is None
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["pr_number"] == 42
    assert item["repository_full_name"] == "acme/payments-api"
    assert item["units"] == 1
    assert item["findings"] == 1
    assert item["top_posterior"] == pytest.approx(0.88)
    # Read from the row, never recomputed from today's artifact (§6).
    assert item["alert_threshold"] == pytest.approx(calibration.alert_threshold)


def test_an_audit_on_an_invisible_installation_is_404(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    """404 rather than 403: a 403 confirms the audit exists (D-035)."""
    sign_in(client)
    upsert_installation(
        db,
        installation_id=OTHER_INSTALLATION,
        account_login="rival",
        account_type="Organization",
    )
    upsert_repository(
        db,
        repo_id=OTHER_REPO,
        installation_id=OTHER_INSTALLATION,
        full_name="rival/secret-thing",
        default_branch="main",
        is_private=True,
    )
    db.flush()
    theirs = make_audit(db, calibration, OTHER_REPO)

    assert client.get("/audits").json()["items"] == []
    response = client.get(f"/audits/{theirs.id}")
    assert response.status_code == 404
    assert "rival" not in response.text


def test_the_detail_keeps_the_three_evidence_kinds_apart(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    """A silence names what it covered; an abstention names why it could not look (§5).

    Serialising both as "found nothing" is the collapse that makes the posterior unexplainable
    one layer up, and it would be invisible in a response that only carried `kind`.
    """
    sign_in(client)
    audit = make_audit(db, calibration, OUR_REPO)
    populate(db, audit)

    body = client.get(f"/audits/{audit.id}").json()

    assert body["unit_count"] == 1
    assert body["units_returned"] == 1
    statements = {item["agent_id"]: item for item in body["units"][0]["evidence"]}
    assert statements["structural.taint"]["kind"] == "detection"
    assert statements["structural.taint"]["cwe"] == "CWE-89"
    assert statements["semantic.hosted"]["kind"] == "silence"
    assert statements["semantic.hosted"]["covered_cwes"] == ["CWE-79", "CWE-89"]
    assert statements["semantic.hosted"]["reason"] is None
    assert statements["runtime.sfi"]["kind"] == "abstention"
    assert statements["runtime.sfi"]["reason"] == "interpreter_unavailable"
    assert statements["runtime.sfi"]["covered_cwes"] == []


def test_the_detail_reports_the_calibration_the_audit_actually_ran_under(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    sign_in(client)
    audit = make_audit(db, calibration, OUR_REPO)

    body = client.get(f"/audits/{audit.id}").json()

    assert body["calibration"]["is_provisional"] is False
    assert body["calibration"]["corpus_hash"] == calibration.corpus_hash
    assert body["prior_probability"] == pytest.approx(calibration.prior_probability)


def test_a_cursor_the_api_did_not_issue_is_rejected(client: TestClient) -> None:
    """400, not a silent restart from the top — that would repeat rows already scrolled past."""
    sign_in(client)
    assert client.get("/audits", params={"cursor": "not-a-cursor"}).status_code == 400
    assert client.get("/audits", params={"cursor": "MjAyNS0wMS0wMXxub3Bl"}).status_code == 400


def test_the_history_pages_and_the_cursor_round_trips(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    sign_in(client)
    for pr_number in range(3):
        make_audit(db, calibration, OUR_REPO, pr_number=pr_number)

    first = client.get("/audits", params={"limit": 2}).json()
    assert len(first["items"]) == 2
    assert first["next_cursor"]

    second = client.get("/audits", params={"limit": 2, "cursor": first["next_cursor"]}).json()

    seen = [item["id"] for item in (*first["items"], *second["items"])]
    assert len(set(seen)) == 3
    assert second["next_cursor"] is None


def test_the_overview_counts_only_what_this_session_may_see(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    sign_in(client)
    audit = make_audit(db, calibration, OUR_REPO)
    populate(db, audit)

    body = client.get("/stats/overview").json()

    assert body["repositories"] == 2
    assert body["audits"] == 1
    assert body["units_analysed"] == 1
    assert body["alerts"] == 1
    assert body["by_cwe"] == [{"cwe": "CWE-89", "findings": 1, "alerts": 1}]
    witnesses = {row["agent_id"]: row for row in body["witnesses"]}
    assert witnesses["semantic.hosted"]["silences"] == 1
    assert witnesses["runtime.sfi"]["abstentions"] == 1
