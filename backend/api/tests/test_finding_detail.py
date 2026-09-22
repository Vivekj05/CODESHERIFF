"""The finding page's route: one posterior, taken apart factor by factor.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

Chapter 15 built the audit page and left the number on it unexplained. What this route adds is the
arithmetic behind one finding, and the claims worth testing are the ones that keep that arithmetic
honest rather than merely present.

**Four witnesses, always.** The roster is fusion's, not the evidence's. A page assembled from the
agents that spoke would shorten to the ones that alerted, which is the D-007 defect rendered in
HTML instead of in a posterior.

**A ratio is read, never computed.** A finding written before migration 0004 has no breakdown, and
the response says so instead of reporting four factors of 1.0 — an unrecorded ratio and a neutral
witness are different claims, and only one of them was made by a run.

**Scope is the audit's.** `finding_key` is a digest of file, symbol and CWE, so two installations
analysing the same open-source function hold the same key. The audit is what disambiguates it, and
the installation filter rides on the audit.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from codesheriff_contracts import CONTRACT_VERSION, Artifact, ChangeUnit, Evidence
from codesheriff_engine.calibration import active_artifact
from codesheriff_engine.fusion.witnesses import WITNESSES
from codesheriff_storage.audits import calibration_run_for, open_audit
from codesheriff_storage.identity import upsert_installation, upsert_repository
from codesheriff_storage.mapping import to_change_unit_row, to_evidence_row
from codesheriff_storage.models import Audit, CalibrationRun, Finding

from .test_audits import OTHER_INSTALLATION, OTHER_REPO, OUR_REPO, sign_in

pytestmark = pytest.mark.db

CWE = "CWE-89"

TAINT_PATH = Artifact(
    artifact_type="taint_path",
    content={
        "length": 2,
        "sink_class": "sql",
        "rule_id": "py.sql.execute",
        "steps": [
            {"line": 10, "expr": "term", "var_name": "term", "role": "source"},
            {"line": 12, "expr": "db.execute(term)", "var_name": "", "role": "sink"},
        ],
    },
)

BREAKDOWN: list[dict[str, object]] = [
    {
        "witness": "structural",
        "stance": "detected",
        "cell": "detection_medium",
        "likelihood_ratio": 6.5,
        "agent_ids": ["structural.taint"],
        "note": "",
    },
    {
        "witness": "semantic",
        "stance": "silent",
        "cell": "silence",
        "likelihood_ratio": 0.62,
        "agent_ids": ["semantic.hosted"],
        "note": "",
    },
    {
        "witness": "context",
        "stance": "neutral",
        "cell": None,
        "likelihood_ratio": 1.0,
        "agent_ids": [],
        "note": "no statement from this witness",
    },
    {
        "witness": "runtime",
        "stance": "neutral",
        "cell": None,
        "likelihood_ratio": 1.0,
        "agent_ids": [],
        "note": "abstained: interpreter_unavailable",
    },
]


@pytest.fixture
def calibration(db: DbSession) -> CalibrationRun:
    return calibration_run_for(db, active_artifact())


def make_unit() -> ChangeUnit:
    return ChangeUnit(
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


def populate(
    db: DbSession,
    calibration: CalibrationRun,
    repo_id: int,
    *,
    contributions: list[dict[str, object]] | None,
) -> tuple[Audit, ChangeUnit]:
    """One audit, one unit carrying all three evidence kinds, and the finding they fused into."""
    audit = open_audit(
        db,
        repository_id=repo_id,
        pr_number=7,
        base_sha="b" * 40,
        head_sha=uuid.uuid4().hex[:40].ljust(40, "0"),
        contract_version=CONTRACT_VERSION,
        calibration_run=calibration,
    )
    db.flush()

    unit = make_unit()
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
                finding_key=unit.key_for(CWE),
                cwe=CWE,
                raw_score=0.72,
                explanation="`term` reaches `db.execute` with no sanitizer on the path.",
                artifacts=[TAINT_PATH],
            ),
            Evidence.silence(
                agent_id="semantic.hosted",
                agent_version="1.0.0",
                unit_id=unit.unit_id,
                covered_cwes={CWE, "CWE-79"},
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
            finding_key=unit.key_for(CWE),
            cwe=CWE,
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
            contributions=contributions,
        )
    )
    db.flush()
    return audit, unit


def url(audit: Audit, unit: ChangeUnit) -> str:
    return f"/audits/{audit.id}/findings/{unit.key_for(CWE)}"


def test_a_finding_needs_a_session(client: TestClient) -> None:
    """401, not an empty body. An empty body would read as "that finding is clean"."""
    response = client.get(f"/audits/{uuid.uuid4()}/findings/0123456789abcdef")
    assert response.status_code == 401


def test_the_breakdown_names_every_witness_including_the_quiet_ones(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    """Four rows in `WITNESSES` order, though only three backends said anything (D-007)."""
    sign_in(client)
    audit, unit = populate(db, calibration, OUR_REPO, contributions=BREAKDOWN)

    body = client.get(url(audit, unit)).json()

    assert body["contributions_recorded"] is True
    assert [item["witness"] for item in body["witnesses"]] == list(WITNESSES)
    context = next(item for item in body["witnesses"] if item["witness"] == "context")
    assert context["stance"] == "neutral"
    assert context["likelihood_ratio"] == 1.0
    assert context["statements"] == []


def test_the_ratios_are_the_ones_the_run_used(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    """Read from the stored breakdown, with the cell that produced each one.

    The cell is what lets a reader check a factor against `calibration.json` rather than take it
    on trust, which is the whole difference between a calibrated number and a confident one.
    """
    sign_in(client)
    audit, unit = populate(db, calibration, OUR_REPO, contributions=BREAKDOWN)

    body = client.get(url(audit, unit)).json()

    structural = next(item for item in body["witnesses"] if item["witness"] == "structural")
    assert structural["likelihood_ratio"] == 6.5
    assert structural["cell"] == "detection_medium"
    semantic = next(item for item in body["witnesses"] if item["witness"] == "semantic")
    assert semantic["cell"] == "silence"
    assert semantic["likelihood_ratio"] == 0.62
    assert body["finding"]["posterior_probability"] == 0.88
    assert body["finding"]["prior_probability"] == audit.prior_probability


def test_a_finding_with_no_recorded_breakdown_says_so(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    """No invented factors for a run that predates migration 0004.

    The statements are still grouped and served — what the agents said is on the record either
    way. What is missing is the arithmetic, and the flag is how a renderer knows not to draw it.
    """
    sign_in(client)
    audit, unit = populate(db, calibration, OUR_REPO, contributions=None)

    body = client.get(url(audit, unit)).json()

    assert body["contributions_recorded"] is False
    assert [item["witness"] for item in body["witnesses"]] == list(WITNESSES)
    assert {item["cell"] for item in body["witnesses"]} == {None}
    assert {item["stance"] for item in body["witnesses"]} == {""}
    structural = next(item for item in body["witnesses"] if item["witness"] == "structural")
    assert [row["agent_id"] for row in structural["statements"]] == ["structural.taint"]


def test_the_three_kinds_stay_distinguishable_under_their_witness(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    """A silence names what it could have found; an abstention names why it could not look."""
    sign_in(client)
    audit, unit = populate(db, calibration, OUR_REPO, contributions=BREAKDOWN)

    body = client.get(url(audit, unit)).json()
    by_witness = {item["witness"]: item for item in body["witnesses"]}

    silence = by_witness["semantic"]["statements"][0]
    assert silence["kind"] == "silence"
    assert sorted(silence["covered_cwes"]) == ["CWE-79", "CWE-89"]
    assert silence["reason"] is None

    abstention = by_witness["runtime"]["statements"][0]
    assert abstention["kind"] == "abstention"
    assert abstention["reason"] == "interpreter_unavailable"
    assert abstention["covered_cwes"] == []


def test_the_detection_carries_its_taint_path(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    """Artifacts reach this route, unlike the audit page's statements.

    The path is the structural witness showing its work. Without it the page asserts that a value
    flows to a sink and offers the reader no way to disagree.
    """
    sign_in(client)
    audit, unit = populate(db, calibration, OUR_REPO, contributions=BREAKDOWN)

    body = client.get(url(audit, unit)).json()

    structural = next(item for item in body["witnesses"] if item["witness"] == "structural")
    artifacts = structural["statements"][0]["artifacts"]
    assert [item["artifact_type"] for item in artifacts] == ["taint_path"]
    steps = artifacts[0]["content"]["steps"]
    assert [step["role"] for step in steps] == ["source", "sink"]


def test_the_unit_carries_no_second_copy_of_the_statements(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    """The statements live under the witness whose factor they justify, and only there.

    Two lists of the same rows is two lists a reader can find disagreeing with each other.
    """
    sign_in(client)
    audit, unit = populate(db, calibration, OUR_REPO, contributions=BREAKDOWN)

    body = client.get(url(audit, unit)).json()

    assert body["unit"]["qualified_symbol"] == unit.qualified_symbol
    assert body["unit"]["start_line"] == 10
    assert "evidence" not in body["unit"]
    assert "post_src" not in body["unit"]


def test_a_finding_on_another_installation_is_404(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    """404 rather than a redacted body.

    For the reason the audit routes give: telling "no such finding" apart from "not yours"
    confirms that a finding exists on a repository the caller cannot see.
    """
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
    sign_in(client)
    audit, unit = populate(db, calibration, OTHER_REPO, contributions=BREAKDOWN)

    assert client.get(url(audit, unit)).status_code == 404


def test_an_unknown_key_on_a_visible_audit_is_404(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    sign_in(client)
    audit, _unit = populate(db, calibration, OUR_REPO, contributions=BREAKDOWN)

    assert client.get(f"/audits/{audit.id}/findings/0123456789abcdef").status_code == 404


def test_the_stored_breakdown_survives_a_round_trip(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    """JSONB in, the same JSON out — the column adapts without a serialiser of its own."""
    sign_in(client)
    audit, unit = populate(db, calibration, OUR_REPO, contributions=BREAKDOWN)
    db.flush()
    db.expire_all()

    stored = db.execute(
        select(Finding).where(
            Finding.audit_id == audit.id, Finding.finding_key == unit.key_for(CWE)
        )
    ).scalar_one()

    assert stored.contributions == BREAKDOWN


def test_an_absent_breakdown_is_sql_null_not_the_json_scalar_null(
    client: TestClient, db: DbSession, calibration: CalibrationRun
) -> None:
    """Two states, not three.

    SQLAlchemy persists Python `None` into a JSONB column as the JSON scalar `null` unless the
    type declares `none_as_null=True`. That value reads back as `None` in Python while being NOT
    NULL in SQL — a third state wearing the second one's clothes, and one that would make "the
    breakdown was not recorded" true in the application and false in the database.
    """
    sign_in(client)
    audit, unit = populate(db, calibration, OUR_REPO, contributions=None)
    db.flush()

    is_sql_null = db.execute(
        select(Finding.contributions.is_(None)).where(
            Finding.audit_id == audit.id, Finding.finding_key == unit.key_for(CWE)
        )
    ).scalar_one()

    assert is_sql_null is True
