"""`patch_proposals`, against a real database.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

Two claims here need a real Postgres and cannot be asserted anywhere else. The **CHECK constraints
are the last wall** between this table and a row that lies — a published suggestion with no digest
identifying it, a comment id on a proposal that was never posted, an empty `checks` array standing
in for "no ladder was run". And the **repaired source must never reach a column**: the mapping
hashes it, and the way to prove that is to write a proposal carrying a distinctive patch and then
grep the whole row for it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from codesheriff_contracts import CONTRACT_VERSION
from codesheriff_engine.calibration import active_artifact
from codesheriff_patch import (
    CheckResult,
    CheckStatus,
    LineReplacement,
    PatchProposal,
    ProposalOutcome,
    Verification,
)
from codesheriff_storage.audits import calibration_run_for, open_audit
from codesheriff_storage.identity import upsert_installation, upsert_repository
from codesheriff_storage.mapping import to_patch_proposal_row
from codesheriff_storage.models import CalibrationRun, Finding, PatchProposalRow

pytestmark = pytest.mark.db

INSTALLATION = 9101
REPO = 5101

PATCH_SOURCE = "    def lookup(self, user_id):\n        return DISTINCTIVE_REPAIRED_MARKER\n"


@pytest.fixture
def calibration(session: DbSession) -> CalibrationRun:
    return calibration_run_for(session, active_artifact())


@pytest.fixture
def finding(session: DbSession, calibration: CalibrationRun) -> Finding:
    upsert_installation(
        session,
        installation_id=INSTALLATION,
        account_login="acme",
        account_type="Organization",
    )
    upsert_repository(
        session,
        repo_id=REPO,
        installation_id=INSTALLATION,
        full_name="acme/payments-api",
        default_branch="main",
        is_private=True,
    )
    audit = open_audit(
        session,
        repository_id=REPO,
        pr_number=11,
        base_sha="b" * 40,
        head_sha="h" * 40,
        contract_version=CONTRACT_VERSION,
        calibration_run=calibration,
    )
    session.flush()

    row = Finding(
        audit_id=audit.id,
        finding_key="a" * 16,
        cwe="CWE-89",
        posterior_probability=0.91,
        is_alert_worthy=True,
        prior_probability=0.03,
        alert_threshold=0.7,
    )
    session.add(row)
    session.flush()
    return row


def a_proposal(
    outcome: ProposalOutcome = ProposalOutcome.VERIFIED,
    patched_src: str | None = PATCH_SOURCE,
) -> PatchProposal:
    return PatchProposal(
        finding_key="a" * 16,
        unit_id="app/db.py::Users.lookup",
        cwe="CWE-89",
        outcome=outcome,
        detail="verified across 6 check(s)",
        drafts_requested=2,
        verification=Verification(
            results=(
                CheckResult("parses", CheckStatus.PASSED, "parses as valid Python"),
                CheckResult("regression:runtime", CheckStatus.NOT_RUN, "no interpreter"),
            )
        ),
        replacement=LineReplacement(start_index=1, end_index=1, lines=("    x",)),
        patched_src=patched_src,
    )


class TestWhatIsStored:
    def test_the_repaired_source_is_hashed_and_never_written(
        self, session: DbSession, finding: Finding
    ) -> None:
        """§6, D-097. A patch is somebody else's source with our edit in it."""
        session.add(
            to_patch_proposal_row(finding.id, a_proposal(), published=True, github_comment_id=4242)
        )
        session.flush()

        row = session.execute(text("SELECT * FROM patch_proposals")).mappings().one()
        assert "DISTINCTIVE_REPAIRED_MARKER" not in str(dict(row))
        assert row["patch_sha256"] is not None and len(row["patch_sha256"]) == 64

    def test_the_ladder_is_stored_with_its_three_states_intact(
        self, session: DbSession, finding: Finding
    ) -> None:
        session.add(to_patch_proposal_row(finding.id, a_proposal()))
        session.flush()
        stored = session.execute(select(PatchProposalRow)).scalar_one()
        assert stored.checks is not None
        assert [c["status"] for c in stored.checks] == ["passed", "not_run"]

    def test_a_proposal_that_never_reached_verification_stores_no_ladder(
        self, session: DbSession, finding: Finding
    ) -> None:
        """NULL means "no ladder was run", which an empty array would misreport (D-090's rule)."""
        proposal = PatchProposal(
            finding_key="a" * 16,
            unit_id="u",
            cwe="CWE-89",
            outcome=ProposalOutcome.PATCHER_UNAVAILABLE,
            detail="no model is configured",
        )
        session.add(to_patch_proposal_row(finding.id, proposal))
        session.flush()

        stored = session.execute(select(PatchProposalRow)).scalar_one()
        assert stored.checks is None
        assert stored.patch_sha256 is None
        assert (
            session.execute(text("SELECT checks IS NULL FROM patch_proposals")).scalar_one() is True
        ), "SQL NULL, not the JSON scalar null — none_as_null must stay on"


class TestTheConstraints:
    def test_a_published_row_must_carry_a_patch(self, session: DbSession, finding: Finding) -> None:
        row = to_patch_proposal_row(finding.id, a_proposal(patched_src=None), published=True)
        session.add(row)
        with pytest.raises(IntegrityError, match="published_has_a_patch"):
            session.flush()

    def test_a_comment_id_implies_the_suggestion_was_published(
        self, session: DbSession, finding: Finding
    ) -> None:
        row = to_patch_proposal_row(finding.id, a_proposal(), published=False)
        row.github_comment_id = 99
        session.add(row)
        with pytest.raises(IntegrityError, match="comment_implies_published"):
            session.flush()

    def test_an_empty_ladder_is_rejected(self, session: DbSession, finding: Finding) -> None:
        row = to_patch_proposal_row(finding.id, a_proposal())
        row.checks = []
        session.add(row)
        with pytest.raises(IntegrityError, match="checks_shape"):
            session.flush()

    def test_one_proposal_per_finding(self, session: DbSession, finding: Finding) -> None:
        session.add(to_patch_proposal_row(finding.id, a_proposal()))
        session.flush()
        session.add(to_patch_proposal_row(finding.id, a_proposal()))
        with pytest.raises(IntegrityError, match="uq_patch_proposals_finding"):
            session.flush()

    def test_deleting_the_finding_takes_its_proposal_with_it(
        self, session: DbSession, finding: Finding
    ) -> None:
        session.add(to_patch_proposal_row(finding.id, a_proposal()))
        session.flush()
        session.execute(text("DELETE FROM findings WHERE id = :id"), {"id": str(finding.id)})
        session.flush()
        assert session.execute(select(PatchProposalRow)).scalars().all() == []


def test_every_outcome_the_patcher_can_produce_is_insertable(
    session: DbSession, finding: Finding
) -> None:
    """The mirror test asserts the two enums name the same values; this asserts Postgres agrees.

    A value present in Python and absent from the database type fails at the end of an audit, which
    is the worst possible place to discover a missing migration.
    """
    for index, outcome in enumerate(ProposalOutcome):
        row = Finding(
            audit_id=finding.audit_id,
            finding_key=f"{index:016x}",
            cwe="CWE-89",
            posterior_probability=0.9,
            is_alert_worthy=True,
            prior_probability=0.03,
            alert_threshold=0.7,
        )
        session.add(row)
        session.flush()
        session.add(
            PatchProposalRow(
                id=uuid.uuid4(),
                finding_id=row.id,
                outcome=outcome.value,
                detail="",
            )
        )
        session.flush()
