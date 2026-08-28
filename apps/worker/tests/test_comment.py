"""What the pull request comment says, and what it must never say.

No database and no GitHub, so these run in every suite. They are assertions about the *claim* the
comment makes, which is the thing this project is actually about — a tool that says "clean" when it
has not looked, or shows a number nothing has calibrated, has failed at its one job regardless of
whether the plumbing works.
"""

from __future__ import annotations

import uuid

from codesheriff_contracts import CONTRACT_VERSION, EvidenceKind
from codesheriff_worker.comment import (
    ABSTENTION_REASON,
    PENDING_AGENTS,
    marker_for,
    pending_evidence,
    render,
)

AUDIT_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
DASHBOARD_URL = "http://localhost:3000/audits/11111111-2222-3333-4444-555555555555"


def body() -> str:
    return render(AUDIT_ID, pending_evidence(AUDIT_ID), DASHBOARD_URL)


def test_every_backend_abstains_rather_than_reporting_nothing_found() -> None:
    """The distinction D-005 exists for. An agent that could not run is not evidence of safety."""
    evidence = pending_evidence(AUDIT_ID)

    assert len(evidence) == len(PENDING_AGENTS)
    assert all(item.kind is EvidenceKind.ABSTENTION for item in evidence)
    assert all(item.reason == ABSTENTION_REASON for item in evidence)


def test_abstentions_carry_no_finding_key() -> None:
    """D-019 enforces it in the contract; asserting it here is what catches a hand-built one."""
    assert all(item.finding_key is None for item in pending_evidence(AUDIT_ID))


def test_the_comment_never_says_the_code_is_clean() -> None:
    """AUDIT.md 4.4: the old orchestrator posted "No security vulnerabilities detected" when its
    agents had failed to load."""
    rendered = body().lower()

    assert "no security vulnerabilities detected" not in rendered
    assert "no vulnerabilities" not in rendered
    assert "no analysis has run" in rendered


def test_the_comment_carries_no_probability() -> None:
    """D-032. There is no fitted likelihood ratio and no selected threshold to derive one from."""
    rendered = body()

    assert "0.05" not in rendered
    assert "0.70" not in rendered
    # The label the old reporter used for a per-finding number. The word "posterior" does appear,
    # in the paragraph explaining what a calibrated one would mean — which is the opposite of
    # asserting one.
    assert "Probability" not in rendered


def test_the_comment_says_why_there_is_no_probability() -> None:
    """Silence about the absence would read as the tool having nothing to say."""
    assert "calibrated" in body().lower()


def test_every_backend_is_named() -> None:
    rendered = body()

    for agent_id, _, _ in PENDING_AGENTS:
        assert f"`{agent_id}`" in rendered


def test_the_comment_states_the_contract_version() -> None:
    """The comment is a record of what produced it, and the contract is half of that."""
    assert f"v{CONTRACT_VERSION}" in body()


def test_the_comment_carries_a_machine_readable_marker() -> None:
    """How this bot recognises its own comment when the row that recorded it is not available."""
    rendered = body()

    assert marker_for(AUDIT_ID) in rendered
    assert str(AUDIT_ID) in rendered
    # An HTML comment, so it is invisible in the rendered markdown.
    assert rendered.strip().endswith("-->")


def test_the_comment_links_to_the_audit() -> None:
    assert DASHBOARD_URL in body()


def test_the_table_has_one_row_per_backend() -> None:
    """Five rows for four agents: the static agent has two backends that emit separately."""
    rows = [line for line in body().splitlines() if line.startswith("| `")]

    assert len(rows) == len(PENDING_AGENTS) == 5
