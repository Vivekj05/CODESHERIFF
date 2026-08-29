"""What the pull request comment says, and what it must never say.

No database and no GitHub, so these run in every suite. They are assertions about the *claim* the
comment makes, which is the thing this project is actually about — a tool that says "clean" when it
has not looked, or shows a number nothing has calibrated, has failed at its one job regardless of
whether the plumbing works.
"""

from __future__ import annotations

import uuid

from codesheriff_contracts import CONTRACT_VERSION, ChangeUnit, EvidenceKind
from codesheriff_engine.extraction import ExtractionResult, SkippedFile, SkipReason
from codesheriff_worker.comment import (
    ABSTENTION_REASON,
    PENDING_AGENTS,
    SKIP_WORDING,
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


# -- what the audit looked at (Chapter 8) -----------------------------------------------------


def extraction(units: int = 0, skipped: list[SkipReason] | None = None) -> ExtractionResult:
    return ExtractionResult(
        units=[
            ChangeUnit(
                unit_id=f"f{i}",
                repo="acme/payments-api",
                language="python",
                file="pkg/mod.py",
                symbol=f"f{i}",
                post_src="def f(): ...",
                base_sha="b" * 40,
                head_sha="h" * 40,
            )
            for i in range(units)
        ],
        skipped=[SkippedFile(path=f"f{i}.x", reason=r) for i, r in enumerate(skipped or [])],
    )


def test_the_comment_reports_how_many_functions_were_extracted() -> None:
    """ "We analysed 4 functions" and "we analysed nothing and said so quietly" have to be
    distinguishable by a reader in a hurry."""
    assert "Extracted **4** changed functions" in render(
        AUDIT_ID, pending_evidence(AUDIT_ID), DASHBOARD_URL, extraction(units=4)
    )


def test_a_single_function_is_not_reported_in_the_plural() -> None:
    assert "**1** changed function." in render(
        AUDIT_ID, pending_evidence(AUDIT_ID), DASHBOARD_URL, extraction(units=1)
    )


def test_skipped_files_are_counted_and_explained_in_words() -> None:
    """A cell reading `language_unsupported` asks a developer to learn this system's vocabulary
    to find out their TypeScript was not scanned."""
    body_text = render(
        AUDIT_ID,
        pending_evidence(AUDIT_ID),
        DASHBOARD_URL,
        extraction(units=1, skipped=[SkipReason.LANGUAGE_UNSUPPORTED] * 2),
    )

    assert "2 not Python" in body_text
    assert "language_unsupported" not in body_text


def test_no_file_path_ever_reaches_the_comment() -> None:
    """A path is chosen by whoever opened the pull request, so it is attacker-controlled text in
    exactly the way AUDIT.md 0.4 describes. Paths belong on the dashboard, behind escaping."""
    result = extraction(units=1)
    result.skipped.append(
        SkippedFile(path="x](javascript:alert(1)).ts", reason=SkipReason.LANGUAGE_UNSUPPORTED)
    )

    body_text = render(AUDIT_ID, pending_evidence(AUDIT_ID), DASHBOARD_URL, result)

    assert "javascript:" not in body_text
    assert "pkg/mod.py" not in body_text


def test_an_audit_that_extracted_nothing_says_so_rather_than_staying_silent() -> None:
    body_text = render(
        AUDIT_ID,
        pending_evidence(AUDIT_ID),
        DASHBOARD_URL,
        extraction(units=0, skipped=[SkipReason.FILE_REMOVED]),
    )

    assert "Extracted **0** changed functions" in body_text
    assert "1 deleted" in body_text


def test_every_skip_reason_has_words_for_it() -> None:
    """A reason added to the enum without a phrase here would raise a KeyError while rendering
    a comment, which is the worst place to find out."""
    assert set(SKIP_WORDING) == set(SkipReason)
