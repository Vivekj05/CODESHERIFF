"""What the pull request comment says, and what it must never say.

No database and no GitHub, so these run in every suite. They are assertions about the *claim* the
comment makes, which is the thing this project is actually about — a tool that says "clean" when it
has not looked, or shows a number nothing has calibrated, has failed at its one job regardless of
whether the plumbing works.

Chapter 9 changed what there is to say. The comment reported five hardcoded abstentions and no
number; it now reports what four witnesses said and the posterior that came out. The tests that
mattered did not change: no path, no unescaped prose, and no probability without its calibration
state.
"""

from __future__ import annotations

import uuid

from codesheriff_contracts import CONTRACT_VERSION, ChangeUnit, Evidence
from codesheriff_engine.extraction import ExtractionResult, SkippedFile, SkipReason
from codesheriff_engine.fusion import WitnessRatios, fuse_all_evidence
from codesheriff_patch import PatchProposal, ProposalOutcome
from codesheriff_worker.comment import (
    PATCH_WORDING,
    SKIP_WORDING,
    STANCE_WORDING,
    CalibrationFacts,
    marker_for,
    render,
)
from codesheriff_worker.patching import PatchRecord

AUDIT_ID = uuid.UUID("11111111-2222-3333-4444-555555555555")
DASHBOARD_URL = "http://localhost:3000/audits/11111111-2222-3333-4444-555555555555"

UNIT = ChangeUnit(
    unit_id="u1",
    repo="acme/payments-api",
    language="python",
    file="pkg/mod.py",
    symbol="charge",
    post_src="def charge(): ...",
    base_sha="b" * 40,
    head_sha="h" * 40,
)
SQLI_KEY = UNIT.key_for("CWE-89")


def detection(agent_id: str, score: float = 0.95, explanation: str = "taint path") -> Evidence:
    return Evidence.detection(
        agent_id=agent_id,
        agent_version="0.1.0",
        unit_id=UNIT.unit_id,
        finding_key=SQLI_KEY,
        cwe="CWE-89",
        raw_score=score,
        explanation=explanation,
    )


def abstention(agent_id: str, reason: str = "agent_unavailable") -> Evidence:
    return Evidence.abstention(
        agent_id=agent_id,
        agent_version="0.0.0",
        unit_id=UNIT.unit_id,
        reason=reason,
    )


ALL_ABSTAINED = [
    abstention("structural.taint"),
    abstention("semantic.hosted"),
    abstention("context.rag"),
    abstention("runtime.sfi"),
]


TABLE: dict[str, WitnessRatios] = {
    "structural": WitnessRatios(
        detection_high=8.5, detection_medium=3.2, detection_low=0.8, silence=0.60
    ),
    "semantic": WitnessRatios(
        detection_high=12.0, detection_medium=4.5, detection_low=0.5, silence=0.50
    ),
    "context": WitnessRatios(
        detection_high=4.2, detection_medium=2.1, detection_low=0.9, silence=0.85
    ),
    "runtime": WitnessRatios(
        detection_high=15.0, detection_medium=5.0, detection_low=0.7, silence=0.40
    ),
}
"""A fixture table. These tests are about what the comment says, not about what the fit
produced, and a rendering test that moved with every re-fit would be measuring the wrong
thing."""

FITTED = CalibrationFacts(
    corpus_hash="1ea6d1cdbf24" + "0" * 52,
    split_hash="e5bf1bb56bde" + "0" * 52,
    base_rate=0.03,
    alert_threshold=0.23,
    is_provisional=False,
    ece=0.03,
    brier=0.01,
)
"""A fitted run, as the audit row records it.

Values rather than the live artifact: the comment renders what its audit ran under, and a
test that read `calibration.json` would change its expectations every time anything is
re-fitted while testing nothing about the rendering.
"""


def body(
    evidence: list[Evidence] | None = None,
    extraction: ExtractionResult | None = None,
    calibration: CalibrationFacts | None = FITTED,
    patches: list[PatchRecord] | None = None,
) -> str:

    statements = ALL_ABSTAINED if evidence is None else evidence
    return render(
        AUDIT_ID,
        statements,
        fuse_all_evidence(statements, prior_p=0.05, alert_threshold=0.70, ratios=TABLE),
        DASHBOARD_URL,
        extraction,
        prior_probability=0.05,
        alert_threshold=0.70,
        calibration=calibration,
        patches=patches,
    )


def patch_record(
    outcome: ProposalOutcome,
    published: bool = False,
    publish_error: str = "",
) -> PatchRecord:
    return PatchRecord(
        finding_id=uuid.uuid4(),
        proposal=PatchProposal(
            finding_key=SQLI_KEY,
            unit_id=UNIT.unit_id,
            cwe="CWE-89",
            outcome=outcome,
            detail="…",
        ),
        published=published,
        publish_error=publish_error,
    )


# -- the claim ---------------------------------------------------------------------------------


def test_the_comment_never_says_the_code_is_clean() -> None:
    """AUDIT.md 4.4: the old orchestrator posted "No security vulnerabilities detected" when its
    agents had failed to load. Here every agent has abstained, which is that exact situation."""
    rendered = body().lower()

    assert "no security vulnerabilities detected" not in rendered
    assert "no vulnerabilities" not in rendered
    assert "no finding" in rendered


def test_a_finding_never_appears_without_its_calibration_state() -> None:
    """D-032, and the one assertion in this file that must never be relaxed.

    The state used to be "provisional" on every render because nothing was fitted. It is now
    whichever state the audit actually ran in, and both readings are asserted — a comment that
    could only say one of them would be a banner rather than a statement.
    """
    fitted = body([detection("structural.taint")])
    assert "%" in fitted, "sanity: this render does contain a probability"
    assert "Calibrated" in fitted
    assert "1ea6d1cdbf24" in fitted, "the corpus the ratios were fitted on is named"
    assert "base rate of 3.0%" in fitted, "a posterior without its base rate cannot be read"

    unfitted = body([detection("structural.taint")], calibration=None)
    assert "Uncalibrated run" in unfitted
    assert "rather than measured against ground truth" in unfitted


def test_a_quiet_audit_carries_no_probability_at_all() -> None:
    """Nothing was detected, so there is no posterior to state — not a reassuring one either."""
    rendered = body()

    assert "P(vulnerable)" not in rendered
    assert "result rather than an absence of one" in rendered


def test_the_comment_explains_what_the_number_is_not() -> None:
    """A probability, not a proof — and the footer says which."""
    rendered = body([detection("structural.taint")])
    assert "held-out calibration split" in rendered
    assert "What it is not is a proof" in rendered


# -- the witness table -------------------------------------------------------------------------


def test_every_witness_gets_a_row_including_the_ones_that_said_nothing() -> None:
    """D-007 made visible: a reader can count four factors and see the abstentions at 1.0."""
    rendered = body([detection("structural.taint")])
    rows = [line for line in rendered.splitlines() if line.startswith("| **")]

    assert len(rows) == 4
    assert [row.split("**")[1] for row in rows] == ["structural", "semantic", "context", "runtime"]
    assert rendered.count("x1.00") == 3


def test_silence_and_abstention_render_differently() -> None:
    """The distinction D-005 exists for, at the only place a developer will ever see it."""
    silence = Evidence.silence(
        agent_id="semantic.hosted",
        agent_version="0.1.0",
        unit_id=UNIT.unit_id,
        covered_cwes={"CWE-89"},
    )
    rendered = body([detection("structural.taint"), silence, abstention("context.rag")])

    assert "looked, found nothing" in rendered
    assert "no statement" in rendered
    assert "Could not run" in rendered


def test_a_silence_is_shown_pulling_the_number_down() -> None:
    """The witness table has to explain the number, and a ratio below 1.0 is how it does."""
    silence = Evidence.silence(
        agent_id="semantic.hosted",
        agent_version="0.1.0",
        unit_id=UNIT.unit_id,
        covered_cwes={"CWE-89"},
    )
    rendered = body([detection("structural.taint"), silence])
    row = next(line for line in rendered.splitlines() if line.startswith("| **semantic**"))

    ratio = float(row.split("x")[1].split(" ")[0].strip("| "))
    assert ratio < 1.0


def test_every_stance_has_words_for_it() -> None:
    """A stance added to the enum without a phrase here would raise a KeyError while rendering a
    comment, which is the worst place to find out."""
    from codesheriff_engine.fusion import Stance

    assert set(STANCE_WORDING) == set(Stance)


# -- what must never reach the comment ---------------------------------------------------------


def test_no_agent_prose_reaches_the_comment() -> None:
    """AUDIT.md 0.4: there is no rationale screening yet, and the semantic agent's explanation
    is LLM output shaped by attacker-controlled source. Rationales land here screened, Ch 11."""
    rendered = body(
        [detection("structural.taint", explanation="x](javascript:alert(1)) | injected | row")]
    )

    assert "javascript:" not in rendered
    assert "injected" not in rendered


def test_no_file_path_ever_reaches_the_comment() -> None:
    """A path is chosen by whoever opened the pull request, so it is attacker-controlled text in
    exactly the way AUDIT.md 0.4 describes. Paths belong on the dashboard, behind escaping."""
    result = extraction(units=1)
    result.skipped.append(
        SkippedFile(path="x](javascript:alert(1)).ts", reason=SkipReason.LANGUAGE_UNSUPPORTED)
    )

    rendered = body([detection("structural.taint")], result)

    assert "javascript:" not in rendered
    assert "pkg/mod.py" not in rendered


def test_no_symbol_name_reaches_the_comment() -> None:
    """The same argument as D-050: a function name is chosen by the pull request author too."""
    assert "charge" not in body([detection("structural.taint")])


# -- provenance --------------------------------------------------------------------------------


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


def test_the_comment_reports_what_the_agents_did() -> None:
    rendered = body([detection("structural.taint"), *ALL_ABSTAINED[1:]])

    assert "1 detection(s)" in rendered
    assert "3 abstention(s)" in rendered


# -- what the audit looked at (Chapter 8) ------------------------------------------------------


def extraction(units: int = 0, skipped: list[SkipReason] | None = None) -> ExtractionResult:
    return ExtractionResult(
        units=[UNIT.model_copy(update={"unit_id": f"f{i}"}) for i in range(units)],
        skipped=[SkippedFile(path=f"f{i}.x", reason=r) for i, r in enumerate(skipped or [])],
    )


def test_the_comment_reports_how_many_functions_were_extracted() -> None:
    """ "We analysed 4 functions" and "we analysed nothing and said so quietly" have to be
    distinguishable by a reader in a hurry."""
    assert "Extracted **4** changed functions" in body(None, extraction(units=4))


def test_a_single_function_is_not_reported_in_the_plural() -> None:
    assert "**1** changed function." in body(None, extraction(units=1))


def test_skipped_files_are_counted_and_explained_in_words() -> None:
    """A cell reading `language_unsupported` asks a developer to learn this system's vocabulary
    to find out their TypeScript was not scanned."""
    rendered = body(None, extraction(units=1, skipped=[SkipReason.LANGUAGE_UNSUPPORTED] * 2))

    assert "2 not Python" in rendered
    assert "language_unsupported" not in rendered


def test_an_audit_that_extracted_nothing_says_so_rather_than_staying_silent() -> None:
    rendered = body(None, extraction(units=0, skipped=[SkipReason.FILE_REMOVED]))

    assert "Extracted **0** changed functions" in rendered
    assert "1 deleted" in rendered


def test_every_skip_reason_has_words_for_it() -> None:
    """A reason added to the enum without a phrase here would raise a KeyError while rendering
    a comment, which is the worst place to find out."""
    assert set(SKIP_WORDING) == set(SkipReason)


# -- suggested repairs (Chapter 17) --------------------------------------------------------------


def test_a_posted_suggestion_is_reported_without_naming_a_file() -> None:
    """D-050 again. The suggestion carries its own location; the summary carries a count."""
    rendered = body(
        [detection("structural.taint")],
        patches=[patch_record(ProposalOutcome.VERIFIED, published=True)],
    )

    assert "Suggested repairs" in rendered
    assert "1" in rendered and "posted as review comment" in rendered
    assert "pkg/mod.py" not in rendered
    assert "charge" not in rendered


def test_a_finding_with_no_repair_says_why_rather_than_saying_nothing() -> None:
    """Nine outcomes, none collapsed. A reader deciding whether to expect a fix has to be able to
    tell "we did not try" from "we tried three times and rejected every result"."""
    rendered = body(
        [detection("structural.taint")],
        patches=[patch_record(ProposalOutcome.UNVERIFIED)],
    )

    assert PATCH_WORDING[ProposalOutcome.UNVERIFIED] in rendered
    assert "posted as review comment" not in rendered


def test_the_comment_never_claims_the_repository_s_tests_were_run() -> None:
    """§7 open question 3, answered where the developer reads it (D-094)."""
    rendered = body(
        [detection("structural.taint")],
        patches=[patch_record(ProposalOutcome.VERIFIED, published=True)],
    )

    assert "does not run this repository's test suite" in rendered


def test_a_suggestion_github_refused_is_reported_as_this_system_failing() -> None:
    rendered = body(
        [detection("structural.taint")],
        patches=[patch_record(ProposalOutcome.VERIFIED, publish_error="HTTP 422")],
    )

    assert "could not be posted to GitHub" in rendered
    assert "HTTP 422" not in rendered, "GitHub's own error text is for the log, not the reader"


def test_findings_below_the_threshold_are_counted_rather_than_itemised() -> None:
    rendered = body(
        [detection("structural.taint")],
        patches=[patch_record(ProposalOutcome.NOT_ALERT_WORTHY) for _ in range(9)],
    )

    assert "No repair was requested" in rendered
    assert rendered.count("below the alert threshold") == 1


def test_an_audit_with_no_patch_records_renders_no_repair_section() -> None:
    assert "Suggested repairs" not in body([detection("structural.taint")])


def test_every_patcher_outcome_has_words_for_it() -> None:
    """A new outcome with no wording would render as a KeyError at the end of a real audit."""
    assert set(PATCH_WORDING) == set(ProposalOutcome)
