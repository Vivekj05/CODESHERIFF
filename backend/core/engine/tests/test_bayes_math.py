"""The fusion arithmetic, and the seven defects it was rebuilt to fix.

Each test below names the `AUDIT.md` finding or decision it holds down, and is written
against observable behaviour wherever possible, so that a refit can replace every number in
`calibration.json` without rewriting the properties that must survive it.

**The ratios used here are a fixture, not the fitted ones.** These tests are about the
arithmetic — that four factors are multiplied, that a silence can lower a posterior, that two
backends behind one witness do not compound — and every one of those properties has to hold
whatever the fit produced. Asserting them against the live artifact would make an ordinary
re-fit look like an arithmetic regression, and would quietly stop testing the property the day
some fitted ratio happened to be 1.0.
"""

import math

import pytest

from codesheriff_contracts import ChangeUnit, Evidence
from codesheriff_engine.fusion import (
    WITNESSES,
    UnknownAgentError,
    compute_bayesian_fusion,
    fuse_all_evidence,
)
from codesheriff_engine.fusion.bayes import Stance
from codesheriff_engine.fusion.ratios import LR_MAX, LR_MIN, WitnessRatios

PRIOR = 0.05

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
"""A complete, ordered, deliberately unremarkable table. Every witness has a row, because
fusion refuses a partial one (D-082), and every value differs from its neighbours so that a
factor applied to the wrong witness shows up as a wrong number rather than a coincidence."""


def posterior_from(prior: float, *ratios: float) -> float:
    """The odds update, written out independently of the implementation."""
    odds = prior / (1.0 - prior)
    for ratio in ratios:
        odds *= ratio
    return odds / (1.0 + odds)


def detection(agent_id: str, key: str, score: float, cwe: str = "CWE-89") -> Evidence:
    return Evidence.detection(
        agent_id=agent_id,
        agent_version="0.1.0",
        unit_id="unit-1",
        finding_key=key,
        cwe=cwe,
        raw_score=score,
        explanation=f"{agent_id} says {cwe}",
    )


def silence(agent_id: str, covered: set[str]) -> Evidence:
    return Evidence.silence(
        agent_id=agent_id,
        agent_version="0.1.0",
        unit_id="unit-1",
        covered_cwes=covered,
    )


def abstention(agent_id: str, reason: str = "tool_unavailable") -> Evidence:
    return Evidence.abstention(
        agent_id=agent_id,
        agent_version="0.1.0",
        unit_id="unit-1",
        reason=reason,
    )


# --------------------------------------------------------------------------
# AUDIT.md 1.4 / D-007 — every witness gets a turn
# --------------------------------------------------------------------------


def test_every_witness_contributes_exactly_one_factor(sample_vulnerable_unit: ChangeUnit) -> None:
    """Four factors, always four, however many agents actually spoke."""
    key = sample_vulnerable_unit.key_for("CWE-89")
    result = compute_bayesian_fusion(
        key, [detection("structural.taint", key, 0.95)], PRIOR, ratios=TABLE
    )

    assert [c.witness for c in result.contributions] == list(WITNESSES)
    assert len(result.contributions) == 4, (
        "the factor count is the witness count, not the alert count"
    )


def test_a_lone_detection_leaves_the_three_silent_witnesses_at_one(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """The three that said nothing contribute the identity, and say why."""
    key = sample_vulnerable_unit.key_for("CWE-89")
    result = compute_bayesian_fusion(
        key, [detection("structural.taint", key, 0.95)], PRIOR, ratios=TABLE
    )

    quiet = [c for c in result.contributions if c.witness != "structural"]
    assert all(c.likelihood_ratio == 1.0 for c in quiet)
    assert all(c.stance is Stance.NEUTRAL for c in quiet)
    assert all("Emitted no statement" in c.note for c in quiet)

    expected = posterior_from(PRIOR, TABLE["structural"].detection_high)
    assert result.posterior_probability == pytest.approx(round(expected, 4))


def test_silence_can_lower_a_posterior(sample_vulnerable_unit: ChangeUnit) -> None:
    """The property AUDIT.md 1.4 says the old engine could not express.

    Under the superseded engine this was arithmetically impossible: only agents that had
    alerted were iterated, so every factor exceeded 1.0 and the number could only rise.
    """
    key = sample_vulnerable_unit.key_for("CWE-89")
    alone = compute_bayesian_fusion(
        key, [detection("structural.taint", key, 0.95)], PRIOR, ratios=TABLE
    )
    disputed = compute_bayesian_fusion(
        key,
        [
            detection("structural.taint", key, 0.95),
            silence("semantic.hosted", {"CWE-89", "CWE-78"}),
        ],
        PRIOR,
        ratios=TABLE,
    )

    assert disputed.posterior_probability < alone.posterior_probability
    semantic = next(c for c in disputed.contributions if c.witness == "semantic")
    assert semantic.stance is Stance.SILENT
    assert semantic.likelihood_ratio < 1.0


def test_adding_a_witness_is_not_monotonically_increasing(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """Stated as the general property, not as one example of it."""
    key = sample_vulnerable_unit.key_for("CWE-89")
    base = [detection("structural.taint", key, 0.95)]

    with_more_evidence = [
        compute_bayesian_fusion(key, [*base, extra], PRIOR, ratios=TABLE).posterior_probability
        for extra in (
            silence("semantic.hosted", {"CWE-89"}),
            silence("context.rag", {"CWE-89"}),
            abstention("runtime.sfi", "no_safe_entrypoint"),
        )
    ]
    alone = compute_bayesian_fusion(key, base, PRIOR, ratios=TABLE).posterior_probability
    assert min(with_more_evidence) < alone


# --------------------------------------------------------------------------
# D-005 / D-006 — three kinds, and silence gated by coverage
# --------------------------------------------------------------------------


def test_abstention_is_exactly_one_and_not_a_configurable_number(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """An agent that could not look must not vote the code either way."""
    key = sample_vulnerable_unit.key_for("CWE-89")
    without = compute_bayesian_fusion(
        key, [detection("structural.taint", key, 0.95)], PRIOR, ratios=TABLE
    )
    with_abstentions = compute_bayesian_fusion(
        key,
        [
            detection("structural.taint", key, 0.95),
            abstention("semantic.hosted", "api_key_missing"),
            abstention("context.rag", "embedding_backend_unavailable"),
            abstention("runtime.sfi", "no_safe_entrypoint"),
        ],
        PRIOR,
        ratios=TABLE,
    )

    assert with_abstentions.posterior_probability == without.posterior_probability
    for witness in ("semantic", "context", "runtime"):
        contribution = next(c for c in with_abstentions.contributions if c.witness == witness)
        assert contribution.likelihood_ratio == 1.0
        assert "Could not run" in contribution.note


def test_silence_about_other_cwes_does_not_suppress_this_finding(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """D-006, stated as the bug it prevents.

    The taint engine holds no CWE-862 rules. If its silence counted against every CWE
    rather than the ones it covers, it would systematically suppress every authorisation
    finding — which only the semantic agent can see, and which is the entire reason the
    corpus contains authz twins with no static path.
    """
    key = sample_vulnerable_unit.key_for("CWE-862")
    findings = [detection("semantic.hosted", key, 0.9, cwe="CWE-862")]

    alone = compute_bayesian_fusion(key, findings, PRIOR, ratios=TABLE)
    with_taint_silence = compute_bayesian_fusion(
        key,
        [*findings, silence("structural.taint", {"CWE-89", "CWE-78", "CWE-22"})],
        PRIOR,
        ratios=TABLE,
    )

    assert with_taint_silence.posterior_probability == alone.posterior_probability
    structural = next(c for c in with_taint_silence.contributions if c.witness == "structural")
    assert structural.stance is Stance.NEUTRAL
    assert structural.likelihood_ratio == 1.0
    assert "holds no rules for CWE-862" in structural.note


def test_covering_silence_and_non_covering_silence_differ(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """The same agent, the same kind of statement, two different factors."""
    key = sample_vulnerable_unit.key_for("CWE-89")
    base = [detection("semantic.hosted", key, 0.9)]

    covering = compute_bayesian_fusion(
        key, [*base, silence("structural.taint", {"CWE-89"})], PRIOR, ratios=TABLE
    )
    not_covering = compute_bayesian_fusion(
        key, [*base, silence("structural.taint", {"CWE-22"})], PRIOR, ratios=TABLE
    )
    assert covering.posterior_probability < not_covering.posterior_probability


# --------------------------------------------------------------------------
# AUDIT.md 2.4 / D-011 — the static agent is one witness
# --------------------------------------------------------------------------


def test_two_structural_backends_contribute_one_factor(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """The 59.5x regression, stated as a test.

    `structural.taint` at 8.5 and `structural.semgrep` at 7.0 previously multiplied to
    59.5 out of what is one rule-based analysis of one source text.
    """
    key = sample_vulnerable_unit.key_for("CWE-89")
    result = compute_bayesian_fusion(
        key,
        [
            detection("structural.taint", key, 0.95),
            detection("structural.semgrep", key, 0.95),
        ],
        PRIOR,
        ratios=TABLE,
    )

    structural = [c for c in result.contributions if c.witness == "structural"]
    assert len(structural) == 1
    assert structural[0].agent_ids == ["structural.semgrep", "structural.taint"]

    high = TABLE["structural"].detection_high
    assert structural[0].likelihood_ratio == high
    assert result.posterior_probability == pytest.approx(round(posterior_from(PRIOR, high), 4))

    # And explicitly: not the product.
    assert result.posterior_probability < posterior_from(PRIOR, high * high)


def test_backends_combine_by_max_not_by_product(sample_vulnerable_unit: ChangeUnit) -> None:
    """D-011's provisional rule: the witness's strongest claim is its statement."""
    key = sample_vulnerable_unit.key_for("CWE-89")
    ratios = TABLE["structural"]

    result = compute_bayesian_fusion(
        key,
        [
            detection("structural.taint", key, 0.95),  # high
            detection("structural.semgrep", key, 0.60),  # medium
        ],
        PRIOR,
        ratios=TABLE,
    )
    structural = next(c for c in result.contributions if c.witness == "structural")
    assert structural.likelihood_ratio == max(ratios.detection_high, ratios.detection_medium)


def test_one_backends_silence_does_not_retract_its_siblings_detection(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """One witness, one statement — and a detection is the statement it made."""
    key = sample_vulnerable_unit.key_for("CWE-89")
    result = compute_bayesian_fusion(
        key,
        [
            detection("structural.taint", key, 0.95),
            silence("structural.semgrep", {"CWE-89"}),
        ],
        PRIOR,
        ratios=TABLE,
    )
    structural = next(c for c in result.contributions if c.witness == "structural")
    assert structural.stance is Stance.DETECTED
    assert structural.likelihood_ratio == TABLE["structural"].detection_high


def test_two_silences_from_one_witness_do_not_square(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    key = sample_vulnerable_unit.key_for("CWE-89")
    result = compute_bayesian_fusion(
        key,
        [
            detection("semantic.hosted", key, 0.9),
            silence("structural.taint", {"CWE-89"}),
            silence("structural.semgrep", {"CWE-89"}),
        ],
        PRIOR,
        ratios=TABLE,
    )
    structural = next(c for c in result.contributions if c.witness == "structural")
    assert structural.likelihood_ratio == TABLE["structural"].silence


# --------------------------------------------------------------------------
# AUDIT.md 2.7 — the ratios are clamped, the posterior is not
# --------------------------------------------------------------------------


def test_likelihood_ratios_are_clamped(sample_vulnerable_unit: ChangeUnit) -> None:
    key = sample_vulnerable_unit.key_for("CWE-89")
    absurd = {
        **TABLE,
        "structural": WitnessRatios(
            detection_high=10_000.0, detection_medium=1.0, detection_low=1.0, silence=0.9
        ),
    }
    result = compute_bayesian_fusion(
        key, [detection("structural.taint", key, 0.95)], PRIOR, ratios=absurd
    )
    structural = next(c for c in result.contributions if c.witness == "structural")
    assert structural.likelihood_ratio == LR_MAX


def test_the_posterior_is_never_clamped_into_a_flat_ceiling(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """The old engine pinned everything strong to 0.9999, hiding an unbounded product.

    With bounded ratios the posterior stays strictly inside (0, 1) on its own, and two
    genuinely different pieces of evidence still produce two different numbers.
    """
    key = sample_vulnerable_unit.key_for("CWE-89")
    three = compute_bayesian_fusion(
        key,
        [
            detection("structural.taint", key, 0.95),
            detection("semantic.hosted", key, 0.95),
            detection("context.rag", key, 0.95),
        ],
        PRIOR,
        ratios=TABLE,
    )
    four = compute_bayesian_fusion(
        key,
        [
            detection("structural.taint", key, 0.95),
            detection("semantic.hosted", key, 0.95),
            detection("context.rag", key, 0.95),
            detection("runtime.sfi", key, 0.95),
        ],
        PRIOR,
        ratios=TABLE,
    )
    assert 0.0 < three.posterior_probability < four.posterior_probability < 1.0


def test_the_ratio_bounds_are_the_right_way_round() -> None:
    assert 0.0 < LR_MIN < 1.0 < LR_MAX
    assert math.isfinite(LR_MAX)


# --------------------------------------------------------------------------
# AUDIT.md 1.1 — no synthetic keys, and no fifth witness
# --------------------------------------------------------------------------


def test_a_unit_nobody_detected_anything_in_produces_no_finding() -> None:
    """The `abstention:all_agents` marker is gone at source.

    It was a raw string in the key space `contracts.finding_key()` owns, and
    `codesheriff_storage` had to grow a wall against it. What a quiet unit produces is
    evidence, which the worker persists; a finding is something an agent found.
    """
    results = fuse_all_evidence(
        [
            silence("structural.taint", {"CWE-89", "CWE-78"}),
            silence("semantic.hosted", {"CWE-89", "CWE-862"}),
            abstention("context.rag", "no_precedent"),
            abstention("runtime.sfi", "no_safe_entrypoint"),
        ],
        prior_p=PRIOR,
    )
    assert results == []


def test_evidence_from_an_unregistered_agent_is_refused(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """An unregistered agent would silently become a witness nobody calibrated."""
    key = sample_vulnerable_unit.key_for("CWE-89")
    with pytest.raises(UnknownAgentError, match="maps to no witness"):
        fuse_all_evidence(
            [detection("structural.taint", key, 0.9), detection("rogue.agent", key, 0.9)]
        )


def test_a_key_no_detection_carries_is_refused() -> None:
    with pytest.raises(ValueError, match="No detection carries finding_key"):
        compute_bayesian_fusion(
            "abstention:all_agents", [abstention("structural.taint")], PRIOR, ratios=TABLE
        )


def test_one_key_may_not_carry_two_cwes(sample_vulnerable_unit: ChangeUnit) -> None:
    """The key is a digest of file, symbol and CWE; two CWEs means a hand-built key."""
    key = sample_vulnerable_unit.key_for("CWE-89")
    with pytest.raises(ValueError, match="detections for"):
        compute_bayesian_fusion(
            key,
            [
                detection("structural.taint", key, 0.9, cwe="CWE-89"),
                detection("semantic.hosted", key, 0.9, cwe="CWE-78"),
            ],
            PRIOR,
            ratios=TABLE,
        )


# --------------------------------------------------------------------------
# Grouping and ordering
# --------------------------------------------------------------------------


def test_a_detection_of_another_cwe_says_nothing_about_this_finding(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """A DETECTION carries no `covered_cwes`, so it cannot vouch for anything else."""
    unit = sample_vulnerable_unit
    results = fuse_all_evidence(
        [
            detection("structural.taint", unit.key_for("CWE-89"), 0.95, cwe="CWE-89"),
            detection("semantic.hosted", unit.key_for("CWE-78"), 0.95, cwe="CWE-78"),
        ],
        prior_p=PRIOR,
    )
    assert len(results) == 2
    for result in results:
        witnesses_that_spoke = [c.witness for c in result.contributions if c.agent_ids]
        assert witnesses_that_spoke == ["structural" if result.cwe == "CWE-89" else "semantic"]


def test_findings_are_returned_most_probable_first(sample_vulnerable_unit: ChangeUnit) -> None:
    unit = sample_vulnerable_unit
    results = fuse_all_evidence(
        [
            detection("structural.taint", unit.key_for("CWE-89"), 0.95, cwe="CWE-89"),
            detection("structural.taint", unit.key_for("CWE-22"), 0.30, cwe="CWE-22"),
        ],
        prior_p=PRIOR,
    )
    assert [r.cwe for r in results] == ["CWE-89", "CWE-22"]
    assert results[0].posterior_probability > results[1].posterior_probability


def test_a_finding_carries_every_unit_level_statement(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """`evidence_list` is what shaped the number, so the number can be explained."""
    key = sample_vulnerable_unit.key_for("CWE-89")
    results = fuse_all_evidence(
        [
            detection("structural.taint", key, 0.95),
            silence("semantic.hosted", {"CWE-89"}),
            abstention("runtime.sfi", "no_safe_entrypoint"),
        ],
        prior_p=PRIOR,
    )
    assert len(results) == 1
    assert {ev.agent_id for ev in results[0].evidence_list} == {
        "structural.taint",
        "semantic.hosted",
        "runtime.sfi",
    }


def test_no_evidence_is_no_findings() -> None:
    assert fuse_all_evidence([]) == []


# --------------------------------------------------------------------------
# The threshold
# --------------------------------------------------------------------------


def test_a_threshold_can_separate_one_witness_from_several(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """One mechanical witness proving reachability is a weaker claim than three agreeing,
    and a threshold has to be able to tell them apart.

    Stated against the fixture table and an explicit threshold rather than against the fitted
    artifact. Whether the *selected* threshold happens to separate these two on the corpus is
    an empirical question the validation sweep answers, and it is not this test's to assert —
    a property test that changes its mind with every re-fit is not a property test.
    """
    key = sample_vulnerable_unit.key_for("CWE-89")
    lone = compute_bayesian_fusion(
        key,
        [detection("structural.taint", key, 0.99)],
        PRIOR,
        alert_threshold=0.70,
        ratios=TABLE,
    )
    consensus = compute_bayesian_fusion(
        key,
        [
            detection("structural.taint", key, 0.95),
            detection("semantic.hosted", key, 0.95),
            detection("context.rag", key, 0.90),
        ],
        PRIOR,
        alert_threshold=0.70,
        ratios=TABLE,
    )

    assert lone.posterior_probability < consensus.posterior_probability
    assert not lone.is_alert_worthy
    assert consensus.posterior_probability > 0.65
