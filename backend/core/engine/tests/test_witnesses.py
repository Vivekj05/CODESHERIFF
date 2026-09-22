"""Who counts as a witness, and why the count is load-bearing.

The number of factors in the odds product is the number of entries in `WITNESSES`. Every
test here is really the same assertion from a different angle: that number cannot drift
without someone noticing.
"""

import pytest

from codesheriff_engine.fusion.witnesses import (
    WITNESS_OF_AGENT,
    WITNESSES,
    UnknownAgentError,
    agents_of,
    witness_for,
)


def test_there_are_four_witnesses() -> None:
    """Four bases for a decision, and the heterogeneity argument rests on it.

    `CLAUDE.md`: the four agents must fail differently. A fifth witness added here is a
    fifth factor in every posterior, and it must be a genuinely different way of being
    wrong — not a second implementation of an existing one.
    """
    assert len(WITNESSES) == 4
    assert set(WITNESSES) == {"structural", "semantic", "context", "runtime"}
    assert len(set(WITNESSES)) == len(WITNESSES)


def test_the_two_structural_backends_are_one_witness() -> None:
    """D-011, at its source. Separate rows here is what produced the 59.5x."""
    assert witness_for("structural.taint") == witness_for("structural.semgrep") == "structural"
    assert set(agents_of("structural")) == {"structural.taint", "structural.semgrep"}


def test_the_two_semantic_backends_are_one_witness() -> None:
    """Swapping the hosted model for the fine-tuned one is not gaining a witness."""
    assert witness_for("semantic.hosted") == witness_for("semantic.lora") == "semantic"


def test_every_registered_agent_maps_to_a_declared_witness() -> None:
    """A typo in the table would create a witness with no ratios and no seat."""
    assert set(WITNESS_OF_AGENT.values()) <= set(WITNESSES)


def test_every_witness_has_at_least_one_backend() -> None:
    """A witness nothing can speak for would contribute 1.0 to every posterior forever."""
    for witness in WITNESSES:
        assert agents_of(witness), f"no backend registered against {witness}"


def test_an_unregistered_agent_raises_rather_than_becoming_a_witness() -> None:
    """The whole point of the module.

    Falling back to "one witness per unknown agent" would let a typo, a renamed backend or
    an experimental agent multiply an uncalibrated factor into the posterior, silently.
    """
    with pytest.raises(UnknownAgentError) as excinfo:
        witness_for("structural.taints")

    assert "maps to no witness" in str(excinfo.value)
    assert "structural.taint" in str(excinfo.value), "the error should list what is valid"


def test_the_debate_synthesiser_is_not_a_witness() -> None:
    """D-009 lets debate emit evidence; D-008 forbids it being counted as independent.

    It reads what the other witnesses said, so it is maximally dependent on all of them.
    Registering it here would be the anchoring violation with a different name.
    """
    assert "debate.synth" not in WITNESS_OF_AGENT
