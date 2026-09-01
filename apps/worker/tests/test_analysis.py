"""Running the agents: every slot speaks, nothing raises, nothing goes missing.

No database and no GitHub, so these run in every suite. They are about the guarantees the
runner makes to fusion, and each one corresponds to a way the old orchestrator let a
witness disappear.
"""

from __future__ import annotations

import pytest

from codesheriff_contracts import ChangeUnit, Evidence, EvidenceKind
from codesheriff_engine.fusion import WITNESSES, witness_for
from codesheriff_worker.analysis import (
    AGENT_SLOTS,
    UnavailableAgent,
    agent_id_of,
    analyse_unit,
    load_agents,
)

UNIT = ChangeUnit(
    unit_id="u1",
    repo="acme/payments-api",
    language="python",
    file="orders/api.py",
    symbol="export",
    post_src="def export(request):\n    return run(request.args['q'], shell=True)\n",
    changed_lines=[2],
    base_sha="b" * 40,
    head_sha="h" * 40,
)


class SilentAgent:
    agent_id = "context.rag"
    agent_version = "0.1.0"

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        return [
            Evidence.silence(
                agent_id=self.agent_id,
                agent_version=self.agent_version,
                unit_id=unit.unit_id,
                covered_cwes={"CWE-862"},
            )
        ]


class EmptyAgent:
    """Returns `[]` from a successful call — the bug the contract names."""

    agent_id = "semantic.hosted"
    agent_version = "0.1.0"

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        return []


class ExplodingAgent:
    agent_id = "structural.taint"
    agent_version = "0.1.0"

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        raise RuntimeError("tree-sitter segfaulted")


class SlowAgent:
    agent_id = "runtime.sfi"
    agent_version = "0.1.0"

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        import time

        time.sleep(5)
        return []


# -- the roster --------------------------------------------------------------------------------


def test_there_is_one_slot_per_witness() -> None:
    """Four seats, four factors. The two structural backends share one seat (D-011)."""
    assert len(AGENT_SLOTS) == len(WITNESSES)
    assert [slot.witness for slot in AGENT_SLOTS] == list(WITNESSES)


def test_every_slots_fallback_id_is_a_registered_agent() -> None:
    """An unregistered id would make fusion raise on the very audit that needed the stand-in."""
    for slot in AGENT_SLOTS:
        assert witness_for(slot.agent_id) == slot.witness


def test_every_slot_is_filled_by_a_real_agent() -> None:
    """All four exist as of Chapter 13, and every seat is occupied by the agent itself.

    This asserted a stand-in for `runtime.sfi` until Chapter 13 built it. The stand-in path
    is still the one that matters and is still tested, one test down — but by a loader that
    genuinely fails, rather than by the shell that used to be the fourth agent. A test whose
    premise is "this component does not exist yet" has to be retired when it does, or it
    starts asserting the absence rather than the mechanism.
    """
    agents = load_agents()

    assert len(agents) == len(AGENT_SLOTS)
    assert not any(isinstance(agent, UnavailableAgent) for agent in agents)
    assert [agent_id_of(agent, "?") for agent in agents] == [s.agent_id for s in AGENT_SLOTS]


def test_a_slot_whose_loader_fails_is_still_occupied() -> None:
    """AUDIT.md 4.4: a missing agent degrading to silence is what made silence read as clean.

    The four packages all import now, so the only way to reach this path is a loader that
    raises — which is what a broken install, a missing extra or a renamed module looks like.
    """
    slot = AGENT_SLOTS[-1]

    def refuses(deps: object) -> object:
        raise ModuleNotFoundError("no module named 'agent_runtime'")

    agents = load_agents((slot.__class__(slot.witness, slot.agent_id, refuses),))

    assert isinstance(agents[0], UnavailableAgent)
    assert agents[0].reason == "agent_unavailable"
    assert agent_id_of(agents[0], "?") == "runtime.sfi"


def test_an_unavailable_agent_abstains_with_a_reason() -> None:
    """AUDIT.md 4.4: a missing agent must never read as an agent that found nothing."""
    evidence = UnavailableAgent("runtime.sfi", "agent_unavailable", "not built").analyze(UNIT)

    assert len(evidence) == 1
    assert evidence[0].kind is EvidenceKind.ABSTENTION
    assert evidence[0].reason == "agent_unavailable"
    assert evidence[0].covered_cwes == frozenset(), "an abstention vouches for nothing"


def test_an_agent_declaring_an_unregistered_id_is_replaced() -> None:
    """Caught at load, so it is one log line at start-up rather than every audit failing."""

    class Rogue:
        agent_id = "structural.taintt"

        def analyze(self, unit: ChangeUnit) -> list[Evidence]:
            return []

    slot = AGENT_SLOTS[0]
    # Slot loaders take the injected dependencies (Chapter 12), so this one ignores them.
    agents = load_agents((slot.__class__(slot.witness, slot.agent_id, lambda deps: Rogue()),))

    assert isinstance(agents[0], UnavailableAgent)
    assert agents[0].reason == "agent_id_unregistered"


# -- running -----------------------------------------------------------------------------------


def test_every_agent_produces_at_least_one_statement() -> None:
    evidence = analyse_unit(load_agents(), UNIT)
    speakers = {witness_for(ev.agent_id) for ev in evidence}

    assert speakers == set(WITNESSES), "a witness with no statement is a witness gone missing"


def test_an_agent_that_raises_becomes_an_abstention() -> None:
    """The contract says agents never raise. This is the belt to that agent-side braces:
    an exception escaping one agent must not cost the audit the other three."""
    evidence = analyse_unit([ExplodingAgent(), SilentAgent()], UNIT)

    exploded = next(ev for ev in evidence if ev.agent_id == "structural.taint")
    assert exploded.kind is EvidenceKind.ABSTENTION
    assert exploded.reason == "agent_raised"
    assert "RuntimeError" in exploded.explanation

    # And the other agent's evidence survived it.
    assert any(ev.kind is EvidenceKind.SILENCE for ev in evidence)


def test_an_agent_returning_nothing_abstains_rather_than_going_silent() -> None:
    """Returning `[]` is indistinguishable from a failure, so it is recorded as one.

    Reading it as silence would invent reassurance the agent never offered — and silence
    now carries a likelihood ratio below 1.0, so the invention would have a price.
    """
    evidence = analyse_unit([EmptyAgent()], UNIT)

    assert len(evidence) == 1
    assert evidence[0].kind is EvidenceKind.ABSTENTION
    assert evidence[0].reason == "agent_returned_nothing"


def test_a_hung_agent_becomes_an_abstention_and_the_audit_continues() -> None:
    evidence = analyse_unit([SlowAgent(), SilentAgent()], UNIT, timeout_seconds=0.2)

    timed_out = next(ev for ev in evidence if ev.agent_id == "runtime.sfi")
    assert timed_out.kind is EvidenceKind.ABSTENTION
    assert timed_out.reason == "agent_timeout"
    assert any(ev.agent_id == "context.rag" for ev in evidence)


def test_agents_receive_the_unit_and_nothing_else() -> None:
    """D-008. There is no `anchors` parameter, and no agent sees another's findings."""
    import inspect

    for agent in load_agents():
        params = list(inspect.signature(agent.analyze).parameters)
        assert params == ["unit"], f"{agent_id_of(agent, '?')} takes {params}"


def test_no_agent_is_asked_about_the_corpus_or_the_database() -> None:
    """A sanity check on the seam: the runner passes a ChangeUnit, which holds neither."""
    assert not hasattr(UNIT, "label")
    assert not hasattr(UNIT, "detectable_by")


@pytest.mark.parametrize("agent_id", [slot.agent_id for slot in AGENT_SLOTS])
def test_each_slot_id_names_a_distinct_witness(agent_id: str) -> None:
    assert witness_for(agent_id) in WITNESSES
