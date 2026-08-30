"""Running the four agents over one change unit.

This module moved here from `codesheriff_engine.orchestrator` in Chapter 9. The worker is
where `CLAUDE.md` says the pipeline and all four agents live, and it is the only process
that declares them as dependencies; the engine reached them through `try: import
static_agent`, an undeclared runtime dependency that would have let a fusion package pull
in an LLM client.

Three guarantees, and each of them exists because its absence is a documented failure.

**Every slot produces at least one statement, per unit.** An agent package that will not
import becomes an abstention with a reason, not a gap. `AUDIT.md` 4.4 is what the absence
looks like: missing agents degraded to silence, and silence read as "clean". An agent that
returns `[]` from a successful call is a contract violation, and gets the same treatment
plus a WARNING — it is indistinguishable from a failure, which is what SILENCE is for.

**Nothing here raises.** An agent that throws is caught and abstains. The contract says
agents never raise; this is the belt to that agent-side braces, because an exception
escaping one agent must not cost the audit the other three's evidence.

**No anchoring (D-008).** Every agent gets the same `ChangeUnit` and nothing else — no
peek at what another agent found. Running static first and handing its finding keys
downstream made the other agents conditionally dependent on it: they could only confirm
what it had already found and never disagree, and multiplying likelihood ratios across
correlated witnesses does not give a posterior, it gives a number shaped like one.

The agents run concurrently, which is safe *because* they are blind — there is no ordering
between them to get wrong. Units stay sequential (`AUDIT.md` 4.5).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Any, Protocol

from codesheriff_contracts import ChangeUnit, Evidence
from codesheriff_engine.fusion import CONTEXT, RUNTIME, SEMANTIC, STRUCTURAL, WITNESS_OF_AGENT
from context_agent.precedent import PrecedentRetriever

logger = logging.getLogger(__name__)

AGENT_TIMEOUT_SECONDS = 120.0
"""Wall clock for one agent on one unit, well above the p95 targets in `CLAUDE.md`.

A hung agent becomes an abstention and the audit continues. The thread it left behind is
not killable in Python; it is the process's problem at shutdown, and preferable to an
audit that never finishes and never says why.
"""


class Agent(Protocol):
    """The whole agent interface. One method, one argument (`CLAUDE.md`)."""

    def analyze(self, unit: ChangeUnit) -> list[Evidence]: ...


class UnavailableAgent:
    """Stands in for an agent that could not be loaded. Abstains, with the reason."""

    def __init__(self, agent_id: str, reason: str, detail: str = "") -> None:
        self.agent_id = agent_id
        self.agent_version = "0.0.0"
        self.reason = reason
        self.detail = detail

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        return [
            Evidence.abstention(
                agent_id=self.agent_id,
                agent_version=self.agent_version,
                unit_id=unit.unit_id,
                reason=self.reason,
                explanation=self.detail or f"Agent {self.agent_id!r} is not available.",
            )
        ]


@dataclass(frozen=True)
class AgentDeps:
    """Infrastructure an agent needs but must not reach for itself.

    Agents may import `codesheriff_contracts` and nothing else, so anything that talks to a
    database, a model or a network arrives through a Protocol the agent declares and this
    process implements. One field today; Chapter 13's sandbox handle is the next.

    Empty is a valid state and is what a bare `load_agents()` produces: the agents that need a
    dependency abstain under a reason naming it, rather than substituting something that
    answers anyway.
    """

    precedent_retriever: PrecedentRetriever | None = None


def _load_static(deps: AgentDeps) -> Agent:
    from static_agent.agent import StaticAgent

    return StaticAgent()


def _load_semantic(deps: AgentDeps) -> Agent:
    from semantic_agent.agent import SemanticAgent

    return SemanticAgent()


def _load_context(deps: AgentDeps) -> Agent:
    from context_agent.agent import ContextAgent

    # None is passed through rather than defaulted away. `ContextAgent` warns and abstains on
    # every unit with no retriever, which is the honest report; giving it a store of its own
    # here would be this process deciding what the agent's history is.
    return ContextAgent(retriever=deps.precedent_retriever)


def _load_runtime(deps: AgentDeps) -> Agent:
    raise ModuleNotFoundError(
        "runtime.sfi is not built — PLAN.md Chapter 13. The Wasmtime sandbox is "
        "isolation infrastructure first and a detection agent second."
    )


@dataclass(frozen=True)
class AgentSlot:
    """One witness's seat at the table, filled or not."""

    witness: str
    agent_id: str
    """The id used when the slot cannot be filled, so an absent agent still abstains
    under a name fusion recognises rather than vanishing from the record."""

    load: Callable[[AgentDeps], Agent]


AGENT_SLOTS: tuple[AgentSlot, ...] = (
    AgentSlot(STRUCTURAL, "structural.taint", _load_static),
    AgentSlot(SEMANTIC, "semantic.hosted", _load_semantic),
    AgentSlot(CONTEXT, "context.rag", _load_context),
    AgentSlot(RUNTIME, "runtime.sfi", _load_runtime),
)
"""Four slots for four witnesses — not five for five backends.

`structural.taint` and `structural.semgrep` are two backends behind one `StaticAgent`, and
they are one witness (D-011). The seat count here and the factor count in the odds product
are the same number, and that is the invariant worth keeping.
"""


def agent_id_of(agent: Any, default: str) -> str:
    """An agent's declared id. `StaticAgent` says `id`; the others say `agent_id`."""
    value = getattr(agent, "agent_id", None) or getattr(agent, "id", None)
    return str(value) if value else default


def load_agents(
    slots: tuple[AgentSlot, ...] = AGENT_SLOTS,
    deps: AgentDeps | None = None,
) -> list[Agent]:
    """Fill every slot, substituting an abstaining stand-in for any that will not load.

    An agent whose declared `agent_id` is not registered against a witness is also
    replaced. Fusion refuses unregistered ids — an agent nobody registered would multiply
    in a factor nobody calibrated — and refusing at load time turns that into one log line
    at worker start rather than an exception in the middle of every audit.
    """
    resolved = deps or AgentDeps()
    agents: list[Agent] = []
    for slot in slots:
        try:
            agent = slot.load(resolved)
        except Exception as exc:
            logger.info("Agent slot %s unavailable: %s", slot.witness, exc)
            agents.append(UnavailableAgent(slot.agent_id, "agent_unavailable", str(exc)[:400]))
            continue

        declared = agent_id_of(agent, slot.agent_id)
        if declared not in WITNESS_OF_AGENT:
            logger.error(
                "Agent in slot %s declares agent_id %r, which maps to no witness. Register it "
                "in codesheriff_engine.fusion.witnesses or fix the id; abstaining meanwhile.",
                slot.witness,
                declared,
            )
            agents.append(
                UnavailableAgent(
                    slot.agent_id,
                    "agent_id_unregistered",
                    f"Loaded agent declares unregistered agent_id {declared!r}.",
                )
            )
            continue

        agents.append(agent)
    return agents


def _run_one(agent: Agent, unit: ChangeUnit, fallback_id: str) -> list[Evidence]:
    """One agent on one unit, guaranteed to yield at least one statement."""
    try:
        evidence = agent.analyze(unit)
    except Exception as exc:
        logger.exception("Agent %s raised on unit %s", fallback_id, unit.unit_id)
        return [
            Evidence.abstention(
                agent_id=agent_id_of(agent, fallback_id),
                agent_version=str(getattr(agent, "agent_version", None) or "0.0.0"),
                unit_id=unit.unit_id,
                reason="agent_raised",
                explanation=f"{type(exc).__name__}: {exc}"[:400],
            )
        ]

    if evidence:
        return evidence

    # Returning [] from a successful analysis is a bug the contract names: it is
    # indistinguishable from a failure, and it throws away the one statement that can
    # lower a posterior. Recorded as an abstention, because an agent that told us nothing
    # has told us nothing — reading it as silence would be inventing reassurance.
    logger.warning(
        "Agent %s returned no evidence for unit %s. A successful analysis must return a "
        "DETECTION, a SILENCE or an ABSTENTION.",
        fallback_id,
        unit.unit_id,
    )
    return [
        Evidence.abstention(
            agent_id=agent_id_of(agent, fallback_id),
            agent_version=str(getattr(agent, "agent_version", None) or "0.0.0"),
            unit_id=unit.unit_id,
            reason="agent_returned_nothing",
            explanation="Agent completed but emitted no evidence.",
        )
    ]


def analyse_unit(
    agents: list[Agent],
    unit: ChangeUnit,
    timeout_seconds: float = AGENT_TIMEOUT_SECONDS,
) -> list[Evidence]:
    """Every agent's statement about one unit, in slot order."""
    if not agents:
        return []

    # Paired with its own declared id, not with a slot by position: `load_agents`
    # guarantees every agent here declares a registered id, and pairing by index would
    # mislabel the moment a caller passed a list assembled some other way.
    with ThreadPoolExecutor(max_workers=len(agents), thread_name_prefix="agent") as pool:
        futures = [
            (
                agent_id_of(agent, "unknown.agent"),
                pool.submit(_run_one, agent, unit, agent_id_of(agent, "unknown.agent")),
            )
            for agent in agents
        ]

        collected: list[Evidence] = []
        for fallback_id, future in futures:
            try:
                collected.extend(future.result(timeout=timeout_seconds))
            except FutureTimeout:
                logger.error(
                    "Agent %s exceeded %.0fs on unit %s; abstaining",
                    fallback_id,
                    timeout_seconds,
                    unit.unit_id,
                )
                collected.append(
                    Evidence.abstention(
                        agent_id=fallback_id,
                        agent_version="0.0.0",
                        unit_id=unit.unit_id,
                        reason="agent_timeout",
                        explanation=f"Exceeded {timeout_seconds:.0f}s on this unit.",
                    )
                )
    return collected
