"""Who the witnesses are, and which backend speaks for which one.

Fusion multiplies one likelihood ratio per **witness**, and this module is the only
place that decides how many witnesses there are. Two rules live here, and both exist
because breaking either one silently inflates a posterior.

**A backend is not a witness (D-011).** `structural.taint` and `structural.semgrep`
are two rule-based analyses of the same source text in the same package — maximally
correlated, and exactly the shared failure mode the four-agent heterogeneity argument
exists to avoid. Fusing them as independent agents multiplied 8.5 x 7.0 = **59.5x**
out of what is really one witness (`AUDIT.md` 2.4). They map to one witness here, and
`bayes.py` combines their statements before the odds are touched.

**The roster is fixed, and fusion iterates all of it (D-007).** An agent that emitted
nothing still gets a turn, at LR 1.0. Iterating only the agents that spoke is what made
the old engine's posterior monotonically non-decreasing in the number of agents that
alerted, because every detection tier exceeds 1.0 (`AUDIT.md` 1.4).

An `agent_id` that is not in `WITNESS_OF_AGENT` raises. It would otherwise become a
witness of its own and multiply in a factor nobody registered, which is a silent
independence violation — the failure this whole module is here to prevent.
"""

from __future__ import annotations

from typing import Final

STRUCTURAL: Final = "structural"
SEMANTIC: Final = "semantic"
CONTEXT: Final = "context"
RUNTIME: Final = "runtime"

WITNESSES: Final[tuple[str, ...]] = (STRUCTURAL, SEMANTIC, CONTEXT, RUNTIME)
"""The four independent bases for a decision (`CLAUDE.md`, "The four agents must fail
differently"). Order is fixed so a fused posterior is reproducible factor by factor;
multiplication commutes, but a recorded per-witness breakdown should not reshuffle."""

WITNESS_OF_AGENT: Final[dict[str, str]] = {
    "structural.taint": STRUCTURAL,
    "structural.semgrep": STRUCTURAL,
    "semantic.hosted": SEMANTIC,
    "semantic.lora": SEMANTIC,
    "context.rag": CONTEXT,
    "runtime.sfi": RUNTIME,
}
"""Every backend that may emit evidence, and the witness it speaks for.

`semantic.lora` is the fine-tuned variant of the same model family (v0.9). It is listed
so that swapping backends cannot accidentally create a fifth witness — it is the same
absorbed model knowledge, and it fails the same way.

`debate.synth` is deliberately **absent**. Debate emits its own evidence rather than
overwriting a posterior (D-009), but it is not an independent witness: it reads what the
others said, so it is maximally dependent on all of them. Registering it here would be
the anchoring violation (D-008) wearing a different hat. Where its contribution belongs
is Chapter 11's to decide, with the LLM client that runs it.
"""


class UnknownAgentError(ValueError):
    """Evidence arrived from an `agent_id` no witness claims."""


def witness_for(agent_id: str) -> str:
    """The witness `agent_id` speaks for. Raises rather than inventing one."""
    try:
        return WITNESS_OF_AGENT[agent_id]
    except KeyError:
        raise UnknownAgentError(
            f"agent_id {agent_id!r} maps to no witness. Register it in WITNESS_OF_AGENT "
            f"against the witness it speaks for — an unregistered agent that fused as its "
            f"own witness would multiply in a factor nobody calibrated. Known: "
            f"{sorted(WITNESS_OF_AGENT)}"
        ) from None


def agents_of(witness: str) -> tuple[str, ...]:
    """Every backend registered against `witness`, in declaration order."""
    return tuple(agent for agent, w in WITNESS_OF_AGENT.items() if w == witness)
