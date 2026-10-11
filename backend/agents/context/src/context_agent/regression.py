"""What this repository established, and what this unit dropped.

This is the reasoning the audit found missing (`AUDIT.md` 3.7). The superseded module was four
substring tests for `stripe_charge`; retrieved documents reached it only as a gate and as a
300-character excerpt, and never influenced what was detected. Everything below is derived
from the retrieved excerpts, and with an empty history it produces nothing at all.

**No LLM.** `CLAUDE.md` gives this witness the basis "this repository's own precedent" and the
failure mode "repo has no relevant history". A model-driven version would share
`semantic.hosted`'s failure mode — confidently wrong, or agreeable — and heterogeneity is the
entire justification for fusing four witnesses rather than trusting one. The superseded
package's `reasoning/prompts/cross_pr_v1.md` was referenced by no code; it is deleted rather
than wired up.

A control is **established** two ways, and both are needed:

*The same symbol carried it.* One merged excerpt of this exact qualified symbol with the
control on it settles the question — the repository accepted this function with that guard.
Frequency is the wrong test here, because a function that has only ever been merged once has
no siblings to be counted against. `cwe-862-xpr-queue-drain` is that case: a handler moved
between modules and lost `@admin_required` on the way, with a single precedent record to its
name. Matching is on the symbol, never the path, because the move changed the path.

*Enough sibling symbols carry it.* Two or more distinct retrieved symbols applying the same
control is a convention rather than a coincidence. One is a coincidence: every function calls
something no other function happens to call, and treating a single neighbour's habit as a rule
would make every added function a regression against whichever neighbour retrieval returned.

What is **missing** is then set arithmetic — established, minus what this unit applies — and
`classify.py` decides which of those are this witness's business. Most are not.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from codesheriff_contracts import ChangeUnit
from context_agent.classify import cwe_for
from context_agent.controls import Control, control_surface
from context_agent.precedent import Precedent

logger = logging.getLogger(__name__)

FULL_CREDIT_SIMILARITY = 0.85
"""Similarity at or above which precedent is treated as fully relevant.

Provisional (D-010). Retrieval that clears the agent's `min_similarity` floor has already
been judged relevant; this is the separate question of whether it is *close* enough that the
support count should stand on its own.
"""

MIN_SUPPORTING_SYMBOLS = 2
"""Distinct retrieved symbols that must share a control before it is a convention.

Provisional, like every other number in this project until Chapter 14 (D-010). Two is the
smallest value that is not "one neighbour did it once", and raising it would silence the
three-precedent authorization cases the corpus holds.
"""


@dataclass(frozen=True)
class MissingControl:
    """A control this repository established that the unit under analysis does not apply."""

    control: Control
    cwe: str
    supporting: tuple[Precedent, ...]
    """The merged excerpts that establish it. Never empty — this is the evidence, and a
    claim about precedent with no precedent behind it is the thing being replaced."""

    same_symbol: bool
    """Whether the repository accepted *this* symbol carrying it, as opposed to siblings."""

    @property
    def support(self) -> int:
        return len({p.qualified_symbol for p in self.supporting})

    @property
    def mean_similarity(self) -> float:
        return sum(p.similarity for p in self.supporting) / len(self.supporting)


def _surface_or_empty(source: str, language: str, what: str) -> frozenset[Control]:
    """Controls in `source`, or nothing if it will not parse.

    A precedent excerpt that cannot be read is dropped with a log line rather than failing the
    unit. The history is a convenience the repository happens to have; a single unparseable
    row in it must not cost the audit this agent's statement altogether.
    """
    try:
        return control_surface(source, language)
    except Exception as exc:
        logger.warning("could not read the control surface of %s: %s", what, exc)
        return frozenset()


def established_controls(
    unit: ChangeUnit,
    precedents: Sequence[Precedent],
) -> dict[Control, tuple[list[Precedent], bool]]:
    """Controls this repository's history establishes, and what establishes each.

    Returns `control -> (supporting excerpts, established by the same symbol)`.
    """
    carriers: dict[Control, list[Precedent]] = {}
    same_symbol: set[Control] = set()

    for precedent in precedents:
        surface = _surface_or_empty(
            precedent.accepted_src,
            unit.language,
            f"precedent #{precedent.pr_number} {precedent.qualified_symbol}",
        )
        for control in surface:
            carriers.setdefault(control, []).append(precedent)
            if precedent.qualified_symbol == unit.qualified_symbol:
                same_symbol.add(control)

    established: dict[Control, tuple[list[Precedent], bool]] = {}
    for control, supporting in carriers.items():
        by_symbol = {p.qualified_symbol for p in supporting}
        if control in same_symbol or len(by_symbol) >= MIN_SUPPORTING_SYMBOLS:
            established[control] = (supporting, control in same_symbol)
    return established


def missing_controls(
    unit: ChangeUnit,
    precedents: Sequence[Precedent],
) -> list[MissingControl]:
    """Established controls the unit does not apply, restricted to this witness's CWEs.

    Ordered by support and then by name so two runs over the same inputs agree — an
    explanation that reshuffles between runs is one nobody can diff.
    """
    if not precedents:
        return []

    applied = _surface_or_empty(unit.post_src, unit.language, f"unit {unit.unit_id}")
    established = established_controls(unit, precedents)

    found: list[MissingControl] = []
    for control, (supporting, by_same_symbol) in established.items():
        if control in applied:
            continue
        if _applied_under_another_kind(control, applied):
            continue
        cwe = cwe_for(control)
        if cwe is None:
            continue
        found.append(
            MissingControl(
                control=control,
                cwe=cwe,
                supporting=tuple(supporting),
                same_symbol=by_same_symbol,
            )
        )

    return sorted(found, key=lambda m: (-m.support, m.control.name))


def _applied_under_another_kind(control: Control, applied: Iterable[Control]) -> bool:
    """Whether the unit enforces the same-named control a different way.

    A repository that guards with `@require_owner` on some endpoints and a `require_owner(...)`
    call at the top of others has one control with two spellings. Reporting the decorator as
    missing from a function that calls it is a false positive that reads, to whoever gets the
    comment, as the agent not having read the code.
    """
    return any(other.name == control.name for other in applied)


def score_for(missing: MissingControl) -> float:
    """A raw score for one missing control, in [0, 1].

    Provisional and hand-set (D-010). It exists to land in the right tier of
    `WitnessRatios.for_score` — high at 0.8, medium at 0.5 — and Chapter 14 replaces the tiers
    with fitted numbers. What it encodes is the only thing this witness has to be confident
    about: how firmly the history establishes the control.

    The repository accepting *this* symbol with the control, or three or more siblings
    agreeing, is the strong form. Two siblings is the weak form — a convention, but a thin
    one — and it lands medium.
    """
    strong = missing.same_symbol or missing.support >= 3
    base = 0.85 if strong else 0.65

    # Similarity damps, but only once it is genuinely weak. Multiplying by the raw similarity
    # instead meant a strong claim backed by excerpts at a perfectly good 0.9 came out at
    # 0.765 and landed in the medium tier — every detection this agent could make was demoted
    # by retrieval doing its job, and the tier boundary stopped meaning anything. Above
    # `FULL_CREDIT_SIMILARITY` the support count decides alone; below it the claim is scaled
    # down in proportion to how far the precedent actually is.
    damping = min(1.0, missing.mean_similarity / FULL_CREDIT_SIMILARITY)
    return round(base * damping, 4)
