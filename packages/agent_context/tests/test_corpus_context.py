"""`context.rag` measured against ground truth — on the calibration split, and only that.

**This file must never read the validation or the test split.** §6 reserves validation for
threshold selection and permits the test split to be evaluated exactly once, at the end.
Iterating a control vocabulary while watching either one is fitting on it, whatever it is
called, and a suite that runs on every commit is the most thorough possible way to do that.
`test_only_the_calibration_split_is_read` asserts the restriction rather than trusting it.

The `codesheriff_corpus` import is deliberate and does not breach D-047, which names the
`context_agent` **package**. A test is where labels are supposed to be read; it is the only
place these numbers can come from.

**Retrieval is deterministic and local.** The agent is handed a `CorpusRetriever` that ranks a
case's authored history by token overlap — no database, no model download, no network. This is
the same discipline as the semantic agent's cassettes (D-068): the measurement runs the real
`analyze()` path, and it runs the same way on every machine and in CI. What is *not* measured
here is pgvector's nearest-neighbour ordering, which is why the ranking is exercised at all
rather than the history being handed over wholesale — a retriever that returned everything
would hide a `top_k` that silently dropped the second carrier of a convention.
"""

from __future__ import annotations

import math
import re

import pytest

from codesheriff_contracts import ChangeUnit, EvidenceKind
from codesheriff_corpus.loader import load_cases
from codesheriff_corpus.models import CorpusCase, Label
from codesheriff_corpus.splits import Split, split_for
from context_agent.agent import ContextAgent
from context_agent.config import AGENT_ID
from context_agent.precedent import Precedent

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN.findall(text)}


def _cosine_ish(left: set[str], right: set[str]) -> float:
    """Token-set cosine. Deterministic, dependency-free, and monotone in overlap.

    A stand-in for the embedding model's ordering, not an imitation of it. It has to agree
    with a real embedder on the only thing this measurement depends on — that a merged sibling
    in the same module ranks above an unrelated one — and it does, because those excerpts share
    identifiers.
    """
    if not left or not right:
        return 0.0
    return len(left & right) / math.sqrt(len(left) * len(right))


class CorpusRetriever:
    """One case's authored history, ranked by similarity to the unit, capped at `limit`."""

    def __init__(self, case: CorpusCase) -> None:
        self._case = case

    def retrieve(self, unit: ChangeUnit, limit: int) -> list[Precedent]:
        query = _tokens(f"{unit.qualified_symbol} {unit.file} {unit.post_src}")
        scored = [
            Precedent(
                pr_number=record.pr_number,
                file=record.file,
                qualified_symbol=record.qualified_symbol,
                accepted_src=record.accepted_src,
                similarity=_cosine_ish(
                    query,
                    _tokens(f"{record.qualified_symbol} {record.file} {record.accepted_src}"),
                ),
            )
            for record in self._case.precedent
        ]
        return sorted(scored, key=lambda p: -p.similarity)[:limit]


def unit_of(case: CorpusCase) -> ChangeUnit:
    """A corpus case as the object an agent actually receives (D-048)."""
    return case.unit


def analyse(case: CorpusCase) -> list:
    """Through the production entry point. Never a helper function inside the agent."""
    return ContextAgent(retriever=CorpusRetriever(case)).analyze(unit_of(case))


def reported_cwes(case: CorpusCase) -> set[str]:
    return {e.cwe for e in analyse(case) if e.kind is EvidenceKind.DETECTION and e.cwe}


CASES = [c for c in load_cases() if split_for(c) is Split.CALIBRATION]
WITH_HISTORY = [c for c in CASES if c.precedent]

EXPECTED = [c for c in WITH_HISTORY if c.label is Label.VULNERABLE and c.detectable(AGENT_ID)]
"""Vulnerable calibration cases `detectable_by` predicted for this agent, pre-registered."""

MUST_STAY_QUIET = [
    c for c in WITH_HISTORY if not (c.label is Label.VULNERABLE and c.detectable(AGENT_ID))
]
"""Everything else that has a history: safe twins, and vulnerable cases about other CWEs."""


def test_only_the_calibration_split_is_read() -> None:
    """The guard on this whole file. §6 is not enforceable by intention alone."""
    assert CASES, "the calibration split is empty — the corpus or the splits did not load"
    assert all(split_for(case) is Split.CALIBRATION for case in CASES)


def test_the_corpus_actually_carries_cross_pr_histories() -> None:
    """Chapter 7's deferred deliverable, landed.

    Without this the suite below would pass vacuously: an agent that abstained on everything
    would have no predicted case to miss and no safe twin to fire on.
    """
    assert EXPECTED, "no calibration case predicts context.rag — the histories are missing"
    assert MUST_STAY_QUIET


@pytest.mark.parametrize("case", EXPECTED, ids=lambda c: c.case_id)
def test_every_predicted_case_is_detected(case: CorpusCase) -> None:
    """`detectable_by` was pre-registered from D-047's rule before any agent ran."""
    assert case.cwe in reported_cwes(case), (
        f"{case.case_id} is labelled detectable by {AGENT_ID} and was not detected. "
        f"Rationale: {case.rationale}"
    )


@pytest.mark.parametrize("case", MUST_STAY_QUIET, ids=lambda c: c.case_id)
def test_nothing_is_reported_where_nothing_regressed(case: CorpusCase) -> None:
    """Both kinds of false positive this agent can make.

    A safe twin differs from its vulnerable partner by the control alone, so firing on it means
    reacting to the shape of the code. A vulnerable case about another CWE carries a history
    that establishes a real convention this unit really breaks — `escape()` on the CWE-79 pair,
    `@rate_limit` on the CWE-918 pair — and reporting either as an authorization failure would
    be a false positive dressed as thoroughness.
    """
    assert not reported_cwes(case), (
        f"{case.case_id} ({case.label.value}) drew {sorted(reported_cwes(case))}. "
        f"Rationale: {case.rationale}"
    )


@pytest.mark.parametrize("case", WITH_HISTORY, ids=lambda c: c.case_id)
def test_a_case_with_a_history_is_never_an_abstention(case: CorpusCase) -> None:
    """Precedent was supplied, so the agent must have an opinion.

    An abstention here would mean the measurement above is measuring an agent that did not
    run — which is exactly how a suite reporting 100% coverage failed to notice that three of
    four analysis components were shells.
    """
    kinds = {e.kind for e in analyse(case)}
    assert EvidenceKind.ABSTENTION not in kinds, f"{case.case_id} abstained despite a history"


@pytest.mark.parametrize("case", [c for c in CASES if not c.precedent][:6], ids=lambda c: c.case_id)
def test_a_case_with_no_history_abstains(case: CorpusCase) -> None:
    """The documented failure mode, measured rather than assumed.

    A repository with no relevant history is the normal case in production, and it must cost
    the posterior nothing — an abstention is a likelihood ratio of exactly 1.0 by definition.
    """
    assert [e.kind for e in analyse(case)] == [EvidenceKind.ABSTENTION]


def test_recall_and_false_positives_over_the_whole_calibration_split() -> None:
    """The two numbers Chapter 12 reports, asserted so they cannot quietly regress.

    Deliberately not a floor on a *rate*: with five predicted cases a rate is a coarse
    instrument, and D-010 forbids presenting any of this as calibrated. What is asserted is
    that every pre-registered case is found and nothing else is reported at all.
    """
    missed = [c.case_id for c in EXPECTED if c.cwe not in reported_cwes(c)]
    false_positives = [c.case_id for c in MUST_STAY_QUIET if reported_cwes(c)]

    assert not missed, f"missed: {missed}"
    assert not false_positives, f"false positives: {false_positives}"
