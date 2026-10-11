"""Cross-PR scenarios: a case plus a precedent history (Chapter 7's deferred deliverable).

The shape was left to Chapter 12 to fix rather than guessed at, because authoring fifteen
histories against a schema that later changed would mean rewriting them all.
"""

from __future__ import annotations

import pytest

from codesheriff_corpus.loader import load_cases, load_pairs
from codesheriff_corpus.models import CorpusCase, PrecedentRecord
from codesheriff_corpus.splits import Split, split_for

CASES = load_cases()
WITH_HISTORY = [c for c in CASES if c.precedent]


def test_the_corpus_carries_cross_pr_scenarios() -> None:
    assert WITH_HISTORY, "no case carries a precedent history"


def test_twins_share_a_precedent_history() -> None:
    """Both members of a pair face the same repository.

    The safe twin exists so a rule keyed on the shape of the code rather than on the flaw
    fires on both members and is measured for it. A twin whose history differed would let an
    agent be right about the pair for the wrong reason, and the difference — not the guard —
    would be doing the work.
    """
    for pair_id, (vuln, safe) in load_pairs().items():
        assert vuln.precedent == safe.precedent, (
            f"{pair_id}: the twins were authored against different histories"
        )


@pytest.mark.parametrize("case", WITH_HISTORY, ids=lambda c: c.case_id)
def test_precedent_sources_are_valid_python(case: CorpusCase) -> None:
    """tree-sitter tolerates broken syntax, so a stray indent would silently analyse a
    fragment rather than fail — the same reason `post.py` is compiled."""
    for record in case.precedent:
        compile(record.accepted_src, f"{case.case_id}:{record.qualified_symbol}", "exec")


@pytest.mark.parametrize("case", WITH_HISTORY, ids=lambda c: c.case_id)
def test_a_history_is_ordered_and_complete(case: CorpusCase) -> None:
    """Ordered by pull request so a history reads as a timeline, and so `corpus_hash` does not
    depend on the order someone happened to type the entries in."""
    numbers = [r.pr_number for r in case.precedent]
    assert numbers == sorted(numbers)
    for record in case.precedent:
        assert record.qualified_symbol
        assert record.file.endswith(".py")


def test_the_authorisation_pairs_are_where_the_histories_are() -> None:
    """`context.rag` reports CWE-862 and CWE-639 only, so those are the pairs a history can
    make detectable. Every other history in the corpus is a negative control."""
    detectable = [c for c in WITH_HISTORY if c.is_vulnerable and c.detectable("context.rag")]
    assert detectable
    assert {c.cwe for c in detectable} <= {"CWE-862", "CWE-639"}


def test_a_history_exists_inside_the_calibration_split() -> None:
    """Otherwise the agent has nothing to be measured against.

    §6 seals validation and test, so a corpus whose only cross-PR scenarios sat in either of
    them would leave Chapter 14 fitting a context ratio on no observations at all.
    """
    calibration = [c for c in WITH_HISTORY if split_for(c) is Split.CALIBRATION]
    assert [c for c in calibration if c.is_vulnerable and c.detectable("context.rag")]
    assert [c for c in calibration if not c.is_vulnerable]


def test_a_precedent_record_needs_a_source() -> None:
    with pytest.raises(ValueError):
        PrecedentRecord(pr_number=1, file="a.py", qualified_symbol="f", accepted_src="   \n")


def test_most_cases_still_have_no_history() -> None:
    """The normal condition, and the one the agent's abstention path is measured on.

    A corpus in which every case had a history would never exercise "this repository has no
    relevant precedent", which is `context.rag`'s documented failure mode.
    """
    assert len(WITH_HISTORY) < len(CASES) / 2
