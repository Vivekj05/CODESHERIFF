"""What must hold of every case, checked over the whole corpus rather than a sample.

These are the gates PLAN.md Chapter 7 names, plus the ones that turned out to matter
while writing the cases. The expensive failure is not a corpus that fails to load —
that is loud. It is a corpus that loads and is subtly not what it claims: a twin whose
key drifted from its partner, a CWE with no safe case, a `detectable_by` naming an
agent that does not exist.
"""

from __future__ import annotations

import pytest

from codesheriff_contracts import IN_SCOPE_CWES, Evidence, EvidenceKind
from codesheriff_corpus import (
    KNOWN_AGENT_IDS,
    CorpusCase,
    Label,
    load_cases,
    load_pairs,
)
from codesheriff_corpus.models import CORPUS_REPO


def test_corpus_loads() -> None:
    cases = load_cases()
    assert len(cases) == 60, "Chapter 7 authors 60 units; see DECISIONS.md D-044"
    assert len({c.case_id for c in cases}) == len(cases)


def test_every_in_scope_cwe_has_a_vulnerable_case_and_a_safe_twin() -> None:
    """The chapter's stated acceptance criterion.

    A CWE with no vulnerable case cannot contribute a single detection observation,
    and one with no safe case measures recall with nothing to say about precision.
    """
    cases = load_cases()
    for cwe in sorted(IN_SCOPE_CWES):
        members = [c for c in cases if c.cwe == cwe]
        assert any(c.is_vulnerable for c in members), f"{cwe}: no vulnerable case"
        assert any(not c.is_vulnerable for c in members), f"{cwe}: no safe twin"


def test_pairs_are_complete_and_opposite() -> None:
    for pair_id, (vulnerable, safe) in load_pairs().items():
        assert vulnerable.label is Label.VULNERABLE, pair_id
        assert safe.label is Label.SAFE, pair_id
        assert vulnerable.cwe == safe.cwe, f"{pair_id}: twins disagree on the CWE"


def test_twins_share_a_finding_key() -> None:
    """The property that makes a false positive measurable at all.

    Fusion groups evidence by `finding_key`. If a twin pair produced two different
    keys, "the agent fired on the safe twin" and "the agent found the bug" would be
    statements about different findings, and precision could not be computed by
    lookup. Same file, same qualified symbol, same CWE — so the same key.
    """
    for pair_id, (vulnerable, safe) in load_pairs().items():
        assert vulnerable.expected_key == safe.expected_key, (
            f"{pair_id}: twins key differently. They must share file, symbol, "
            "enclosing_class and CWE."
        )


def test_twins_differ_in_source() -> None:
    """A twin that is a copy measures nothing."""
    for pair_id, (vulnerable, safe) in load_pairs().items():
        assert vulnerable.post_src != safe.post_src, f"{pair_id}: identical twins"


@pytest.mark.parametrize("case", load_cases(), ids=lambda c: c.case_id)
def test_case_sources_are_valid_python(case: CorpusCase) -> None:
    """Every source parses.

    The static agent runs tree-sitter, which tolerates broken syntax by design — so a
    case with a stray indent would not fail there, it would silently analyse a
    fragment. `compile` is the cheapest way to be sure the sample is what it looks
    like. It only parses; nothing here executes, which matters because these files
    are deliberately vulnerable.
    """
    compile(case.post_src, f"{case.case_id}/post.py", "exec")
    if case.pre_src is not None:
        compile(case.pre_src, f"{case.case_id}/pre.py", "exec")


@pytest.mark.parametrize("case", load_cases(), ids=lambda c: c.case_id)
def test_case_builds_a_usable_change_unit(case: CorpusCase) -> None:
    """What an agent receives is a `ChangeUnit`, indistinguishable from a real one."""
    unit = case.unit
    assert unit.unit_id == case.case_id
    assert unit.repo == CORPUS_REPO
    assert unit.post_src == case.post_src
    assert unit.changed_lines, "a case with no changed line is not a change"
    assert min(unit.changed_lines) >= unit.start_line
    assert max(unit.changed_lines) <= unit.start_line + len(unit.post_src.splitlines())
    assert unit.base_sha and unit.head_sha


@pytest.mark.parametrize("case", load_cases(), ids=lambda c: c.case_id)
def test_expected_key_is_a_contract_key(case: CorpusCase) -> None:
    """The corpus never hand-rolls a key (D-019), so it must satisfy the same shape.

    Storage enforces `^[0-9a-f]{16}$` as a CHECK constraint (D-026). A corpus key that
    could not be stored would be a corpus that cannot be scored against the database.
    """
    key = case.expected_key
    assert len(key) == 16
    assert set(key) <= set("0123456789abcdef")
    assert key == case.unit.key_for(case.cwe)


@pytest.mark.parametrize("case", load_cases(), ids=lambda c: c.case_id)
def test_expected_key_is_constructible_as_evidence(case: CorpusCase) -> None:
    """An agent must be able to emit exactly this finding without a validator rejecting it.

    Cheap, and it closes a real gap: a case whose CWE the contract would refuse on a
    DETECTION is a case no agent can ever be scored as having found.
    """
    evidence = Evidence.detection(
        agent_id="corpus.selftest",
        agent_version="0",
        unit_id=case.case_id,
        finding_key=case.expected_key,
        cwe=case.cwe,
        raw_score=1.0,
    )
    assert evidence.kind is EvidenceKind.DETECTION
    assert evidence.finding_key == case.expected_key


def test_detectable_by_is_authored_only_on_vulnerable_cases() -> None:
    """Safe twins carry no excuse.

    `detectable_by` decides whose miss is forgiven. On a safe case there is nothing to
    miss, so the field would have no meaning and every use of it would be a way to
    forgive a false positive.
    """
    for case in load_cases():
        if case.is_vulnerable:
            assert case.detectable_by, case.case_id
            assert case.detectable_by <= KNOWN_AGENT_IDS, case.case_id
        else:
            assert not case.detectable_by, case.case_id


def test_the_authorisation_cwes_have_no_static_path() -> None:
    """Heterogeneity, asserted rather than assumed (PROJECT_CONTEXT.md §5).

    CWE-862 and CWE-639 are in the corpus to demonstrate that agents fail differently.
    If a static backend were ever listed as able to find one, the demonstration would
    be gone and the four-agent argument would lose its clearest evidence.
    """
    authz = [c for c in load_cases() if c.cwe in {"CWE-862", "CWE-639"} and c.is_vulnerable]
    assert authz, "the heterogeneity cases are missing"
    for case in authz:
        assert "structural.taint" not in case.detectable_by, case.case_id
        assert "structural.semgrep" not in case.detectable_by, case.case_id
        assert "semantic.hosted" in case.detectable_by, (
            f"{case.case_id}: no agent that can reason about intent is listed, so this "
            "case would be excused for everyone and contribute nothing"
        )


def test_every_agent_has_cases_it_is_expected_to_find() -> None:
    """A ratio cannot be fitted for an agent with no positive observations.

    `context.rag` is deliberately the smallest set: it is a corroborating witness, not
    a soloist (PROJECT_CONTEXT.md §5), and the cases where repository precedent is the
    signal are the authorisation ones.
    """
    vulnerable = [c for c in load_cases() if c.is_vulnerable]
    for agent_id in sorted(KNOWN_AGENT_IDS):
        found = [c for c in vulnerable if c.detectable(agent_id)]
        assert found, f"{agent_id} is expected to find nothing in the whole corpus"


def test_no_case_carries_pr_prose() -> None:
    """`PRContext` is separate and stays separate (D-014).

    Attacker-controlled text absent from corpus cases is exactly why it was pulled out
    of `ChangeUnit`. A corpus case that smuggled it back in would make corpus runs
    structurally different from production runs.
    """
    assert not hasattr(CorpusCase, "pr_context")
    for case in load_cases():
        assert "pr_context" not in case.unit.model_dump()
