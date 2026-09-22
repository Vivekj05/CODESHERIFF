"""The Chapter 2 acceptance test: two witnesses, one case number.

This is the property the whole project rests on. Under the v1 contract every one of
these tests failed, because `finding_key` included the sink expression: the taint
engine reported `cursor.execute(q).fetchone()` and the LLM reported `cursor.execute`,
so the same bug produced two keys, every finding was a singleton, and the Bayesian
engine never performed a single update (AUDIT.md 1.1, D-004).
"""

import pytest

from codesheriff_contracts import (
    IN_SCOPE_CWES,
    ChangeUnit,
    Evidence,
    EvidenceKind,
    finding_key,
)
from codesheriff_engine.fusion.bayes import fuse_all_evidence


def test_two_agents_describing_one_bug_produce_one_finding(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """Static and semantic evidence for the same bug fuse into ONE posterior."""
    unit = sample_vulnerable_unit

    # Each agent phrases the sink its own way. Neither wording enters the key.
    static_ev = Evidence.detection(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id=unit.unit_id,
        finding_key=unit.key_for("CWE-89"),
        cwe="CWE-89",
        raw_score=0.95,
        explanation="Taint path reaches cursor.execute(q).fetchone()",
    )
    semantic_ev = Evidence.detection(
        agent_id="semantic.hosted",
        agent_version="0.1.0",
        unit_id=unit.unit_id,
        finding_key=unit.key_for("CWE-89"),
        cwe="CWE-89",
        raw_score=0.90,
        explanation="Untrusted id interpolated into SQL at cursor.execute",
    )

    assert static_ev.finding_key == semantic_ev.finding_key

    results = fuse_all_evidence([static_ev, semantic_ev], prior_p=0.05)

    assert len(results) == 1, "two singletons means the fusion engine never updated"
    fused = results[0]
    assert len(fused.evidence_list) == 2
    assert fused.finding_key == unit.key_for("CWE-89")

    # And the fused posterior must actually exceed either agent alone.
    static_only = fuse_all_evidence([static_ev], prior_p=0.05)[0]
    assert fused.posterior_probability > static_only.posterior_probability


def test_finding_key_ignores_how_the_sink_is_written() -> None:
    """The defect, stated directly as a test."""
    a = finding_key("app/api/users.py", "get_user", "CWE-89")
    b = finding_key("app/api/users.py", "get_user", "cwe-89")
    assert a == b
    assert len(a) == 16


def test_finding_key_still_separates_genuinely_different_findings(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    """Dropping the sink expression must not collapse distinct findings together."""
    unit = sample_vulnerable_unit
    assert unit.key_for("CWE-89") != unit.key_for("CWE-78")
    assert unit.key_for("CWE-89") != finding_key("other/file.py", unit.qualified_symbol, "CWE-89")
    assert unit.key_for("CWE-89") != finding_key(unit.file, "other_symbol", "CWE-89")


def test_qualified_symbol_is_the_single_source_of_the_name() -> None:
    """Methods qualify by class, so two classes' `get` are not one finding."""
    base = dict(
        unit_id="u",
        repo="r",
        language="python",
        file="app/svc.py",
        post_src="def get(self): ...",
        base_sha="a",
        head_sha="b",
    )
    plain = ChangeUnit(symbol="get", **base)
    method = ChangeUnit(symbol="get", enclosing_class="UserService", **base)
    other = ChangeUnit(symbol="get", enclosing_class="AdminService", **base)

    assert plain.qualified_symbol == "get"
    assert method.qualified_symbol == "UserService.get"
    assert method.key_for("CWE-89") != other.key_for("CWE-89")
    assert method.key_for("CWE-89") != plain.key_for("CWE-89")


def test_silence_and_abstention_are_not_the_same_thing() -> None:
    """Three kinds, not two (D-005). The old `abstained: bool` could not say this."""
    silence = Evidence.silence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id="u",
        covered_cwes={"CWE-89", "CWE-78"},
    )
    abstention = Evidence.abstention(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id="u",
        reason="unsupported_language",
    )

    assert silence.kind is not abstention.kind
    assert silence.covers("CWE-89")
    # The taint rules hold nothing for authorisation bugs, so this silence must not
    # be read as reassurance about them (D-006).
    assert not silence.covers("CWE-862")
    assert abstention.covered_cwes == frozenset()


def test_silence_must_declare_what_it_covers() -> None:
    """Silence about CWEs an agent cannot detect is not evidence."""
    with pytest.raises(ValueError, match="covered_cwes"):
        Evidence.silence(
            agent_id="structural.taint",
            agent_version="0.1.0",
            unit_id="u",
            covered_cwes=set(),
        )


def test_non_detections_carry_no_key() -> None:
    """Closes the two raw key formats that bypassed finding_key() (AUDIT.md 1.1)."""
    with pytest.raises(ValueError, match="finding_key"):
        Evidence(
            agent_id="a",
            agent_version="0.1.0",
            unit_id="u",
            kind=EvidenceKind.ABSTENTION,
            reason="internal_error",
            finding_key="abstain:u:internal_error",
        )


def test_detections_outside_the_closed_cwe_set_are_rejected() -> None:
    """IN_SCOPE_CWES is closed (§6). CWE-200 was previously the silent default."""
    assert "CWE-200" not in IN_SCOPE_CWES
    with pytest.raises(ValueError, match="IN_SCOPE_CWES"):
        Evidence.detection(
            agent_id="structural.semgrep",
            agent_version="0.1.0",
            unit_id="u",
            finding_key="a" * 16,
            cwe="CWE-200",
            raw_score=0.5,
        )
