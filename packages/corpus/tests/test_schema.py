"""The validators, exercised on the states they exist to reject.

Every rule here was written because the alternative failure is quiet. A case that
loads with a mistyped agent id, or a twin whose id drifted from its pair, produces a
corpus that scores — just not the thing it claims to score.
"""

from __future__ import annotations

import pytest

from codesheriff_corpus import CorpusCase, Label
from codesheriff_corpus.loader import CorpusError, case_by_id

MINIMAL = {
    "case_id": "cwe-089-example-vuln",
    "pair_id": "cwe-089-example",
    "label": Label.VULNERABLE,
    "cwe": "CWE-89",
    "file": "app/api/users.py",
    "symbol": "get_user",
    "rationale": "An untrusted value is interpolated into SQL.",
    "detectable_by": frozenset({"structural.taint"}),
    "post_src": "def get_user(request):\n    return cursor.execute(f'... {request.args}')\n",
}


def _case(**overrides: object) -> CorpusCase:
    return CorpusCase(**{**MINIMAL, **overrides})  # type: ignore[arg-type]


def test_minimal_case_is_valid() -> None:
    assert _case().is_vulnerable


def test_out_of_scope_cwe_is_rejected() -> None:
    """`IN_SCOPE_CWES` is closed. A corpus case outside it could never be detected
    either, since the contract rejects such a DETECTION at construction."""
    with pytest.raises(ValueError, match="outside IN_SCOPE_CWES"):
        _case(cwe="CWE-200")


def test_case_id_must_follow_its_pair() -> None:
    """Pairing is derived from the id, so a rename cannot orphan a twin silently."""
    with pytest.raises(ValueError, match="must be"):
        _case(case_id="cwe-089-example-vulnerable")
    with pytest.raises(ValueError, match="must be"):
        _case(case_id="cwe-089-example-vuln", label=Label.SAFE, detectable_by=frozenset())


def test_vulnerable_case_needs_at_least_one_agent_that_could_find_it() -> None:
    with pytest.raises(ValueError, match="unscoreable"):
        _case(detectable_by=frozenset())


def test_detectable_by_rejects_an_unknown_agent() -> None:
    """A typo would forgive that agent forever, because nothing would ever match it."""
    with pytest.raises(ValueError, match="unknown agents"):
        _case(detectable_by=frozenset({"structural.tiant"}))


def test_safe_case_may_not_carry_detectable_by() -> None:
    with pytest.raises(ValueError, match="belongs to vulnerable cases"):
        _case(
            case_id="cwe-089-example-safe",
            label=Label.SAFE,
            detectable_by=frozenset({"structural.taint"}),
        )


def test_rationale_is_required() -> None:
    with pytest.raises(ValueError, match="why its label is certain"):
        _case(rationale="   ")


def test_empty_post_src_is_rejected() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        _case(post_src="   \n")


def test_added_function_has_no_pre_image_and_every_line_is_changed() -> None:
    case = _case(pre_src=None, start_line=10)
    assert case.unit.pre_src is None
    assert case.changed_lines == [10, 11]


def test_a_pure_deletion_still_reports_a_changed_line() -> None:
    """The CWE-862 shape: the PR removes a decorator and adds nothing.

    Reporting no changed line would hide the entire signal for the access-control
    CWEs, which is what `decorators` on `ChangeUnit` exists for (D-013).
    """
    case = _case(
        pre_src="@admin_required\ndef export_users():\n    return rows\n",
        post_src="def export_users():\n    return rows\n",
        start_line=44,
    )
    assert case.changed_lines == [44]


def test_case_is_frozen() -> None:
    case = _case()
    with pytest.raises(ValueError, match="frozen"):
        case.rationale = "edited"  # type: ignore[misc]


def test_enclosing_class_reaches_the_qualified_symbol() -> None:
    """Methods key on `Class.method`, and the key must follow (D-013, D-019)."""
    method = _case(enclosing_class="UserRepository")
    assert method.unit.qualified_symbol == "UserRepository.get_user"
    assert method.expected_key != _case().expected_key


def test_unknown_case_id_raises() -> None:
    with pytest.raises(CorpusError, match="no such case"):
        case_by_id("cwe-089-does-not-exist-vuln")


def test_a_real_case_round_trips_through_the_loader() -> None:
    case = case_by_id("cwe-089-user-lookup-vuln")
    assert case.cwe == "CWE-89"
    assert case.is_vulnerable
    assert 'f"SELECT' in case.post_src
    assert case.pre_src is not None
