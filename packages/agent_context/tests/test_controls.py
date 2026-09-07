"""Reading a function's control surface, and choosing a CWE for a missing one."""

from __future__ import annotations

import pytest

from codesheriff_contracts import IN_SCOPE_CWES
from context_agent.classify import COVERED_CWES, cwe_for
from context_agent.controls import (
    Control,
    ControlKind,
    UnsupportedLanguageError,
    control_surface,
)


def names(source: str, kind: ControlKind | None = None) -> set[str]:
    return {c.name for c in control_surface(source) if kind is None or c.kind is kind}


# -- the surface ---------------------------------------------------------------------------


def test_decorators_are_read_with_their_arguments_stripped() -> None:
    """`@require_owner("attachment_id")` and `@require_owner` are one control.

    A repository that tightens a decorator's argument has not removed a guard.
    """
    source = (
        '@bp.get("/attachments/<int:aid>")\n'
        '@require_owner("attachment_id")\n'
        "def download(aid):\n"
        "    return send_file(Attachment.get(aid).path)\n"
    )
    assert names(source, ControlKind.DECORATOR) == {"bp.get", "require_owner"}


def test_a_decorator_named_in_a_comment_or_a_string_is_not_a_control() -> None:
    """The substring bug this module exists to not have (`AUDIT.md` 3.7, 3.3).

    The superseded analyzer scanned source text for `@require_csrf_token`, which finds it in a
    comment, in a docstring, and in an identifier that merely contains it.
    """
    source = (
        "def handler(request):\n"
        '    """Historically this was @admin_required; see #412."""\n'
        "    # TODO: restore @admin_required\n"
        '    note = "@admin_required"\n'
        "    has_admin_required = False\n"
        "    return note\n"
    )
    assert "admin_required" not in names(source)


def test_a_nested_helper_s_decorator_does_not_guard_the_outer_function() -> None:
    """D-049: the unit is the outermost function.

    A guard applied to a closure does not run when the enclosing function is called, and
    counting it would let a function be credited with a control it never applies.
    """
    source = (
        "def outer(request):\n"
        "    @admin_required\n"
        "    def inner():\n"
        "        return 1\n"
        "    return inner\n"
    )
    assert "admin_required" not in names(source, ControlKind.DECORATOR)


def test_calls_in_the_body_are_read_as_controls_too() -> None:
    """A repository that guards with an entry call has established its convention just as
    firmly as one that guards with a decorator."""
    source = (
        "def set_flag(name):\n    ensure_staff(request.user)\n    return FeatureFlag.upsert(name)\n"
    )
    assert {"ensure_staff", "FeatureFlag.upsert"} <= names(source, ControlKind.GUARD_CALL)


def test_a_chained_call_yields_the_method_actually_invoked() -> None:
    """Slicing the source gave `Query.filter(x >= y).all` — a name no other excerpt can ever
    produce, so every such call would read as a control unique to one function."""
    source = "def q():\n    return Model.query.filter(Model.at >= since).all()\n"
    assert "Model.query.filter.all" in names(source)
    assert not any(">=" in name for name in names(source))


def test_a_method_keeps_its_indentation_and_still_parses() -> None:
    """Corpus cases and precedent excerpts hold methods with their leading indentation."""
    source = (
        '    @permission_required("team:manage")\n'
        "    def remove_member(self, team_id, user_id):\n"
        "        return self.repo.save(team_id)\n"
    )
    assert "permission_required" in names(source, ControlKind.DECORATOR)
    assert "self.repo.save" in names(source, ControlKind.GUARD_CALL)


def test_source_with_no_function_yields_no_controls_rather_than_raising() -> None:
    """A `<module>` unit is a legitimate unit (D-049) with no decorators to read."""
    assert control_surface("API_KEY = 'sk-live-1234'\n") == frozenset()


def test_a_language_with_no_control_model_raises_rather_than_guessing() -> None:
    with pytest.raises(UnsupportedLanguageError):
        control_surface("function f(){}", language="javascript")


# -- the classifier ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("admin_required", "CWE-862"),
        ("permission_required", "CWE-862"),
        ("requires_scope", "CWE-862"),
        ("ensure_staff", "CWE-862"),
        ("login_required", "CWE-862"),
        ("has_role", "CWE-862"),
        ("require_owner", "CWE-639"),
        ("assert_owner", "CWE-639"),
        ("belongs_to_current_user", "CWE-639"),
    ],
)
def test_authorization_controls_map_to_their_cwe(name: str, expected: str) -> None:
    assert cwe_for(Control(ControlKind.DECORATOR, name)) == expected


@pytest.mark.parametrize(
    "name",
    [
        "rate_limit",  # availability, not authorization
        "throttle",
        "log_access",  # observability; and the reason there is no bare `access` token
        "audit_log",
        "escape",  # a real control, and CWE-79 is not this witness's CWE
        "validate_payload",  # the four commonest verbs are deliberately not tokens
        "check_input",
        "verify_signature",
        "require_json",
        "get_or_404",
        "save",
    ],
)
def test_things_that_are_not_authorization_controls_map_to_nothing(name: str) -> None:
    """The filter that stops a mined convention from becoming a finding."""
    assert cwe_for(Control(ControlKind.GUARD_CALL, name)) is None


def test_ownership_is_decided_before_general_authorization() -> None:
    """`require_owner` contains no authorization token, but a name could hold both.

    Ownership is the more specific claim and is tested first.
    """
    assert cwe_for(Control(ControlKind.DECORATOR, "admin_or_owner_required")) == "CWE-639"


def test_the_receiver_of_a_call_does_not_decide_the_cwe() -> None:
    """Classification is on the last dotted segment, where a function's intent lives.

    `AdminUser.query.get` is a lookup, not an access control, and the class it hangs off is
    named after data.
    """
    assert cwe_for(Control(ControlKind.GUARD_CALL, "AdminUser.query.get")) is None


def test_covered_cwes_matches_the_classifier() -> None:
    """D-006. A witness whose silence covered more than it can detect would suppress other
    witnesses' findings on CWEs it never looked for."""
    reachable = {
        cwe_for(Control(ControlKind.DECORATOR, name))
        for name in ("admin_required", "require_owner")
    }
    assert COVERED_CWES == {c for c in reachable if c} <= IN_SCOPE_CWES
