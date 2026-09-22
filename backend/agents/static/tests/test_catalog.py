"""Rule loading and rule matching.

Matching is where `AUDIT.md` 3.3 lived: patterns were `re.search`ed against raw lines, so a comment
was a sink and `eval` matched `evaluate`. These tests pin the callee-matching behaviour that
replaced it, and the `extra="forbid"` that stops a mistyped field being silently dropped.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from static_agent.config import StaticConfig
from static_agent.taint.catalog import (
    ALL_CLASSES,
    Catalog,
    RuleSanitizer,
    RuleSink,
    SinkClass,
    dotted_suffixes,
)

CATALOG = Catalog.load_from_dir(StaticConfig().rules_dir)


def sink(rule_id: str) -> RuleSink:
    return next(rule for rule in CATALOG.sinks["python"] if rule.id == rule_id)


# -- loading -----------------------------------------------------------------------------------


def test_the_shipped_catalog_loads() -> None:
    assert CATALOG.sinks["python"]
    assert CATALOG.sources["python"]
    assert CATALOG.sanitizers["python"]


def test_every_sink_declares_a_class() -> None:
    """A sink with no class cannot be reasoned about by any sanitizer."""
    assert all(isinstance(rule.sink_class, SinkClass) for rule in CATALOG.sinks["python"])


def test_covered_cwes_comes_from_the_rules_that_loaded() -> None:
    """Derived, not written down: a rule file that fails to load narrows what this agent claims
    to have looked for, instead of leaving the claim intact (D-006)."""
    covered = CATALOG.covered_cwes("python")

    assert {"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502", "CWE-918"} == covered
    # The three it has no rules for. Claiming them would suppress every semantic-only finding.
    assert not covered & {"CWE-862", "CWE-639", "CWE-798"}


def test_an_unknown_field_is_rejected_rather_than_ignored() -> None:
    """`extra="ignore"` meant adding `class:` to a YAML rule was silently dropped, and the rule
    went on behaving like the one it was meant to replace."""
    with pytest.raises(ValidationError):
        RuleSink(id="x", match="y", cwe="CWE-89", **{"class": "injection", "clazz": "typo"})


def test_parameterised_sql_is_not_a_sanitizer() -> None:
    """`AUDIT.md` 3.5 and §5. As a sanitizer it cleared taint for the whole function, so one safe
    `execute(q, (uid,))` excused every vulnerable `execute(f"...{x}")` after it."""
    ids = {rule.id for rule in CATALOG.sanitizers["python"]}

    assert not any("parameter" in rule_id or "sql" in rule_id for rule_id in ids)
    assert sink("sql.execute").args == [0]
    assert sink("sql.execute").safe_when == "params_passed_separately"


# -- callee matching ---------------------------------------------------------------------------


def test_dotted_suffixes_lets_one_rule_cover_a_receiver_chain() -> None:
    assert dotted_suffixes("self.session.execute") == [
        "self.session.execute",
        "session.execute",
        "execute",
    ]


def test_a_chained_call_is_not_matched_as_a_callee() -> None:
    """`cursor.execute(q).fetchone` is not a dotted name; its inner call is visited separately."""
    assert dotted_suffixes("cursor.execute(q).fetchone") == []


def test_eval_does_not_match_evaluate() -> None:
    """`AUDIT.md` 3.3 named this one: the JS rule `\\beval` matched `evaluate` and `evalContext`."""
    rule = sink("code.exec")

    assert rule.matches_callee("eval")
    assert not rule.matches_callee("evaluate")
    assert not rule.matches_callee("evalContext")


def test_json_loads_is_not_a_deserialisation_sink() -> None:
    """It is the *fix* in the safe member of `cwe-502-cache-get`."""
    assert not sink("pickle.loads").matches_callee("json.loads")
    assert sink("pickle.loads").matches_callee("pickle.loads")


def test_a_safe_yaml_loader_disarms_the_sink() -> None:
    rule = sink("yaml.unsafe_load")

    assert rule.keywords_allow({"Loader": "yaml.Loader"})
    assert not rule.keywords_allow({"Loader": "SafeLoader"})
    assert not rule.keywords_allow({"Loader": "yaml.CSafeLoader"})


def test_subprocess_is_only_a_sink_with_a_shell() -> None:
    rule = sink("subprocess.shell")

    assert rule.matches_callee("subprocess.run")
    assert rule.keywords_allow({"shell": "True"})
    assert not rule.keywords_allow({})
    assert not rule.keywords_allow({"capture_output": "True"})


def test_a_response_is_only_an_xss_sink_when_it_is_html() -> None:
    rule = sink("xss.html_response")

    assert rule.keywords_allow({"mimetype": "text/html"})
    assert rule.keywords_allow({"content_type": "text/html; charset=utf-8"})
    assert not rule.keywords_allow({"mimetype": "application/json"})
    assert not rule.keywords_allow({"status": "204"})


# -- sanitizer classes -------------------------------------------------------------------------


def test_clears_all_means_every_class() -> None:
    assert RuleSanitizer(id="c", match="int", clears=["all"]).cleared_classes() == ALL_CLASSES


def test_clears_resolves_named_classes_only() -> None:
    resolved = RuleSanitizer(id="c", match="escape", clears=["xss"]).cleared_classes()
    assert resolved == frozenset({SinkClass.XSS})


def test_url_encoding_does_not_clear_ssrf() -> None:
    """An encoded link to the metadata service still reaches it."""
    rule = next(r for r in CATALOG.sanitizers["python"] if r.id == "url.quote")
    cleared = rule.cleared_classes()

    assert SinkClass.XSS in cleared
    assert SinkClass.SSRF not in cleared


def test_a_bare_quote_is_not_a_shell_sanitizer() -> None:
    """`urllib.parse.quote` would match a bare `quote`, and percent-encoding a string does not
    make it safe to hand to a shell."""
    rule = next(r for r in CATALOG.sanitizers["python"] if r.id == "shell.quote")

    assert rule.matches_callee("shlex.quote")
    assert not rule.matches_callee("urllib.parse.quote")


def test_an_allowlist_receiver_must_look_like_a_constant() -> None:
    rule = next(r for r in CATALOG.sanitizers["python"] if r.id == "allowlist.mapping_lookup")

    assert rule.matches_callee("SORT_COLUMNS.get")
    assert not rule.matches_callee("self.redis.get"), "an instance attribute is not an allowlist"


# -- sources -----------------------------------------------------------------------------------


def test_a_source_matches_by_prefix() -> None:
    rule = next(r for r in CATALOG.sources["python"] if r.id == "http.flask_request")

    assert rule.matches("request.args")
    assert rule.matches('request.args.get("id", "")')
    assert not rule.matches("requests.get")


def test_environment_variables_are_not_a_source() -> None:
    """Operator-controlled, not attacker-controlled — and the *fix* in
    `cwe-798-warehouse-connect`."""
    assert not any(rule.matches("os.environ['X']") for rule in CATALOG.sources["python"])
    assert not any(rule.matches("sys.argv[1]") for rule in CATALOG.sources["python"])
