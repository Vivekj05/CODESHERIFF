"""The rule catalog: what is a source, what is a sink, and what makes a value safe.

Three things changed here in Chapter 10, and each closes an audit finding.

**Rules match AST nodes, not lines of text** (`AUDIT.md` 3.3). A sink pattern is `fullmatch`ed
against the *callee* of a call expression, so `# TODO: replace os.system with subprocess` matches
nothing at all and `eval` no longer matches the identifier `evaluate`. Keyword predicates read the
call's actual keyword arguments, so a `shell=True` or a `Loader=SafeLoader` on the following line
is seen — the old same-line regex could not see either.

**A sink has a class, and a sanitizer clears classes** (`AUDIT.md` 3.4). `RuleSanitizer.clears` was
declared and never read: any sanitizer between a source and a sink suppressed the finding whatever
they were, so an `html.escape` anywhere in a function silenced its `os.system`. The class is now the
thing that decides whether a sanitizer applies.

**A sink names its dangerous argument positions** (`AUDIT.md` 3.5). That is how parameterised SQL is
modelled — as a property of the `execute` call, never as a sanitizer, which is what §5 requires.

`extra="forbid"` on every model, deliberately. The old models used `extra="ignore"`, so adding
`class:` to a YAML rule would have been silently dropped and the rule would have gone on behaving
like the one it was meant to replace. A typo in a rule file must fail loudly, not analyse quietly.
"""

from __future__ import annotations

import logging
import re
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)


class SinkClass(StrEnum):
    """What kind of harm a sink does, and therefore what has to be cleared to make it safe."""

    INJECTION = "injection"
    """SQL and other query languages. Cleared by nothing except not building the query."""

    COMMAND = "command"
    XSS = "xss"
    PATH = "path"
    DESERIALIZATION = "deserialization"
    CODE = "code"
    SSRF = "ssrf"
    """Not in the six §5 lists, and required: CWE-918 is in `IN_SCOPE_CWES` and its sinks are
    neither command nor injection. A URL-encoding sanitizer clears `xss` and `path` and must not
    clear this one — an encoded link to the metadata service still reaches it."""


ALL_CLASSES: frozenset[SinkClass] = frozenset(SinkClass)

_CLEARS_ALL = "all"

_DOTTED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


def dotted_suffixes(callee: str) -> list[str]:
    """`a.b.c` -> `[a.b.c, b.c, c]`; anything that is not a dotted name -> `[]`.

    Suffixes are what let one rule cover `session.execute` and `self.session.execute` without a
    pattern that would also match a comment. The empty list for a non-name is what keeps a chained
    call like `cursor.execute(q).fetchone` from being matched as a callee — its inner `call` node
    is visited separately and matched properly.
    """
    if not _DOTTED.fullmatch(callee):
        return []
    parts = callee.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


def _compile(pattern: str, rule_id: str) -> re.Pattern[str] | None:
    try:
        return re.compile(pattern)
    except re.error as exc:
        logger.error("Rule %s has an invalid pattern %r: %s", rule_id, pattern, exc)
        return None


class RuleSource(BaseModel):
    """An expression whose value came from outside the trust boundary."""

    model_config = ConfigDict(extra="forbid")

    id: str
    match: str

    def matches(self, expression_text: str) -> bool:
        """Prefix match, so `request.args` covers `request.args.get("id", "")`."""
        compiled = _compile(self.match, self.id)
        return bool(compiled and compiled.match(expression_text))


class RuleSink(BaseModel):
    """A call that does something dangerous with one of its arguments."""

    model_config = ConfigDict(extra="forbid")

    id: str
    match: str
    cwe: str
    sink_class: SinkClass = Field(alias="class")
    danger: str = "high"

    args: list[int] = Field(default_factory=lambda: [0])
    """Positional argument indices that are dangerous. Everything else is safe by construction."""

    safe_when: str | None = None
    """The name of the modelling choice `args` encodes, for the reader and the explanation.

    `params_passed_separately` on `sql.execute` says: only the statement is a sink, because the
    driver never interpolates the parameter bag. §5 requires this to be a sink property and
    explicitly forbids modelling it as a sanitizer (`AUDIT.md` 3.5)."""

    requires_kwarg: dict[str, str] = Field(default_factory=dict)
    """Sink only when one of these keyword arguments is present and its value matches."""

    forbids_kwarg: dict[str, str] = Field(default_factory=dict)
    """Not a sink when one of these keyword arguments is present and its value matches."""

    forbids_callee: str | None = None
    """Not a sink when the callee also matches this — `json.loads` against a bare `loads`."""

    requires_path_composition: bool = False
    """Sink only when the tainted value was joined onto a base path somewhere on the flow.

    Traversal means escaping a base directory. A function handed a whole path and opening it has
    not been tricked; the caller chose the path, which is the interface."""

    @field_validator("cwe")
    @classmethod
    def _normalise_cwe(cls, value: str) -> str:
        return value.strip().upper()

    def matches_callee(self, callee: str) -> bool:
        compiled = _compile(self.match, self.id)
        if compiled is None:
            return False
        candidates = dotted_suffixes(callee)
        if not any(compiled.fullmatch(candidate) for candidate in candidates):
            return False
        if self.forbids_callee:
            forbidden = _compile(self.forbids_callee, self.id)
            if forbidden and any(forbidden.fullmatch(candidate) for candidate in candidates):
                return False
        return True

    def keywords_allow(self, keywords: dict[str, str]) -> bool:
        """Whether this call's keyword arguments leave it a sink."""
        for name, pattern in self.forbids_kwarg.items():
            value = keywords.get(name)
            compiled = _compile(pattern, self.id)
            if value is not None and compiled and compiled.search(value):
                return False

        if not self.requires_kwarg:
            return True
        for name, pattern in self.requires_kwarg.items():
            value = keywords.get(name)
            compiled = _compile(pattern, self.id)
            if value is not None and compiled and compiled.search(value):
                return True
        return False


class RuleSanitizer(BaseModel):
    """A call that makes its argument safe, for a stated set of sink classes."""

    model_config = ConfigDict(extra="forbid")

    id: str
    match: str
    clears: list[str] = Field(default_factory=list)

    def cleared_classes(self) -> frozenset[SinkClass]:
        """The classes this sanitizer neutralises. `all` means every one of them."""
        if any(entry.strip().lower() == _CLEARS_ALL for entry in self.clears):
            return ALL_CLASSES
        resolved: set[SinkClass] = set()
        for entry in self.clears:
            try:
                resolved.add(SinkClass(entry.strip().lower()))
            except ValueError:
                logger.error("Sanitizer %s clears unknown class %r", self.id, entry)
        return frozenset(resolved)

    def matches_callee(self, callee: str) -> bool:
        compiled = _compile(self.match, self.id)
        if compiled is None:
            return False
        return any(compiled.fullmatch(candidate) for candidate in dotted_suffixes(callee))


class Catalog(BaseModel):
    """Every rule, by language."""

    model_config = ConfigDict(extra="forbid")

    sources: dict[str, list[RuleSource]] = Field(default_factory=dict)
    sinks: dict[str, list[RuleSink]] = Field(default_factory=dict)
    sanitizers: dict[str, list[RuleSanitizer]] = Field(default_factory=dict)

    @classmethod
    def load_from_dir(cls, rules_dir: Path) -> Catalog:
        """Load the three rule files. A malformed rule is logged and skipped, never swallowed."""

        def _load_yaml(path: Path) -> dict[str, Any]:
            if not path.exists():
                logger.error("Rule file missing: %s", path)
                return {}
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                logger.error("Rule file %s is not valid YAML: %s", path, exc)
                return {}
            return data if isinstance(data, dict) else {}

        def _parse(raw: dict[str, Any], model_cls: Any, kind: str) -> dict[str, list[Any]]:
            parsed: dict[str, list[Any]] = {}
            for lang, items in raw.items():
                if not isinstance(items, list):
                    continue
                built = []
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    try:
                        built.append(model_cls(**item))
                    except Exception as exc:
                        # Loudly. A rule that silently fails to load is an agent quietly losing
                        # coverage while still reporting SILENCE over the CWE it can no longer
                        # reach — which is reassurance it has not earned (D-006).
                        logger.error(
                            "Skipping malformed %s rule %r in %s: %s",
                            kind,
                            item.get("id", "<no id>"),
                            lang,
                            exc,
                        )
                parsed[lang] = built
            return parsed

        return cls(
            sources=_parse(_load_yaml(rules_dir / "sources.yml"), RuleSource, "source"),
            sinks=_parse(_load_yaml(rules_dir / "sinks.yml"), RuleSink, "sink"),
            sanitizers=_parse(_load_yaml(rules_dir / "sanitizers.yml"), RuleSanitizer, "sanitizer"),
        )

    def covered_cwes(self, language: str) -> frozenset[str]:
        """The CWEs this catalog's sinks can actually reach, for SILENCE (D-006).

        Derived from the loaded rules rather than written down, so a rule file that failed to load
        narrows what this agent claims to have looked for instead of leaving the claim intact.
        """
        return frozenset(rule.cwe for rule in self.sinks.get(language, []))
