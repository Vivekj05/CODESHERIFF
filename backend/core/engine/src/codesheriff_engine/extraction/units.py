"""Fetched file blobs to `ChangeUnit`s. One unit per changed function.

**Replaces** `codesheriff_engine/github/parser.py`, which is deleted rather than patched. That
module built one unit per *file* with `symbol=None` (`AUDIT.md` 4.1), so `qualified_symbol` was
always `<module>` and every finding anywhere in a file collapsed onto one `finding_key` — the
D-004 failure by a different route, and one the frozen contract cannot prevent on its own because
a null symbol is legitimate for a genuinely module-scope change.

Nothing here touches the network or a database. The caller fetches; this decides what the units
are. That split is what lets Chapter 14 run extraction over corpus cases without an installation
token, and it is why the package sits below `apps/worker` rather than inside it.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from enum import StrEnum

from codesheriff_contracts import ChangeUnit
from codesheriff_engine.extraction.diffing import changed_line_numbers
from codesheriff_engine.extraction.python import PythonFile, PythonSymbol, parse_python_file

logger = logging.getLogger(__name__)

PYTHON_SUFFIXES: frozenset[str] = frozenset({".py", ".pyi"})
"""Python only, per §6's "Python-first" scope. JS/TS support is unscheduled, and the honest
behaviour for an unscheduled language is a recorded skip — not a unit nothing can analyse."""

_UNIT_ID_SYMBOL_BUDGET = 120


class SkipReason(StrEnum):
    """Why a changed file produced no unit. Recorded, never silent.

    The superseded parser dropped a file for three different reasons with one bare `continue` each
    and told nobody, so "this pull request is clean" and "we did not look at this pull request"
    rendered identically — `AUDIT.md` 4.4 in another module. A skip is a fact about the audit's
    coverage and belongs in its record.
    """

    FILE_REMOVED = "file_removed"
    """Deleted by the pull request. There is no post-image to analyse."""

    LANGUAGE_UNSUPPORTED = "language_unsupported"
    """Not Python. In scope for the project, not for this extractor."""

    CONTENT_UNAVAILABLE = "content_unavailable"
    """The head blob could not be fetched: over the fetch budget, binary, or gone."""

    NO_CHANGED_LINES = "no_changed_lines"
    """The two blobs are identical. GitHub lists a file whose only change was a rename or a mode
    change, and diffing the content is what reveals there is nothing to analyse."""


@dataclass(frozen=True)
class FetchedFile:
    """One changed file of a pull request, with both versions already fetched.

    `post_src` is None when there is nothing to analyse at the head commit: the file was deleted,
    or the caller could not fetch it. `pre_src` is None when the file is new.

    Neither is ever a diff fragment. A caller tempted to synthesise one of these from a patch is
    about to reintroduce `AUDIT.md` 4.2, and the unit built from it would be worse than no unit.
    """

    path: str
    status: str
    post_src: str | None = None
    pre_src: str | None = None
    unavailable_reason: SkipReason | None = None
    """Set by the caller when it could not fetch the head blob, so the skip records why rather
    than falling back to the generic case."""


@dataclass(frozen=True)
class SkippedFile:
    path: str
    reason: SkipReason


@dataclass
class ExtractionResult:
    """What the audit will analyse, and what it will not."""

    units: list[ChangeUnit] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)


def is_analysable_path(path: str) -> bool:
    """Whether this extractor can produce units from this file.

    Exported so the fetching caller can decide what to *fetch* using the same rule that decides
    what to extract. Two predicates would drift, and the drift would be invisible: the caller would
    fetch a file this module then skips, or skip one it would have analysed.
    """
    return any(path.endswith(suffix) for suffix in PYTHON_SUFFIXES)


def is_test_path(path: str) -> bool:
    """Whether this file looks like a test.

    Downweighted by the taint engine in Chapter 10, never suppressed: a hard-coded credential in a
    fixture is still a hard-coded credential, and test helpers are where the least careful
    `os.system` calls live.
    """
    lower = path.lower()
    markers = ("test_", "_test.", "/tests/", "/test/", "/spec/", "_spec.", ".test.", ".spec.")
    return any(marker in lower for marker in markers)


def unit_id_for(path: str, qualified_symbol: str) -> str:
    """A stable id for one function in one file.

    Readable at the front so a log line names the function, hashed at the back so the id is
    bounded — `change_units.unit_id` is `String(255)`, and a deep path with a long method name can
    exceed it. The hash covers the *full* path and symbol, so two units cannot collide on a
    truncated prefix.

    Deterministic across audits on purpose: a function keeps its id from one push to the next,
    which is what lets `change_units.post_src_sha256` recognise an unchanged unit and reuse its
    evidence rather than pay the semantic agent for it again.
    """
    digest = hashlib.sha256(f"{path}::{qualified_symbol}".encode()).hexdigest()[:12]
    return f"{qualified_symbol[:_UNIT_ID_SYMBOL_BUDGET]}@{digest}"


def extract_units(
    files: list[FetchedFile],
    *,
    repo: str,
    base_sha: str,
    head_sha: str,
) -> ExtractionResult:
    """Every changed function across a pull request, plus what was skipped and why."""
    result = ExtractionResult()
    for changed in files:
        result.units.extend(_units_for_file(changed, repo, base_sha, head_sha, result.skipped))
    return result


def _units_for_file(
    changed: FetchedFile,
    repo: str,
    base_sha: str,
    head_sha: str,
    skipped: list[SkippedFile],
) -> list[ChangeUnit]:
    def skip(reason: SkipReason) -> list[ChangeUnit]:
        logger.info("No units from %s: %s", changed.path, reason.value)
        skipped.append(SkippedFile(path=changed.path, reason=reason))
        return []

    if changed.status == "removed":
        return skip(SkipReason.FILE_REMOVED)
    if not is_analysable_path(changed.path):
        return skip(SkipReason.LANGUAGE_UNSUPPORTED)
    if changed.post_src is None:
        return skip(changed.unavailable_reason or SkipReason.CONTENT_UNAVAILABLE)

    post_src = changed.post_src
    changed_lines = changed_line_numbers(changed.pre_src, post_src)
    if not changed_lines:
        return skip(SkipReason.NO_CHANGED_LINES)

    post = parse_python_file(post_src)
    pre = parse_python_file(changed.pre_src) if changed.pre_src is not None else None
    is_test = is_test_path(changed.path)

    module_lines: list[int] = []
    touched: dict[str, list[int]] = {}
    for line in changed_lines:
        symbol = post.symbol_for(line)
        if symbol is None:
            module_lines.append(line)
        else:
            touched.setdefault(qualified(symbol.enclosing_class, symbol.name), []).append(line)

    units: list[ChangeUnit] = []
    for name, symbol in _one_symbol_per_name(post).items():
        lines = touched.get(name)
        if not lines:
            continue
        units.append(
            _function_unit(changed, symbol, lines, post, pre, repo, base_sha, head_sha, is_test)
        )

    if module_lines:
        units.append(
            _module_unit(changed, post_src, module_lines, post, repo, base_sha, head_sha, is_test)
        )
    return units


def _function_unit(
    changed: FetchedFile,
    symbol: PythonSymbol,
    lines: list[int],
    post: PythonFile,
    pre: PythonFile | None,
    repo: str,
    base_sha: str,
    head_sha: str,
    is_test: bool,
) -> ChangeUnit:
    """One changed function. `post_src` is that function's real source, at its real line numbers."""
    return ChangeUnit(
        unit_id=unit_id_for(changed.path, qualified(symbol.enclosing_class, symbol.name)),
        repo=repo,
        language="python",
        file=changed.path,
        symbol=symbol.name,
        enclosing_class=symbol.enclosing_class,
        decorators=list(symbol.decorators),
        # The pre-image of *this function*, not of the diff, matched by qualified name — so a
        # function that merely moved down the file still has a before, and a genuinely new one
        # correctly has none, which is what `pre_src: str | None` means in the contract.
        pre_src=_previous_source(pre, symbol),
        post_src=symbol.source,
        changed_lines=lines,
        start_line=symbol.start_line,
        imports=list(post.imports),
        base_sha=base_sha,
        head_sha=head_sha,
        is_test_file=is_test,
    )


def _module_unit(
    changed: FetchedFile,
    post_src: str,
    lines: list[int],
    post: PythonFile,
    repo: str,
    base_sha: str,
    head_sha: str,
    is_test: bool,
) -> ChangeUnit:
    """A change with no enclosing function is still a change.

    Hard-coded credentials (CWE-798) sit at module scope more often than not, and this unit is the
    only way an agent ever sees one. The whole file is the unit, untruncated by construction:
    oversized units are for the agent to abstain on and never for extraction to trim.

    `changed_lines` holds only the lines outside every function, because the lines inside one are
    already carried by that function's own unit. Overlapping them would present one edit to fusion
    twice under two keys.
    """
    return ChangeUnit(
        unit_id=unit_id_for(changed.path, "<module>"),
        repo=repo,
        language="python",
        file=changed.path,
        symbol=None,
        pre_src=changed.pre_src,
        post_src=post_src,
        changed_lines=lines,
        start_line=1,
        imports=list(post.imports),
        base_sha=base_sha,
        head_sha=head_sha,
        is_test_file=is_test,
    )


def qualified(enclosing_class: str | None, name: str) -> str:
    """Mirrors `ChangeUnit.qualified_symbol`, for the unit id and pre-image matching only.

    Every `finding_key` is still built by `ChangeUnit.key_for` (D-019). This is not a second way of
    naming a symbol for keying — it is how two *versions* of a file are matched to each other,
    which happens before any `ChangeUnit` exists to ask.
    """
    return f"{enclosing_class}.{name}" if enclosing_class else name


def _one_symbol_per_name(parsed: PythonFile) -> dict[str, PythonSymbol]:
    """One symbol per qualified name, keeping the longest definition.

    A file can define the same qualified name more than once: `@overload` stubs above the real
    implementation, a `def` in each branch of `if TYPE_CHECKING`, a redefinition. All of them
    produce the *same* `finding_key`, because a key is file, qualified symbol and CWE (D-004). Two
    units would therefore hand fusion one agent's opinion about one key twice, applying that
    agent's likelihood ratio twice to a single finding — the multiple-counting D-019 closed for the
    static backends, arriving from the extraction side instead. It would also collide on
    `change_units`' UNIQUE (audit_id, unit_id) and fail the audit outright.

    The **last** definition wins, because that is the one Python binds: `@overload` stubs are
    written above the implementation, and a redefinition replaces what came before it. Preferring
    the longest definition instead would look reasonable and pick the stub whenever the two happen
    to be the same length — a signature and an ellipsis, analysed in place of the body, finding
    nothing and reporting that as silence.
    """
    best: dict[str, PythonSymbol] = {}
    for symbol in parsed.symbols:
        best[qualified(symbol.enclosing_class, symbol.name)] = symbol
    return best


def _previous_source(pre: PythonFile | None, symbol: PythonSymbol) -> str | None:
    if pre is None:
        return None
    match = _one_symbol_per_name(pre).get(qualified(symbol.enclosing_class, symbol.name))
    return match.source if match is not None else None
