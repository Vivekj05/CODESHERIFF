"""Reading the corpus off disk.

Cases live inside the package rather than beside it, and are read through
`importlib.resources`, so an installed wheel and a source checkout load the same
corpus. A corpus that only loads from a checkout cannot be verified anywhere else,
which makes `corpus_hash` a claim about one machine.

Layout, one directory per case:

    cases/<cwe-slug>/<pair>-{vuln,safe}/
        case.yaml     labels and unit metadata
        post.py       the unit under analysis
        pre.py        optional; absent for an added function

The source is kept in real `.py` files rather than embedded in the YAML. It is code:
it has to survive tree-sitter, carry honest line numbers, and be reviewable in a
diff. Indentation inside a YAML block scalar is none of those things.

Those files are deliberately vulnerable and are excluded from ruff and mypy in the
root pyproject.toml (D-046). Linting them would either fail the gate or, worse,
pressure someone into fixing the vulnerability the case exists to contain.
"""

from __future__ import annotations

from functools import cache
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Any

import yaml

from codesheriff_corpus.models import CorpusCase, Label

CASES_DIRNAME = "cases"
CASE_MANIFEST = "case.yaml"


class CorpusError(RuntimeError):
    """The corpus on disk is not loadable or not self-consistent.

    Raised rather than tolerated. Every number this project publishes is fitted on
    this data; a corpus that half-loads produces numbers that are quietly wrong.
    """


def cases_root() -> Traversable:
    return files("codesheriff_corpus") / CASES_DIRNAME


def _iter_case_dirs() -> list[Traversable]:
    """Every case directory, in a stable order.

    Sorted by name at both levels: the corpus hash must not depend on the order the
    filesystem happens to hand back directory entries.
    """
    root = cases_root()
    if not root.is_dir():
        raise CorpusError(f"corpus cases directory is missing: {root}")

    found: list[Traversable] = []
    for cwe_dir in sorted(root.iterdir(), key=lambda p: p.name):
        if not cwe_dir.is_dir() or cwe_dir.name.startswith((".", "_")):
            continue
        for case_dir in sorted(cwe_dir.iterdir(), key=lambda p: p.name):
            if not case_dir.is_dir() or case_dir.name.startswith((".", "_")):
                continue
            if not (case_dir / CASE_MANIFEST).is_file():
                raise CorpusError(f"{case_dir.name}: no {CASE_MANIFEST}; not a loadable case")
            found.append(case_dir)
    return found


def _read_optional(case_dir: Traversable, name: str) -> str | None:
    target = case_dir / name
    return target.read_text(encoding="utf-8") if target.is_file() else None


def _load_case_dir(case_dir: Traversable) -> CorpusCase:
    raw: Any = yaml.safe_load((case_dir / CASE_MANIFEST).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise CorpusError(f"{case_dir.name}/{CASE_MANIFEST} is not a mapping")

    post_src = _read_optional(case_dir, "post.py")
    if post_src is None:
        raise CorpusError(f"{case_dir.name}: post.py is the unit under analysis and is required")

    try:
        case = CorpusCase(**raw, post_src=post_src, pre_src=_read_optional(case_dir, "pre.py"))
    except Exception as exc:
        raise CorpusError(f"{case_dir.name}: {exc}") from exc

    if case.case_id != case_dir.name:
        raise CorpusError(
            f"{case_dir.name}: declares case_id {case.case_id!r}. The directory name is the "
            "id, so a rename cannot silently orphan a split assignment."
        )
    return case


@cache
def load_cases() -> tuple[CorpusCase, ...]:
    """Every case, ordered by `case_id`. Cached — the corpus does not change at runtime."""
    cases = tuple(sorted((_load_case_dir(d) for d in _iter_case_dirs()), key=lambda c: c.case_id))

    seen: set[str] = set()
    for case in cases:
        if case.case_id in seen:
            raise CorpusError(f"duplicate case_id: {case.case_id}")
        seen.add(case.case_id)
    return cases


def load_pairs() -> dict[str, tuple[CorpusCase, CorpusCase]]:
    """Twin pairs as `pair_id -> (vulnerable, safe)`.

    A pair missing a member is an error, not a partial result. An unpaired vulnerable
    case measures detection with no measure of false positives, which is the reading
    this project exists to argue against.
    """
    grouped: dict[str, dict[Label, CorpusCase]] = {}
    for case in load_cases():
        members = grouped.setdefault(case.pair_id, {})
        if case.label in members:
            raise CorpusError(f"{case.pair_id}: two {case.label.value} members")
        members[case.label] = case

    pairs: dict[str, tuple[CorpusCase, CorpusCase]] = {}
    for pair_id, members in sorted(grouped.items()):
        missing = {Label.VULNERABLE, Label.SAFE} - set(members)
        if missing:
            raise CorpusError(
                f"{pair_id}: no {'/'.join(sorted(m.value for m in missing))} twin. "
                "Every vulnerable case ships with a safe twin (PROJECT_CONTEXT.md §5)."
            )
        pairs[pair_id] = (members[Label.VULNERABLE], members[Label.SAFE])
    return pairs


def case_by_id(case_id: str) -> CorpusCase:
    for case in load_cases():
        if case.case_id == case_id:
            return case
    raise CorpusError(f"no such case: {case_id}")
