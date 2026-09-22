"""Which lines a change touched, derived from the two file versions themselves.

**GitHub's `patch` field is not read anywhere in this package, and that is deliberate.**
The previous parser reconstructed `post_src` by concatenating hunk fragments, which produced
syntactically broken source with wrong line numbers (`AUDIT.md` 4.2), and skipped outright the
files for which GitHub omits `patch` because the diff is too large (`AUDIT.md` 4.1's neighbour at
`parser.py:102`). Both failures share one cause: treating the diff as the source of truth about
the code rather than as a summary of it.

Diffing the two fetched blobs instead removes the large-diff special case structurally — there is
no branch that can skip a file for want of a patch — and it makes production extraction use the
*same* derivation as `codesheriff_corpus.models.CorpusCase.changed_lines`. That parity is not
cosmetic: every likelihood ratio is fitted on corpus units and applied to production units, which
is only sound if the two are the same kind of object.
"""

from __future__ import annotations

import difflib


def changed_line_numbers(pre_src: str | None, post_src: str) -> list[int]:
    """1-based line numbers in `post_src` that this change touched.

    `pre_src` is None for a file that did not exist before, in which case every line is new.

    A pure deletion adds no line to post, so it would otherwise report that nothing changed at
    all. The line the deletion sits against is reported instead — removing `@login_required` is
    the entire signal for the access-control CWEs (D-013), and an extractor that called that "no
    change" would hide the one case class §5 says exists to prove heterogeneity.

    Whitespace-only lines are dropped. A blank line carries no code, and a unit built because one
    appeared is a unit an agent pays to analyse for nothing. This is not truncation: the unit's
    `post_src` is always the whole function, blank lines included. It decides which functions are
    worth looking at, not how much of one an agent gets to see.
    """
    post_lines = post_src.splitlines()
    if pre_src is None:
        return [i for i in range(1, len(post_lines) + 1) if post_lines[i - 1].strip()]

    matcher = difflib.SequenceMatcher(a=pre_src.splitlines(), b=post_lines, autojunk=False)
    changed: set[int] = set()
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue

        introduced = [j + 1 for j in range(j1, j2) if post_lines[j].strip()]
        if introduced:
            changed.update(introduced)
        elif i2 > i1 and post_lines:
            # Code left and nothing of substance took its place. `delete` is the obvious form of
            # this; `replace` is the one that matters, because a removed decorator most often
            # shows up as its line becoming blank rather than as the line disappearing, and
            # treating that as "only whitespace changed" would discard the D-013 signal entirely.
            anchor = _first_code_line(post_lines, j1)
            if anchor is not None:
                changed.add(anchor)
    return sorted(changed)


def _first_code_line(post_lines: list[str], index: int) -> int | None:
    """The 1-based line at or after `index` that holds code, searching backwards if none does.

    A deletion is anchored to a line rather than to the gap it left, and that line has to survive
    the blank-line filter above or the deletion is silently lost. Deleting `@login_required`
    anchors to the `def` beneath it; deleting the last statement of a file anchors to the last
    line of code before the gap.
    """
    for i in range(max(index, 0), len(post_lines)):
        if post_lines[i].strip():
            return i + 1
    for i in range(min(index, len(post_lines)) - 1, -1, -1):
        if post_lines[i].strip():
            return i + 1
    return None
