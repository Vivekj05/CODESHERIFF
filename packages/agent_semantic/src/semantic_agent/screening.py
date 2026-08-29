"""Screening model-authored prose before it becomes Evidence.

`AUDIT.md` 0.4: `rationale`, `functional_intent` and `violated_safety_invariant` flowed verbatim
from the model into `Evidence.explanation`, into a markdown table with no pipe-escaping, and into
the pull request comment. The only control was `max_length=400`.

That text is not the model's own idea. It is a function of attacker-controlled source code — the
whole job of this agent is to read untrusted input and write prose about it — so it must be treated
as untrusted output, not as a trusted summary. §5 requires rationales screened so injected strings
are not echoed.

**Two outcomes, and the second one matters.** Ordinary prose is *sanitised*: control characters
removed, markdown made inert, length capped. Prose that looks like it is addressing the reader
rather than describing the code is *rejected* outright, and the caller falls back to a summary
assembled from validated fields. Sanitising an injection attempt would still echo it; the point of
rejection is that some text should not be repeated at all.

**This is a boundary, not a filter chain.** It runs in `mapping.map_finding_to_evidence`, which is
the single place an `LLMFinding` becomes an `Evidence`, so there is no path from the model to a
stored record that skips it.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass

logger = logging.getLogger(__name__)

MAX_PROSE_LENGTH = 400

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_WHITESPACE = re.compile(r"\s+")

_MARKDOWN_INERT = str.maketrans(
    {
        "|": "│",  # a cell separator is how one field becomes three columns
        # The look-alikes are the mechanism, so the ambiguity warning is the point.
        "<": "‹",  # noqa: RUF001 - tag injection, for a renderer that does not escape
        ">": "›",  # noqa: RUF001
        "`": "'",  # an unbalanced code span swallows everything after it
    }
)
"""Rendered as look-alikes rather than escaped.

Escaping depends on the renderer: `\\|` is inert in a GitHub table and literal in a code block, and
the dashboard escapes differently again. Substituting a character that is not markdown syntax
anywhere is correct in every renderer, including ones not written yet (Chapter 16).

Deliberately **only** these four. `[`, `]`, `*`, `_` and `\\` were substituted too, and the cost was
absurd: `get_user` rendered as `getˍuser` and `request.args['id']` — the single most common value of
`untrusted_data_sources` — became `request.args('id')`. Mangling every identifier to defend against
emphasis markers is a bad trade, and the one case that mattered, the `](` of a markdown link, is
*rejected* by `INJECTION_PATTERNS` rather than rewritten."""

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # `(?:\w+\s+){0,3}` because the filler varies and the intent does not: "ignore previous",
    # "ignore the above", "ignore all of the preceding" are one attack with three phrasings.
    (
        "instruction_override",
        re.compile(
            r"\bignore\s+(?:\w+\s+){0,3}(previous|prior|above|preceding|earlier|instruction)",
            re.I,
        ),
    ),
    (
        "instruction_override",
        re.compile(
            r"\bdisregard\s+(?:\w+\s+){0,3}(previous|prior|above|preceding|instruction)",
            re.I,
        ),
    ),
    ("role_injection", re.compile(r"^\s*(system|assistant|user|developer)\s*:", re.I | re.M)),
    ("role_injection", re.compile(r"\byou\s+are\s+(now\s+)?an?\b", re.I)),
    ("role_injection", re.compile(r"\bnew\s+(instructions?|task|role|persona)\b", re.I)),
    ("delimiter_forgery", re.compile(r"</?\s*code_to_analyze", re.I)),
    ("delimiter_forgery", re.compile(r"CODESHERIFF-[A-Z0-9]{8,}", re.I)),
    ("delimiter_forgery", re.compile(r"<\|.*?\|>")),
    ("markdown_link", re.compile(r"\]\s*\(")),
)
"""Patterns that mean the text is addressing a *reader* rather than describing code.

A legitimate rationale says what the code does and which invariant it breaks. It has no reason to
name a role, close a delimiter, or build a link — and `CODESHERIFF-<nonce>` in model output means
the model has echoed the sentinel marking the untrusted region, which is the one string that must
never survive into a record.

**Tags and URI schemes are deliberately not here**, though they were. Rejecting `<script` cost a
real finding on the first live run: the model explained an XSS bug by quoting the payload it had
found, and a security tool that cannot describe `<script>alert(1)</script>` cannot describe
cross-site scripting. They are *sanitised* instead — `_MARKDOWN_INERT` turns `<` and `>` into
characters that are not markup in any renderer, which defuses them without silencing the
explanation.

The one that stays a rejection is `](`, because `[` and `]` are no longer substituted: a markdown
link is the one construct here that survives sanitising and renders as something clickable.
"""


@dataclass(frozen=True)
class ScreenResult:
    """Screened prose, and whether it survived."""

    text: str
    rejected: bool = False
    reason: str = ""

    def __bool__(self) -> bool:
        return not self.rejected and bool(self.text)


def screen(value: str, *, field: str = "prose", max_length: int = MAX_PROSE_LENGTH) -> ScreenResult:
    """Sanitise model prose, or reject it if it is addressing the reader.

    Rejection returns empty text and a machine-readable reason. The caller decides what to render
    instead; this function never invents a substitute, because a placeholder chosen here would end
    up looking like something the model said.
    """
    if not value or not value.strip():
        return ScreenResult(text="", rejected=False)

    # Normalise first. Without this, a pattern can be evaded with a combining character or a
    # full-width colon, and the comparison below would run against a different string than the one
    # a reader eventually sees.
    normalised = unicodedata.normalize("NFKC", value)

    for reason, pattern in INJECTION_PATTERNS:
        if pattern.search(normalised):
            logger.warning(
                "Rejected model %s: matched %s. The finding survives; its prose does not.",
                field,
                reason,
            )
            return ScreenResult(text="", rejected=True, reason=reason)

    cleaned = _CONTROL.sub("", normalised)
    cleaned = _WHITESPACE.sub(" ", cleaned).strip()
    cleaned = cleaned.translate(_MARKDOWN_INERT)

    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 1].rstrip() + "…"

    return ScreenResult(text=cleaned)


def screen_all(values: list[str], *, field: str, limit: int = 8) -> list[str]:
    """Screen a list, dropping anything rejected. Used for `untrusted_data_sources`."""
    kept: list[str] = []
    for value in values[:limit]:
        result = screen(value, field=field, max_length=120)
        if result:
            kept.append(result.text)
    return kept
