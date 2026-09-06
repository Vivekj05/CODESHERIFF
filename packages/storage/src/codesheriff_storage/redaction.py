"""Excerpt budgets. Nothing reaches the database without passing through here.

PROJECT_CONTEXT.md §6: persisted records hold findings, evidence and hashes — never full file
contents. Two things resist that literally. A taint-path artifact is a list of steps naming the
lines it walked, and that artifact *is* the explanation rendered into the pull request comment. A
RAG precedent chunk has to hold the text it was embedded from, or retrieval can neither be shown
as evidence nor re-embedded when the model changes.

D-027 resolves it as bounded excerpts: a capped number of capped-length lines, never a whole file
and never a whole diff. The caps live here, in one place, and are applied by `mapping.py` and by
the precedent writer rather than left to each call site.

Truncating an excerpt is not the truncation D-015 forbids. That rule protects *analysis input* —
an agent must abstain rather than reason about half a function. This truncates an explanation
already produced from the whole unit, and says so where it cuts.
"""

from __future__ import annotations

from typing import Any

MAX_EXCERPT_LINE_CHARS = 300
"""One excerpt line. Long enough for a realistic statement, short enough that a minified bundle or
a base64 blob cannot ride in on it."""

MAX_EXCERPT_LINES = 20
"""Lines per excerpt. A taint path long enough to need more than this is not an explanation."""

MAX_ARTIFACTS_BYTES = 8192
"""Serialised artifacts per evidence row."""

MAX_CHUNK_BYTES = 4096
"""One precedent chunk. Also a CHECK constraint on `precedent_chunks.content`."""

MAX_CHUNK_LINES = 60
"""Lines per precedent chunk — a function-sized excerpt, not a file."""

TRUNCATION_MARKER = "… [truncated by CodeSheriff excerpt budget]"


def truncate_line(text: str, limit: int = MAX_EXCERPT_LINE_CHARS) -> str:
    """Clip one line, marking the cut."""
    if len(text) <= limit:
        return text
    return text[:limit] + TRUNCATION_MARKER


def truncate_excerpt(
    text: str,
    max_lines: int = MAX_EXCERPT_LINES,
    max_line_chars: int = MAX_EXCERPT_LINE_CHARS,
) -> str:
    """Clip a multi-line excerpt to the budget, marking every cut it makes."""
    lines = text.splitlines()
    kept = [truncate_line(line, max_line_chars) for line in lines[:max_lines]]
    if len(lines) > max_lines:
        kept.append(TRUNCATION_MARKER)
    return "\n".join(kept)


def redact_artifact_content(content: Any, _depth: int = 0) -> Any:
    """Walk an artifact payload and clip every string in it.

    Artifacts are agent-shaped: a taint path from the static agent, a SARIF match from Semgrep, a
    quoted invariant from the LLM. There is no schema to validate against, so the budget is applied
    structurally rather than per field.
    """
    if _depth > 8:
        return TRUNCATION_MARKER
    if isinstance(content, str):
        return truncate_excerpt(content)
    if isinstance(content, dict):
        return {str(k): redact_artifact_content(v, _depth + 1) for k, v in content.items()}
    if isinstance(content, list):
        clipped = content[:MAX_EXCERPT_LINES]
        return [redact_artifact_content(v, _depth + 1) for v in clipped]
    return content


def redact_chunk(text: str) -> str:
    """Clip a precedent chunk to `MAX_CHUNK_LINES` / `MAX_CHUNK_BYTES`.

    The byte cap is applied last and on the encoded form, because it is also a CHECK constraint on
    the column and Postgres counts octets, not characters.
    """
    clipped = truncate_excerpt(text, max_lines=MAX_CHUNK_LINES, max_line_chars=MAX_CHUNK_LINES * 8)
    encoded = clipped.encode("utf-8")
    if len(encoded) <= MAX_CHUNK_BYTES:
        return clipped
    marker = TRUNCATION_MARKER.encode("utf-8")
    budget = MAX_CHUNK_BYTES - len(marker)
    return encoded[:budget].decode("utf-8", errors="ignore") + TRUNCATION_MARKER
