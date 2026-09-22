"""Excerpt budgets.

The caps are the whole of D-027: they are what makes "bounded excerpts" a property of the code
rather than an intention in a document.
"""

from __future__ import annotations

from codesheriff_storage.redaction import (
    MAX_CHUNK_BYTES,
    MAX_EXCERPT_LINE_CHARS,
    MAX_EXCERPT_LINES,
    TRUNCATION_MARKER,
    redact_artifact_content,
    redact_chunk,
    truncate_excerpt,
    truncate_line,
)


def test_short_text_is_untouched() -> None:
    assert truncate_line("query = build(x)") == "query = build(x)"
    assert truncate_excerpt("a\nb\nc") == "a\nb\nc"


def test_long_line_is_clipped_and_marked() -> None:
    clipped = truncate_line("x" * 10_000)
    assert clipped.startswith("x" * MAX_EXCERPT_LINE_CHARS)
    assert clipped.endswith(TRUNCATION_MARKER)


def test_excerpt_line_count_is_capped() -> None:
    clipped = truncate_excerpt("\n".join(f"line {i}" for i in range(500)))
    lines = clipped.splitlines()
    assert len(lines) == MAX_EXCERPT_LINES + 1
    assert lines[-1] == TRUNCATION_MARKER


def test_truncation_is_visible_rather_than_silent() -> None:
    """A cut excerpt must say so. A silently shortened taint path reads as a complete one."""
    assert TRUNCATION_MARKER in truncate_excerpt("y" * 5000)


def test_nested_artifact_strings_are_all_clipped() -> None:
    content = {
        "steps": [
            {"line": 1, "code": "a" * 900},
            {"line": 2, "note": {"deep": ["b" * 900]}},
        ]
    }
    redacted = redact_artifact_content(content)

    assert redacted["steps"][0]["code"].endswith(TRUNCATION_MARKER)
    assert redacted["steps"][1]["note"]["deep"][0].endswith(TRUNCATION_MARKER)


def test_artifact_non_strings_survive_intact() -> None:
    """Line numbers, scores and flags are metadata, not excerpts."""
    redacted = redact_artifact_content({"line": 42, "score": 0.91, "sanitized": False})
    assert redacted == {"line": 42, "score": 0.91, "sanitized": False}


def test_deeply_nested_artifact_is_bounded() -> None:
    """A hostile or pathological artifact must not recurse without limit."""
    content: dict[str, object] = {"k": "leaf"}
    for _ in range(40):
        content = {"k": content}
    assert redact_artifact_content(content) is not None


def test_chunk_respects_the_byte_cap_that_the_column_enforces() -> None:
    """The cap is also a CHECK constraint, and Postgres counts octets, not characters."""
    chunk = redact_chunk("héllo wörld " * 5000)
    assert len(chunk.encode("utf-8")) <= MAX_CHUNK_BYTES


def test_chunk_under_the_cap_is_preserved_exactly() -> None:
    """Within budget a chunk is stored verbatim — retrieval has to show real precedent code.

    Line endings are normalised on the way through: `redact_chunk` splits and rejoins on "\\n", so a
    trailing newline does not survive. A chunk is an excerpt for display and embedding, not a file
    to be written back out.
    """
    original = "def handler(request):\n    return render(request.GET['q'])"
    assert redact_chunk(original) == original
    assert redact_chunk(original + "\n") == original
