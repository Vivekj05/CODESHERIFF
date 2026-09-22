"""The page cursor, on its own.

No database and no marker: the cursor is a pure function, and the reason it is a function rather
than two query parameters is worth a test that runs everywhere.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from codesheriff_api.audits import CursorError, decode_cursor, encode_cursor


def test_a_cursor_round_trips_exactly() -> None:
    """Microseconds included. A cursor that lost precision would re-serve the row it points at."""
    stamp = datetime(2026, 9, 5, 12, 30, 15, 123456, tzinfo=UTC)
    ident = uuid.uuid4()

    assert decode_cursor(encode_cursor(stamp, ident)) == (stamp, ident)


@pytest.mark.parametrize("candidate", ["not-a-cursor", "", "!!!!", "2026-09-05T12:30:15+00:00|x"])
def test_a_cursor_the_api_did_not_issue_raises(candidate: str) -> None:
    """Opaque so a caller cannot construct one.

    A cursor a client can hand-write is a filter a client can widen, and the next reader of the
    route would have to notice for themselves that `before` reaches a WHERE clause.
    """
    with pytest.raises(CursorError):
        decode_cursor(candidate)
