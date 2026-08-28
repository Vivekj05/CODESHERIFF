"""Diff parsing and PR comment rendering.

No webhook and no API client any more. `webhook.py` was replaced in Chapter 6 by
`apps/api/src/codesheriff_api/webhooks.py`, which verifies the HMAC signature before parsing and
enqueues rather than analysing inline (AUDIT.md 0.1 and 4.3). Writing to GitHub belongs to
`apps/worker`; the engine below it is fusion and calibration, and must stay callable with no
network and no credentials.
"""

from codesheriff_engine.github.parser import parse_pr_files_to_change_units
from codesheriff_engine.github.reporter import format_github_comment

__all__ = [
    "format_github_comment",
    "parse_pr_files_to_change_units",
]
