"""Giving `calibration_runs.corpus_hash` and `.split_hash` an actual definition.

`packages/storage` has held both columns since Chapter 3 with nothing to put in
them. PROJECT_CONTEXT.md §6 requires every fitted number to be reproducible from the
calibration split and a recorded corpus hash; until there is a computable hash, that
requirement is a sentence rather than a check.

Both hashes are computed over the *loaded, canonical* form, not over raw file bytes.
Reflowing a comment in a `case.yaml` or reordering its keys does not change the
corpus, and should not invalidate a calibration run. Changing a line of `post.py`,
a label, or a `detectable_by` entry does, and does.

Deliberately independent of git. A hash derived from a commit says when the corpus
was read, not what it contained, and it cannot be recomputed from a wheel.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from codesheriff_corpus.loader import load_cases

if TYPE_CHECKING:
    from codesheriff_corpus.models import CorpusCase
    from codesheriff_corpus.splits import SplitFile

HASH_ALGORITHM = "sha256"
"""64 hex characters, which is what `calibration_runs.corpus_hash` is sized for."""


def _canonical(payload: object) -> bytes:
    """One byte sequence per value, on any platform.

    `sort_keys` so field order cannot shift the hash, and `\\n` separators so a Windows
    checkout and a Linux CI runner agree.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def case_digest(case: CorpusCase) -> str:
    """A single case's contribution. Covers labels, metadata and both sources."""
    return hashlib.sha256(_canonical(json.loads(case.model_dump_json()))).hexdigest()


def corpus_hash(cases: tuple[CorpusCase, ...] | None = None) -> str:
    """Identifies the corpus a calibration run was fitted on.

    Order-independent by construction: the per-case digests are sorted before they
    are combined, so moving a case between CWE directories changes nothing unless its
    content changed too.
    """
    resolved = load_cases() if cases is None else cases
    digests = sorted(f"{case.case_id}:{case_digest(case)}" for case in resolved)
    return hashlib.sha256(_canonical(digests)).hexdigest()


def split_hash(splits: SplitFile | None = None) -> str:
    """Identifies the split assignment.

    Recorded alongside `corpus_hash` on every calibration run, and it is what makes a
    later reassignment *detectable*. Nothing can prevent someone editing splits.json;
    what matters is that a run fitted before the edit no longer matches the corpus it
    claims to have been fitted on (D-045).
    """
    if splits is None:
        from codesheriff_corpus.splits import load_splits

        splits = load_splits()
    payload = {pair: split.value for pair, split in sorted(splits.assignments.items())}
    return hashlib.sha256(_canonical(payload)).hexdigest()
