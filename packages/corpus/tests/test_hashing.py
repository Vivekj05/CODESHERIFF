"""The two hashes a calibration run has to record (PROJECT_CONTEXT.md §6).

`calibration_runs.corpus_hash` and `.split_hash` have been nullable columns since
Chapter 3 with nothing to put in them. What matters is not that a hash exists but that
it moves when the thing it names moves, and does not move when nothing did.
"""

from __future__ import annotations

import dataclasses
import os
import subprocess
import sys

from codesheriff_corpus import Split, corpus_hash, load_cases, load_splits, split_hash
from codesheriff_corpus.hashing import case_digest
from codesheriff_corpus.splits import SplitFile


def test_hashes_fit_the_storage_columns() -> None:
    """String(64) on both columns, and the CHECK constraints assume hex."""
    for value in (corpus_hash(), split_hash()):
        assert len(value) == 64
        assert set(value) <= set("0123456789abcdef")


def test_hashes_are_stable_across_calls() -> None:
    assert corpus_hash() == corpus_hash()
    assert split_hash() == split_hash()


def test_corpus_hash_is_independent_of_case_order() -> None:
    """Moving a case between CWE directories is not a change to the corpus."""
    cases = load_cases()
    assert corpus_hash(tuple(reversed(cases))) == corpus_hash(cases)


def test_corpus_hash_changes_when_a_source_line_changes() -> None:
    """The failure that must never be silent: a fitted run outliving its corpus."""
    cases = load_cases()
    edited = cases[0].model_copy(update={"post_src": cases[0].post_src + "\n# touched\n"})
    assert corpus_hash((edited, *cases[1:])) != corpus_hash(cases)


def test_corpus_hash_changes_when_a_label_changes() -> None:
    """Relabelling is the most consequential edit possible and must be visible."""
    cases = load_cases()
    vulnerable = next(c for c in cases if c.is_vulnerable)
    flipped = vulnerable.model_copy(update={"detectable_by": frozenset({"semantic.hosted"})})
    others = tuple(c for c in cases if c.case_id != vulnerable.case_id)
    assert corpus_hash((flipped, *others)) != corpus_hash(cases)


def test_case_digests_are_distinct() -> None:
    digests = {case_digest(c) for c in load_cases()}
    assert len(digests) == len(load_cases())


def test_split_hash_changes_when_a_pair_moves() -> None:
    """What makes a reassignment detectable after the fact.

    Nothing prevents someone editing splits.json. This is the property that makes the
    edit show up: a calibration run recorded before it no longer matches the splits it
    claims to have been fitted on (D-045).
    """
    splits = load_splits()
    moved = dict(splits.assignments)
    victim = next(p for p, s in moved.items() if s is not Split.TEST)
    moved[victim] = Split.TEST

    assert split_hash(splits.model_copy(update={"assignments": moved})) != split_hash(splits)


def test_split_hash_ignores_incidental_metadata() -> None:
    """It identifies the assignment, not the note someone wrote next to it."""
    splits = load_splits()
    reworded = splits.model_copy(update={"notes": "reworded", "generated": "1999-01-01"})
    assert split_hash(reworded) == split_hash(splits)


def test_split_file_is_not_mutable_in_place() -> None:
    """Frozen, so a split cannot be nudged by an accidental assignment."""
    splits = load_splits()
    assert isinstance(splits, SplitFile)
    try:
        splits.assignments = {}  # type: ignore[misc]
    except (ValueError, TypeError, dataclasses.FrozenInstanceError):
        return
    raise AssertionError("SplitFile allowed in-place mutation")


def test_hashes_are_stable_across_processes() -> None:
    """The check a same-process assertion cannot make, and the one that mattered.

    Python randomises string hashing per process, so a frozenset serialises in a
    different order each run. `corpus_hash` was computed over a dump containing
    `detectable_by` and therefore differed on every invocation -- caught by running
    the CLI twice, not by the test suite. A calibration run could never have been
    shown to match the corpus it was fitted on, which is the hash's only job.

    Fixed by a field serialiser that sorts, the same one `Evidence.covered_cwes`
    carries for the same reason (D-024). This runs the hash under two hash seeds and
    a random one, because with PYTHONHASHSEED unset each subprocess picks its own.
    """
    script = (
        "from codesheriff_corpus import corpus_hash, split_hash; print(corpus_hash(), split_hash())"
    )
    outputs = set()
    for seed in ("0", "1", "12345", "random", "random"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, check=True, env=env
        )
        outputs.add(result.stdout.strip())

    assert len(outputs) == 1, f"hashes vary across processes: {outputs}"
    assert outputs == {f"{corpus_hash()} {split_hash()}"}
