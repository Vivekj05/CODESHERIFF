"""The committed, immutable splits.

Assignment is by `pair_id`, never by `case_id`. A twin pair is one decision, so a
twin cannot straddle a split by construction rather than by a rule someone remembers
to follow. The vulnerable and safe members of a pair differ by a few characters; with
one in the calibration split and the other in test, a fitted ratio would have been
tuned on all but a sanitizer call of the case it is later scored against.

Three splits, three questions, and each split answers exactly one (§6):

    calibration   likelihood ratios and the prior are fitted here
    validation    the alert threshold is swept here, ratios already frozen
    test          evaluated once, at the very end

Nothing here can *prevent* a later edit to splits.json, and this module does not
pretend otherwise. A committed checksum verified by a test is the mechanism that was
already defeated once in this repository — AUDIT.md 4.8, where the expected hash was
rewritten to make the test pass. What exists instead is a `split_hash` recorded on
every calibration run, so a run fitted before an edit stops matching the splits it
claims, plus an assignment routine that will not move a pair that already has a home
(D-045).
"""

from __future__ import annotations

import json
import random
from collections import defaultdict
from importlib.resources import files

from pydantic import BaseModel, ConfigDict, Field, field_validator

from codesheriff_corpus.loader import CorpusError, load_cases, load_pairs
from codesheriff_corpus.models import CorpusCase, Split

SPLITS_FILENAME = "splits.json"

DEFAULT_SPLIT_RATIOS: dict[Split, float] = {
    Split.CALIBRATION: 0.6,
    Split.VALIDATION: 0.2,
    Split.TEST: 0.2,
}
"""60/20/20 by pair.

Named `..._SPLIT_RATIOS` because "ratios" means *likelihood* ratios everywhere else in this
codebase, and these are proportions of a corpus. The collision was harmless while nothing was
fitted; it stopped being harmless the moment a test had to assert that no module anywhere
defines a default ratio table.

Weighted toward calibration because that is where the work is: four agents times
three evidence kinds is twelve cells to fit, and a cell with two observations in it
produces a ratio that Laplace smoothing is holding up on its own. Validation and test
each answer a single scalar question and can afford to be smaller.
"""


class SplitFile(BaseModel):
    """`splits.json`. Written once by `codesheriff-corpus assign`, then left alone."""

    model_config = ConfigDict(frozen=True)

    schema_version: int = 1
    generated: str
    seed: int
    """Recorded so the assignment can be re-derived and shown to be unrigged."""

    ratios: dict[Split, float]
    assignments: dict[str, Split] = Field(default_factory=dict)
    """`pair_id -> split`. Both members of the pair follow it."""

    notes: str = ""

    @field_validator("ratios")
    @classmethod
    def _ratios_sum_to_one(cls, value: dict[Split, float]) -> dict[Split, float]:
        if set(value) != set(Split):
            raise ValueError(f"ratios must name every split, got {sorted(s.value for s in value)}")
        total = sum(value.values())
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"ratios sum to {total}, not 1.0")
        return value


def _splits_path() -> object:
    return files("codesheriff_corpus") / SPLITS_FILENAME


def read_splits_file() -> SplitFile | None:
    """The committed assignment exactly as written, or None if there is not one yet.

    Deliberately *without* the completeness check `load_splits` applies. `assign` is
    only ever run after new cases have been added, which is exactly when that check
    fails — so routing the CLI through `load_splits` meant the one command that must
    preserve settled assignments received none of them and re-drew the whole corpus.
    Chapter 12 found it by adding eight pairs and watching sixteen of the settled
    thirty move, four of them out of the sealed test split (D-069).

    Consumers still go through `load_splits`. A reader that silently accepted a
    half-assigned file would let cases drop out of a split without saying so, which is
    the failure that check exists to prevent.
    """
    target = _splits_path()
    if not target.is_file():  # type: ignore[attr-defined]
        return None
    return SplitFile.model_validate_json(target.read_text(encoding="utf-8"))  # type: ignore[attr-defined]


def load_splits() -> SplitFile:
    """Read the committed assignment, and check it still describes this corpus.

    An assignment naming a pair that no longer exists, or missing one that does, is an
    error rather than something to work around: either way some case would silently
    drop out of, or into, a split it was never assigned to.
    """
    target = _splits_path()
    if not target.is_file():  # type: ignore[attr-defined]
        raise CorpusError(f"{SPLITS_FILENAME} is missing; run `codesheriff-corpus assign`")

    splits = SplitFile.model_validate_json(target.read_text(encoding="utf-8"))  # type: ignore[attr-defined]

    known = set(load_pairs())
    assigned = set(splits.assignments)
    if orphaned := assigned - known:
        raise CorpusError(f"{SPLITS_FILENAME} assigns pairs that do not exist: {sorted(orphaned)}")
    if unassigned := known - assigned:
        raise CorpusError(
            f"pairs with no split: {sorted(unassigned)}. Run `codesheriff-corpus assign` — it "
            "places new pairs without disturbing existing ones."
        )
    return splits


def split_for(case: CorpusCase) -> Split:
    return load_splits().assignments[case.pair_id]


def cases_in(split: Split) -> tuple[CorpusCase, ...]:
    """Every case in one split, both twins together.

    The calibration and validation helpers a fitting routine reaches for. `test` is
    reachable the same way, deliberately: an interface that made the test split hard
    to load would only encourage a private copy of this function.
    """
    assignments = load_splits().assignments
    return tuple(c for c in load_cases() if assignments[c.pair_id] is split)


def pairs_in(split: Split) -> tuple[str, ...]:
    assignments = load_splits().assignments
    return tuple(sorted(p for p, s in assignments.items() if s is split))


# ---------------------------------------------------------------------------
# Assignment
# ---------------------------------------------------------------------------


def _targets(total: int, ratios: dict[Split, float]) -> dict[Split, int]:
    """Largest-remainder allocation, so the counts sum to `total` exactly."""
    exact = {s: total * r for s, r in ratios.items()}
    floors = {s: int(v) for s, v in exact.items()}
    for split in sorted(exact, key=lambda s: (-(exact[s] - floors[s]), s.value))[
        : total - sum(floors.values())
    ]:
        floors[split] += 1
    return floors


def _interleaved(pairs: dict[str, str], seed: int) -> list[str]:
    """Order pairs so that consecutive draws come from different CWEs.

    Taking the nth pair of every CWE before any CWE's (n+1)th means a prefix of this
    sequence is spread across CWEs rather than concentrated in the alphabetically
    early ones. `pairs` maps pair_id to its CWE.
    """
    rng = random.Random(seed)

    by_cwe: dict[str, list[str]] = defaultdict(list)
    for pair_id in sorted(pairs):
        by_cwe[pairs[pair_id]].append(pair_id)
    for bucket in by_cwe.values():
        rng.shuffle(bucket)

    cwe_order = sorted(by_cwe)
    rng.shuffle(cwe_order)

    ordered: list[str] = []
    for index in range(max(len(b) for b in by_cwe.values()) if by_cwe else 0):
        for cwe in cwe_order:
            if index < len(by_cwe[cwe]):
                ordered.append(by_cwe[cwe][index])
    return ordered


def assign(
    seed: int,
    ratios: dict[Split, float] | None = None,
    existing: dict[str, Split] | None = None,
) -> dict[str, Split]:
    """Place every unassigned pair, leaving assigned ones exactly where they are.

    Existing assignments are load-bearing: once a pair has been in the test split, it
    has to stay there, or a later "rebalance" quietly moves cases the test estimate
    was already computed against. New pairs are dealt to whichever split is furthest
    below its share, so the ratios are approached over time rather than enforced by
    moving things.
    """
    resolved_ratios = dict(DEFAULT_SPLIT_RATIOS) if ratios is None else ratios
    settled = dict(existing or {})

    cwe_of = {pair_id: vuln.cwe for pair_id, (vuln, _safe) in load_pairs().items()}
    if stale := set(settled) - set(cwe_of):
        raise CorpusError(
            f"cannot keep assignments for pairs that no longer exist: {sorted(stale)}"
        )

    targets = _targets(len(cwe_of), resolved_ratios)
    held: dict[Split, int] = {s: 0 for s in Split}
    for split in settled.values():
        held[split] += 1

    for pair_id in _interleaved(cwe_of, seed):
        if pair_id in settled:
            continue
        chosen = max(Split, key=lambda s: (targets[s] - held[s], -list(Split).index(s)))
        settled[pair_id] = chosen
        held[chosen] += 1
    return settled


def write_splits(splits: SplitFile, path: str) -> None:
    """Serialise `splits.json`. Sorted and newline-terminated so a rerun is a no-op diff."""
    payload = {
        "schema_version": splits.schema_version,
        "generated": splits.generated,
        "seed": splits.seed,
        "ratios": {
            s.value: r for s, r in sorted(splits.ratios.items(), key=lambda kv: kv[0].value)
        },
        "notes": splits.notes,
        "assignments": {p: s.value for p, s in sorted(splits.assignments.items())},
    }
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
