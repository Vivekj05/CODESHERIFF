"""What a fit is fitted from: one claim, one label, one cell per witness.

A **claim** is a `(case, CWE)` question — "is this unit vulnerable to this CWE?" — together
with what each witness said about it. It is deliberately the same object fusion produces a
posterior for: `compute_bayesian_fusion` answers exactly one finding key, and a finding key
is a case and a CWE. Fitting on anything coarser would fit a quantity fusion never computes.

Every case contributes its **primary** claim, about the CWE its twin pair is built around,
whether or not anything was detected. That is not a formality: a vulnerable case where every
witness stayed silent is the observation that makes a silence ratio mean something. Drop it
and `silence` is fitted only from cases where somebody spoke, which is the one population it
is never applied to.

A case also contributes a **spurious** claim for every other CWE some witness detected. Those
are labelled `False`, because the corpus asserts what each pair is about and a witness that
reports a different CWE on it has produced a finding no ground truth supports. They exist so
that the threshold sweep scores what a developer would actually be shown — every alert,
not just the alerts about the CWE the case was written for.

The cells themselves come from `fusion.cells.cell_for`, which is the same function `bayes.py`
uses to look a ratio up. One definition of "what did this witness say", used by both halves,
is the whole reason that module exists.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from codesheriff_contracts import Evidence, EvidenceKind
from codesheriff_engine.fusion.cells import RatioCell, cell_for
from codesheriff_engine.fusion.witnesses import WITNESSES, witness_for


class Claim(BaseModel):
    """One `(case, CWE)` question, its ground truth, and one cell per witness.

    `cells` maps every registered witness to the cell its statements selected, or `None`
    where it contributed nothing — an abstention, a silence about other CWEs, or no
    statement at all. `None` is not a table entry and is never counted: an abstention is
    exactly 1.0 by definition, and fitting a number for it would mean the act of failing
    carried information about the code.
    """

    model_config = ConfigDict(frozen=True)

    case_id: str
    pair_id: str
    split: str
    cwe: str
    finding_key: str

    label: bool
    """Ground truth for this claim. True only for the primary claim of a vulnerable case."""

    is_primary: bool
    """Whether this is the claim the corpus pair was written to answer.

    Recorded rather than re-derived, because "the case is vulnerable" and "this claim is
    the one the case is about" are different questions and conflating them is how a
    spurious alert would come to be scored as a miss.
    """

    cells: dict[str, RatioCell | None]

    def cell(self, witness: str) -> RatioCell | None:
        return self.cells.get(witness)


class RunProvenance(BaseModel):
    """What machine produced these observations, and which backends actually ran.

    Not decoration. `structural.semgrep` has no Windows build and abstains there, so a run
    from a Windows checkout fits a structural witness with one backend behind it rather than
    two. That is a property of the number, and a number whose provenance is not recorded
    cannot be told apart from one fitted on the full witness.
    """

    model_config = ConfigDict(frozen=True)

    platform: str
    python_version: str
    generated: str
    agent_versions: dict[str, str] = Field(default_factory=dict)
    backends_silent: list[str] = Field(default_factory=list)
    """Backends that abstained on **every** unit — the ones that were not really present."""

    semantic_source: str = ""
    """Where the semantic witness's model output came from: recorded responses, and which."""

    notes: str = ""


class ObservationSet(BaseModel):
    """Claims from one split, with the corpus they were drawn from named on the record.

    `corpus_hash` and `split_hash` travel with the observations rather than being attached
    at fit time. §6 requires a fitted number to be reproducible from the calibration split
    and a recorded corpus hash; a hash stamped on later would only record which corpus was
    checked out when somebody ran the fit.
    """

    model_config = ConfigDict(frozen=True)

    split: str
    corpus_hash: str
    split_hash: str
    provenance: RunProvenance
    claims: tuple[Claim, ...]

    def primary(self) -> tuple[Claim, ...]:
        return tuple(c for c in self.claims if c.is_primary)

    def prevalence(self) -> float:
        """Fraction of claims that are true. About 0.5 here, and that is the point.

        The corpus is balanced by construction, so this is not the production base rate and
        must never be used as one. It is recorded because rescaling to a real base rate is
        only meaningful if the rate being rescaled *from* is stated.
        """
        return sum(c.label for c in self.claims) / len(self.claims) if self.claims else 0.0

    def counts(self) -> Counter[str]:
        """`witness:cell` tallies, for a quick look at what a run actually saw."""

        def label(claim: Claim, witness: str) -> str:
            cell = claim.cells.get(witness)
            return f"{witness}:{cell.value if cell is not None else 'none'}"

        return Counter(label(claim, witness) for claim in self.claims for witness in WITNESSES)

    # -- serialisation ------------------------------------------------------------------

    def to_jsonl(self, path: Path) -> None:
        """One header line, then one claim per line.

        JSONL rather than a single document so that a partial run is still readable and a
        diff shows which case changed. Newline-terminated and `\\n`-separated explicitly:
        these files are committed, and a Windows checkout must not rewrite every line.
        """
        header = self.model_dump(mode="json", exclude={"claims"})
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps({"header": header}, sort_keys=True) + "\n")
            for claim in self.claims:
                handle.write(json.dumps(claim.model_dump(mode="json"), sort_keys=True) + "\n")

    @classmethod
    def from_jsonl(cls, path: Path) -> ObservationSet:
        lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if not lines:
            raise ValueError(f"{path} is empty; nothing was observed")
        header = json.loads(lines[0])["header"]
        claims = [Claim.model_validate(json.loads(ln)) for ln in lines[1:]]
        return cls(**header, claims=tuple(claims))


def claims_for_case(
    *,
    case_id: str,
    pair_id: str,
    split: str,
    cwe: str,
    finding_key: str,
    label_vulnerable: bool,
    evidence: Iterable[Evidence],
    key_for: Callable[[str], str],
) -> list[Claim]:
    """Every claim one analysed case supports: its own CWE, plus any CWE a witness reported.

    `key_for` is the case's `ChangeUnit.key_for` — passed in rather than imported, because a
    finding key is built one way only (D-019) and rebuilding it here by hand is exactly the
    bug that gave one finding two keys (`AUDIT.md` 1.1).
    """
    statements = list(evidence)
    by_witness_detections: dict[str, dict[str, list[Evidence]]] = {w: {} for w in WITNESSES}
    silences: dict[str, list[Evidence]] = {w: [] for w in WITNESSES}

    for item in statements:
        witness = witness_for(item.agent_id)
        if item.kind is EvidenceKind.DETECTION and item.cwe:
            by_witness_detections[witness].setdefault(item.cwe, []).append(item)
        elif item.kind is EvidenceKind.SILENCE:
            silences[witness].append(item)

    reported = {
        reported_cwe
        for witness in WITNESSES
        for reported_cwe in by_witness_detections[witness]
        if reported_cwe != cwe
    }

    def build(claim_cwe: str, key: str, primary: bool) -> Claim:
        return Claim(
            case_id=case_id,
            pair_id=pair_id,
            split=split,
            cwe=claim_cwe,
            finding_key=key,
            label=label_vulnerable and primary,
            is_primary=primary,
            cells={
                witness: cell_for(
                    claim_cwe,
                    by_witness_detections[witness].get(claim_cwe, []),
                    silences[witness],
                )
                for witness in WITNESSES
            },
        )

    claims = [build(cwe, finding_key, True)]
    claims.extend(build(other, key_for(other), False) for other in sorted(reported))
    return claims


def iter_claims(sets: Iterable[ObservationSet]) -> Iterator[Claim]:
    for observation_set in sets:
        yield from observation_set.claims
