"""Bayesian odds fusion: one likelihood ratio per witness, per finding.

    posterior_odds = prior_odds x LR(structural) x LR(semantic) x LR(context) x LR(runtime)

Four factors, always four, whatever the agents did or did not say. That is the whole
correction this module exists for. The superseded engine multiplied one factor per agent
*that had alerted*, and since every detection tier exceeds 1.0, its posterior could only
ever rise with the number of agents that spoke (`AUDIT.md` 1.4, D-007). An agent that
looked and found nothing could not lower a number, and an agent that could not look at all
was indistinguishable from one that had.

Three statements, three treatments (D-005, D-006):

* **DETECTION** — a ratio from the witness's tier for its `raw_score`.
* **SILENCE** — a ratio below 1.0, and **only** if `covered_cwes` contains this finding's
  CWE. The taint engine holds no CWE-862 rules; letting its silence count there would
  suppress every semantic-only authorisation finding on principle.
* **ABSTENTION** — exactly 1.0. Not a fitted number, not a configurable one. An agent
  that could not run has said nothing, and nothing is the multiplicative identity.

A witness that emitted no statement at all also contributes 1.0, and is logged at WARNING.
It should not be possible: returning `[]` from a successful analysis is a bug the contract
names, and the runner is expected to synthesise an abstention rather than leave a gap. The
factor is right either way; the log is what stops it being invisible.

**No result is produced for a unit nobody detected anything in.** The old engine minted
`finding_key="abstention:all_agents"` — a raw string in the key space that
`contracts.finding_key()` owns, and the `AUDIT.md` 1.1 bypass one layer above where the
Evidence validator can see it. `codesheriff_storage.persistable_findings` was built as a
wall against that marker; the wall stays, but nothing throws itself at it any more. What a
quiet unit produces is evidence rows, which the worker persists regardless.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from codesheriff_contracts import Evidence, EvidenceKind
from codesheriff_engine.fusion.cells import RatioCell, cell_for
from codesheriff_engine.fusion.ratios import LR_MAX, LR_MIN, WitnessRatios
from codesheriff_engine.fusion.witnesses import WITNESSES, witness_for

logger = logging.getLogger(__name__)

ABSTENTION_LR = 1.0
"""An agent that could not run tells us nothing. Named, so that grepping for the value
finds the reason rather than a bare float."""


class Stance(StrEnum):
    """What one witness said about one finding, after its backends are combined."""

    DETECTED = "detected"
    SILENT = "silent"
    NEUTRAL = "neutral"
    """Abstained, said nothing, or was silent about CWEs that do not include this one."""


class WitnessContribution(BaseModel):
    """One factor of the odds product, with its provenance.

    Recorded so a posterior can be read back apart. A calibrated number that cannot be
    explained factor by factor is not auditable, and §6 makes auditability the deliverable
    rather than the detection.
    """

    model_config = ConfigDict(frozen=True)

    witness: str
    stance: Stance
    cell: RatioCell | None = None
    """The ratio-table cell this witness's statements selected, or None for an abstention.

    Recorded because it is the join between a published posterior and the artifact that
    produced it: `calibration.json` states a ratio per cell, and this says which one was
    read. A breakdown that named only the number would leave a reader unable to check it
    against the fit.
    """

    likelihood_ratio: float
    agent_ids: list[str] = Field(default_factory=list)
    """The backends that spoke for this witness on this finding. Empty when NEUTRAL."""

    note: str = ""
    """Why the ratio is what it is — chiefly why a NEUTRAL witness is neutral."""


class FusionResult(BaseModel):
    """Aggregated output from Bayesian fusion over all agent evidence for a finding."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    finding_key: str
    posterior_probability: float
    is_alert_worthy: bool
    evidence_list: list[Evidence]
    consensus_rationale: str = ""
    cwe: str | None = None
    title: str | None = None
    severity: str | None = None
    file: str | None = None
    line_numbers: list[int] = Field(default_factory=list)

    contributions: list[WitnessContribution] = Field(default_factory=list)
    """One entry per witness, in `WITNESSES` order — including the ones that said nothing.

    The length of this list is the D-007 property made visible: it is the witness count,
    never the count of agents that alerted."""


def normalize_evidence(evidence_list: list[Any]) -> list[Evidence]:
    """Coerce inbound items to the shared Evidence contract.

    This used to reconcile four vendored, separately-evolving Evidence classes. There
    is now exactly one contract package, so the only real work left is validating
    dicts that arrive over the wire.

    It does not swallow failures. The previous `except Exception: pass` discarded
    malformed evidence silently (`AUDIT.md` 2.6) — evidence vanishing without trace is
    the one thing a calibration claim cannot survive.
    """
    normalized: list[Evidence] = []
    for ev in evidence_list:
        if isinstance(ev, Evidence):
            normalized.append(ev)
        elif isinstance(ev, dict):
            normalized.append(Evidence.model_validate(ev))
        elif hasattr(ev, "model_dump"):
            normalized.append(Evidence.model_validate(ev.model_dump()))
        else:
            raise TypeError(
                f"Cannot normalise {type(ev).__name__} into Evidence. Agents must return "
                "codesheriff_contracts.Evidence; there is no vendored variant any more."
            )
    return normalized


def _clamp_lr(lr: float) -> float:
    """Bound one witness's claim. The ratios are clamped; the posterior is not.

    The old engine clamped the posterior to [0.0001, 0.9999] and left the ratios free
    (`AUDIT.md` 2.7), so an unbounded odds product was hidden behind a number that looked
    like a probability. Bounding the factor bounds the quantity that has a meaning.
    """
    return max(LR_MIN, min(LR_MAX, lr))


def _ratios_for(witness: str, table: Mapping[str, WitnessRatios]) -> WitnessRatios:
    """This witness's row, or a refusal.

    There is no fallback table any more (D-082). A fitted artifact covers every registered
    witness — `CalibrationArtifact.load` refuses one that does not — so a missing row here
    means the caller assembled a partial table by hand, and inventing timid numbers for it
    would put an unfitted factor into a posterior nobody could later account for.
    """
    ratios = table.get(witness)
    if ratios is None:
        raise KeyError(
            f"no likelihood ratios for witness {witness!r}. Fusion multiplies one factor per "
            f"registered witness, so a table missing one cannot produce a posterior; supply a "
            f"complete table or use the fitted artifact. Known: {sorted(table)}"
        )
    return ratios


def posterior_from_cells(
    cells: Mapping[str, RatioCell | None],
    table: Mapping[str, WitnessRatios],
    prior_p: float,
) -> float:
    """The odds product, from one cell per witness. **The** arithmetic, used by both halves.

    `compute_bayesian_fusion` calls this to produce the number a developer is shown, and
    `calibration.scoring` calls it to sweep a threshold and measure ECE. A sweep with its own
    copy of these four lines would be selecting a cut point for a quantity the engine does not
    emit, and the two would agree exactly until one of them was edited.

    A witness whose cell is `None` contributes `ABSTENTION_LR`, which is 1.0 by definition.
    """
    clamped_prior = max(0.001, min(0.999, prior_p))
    odds = clamped_prior / (1.0 - clamped_prior)
    for witness in WITNESSES:
        cell = cells.get(witness)
        if cell is None:
            odds *= ABSTENTION_LR
            continue
        odds *= _clamp_lr(_ratios_for(witness, table).for_cell(cell))
    return odds / (1.0 + odds)


def _contribution(
    witness: str,
    cwe: str,
    detections: list[Evidence],
    silences: list[Evidence],
    abstentions: list[Evidence],
    table: Mapping[str, WitnessRatios],
) -> WitnessContribution:
    """This witness's single factor, after combining whatever its backends said.

    Backends combine by **plain max** (D-011, and Chapter 14 kept it). One witness makes one
    statement, and its strongest claim is that statement: two structural backends both firing
    high stay at one high detection rather than compounding, two silences stay one silence
    rather than squaring, and one backend's silence does not retract its sibling's detection.
    Max can never exceed what a single backend claimed alone, and the fit counts observations
    the same way — `cells.cell_for` is the one definition of what a witness said, and it is
    what both this function and `calibration.fit` ask.
    """
    ratios = _ratios_for(witness, table)
    cell = cell_for(cwe, detections, silences)
    covering = [ev for ev in silences if ev.covers(cwe)]

    if detections:
        return WitnessContribution(
            witness=witness,
            stance=Stance.DETECTED,
            cell=cell,
            likelihood_ratio=_clamp_lr(ratios.for_cell(cell)) if cell else ABSTENTION_LR,
            agent_ids=sorted({ev.agent_id for ev in detections}),
            note=f"Detected {cwe}.",
        )

    if covering:
        return WitnessContribution(
            witness=witness,
            stance=Stance.SILENT,
            cell=cell,
            likelihood_ratio=_clamp_lr(ratios.silence),
            agent_ids=sorted({ev.agent_id for ev in covering}),
            note=f"Ran to completion and found no {cwe}.",
        )

    # Everything below is exactly 1.0. The distinction between these notes is not
    # arithmetic — it is the difference between "could not look", "looked for other
    # things" and "said nothing at all", which is what makes a posterior explainable.
    if abstentions:
        reasons = sorted({ev.reason or "unspecified" for ev in abstentions})
        note = f"Could not run: {', '.join(reasons)}."
    elif silences:
        note = f"Ran, but holds no rules for {cwe}."
    else:
        logger.warning(
            "Witness %r emitted no statement at all about this unit. Every agent must "
            "return a DETECTION, a SILENCE or an ABSTENTION; an empty list is a bug the "
            "contract names. Contributing LR 1.0.",
            witness,
        )
        note = "Emitted no statement."

    return WitnessContribution(
        witness=witness,
        stance=Stance.NEUTRAL,
        cell=None,
        likelihood_ratio=ABSTENTION_LR,
        agent_ids=sorted({ev.agent_id for ev in abstentions}),
        note=note,
    )


def _severity_for(posterior: float) -> str:
    """A display band, derived from an uncalibrated posterior and worth no more than one.

    Impact and probability are different quantities and this conflates them. It is kept
    because `findings.severity` is NOT NULL and the dashboard sorts on it; nothing in the
    research claim reads it.
    """
    if posterior >= 0.85:
        return "critical"
    if posterior >= 0.70:
        return "high"
    if posterior >= 0.40:
        return "medium"
    return "low"


def _line_numbers(detections: list[Evidence]) -> list[int]:
    """Lines named by the detections' artifacts, deduplicated and ordered."""
    lines: set[int] = set()
    for ev in detections:
        for art in ev.artifacts:
            content = getattr(art, "content", art)
            if not isinstance(content, dict):
                continue
            for step in content.get("steps", []):
                if isinstance(step, dict) and isinstance(step.get("line"), int):
                    lines.add(step["line"])
            if isinstance(content.get("line"), int):
                lines.add(content["line"])
    return sorted(lines)


def _defaults(
    prior_p: float | None,
    alert_threshold: float | None,
    ratios: Mapping[str, WitnessRatios] | None,
) -> tuple[float, float, Mapping[str, WitnessRatios]]:
    """Fill unset arguments from the fitted artifact.

    Resolved per call rather than as parameter defaults, for two reasons. A default evaluated
    at import time would freeze whichever artifact was on disk when the module was first
    imported, which is wrong for a long-lived worker and wrong for a re-fit during
    development. And the import is local because `calibration.scoring` imports this module —
    the arithmetic belongs to fusion, the fitted numbers belong to calibration, and only one
    of those two directions can be a module-level import.
    """
    from codesheriff_engine.calibration.artifact import active_artifact

    if prior_p is not None and alert_threshold is not None and ratios is not None:
        return prior_p, alert_threshold, ratios

    artifact = active_artifact()
    return (
        artifact.base_rate if prior_p is None else prior_p,
        artifact.alert_threshold if alert_threshold is None else alert_threshold,
        artifact.table() if ratios is None else ratios,
    )


def compute_bayesian_fusion(
    finding_key: str,
    evidence_list: list[Any],
    prior_p: float | None = None,
    alert_threshold: float | None = None,
    ratios: Mapping[str, WitnessRatios] | None = None,
) -> FusionResult:
    """One posterior for one finding, from **every** witness's statement about the unit.

    `evidence_list` is the whole unit's evidence, not one key's group. That is deliberate:
    a silence is a statement about the unit rather than about a finding, so it carries no
    key, and passing only the keyed group is precisely how the silences and abstentions
    used to fall out of the arithmetic.
    """
    prior, threshold, table = _defaults(prior_p, alert_threshold, ratios)
    normalized = normalize_evidence(evidence_list)

    detections = [
        ev
        for ev in normalized
        if ev.kind is EvidenceKind.DETECTION and ev.finding_key == finding_key
    ]
    if not detections:
        raise ValueError(
            f"No detection carries finding_key {finding_key!r}. A finding is something an "
            f"agent found; a unit nobody detected anything in produces evidence rows and no "
            f"finding at all. Synthesising a key here is the AUDIT.md 1.1 bypass."
        )

    cwes = {ev.cwe for ev in detections if ev.cwe}
    if len(cwes) != 1:
        raise ValueError(
            f"finding_key {finding_key!r} carries detections for {sorted(cwes)}. The key is a "
            f"digest of file, symbol and CWE, so this means a key was built by hand instead of "
            f"through ChangeUnit.key_for()."
        )
    cwe = cwes.pop()

    # Bucket by witness once. Every agent_id is resolved here, so evidence from an
    # unregistered agent raises before it can influence an odds product.
    by_witness: dict[str, dict[EvidenceKind, list[Evidence]]] = {
        w: {kind: [] for kind in EvidenceKind} for w in WITNESSES
    }
    for ev in normalized:
        if ev.kind is EvidenceKind.DETECTION and ev.finding_key != finding_key:
            # A detection of a different CWE in the same unit. It says nothing about this
            # finding, and a DETECTION carries no covered_cwes to say otherwise.
            continue
        by_witness[witness_for(ev.agent_id)][ev.kind].append(ev)

    contributions = [
        _contribution(
            witness=witness,
            cwe=cwe,
            detections=by_witness[witness][EvidenceKind.DETECTION],
            silences=by_witness[witness][EvidenceKind.SILENCE],
            abstentions=by_witness[witness][EvidenceKind.ABSTENTION],
            table=table,
        )
        for witness in WITNESSES
    ]

    # Through the shared arithmetic, from the cells the contributions recorded. The
    # breakdown above and the number below therefore cannot disagree, and the threshold
    # sweep in `calibration` scores the identical function.
    posterior = posterior_from_cells(
        {c.witness: c.cell for c in contributions},
        table,
        prior,
    )

    primary = max(detections, key=lambda ev: ev.raw_score)
    return FusionResult(
        finding_key=finding_key,
        posterior_probability=round(posterior, 4),
        is_alert_worthy=posterior >= threshold,
        # Everything that shaped this number: this key's detections, plus every
        # unit-level statement. Detections of other CWEs belong to other findings.
        evidence_list=[
            *detections,
            *(ev for ev in normalized if ev.kind is not EvidenceKind.DETECTION),
        ],
        contributions=contributions,
        cwe=cwe,
        title=f"{cwe}: {primary.explanation[:60]}",
        severity=_severity_for(posterior),
        file=None,
        line_numbers=_line_numbers(detections),
    )


def fuse_all_evidence(
    evidence_list: list[Any],
    prior_p: float | None = None,
    alert_threshold: float | None = None,
    ratios: Mapping[str, WitnessRatios] | None = None,
) -> list[FusionResult]:
    """Every finding in one unit's evidence, most probable first.

    Returns `[]` when nothing was detected. That is not "no result" — it is the honest
    shape of a unit that four witnesses looked at and found nothing in, and the evidence
    saying so is the caller's to persist.
    """
    normalized = normalize_evidence(evidence_list)
    if not normalized:
        return []

    # Resolve every agent up front, so an unregistered one fails the audit instead of
    # quietly becoming a fifth witness in whichever group happens to mention it.
    for ev in normalized:
        witness_for(ev.agent_id)

    keys: list[str] = []
    for ev in normalized:
        if ev.kind is EvidenceKind.DETECTION and ev.finding_key not in keys:
            assert ev.finding_key is not None  # the contract validator guarantees this
            keys.append(ev.finding_key)

    results = [
        compute_bayesian_fusion(
            finding_key=key,
            evidence_list=normalized,
            prior_p=prior_p,
            alert_threshold=alert_threshold,
            ratios=ratios,
        )
        for key in keys
    ]
    results.sort(key=lambda r: r.posterior_probability, reverse=True)
    return results
