"""`calibration.json`: the fitted numbers, and everything needed to disbelieve them.

This file is the deliverable of PLAN.md Chapter 14. Before it existed, every likelihood ratio,
the prior and the alert threshold were constants in `fusion/ratios.py` with a comment saying
they were provisional — which is the practice the paper criticises, carried out honestly.

An artifact is **not** a table of numbers. It is a table of numbers plus the evidence that
they were measured rather than chosen:

* `corpus_hash` and `split_hash` name the ground truth and the assignment they came from. §6
  requires a fitted number to be reproducible from the calibration split and a recorded corpus
  hash; these two fields are what makes "reproducible" checkable rather than aspirational. Edit
  a case or move a pair and the recorded hashes stop matching, which is the whole mechanism
  (D-045) — nothing prevents the edit, and everything detects it.
* `fit` carries the per-cell counts, so a ratio held up entirely by Laplace smoothing looks
  like one.
* `prior` states the base rate as **declared** and records the corpus prevalence it was
  rescaled from, because a balanced corpus cannot supply a prior and pretending otherwise
  would put 50% into every posterior.
* `threshold` carries the whole validation sweep, not just the winner.
* `provenance` records which backends actually ran. `structural.semgrep` has no Windows build;
  a structural ratio fitted on a Windows checkout describes a one-backend witness, and that is
  a property of the number rather than a footnote about the machine.

**Loading is strict.** An artifact missing a witness, or carrying one fusion does not know,
is rejected rather than patched with a default — the roster is fixed in `fusion.witnesses`, and
a missing row means the fit is incomplete, not that a timid fallback should be invented (D-082).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from codesheriff_contracts import CONTRACT_VERSION
from codesheriff_engine.calibration.fit import Fit
from codesheriff_engine.calibration.metrics import CalibrationMetrics
from codesheriff_engine.calibration.observations import RunProvenance
from codesheriff_engine.calibration.prior import Prior
from codesheriff_engine.calibration.threshold import ThresholdSelection
from codesheriff_engine.fusion.ratios import WitnessRatios
from codesheriff_engine.fusion.witnesses import WITNESSES

ARTIFACT_FILENAME = "calibration.json"
PACKAGED_ARTIFACT = Path(__file__).parent / ARTIFACT_FILENAME
"""The committed artifact, shipped inside the package.

Inside `codesheriff_engine` rather than beside it, so that an installed wheel carries the
numbers it fuses with. A worker that had to be told where its calibration lives would run
uncalibrated the first time somebody forgot.
"""

CALIBRATION_PATH_ENV = "CALIBRATION_PATH"
"""Overrides the packaged artifact. The name `.env.example` documents (D-064)."""

SCHEMA_VERSION = 1


class CalibrationError(RuntimeError):
    """The artifact is missing, unreadable, or does not describe this engine."""


class CalibrationArtifact(BaseModel):
    """One fitted calibration run, as it is committed and as it is loaded."""

    model_config = ConfigDict(frozen=True)

    schema_version: int = SCHEMA_VERSION
    contract_version: str = CONTRACT_VERSION
    generated: str

    corpus_hash: str
    split_hash: str

    fit: Fit
    prior: Prior
    threshold: ThresholdSelection
    metrics: dict[str, CalibrationMetrics] = Field(default_factory=dict)
    provenance: dict[str, RunProvenance] = Field(default_factory=dict)
    notes: str = ""

    # -- what fusion asks it for --------------------------------------------------------

    def table(self) -> dict[str, WitnessRatios]:
        return self.fit.table()

    @property
    def base_rate(self) -> float:
        return self.prior.base_rate

    @property
    def alert_threshold(self) -> float:
        return self.threshold.value

    @property
    def is_fitted(self) -> bool:
        """True for every artifact that loads. There is no provisional artifact.

        Kept as a property because `calibration_runs.is_provisional` is the column the
        dashboard reads, and the mapping between the two should be written down once rather
        than assumed at each call site.
        """
        return True

    def summary(self) -> str:
        validation = self.metrics.get("validation")
        measured = (
            f"ECE {validation.ece:.3f}, Brier {validation.brier:.3f} on validation"
            if validation
            else "no validation metrics recorded"
        )
        return (
            f"fitted {self.generated} on corpus {self.corpus_hash[:12]} "
            f"split {self.split_hash[:12]}; base rate {self.prior.base_rate:.1%} "
            f"({self.prior.source}); alert at {self.threshold.value:.2f}; {measured}"
        )

    # -- persistence --------------------------------------------------------------------

    def save(self, path: Path) -> None:
        """Sorted keys, two-space indent, `\\n` endings: a re-fit is a readable diff."""
        payload = self.model_dump(mode="json")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")

    @classmethod
    def load(cls, path: Path) -> CalibrationArtifact:
        if not path.is_file():
            raise CalibrationError(
                f"no calibration artifact at {path}. Fusion has no hand-set numbers to fall "
                f"back on any more — fit one with `codesheriff-worker calibrate fit`."
            )
        try:
            artifact = cls.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise CalibrationError(f"{path} is not a readable calibration artifact: {exc}") from exc
        artifact._check_covers_every_witness(path)
        return artifact

    def _check_covers_every_witness(self, path: Path) -> None:
        fitted = set(self.fit.witnesses)
        expected = set(WITNESSES)
        if fitted != expected:
            raise CalibrationError(
                f"{path} fits {sorted(fitted)}, but fusion multiplies one ratio per witness for "
                f"{sorted(expected)}. A missing row is an incomplete fit, not a witness to give a "
                f"default to; an extra one is a factor nobody registered."
            )


def artifact_path() -> Path:
    """Where the active artifact is read from: `$CALIBRATION_PATH`, else the packaged one."""
    override = os.environ.get(CALIBRATION_PATH_ENV, "").strip()
    return Path(override) if override else PACKAGED_ARTIFACT


@lru_cache(maxsize=4)
def _load_cached(path: str, mtime: float) -> CalibrationArtifact:
    return CalibrationArtifact.load(Path(path))


def active_artifact() -> CalibrationArtifact:
    """The artifact fusion runs on, cached on path and mtime.

    Cached because every audit reads it and it never changes within a process; keyed on mtime
    so that re-fitting during development does not require a restart to be believed.
    """
    path = artifact_path()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0.0
    return _load_cached(str(path), mtime)


def build(
    *,
    corpus_hash: str,
    split_hash: str,
    fit: Fit,
    prior: Prior,
    threshold: ThresholdSelection,
    metrics: dict[str, CalibrationMetrics],
    provenance: dict[str, RunProvenance],
    notes: str = "",
) -> CalibrationArtifact:
    return CalibrationArtifact(
        generated=datetime.now(UTC).isoformat(timespec="seconds"),
        corpus_hash=corpus_hash,
        split_hash=split_hash,
        fit=fit,
        prior=prior,
        threshold=threshold,
        metrics=metrics,
        provenance=provenance,
        notes=notes,
    )
