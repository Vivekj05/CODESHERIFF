"""The shape of a witness's likelihood ratios, and the bounds any fit has to respect.

**There are no numbers in this file any more.** Until Chapter 14 there were: four hand-set
tables, a hand-set prior and a hand-set threshold, each with a comment saying it was
provisional. `codesheriff_engine.calibration` replaced them with values fitted on the
calibration split, and `calibration.json` is where they live — with the counts, the corpus
hash and the split hash that make them checkable. D-010 is discharged by deleting the
constants rather than by relabelling them.

What remains here is the *type* and the *bounds*, and neither is a fitted quantity:

* `WitnessRatios` is keyed by **witness**, not by backend (D-011). A row per backend is what
  let `structural.taint` and `structural.semgrep` multiply as two independent agents
  (`AUDIT.md` 2.4).
* There is no entry for an abstention, and there must never be one. An abstention is exactly
  1.0 — the multiplicative identity — because an agent that could not run is evidence of
  nothing (D-005). A fitted number there would mean the act of failing carried information.
* `LR_MIN` and `LR_MAX` bound what any single witness may claim. They are policy, not
  measurement: the fit records the raw ratio beside the clamped one, so a bound that bit is
  visible in the artifact rather than hidden in the value.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from codesheriff_engine.fusion.cells import RatioCell, tier_for_score


class WitnessRatios(BaseModel):
    """The likelihood ratios one witness contributes, by what it said."""

    model_config = {"frozen": True}

    detection_high: float = Field(gt=0.0)
    """`raw_score >= 0.8`."""

    detection_medium: float = Field(gt=0.0)
    """`0.5 <= raw_score < 0.8`."""

    detection_low: float = Field(gt=0.0)
    """`raw_score < 0.5`. Free to fit below 1.0, and for some witnesses it does: an agent
    that fires with low confidence can be mild evidence the code is fine."""

    silence: float = Field(gt=0.0, lt=1.0)
    """Ran to completion, covers this CWE, found nothing (D-006).

    Constrained below 1.0 by the type, not by convention: a silence at or above 1.0 would
    make looking-and-finding-nothing evidence *for* a vulnerability. A fit that lands above
    the ceiling is clamped and records its raw value (`calibration.fit.SILENCE_CEILING`,
    D-081). It applies only when the witness's `covered_cwes` contains the finding's CWE —
    the taint engine holds no CWE-862 rules, and its silence must not suppress a
    semantic-only authorisation finding."""

    def for_cell(self, cell: RatioCell) -> float:
        """The ratio for a named cell. The only mapping from cell to number."""
        return float(getattr(self, cell.value))

    def for_score(self, raw_score: float) -> float:
        """The detection ratio for a raw score.

        Delegates to `cells.tier_for_score` rather than repeating the boundaries, so the
        tiers a fit counts observations into and the tiers fusion scores with cannot drift
        apart. They did not drift, historically — the two tables simply did not both exist,
        and this is the seam where they would have.
        """
        return self.for_cell(tier_for_score(raw_score))


LR_MIN: float = 0.05
LR_MAX: float = 20.0
"""Bounds on each witness's contribution — the **likelihood ratios**, not the posterior.

The old engine had this exactly backwards (`AUDIT.md` 2.7): unbounded ratios multiplied into
an arbitrarily large odds product, and a clamp at 0.9999 hid the overflow behind a number that
looked like a probability. Clamping here bounds what any one witness can claim, which is the
quantity that has a meaning to bound. With ratios inside these bounds and a prior in (0, 1),
the posterior is strictly inside (0, 1) with no clamp at all.

They also bound what a small corpus can assert. Four cells fitted from 46 cases can produce a
ratio of 30 from a cell that was observed three times; the clamp is the statement that no
witness earns that on this much data, and `CellFit.clamped` records every time it applied."""
