"""The provisional numbers, and the shape a fitted set will have to fill.

Every value here is **asserted, not fitted**, and stays that way until Chapter 14 measures
it on the calibration split. D-010 requires anything derived from them to be presented as
provisional; `storage.provisional_calibration_run` records that on each audit, and
`apps/worker/comment.py` states it above every posterior it renders.

They live beside the fusion arithmetic rather than in `config.py` because `bayes` needs
them and `config` needs `bayes` — a settings module that the maths imports is a settings
module the maths cannot be tested without.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from codesheriff_engine.fusion.witnesses import CONTEXT, RUNTIME, SEMANTIC, STRUCTURAL


class WitnessRatios(BaseModel):
    """The likelihood ratios one witness contributes, by what it said.

    Keyed by **witness**, not by backend (D-011). The table previously held a row per
    backend, which is what let `structural.taint` and `structural.semgrep` multiply as
    two independent agents (`AUDIT.md` 2.4).

    There is no entry for an abstention, and there must never be one. An abstention is
    exactly 1.0 by definition — the multiplicative identity — because an agent that could
    not run is evidence of nothing (D-005). A fitted number there would mean the act of
    failing carried information about the code.
    """

    model_config = {"frozen": True}

    detection_high: float = Field(gt=0.0)
    """`raw_score >= 0.8`."""

    detection_medium: float = Field(gt=0.0)
    """`0.5 <= raw_score < 0.8`."""

    detection_low: float = Field(gt=0.0)
    """`raw_score < 0.5`. Below 1.0 on purpose for witnesses whose weak alerts are
    historically noise: an agent that fires with low confidence is, for those, mild
    evidence the code is fine."""

    silence: float = Field(gt=0.0, lt=1.0)
    """Ran to completion, covers this CWE, found nothing (D-006).

    Constrained below 1.0 by the type, not by convention: a silence at or above 1.0 would
    make looking-and-finding-nothing evidence *for* a vulnerability. It applies only when
    the witness's `covered_cwes` contains the finding's CWE — the taint engine holds no
    CWE-862 rules, and its silence must not suppress a semantic-only authorisation
    finding."""

    def for_score(self, raw_score: float) -> float:
        """The detection ratio for a raw score. Tiers, until Chapter 14 fits a curve."""
        if raw_score >= 0.8:
            return self.detection_high
        if raw_score >= 0.5:
            return self.detection_medium
        return self.detection_low


PROVISIONAL_RATIOS: dict[str, WitnessRatios] = {
    # Mechanical reachability. Its detections are the most trustworthy of the four when
    # it fires; its silence is only moderately informative, because a bug with no
    # syntactic pattern is precisely what it cannot see.
    STRUCTURAL: WitnessRatios(
        detection_high=8.5, detection_medium=3.2, detection_low=0.8, silence=0.60
    ),
    # Absorbed model knowledge. Highest detection ratios and the most informative
    # silence, and also the witness most able to be confidently wrong — which is what
    # the anti-sycophancy work in Chapter 11 exists to bound.
    SEMANTIC: WitnessRatios(
        detection_high=12.0, detection_medium=4.5, detection_low=0.5, silence=0.50
    ),
    # This repository's own precedent. Weak in both directions by construction: a repo
    # with no relevant history is the normal case, and that is an abstention, not this.
    CONTEXT: WitnessRatios(
        detection_high=4.2, detection_medium=2.1, detection_low=0.9, silence=0.85
    ),
    # Direct observation in a sandbox. Strongest in both directions when it can run at
    # all, and it usually cannot — most changed functions will not execute in isolation,
    # which is an abstention and contributes nothing either way.
    RUNTIME: WitnessRatios(
        detection_high=15.0, detection_medium=5.0, detection_low=0.7, silence=0.40
    ),
}
"""Hand-set, and wrong. Chapter 14 replaces this wholesale with ratios fitted on the
calibration split, and nothing derived from these values may be called calibrated.

They are ordered so that a single witness cannot reach the alert threshold alone: the
strongest structural detection takes a 0.05 prior to 0.31, well under 0.70. That is a
property worth keeping when the fitted numbers land — one mechanical witness proving
reachability is not the same claim as four witnesses agreeing."""

FALLBACK_RATIOS: WitnessRatios = WitnessRatios(
    detection_high=3.0, detection_medium=1.5, detection_low=1.0, silence=0.90
)
"""For a witness with no row of its own. Deliberately timid — an unfitted witness should
barely move a posterior — and reachable only via a registered witness whose ratios were
not supplied, since an unregistered `agent_id` raises in `witnesses.witness_for`."""

LR_MIN: float = 0.05
LR_MAX: float = 20.0
"""Bounds on each witness's contribution — the **likelihood ratios**, not the posterior.

The old engine had this exactly backwards (`AUDIT.md` 2.7): unbounded ratios multiplied
into an arbitrarily large odds product, and a clamp at 0.9999 hid the overflow behind a
number that looked like a probability. Clamping here bounds what any one witness can
claim, which is the quantity that has a meaning to bound. With ratios inside these bounds
and a prior in (0, 1), the posterior is strictly inside (0, 1) with no clamp at all."""

PROVISIONAL_PRIOR = 0.05
"""Asserted, not fitted. A placeholder until Chapter 14 measures it (D-010).

A module constant rather than only a field default because `apps/api` has to stamp it onto
every audit it opens, and §6 requires each audit to record the numbers it actually ran
under. Importing one named constant keeps the edge out of the engine's configuration
object, which also holds settings the API process has no business loading."""

PROVISIONAL_ALERT_THRESHOLD = 0.70
"""Asserted, not fitted. §6 requires the threshold to be selected on the validation split,
which has not happened. Nothing derived from this value may be presented as calibrated."""
