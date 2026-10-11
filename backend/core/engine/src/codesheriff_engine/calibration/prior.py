"""The prior, the base rate it is rescaled to, and the weights that make a measurement mean it.

**The corpus is balanced on purpose and that makes it the wrong place to read a prior.** Every
case has a twin, so prevalence is 50% by construction — a number about how the corpus was
written, not about how often pull requests introduce vulnerabilities. Reading it as a prior
would state that one change in two is vulnerable, and every posterior in the system would
inherit that.

What the corpus *can* supply is the likelihood ratios, because those are conditioned on the
label and so do not depend on prevalence at all (`fit.py`). Prevalence therefore enters exactly
once, here, as a **declared** base rate — and being declared, it is recorded as such. D-010
forbids presenting a hand-set number as calibrated, and the honest form of that is not to hide
the assumption but to name it, record what it was rescaled from, and let it be changed without
refitting anything.

**Rescaling is one line of arithmetic and one line of provenance.** Prior odds are
`π / (1 - π)`; changing the base rate multiplies every posterior's odds by a constant factor.
`rescaling_factor` records that constant, so a reader can convert a published posterior back to
the balanced-corpus figure and check it.

**The same rescaling has to be applied to any rate measured on a balanced split.** Precision on
a 50/50 validation split is not the precision a developer will see at a 3% base rate — it is
far better, because half the changes really are vulnerable. `importance_weights` reweights the
split so that measured precision, ECE and Brier estimate the production quantity rather than a
corpus artefact (D-083).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_BASE_RATE = 0.03
"""The production base rate posteriors are stated at, in the absence of a measured one.

Declared, not fitted, and the artifact says so on its face. PLAN.md Chapter 14 puts the real
rate at 2-5%; 3% sits in the middle of that band. It is a field of the artifact rather than a
constant in the fusion path precisely so that replacing it is a re-fit of nothing: the ratios
are unchanged, the prior odds move by a recorded factor, and the threshold is re-swept.
"""


class Prior(BaseModel):
    """The prior fusion runs at, and everything needed to check it."""

    model_config = ConfigDict(frozen=True)

    base_rate: float = Field(gt=0.0, lt=1.0)
    """The probability a randomly chosen changed function is vulnerable. Declared."""

    source: str = "declared"
    """`declared` or `measured`. Never `measured` from a balanced corpus."""

    corpus_prevalence: float = Field(ge=0.0, le=1.0)
    """What the calibration split's prevalence actually was. Recorded so the rescaling
    below is a statement about two named numbers rather than about one."""

    rationale: str = ""

    @property
    def odds(self) -> float:
        return self.base_rate / (1.0 - self.base_rate)

    @property
    def corpus_odds(self) -> float:
        prevalence = min(max(self.corpus_prevalence, 1e-9), 1 - 1e-9)
        return prevalence / (1.0 - prevalence)

    @property
    def rescaling_factor(self) -> float:
        """`odds / corpus_odds`. Multiply a balanced-corpus odds by this to get ours."""
        return self.odds / self.corpus_odds


def importance_weights(prior: Prior, split_prevalence: float) -> tuple[float, float]:
    """`(weight_positive, weight_negative)` that reweight a balanced split to the base rate.

    A vulnerable claim in a 50/50 split stands for far fewer real changes than a safe one
    does, and weighting is how a rate measured on the split becomes an estimate of the rate
    in production. The weights are normalised to average 1.0 per claim, so counts stay
    readable as counts rather than becoming tiny fractions.
    """
    prevalence = min(max(split_prevalence, 1e-9), 1 - 1e-9)
    return prior.base_rate / prevalence, (1.0 - prior.base_rate) / (1.0 - prevalence)
