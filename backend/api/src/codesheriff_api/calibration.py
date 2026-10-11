"""What the fitted numbers are, and what they rest on.

The project's claim is that a stated 87% corresponds to being right 87% of the time. A dashboard
that shows the 87% and not the evidence for that correspondence is the tool this project was
written to argue against, carried out in a nicer font. This endpoint is the evidence: the
reliability bins the metric was computed over, the per-cell observation counts behind every
likelihood ratio, the whole validation threshold sweep rather than the winning point, and the
provenance saying which backends were actually running when the observations were made.

**It serves the artifact, and it does not compute.** No ratio is derived here, no metric is
recalculated, nothing is rounded on the way out. `calibration.json` is the single source of every
ratio, prior and threshold (D-080); a route that recomputed any of them would be a second
implementation whose agreement with the first nobody checks.

**A missing artifact is a 503, not an empty page.** There is no fallback table anywhere in this
codebase by design (D-082), and the honest report of that at the edge is "this deployment cannot
tell you how reliable it is" — not a blank card that reads as "no findings yet".
"""

from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from codesheriff_api.deps import SessionDep
from codesheriff_engine.calibration import (
    CALIBRATION_PATH_ENV,
    CalibrationArtifact,
    CalibrationError,
    active_artifact,
)
from codesheriff_engine.fusion.witnesses import WITNESSES, agents_of

router = APIRouter(tags=["calibration"])


class WitnessOut(BaseModel):
    """One witness and the backends registered to speak for it.

    Backends are listed under their witness rather than beside it because that grouping is the
    whole of D-052: `structural.taint` and `structural.semgrep` are two analyses of the same
    source text, and a UI that listed them as peers of `semantic.hosted` would be drawing the
    independence violation the fusion engine exists to refuse.
    """

    witness: str
    agents: list[str]


class CalibrationOut(BaseModel):
    """The active artifact, verbatim, plus where it came from.

    `source` says whether the packaged artifact or a `CALIBRATION_PATH` override is in force. It
    reports which of the two, never the filesystem path: the path is the server's business, and
    the only thing a reader needs is whether the numbers are the committed ones.
    """

    source: str
    artifact: CalibrationArtifact
    witnesses: list[WitnessOut]


@router.get("/calibration", response_model=CalibrationOut)
def get_calibration(session: SessionDep) -> CalibrationOut:
    """The fitted artifact this deployment fuses with.

    Behind the session like every other route. Not because the numbers are secret — they are
    committed to the repository and belong in the paper — but because an unauthenticated endpoint
    is a decision, and this one has no reason to be the first.
    """
    try:
        artifact = active_artifact()
    except CalibrationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"No calibration artifact could be loaded, so this deployment cannot state how "
                f"reliable its posteriors are: {exc}"
            ),
        ) from exc

    return CalibrationOut(
        source="override" if os.environ.get(CALIBRATION_PATH_ENV) else "packaged",
        artifact=artifact,
        witnesses=[
            WitnessOut(witness=witness, agents=list(agents_of(witness))) for witness in WITNESSES
        ],
    )
