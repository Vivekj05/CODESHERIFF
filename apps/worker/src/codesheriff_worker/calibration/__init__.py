"""The calibration harness: run the agents over the corpus, fit, and write the artifact.

It lives in `apps/worker` because running agents is `apps/worker`'s job and nothing else's
(D-054). The alternative — a research package that loaded the agents its own way — would have
measured an object production never builds, which is the failure this whole chapter exists to
avoid making at the level of numbers.

**The audit path cannot reach any of this, and cannot reach the corpus.** `lint-imports` holds
`codesheriff_worker.tasks`, `.pipeline` and `.analysis` away from `codesheriff_corpus` (D-086):
the harness may read labels because measuring is what it does, and the code that analyses a
real pull request may not, because an analysis path that can see ground truth is not being
measured — it is being told the answer.
"""

from codesheriff_worker.calibration.fitting import fit_from_observations, write_artifact
from codesheriff_worker.calibration.recorder import RecordingReport, record_split
from codesheriff_worker.calibration.responses import Recording, ReplayClient, ResponseStore
from codesheriff_worker.calibration.runner import (
    TestSplitSealedError,
    cases_in_split,
    observations_path,
    observe,
    read,
    write,
)

__all__ = [
    "Recording",
    "RecordingReport",
    "ReplayClient",
    "ResponseStore",
    "TestSplitSealedError",
    "cases_in_split",
    "fit_from_observations",
    "observations_path",
    "observe",
    "read",
    "record_split",
    "write",
    "write_artifact",
]
