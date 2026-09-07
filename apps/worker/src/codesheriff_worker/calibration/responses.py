"""Recorded model output, replayed — so a fit is reproducible and costs nothing to re-run.

The semantic witness is the only one whose answer is not a function of its input. Fitting a
likelihood ratio against a model that has a different day each time would produce a number
nobody could reproduce from the recorded corpus hash, which is exactly what §6 forbids. So its
responses are recorded **once** and replayed, the same discipline Chapter 11's cassettes
established (D-068), extended here to the validation split.

Two stores, read in order, and which one answered is recorded in the run's provenance:

* `packages/agent_semantic/tests/cassettes/` — the calibration recordings, shared with the
  semantic agent's own corpus measurement. Shared deliberately: two recordings of the same
  case against the same prompt would be two answers to one question, and the first time they
  disagreed nobody would know which had been fitted on.
* `calibration/responses/` — everything this harness recorded that the suite must not read.
  Validation responses live here and **only** here. The semantic test suite runs on every
  commit, and a suite that could reach validation recordings would be iterating against the
  split §6 reserves for selecting the threshold.

**A case with no recording gets a client that refuses.** Not a live client, and not a stub: a
stub answers anything it does not recognise with `{"findings": []}`, which the agent would
report as SILENCE across all ten in-scope CWEs — a witness that read nothing arguing, below a
likelihood ratio of 1.0, that the code is safe (`AUDIT.md` 3.12). Refusing produces an
`llm_unavailable` abstention, which contributes exactly 1.0 and is honest about why.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from codesheriff_corpus.models import CorpusCase
from semantic_agent.llm.hosted import ProviderUnavailableError

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[5]
CASSETTE_DIR = REPO_ROOT / "packages" / "agent_semantic" / "tests" / "cassettes"
HARNESS_DIR = REPO_ROOT / "calibration" / "responses"


@dataclass(frozen=True)
class Recording:
    """Every sample recorded for one case, and where it was read from."""

    case_id: str
    model: str
    prompt_fingerprint: str
    samples: tuple[str, ...]
    source: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "case_id": self.case_id,
                "model": self.model,
                "prompt_fingerprint": self.prompt_fingerprint,
                "samples": list(self.samples),
            },
            indent=2,
        )


@dataclass
class ResponseStore:
    """Recorded responses, looked up by case id across both directories."""

    directories: tuple[tuple[str, Path], ...] = (
        ("cassettes", CASSETTE_DIR),
        ("harness", HARNESS_DIR),
    )
    _cache: dict[str, Recording | None] = field(default_factory=dict)

    def get(self, case_id: str) -> Recording | None:
        if case_id not in self._cache:
            self._cache[case_id] = self._read(case_id)
        return self._cache[case_id]

    def _read(self, case_id: str) -> Recording | None:
        for name, directory in self.directories:
            path = directory / f"{case_id}.json"
            if not path.is_file():
                continue
            raw = json.loads(path.read_text(encoding="utf-8"))
            samples = tuple(raw["samples"])
            if not samples:
                logger.warning("Recording %s holds no samples; treating as absent", path)
                return None
            return Recording(
                case_id=raw["case_id"],
                model=raw.get("model", "unknown"),
                prompt_fingerprint=raw.get("prompt_fingerprint", ""),
                samples=samples,
                source=name,
            )
        return None

    def write(self, recording: Recording, directory: Path = HARNESS_DIR) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{recording.case_id}.json"
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(recording.to_json())
            handle.write("\n")
        self._cache.pop(recording.case_id, None)
        return path

    def sources(self, cases: list[CorpusCase]) -> dict[str, int]:
        """How many cases each store answered for. Goes into the run's provenance."""
        counts: dict[str, int] = {"cassettes": 0, "harness": 0, "missing": 0}
        for case in cases:
            recording = self.get(case.case_id)
            counts[recording.source if recording else "missing"] += 1
        return counts


class ReplayClient:
    """An `LLMClient` that replays a recording instead of calling anything.

    Samples are returned in the order they were recorded, so self-consistency aggregation sees
    the same spread of answers the live run produced — including disagreement between samples,
    which is the signal `raw_score` is derived from and would be lost by replaying one answer
    three times.
    """

    def __init__(self) -> None:
        self._recording: Recording | None = None
        self._calls = 0

    def bind(self, recording: Recording | None) -> None:
        self._recording = recording
        self._calls = 0

    @property
    def recording(self) -> Recording | None:
        return self._recording

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: object,
        temperature: float = 0.3,
        seed: int | None = None,
    ) -> str:
        if self._recording is None:
            raise ProviderUnavailableError(
                "no recorded response for this unit; nothing was replayed and nothing was "
                "called. Record one with `codesheriff-worker calibrate record`."
            )
        sample = self._recording.samples[self._calls % len(self._recording.samples)]
        self._calls += 1
        return sample
