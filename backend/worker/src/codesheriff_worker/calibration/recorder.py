"""Recording the semantic witness's answers for a split the test suite must never read.

Chapter 11 records the **calibration** split into `packages/agent_semantic/tests/cassettes/`,
where the semantic agent's own measurement replays them. That directory is deliberately
calibration-only: the suite runs on every commit, and a suite that could reach validation
recordings would be iterating against the split §6 reserves for selecting the threshold.

Selecting a threshold, though, requires posteriors on validation — real ones, from all four
witnesses. A semantic witness that abstained across the whole split would put the cut point on
a three-witness quantity that production never computes. So the model is asked about the
validation cases **once**, here, and the answers are written to `calibration/responses/`, which
no test reads and this harness replays for every subsequent fit.

That is the entire live-API surface of Chapter 14, it happens under a command a person types,
and its output is committed so nobody has to run it again.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass

from codesheriff_corpus.models import CorpusCase, Split
from codesheriff_worker.calibration.responses import HARNESS_DIR, Recording, ResponseStore
from codesheriff_worker.calibration.runner import cases_in_split
from semantic_agent.agent import CACHE_KEY_NONCE, SemanticAgent
from semantic_agent.config import SemanticConfig
from semantic_agent.llm.hosted import ProviderUnavailableError
from semantic_agent.schema import LLMResponse

logger = logging.getLogger(__name__)

PACE_SECONDS = float(os.environ.get("CALIBRATION_RECORD_PACE", "5.0"))
"""Seconds between samples, from `CALIBRATION_RECORD_PACE`.

The free tier limits requests **per minute**, and the client's own retry budget — three
attempts with at most twelve seconds of backoff — is far shorter than the window a 429 asks
you to wait for. Recording without pacing therefore does not fail slowly, it fails at the
sixteenth call and reports every remaining case as `provider unavailable`, which reads exactly
like a daily quota being exhausted. Default 5s, comfortably under a 15-per-minute ceiling.
"""


def prompt_fingerprint(system_prompt: str, cache_prompt: str) -> str:
    """A stable id for "the prompt we would send", ignoring the per-request sentinel.

    Deliberately identical to the semantic package's own definition, which lives beside the
    cassettes it stamps and is therefore in a test directory this cannot import. Identical is
    the requirement: a recording carries a fingerprint so that a later prompt edit invalidates
    it, and a fingerprint computed a second way would invalidate nothing.
    """
    joined = f"{system_prompt}\x00{cache_prompt}"
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class RecordingReport:
    written: int
    skipped: int
    failed: list[str]


def record_case(case: CorpusCase, agent: SemanticAgent) -> Recording | None:
    """Every sample for one case, or None if the provider never answered."""
    unit = case.unit
    context = agent.retriever.retrieve(unit)
    cache_prompt = agent.build_prompt(unit, context, CACHE_KEY_NONCE)

    if agent.llm_client is None:
        return None

    samples: list[str] = []
    for index in range(agent.config.n_samples):
        prompt = agent.build_prompt(unit, context, agent.new_nonce())
        try:
            samples.append(
                agent.llm_client.generate(
                    system_prompt=agent._system_prompt,
                    user_prompt=prompt,
                    schema=LLMResponse,
                    temperature=agent.config.temperature,
                    seed=100 + index,
                )
            )
        except ProviderUnavailableError as exc:
            logger.warning("%s sample %s: provider unavailable (%s)", case.case_id, index, exc)
            return None
        time.sleep(PACE_SECONDS)

    return Recording(
        case_id=case.case_id,
        model=agent.config.model,
        prompt_fingerprint=prompt_fingerprint(agent._system_prompt, cache_prompt),
        samples=tuple(samples),
        source="harness",
    )


def record_split(
    split: Split,
    *,
    store: ResponseStore | None = None,
    missing_only: bool = True,
) -> RecordingReport:
    """Ask the model about every case in `split` that has no recording yet.

    `missing_only` defaults to True because re-recording a case that already has an answer
    changes a committed measurement for no reason. The fingerprint recorded beside each answer
    is what says whether it still answers the prompt we send; an unchanged prompt needs no new
    answer, and a changed one turns the semantic suite red on purpose.
    """
    config = SemanticConfig.load()
    if not config.api_key:
        raise RuntimeError(
            "no API key configured, so nothing can be recorded. Set GEMINI_API_KEY in .env "
            "(see .env.example); the agent reads it through SemanticConfig, not os.getenv."
        )

    resolved = store or ResponseStore()
    agent = SemanticAgent(config=config)

    written = skipped = 0
    failed: list[str] = []

    for case in sorted(cases_in_split(split), key=lambda c: c.case_id):
        if missing_only and resolved.get(case.case_id) is not None:
            skipped += 1
            continue

        recording = record_case(case, agent)
        if recording is None:
            failed.append(case.case_id)
            continue

        path = resolved.write(recording, HARNESS_DIR)
        logger.info("recorded %s -> %s", case.case_id, path)
        written += 1

    return RecordingReport(written=written, skipped=skipped, failed=failed)
