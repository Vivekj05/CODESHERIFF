"""Running all four agents over one split, and writing down what they said.

This is the only place in the project where ground truth and the analysis path meet, and the
meeting is one-directional: the agents are handed `case.unit` and nothing else. They cannot see
`label`, they cannot see `detectable_by`, and `lint-imports` refuses an agent package that
imports the corpus at all (D-047). What this module does with the labels is attach them to the
evidence *afterwards*, which is what measuring is.

**The test split is not reachable from here.** §6 permits it to be evaluated exactly once, at
the end, and Chapter 18 is the end. `observe` refuses it by name rather than by convention: a
harness that would run on the test split if asked is a harness that eventually will be.

**Nothing here writes to a database.** The corpus run needs no session, and giving it one would
put the labelled corpus and the production store in the same process. The output is a JSONL
file that is committed, reviewed and diffed like any other artifact.
"""

from __future__ import annotations

import logging
import os
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path

from codesheriff_corpus.hashing import corpus_hash, split_hash
from codesheriff_corpus.loader import load_cases
from codesheriff_corpus.models import CorpusCase, Split
from codesheriff_corpus.splits import split_for
from codesheriff_engine.calibration.observations import (
    Claim,
    ObservationSet,
    RunProvenance,
    claims_for_case,
)
from codesheriff_worker.analysis import AgentDeps, analyse_unit, load_agents
from codesheriff_worker.calibration.bindings import CaseBoundRetriever
from codesheriff_worker.calibration.responses import ReplayClient, ResponseStore

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[5]
OBSERVATIONS_DIR = REPO_ROOT / "calibration" / "observations"


class TestSplitSealedError(RuntimeError):
    """The test split was asked for before the one time it may be evaluated."""


def cases_in_split(split: Split) -> list[CorpusCase]:
    if split is Split.TEST:
        raise TestSplitSealedError(
            "the test split is evaluated exactly once, at the end (PROJECT_CONTEXT.md §6, "
            "PLAN.md Chapter 18). It is not available to the fitting harness — fit ratios on "
            "calibration, select the threshold on validation, and leave this one alone."
        )
    return [case for case in load_cases() if split_for(case) is split]


def observe(
    split: Split,
    *,
    store: ResponseStore | None = None,
    progress: bool = True,
) -> ObservationSet:
    """Run every agent over every case in `split` and reduce it to labelled claims.

    Agents are loaded **once** and their per-case dependencies rebound between units, because
    the runtime sandbox costs seconds to build and rebuilding it per case would measure
    patience rather than detection. Everything else is the production path: the same slots, the
    same loader, the same `analyse_unit` with its timeout and its guarantee of one statement
    per agent per unit.
    """
    cases = cases_in_split(split)
    if not cases:
        raise ValueError(f"the {split.value} split is empty; the corpus or splits did not load")

    responses = store or ResponseStore()
    retriever = CaseBoundRetriever()
    replay = ReplayClient()

    # A cached answer from an earlier run, keyed on the prompt, would be served in place of the
    # recording this run is supposed to be replaying — two sources of truth for one number.
    os.environ.setdefault("SEMANTIC_ENABLE_CACHE", "false")

    agents = load_agents(deps=AgentDeps(precedent_retriever=retriever, llm_client=replay))

    claims: list[Claim] = []
    agent_versions: dict[str, str] = {}
    spoke: set[str] = set()

    for index, case in enumerate(cases, start=1):
        retriever.bind(case)
        replay.bind(responses.get(case.case_id))

        unit = case.unit
        evidence = analyse_unit(agents, unit)

        for item in evidence:
            agent_versions.setdefault(item.agent_id, item.agent_version)
            if item.kind.value != "abstention":
                spoke.add(item.agent_id)

        claims.extend(
            claims_for_case(
                case_id=case.case_id,
                pair_id=case.pair_id,
                split=split.value,
                cwe=case.cwe,
                finding_key=case.expected_key,
                label_vulnerable=case.is_vulnerable,
                evidence=evidence,
                key_for=unit.key_for,
            )
        )
        if progress:
            logger.info("[%3d/%3d] %s", index, len(cases), case.case_id)

    silent = sorted(set(agent_versions) - spoke)
    if silent:
        logger.warning(
            "These backends abstained on every unit of the %s split: %s. Ratios fitted from this "
            "run describe a witness they were not behind.",
            split.value,
            ", ".join(silent),
        )

    return ObservationSet(
        split=split.value,
        corpus_hash=corpus_hash(),
        split_hash=split_hash(),
        provenance=RunProvenance(
            platform=platform.platform(),
            python_version=sys.version.split()[0],
            generated=datetime.now(UTC).isoformat(timespec="seconds"),
            agent_versions=agent_versions,
            backends_silent=silent,
            semantic_source=", ".join(
                f"{name}={count}" for name, count in sorted(responses.sources(cases).items())
            ),
        ),
        claims=tuple(claims),
    )


def observations_path(split: Split) -> Path:
    return OBSERVATIONS_DIR / f"{split.value}.jsonl"


def write(observations: ObservationSet) -> Path:
    OBSERVATIONS_DIR.mkdir(parents=True, exist_ok=True)
    path = observations_path(Split(observations.split))
    observations.to_jsonl(path)
    return path


def read(split: Split) -> ObservationSet:
    path = observations_path(split)
    if not path.is_file():
        raise FileNotFoundError(
            f"no observations for the {split.value} split at {path}. Run "
            f"`codesheriff-worker calibrate observe --split {split.value}` first."
        )
    observed = ObservationSet.from_jsonl(path)
    current_corpus, current_split = corpus_hash(), split_hash()
    if observed.corpus_hash != current_corpus or observed.split_hash != current_split:
        raise ValueError(
            f"{path} was recorded against corpus {observed.corpus_hash[:12]}/"
            f"split {observed.split_hash[:12]}, and the corpus here is {current_corpus[:12]}/"
            f"{current_split[:12]}. Fitting on it would produce an artifact whose recorded hash "
            f"describes ground truth it was not measured against — re-observe."
        )
    return observed
