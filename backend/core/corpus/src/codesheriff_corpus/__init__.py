"""Labelled corpus and committed splits (PLAN.md Chapter 7).

Gates every numeric claim the project makes: likelihood ratios, the prior, and the
alert threshold are all fitted here or they are asserted, and asserting them is the
failure the paper exists to criticise.

  The corpus is not a training set for detecting vulnerabilities. It answers a
  different question: how much each agent should be trusted when it speaks.
  The learning is about the witnesses, not the crime.

Nothing that analyses code may import this package. An agent that can read
`detectable_by` can be excused by it, and an agent that can read `label` is not being
measured at all — enforced by import-linter in the root pyproject.toml.
"""

from codesheriff_corpus.hashing import case_digest, corpus_hash, split_hash
from codesheriff_corpus.loader import CorpusError, case_by_id, load_cases, load_pairs
from codesheriff_corpus.models import (
    CORPUS_REPO,
    KNOWN_AGENT_IDS,
    CorpusCase,
    Label,
    Split,
)
from codesheriff_corpus.splits import (
    DEFAULT_SPLIT_RATIOS,
    SplitFile,
    cases_in,
    load_splits,
    pairs_in,
    split_for,
)

__all__ = [
    "CORPUS_REPO",
    "DEFAULT_SPLIT_RATIOS",
    "KNOWN_AGENT_IDS",
    "CorpusCase",
    "CorpusError",
    "Label",
    "Split",
    "SplitFile",
    "case_by_id",
    "case_digest",
    "cases_in",
    "corpus_hash",
    "load_cases",
    "load_pairs",
    "load_splits",
    "pairs_in",
    "split_for",
    "split_hash",
]
