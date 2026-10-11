"""Configuration for `context.rag`.

`chroma_db_dir` is gone with the store it pointed at (D-016, `AUDIT.md` 0.2). The agent no
longer owns a vector store, a local directory or an embedding model; it is handed a retriever
and reads what that returns.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

AGENT_ID = "context.rag"
"""Registered against the CONTEXT witness in `codesheriff_engine.fusion.witnesses`.

A module constant rather than a setting. It was configurable, and an `agent_id` that can be
changed by an environment variable is one that can be changed to a value fusion does not
recognise — which raises there, by design, because an unregistered agent would fuse as a fifth
witness with a factor nobody calibrated."""

AGENT_VERSION = "0.2.0"
"""Chapter 12: retrieval-driven, replacing the four substring tests of 0.1.0."""


class ContextConfig(BaseSettings):
    """Runtime knobs. Every number here is provisional until Chapter 14 (D-010)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CODESHERIFF_CONTEXT_",
        extra="ignore",
    )

    top_k: int = Field(default=5, ge=1, le=50)
    """How many merged excerpts to consider.

    Five rather than three: a convention needs corroborating siblings to be visible at all, and
    the `MIN_SUPPORTING_SYMBOLS` test cannot be met by a history that was truncated before the
    second carrier of a control was returned.
    """

    min_similarity: float = Field(default=0.35, ge=0.0, le=1.0)
    """The floor below which a retrieved excerpt is not precedent about this unit.

    Applied here rather than in the query, deliberately. `search_precedents` defaults to no
    floor and returns the nearest `limit` rows with their similarities, because a store that
    filtered would return fewer rows than asked for and read as "this repository has no
    precedent" — a different claim entirely, and one that would turn a threshold into an
    abstention. Deciding what is close enough is the agent's judgement, and eventually a
    fitted number.
    """

    max_unit_bytes: int = Field(default=60_000, ge=1_000)
    """Above this the agent abstains rather than analysing (D-015).

    Same value the semantic agent uses. Not a token limit — nothing here calls a model — but
    the point past which one "function" is not the thing this analysis was designed for, and a
    control surface mined from 60 kB of code is not a claim about a guard.
    """

    @classmethod
    def load(cls) -> ContextConfig:
        return cls()
