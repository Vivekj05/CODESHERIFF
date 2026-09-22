"""What the patcher is allowed to do, and how hard it is allowed to try.

Every bound here is a refusal rather than a budget. A patcher that keeps drafting until something
passes is selecting for a draft that satisfies the checks rather than one that fixes the code, and
the checks are cheap enough that the difference is invisible from the outside.
"""

from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PATCHER_ID = "patch.hosted"
"""The identity that drafted a suggestion, recorded on every proposal.

Deliberately *not* an `agent_id`. `WITNESS_OF_AGENT` refuses an identifier it does not know
(D-052), and this one must never be registered there: the patcher reads the finding, so it is
maximally dependent on the witnesses that produced it, and a fifth factor drawn from what the
other four already said is the anchoring violation (D-008) wearing a different hat. It emits no
`Evidence` at all — a suggestion is not a statement about whether the code is vulnerable.
"""

PATCHER_VERSION = "0.1.0"

MAX_DRAFTS = 3
"""Drafts per finding, including the first.

Three rather than one because the rejection reasons are specific enough to act on — "you changed
the signature", "you referenced a name the file does not import" — and three rather than ten
because after that the loop stops being iteration and starts being search. A finding with no
verified draft after three publishes nothing, which is the correct outcome: an unverified patch
posted as a suggestion is a change a reviewer is invited to accept on our word.
"""

MAX_UNIT_BYTES = 24_000
"""Largest function this patcher will draft against.

The same rule the semantic agent applies to analysis (D-015), for the same reason and one more.
A truncated unit produces a patch for code the model never saw, and the patch would then be
checked against the whole function and rejected — spending three drafts to discover the input was
short. Oversized units are declined up front, under their own reason.
"""


class PatchConfig(BaseSettings):
    """Configuration for drafting. Nothing here identifies the patcher."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    max_drafts: int = Field(default=MAX_DRAFTS, alias="PATCH_MAX_DRAFTS")
    max_unit_bytes: int = Field(default=MAX_UNIT_BYTES, alias="PATCH_MAX_UNIT_BYTES")

    temperature: float = Field(default=0.2, alias="PATCH_TEMPERATURE")
    """Lower than the semantic agent's 0.3. That agent samples three times and reads the spread as
    a confidence signal; this one wants the most conventional repair it can get, and disagreement
    between drafts here is noise rather than evidence."""

    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GEMINI_API_KEY", "GOOGLE_API_KEY", "LLM_API_KEY"),
    )
    """The same key `semantic.hosted` reads, under the same names.

    Read here rather than reached for through `SemanticConfig`, because the patcher is not part of
    that agent and a subsystem that borrows another's configuration object acquires its defaults by
    accident. It is a *value*, not a client: this package cannot open a socket (`lint-imports`
    forbids `httpx` here), so the key is carried across to `apps/worker`, which builds the client.

    Unset means the patcher is unavailable and every alert-worthy finding records
    `patcher_unavailable`. It must never fall back to a stub — a stub that answered would produce
    a suggestion nobody's model wrote.
    """

    model: str = Field(default="gemini-3.5-flash", alias="PATCH_MODEL")
    """Pinned, never a `-latest` alias — the same rule `SemanticConfig.model` states, minus the
    calibration argument, which does not apply: no number is fitted against the patcher."""

    enabled: bool = Field(default=True, alias="PATCH_ENABLED")
    """Off means no draft is requested and every alert-worthy finding records
    `patcher_unavailable`. It does not mean patches are silently skipped: the pull request comment
    says a suggestion was not attempted, in the same place it would have said one was."""

    @classmethod
    def load(cls) -> PatchConfig:
        return cls()
