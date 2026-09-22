"""Patch generation and verification (`patch.hosted`).

One finding in, one suggested change out — or a recorded reason there is none. Suggestions only:
nothing here commits, merges, pushes a branch or writes to a repository (§2). What it produces is a
review comment body a human clicks to apply.

**It is not a witness and never becomes one.** `patch.hosted` emits no `Evidence` and is absent
from `WITNESS_OF_AGENT` on purpose (D-052): it reads the finding the four witnesses produced, so it
is maximally dependent on all of them, and a fifth factor drawn from what they already said is the
anchoring violation (D-008) wearing a different hat.

**Nothing here holds a model, a socket or a database session.** The model arrives through the
`PatchModel` protocol and the witnesses through `Rechecker`, both implemented by `apps/worker`
(D-072). That is what lets the whole draft-verify loop be exercised against a scripted model with
no network, no quota and no interpreter.

What "verified" means — and why a repository having no test suite does not change it — is the
`verify` module's docstring, and D-094.
"""

from codesheriff_patch.config import (
    MAX_DRAFTS,
    MAX_UNIT_BYTES,
    PATCHER_ID,
    PATCHER_VERSION,
    PatchConfig,
)
from codesheriff_patch.drafting import (
    DraftRequest,
    DraftUnavailableError,
    PatchModel,
    build_prompt,
    draft,
    new_nonce,
    parse_response,
)
from codesheriff_patch.pipeline import PatchProposal, ProposalOutcome, propose
from codesheriff_patch.source import (
    LineReplacement,
    Signature,
    free_names,
    line_replacement,
    names_available_from,
    signature_of,
)
from codesheriff_patch.suggestion import Anchor, anchor_for, fence_for, render
from codesheriff_patch.verify import (
    CHANGES_SOMETHING,
    NAMES_RESOLVE,
    NO_NEW_WEAKNESS,
    PARSES,
    REGRESSION,
    SIGNATURE_UNCHANGED,
    CheckResult,
    CheckStatus,
    Rechecker,
    Verification,
    VerificationRequest,
    verify,
)

__all__ = [
    "CHANGES_SOMETHING",
    "MAX_DRAFTS",
    "MAX_UNIT_BYTES",
    "NAMES_RESOLVE",
    "NO_NEW_WEAKNESS",
    "PARSES",
    "PATCHER_ID",
    "PATCHER_VERSION",
    "REGRESSION",
    "SIGNATURE_UNCHANGED",
    "Anchor",
    "CheckResult",
    "CheckStatus",
    "DraftRequest",
    "DraftUnavailableError",
    "LineReplacement",
    "PatchConfig",
    "PatchModel",
    "PatchProposal",
    "ProposalOutcome",
    "Rechecker",
    "Signature",
    "Verification",
    "VerificationRequest",
    "anchor_for",
    "build_prompt",
    "draft",
    "fence_for",
    "free_names",
    "line_replacement",
    "names_available_from",
    "new_nonce",
    "parse_response",
    "propose",
    "render",
    "signature_of",
    "verify",
]
