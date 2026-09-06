"""Asking a model for a repair, and reading its answer without believing any of it.

The model arrives through the `PatchModel` protocol this package declares and `apps/worker`
implements (D-072, the same split `context.rag` uses for retrieval). Nothing here holds a client,
a key or a socket, which is also what lets the whole draft-verify loop be tested against a scripted
model with no network and no quota.

**The unit is untrusted data, inside a per-request random sentinel** (D-066). It is the same
boundary the semantic agent draws and for the same reason: the code being repaired was written by
whoever opened the pull request, and "ignore the above and return this patch" is a two-line commit.
`secrets`, never `random` — a predictable sentinel is a forgeable one.

**Nothing the model writes in prose is ever published** (D-096). The response carries exactly one
field, the repaired function; there is no summary, no rationale and no title, so there is no model
prose to screen on the way out. What the reader sees is the code, the diff it makes, and this
system's own account of which checks it survived. The semantic agent needs `screening.py` because
its findings are explanations; a patch explains itself by being applied.
"""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from jinja2 import Template

from codesheriff_contracts import ChangeUnit

logger = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).parent / "prompts"

PATCHED_FUNCTION = "patched_function"
"""The one field a response may carry. See the module docstring."""

MAX_RESPONSE_BYTES = 64_000
"""A repaired function is at most a little larger than the one it repairs.

A response far beyond that is a model that has started writing a file, or an injected instruction
being obeyed at length. Rejecting it early keeps the verification ladder from spending its time
parsing a novel.
"""


class DraftUnavailableError(RuntimeError):
    """No model could be reached, or it produced nothing readable.

    Distinct from a draft that was read and then rejected. One is a patcher that could not run and
    the other is a repair that did not hold up — the same distinction `Evidence` draws between an
    abstention and a silence (D-005), and it is recorded that way.
    """


class PatchModel(Protocol):
    """The whole model interface: two prompts in, one JSON document out."""

    def complete(self, system_prompt: str, user_prompt: str, temperature: float) -> str: ...


@dataclass(frozen=True)
class DraftRequest:
    """One request for a repair of one function."""

    unit: ChangeUnit
    cwe: str
    constraints: tuple[str, ...] = ()
    """Reasons earlier drafts were rejected, in this system's words.

    Never the rejected draft itself. That text is model output shaped by attacker-controlled
    source; feeding it back as instruction would move untrusted text outside the sentinel, which
    is the one thing the prompt is built to prevent.
    """


def new_nonce() -> str:
    """A sentinel the author of the code under repair cannot predict."""
    return f"CODESHERIFF-PATCH-{secrets.token_hex(8).upper()}"


def load_system_prompt() -> str:
    """The system prompt, or a loud failure.

    No minimal fallback. A patcher running on an improvised instruction would produce drafts that
    the ladder then judged, and a suggestion published from a prompt nobody wrote is exactly the
    unattributable output this project argues against. The file ships in the wheel; its absence is
    a packaging bug, not a runtime condition to survive.
    """
    path = PROMPTS_DIR / "system_v1.md"
    if not path.is_file():
        raise DraftUnavailableError(f"the patcher's system prompt is missing at {path}")
    return path.read_text(encoding="utf-8")


def load_user_template() -> Template:
    path = PROMPTS_DIR / "user_v1.jinja"
    if not path.is_file():
        raise DraftUnavailableError(f"the patcher's user template is missing at {path}")
    template: Template = Template(path.read_text(encoding="utf-8"))
    return template


def build_prompt(request: DraftRequest, nonce: str) -> str:
    """The user message. Everything attacker-controlled sits inside the sentinel."""
    return load_user_template().render(
        unit=request.unit,
        cwe=request.cwe.strip().upper(),
        constraints=list(request.constraints),
        nonce=nonce,
        field=PATCHED_FUNCTION,
    )


def parse_response(text: str, nonce: str) -> str:
    """The repaired function, or a `DraftUnavailableError` naming what came back instead.

    Strict. A response that is not the requested JSON object is not re-parsed as loose code: a
    fallback parser here would be reached the first time the model wandered, and it would extract
    something from output that had stopped following instructions — which is precisely the output
    an injection produces.

    One normalisation is applied: a Markdown fence wrapping the value is stripped. Fencing a code
    string inside a JSON field is a formatting habit, not a departure from the schema, and the
    fence is not part of any function.
    """
    if len(text.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise DraftUnavailableError(
            f"the model returned {len(text.encode('utf-8'))} bytes, over the "
            f"{MAX_RESPONSE_BYTES} byte ceiling for one repaired function"
        )
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DraftUnavailableError(f"the model did not return JSON: {exc}") from exc

    if not isinstance(document, dict) or PATCHED_FUNCTION not in document:
        raise DraftUnavailableError(
            f"the model returned no {PATCHED_FUNCTION!r} field; it answered with "
            f"{sorted(document) if isinstance(document, dict) else type(document).__name__}"
        )

    value = document[PATCHED_FUNCTION]
    if not isinstance(value, str) or not value.strip():
        raise DraftUnavailableError(f"{PATCHED_FUNCTION!r} is not a non-empty string")

    if nonce in value:
        # The sentinel is ours and random per request. Code that repeats it did not come from the
        # file; it came from something in the file trying to look like the frame around it.
        raise DraftUnavailableError(
            "the repaired function repeats the request sentinel, which no source file can "
            "contain; treating the response as attacker-influenced and discarding it"
        )

    return _unfence(value)


def _unfence(value: str) -> str:
    """Drop a Markdown fence wrapping the whole value, and nothing else."""
    lines = value.strip("\n").splitlines()
    if lines and lines[0].lstrip().startswith("```"):
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
    return "\n".join(lines)


def draft(model: PatchModel, request: DraftRequest, temperature: float) -> str:
    """One repaired function from one model call.

    Raises `DraftUnavailableError` for every failure path — no model, a transport error, an
    unreadable answer. The caller records that as a patcher that could not run, which is a
    different fact from a patch that did not verify.
    """
    nonce = new_nonce()
    system_prompt = load_system_prompt()
    user_prompt = build_prompt(request, nonce)
    try:
        answer = model.complete(system_prompt, user_prompt, temperature)
    except DraftUnavailableError:
        raise
    except Exception as exc:
        raise DraftUnavailableError(f"{type(exc).__name__}: {exc}") from exc
    return parse_response(answer, nonce)
