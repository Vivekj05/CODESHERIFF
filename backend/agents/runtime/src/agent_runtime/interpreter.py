"""Finding the WASI CPython build, and refusing to run one we did not choose.

The interpreter is a 26 MB binary and is deliberately **not committed**. A binary in a git
history is in that history forever, and this project's whole reproducibility argument rests
on artifacts being identified by digest rather than by having been checked in once.

So the agent looks in a short, ordered list of places, verifies what it finds against
`INTERPRETER_SHA256`, and abstains under a distinct reason when it finds nothing. That
abstention is the expected state on a machine that has not fetched the artifact, and
`runtime-agent doctor` exists so the difference between "not fetched" and "broken" takes
one command rather than a debugging session (D-077).

**A digest mismatch is fatal, not a warning.** The security argument is that untrusted code
runs inside a module we chose. A module we did not choose carries no such argument, and the
observation it produces is not the observation this agent's likelihood ratio was fitted
against: a build whose `pickle` is missing turns a detection into an abstention, and one
whose `socket` works turns the sandbox into a proxy.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

from agent_runtime.config import (
    INTERPRETER_FILENAME,
    INTERPRETER_SHA256,
    RuntimeConfig,
    default_interpreter_paths,
)

logger = logging.getLogger(__name__)

RELEASE_URL = (
    "https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/"
    "python%2F3.12.0%2B20231211-040d5a6/python-3.12.0.wasm"
)
"""Where the pinned artifact comes from. Recorded here so a reader can obtain the same
bytes, and printed by `runtime-agent doctor` when the search comes up empty. Nothing in
this package downloads it: an agent that fetched code over the network at analysis time
would be the supply-chain problem this project is meant to notice."""

_DIGEST_CHUNK = 1 << 20


class InterpreterUnavailableError(RuntimeError):
    """No usable interpreter. Carries a machine-readable `reason` for the abstention."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class InterpreterSearch:
    """Every path consulted and what was there. The whole point is that it is complete.

    A search that reports only its result is indistinguishable from one that was never
    run, which is the shape of `AUDIT.md` 3.8 - a fallback that answered quietly forever.
    """

    searched: tuple[Path, ...]
    found: Path | None
    digest: str | None
    digest_matches: bool | None

    @property
    def usable(self) -> bool:
        return self.found is not None and self.digest_matches is not False


def digest_of(path: Path) -> str:
    """SHA-256 of a file, read in chunks - the artifact is 26 MB."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_DIGEST_CHUNK):
            hasher.update(chunk)
    return hasher.hexdigest()


def search(config: RuntimeConfig) -> InterpreterSearch:
    """Look for the interpreter without deciding whether the result is acceptable.

    Split from `locate` so `doctor` can report a mismatch rather than only a failure: a
    file that is present and wrong is a different problem from a file that is absent, and
    it needs a different fix.
    """
    candidates: tuple[Path, ...]
    if config.interpreter_path is not None:
        candidates = (config.interpreter_path,)
    else:
        candidates = default_interpreter_paths()

    for candidate in candidates:
        if not candidate.is_file():
            continue
        found_digest = digest_of(candidate)
        return InterpreterSearch(
            searched=candidates,
            found=candidate,
            digest=found_digest,
            digest_matches=found_digest == INTERPRETER_SHA256,
        )
    return InterpreterSearch(searched=candidates, found=None, digest=None, digest_matches=None)


def locate(config: RuntimeConfig) -> Path:
    """The interpreter to run, or an `InterpreterUnavailableError` naming why not."""
    result = search(config)

    if result.found is None:
        raise InterpreterUnavailableError(
            "interpreter_unavailable",
            f"No {INTERPRETER_FILENAME} found. Looked in: "
            f"{', '.join(str(p) for p in result.searched)}. Fetch it from {RELEASE_URL} "
            f"(sha256 {INTERPRETER_SHA256}) or set CODESHERIFF_RUNTIME_INTERPRETER_PATH. "
            "Run `runtime-agent doctor` for the full report.",
        )

    if not result.digest_matches:
        if config.verify_interpreter_digest:
            raise InterpreterUnavailableError(
                "interpreter_digest_mismatch",
                f"{result.found} has sha256 {result.digest}, expected {INTERPRETER_SHA256}. "
                "Refusing to execute untrusted code inside an interpreter this agent was not "
                "built and measured against.",
            )
        # Recorded loudly rather than passed over. A run made with verification off is
        # identifiable afterwards from its own logs, which a silent acceptance would not be.
        logger.warning(
            "running with an UNVERIFIED interpreter at %s (sha256 %s, expected %s) because "
            "verify_interpreter_digest is off; findings from this run are not comparable to "
            "any calibrated number",
            result.found,
            result.digest,
            INTERPRETER_SHA256,
        )

    return result.found
