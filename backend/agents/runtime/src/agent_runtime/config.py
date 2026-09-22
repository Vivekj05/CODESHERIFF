"""Configuration for `runtime.sfi`.

Every number here is a **capability bound**, not a tuning knob, and that distinction is
why they are separated from the scoring constants the way they are. A fuel budget that is
too small produces an abstention; one that is too large produces a slow audit. Neither
produces a wrong answer, which is the property a resource cap has to have.

The interpreter path is the one setting with no safe default. There is no bundled
`python.wasm` (26 MB, and a binary in a git history is a binary in that history forever),
so the agent looks where it is told and abstains — loudly, under a distinct reason — when
it does not find it. `runtime-agent doctor` reports exactly where it looked (D-077).
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

AGENT_ID = "runtime.sfi"
"""Registered against the RUNTIME witness in `codesheriff_engine.fusion.witnesses`.

A module constant rather than a setting, for the reason `context_agent` gives: an
`agent_id` that an environment variable can change is one that can be changed to a value
fusion does not recognise, and fusion raises on an unregistered id by design.
"""

AGENT_VERSION = "0.2.0"
"""Chapter 13: the sandbox and the probe. 0.1.0 was an empty package."""

COVERED_CWES: frozenset[str] = frozenset(
    {
        "CWE-22",  # a composed path reaches a filesystem operation
        "CWE-78",  # a value reaches a shell
        "CWE-94",  # a value reaches an evaluator
        "CWE-502",  # a value reaches a deserialiser
        "CWE-918",  # a value reaches an outbound request
    }
)
"""What this witness can observe, and therefore what its SILENCE may argue about (D-006).

Five of the ten in-scope CWEs, and the omissions are the mechanism rather than a gap.

**CWE-89 and CWE-79 are absent because their sinks are not names.** `cursor.execute(sql)`
is a method on a connection object the unit builds at runtime; `template.render(...)` is a
method on a template object. The harness can only interpose on names it binds into the
unit's namespace — `os.system`, `pickle.loads`, `eval`, `urlopen` — so a database cursor
that the probe itself fabricated is a stub calling a stub, and any "observation" of SQL
injection there would be an observation of the harness. Reporting it would be this witness
restating the structural witness's finding by a weaker method, which is exactly the
correlation D-011 exists to prevent.

**CWE-862, CWE-639 and CWE-798 are absent because there is nothing to observe.** A missing
authorisation check is the absence of an event, and a hard-coded credential is a fact about
the source text. Neither becomes visible by running the function once.

The corpus pre-registered exactly these five in `detectable_by` before this agent existed
(D-047), and that pre-registration is what makes the narrowness a claim rather than a
convenience.
"""


def default_interpreter_paths() -> tuple[Path, ...]:
    """Where the WASI CPython build is looked for when nothing names it.

    Ordered, and every one of them is reported by `runtime-agent doctor` whether it hit or
    missed — a search path that fails silently is indistinguishable from a search path that
    was never consulted.
    """
    candidates = [Path.cwd() / ".wasm-runtimes", Path.home() / ".cache" / "codesheriff" / "wasm"]
    if xdg := os.environ.get("XDG_CACHE_HOME"):
        candidates.insert(1, Path(xdg) / "codesheriff" / "wasm")
    return tuple(c / INTERPRETER_FILENAME for c in candidates)


INTERPRETER_FILENAME = "python-3.12.0.wasm"
"""The artifact this agent is built against, by name and by digest.

Pinned rather than "whatever python.wasm is lying around" because the observation depends
on which standard library the guest has: a build whose `pickle` is missing turns a
detection into an abstention, and a build whose `socket` works turns the sandbox into a
proxy. `INTERPRETER_SHA256` is checked on load.
"""

INTERPRETER_SHA256 = "e5dc5a398b07b54ea8fdb503bf68fb583d533f10ec3f930963e02b9505f7a763"
"""SHA-256 of `python-3.12.0.wasm` from vmware-labs/webassembly-language-runtimes,
release `python/3.12.0+20231211-040d5a6`. Published by the project beside the artifact.

Verified on load, and a mismatch is an abstention rather than a warning. The whole
security argument of this agent is that untrusted code runs inside a module we chose; a
module we did not choose has no such argument, and running it anyway to save an audit is
the trade this project does not make.
"""


class RuntimeConfig(BaseSettings):
    """Resource bounds and the interpreter location. Provisional until Chapter 14 (D-010)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="CODESHERIFF_RUNTIME_",
        extra="ignore",
    )

    interpreter_path: Path | None = None
    """Explicit path to the WASI CPython module. `None` searches `default_interpreter_paths()`."""

    verify_interpreter_digest: bool = True
    """Whether a digest mismatch is fatal. Off only to test a different build deliberately;
    the agent logs a WARNING naming the digest it actually loaded, so a run made with this
    off is identifiable afterwards from its own logs."""

    fuel: int = Field(default=20_000_000_000, ge=1_000_000)
    """Deterministic instruction budget for one unit.

    A bare `print()` costs ~2.6e8 in this build and the isolation probe ~1.3e9, so this is
    roughly seventy interpreter start-ups: generous for one function call, and finite. Fuel
    is what makes the cap *deterministic* — the same unit exhausts it at the same point on
    every machine, which the wall clock cannot promise and which a calibration run needs.
    """

    wall_clock_seconds: float = Field(default=15.0, gt=0.0)
    """Epoch-interruption deadline, the backstop for what fuel cannot bound.

    Fuel counts WebAssembly instructions and a host call that blocks burns none of it. Both
    caps are armed on every run because each one covers the other's blind spot.
    """

    memory_bytes: int = Field(default=512 * 1024 * 1024, ge=16 * 1024 * 1024)
    """Guest linear-memory ceiling. `memory.grow` past it returns -1, which CPython raises
    as `MemoryError` inside the guest — an abstention, not a host OOM."""

    max_unit_bytes: int = Field(default=60_000, ge=1_000)
    """Above this the agent abstains rather than analysing (D-015). Same value the semantic
    and context agents use, so "too large" means one thing across the four witnesses."""

    @classmethod
    def load(cls) -> RuntimeConfig:
        return cls()
