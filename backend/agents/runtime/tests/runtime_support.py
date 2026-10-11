"""Shared constants and the interpreter skip for the runtime agent's tests.

Imported as `from .runtime_support import ...`, the relative form this repository already
uses for `agent_context`'s `context_support` and `apps/worker`'s `payloads` - the one that
works under `--import-mode=importlib`. `conftest.py` cannot use that form, so the few lines
it needs are repeated there rather than shared from here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_runtime.config import RuntimeConfig
from agent_runtime.interpreter import InterpreterUnavailableError, locate
from agent_runtime.sandbox import SandboxPolicy

GENEROUS = SandboxPolicy(fuel=50_000_000_000, wall_clock_seconds=60.0, memory_bytes=512 << 20)
"""Enough for CPython to start and run a small function, with both caps still armed."""


def interpreter_or_none() -> Path | None:
    """The pinned WASI CPython build, if this machine has it."""
    try:
        return locate(RuntimeConfig(verify_interpreter_digest=True))
    except InterpreterUnavailableError:
        return None


requires_interpreter = pytest.mark.skipif(
    interpreter_or_none() is None,
    reason="the pinned WASI CPython build is not present; run `runtime-agent doctor`",
)
"""The `wasm` marker's teeth. Same principle as `db` (D-029): the sandbox runs a real
interpreter inside a real Wasmtime engine, or these tests do not run. There is no in-process
fake, deliberately - a faked sandbox measures the fake, and the isolation claim is this
chapter's whole deliverable."""
