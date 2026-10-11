"""Fixtures for the runtime witness.

The shared constants and the interpreter skip live in `runtime_support`, imported by test
modules as `from .runtime_support import ...` - the relative form this repository uses under
`--import-mode=importlib`. This file cannot use that form, so it re-derives the two things
it needs rather than importing them.

The WAT fixtures the tests build through `wat` need no interpreter at all: they are
hand-written WebAssembly that calls one WASI function and exits with its errno, so the
capability tests run on every machine, in CI, in milliseconds. A denial proved by a module
that does nothing else is a cleaner proof than one inferred from CPython's exception text.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from agent_runtime.config import RuntimeConfig
from agent_runtime.interpreter import InterpreterUnavailableError, locate
from agent_runtime.sandbox import SandboxPolicy, WasmSandbox

_GENEROUS = SandboxPolicy(fuel=50_000_000_000, wall_clock_seconds=60.0, memory_bytes=512 << 20)


@pytest.fixture(scope="session")
def interpreter() -> Path:
    try:
        return locate(RuntimeConfig(verify_interpreter_digest=True))
    except InterpreterUnavailableError:  # pragma: no cover - the marker skips first
        pytest.skip("the pinned WASI CPython build is not present")


@pytest.fixture(scope="session")
def sandbox(interpreter: Path) -> WasmSandbox:
    """One compiled interpreter for the whole session.

    Compiling costs seconds and each test still gets a fresh `Store`, which is where all
    guest state lives - so sharing the module shares no state between tests.
    """
    return WasmSandbox(interpreter, _GENEROUS)


@pytest.fixture
def wat(tmp_path: Path) -> Callable[..., WasmSandbox]:
    """Compile a hand-written WebAssembly module into a sandbox, with a chosen policy."""

    def build(source: str, policy: SandboxPolicy | None = None) -> WasmSandbox:
        path = tmp_path / "fixture.wat"
        path.write_text(source, encoding="utf-8")
        return WasmSandbox(path, policy or _GENEROUS)

    return build
