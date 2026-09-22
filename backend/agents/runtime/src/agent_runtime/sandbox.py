"""The isolation boundary. Wasmtime + WASI, deny-by-default, no second backend.

This module is the reason Chapter 13 is ordered the way it is: **isolation infrastructure
first, detection agent second**. Running a pull request's code is how continuous
integration systems get compromised, so the sandbox has to be right whether or not the
agent above it ever detects anything. Everything in `probe.py` is a consumer of this file.

**Why Wasmtime and not a container.** A container is OS-level isolation: the guest runs as
native code and the kernel is the boundary, so a kernel bug is a full escape and the host's
process table, network namespace and credentials are all one misconfiguration away.
WebAssembly is software fault isolation: the guest cannot name an address outside its own
linear memory, and it cannot perform an operation the host did not hand it as an import.
`PROJECT_CONTEXT.md` rejects Docker here for exactly this reason, and the difference is
visible in the tests - `test_a_module_that_asks_to_connect_cannot_even_load` passes because
the capability is *absent*, not because a policy refused it.

**Four caps, and each covers another's blind spot.**

* *Capabilities* - no preopened directory, no inherited environment, no socket. Absence,
  not refusal.
* *Fuel* - a deterministic WebAssembly instruction budget. The same unit runs out at the
  same instruction on every machine, which is what a calibration run needs and what a
  wall clock cannot promise.
* *Epoch* - a wall-clock deadline. Fuel counts guest instructions, so a guest blocked in a
  host call burns none of it; this is the cap that ends that run.
* *Memory* - a linear-memory ceiling, so a guest allocation loop raises `MemoryError`
  inside the guest instead of an OOM on the host.

**Nothing here inherits anything.** `WasiConfig` is constructed empty and stays that way:
no `inherit_env`, no `inherit_stdin`, no `preopen_dir`. That is the whole of "the sandbox
holds no credentials" - the guest's `os.environ` is `{}` because there is nothing to
inherit from, not because a filter removed the interesting keys. A filter is a list someone
has to keep correct; an empty environment is correct by construction (D-075).

Standard input and the two output streams are host temporary files, which is not a guest
capability: file descriptors 0, 1 and 2 exist in every WASI instance and carry no name a
guest can use to open anything else.
"""

from __future__ import annotations

import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import wasmtime

logger = logging.getLogger(__name__)


class SandboxUnavailableError(RuntimeError):
    """The sandbox itself could not be stood up.

    Distinct from every outcome in `SandboxStatus`, and deliberately an exception rather
    than a status: a missing interpreter, an unreadable module or a digest mismatch are
    facts about *this host*, not observations about the unit. Reporting them as a result
    would let a broken installation read as a clean analysis - `AUDIT.md` 3.8 is what that
    looked like the last time this project did it.
    """


class SandboxStatus(StrEnum):
    """How one guest run ended. Every one of these is an observation about the run."""

    COMPLETED = "completed"
    """The guest reached the end of `_start` and exited 0."""

    GUEST_ERROR = "guest_error"
    """The guest ran and exited non-zero - an uncaught Python exception, typically."""

    FUEL_EXHAUSTED = "fuel_exhausted"
    """The instruction budget ran out. Deterministic: the same unit does this every time."""

    TIMED_OUT = "timed_out"
    """The wall-clock deadline fired. Not deterministic, and never the sole basis of a
    claim about the code - only ever an abstention."""

    TRAPPED = "trapped"
    """The guest trapped for some other reason: an unlinkable import, a bad instruction,
    memory it may not touch. A denied capability arrives here."""


@dataclass(frozen=True)
class SandboxRun:
    """What one guest execution produced. Never the source, only what it wrote."""

    status: SandboxStatus
    exit_code: int | None
    stdout: str
    stderr: str
    fuel_used: int
    wall_seconds: float
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is SandboxStatus.COMPLETED


@dataclass(frozen=True)
class SandboxPolicy:
    """The capability grant, written out so it can be read and asserted against.

    Every field is a bound. There is no field that grants anything, and that asymmetry is
    the point: a policy object whose defaults are safe but which carries an `allow_network`
    flag is one flag away from not being a sandbox, and the flag would eventually be set by
    someone debugging a fixture at midnight.
    """

    fuel: int
    wall_clock_seconds: float
    memory_bytes: int


class WasmSandbox:
    """A compiled WASI interpreter plus the policy every guest runs under.

    The module is compiled once and reused. Compilation of the 26 MB CPython build costs
    about 2.6 seconds and instantiation costs milliseconds, so an agent that rebuilt the
    engine per unit would spend its entire p95 budget in the compiler. Each `run()` still
    gets a **fresh `Store`**, which is where all guest state lives: two units cannot see
    each other's memory, globals or file descriptors, because they do not share a store.
    """

    def __init__(self, module_path: Path, policy: SandboxPolicy) -> None:
        self.module_path = module_path
        self.policy = policy

        config = wasmtime.Config()
        config.consume_fuel = True
        config.epoch_interruption = True
        self._engine = wasmtime.Engine(config)

        try:
            self._module = wasmtime.Module.from_file(self._engine, str(module_path))
        except Exception as exc:  # pragma: no cover - depends on a corrupt artifact
            raise SandboxUnavailableError(
                f"{module_path} is not a WebAssembly module Wasmtime can compile: {exc}"
            ) from exc

    # -- one run ---------------------------------------------------------------------

    def run(self, argv: list[str], stdin_bytes: bytes = b"") -> SandboxRun:
        """Execute the guest once, under the full policy, and return what it wrote.

        Raises nothing that describes the guest. A guest that crashes, spins, allocates or
        reaches for a capability it does not have is a `SandboxRun`, because all four are
        things the analysis above needs to reason about rather than fail on.
        """
        with tempfile.TemporaryDirectory(prefix="codesheriff-sfi-") as tmp:
            paths = {name: Path(tmp) / name for name in ("stdin", "stdout", "stderr")}
            paths["stdin"].write_bytes(stdin_bytes)
            paths["stdout"].touch()
            paths["stderr"].touch()
            return self._run_once(argv, paths)

    def _run_once(self, argv: list[str], paths: dict[str, Path]) -> SandboxRun:
        linker = wasmtime.Linker(self._engine)
        linker.define_wasi()

        store = wasmtime.Store(self._engine)
        store.set_fuel(self.policy.fuel)
        store.set_limits(memory_size=self.policy.memory_bytes)
        # Epoch interruption is armed engine-wide, so a store that never sets a deadline is
        # already past one and traps on its first instruction. This line is not optional.
        store.set_epoch_deadline(1)
        store.set_wasi(self._wasi_config(argv, paths))

        expired = threading.Event()
        ticker = threading.Thread(
            target=self._deadline, args=(expired,), daemon=True, name="codesheriff-sfi-deadline"
        )
        ticker.start()

        started = time.monotonic()
        status = SandboxStatus.COMPLETED
        exit_code: int | None = 0
        detail = ""
        try:
            instance = linker.instantiate(store, self._module)
            start = instance.exports(store)["_start"]
            if not isinstance(start, wasmtime.Func):
                raise SandboxUnavailableError("guest module exports no callable _start")
            start(store)
        except wasmtime.ExitTrap as exc:
            exit_code = int(exc.code)
            status = SandboxStatus.COMPLETED if exit_code == 0 else SandboxStatus.GUEST_ERROR
            detail = f"guest exited {exit_code}"
        except wasmtime.Trap as exc:
            exit_code = None
            status, detail = self._classify_trap(exc, expired)
        except wasmtime.WasmtimeError as exc:
            # Instantiation failures land here, and an unlinkable import is one of them. A
            # guest asking for a capability this linker does not define is denied before it
            # executes a single instruction, which is the strongest form of denial there is.
            exit_code = None
            status, detail = SandboxStatus.TRAPPED, str(exc).strip()
        finally:
            expired.set()
            ticker.join(timeout=1.0)

        elapsed = time.monotonic() - started
        remaining = store.get_fuel() or 0
        return SandboxRun(
            status=status,
            exit_code=exit_code,
            stdout=_read_text(paths["stdout"]),
            stderr=_read_text(paths["stderr"]),
            fuel_used=self.policy.fuel - remaining,
            wall_seconds=elapsed,
            detail=detail[:1000],
        )

    # -- policy ----------------------------------------------------------------------

    def _wasi_config(self, argv: list[str], paths: dict[str, Path]) -> wasmtime.WasiConfig:
        """The capability grant, in full. Everything absent from this method is denied.

        Read it as a list of what the guest gets: an argv, three file descriptors, and
        nothing else. No `inherit_env` - so the guest's environment is empty and the
        process's `GITHUB_TOKEN`, `DATABASE_URL` and LLM key are not merely filtered out
        but were never candidates. No `preopen_dir` - so there is no directory the guest
        can name, and `open("/etc/passwd")` fails with ENOENT because `/` does not exist
        from inside. No socket, because WASI preview1 offers no way to create one.
        """
        wasi = wasmtime.WasiConfig()
        wasi.argv = argv
        wasi.stdin_file = str(paths["stdin"])
        wasi.stdout_file = str(paths["stdout"])
        wasi.stderr_file = str(paths["stderr"])
        return wasi

    def _deadline(self, expired: threading.Event) -> None:
        """Advance the engine's epoch once the wall clock is up, which traps the guest.

        A thread rather than a signal: signals are process-wide and the worker runs agents
        in a pool, so an alarm meant for one unit would land in whichever thread the OS
        chose. `increment_epoch` is scoped to this engine and is the mechanism Wasmtime
        documents for exactly this.
        """
        if not expired.wait(self.policy.wall_clock_seconds):
            logger.info("sandbox wall clock expired after %.1fs", self.policy.wall_clock_seconds)
            self._engine.increment_epoch()

    def _classify_trap(
        self, exc: wasmtime.Trap, expired: threading.Event
    ) -> tuple[SandboxStatus, str]:
        """Which cap fired. The message is Wasmtime's; the reading of it is ours."""
        message = str(exc).strip()
        code: Any = getattr(exc, "trap_code", None)
        if code is not None and code == wasmtime.TrapCode.OUT_OF_FUEL:
            return SandboxStatus.FUEL_EXHAUSTED, message
        if "fuel" in message:
            return SandboxStatus.FUEL_EXHAUSTED, message
        if "interrupt" in message:
            return SandboxStatus.TIMED_OUT, message
        return SandboxStatus.TRAPPED, message


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:  # pragma: no cover - the temp dir is ours
        return ""


def credential_shaped_host_variables() -> tuple[str, ...]:
    """Host environment variables that look like secrets, for the sandbox's own assertions.

    Not a filter - nothing here is ever passed to a guest, because nothing at all is. It
    exists so `test_the_guest_environment_is_empty_even_when_the_host_is_not` can prove
    emptiness against a host that genuinely holds a credential-shaped variable. A test that
    proved emptiness against an already-empty host would prove nothing.
    """
    markers = ("TOKEN", "SECRET", "KEY", "PASSWORD", "DATABASE_URL", "DSN")
    return tuple(name for name in os.environ if any(m in name.upper() for m in markers))
