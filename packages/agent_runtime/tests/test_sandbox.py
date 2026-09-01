"""The isolation boundary, asserted. This file is Chapter 13's "Done when".

> *a network-attempting fixture is observed and denied, and the sandbox holds no
> credentials.*

Both criteria are here, and each is proved twice: once by a hand-written WebAssembly module
that calls exactly one WASI function and exits with its errno, and once by real CPython
running real attack code inside the same sandbox. The first proof runs on every machine and
takes milliseconds. The second needs the pinned interpreter and is what stops the first from
being a statement about a toy.

The distinction the WAT fixtures make visible is the one that matters: these capabilities
are **absent**, not refused. `sock_connect` is not a function this linker declines to call,
it is a function that does not exist, so a module importing it never reaches its first
instruction. That is what software fault isolation buys over a container, where the
syscall exists and a policy stands in front of it.
"""

from __future__ import annotations

from agent_runtime.sandbox import (
    SandboxPolicy,
    SandboxStatus,
    WasmSandbox,
    credential_shaped_host_variables,
)

from .runtime_support import requires_interpreter

# -- hand-written guests ---------------------------------------------------------------

CONNECTS = """
(module
  (import "wasi_snapshot_preview1" "sock_connect"
    (func $connect (param i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start") (drop (call $connect (i32.const 0) (i32.const 0) (i32.const 0)))))
"""

ACCEPTS = """
(module
  (import "wasi_snapshot_preview1" "sock_accept"
    (func $accept (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (call $exit (call $accept (i32.const 3) (i32.const 0) (i32.const 8)))))
"""

COUNTS_ENVIRON = """
(module
  (import "wasi_snapshot_preview1" "environ_sizes_get"
    (func $sizes (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (drop (call $sizes (i32.const 0) (i32.const 8)))
    (call $exit (i32.load (i32.const 0)))))
"""

OPENS_A_FILE = """
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 64) "/etc/passwd")
  (func (export "_start")
    (call $exit
      (call $open (i32.const 3) (i32.const 0) (i32.const 64) (i32.const 11)
                  (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0) (i32.const 8)))))
"""

SPINS = '(module (func (export "_start") (loop $l (br $l))))'

GROWS = """
(module
  (memory (export "memory") 1)
  (func (export "_start")
    (drop (memory.grow (i32.const 200)))
    (i32.store (i32.const 13107200) (i32.const 1))))
"""

EXITS_CLEANLY = """
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start") (call $exit (i32.const 0))))
"""
"""WASI requires an exported linear memory even from a module that never reads it - the
host writes into the guest's memory to answer calls, so a module without one fails to
instantiate with `missing required memory export`."""


# -- the network is not there ------------------------------------------------------------


def test_a_module_that_asks_to_connect_cannot_even_load(wat) -> None:
    """The first half of the chapter's acceptance criterion, at its strongest.

    `sock_connect` is not defined by this linker, so the module fails to instantiate and
    the guest never executes an instruction. The denial is not a policy decision taken at
    call time - the capability is absent from the namespace, which is a property no
    misconfiguration can undo.
    """
    run = wat(CONNECTS).run(["guest"])

    assert run.status is SandboxStatus.TRAPPED
    assert "sock_connect" in run.detail
    assert run.fuel_used == 0, "the guest ran; denial must come before the first instruction"


def test_a_socket_the_guest_did_try_for_is_refused(wat) -> None:
    """WASI preview1 does define `sock_accept`, and it is still useless here.

    Accepting needs a listening descriptor, and nothing in `_wasi_config` creates one - so
    every descriptor the guest can name answers with an errno rather than a socket. The
    module exits with that errno, and any non-zero value is a denial.
    """
    run = wat(ACCEPTS).run(["guest"])

    assert run.status is SandboxStatus.GUEST_ERROR
    assert run.exit_code not in (0, None), "sock_accept succeeded on a descriptor we never gave"


@requires_interpreter
def test_the_guest_cannot_reach_the_network_from_python(sandbox: WasmSandbox) -> None:
    """The same denial, through the interface an attacker would actually use."""
    run = sandbox.run(
        [
            "python",
            "-I",
            "-c",
            "import socket\n"
            "try:\n"
            "    socket.socket().connect(('example.com', 80))\n"
            "    print('CONNECTED')\n"
            "except BaseException as exc:\n"
            "    print('DENIED', type(exc).__name__)\n",
        ]
    )

    assert "CONNECTED" not in run.stdout
    assert "DENIED" in run.stdout


@requires_interpreter
def test_an_outbound_http_request_from_the_guest_fails(sandbox: WasmSandbox) -> None:
    """`urlopen` is the sink this agent reports; it must not work from inside."""
    run = sandbox.run(
        [
            "python",
            "-I",
            "-c",
            "import urllib.request\n"
            "try:\n"
            "    urllib.request.urlopen('http://example.com', timeout=2)\n"
            "    print('FETCHED')\n"
            "except BaseException as exc:\n"
            "    print('DENIED', type(exc).__name__)\n",
        ]
    )

    assert "FETCHED" not in run.stdout
    assert "DENIED" in run.stdout


# -- the sandbox holds no credentials ------------------------------------------------------


def test_the_guest_environment_is_empty(wat) -> None:
    """The second half of the acceptance criterion. The module exits with the variable count."""
    run = wat(COUNTS_ENVIRON).run(["guest"])

    assert run.status is SandboxStatus.COMPLETED
    assert run.exit_code == 0, "the guest was handed environment variables"


def test_the_guest_environment_is_empty_even_when_the_host_is_not(wat, monkeypatch) -> None:
    """Emptiness proved against a host that genuinely holds credential-shaped variables.

    Without this the previous test would pass on a host whose environment happened to be
    empty, which proves nothing about the sandbox. Here the host has a token, a database
    URL and an API key at the moment the guest runs, and the guest still counts zero.
    """
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_" + "a" * 36)
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pw@localhost/codesheriff")
    monkeypatch.setenv("CODESHERIFF_LLM_API_KEY", "sk-" + "b" * 32)

    assert set(credential_shaped_host_variables()) >= {
        "GITHUB_TOKEN",
        "DATABASE_URL",
        "CODESHERIFF_LLM_API_KEY",
    }, "the host is not holding what this test needs it to hold"

    run = wat(COUNTS_ENVIRON).run(["guest"])

    assert run.exit_code == 0


@requires_interpreter
def test_python_inside_the_guest_sees_no_environment(sandbox: WasmSandbox, monkeypatch) -> None:
    """`os.environ` is `{}` because there was nothing to inherit, not because of a filter."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_" + "c" * 36)

    run = sandbox.run(["python", "-I", "-c", "import os; print(dict(os.environ))"])

    assert run.stdout.strip() == "{}"
    assert "ghs_" not in run.stdout


# -- there is no filesystem -----------------------------------------------------------------


def test_the_guest_cannot_open_a_path(wat) -> None:
    """No `preopen_dir`, so descriptor 3 is not a directory and no path resolves through it."""
    run = wat(OPENS_A_FILE).run(["guest"])

    assert run.status is SandboxStatus.GUEST_ERROR
    assert run.exit_code == 8, "expected EBADF: the guest holds no directory descriptor"


@requires_interpreter
def test_python_inside_the_guest_has_no_filesystem(sandbox: WasmSandbox) -> None:
    """Reading and writing both fail, and the root itself does not exist from inside."""
    run = sandbox.run(
        [
            "python",
            "-I",
            "-c",
            "import os\n"
            "for label, fn in (('read', lambda: open('/etc/passwd').read()),\n"
            "                  ('write', lambda: open('/tmp/x', 'w')),\n"
            "                  ('list', lambda: os.listdir('/'))):\n"
            "    try:\n"
            "        fn(); print(label, 'ALLOWED')\n"
            "    except BaseException as exc:\n"
            "        print(label, 'DENIED', type(exc).__name__)\n",
        ]
    )

    assert "ALLOWED" not in run.stdout
    assert run.stdout.count("DENIED") == 3


@requires_interpreter
def test_the_guest_cannot_spawn_a_process(sandbox: WasmSandbox) -> None:
    """A shell is the escape a sandboxed analysis of `os.system` would most regret."""
    run = sandbox.run(
        [
            "python",
            "-I",
            "-c",
            "import subprocess\n"
            "try:\n"
            "    subprocess.run(['echo', 'escaped']); print('SPAWNED')\n"
            "except BaseException as exc:\n"
            "    print('DENIED', type(exc).__name__)\n",
        ]
    )

    assert "SPAWNED" not in run.stdout
    assert "DENIED" in run.stdout


# -- the resource caps ----------------------------------------------------------------------


def test_fuel_bounds_a_spinning_guest(wat) -> None:
    """Deterministic: an instruction budget, not a clock, so it is the same on every host."""
    policy = SandboxPolicy(fuel=100_000, wall_clock_seconds=60.0, memory_bytes=64 << 20)

    run = wat(SPINS, policy).run(["guest"])

    assert run.status is SandboxStatus.FUEL_EXHAUSTED
    assert run.fuel_used == 100_000
    assert run.wall_seconds < 5.0


def test_the_wall_clock_bounds_a_guest_fuel_would_not(wat) -> None:
    """The cap for a guest with fuel to spare. Both are armed on every run for this reason."""
    policy = SandboxPolicy(fuel=10**12, wall_clock_seconds=0.5, memory_bytes=64 << 20)

    run = wat(SPINS, policy).run(["guest"])

    assert run.status is SandboxStatus.TIMED_OUT
    assert run.wall_seconds < 20.0


def test_memory_growth_stops_at_the_ceiling(wat) -> None:
    """`memory.grow` past the limit returns -1, so the store into the page it wanted traps."""
    policy = SandboxPolicy(fuel=10**9, wall_clock_seconds=30.0, memory_bytes=2 << 16)

    run = wat(GROWS, policy).run(["guest"])

    assert run.status is SandboxStatus.TRAPPED


@requires_interpreter
def test_an_allocation_bomb_raises_inside_the_guest(interpreter) -> None:
    """A host OOM would take the worker down; a guest `MemoryError` is an abstention."""
    small = SandboxPolicy(fuel=50_000_000_000, wall_clock_seconds=60.0, memory_bytes=64 << 20)

    run = WasmSandbox(interpreter, small).run(
        ["python", "-I", "-c", "b = bytearray(400 * 1024 * 1024); print('ALLOCATED')"]
    )

    assert "ALLOCATED" not in run.stdout
    assert "MemoryError" in run.stderr


# -- state does not survive between runs ------------------------------------------------------


def test_each_run_gets_its_own_store(wat) -> None:
    """Two runs of one compiled module share no memory: guest state lives in the `Store`."""
    sandbox = wat(EXITS_CLEANLY)

    first = sandbox.run(["guest"])
    second = sandbox.run(["guest"])

    assert first.status is second.status is SandboxStatus.COMPLETED
    assert first.fuel_used == second.fuel_used, "fuel carried over; the store was reused"


def test_the_policy_grants_nothing(wat) -> None:
    """`SandboxPolicy` has no field that can widen the sandbox, and that is deliberate.

    A policy object with an `allow_network` flag is one flag away from not being a sandbox.
    This asserts the shape rather than the behaviour, because the behaviour is only safe for
    as long as nobody adds the field.
    """
    from dataclasses import fields

    from agent_runtime.sandbox import SandboxPolicy as Policy

    assert {f.name for f in fields(Policy)} == {"fuel", "wall_clock_seconds", "memory_bytes"}
    assert all(f.type in ("int", "float") for f in fields(Policy)), "a non-numeric bound is a grant"


def test_a_clean_exit_is_reported_as_completed(wat) -> None:
    run = wat(EXITS_CLEANLY).run(["guest"])

    assert run.ok
    assert run.exit_code == 0
