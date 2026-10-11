# `runtime.sfi` — the runtime witness

Executes one changed function inside a **Wasmtime + WASI** sandbox and reports which
dangerous operations an untrusted value actually reached.

Isolation infrastructure first, detection agent second. Running a pull request's code is how
CI systems get compromised, so the sandbox is worth having whether or not the observation
above it ever fires.

## What the guest gets

An `argv`, three file descriptors, and nothing else.

| | |
|---|---|
| Network | **Absent.** WASI preview1 has no `sock_connect`; a module that imports one fails to link. |
| Filesystem | **Absent.** No `preopen_dir`, so `/` does not exist from inside. |
| Environment | **Empty.** No `inherit_env`, so the process's tokens were never candidates. |
| CPU | Deterministic fuel budget. The same unit exhausts it at the same instruction. |
| Wall clock | Epoch interruption — the cap for a guest that is blocked rather than spinning. |
| Memory | Linear-memory ceiling; a guest allocation loop raises `MemoryError` inside the guest. |

## The interpreter is not committed

The agent runs a pinned WASI CPython build, verified against `INTERPRETER_SHA256` on load.
It is 26 MB and deliberately absent from this repository — a binary in a git history is in
that history forever.

```
runtime-agent doctor          # where it looked, what it found, and the digest
```

Without it the agent abstains `interpreter_unavailable` on every unit, under its own name,
at a likelihood ratio of exactly 1.0. That is the expected state, not a defect. To fetch it:

```
mkdir -p .wasm-runtimes
curl -L -o .wasm-runtimes/python-3.12.0.wasm \
  https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/python%2F3.12.0%2B20231211-040d5a6/python-3.12.0.wasm
runtime-agent doctor          # verifies the digest
```

Tests marked `wasm` skip without it.

## What it claims

CWE-22, 78, 94, 502 and 918 — the five whose sinks are *names* the probe can bind. SQL
injection and XSS are absent because their sinks are methods on objects the probe itself
fabricated, so an "observation" there would be the harness observing itself. Missing
authorisation and hard-coded credentials are absent because neither becomes visible by
running a function once.

The corpus pre-registered exactly these five in `detectable_by` before this agent existed,
which is what makes the narrowness a claim rather than a convenience.
