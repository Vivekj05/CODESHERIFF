# The corpus-run image

A Linux userland with Semgrep in it. That is the whole idea.

## Why it exists

`structural.semgrep` has no Windows build. On a Windows checkout it abstains
`tool_unavailable` on every unit — correctly handled, and recorded in the run's
provenance as a backend that was silent throughout — but it means the structural
witness is the taint engine alone. The likelihood ratios in `calibration.json`
were fitted that way, and `PLAN.md` Chapter 14 flags it: *"Chapter 18 must
re-observe on Linux or CI, or its fitted structural ratios will describe a
one-backend witness."*

Chapter 18 also spends the one evaluation of the held-out test split that §6
permits. Both of those need a host where all four witnesses are live.

## What it is not

It is **not** the sandbox. `PROJECT_CONTEXT.md` §4 rejects Docker as the sandbox:
a container is OS-level isolation, and the software-fault-isolation claim requires
Wasmtime. Corpus cases still execute inside the WASI sandbox *within* this
container, with the same fuel, wall-clock, memory and capability bounds they get
anywhere else. The container supplies a Linux userland; the sandbox is unchanged.

## Running it

The interpreter is mounted, not baked (D-074): fetch it on the host first if you
have not, and the digest check runs inside the container as usual.

```bash
docker compose --profile corpus build corpus-run
docker compose --profile corpus run --rm corpus-run
```

That drops you at a shell in `/workspace` with the repository bind-mounted, so
anything written to `calibration/` lands on the host and can be committed.

Inside:

```bash
runtime-agent doctor                 # interpreter found? digest match?
semgrep --version && bandit --version
codesheriff-corpus validate          # corpus_hash / split_hash must match the artifact
```

The console scripts are on `PATH` because `UV_PROJECT_ENVIRONMENT=/opt/venv` is
first in it — there is no `uv run` prefix needed, and the Windows `.venv` in the
bind mount is not on `PATH` at all.

## Pinning, and the one gap in it

Pinned: Python 3.12-slim-bookworm, `uv==0.12.12`, the whole workspace resolved
`--frozen` from the committed `uv.lock`, `semgrep==1.176.1`, `bandit==1.9.4`, and
torch from the CPU-only index (D-100) — the default Linux wheel pulls the CUDA
runtime and took the image from 2.63 GB to 9.15 GB for code that cannot use a GPU.

**Not fully pinned: the Semgrep rulesets.** `static_agent.config` asks for
`p/security-audit` and `p/owasp-top-ten`, which Semgrep fetches from its registry.
The build warms them into the image so that every run from one image sees the same
rules — but a rebuild months later fetches whatever the registry serves then, and
that is a different structural witness.

Vendoring the rule YAML would close it. It is left open deliberately for now,
because the fix has a cost worth deciding on rather than absorbing: vendored
registry rules are a redistribution question, and they go stale in the opposite
direction. **What must not happen is fitting the ratios from one image and
evaluating the test split from another.** Record the image digest with the run:

```bash
docker image inspect codesheriff-corpus-run:latest --format '{{index .RepoDigests 0}}{{.Id}}'
```

## The discipline this image does not enforce

§6 is a rule about which split decides what, and no container checks it:

1. Ratios are fitted on **calibration** only.
2. The threshold is selected on **validation** only.
3. The **test** split is evaluated **exactly once**, at the end.

`calibrate observe` refuses the test split by name (`TestSplitSealedError`), so
the fitting harness cannot reach it by accident. The one run that may is
Chapter 18's, and re-observing calibration and validation here — on the
two-backend structural witness — has to come first, because a test split scored
against one-backend ratios is measuring a system that no longer exists.
