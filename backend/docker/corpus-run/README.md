# The corpus-run image

A Linux userland with Semgrep in it. That is the whole idea.

## Why it exists

Semgrep cannot run on the Windows development machine. PyPI does publish a
`win_amd64` wheel for `semgrep==1.176.1`, but its `semgrep-core` dies with
`Unix_error: Invalid argument socketpair` before reading a single rule, from
any shell and with the AF_UNIX driver running. On Windows `structural.semgrep`
therefore abstains on every unit, and the structural witness is the taint engine
alone.

That is only safe if the ratios were fitted the same way. So this image is the
one place the structural witness has both backends, and **both** halves of the
system run in it (D-104):

- the corpus run that fits the ratios (`corpus-run`, below), and
- the audit worker that applies them (`worker`, `docker compose --profile worker`).

A worker on Windows with ratios fitted here would score a one-backend witness
with numbers measured on two, and the posteriors would stop meaning what they say.

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

## Pinning

Pinned: Python 3.12-slim-bookworm, `uv==0.12.12`, the whole workspace resolved
`--frozen` from the committed `uv.lock`, `semgrep==1.176.1`, `bandit==1.9.4`, and
torch from the CPU-only index (D-100) — the default Linux wheel pulls the CUDA
runtime and took the image from 2.63 GB to 9.15 GB for code that cannot use a GPU.

**The Semgrep rules are pinned by digest, not by image** (D-104). `static_agent`
no longer names `p/security-audit` or `p/owasp-top-ten`; it reads two files from
`.semgrep/rules/` in the checkout and checks each against the SHA-256 in
`static_agent/config.py` before every unit. A missing file abstains
`rules_unavailable`, an edited one `rules_mismatch`, and a different Semgrep build
`tool_version_mismatch` — nothing fetches rules at analysis time. The files are
gitignored because they are Semgrep's to distribute; fetch them once, by hand:

```bash
mkdir -p .semgrep/rules
curl -L -o .semgrep/rules/security-audit.yml https://semgrep.dev/c/p/security-audit
curl -L -o .semgrep/rules/owasp-top-ten.yml  https://semgrep.dev/c/p/owasp-top-ten
sha256sum .semgrep/rules/*.yml   # must equal SEMGREP_RULESETS
```

A later fetch will usually not match, because the registry moves. That is the
point: changing the rules is changing the witness, so it means editing
`SEMGREP_RULESETS` and re-fitting, never a quiet download. **What must not happen
is fitting the ratios from one image and evaluating the test split from another.**
Record the image digest with the run:

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
