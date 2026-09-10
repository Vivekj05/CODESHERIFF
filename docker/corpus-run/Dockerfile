# The Linux host for a corpus run — the one place all four witnesses are live.
#
# Why this image exists: `structural.semgrep` has no Windows build, so a corpus
# run from a Windows checkout fits a structural witness with **one** backend
# behind it (PLAN.md Chapter 14, Chapter 18). The fitted ratios in
# `calibration.json` carry that caveat today. Chapter 18 may not publish a
# structural number measured that way, and the held-out test split may be
# evaluated exactly once (PROJECT_CONTEXT.md §6) — so the one run that counts
# has to happen somewhere Semgrep actually runs.
#
# This is NOT the sandbox. PROJECT_CONTEXT.md §4 rejects Docker as the sandbox:
# containers are OS-level isolation, not software fault isolation, and the SFI
# claim requires Wasmtime. The corpus cases still execute inside the WASI
# sandbox *within* this container, exactly as they do on a developer machine.
# The container is a Linux userland with Semgrep in it, nothing more.

FROM python:3.12-slim-bookworm

# git: Semgrep shells out to it for its own file discovery.
# ca-certificates: registry rule fetch and the Gemini call both need TLS.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The workspace venv lives OUTSIDE /workspace, because the host repository is
# mounted over /workspace at run time and its `.venv` is a Windows build. With
# the default location, that mount would shadow this image's interpreter with
# one full of `.pyd` files Linux cannot load.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    # Semgrep phones home with usage metrics by default. A measurement run
    # should not report itself to a third party, and the corpus cases are
    # deliberately vulnerable code.
    SEMGREP_SEND_METRICS=off

RUN pip install --no-cache-dir uv==0.12.12

WORKDIR /workspace

# Dependencies first, so a source edit does not re-resolve the whole workspace.
# `uv sync` needs every member's manifest to build the workspace graph.
COPY pyproject.toml uv.lock ./
COPY packages/contracts/pyproject.toml   packages/contracts/
COPY packages/corpus/pyproject.toml      packages/corpus/
COPY packages/agent_static/pyproject.toml   packages/agent_static/
COPY packages/agent_semantic/pyproject.toml packages/agent_semantic/
COPY packages/agent_context/pyproject.toml  packages/agent_context/
COPY packages/agent_runtime/pyproject.toml  packages/agent_runtime/
COPY packages/engine/pyproject.toml      packages/engine/
COPY packages/patch/pyproject.toml       packages/patch/
COPY packages/storage/pyproject.toml     packages/storage/
COPY apps/api/pyproject.toml             apps/api/
COPY apps/worker/pyproject.toml          apps/worker/

# --frozen: resolve from the committed lock or fail. A corpus run that quietly
# resolved a different dependency set would be measuring a different system.
RUN uv sync --all-packages --frozen --no-install-workspace

COPY . .

RUN uv sync --all-packages --frozen

# Semgrep and Bandit are external CLIs, not workspace dependencies: nothing
# imports them, `static_agent.semgrep.runner` shells out to `semgrep --sarif`,
# and Bandit is a Chapter 18 baseline to compare against, not a witness. They
# are pinned because an unpinned scanner makes the structural witness a moving
# target between the run that fits its ratios and the run that tests them.
RUN pip install --no-cache-dir semgrep==1.176.1 bandit==1.9.4

# Warm the registry rulesets into the image. `static_agent.config` asks for
# `p/security-audit` and `p/owasp-top-ten`, which Semgrep fetches from its
# registry on first use — so without this the rules a run measures are whatever
# the registry served that morning, and a re-run is not a re-run.
#
# NOTE: this freezes the rules as of image build, which is better than fetching
# per run but is still weaker than vendoring the YAML. See docker/corpus-run/README.md.
RUN mkdir -p /tmp/warm \
    && printf 'x = 1\n' > /tmp/warm/warm.py \
    && semgrep --config p/security-audit --config p/owasp-top-ten \
         --quiet --sarif --metrics=off /tmp/warm/warm.py > /dev/null \
    && rm -rf /tmp/warm

# No CMD that runs a measurement. The test split is evaluated exactly once
# (§6), and an image whose default command performs a run is an image that
# eventually performs it by accident.
CMD ["/bin/bash"]
