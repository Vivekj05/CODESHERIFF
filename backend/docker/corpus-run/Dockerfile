# The Linux host where all four witnesses are live: the corpus run that fits the
# ratios, and the worker that applies them (D-104).
#
# Why this image exists: Semgrep cannot run on the Windows development machine.
# PyPI does publish a win_amd64 wheel for 1.176.1, but its semgrep-core dies on
# `Unix_error: Invalid argument socketpair` before reading a rule. A structural
# witness fitted here and applied on Windows would be two different backends
# sharing one ratio table, so the fit and the audit path both run in this image.
#
# This is NOT the sandbox. PROJECT_CONTEXT.md §4 rejects Docker as the sandbox:
# containers are OS-level isolation, not software fault isolation, and the SFI
# claim requires Wasmtime. The corpus cases still execute inside the WASI
# sandbox *within* this container, exactly as they do on a developer machine.
# The container is a Linux userland with Semgrep in it, nothing more.

FROM python:3.12-slim-bookworm

# git: Semgrep shells out to it for its own file discovery.
# ca-certificates: the Gemini and GitHub API calls need TLS.
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
COPY backend/core/contracts/pyproject.toml      backend/core/contracts/
COPY backend/core/corpus/pyproject.toml         backend/core/corpus/
COPY backend/agents/static/pyproject.toml       backend/agents/static/
COPY backend/agents/semantic/pyproject.toml     backend/agents/semantic/
COPY backend/agents/context/pyproject.toml      backend/agents/context/
COPY backend/agents/runtime/pyproject.toml      backend/agents/runtime/
COPY backend/core/engine/pyproject.toml         backend/core/engine/
COPY backend/core/patch/pyproject.toml          backend/core/patch/
COPY backend/core/storage/pyproject.toml        backend/core/storage/
COPY backend/api/pyproject.toml                  backend/api/
COPY backend/worker/pyproject.toml               backend/worker/

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

# tree-sitter-language-pack downloads each grammar on first use. Fetched here,
# checksum-verified by the library, so extraction never reaches the network at
# analysis time: in a fresh worker container that first-use download timed out
# and every audit would have failed before a single unit existed (D-104).
RUN python -c "import tree_sitter_language_pack as t; t.download(['python']); t.get_parser('python')"

# No rules are baked in. `static_agent` reads the pinned rulesets from
# `.semgrep/rules/` in the bind-mounted checkout and checks each one against its
# SHA-256 before every unit (D-104), so the image and the rules it measures are
# separately versioned and neither can drift silently. The earlier registry warm
# froze whatever `p/...` served on build day, which a rebuild then changed.

# No CMD that runs a measurement. The test split is evaluated exactly once
# (§6), and an image whose default command performs a run is an image that
# eventually performs it by accident.
CMD ["/bin/bash"]
