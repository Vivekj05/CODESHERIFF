# CLAUDE.md

Guidance for Claude Code sessions working in this repository.

---

## What this project is

CodeSheriff is a GitHub App that security-reviews pull requests. Four specialist agents analyse
each changed function independently, and a Bayesian inference engine fuses their evidence into a
**calibrated** posterior probability that the change introduces a vulnerability.

The thesis is not detection coverage. It is calibration: a stated 87% must correspond to being
right about 87% of the time, measured against ground truth. Existing PR security tools emit binary
alerts with no reliability measure, so developers learn to ignore them.

> An AI code reviewer tells you what it thinks. CodeSheriff tells you how often it is right when
> it thinks that.

Final-year academic project. Solo maintainer plus contributors, part-time, no fixed deadline. A
research paper is a deliverable; calibration metrics (ECE, Brier) are **mandatory acceptance
criteria**, not optional analysis.

---

## Document hierarchy — read this before trusting any spec in this repo

| Document | Status | Use for |
|---|---|---|
| `PROJECT_CONTEXT.md` | **AUTHORITATIVE** | The finalized design. §5 "Finalized Decisions" overrides everything else. |
| `DECISIONS.md` | **AUTHORITATIVE**, living | Decisions taken since, each with its rationale. Append here as you go. |
| `AUDIT.md` | Current | What the code actually does vs. what it should. The gap list. |
| `PLAN.md` | Current | The roadmap: 18 chapters, one per session, with live status. **Start here each session.** |
| `DEFECTS.md` | Current, living | One line per false positive / false negative, written as found. |
| `docs/history/**` | **SUPERSEDED — DO NOT BUILD FROM THESE** | Archived drafts, kept for provenance. See `docs/history/README.md`. |

### Why `docs/history/00-START-HERE.md` is dangerous

It is an earlier draft that `PROJECT_CONTEXT.md` §5 explicitly reverses on four points: it
mandates independent repos with vendored contracts, `analyze(unit, anchors=...)`, anchored
execution, and three agents. §5 reverses all four, and each reversal exists to fix a specific
identified bug.

The entire non-conformance documented in `AUDIT.md` traces to that file sitting in the repo root
looking authoritative while three contributors built against it. It has been moved to
`docs/history/` for exactly that reason. **If a spec in this repo contradicts
`PROJECT_CONTEXT.md` §5, §5 wins.**

---

## The conflict rule (from PROJECT_CONTEXT.md §8)

> If a new decision conflicts with a finalized decision in Section 5, **identify the conflict and
> discuss it before changing anything.**

Several §5 entries reverse earlier drafts and exist to fix specific bugs. Reverting one silently
reintroduces its bug. This is not a style preference — it is how this codebase got into its
current state.

**Do not "simplify" any of the following without raising the conflict first.** Each looks like an
odd choice and is load-bearing:

| Invariant | Why it looks wrong | Why it is right |
|---|---|---|
| `finding_key` **excludes** the sink expression | Seems to lose precision | With it, taint reports `cursor.execute(query)` and the LLM reports `cursor.execute` → different keys → every finding a singleton → the Bayesian engine never performs a single update |
| Three evidence kinds, not two | `abstained: bool` seems sufficient | SILENCE (ran, found nothing) gets LR < 1.0; ABSTENTION (could not run) gets exactly 1.0. Conflating them means an agent that *could not look* penalises the finding |
| SILENCE carries `covered_cwes` | Extra field for little gain | Without it, the taint engine's silence on CWE-862 (which it has no rules for) systematically suppresses every semantic-only finding |
| Fusion iterates **all** agents, not just those that emitted | Wasteful loop | Otherwise odds can only ever increase |
| Agents run **blind** — no anchors | Anchoring is obviously more efficient | It correlates the agents and breaks the conditional independence the fusion math assumes |
| Debate emits its own evidence, never overwrites the posterior | Overwriting is simpler | Overwriting destroys calibration exactly on the contested cases and makes the debate step unmeasurable |
| Oversized units **abstain**, never truncate | Truncating gets partial signal | Truncated analysis produces confident findings from half-read code, biased toward over-reporting, and silently invalidates calibration |
| PR title/description passed as separate `pr_context` | Convenient inside `ChangeUnit` | Attacker-controlled, and absent from corpus cases — embedding it makes corpus runs behave differently from production, corrupting calibration |

---

## Current state — read `AUDIT.md` before writing code

**The committed code does not implement the design above.** A full conformance audit found that
three of four analysis components are shells:

- The static agent has **no taint engine** — the def-use graph is built and discarded; "taint
  paths" are a line-number cross-product.
- The context agent has **no RAG reasoning** — four hard-coded substring tests.
- The semantic agent's anti-sycophancy exemplars exist on disk and are **never loaded**.
- The runtime agent **does not exist**.
- The webhook has **no HMAC verification**.

The test suite passes and reports 100%. It cannot detect any of this. `static-agent/cli.py` `bench`
returns hard-coded `precision: 1.0, recall: 1.0`.

**Do not assume a component works because it has a plausible filename or a passing test.** Read
the implementation.

---

## Repository layout

`uv` workspace monorepo, per `PROJECT_CONTEXT.md` §5.

```
CODESHERIFF/
├── pyproject.toml        # uv workspace + ruff/mypy/import-linter config
├── packages/
│   ├── contracts/        # THE single shared contract. Never vendored.
│   ├── corpus/           # Labelled cases + committed immutable splits  (empty — Ch 7)
│   ├── agent_static/     # structural.taint + structural.semgrep
│   ├── agent_semantic/   # semantic.hosted
│   ├── agent_context/    # context.rag
│   ├── agent_runtime/    # runtime.sfi                                  (empty — Ch 13)
│   ├── engine/           # Fusion, calibration. May NOT import a DB client.
│   └── storage/          # SQLAlchemy models, Alembic, pgvector precedent store
├── apps/
│   ├── api/              # FastAPI: sign-in + repo listing (Ch 5); HMAC + enqueue (Ch 6)
│   ├── worker/           # Celery: owns the pipeline and all agents          (stub — Ch 6)
│   └── dashboard/        # Next.js 16 — rendering layer only. Shell + mock data (Ch 4)
└── docs/history/         # Superseded specs, kept for provenance
```

⚠️ **The layout is correct and the workspace now runs; most of the code inside it is still not.**
Chapter 2 froze the contract at v2.0.0, rewired every package onto it, and got `uv sync`, `pytest`,
`ruff`, `mypy --strict` and `lint-imports` green. It did **not** fix the analysis defects in
`AUDIT.md` — it made the agents speak the right contract, not do the right work. The taint engine
still builds a def-use graph and discards it; the context agent is still four substring tests; the
runtime agent still does not exist.

The live webhook still sits at `packages/engine/src/codesheriff_engine/github/webhook.py` and is
**not** mounted by `apps/api` — it has no HMAC verification (`AUDIT.md` 0.1). It moves to
`apps/api` in Chapter 6, verified and enqueueing.

**Persisting anything.** All database access lives in `packages/storage`, and `codesheriff_engine`
is forbidden from importing `sqlalchemy`, `alembic`, `psycopg` or `codesheriff_storage` — enforced
by `import-linter` (D-025). Fitted numbers must be reproducible from the calibration split and a
recorded corpus hash; a fusion module that can open a session makes that unverifiable. Never write a
row by hand: `mapping.py` is the only writer, it hashes source rather than storing it, and it drops
fusion results whose key no agent could have produced (D-026, D-027).

**Building evidence.** Never construct `Evidence(...)` directly — use `Evidence.detection()`,
`.silence()` or `.abstention()`. Never build a `finding_key` by hand — use `unit.key_for(cwe)`. Both
rules exist because hand-rolled variants are exactly how the same bug came to have two keys
(`AUDIT.md` 1.1). Returning `[]` from a successful analysis is a bug; that is what SILENCE is for.

---

## Architectural rules

**Agent isolation.** Every agent implements exactly `analyze(unit: ChangeUnit) -> list[Evidence]`.
No agent knows another exists, or knows about GitHub, the database, or fusion. Agents may import
`contracts` and nothing else — enforced by `import-linter` in CI once Chapter 2 lands.

*This is the one property the current code got right.* No agent imports a sibling, the engine,
GitHub, or a DB client. It is why a rebuild is cheap rather than catastrophic. Do not break it.

**Agents never raise.** Every failure path returns an abstention with a distinct reason. Returning
an empty list on a failure path is a bug — it is indistinguishable from "analysed, found nothing",
which is what SILENCE is for.

**The four agents must fail differently.** Heterogeneity is the entire justification for the
project; agents that failed the same way would add nothing to a probability estimate.

| Agent | Basis for decision | Fails when |
|---|---|---|
| `structural.taint` / `structural.semgrep` | Mechanical reachability proof. No LLM. | Bug has no syntactic pattern |
| `semantic.hosted` | Absorbed model knowledge: intent → trust boundaries → violated invariant | Model hallucinates or is over-agreeable |
| `context.rag` | This repository's own precedent | Repo has no relevant history |
| `runtime.sfi` | Direct observation in a sandbox | Code will not run in a sandbox |

**Research integrity — non-negotiable (§6).**
- Scoring weights and likelihood ratios fitted **only** on the calibration split
- Threshold selected **only** on the validation split
- Test split evaluated **exactly once**, at the end

**Sign-in and access.** The dashboard never talks to GitHub and holds no secret; `apps/api` owns the
OAuth flow. What a user may see is read from `GET /user/installations` at sign-in and stored on their
session — there is no permissions table, and an empty installation list returns nothing rather than
everything (D-035). The database holds no GitHub token and no session token, only a SHA-256 of the
cookie (D-036). A URL parameter never widens a session: the installation callback re-derives
everything through OAuth (D-037).

**Security.** Untrusted PR code executes only in the sandbox (deny-by-default network, ephemeral
filesystem, resource caps) and never on a host holding database credentials. Source code lives in
memory and ephemeral storage only; persisted records hold findings, evidence and hashes — never
full file contents.

---

## Stack

Python 3.12 · `uv` workspace · FastAPI · Pydantic v2 · Celery + Redis · PostgreSQL 16 with
**pgvector** · SQLAlchemy + Alembic · `githubkit` · `tree-sitter` + `tree-sitter-language-pack` ·
`semgrep` CLI (`--sarif`) · `networkx` · `scikit-learn` · `sentence-transformers`
(`BAAI/bge-small-en-v1.5`, 384-dim, local) · Gemini Flash free tier · **Wasmtime + WASI** ·
`typer` · `pytest` + `pytest-cov` + `syrupy` + `hypothesis` · `ruff` + `mypy --strict` ·
`import-linter` · Next.js + TypeScript + Tailwind + shadcn/ui + Recharts · Docker Compose

**Explicitly rejected** — do not reintroduce:

- **LangGraph** — agents are pure functions with no shared state; a shared-state framework fights
  the independence requirement and obscures the exact prompt bytes needed for cache keys
- **ChromaDB** — pgvector instead: survives restarts, one less service, metadata filtering and
  similarity search in one query. *(ChromaDB is currently in `requirements.txt` — that is drift.)*
- **Python's built-in `ast`** — tree-sitter handles JS/TS through the same API and tolerates the
  syntax errors PR diffs frequently contain
- **Docker as the sandbox** — containers are OS-level isolation, not software fault isolation; the
  SFI claim requires Wasmtime
- **Prisma / Inngest / Pinecone / Next.js API routes as backend** — the backend must be Python
  because tree-sitter, scikit-learn and Wasmtime bindings have no viable JS equivalent

**Constraints.** Zero recurring cost (free-tier LLM, local embeddings, self-hosted). No dedicated
GPU — any fine-tuning must fit free Colab/Kaggle tiers. Webhook acknowledged in < 3s (GitHub's
hard limit is 10s) — enqueue, never process inline. GitHub API 5,000 req/hr per installation.

**Scope.** GitHub only, Python-first. `IN_SCOPE_CWES` is a **closed set**: CWE-22, 78, 79, 89, 94,
502, 639, 798, 862, 918. Out of scope: dependency/supply-chain scanning, container and IaC
scanning, binary analysis, auto-merge or auto-commit of patches, compliance reporting,
multi-tenancy with billing, IDE plugins. JS/TS support is unscheduled until explicitly decided.

---

## Commands

```bash
uv sync --all-packages           # install the workspace  (--all-packages, or members are skipped)
uv run pytest                    # all packages
uv run pytest packages/agent_static
uv run ruff check . && uv run ruff format --check . && uv run mypy .
uv run lint-imports              # agent + storage boundary enforcement — must stay green
uv run uvicorn codesheriff_api.main:app --reload   # /health, /auth/*, /repositories

# Database (Chapter 3). Alembic owns the schema; never Base.metadata.create_all.
docker compose up -d postgres
uv run alembic -c packages/storage/alembic.ini upgrade head
uv run alembic -c packages/storage/alembic.ini downgrade base

# Tests that touch Postgres are marked `db` and SKIP unless this is set (D-029).
export CODESHERIFF_TEST_DB=postgresql+psycopg://codesheriff:codesheriff@localhost:5432/codesheriff
uv run pytest packages/storage -m db
```

The dashboard is a separate npm project, not a uv workspace member (Chapter 4):

```bash
cd apps/dashboard
npm run dev                      # http://localhost:3000 — sign-in needs the API on :8000
npm run lint && npm run build    # the two frontend gates — must stay green
```

`NEXT_PUBLIC_API_BASE_URL` is inlined at **build** time, not read at runtime. Changing which API the
dashboard talks to means rebuilding it.

Signing in needs a registered GitHub App — `docs/github-app-setup.md`. Without one the API answers
`501` naming the missing variable rather than failing at import, so `/health` works on a machine
that has never seen a `.pem`.

All five Python gates and both frontend gates are green as of Chapter 5. `ruff` and `mypy` are
configured **once**, in the root `pyproject.toml` — a per-package `[tool.ruff]` silently shadows it
with a different rule set, which is how the agent packages went unlinted (D-023).

**Tests must never make live API calls.** `apps/api/tests/conftest.py` fails any non-loopback socket
connection unless `CODESHERIFF_ALLOW_LIVE_CALLS` is set — a guard at the socket layer, so a forgotten
mock cannot leak a real request. GitHub is substituted at the `GitHubGateway` interface rather than
at the HTTP layer; the real `githubkit` client is exercised separately against an httpx
`MockTransport`, with response bodies generated from githubkit's own schemas.

---

## Working practice (PROJECT_CONTEXT.md §8)

1. Understand the existing repository state before proposing anything
2. Divide work into logical phases based on what actually exists
3. Inspect the current implementation before a significant phase
4. Brainstorm approaches and evaluate trade-offs
5. Agree the approach before implementing, when the decision is significant
6. Implement → test → review
7. **Record the decision and its reason in `DECISIONS.md`**
8. Create or update documentation only when it becomes useful

Record every false positive and false negative in `DEFECTS.md` with a one-line cause **as it is
found**, not reconstructed at the end.

Targets worth keeping in view: static agent p95 ≤ 3s per ChangeUnit; semantic agent ≤ $0.01 per
ChangeUnit at n=3; full audit < 5 min; coverage ≥ 80% per package; `mypy --strict` and `ruff`
clean; zero unhandled exceptions across a full corpus run.
