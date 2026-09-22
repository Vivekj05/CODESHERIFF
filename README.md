# CodeSheriff

Automated security review for GitHub pull requests, with **calibrated** confidence.

Four specialist agents analyse each changed function independently, and a Bayesian inference engine
fuses their evidence into a posterior probability that the change introduces a vulnerability.

> 🚧 **Under active reconstruction.** The architecture below is the design; much of it is not yet
> built, and some committed code does not implement it. See **Project status**.

---

## Why

Existing PR security tooling emits binary alerts with no measure of reliability. State-of-the-art
research tools still report false discovery rates above 80%, which trains developers to ignore
alerts entirely.

The problem is not detection count. It is that no tool tells you how much to trust a given finding.

> An AI code reviewer tells you what it thinks. CodeSheriff tells you how often it is right when it
> thinks that.

A stated 87% must correspond to being right about 87% of the time, **measured against ground truth
rather than asserted**. Calibration metrics (ECE, Brier score) are mandatory acceptance criteria,
not optional analysis.

## The four agents

Each decides on a fundamentally different basis. This heterogeneity is the entire justification for
the project — agents that failed the same way would add nothing to a probability estimate.

| Agent | Basis for decision | Fails when |
|---|---|---|
| `structural.taint` / `structural.semgrep` | Rules plus a mechanical reachability proof: source → sink with no covering sanitizer. No LLM. | The bug has no syntactic pattern |
| `semantic.hosted` | Absorbed model knowledge — functional intent → trust boundaries → violated safety invariant | The model hallucinates or is over-agreeable |
| `context.rag` | This repository's own precedent: does the change bypass a control an earlier merged PR established? | The repo has no relevant history |
| `runtime.sfi` | Direct observation — executes in a Wasmtime/WASI sandbox, recording attempted syscalls, network egress and file access | The code will not run in a sandbox |

Agents run **blind and in parallel**. None knows another exists, or knows about GitHub, the
database, or fusion. Every agent implements exactly `analyze(unit: ChangeUnit) -> list[Evidence]`,
and none ever raises — failure paths return an abstention with a distinct reason.

## How it works

```
GitHub PR opened
      ▼
API: verify HMAC → enqueue → return 202
      ▼
Worker: diff → ChangeUnits (one per changed function)
      ▼
  ┌──────┬──────────┬─────────┬─────────┐
Static  Semantic  Context  Runtime      ← blind, parallel, no shared state
  └──────┴─────┬────┴─────────┘
              ▼
   Evidence grouped by finding_key
              ▼
   Bayesian fusion → posterior per finding
              ▼
   PR Comment & Dashboard Artifacts:
   - Calibrated posterior with per-agent evidence breakdown (Detections, Silences, Abstentions)
   - Dynamic Mermaid.js sequence diagrams for change execution flow
   - Structured file-by-file walkthrough & engineering summary
   - Verified patch suggestions anchored in diff
   - Interactive web dashboard with RAG search and engineering analytics
```

Evidence comes in three kinds. **Detection** raises the odds. **Silence** — an agent ran and found
nothing — lowers them, but only within the CWEs that agent actually covers. **Abstention** — an
agent could not run — leaves them untouched. Conflating the last two would let an agent that
*could not look* penalise a finding.

Likelihood ratios are fitted on a held-out calibration split, never hardcoded. The alert threshold
comes from a precision-recall sweep on a separate validation split. The test split is evaluated
exactly once, at the end.

Patches are **suggestions only** — the system never commits or merges.

## Stack

* **Backend**: Python 3.12 · uv workspace · FastAPI · Celery + Redis · PostgreSQL 16 + pgvector · SQLAlchemy + Alembic · tree-sitter · Semgrep · scikit-learn · sentence-transformers (`bge-small-en-v1.5`, local) · Gemini Flash free tier · Wasmtime + WASI
* **Frontend & SaaS**: Next.js 16 (App Router) · React 19 · TypeScript · Tailwind CSS 4 · Base UI / shadcn/ui · Pinecone (vector DB) & Google `text-embedding-004` · Octokit GitHub API · TanStack Query v5 · Recharts · Mermaid.js

Zero recurring cost: free-tier LLM, local embeddings, self-hosted everything.

## Layout

```
backend/
  api/           FastAPI: verify HMAC, enqueue, 202. No analysis.
  worker/        Celery: owns the pipeline and all agents
  core/
    contracts/   Shared Pydantic data schemas
    engine/      Bayesian fusion & inference engine
    storage/     Database repositories (pgvector, redis)
    patch/       Patch proposal and sandbox verification
    corpus/      Labelled cases + committed immutable splits
  agents/        The 4 specialist analysis agents
    static/      Semgrep & Taint static analysis agent
    semantic/    LLM semantic reasoning agent
    context/     Repository context & RAG agent
    runtime/     WASI / Wasmtime sandbox agent
  calibration/   Observations, recorded responses
  docker/        Corpus evaluation Dockerfiles
  scripts/       Database init scripts (init-pgvector.sql)

frontend/        Next.js 16 + React 19 web dashboard & SaaS platform
  src/app/       Marketing landing page, dashboard routes, RAG API routes
  src/components/ Analytics (Recharts, heatmap), Mermaid viewer, Base UI
  src/lib/       Pinecone RAG, Gemini review generator, Octokit client, FastAPI edge

examples/        Evaluation benchmarks (baseline_eval, paper_eval) and sample PRs

docs/            Consolidated documentation (specs, architecture, roadmap, guides)
```

## Getting started

Requires Docker, Node 20+, and Python 3.12 with `uv`.

### Quick Start (Windows)
Use the one-click batch runner:
```cmd
# Start full development stack (Docker infra + API + Worker + Web Dashboard)
codesheriff.bat dev

# Run full test suite
codesheriff.bat test

# Run benchmark evaluations
codesheriff.bat eval
```

### Manual Setup
```bash
cp .env.example .env          # then fill it in
docker compose up -d          # Postgres + pgvector, Redis
uv sync                       # install the workspace
uv run pytest
uv run lint-imports           # agent boundary enforcement
```

`import-linter` is the guardrail that matters: agents may import `contracts` and nothing else. An
agent importing a sibling, the engine, or infrastructure fails CI.

## Project status

A full conformance audit found that the committed code did not implement the design above: three
of four analysis components were shells and no corpus existed. **No number the system produces is
calibrated yet**, and it says so on every pull request it comments on — the likelihood ratios, the
prior and the alert threshold are still hand-set, and Chapter 14 is where they are fitted.

The seam around the analysis is real as of Chapter 6: a signature-verified webhook becomes a queued
audit becomes one comment posted by the worker. The unauthenticated endpoint the audit found was
deleted rather than patched. Chapter 7 built the ground truth — 60 hand-written units in 30
vulnerable/safe twin pairs, with committed splits. Chapter 8 made the pipeline hand over one
`ChangeUnit` per changed function, and Chapter 9 made fusion multiply one likelihood ratio per
witness over a fixed roster, so a posterior can go down as well as up.

Two of the four agents now do the work their names claim, each measured against the corpus on the
calibration split. `structural.taint` (Chapter 10) propagates over a def-use graph it consumes:
13/13 recall on the cases the corpus predicts for it, 0 false positives across 18 safe twins.
`semantic.hosted` (Chapter 11) reads its exemplars and bounds untrusted code with a sentinel the
code author cannot forge: 0% injection subversion, a 94% safe-twin pass rate, zero hallucinated
sinks reaching output.

What is still missing is the RAG reasoning, the runtime sandbox, and the calibration itself. Both
missing agents abstain under their own names at a likelihood ratio of exactly 1.0, per unit, on the
record — so a witness that is not built costs the posterior nothing and hides from nobody.

The audit is in **[`docs/architecture/AUDIT.md`](docs/architecture/AUDIT.md)**, with a `file:line` citation for every claim. It is the
baseline the rebuild is measured against.

| Doc | What it's for |
|---|---|
| **[`docs/roadmap/PLAN.md`](docs/roadmap/PLAN.md)** | The roadmap: 18 chapters, one per session, with live status. **Start here.** |
| [`CLAUDE.md`](CLAUDE.md) | Session guidance, document hierarchy, invariants that must not be "simplified" |
| [`docs/specs/PROJECT_CONTEXT.md`](docs/specs/PROJECT_CONTEXT.md) | **Authoritative** design. §5 overrides everything else |
| [`docs/architecture/DECISIONS.md`](docs/architecture/DECISIONS.md) | Living record — every decision with its reason |
| [`docs/architecture/AUDIT.md`](docs/architecture/AUDIT.md) | Conformance audit: what the code does vs. what it should |
| [`docs/roadmap/DEFECTS.md`](docs/roadmap/DEFECTS.md) | One line per false positive / false negative, written as found |
| [`docs/specs/G2_Synopsis_CodeSheriff.pdf`](docs/specs/G2_Synopsis_CodeSheriff.pdf) | Academic synopsis paper |
| [`docs/history/`](docs/history/) | Superseded specs, kept for provenance |

⚠️ Anything in `docs/history/` is **superseded**. One of those documents is the direct cause of the
non-conformance recorded in the audit, and following it reproduces known bugs.

## Scope

GitHub only, Python first. In scope: CWE-22, 78, 79, 89, 94, 502, 639, 798, 862, 918.

Out of scope: dependency and supply-chain scanning, container and IaC scanning, binary analysis,
auto-merge or auto-commit of patches, compliance reporting, multi-tenancy with billing, IDE plugins.

## License

Developed as a final-year B.Tech project.
