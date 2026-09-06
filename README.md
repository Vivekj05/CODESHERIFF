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
   PR comment + dashboard
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

Python 3.12 · uv workspace · FastAPI · Celery + Redis · PostgreSQL 16 + pgvector · SQLAlchemy +
Alembic · tree-sitter · Semgrep · scikit-learn · sentence-transformers (`bge-small-en-v1.5`, local)
· Gemini Flash free tier · Wasmtime + WASI · Next.js + TypeScript + Tailwind + shadcn/ui

Zero recurring cost: free-tier LLM, local embeddings, self-hosted everything.

## Layout

```
packages/
  contracts/     The single shared contract. Never vendored.
  corpus/        Labelled cases + committed immutable splits
  agent_static/  agent_semantic/  agent_context/  agent_runtime/
  engine/        Fusion, calibration
apps/
  api/           FastAPI: verify HMAC, enqueue, 202. No analysis.
  worker/        Celery: owns the pipeline and all agents
  dashboard/     Next.js — rendering layer only
```

## Getting started

Requires [uv](https://docs.astral.sh/uv/), Docker, and Node 20+.

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

A full conformance audit found that the committed code does not implement the design above. Three
of four analysis components are shells, the webhook is unauthenticated, and no corpus exists — so
no number the system currently produces is calibrated.

The audit is in **[`AUDIT.md`](AUDIT.md)**, with a `file:line` citation for every claim. It is the
baseline the rebuild is measured against.

| Doc | What it's for |
|---|---|
| **[`PLAN.md`](PLAN.md)** | The roadmap: 18 chapters, one per session, with live status. **Start here.** |
| [`CLAUDE.md`](CLAUDE.md) | Session guidance, document hierarchy, invariants that must not be "simplified" |
| [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) | **Authoritative** design. §5 overrides everything else |
| [`DECISIONS.md`](DECISIONS.md) | Living record — every decision with its reason |
| [`AUDIT.md`](AUDIT.md) | Conformance audit: what the code does vs. what it should |
| [`DEFECTS.md`](DEFECTS.md) | One line per false positive / false negative, written as found |
| [`docs/history/`](docs/history/) | Superseded specs, kept for provenance |

⚠️ Anything in `docs/history/` is **superseded**. One of those documents is the direct cause of the
non-conformance recorded in the audit, and following it reproduces known bugs.

## Scope

GitHub only, Python first. In scope: CWE-22, 78, 79, 89, 94, 502, 639, 798, 862, 918.

Out of scope: dependency and supply-chain scanning, container and IaC scanning, binary analysis,
auto-merge or auto-commit of patches, compliance reporting, multi-tenancy with billing, IDE plugins.

## License

Developed as a final-year B.Tech project.
