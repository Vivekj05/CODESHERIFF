# CodeSheriff

Automated security review for GitHub pull requests, with **calibrated** confidence.

Four specialist agents analyse each changed function independently, and a Bayesian inference engine
fuses their evidence into a posterior probability that the change introduces a vulnerability.

> 🔨 **In evaluation.** All four agents are built and measured, and every likelihood ratio and the
> alert threshold are fitted from a labelled corpus. What remains is the held-out evaluation the
> research paper reports. See **Project status**.

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
backend/         Every uv workspace member lives here
  api/           FastAPI: GitHub sign-in, verify HMAC + enqueue + 202, dashboard reads. No analysis.
  worker/        Celery: owns the pipeline and all agents, runs them, fuses, posts to GitHub
  core/
    contracts/   The single shared contract (ChangeUnit, Evidence). Never vendored.
    engine/      ChangeUnit extraction, Bayesian fusion, calibration fitting. No DB, no agents.
    storage/     SQLAlchemy models, Alembic migrations, pgvector store, dashboard queries
    patch/       Draft a repair, check it on a fixed ladder, anchor it as a suggestion
    corpus/      Labelled cases + committed immutable splits
  agents/        The 4 specialist analysis agents
    static/      Semgrep & Taint static analysis agent
    semantic/    LLM semantic reasoning agent
    context/     Repository context & RAG agent
    runtime/     WASI / Wasmtime sandbox agent
  calibration/   Observations, recorded responses
  docker/        Corpus evaluation Dockerfiles
  scripts/       Database init scripts (init-pgvector.sql)

frontend/        Next.js 16 + React 19 web dashboard & SaaS platform (separate npm project)
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
uv sync --all-packages        # install the workspace (without the flag, members are skipped)
uv run pytest
uv run lint-imports           # agent boundary enforcement
```

`import-linter` is the guardrail that matters: agents may import `contracts` and nothing else. An
agent importing a sibling, the engine, or infrastructure fails CI.

## Project status

Chapters 1–17 of the 18-chapter roadmap are done; Chapter 18, the evaluation, is in progress.

**The pipeline runs end to end.** A signature-verified webhook becomes a queued audit. The worker
cuts one `ChangeUnit` per changed function from the real base and head files, runs the four agents
blind, fuses what they said into one posterior per finding, and posts a single summary comment
that is edited in place on later pushes.

**All four agents are built and measured** on the calibration split of a corpus of 76 hand-written
units in 38 vulnerable/safe twin pairs:

| Agent | Recall on the cases it should catch | False positives |
|---|---|---|
| `structural.taint` | 13/13 | 0 across 23 safe twins |
| `semantic.hosted` | — | 94% safe-twin pass rate, 0% injection subversion, 0 hallucinated sinks |
| `context.rag` | 5/5 | 0 across 11 twins and negative controls |
| `runtime.sfi` | 9/9 | 0 across 23 safe twins |

An agent that cannot run, such as the runtime witness on a machine without the pinned WASI
interpreter, abstains under its own name at a likelihood ratio of exactly 1.0. It costs the
posterior nothing and is visible on the record.

**The numbers are fitted, not hand-set.** Likelihood ratios come from the calibration split, the
alert threshold from a precision–recall sweep on the validation split, and both ship in
`calibration.json` with the corpus hash they were measured against. Weighted ECE is 0.027 and Brier
0.013 at selection time. No hand-set fallback exists: a missing artifact is an error. The prior is
a declared 3%, because a twin-paired corpus has a prevalence of 0.5 by construction.

**Findings are explainable.** The dashboard shows every audit, every witness's statement per
function, and each finding's odds product factor by factor, as stored at the time of the run.
The calibration page shows the reliability bins, per-cell observation counts and the full threshold
sweep.

**An alert-worthy finding can carry a repair.** A drafted patch is checked on a fixed six-step
ladder and, if it passes, posted as a GitHub suggested change inside the diff. CodeSheriff never
commits, merges, or runs the repository's own test suite.

**Still to do (Chapter 18):**

- Re-observe the calibration and validation splits on the Linux corpus image, where Semgrep runs,
  and re-fit. The committed ratios describe a structural witness with only the taint backend live,
  because Semgrep has no Windows build.
- Finish the comparisons against majority voting, leave-one-witness-out ablations, and the Semgrep,
  Bandit and single-LLM baselines (`examples/paper_eval.py`, `examples/baseline_eval.py`).
- Evaluate the held-out test split, exactly once, last.

Separately, Chapter 5 needs one person-only step: confirming sign-in and the repository list
against the registered GitHub App ([`docs/github-app-setup.md`](docs/github-app-setup.md)).

The conformance audit that started the rebuild is in
**[`docs/architecture/AUDIT.md`](docs/architecture/AUDIT.md)**, with a `file:line` citation for
every claim. Its findings are left as audited; the "Closure status" at its top records which
chapter closed each one.

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
