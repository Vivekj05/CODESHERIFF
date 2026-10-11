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
   One summary comment on the PR, plus the dashboard:
   - a calibrated posterior per finding, with what each agent said (detection, silence, abstention)
   - the odds product factor by factor, and the calibration it ran under
   - a checked repair, posted as a GitHub suggested change inside the diff, when one survives
```

### Using it

1. **Sign in** from the home page (`/sign-in`, GitHub). Signing in grants no repository access.
2. **Connect the GitHub App** from the dashboard's GitHub App page, choosing all or selected
   repositories on GitHub. Overview prompts for this until it is done.
3. **Open a pull request** on a connected repository. The audit runs and comments on the PR, and the
   dashboard shows how every number was reached.

Disconnecting the App, or deselecting a repository, hides its audits rather than deleting them;
reconnecting brings them back (D-102).

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
* **Frontend**: Next.js 16 (App Router) · React 19 · TypeScript · Tailwind CSS 4 · ChaiUI (on shadcn/ui) and Base UI · Better Auth (GitHub sign-in, JWT for the API) · TanStack Query v5 · Recharts

Zero recurring cost: free-tier LLM, local embeddings, self-hosted everything.

## Layout

```
backend/         Every uv workspace member lives here
  api/           FastAPI: verifies the dashboard's JWT, webhooks (HMAC + enqueue + 202), dashboard reads
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

frontend/        Next.js 16 dashboard (separate npm project, not a uv member)
  src/app/       Home page, /sign-in, the dashboard pages, and /api/auth (Better Auth, the only API route)
  src/components/ ChaiUI pieces (components/chai), the shell, sidebar and shared widgets
  src/lib/       auth.ts (Better Auth server), auth-client.ts, api.ts (the only caller of the Python API)

examples/        Evaluation benchmarks (baseline_eval, paper_eval) and sample PRs

docs/            Consolidated documentation (specs, architecture, roadmap, guides)
```

## Getting started

Requires Docker, Node 20+, and Python 3.12 with `uv`.

### Quick Start (Windows)
Use the one-click batch runner:
```cmd
# Docker infra + API + Worker + webhook forwarder (smee) + Dashboard, each in its own window
codesheriff.bat dev

# Run full test suite
codesheriff.bat test

# Run benchmark evaluations
codesheriff.bat eval
```

### Manual Setup
```bash
cp .env.example .env          # then fill it in; it also lists what frontend/.env.local needs
docker compose up -d postgres redis
uv sync --all-packages        # install the workspace (without the flag, members are skipped)
uv run alembic -c backend/core/storage/alembic.ini upgrade head
uv run lint-imports           # agent boundary enforcement
```

Then, each in its own terminal:

```bash
uv run uvicorn codesheriff_api.main:app --reload --port 8000
uv run celery -A codesheriff_worker.celery_app worker --loglevel=info --queues=audits --pool=solo
npx smee-client --url "$SMEE_URL" --target http://localhost:8000/webhooks/github
npm --prefix frontend run dev
```

`--pool=solo` is for Windows. Without the smee forwarder, GitHub's webhooks never reach a local API,
and smee keeps nothing for a client that was not listening.

**The GitHub App** needs, in its settings: the callback URL
`http://localhost:3000/api/auth/callback/github`, the "Email addresses: Read-only" account
permission, and the Setup URL `http://localhost:8000/auth/install/callback` with "Redirect on
update". [`docs/github-app-setup.md`](docs/github-app-setup.md) walks through registering one.

**Tests that touch Postgres** migrate their database to empty and back, so point them at a separate
database, never the one holding real audits:

```bash
export CODESHERIFF_TEST_DB=postgresql+psycopg://codesheriff:codesheriff@localhost:5432/codesheriff_test
uv run pytest
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

**Sign-in and connecting are separate steps.** Better Auth signs users in with GitHub in the
dashboard and hands the Python API a short-lived signed token; the API verifies it and still shows
each user only the installations GitHub says they can reach (D-101). The GitHub App page installs,
manages and disconnects the App, and disconnecting keeps the history (D-102).

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
