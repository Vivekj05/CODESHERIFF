<div align="center">

# CodeSheriff

**Calibrated security review for GitHub pull requests**

Four independent analysis agents examine every changed function. A Bayesian engine combines their
evidence into a probability that the change introduces a vulnerability, and that probability is
measured against ground truth.

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-API-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Celery](https://img.shields.io/badge/Celery-Redis-37814A?style=flat-square&logo=celery&logoColor=white)](https://docs.celeryq.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%20%2B%20pgvector-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://github.com/pgvector/pgvector)
[![Next.js](https://img.shields.io/badge/Next.js-16-000000?style=flat-square&logo=nextdotjs&logoColor=white)](https://nextjs.org/)
<br>
[![Semgrep](https://img.shields.io/badge/Semgrep-1.176.1-2B4C7E?style=flat-square)](https://semgrep.dev/)
[![tree-sitter](https://img.shields.io/badge/tree--sitter-AST-6E5494?style=flat-square)](https://tree-sitter.github.io/)
[![Gemini](https://img.shields.io/badge/Gemini-Flash-8E75B2?style=flat-square&logo=googlegemini&logoColor=white)](https://ai.google.dev/)
[![Wasmtime](https://img.shields.io/badge/Wasmtime-WASI%20sandbox-654FF0?style=flat-square&logo=webassembly&logoColor=white)](https://wasmtime.dev/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docs.docker.com/compose/)

</div>

---

## Contents

- [Problem statement](#problem-statement)
- [Core idea](#core-idea)
- [Research gap](#research-gap)
- [What makes it different](#what-makes-it-different)
- [System architecture](#system-architecture)
- [How an audit works](#how-an-audit-works)
- [The four agents](#the-four-agents)
- [Combining the evidence](#combining-the-evidence)
- [Security model](#security-model)
- [Tech stack](#tech-stack)
- [Getting started](#getting-started)
- [Repository layout](#repository-layout)
- [Scope](#scope)
- [License](#license)

---

## Problem statement

Pull request security tools report findings as binary alerts: a rule matched, or it did not. None of
them says how far a given alert can be trusted.

| Challenge | Impact |
|---|---|
| Alerts carry no measure of reliability | A reviewer cannot tell a near-certain finding from a guess |
| High false-positive rates | Developers learn to ignore alerts, including the real ones |
| Confidence scores, where they exist, are asserted rather than measured | A stated "high confidence" has no defined meaning |
| One analysis technique per tool | Every finding fails the same way the technique fails |
| Findings rarely explain themselves | Fixing or dismissing one takes investigation |

## Core idea

> An AI code reviewer tells you what it thinks. CodeSheriff tells you how often it is right when
> it thinks that.

CodeSheriff's output is a **calibrated probability**: across many findings reported at 87%, about
87% should turn out to be real vulnerabilities. Calibration is checked against a labelled corpus
using Expected Calibration Error (ECE) and the Brier score, and those metrics are acceptance
criteria for the project rather than optional analysis.

## Research gap

Static analysers such as Semgrep and CodeQL match patterns and data flows; LLM-based reviewers
reason about intent. Each is useful, and each reports what it found without stating, in a
measurable way, how often that kind of finding is correct.

CodeSheriff does not try to out-detect them. It contributes the layer they lack:

- **Several independent witnesses** that fail in different ways, so their agreement is informative.
- **Likelihood ratios fitted from labelled data**, so each witness's statement carries the weight
  its measured accuracy earns, and no more.
- **A probability whose reliability is itself measured**, on a corpus split that was never used to
  fit it.

## What makes it different

| | |
|---|---|
| **Calibrated, not asserted** | Every number in the posterior is fitted on a calibration split and checked on a separate validation split. No confidence value is hand-set. |
| **Four heterogeneous witnesses** | Data-flow analysis, model reasoning, repository precedent and sandboxed execution. They fail for different reasons, which is what makes combining them worthwhile. |
| **Explainable by construction** | Each finding shows the odds product witness by witness: what each agent said and how much that moved the probability. |
| **Abstains rather than guesses** | An agent that cannot analyse a function says so. An abstention leaves the probability unchanged instead of counting as evidence of safety. |
| **Real isolation for untrusted code** | Pull request code is only ever executed inside a Wasmtime/WASI sandbox with no network, no environment and no filesystem. |
| **Suggestions, never commits** | A verified repair is posted as a GitHub suggested change. CodeSheriff never commits, pushes or merges. |

---

## System architecture

```mermaid
flowchart TD
    GH["GitHub<br/>pull request event"] -->|webhook| SMEE["smee.io forwarder<br/>local development"]
    SMEE --> API["FastAPI<br/>verify HMAC, enqueue, 202"]
    API --> REDIS[("Redis<br/>audit queue")]
    REDIS --> EXT

    subgraph WORKER_BOX["Celery worker, Linux container"]
        direction TB
        EXT["Extract one unit<br/>per changed function"]
        AG["Four agents<br/>run blind and in parallel"]
        FUS["Bayesian fusion<br/>fitted ratios"]
        PAT["Patch drafting<br/>and verification"]
        EXT --> AG --> FUS --> PAT
    end

    PAT --> PG[("PostgreSQL + pgvector<br/>audits, evidence, findings")]
    PAT -->|summary comment<br/>and suggestions| GH
    PG --> API2["FastAPI<br/>read routes"]
    API2 --> DASH["Next.js dashboard<br/>Better Auth sign-in"]
```

Three processes, each holding only its own credentials:

| Process | Holds | Never holds |
|---|---|---|
| Dashboard (Next.js) | GitHub OAuth client secret, Better Auth secret | Webhook secret, LLM key |
| API (FastAPI) | Webhook secret, GitHub App private key | User tokens, LLM key |
| Worker (Celery, in Docker) | LLM key, GitHub App private key | Webhook secret, OAuth secrets |

## How an audit works

```mermaid
flowchart TD
    A["Pull request opened or updated"] --> B["Webhook signature verified<br/>before the body is parsed"]
    B --> C["Audit row written and queued<br/>response in under 3 seconds"]
    C --> D["Worker fetches base and head files"]
    D --> E["One ChangeUnit per changed function"]
    E --> F["Structural, semantic, context and runtime<br/>agents analyse each unit independently"]
    F --> G["Each agent returns detection,<br/>silence or abstention"]
    G --> H["Fusion: prior odds multiplied by<br/>one fitted ratio per witness"]
    H --> I{"Posterior at or above<br/>the alert threshold?"}
    I -->|yes| J["Alert, plus a verified repair<br/>where one can be produced"]
    I -->|no| K["Recorded, not alerted"]
    J --> L["One summary comment on the pull request<br/>edited in place on later pushes"]
    K --> L
    L --> M["Full record on the dashboard"]
```

Every agent returns one of three kinds of statement for each function:

| Statement | Meaning | Effect on the probability |
|---|---|---|
| **Detection** | "I found this vulnerability class here" | Raises it, by the agent's fitted ratio |
| **Silence** | "I looked for these vulnerability classes and found nothing" | Lowers it, by the agent's fitted ratio |
| **Abstention** | "I could not analyse this" | None. The ratio is exactly 1.0 |

---

## The four agents

Each agent sees only the changed function. None of them knows the others exist or sees their
results; running them blind keeps their errors independent, which the fusion step depends on.

Accuracy figures below are measured on the **calibration split** of the project's corpus: 76
hand-written functions in 38 pairs, each pair being the same function once vulnerable and once
safe. A false positive is a finding on the safe twin.

### 1. Structural: taint analysis and Semgrep

Follows untrusted data through the function to a dangerous operation, using two backends that are
counted together as **one** witness, because they read the same source text with related
techniques.

```mermaid
flowchart TD
    S["Function parameters<br/>treated as untrusted"] --> G["Def-use graph<br/>built from the tree-sitter AST"]
    G --> P["Taint spreads through assignments,<br/>f-strings, concatenation, calls"]
    P --> Z{"Sanitizer or validating<br/>guard on the path?"}
    Z -->|yes| C["Taint cleared"]
    Z -->|no| K{"Reaches a dangerous<br/>argument of a sink?"}
    K -->|yes| D["Detection with the full path<br/>source to sink"]
    K -->|no| SI["Silence"]
    SG["Semgrep, pinned rules"] --> M["CWE from the rule's own tags"] --> D2["Detection or silence"]
```

- **Taint engine:** every parameter is treated as untrusted input. A sanitizer only clears the
  matching class of danger, so escaping HTML does not silence a shell command. A check such as
  `if x not in ALLOWED: raise` counts as validation; `if x is None: return` does not.
- **Semgrep:** runs digest-pinned rule sets at a pinned version and takes each finding's CWE from
  the rule's metadata.
- **Accuracy:** taint engine 13 of 13 expected detections, 0 false positives across 23 safe twins.
  Semgrep adds independent signal but fires on 2 safe twins, which the fitted ratios account for.
- **Fails when** a vulnerability has no syntactic pattern, such as a missing permission check.
- **Fallbacks:** source that cannot be parsed (`parse_failed`); Semgrep missing, its rules missing
  or altered, or the wrong Semgrep version (`tool_unavailable`, `rules_unavailable`,
  `rules_mismatch`, `tool_version_mismatch`); a run past its time limit (`timeout`); a function too
  large to analyse whole (`unit_too_large`). Each is an abstention, never a guess.

### 2. Semantic: hosted model reasoning

Asks a language model what the function is for, where its trust boundaries are, and which security
invariant the change breaks.

```mermaid
flowchart TD
    U["Changed function"] --> W["Wrapped in a random,<br/>per-request sentinel"]
    W --> P["Prompt with worked examples,<br/>including safe code that looks unsafe"]
    P --> L["Gemini, 3 samples<br/>with different seeds"]
    L --> H{"Hallucination gate"}
    H -->|"CWE in scope, sink appears verbatim,<br/>lines inside the function"| D["Detection, confidence from<br/>agreement across samples"]
    H -->|fails any check| X["That finding is dropped"]
    L -->|no finding| S["Silence"]
```

- The analysed code sits between random markers generated for each request, so code that tries to
  pass itself off as instructions cannot escape them.
- The worked examples include safe code that looks dangerous, which discourages the model from
  simply agreeing that something is a bug.
- Every finding must name an in-scope CWE, quote a sink that appears verbatim in the code, and
  point at lines inside the function. Model prose that reads like an instruction is discarded
  before anything is published.
- **Accuracy:** 94% of safe twins correctly passed, 0% success for prompt-injection attempts, and 0
  hallucinated sinks on the calibration split.
- **Fails when** the model is confidently wrong or too ready to agree.
- **Fallbacks:** no API key or provider unreachable (`llm_unavailable`, `provider_unavailable`);
  the per-function cost budget would be exceeded (`budget_exceeded`); the function is too large
  (`unit_too_large`).

### 3. Context: repository precedent

Checks whether the change drops a security control that this repository's own merged code
consistently applies. There is deliberately no language model in this agent.

```mermaid
flowchart TD
    U["Changed function"] --> E["Embedded locally<br/>bge-small-en-v1.5"]
    E --> R["Nearest merged code<br/>from this repository only, pgvector"]
    R --> C["Controls that history establishes,<br/>for example an ownership check"]
    C --> Q{"Established control missing<br/>from the changed function?"}
    Q -->|yes| D["Detection: CWE-862 or CWE-639"]
    Q -->|no| S["Silence"]
```

- A control counts as established only if the same function carried it before, or at least two
  other functions share it. One neighbour's habit is treated as coincidence.
- It reports only missing authorization (CWE-862) and access to another user's object (CWE-639).
  Retrieval can never cross repositories: the repository is fixed when the retriever is built.
- **Accuracy:** 5 of 5 expected detections, 0 false positives across 11 twins and negative
  controls.
- **Fails when** a repository has no relevant history.
- **Fallbacks:** no relevant history (`no_precedent`); the vector store or embedding model is
  unavailable (`retrieval_unavailable`), kept distinct because a store that is down is not a
  repository that is new; the function is too large (`unit_too_large`).

### 4. Runtime: sandboxed execution

Runs the changed function once inside a Wasmtime/WASI sandbox, with every parameter set to a
uniquely tagged untrusted value, and reports which dangerous operations that value actually
reached.

```mermaid
flowchart TD
    U["Changed function"] --> T["Each parameter bound to a<br/>uniquely tagged untrusted string"]
    T --> SB["Wasmtime + WASI sandbox<br/>no network, empty environment,<br/>fuel, time and memory limits"]
    SB --> O["Recorded stand-ins for dangerous calls:<br/>os.system, open, pickle.loads, ..."]
    O --> Q{"Did the tagged value<br/>reach one?"}
    Q -->|yes| D["Detection: observed, not inferred"]
    Q -->|no| S["Silence"]
```

- The sandbox has no network capability at all, so a module that tries to connect fails before
  running a single instruction. The guest receives an argument list and three standard streams,
  and nothing else.
- It covers CWE-22, 78, 94, 502 and 918, where an observation is direct evidence. SQL injection and
  XSS are left to the other witnesses, because there the "sink" would be an object the harness
  itself created.
- **Accuracy:** 9 of 9 expected detections, 0 false positives across 23 safe twins.
- **Fails when** the code will not run in a sandbox.
- **Fallbacks:** the pinned interpreter is missing (`interpreter_unavailable`) or its checksum
  does not match (`interpreter_digest_mismatch`); a non-Python unit (`unsupported_language`); the function raised, had
  no safe entry point, ran out of fuel or time, or reached for a capability the sandbox does not
  have (`unit_raised`, `no_safe_entrypoint`, `fuel_exhausted`, `timed_out`, `sandbox_trapped`); a
  guard the probe could not evaluate (`guard_unresolved`). Reporting in that last case would
  penalise code that defends itself, so it abstains.

### Fallbacks shared by all agents

The worker guarantees at least one statement per agent per function. An agent that fails to load,
raises an exception, exceeds its time limit or returns nothing is recorded as an abstention under
its own name (`agent_unavailable`, `agent_raised`, `agent_timeout`, `agent_returned_nothing`). A
missing agent therefore never shortens the record or silently lowers a probability.

---

## Combining the evidence

```mermaid
flowchart LR
    P["Prior odds<br/>declared base rate 3%"] --> X(("multiply"))
    W1["Structural ratio"] --> X
    W2["Semantic ratio"] --> X
    W3["Context ratio"] --> X
    W4["Runtime ratio"] --> X
    X --> PO["Posterior probability"]
    PO --> T{"At or above the fitted<br/>threshold 0.218?"}
    T -->|yes| A["Alert"]
    T -->|no| N["No alert"]
```

- Exactly **four** factors are multiplied, one per witness, whatever the agents said. Fusion
  iterates over all witnesses, so silence can lower a probability as well as detection raise it.
- Each likelihood ratio is **fitted on the calibration split**, per witness and per confidence
  level, with its observation counts recorded. The alert threshold is **selected on the validation
  split**. The held-out test split is reserved for a single final evaluation.
- The prior is **declared, not measured**: a corpus built from twin pairs is 50% vulnerable by
  construction, which would wildly overstate how often real changes are vulnerable.
- There is no hand-set fallback. If the fitted artifact (`calibration.json`) is missing, fusion
  refuses to run rather than invent numbers.

**Measured on the validation split** (base-rate weighted): ECE 0.024, Brier score 0.013, precision
1.000 and recall 0.857 at the selected threshold of 0.218. The held-out test split has not yet been
evaluated; it is opened exactly once, at the end.

---

## Security model

```mermaid
flowchart TD
    GH["GitHub"] -->|"X-Hub-Signature-256,<br/>checked before parsing"| API["API"]
    USER["Browser"] -->|"15-minute EdDSA JWT<br/>from Better Auth"| API
    API -->|"audit id only"| Q[("Redis")]
    Q --> W["Worker container<br/>read-only mounts: code, rules, interpreter"]
    W --> SB["Wasmtime sandbox<br/>no network, no files, no environment"]
    W --> DB[("PostgreSQL<br/>findings, evidence and hashes,<br/>never full source")]
```

- **Webhook authenticity:** the signature is verified against the raw body before anything is
  parsed, and the API answers within GitHub's time limit by queuing rather than processing.
- **Access control:** the dashboard signs users in with GitHub, and the API verifies a short-lived
  signed token. Each user sees only the installations GitHub says they can reach; an empty list
  returns nothing rather than everything.
- **Untrusted code:** pull request code is executed only inside the WASI sandbox, which has no
  network, no files and no environment variables, so it cannot reach the credentials of the worker
  around it.
- **Credential separation:** the worker container mounts only the code, the pinned Semgrep rules
  and the interpreter, all read-only. No `.env` file is visible inside it, and the image contains
  no secrets.
- **Data minimisation:** stored records hold findings, evidence and hashes of source, never full
  file contents. The pull request comment carries no file paths or source.
- **Prompt injection:** analysed code is fenced by a random per-request sentinel, and
  instruction-like model output is dropped rather than published.

---

## Tech stack

| Layer | Technology |
|---|---|
| API | Python 3.12, FastAPI, Pydantic v2 |
| Queue and worker | Celery, Redis |
| Database | PostgreSQL 16 with pgvector, SQLAlchemy, Alembic |
| Code parsing | tree-sitter, tree-sitter-language-pack, networkx |
| Static analysis | Custom taint engine, Semgrep CLI (SARIF) |
| Model reasoning | Gemini Flash (free tier) |
| Embeddings | sentence-transformers, BAAI/bge-small-en-v1.5 (384 dimensions, local) |
| Sandbox | Wasmtime with WASI, pinned CPython build |
| Calibration | Likelihood-ratio fitting and ECE/Brier metrics, implemented in the engine |
| GitHub integration | githubkit, GitHub App, smee.io for local webhooks |
| Dashboard | Next.js 16, TypeScript, Tailwind, ChaiUI on shadcn/ui, Recharts, Better Auth |
| Tooling | uv workspace, pytest, ruff, mypy --strict, import-linter, Typer, Docker Compose |

---

## Getting started

### Prerequisites

- Docker Desktop
- Python 3.12 and [`uv`](https://docs.astral.sh/uv/)
- Node.js 20 or later
- A registered GitHub App and a smee.io channel. [`docs/github-app-setup.md`](docs/github-app-setup.md)
  walks through both.
- A Gemini API key

### 1. Install and configure

```bash
cp .env.example .env
```

Fill in `.env`, and `frontend/.env.local` for the dashboard's variables; `.env.example` lists both.
Then install the workspace:

```bash
uv sync --all-packages
```

```bash
npm --prefix frontend install
```

### 2. Fetch the pinned analysis artifacts

Neither file is committed. Each is checked against a recorded SHA-256 before use, and a mismatch is
an abstention, not a silent change of behaviour.

```bash
mkdir -p .wasm-runtimes
curl -L -o .wasm-runtimes/python-3.12.0.wasm https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/python%2F3.12.0%2B20231211-040d5a6/python-3.12.0.wasm
```

```bash
mkdir -p .semgrep/rules
curl -L -o .semgrep/rules/security-audit.yml https://semgrep.dev/c/p/security-audit
curl -L -o .semgrep/rules/owasp-top-ten.yml https://semgrep.dev/c/p/owasp-top-ten
```

The rule sets must match the digests in `SEMGREP_RULESETS`
(`backend/agents/static/src/static_agent/config.py`). The registry changes over time, so a fresh
download may not match; see [`backend/docker/corpus-run/README.md`](backend/docker/corpus-run/README.md).

### 3. Create the database and build the worker image

```bash
docker compose up -d postgres redis
```

```bash
uv run alembic -c backend/core/storage/alembic.ini upgrade head
```

```bash
docker compose --profile worker build worker
```

The worker runs in a Linux container because Semgrep does not run on Windows; running it natively
would score a different structural witness than the one that was fitted.

### 4. Run

**Windows, one command:**

```bash
codesheriff.bat dev
```

This checks that Docker is running and that ports 8000 and 3000 are free, then starts Postgres and
Redis, the API, the worker container, the webhook forwarder and the dashboard, each in its own
window. Open http://localhost:3000. To stop everything (container data is kept):

```bash
codesheriff.bat stop
```

**Any platform, one terminal each:**

```bash
uv run uvicorn codesheriff_api.main:app --reload --port 8000
```

```bash
docker compose --profile worker up -d --force-recreate worker
```

```bash
npx smee-client --url "$SMEE_URL" --target http://localhost:8000/webhooks/github
```

```bash
npm --prefix frontend run dev
```

Restart the worker after a code change; Celery does not reload. Without the smee forwarder,
webhooks never reach a local API.

### 5. Test

```bash
uv run pytest
```

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy . && uv run lint-imports
```

```bash
npm --prefix frontend run lint && npm --prefix frontend run build
```

Tests that need Postgres run only when `CODESHERIFF_TEST_DB` is set, and they reset that database,
so point it at a separate one:

```bash
docker exec codesheriff-postgres psql -U codesheriff -c "create database codesheriff_test"
```

```bash
export CODESHERIFF_TEST_DB=postgresql+psycopg://codesheriff:codesheriff@localhost:5432/codesheriff_test
```

Sandbox tests run only when the WASI interpreter is present. No test makes a live network call:
non-local connections fail at the socket layer.

---

## Repository layout

```
backend/
  api/            FastAPI: webhook verification and queuing, JWT verification, dashboard reads
  worker/         Celery: fetches files, runs the agents, fuses, posts to GitHub
  core/
    contracts/    The single shared contract (ChangeUnit, Evidence)
    engine/       Unit extraction, Bayesian fusion, calibration fitting; no database, no agents
    storage/      SQLAlchemy models, Alembic migrations, pgvector store, dashboard queries
    patch/        Drafts a repair, checks it on a fixed ladder, anchors it as a suggestion
    corpus/       Labelled vulnerable/safe twin cases and their fixed splits
  agents/
    static/       structural.taint and structural.semgrep
    semantic/     semantic.hosted
    context/      context.rag
    runtime/      runtime.sfi and its Wasmtime sandbox
  calibration/    Recorded observations and model responses used for fitting
  docker/         The Linux image used by the worker and for corpus runs
  scripts/        Database initialisation (pgvector)
frontend/         Next.js dashboard and Better Auth sign-in
examples/         Evaluation scripts and sample pull requests
docs/             Specifications, architecture decisions, roadmap
```

Module boundaries are enforced by `import-linter`: an agent may import only the shared contract,
the engine may not reach the database, and the audit path may not read the corpus labels.

---

## Scope

**Platform:** GitHub, Python first.

**Vulnerability classes (closed set):**

| CWE | Vulnerability |
|---|---|
| CWE-22 | Path traversal |
| CWE-78 | OS command injection |
| CWE-79 | Cross-site scripting |
| CWE-89 | SQL injection |
| CWE-94 | Code injection |
| CWE-502 | Deserialization of untrusted data |
| CWE-639 | Authorization bypass through a user-controlled key |
| CWE-798 | Hard-coded credentials |
| CWE-862 | Missing authorization |
| CWE-918 | Server-side request forgery |

<details>
<summary><b>Out of scope</b></summary>
<br>

- Dependency and supply-chain scanning
- Container and infrastructure-as-code scanning
- Binary analysis
- Automatic commits or merges of patches
- Running a repository's own test suite
- Compliance reporting
- Multi-tenant billing
- IDE plugins

</details>

---

## License

Developed as a final-year B.Tech project. No open-source license has been granted.

<div align="center">
<br>

**CodeSheriff**: a probability you can check, for every finding.

</div>
