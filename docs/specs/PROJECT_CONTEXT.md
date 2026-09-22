# CodeSheriff — Starting Context for Claude Code

**Status:** Planning complete, no code written. Development begins at v0.1.

This handoff gives you enough context to start intelligently. It is deliberately **not**
a full plan — the project is built iteratively, phase by phase, with approaches agreed
before each significant phase.

---

## 1. Project Overview

**What it is.** A GitHub App that performs automated security review on pull requests.
When a PR opens, changed code is analysed independently by four specialist agents, each
producing a different *kind* of evidence. A Bayesian inference engine fuses that evidence
into a calibrated posterior probability that the change introduces a vulnerability.

**Problem it solves.** Existing PR security tooling emits binary alerts with no measure of
reliability. State-of-the-art research tools still report false discovery rates above 80%,
which trains developers to ignore alerts entirely. The problem is not detection count — it
is that no tool tells you how much to trust a given finding.

**Primary objective.** Produce findings whose confidence values *mean something* — where a
stated 87% corresponds to being right about 87% of the time, measured against ground truth
rather than asserted.

**Framing.** An AI code reviewer tells you what it thinks. CodeSheriff tells you how often
it is right when it thinks that.

**Users.** Small-to-mid engineering teams on GitHub without dedicated AppSec staff;
open-source maintainers reviewing PRs from untrusted contributors; individual developers.

**Context.** Final-year academic project. Solo developer, part-time, **no fixed deadline**.
A research paper is a deliverable at the end; current focus is entirely on building.

---

## 2. Core Requirements

**Functional**
- GitHub App receiving `pull_request` webhooks, HMAC signature-verified
- Diff parsed into `ChangeUnit` objects — one per changed function or method
- Four agents analysing each unit blind and in parallel
- Evidence grouped by `finding_key`
- Bayesian fusion producing one posterior per finding group
- Conditional branch: above threshold → patch generation; report fires on **both** paths,
  including when the verdict is clean
- Results posted as a GitHub PR comment and shown on a web dashboard
- Shared labelled corpus used to fit likelihood ratios and select the alert threshold
- Patches are suggestions only — the system never commits or merges

**Non-functional** (explicitly discussed)
- Webhook acknowledged in < 3s (GitHub hard limit is 10s)
- Full audit completion target < 5 min
- Static agent p95 latency ≤ 3s per ChangeUnit
- Semantic agent cost ≤ $0.01 per ChangeUnit at n=3
- Zero live API calls in the test suite (enforced via recorded responses)
- Test coverage ≥ 80% per package; `mypy --strict` and `ruff check` clean in CI
- Zero unhandled exceptions across a full corpus run
- Calibration metrics (ECE, Brier score) are **mandatory** acceptance criteria, not
  optional analysis

---

## 3. High-Level Architecture

### Data flow

```
GitHub PR opened
      ▼
API: verify HMAC → enqueue → return 202
      ▼
Job queue
      ▼
ChangeUnit extraction (diff → changed functions)
      ▼
  ┌──────┬──────────┬─────────┬─────────┐
Static  Semantic  Context  Runtime        ← blind, parallel, no shared state
  └──────┴─────┬────┴─────────┘
              ▼
   Evidence grouped by finding_key
              ▼
   Bayesian fusion (posterior per group)
              │
    ┌─────────┴─────────┐
 above threshold    below threshold
    ▼                   │
Patch generation        │
(draft, verify)         │
    └─────────┬─────────┘
              ▼
   PR comment + dashboard
```

### Processes

| Process | Responsibility |
|---|---|
| **API** (FastAPI) | Verify HMAC, enqueue, return 202. Serve dashboard REST. Performs no analysis. |
| **Worker** (Celery) | Runs the audit pipeline. Owns all agents. |
| **Sandbox** | Separate container. No DB credentials, no network egress, ephemeral filesystem. |

### The four agents

Each decides on a **fundamentally different basis**. This heterogeneity is the entire
justification for the project — agents that failed the same way would add nothing to a
probability estimate.

| Agent | Basis for decision | Fails when |
|---|---|---|
| **Static** (`structural.taint`, `structural.semgrep`) | Rules + mechanical reachability proof: source → sink with no covering sanitizer. No LLM. | Bug has no syntactic pattern |
| **Semantic** (`semantic.hosted`) | Absorbed model knowledge. Three stages: functional intent → trust boundaries → violated safety invariant. | Model hallucinates or is over-agreeable |
| **Context** (`context.rag`) | This repository's own precedent — does this change bypass a control an earlier merged PR established? | Repo has no relevant history |
| **Runtime** (`runtime.sfi`) | Direct observation. Executes in a sandbox, records attempted syscalls, network egress, file access. | Code will not run in a sandbox |

### Interaction rules

- Every agent implements exactly `analyze(unit: ChangeUnit) -> list[Evidence]`
- No agent knows another exists, or knows about GitHub, the database, or fusion
- Agents never raise — every failure path produces an abstention with a distinct reason
- Orchestration is a plain `asyncio.gather` fan-out over pure functions

### External integrations

GitHub REST API (App installation tokens, PR comments, checks) · Gemini Flash free tier
(behind a provider-agnostic interface)

---

## 4. Technology Decisions

**Committed:**

| Concern | Choice |
|---|---|
| Language | Python 3.12 |
| Packaging | `uv` workspace (monorepo) |
| API | FastAPI |
| Validation | Pydantic v2 |
| Queue | Celery + Redis |
| Database | PostgreSQL 16 with **pgvector** |
| ORM / migrations | SQLAlchemy + Alembic |
| GitHub client | `githubkit` |
| Parsing | `tree-sitter` + `tree-sitter-language-pack` |
| Pattern scan | `semgrep` CLI via subprocess, `--sarif` |
| Graphs | `networkx` |
| Learned scorer | `scikit-learn` (logistic regression) |
| Embeddings | `sentence-transformers`, `BAAI/bge-small-en-v1.5` (384-dim, local) |
| LLM | Gemini Flash free tier |
| Sandbox | **Wasmtime + WASI** |
| CLI | `typer` |
| Testing | `pytest`, `pytest-cov`, `syrupy`, `hypothesis` |
| Lint / types | `ruff`, `mypy --strict` |
| Boundary enforcement | `import-linter` |
| Frontend | Next.js (App Router) + TypeScript, Tailwind, shadcn/ui, Recharts |
| Deployment | Docker Compose |

**Explicitly rejected, with reasons:**

- **LangGraph** — agents are pure functions with no shared state; a shared-state framework
  would fight the independence requirement and obscure the exact prompt bytes needed for
  cache keys and reproducibility
- **ChromaDB** — pgvector instead; survives restarts, one less service, and allows metadata
  filtering and similarity search in one query
- **Python's built-in `ast`** — tree-sitter handles JS/TS through the same API and tolerates
  syntax errors, which PR diffs frequently contain
- **Docker as the sandbox** — containers are OS-level isolation, not software fault
  isolation; the SFI claim requires Wasmtime
- **Prisma / Inngest / Pinecone / Next.js API routes as backend** — the backend must be
  Python because tree-sitter, scikit-learn, and Wasmtime bindings have no viable JS
  equivalent

---

## 5. Finalized Decisions

**These are final. Several reverse earlier drafts and exist to fix specific identified
bugs — do not revert them without raising the conflict first.**

### Repository structure

**Monorepo, `uv` workspace.** Not six separate repos. Solo development has no multi-person
schema drift to solve, so vendoring `contracts.py` with SHA-256 checks (present in earlier
specs) is dropped in favour of a shared package.

**Agent boundaries enforced by `import-linter`.** Agents may import `contracts` and nothing
else; an agent importing a sibling fails CI. Preserves the isolation benefit of separate
repos without the ceremony.

Layout: `packages/{contracts, corpus, agent_static, agent_semantic, agent_context,
agent_runtime, engine}` and `apps/{api, worker, dashboard}`.

### Contracts

**`finding_key = sha256(f"{file}::{qualified_symbol}::{cwe}")[:16]`.** The sink expression
is deliberately excluded. With it, the taint engine reports `cursor.execute(query)` while
the LLM reports `cursor.execute` — different hashes, different groups, and the agents would
never fuse. Every finding would be a singleton and the Bayesian engine would never perform
an update. Accepted trade-off: two independent bugs of the same CWE in one function collapse
into one group. Computed **only** by the contracts package; agents never construct it.

**`ChangeUnit` carries `pre_src` (nullable) as well as `post_src`,** plus `imports`,
`decorators`, `enclosing_class`, `is_test_file`. The context and semantic agents must see
what was *removed*, not only what was added.

**PR title/description passed separately as optional `pr_context`,** never inside
`ChangeUnit`. They are PR-level not unit-level, attacker-controlled and unverifiable, and
absent from corpus cases — embedding them would make agents behave differently on corpus
runs than in production, corrupting calibration.

**Three evidence kinds: `DETECTION`, `SILENCE`, `ABSTENTION`.** Silence (ran, found nothing)
gets a likelihood ratio below 1.0; abstention (could not run) gets exactly 1.0. Conflating
them was a wrong-sign bug — an agent that could not look would penalise the finding.

**`SILENCE` carries `covered_cwes`; the silence ratio applies only inside that set.**
Otherwise the taint engine's silence on CWE-862 (which it has no rules for) would
systematically suppress every semantic-only finding.

**`raw_score` is agent-internal and monotonic within that agent, not a probability.** Scores
are not comparable across agents; calibration handles that.

**Artifacts are the only extension point.** A needed new field is almost always an artifact.

**Oversized units abstain with `unit_too_large` (per-agent thresholds), never truncate.**
Truncated analysis produces confident-looking findings from half-read code, biased toward
over-reporting, and silently invalidates calibration.

**`IN_SCOPE_CWES` is a closed set:** CWE-22, 78, 79, 89, 94, 502, 639, 798, 862, 918.

### Orchestration

**No anchors — agents run blind.** An earlier design ran static first and passed its finding
keys downstream. That correlates the agents and breaks the conditional independence the
fusion math assumes. Anchored execution becomes a labelled ablation, not the default.

### Static agent

- **Sinks declare a `class:` field** (`injection`, `command`, `xss`, `path`,
  `deserialization`, `code`); sanitizers clear a list of classes. Without it the engine
  cannot tell whether `shlex.quote` covers `os.system`.
- **Parameterised SQL is not a sanitizer** — it is a property of the sink call, modelled as
  `safe_when: params_passed_separately`. As a sanitizer it would clear taint for every
  injection sink in the function.
- **Rules match the text of call-expression AST nodes, not raw source.** Raw-text regex
  matches inside comments and string literals.
- **Type-coercion sanitizers required** (`int()`, `float()`, `uuid.UUID()`, allowlist
  membership) — the largest false-positive source without them.
- **Build the def-use graph before the taint engine.** On a correct graph the engine is
  ~150 lines; without one it becomes 600 lines of special cases.
- **Scoring is learned, not hand-tuned** (v0.9). Path length, sink danger, sanitizer
  presence, source type, test-file flag, unknown-call count become features for logistic
  regression fitted on the corpus. Gives genuine learning over graph-derived features,
  trains on hundreds not thousands of examples, and outputs a natively calibrated
  probability (Platt scaling *is* logistic regression on scores). *Interim: the hand-tuned
  formula from the original build spec is acceptable until v0.9.*
- Ten precise sinks beat sixty sloppy ones; every new sink ships with a vulnerable fixture
  **and** a safe twin.
- Test-file findings are downweighted, not suppressed — suppressing hides signal from fusion.

### Semantic agent

- **Hallucination gate** rejects a finding if the sink expression is not verbatim in
  `post_src`, evidence lines fall outside the unit range, the file path differs, or the CWE
  is outside `IN_SCOPE_CWES`.
- **n=3 self-consistency with varying seeds.** A fixed seed produces three identical samples
  and defeats the purpose.
- **Anti-sycophancy: three few-shot exemplars, two returning `{"findings": []}`.** Teaches
  that safe-by-default is an acceptable answer.
- **Prompt injection defence:** untrusted code inside delimited data tags with an explicit
  data-vs-instruction boundary; rationales screened so injected strings are not echoed.
- Response cache keyed on
  `sha256(system + user + model + agent_version + temperature + sample_index)`.

### Context agent

- **Indexes per-symbol documents, not per-PR.** `bge-small-en-v1.5` truncates at 512 tokens,
  so PR-level diffs are silently cut, and PR-level vectors match poorly against
  function-level queries.
- **Retrieval filtered by repository.**
- **Must emit evidence under the same `finding_key` as the finding it relates to.** With its
  own key it is architecturally inert: prior odds 0.0526 × its best ratio 4.2 = posterior
  0.18 against a 0.70 threshold — it could never alert and never corroborate. It is a
  corroborating witness, not a soloist.
- Cold start and below-similarity-floor both abstain.

### Runtime agent

- **Built as isolation infrastructure first, detection agent second.** The sandbox earns its
  place because running untrusted PR code is how CI systems get compromised; evidence is a
  secondary benefit. This also makes the SFI claim in the title honest immediately rather
  than conditional on the agent detecting well.
- Deny-by-default: no network, ephemeral read-only filesystem, CPU/memory/wall-clock caps.
- **Abstains widely** (`no_safe_entrypoint`, `dependency_unavailable`) — expected, not a
  defect.

### Fusion engine

- `posterior_odds = prior_odds × ∏ LR(agent_i)`
- **Every agent contributes exactly one LR per finding group.** Iterate over all agents, not
  only those that emitted evidence — otherwise odds can only ever increase.
- **Likelihood ratios fitted on the calibration split, never hardcoded.** Laplace smoothing;
  clamped to prevent a handful of observations producing absurd values. *(Specific clamp
  bounds are a proposed default, not measured.)*
- **Prior is measured, then rescaled** from the balanced corpus (~50%) to the real base rate
  (~2–5% of changed functions). Without rescaling every posterior is inflated. The rescaling
  must be recorded.
- **Threshold selected from a precision-recall sweep on the validation split.**
- **Debate emits its own evidence** (`agent_id="debate.synth"`) with its own calibrated LR;
  it never overwrites the posterior. Overwriting destroys calibration exactly on the
  contested cases and makes the debate step unmeasurable.
- `calibration.json` records the corpus commit hash that produced it.

### Corpus

- **One shared corpus**, not one per agent — calibration requires all agents scored on
  identical items.
- **Splits committed once and immutable. Twins stay in the same split** or information leaks.
- **Labels carry `detectable_by`** so a static miss on a semantic-only case is not counted
  as a failure.
- **Hand-written, not sourced from public datasets** — at this size every label must be
  certain, and clean twins cannot be reliably extracted from real commits.
- Authz cases (CWE-862/639) deliberately have no static path; they exist to prove
  heterogeneity.
- **The corpus is not a training set for detecting vulnerabilities.** No agent learns what a
  vulnerability is from it. It answers a different question: how much each agent should be
  trusted when it speaks. The learning is about the witnesses, not the crime.

### Build order

Each version independently demoable. Principle: **working before optimal.**

```
v0.1  webhook → diff parsed → hardcoded comment posted (no analysis)
v0.2  contracts frozen + corpus with committed splits
v0.3  Semgrep backend + fusion engine with hand-set ratios
v0.4  taint engine (parse, def-use graph, propagation, paths)
v0.5  semantic agent (prompted)
v0.6  empirical calibration from corpus outcomes
v0.7  context agent (RAG over merged PRs)
v0.8  runtime agent (Wasmtime + WASI)
v0.9  learned scorer + fine-tuned semantic model
v1.0  dashboard, patch loop, full evaluation
```

### Proposed defaults, not final

These were discussed as reasonable starting values and should be revisited with real data
rather than treated as settled: corpus size (~60 cases + ~15 cross-PR scenarios), the
0.70 alert threshold, per-agent likelihood ratio values, LR clamp bounds, cosine similarity
floor, top-K retrieval depth, and per-agent oversized-unit thresholds.

---

## 6. Constraints

**Project**
- Solo developer, part-time, no fixed deadline
- Serial execution — nothing built in parallel; any overrun pushes everything after it
- Zero recurring cost: free-tier LLM APIs, local embeddings, self-hosted everything
- No dedicated GPU; any fine-tuning must fit free Colab/Kaggle tiers

**Architectural**
- Backend must be Python — tree-sitter, scikit-learn and Wasmtime bindings have no viable
  JS equivalent
- Next.js is a **rendering layer only**: no business logic, no database access, no detection
  logic in TypeScript
- Agents are pure functions with no shared state; anything that introduces shared state
  between agents violates the fusion independence assumption
- Webhook must be acknowledged within GitHub's 10s limit — enqueue, never process inline
- GitHub API: 5,000 requests/hour per installation; cache aggressively
- LLM free tier has requests-per-minute caps; batch and back off

**Security**
- Untrusted code executes only in the sandbox: deny-by-default network, ephemeral
  filesystem, resource caps, and never on a host holding database credentials
- Source code held in memory and ephemeral storage only; persisted records contain findings,
  evidence and hashes — never full file contents
- GitHub App private key, webhook secret and LLM credentials via environment variables only
- PR-authored text is attacker-controlled and must not be routed to agents that do not need it

**Research integrity (non-negotiable)**
- Scoring weights and likelihood ratios fitted **only** on the calibration split
- Threshold selected **only** on the validation split
- Test split evaluated exactly once, at the end

**Scope limits**
- GitHub only. Python is the primary language. Out of scope: dependency/supply-chain
  scanning, container and IaC scanning, binary analysis, auto-merge or auto-commit of
  patches, compliance reporting, multi-tenancy with billing, IDE plugins

---

## 7. Open Questions

Unresolved. Several are better answered by observing the real API than by deciding now.

1. **GitHub App configuration** — permissions and events to request; behaviour on
   force-push; one summary comment vs inline review comments anchored to lines; how to
   update rather than duplicate on subsequent pushes
2. **Dashboard scope** — minimum agreed is repo list, audit history, finding detail with
   per-agent evidence breakdown, and taint path rendering. Anything beyond is undecided
3. **Patch generation mechanics** — how the LLM receives context; what "verified" means when
   a repo has no test suite; retry count; GitHub suggested-change block vs plain code block
4. **Local development setup** — smee.io vs ngrok for webhook tunnelling; Docker Compose
   layout
5. **Demo repository** — needs real merged PRs for the context agent plus craftable PRs for
   detection demos. A small self-owned Flask/FastAPI app was suggested but not chosen.
   Corpus scenarios should mirror whatever this becomes
6. **Abstract wording** — "confidential execution" implies a hardware TEE (SGX/SEV/TDX),
   which is not what is being built. Two options were identified — soften to "isolated
   execution layer", or keep the phrase and define it in the report as SFI-based isolation.
   **Neither was chosen.** Using Wasmtime keeps the SFI claim defensible either way
7. **JavaScript/TypeScript support — ambiguous.** Referenced in the original static agent
   build spec and described elsewhere as "if time permits". Treat as Python-first with JS/TS
   unscheduled until explicitly decided
8. **Fine-tuned semantic model (v0.9) — ambiguous.** Discussed as the way to make the
   abstract's "fine-tuned language model" claim honest, and as better for calibration
   (continuous logit vs four discrete self-consistency buckets). Not confirmed as committed

---

## 8. Development Workflow

Planning stops here. Development is iterative:

1. Understand the existing repository state before proposing anything
2. Divide work into logical phases based on what actually exists
3. Inspect the current implementation before a significant phase
4. Brainstorm approaches and evaluate trade-offs
5. Agree the approach before implementing, when the decision is significant
6. Implement
7. Test and review
8. Record important decisions in `DECISIONS.md` — decision, rationale, consequences
9. Create or update documentation only when it becomes useful
10. Repeat

**`DECISIONS.md` is a living record.** Every entry states the decision *and the reason* —
in four months the reason is what matters, and each entry becomes a paragraph in the report.

**Conflict rule:** if a new decision conflicts with a finalized decision in Section 5,
**identify the conflict and discuss it before changing anything.** Several Section 5 entries
reverse earlier drafts and exist to fix specific bugs; reverting them silently would
reintroduce those bugs.

**Also worth maintaining:** a one-line recorded cause for every false positive and false
negative, written as it is found rather than reconstructed at the end.
