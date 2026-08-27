# PLAN.md — Roadmap and session-by-session build plan

One chapter per session. Start a session by reading this file, take the first chapter not marked
✅, and work only that chapter. Finish by updating its status here and appending any decision to
`DECISIONS.md`.

**Status:** ⬜ not started · 🔨 in progress · ✅ done · ⚠️ done with caveats (note them)

**Read first:** `CLAUDE.md` → `PROJECT_CONTEXT.md` §5 → the `AUDIT.md` entries your chapter closes.

> Most chapters from 6 onward are **rewrites, not greenfield**. Code with the right filename already
> exists and is non-conformant. Each such chapter begins by deleting the existing version, not by
> patching it — see its "Replaces" line. Patching code built against a superseded spec is how this
> project reached the state `AUDIT.md` documents.

---

## Where the project actually is

Roughly: **v0.1 partially built, v0.3–v0.5 built as facades.**

Four packages exist with a passing test suite and a webhook that reaches GitHub. But the conformance
audit found three of four analysis components non-functional, the fusion engine implementing the
pre-reversal form of nearly every finalized decision, and the webhook unauthenticated. Nothing
numeric is calibrated, because no corpus exists.

The test suite reports 100% and cannot detect any of this.

| Version | Goal | Status |
|---|---|---|
| v0.1 | webhook → diff parsed → comment posted | ⚠️ posts comments; no HMAC, no queue, per-file units |
| v0.2 | contracts frozen + corpus with committed splits | ⚠️ contracts non-conformant; **no corpus at all** |
| v0.3 | Semgrep backend + fusion engine | ⚠️ Semgrep runner works; fusion has 7 defects |
| v0.4 | taint engine | ⚠️ **no taint engine** — def-use graph discarded; line cross-product |
| v0.5 | semantic agent | ⚠️ runs; exemplars never loaded, gate incomplete, no size check |
| v0.6 | empirical calibration | ⬜ blocked on corpus |
| v0.7 | context agent | ⚠️ **no RAG reasoning** — four hard-coded substring tests |
| v0.8 | runtime agent (Wasmtime + WASI) | ⬜ does not exist |
| v0.9 | learned scorer + fine-tuned semantic model | ⬜ |
| v1.0 | dashboard, patch loop, full evaluation | ⬜ |

---

# Phase A — Foundations and the end-to-end seam

Goal: a real PR on a real repository receives a real comment, with the pipeline plumbed but no
analysis. Proves every integration boundary before any research work depends on it.

## Chapter 1 — Theory, tech stack, and decisions ✅

Why calibrated confidence over binary alerts. The four-agent independence argument. The stack and
its rejected alternatives.

**Delivered.** Documentation spine: `CLAUDE.md`, `DECISIONS.md` (D-001…D-018), `AUDIT.md`, this
file, `DEFECTS.md`; `PROJECT_CONTEXT.md` moved into the repo.

**Workspace restructure**, branch `refactor/monorepo-layout`. A **pure move** — no
analysis code changed (D-018). 124 renames via `git mv`, so per-file history and contributor
authorship survive. Four packages → `packages/{agent_static, agent_semantic, agent_context, engine}`;
one canonical contract → `packages/contracts/`; stubs for `packages/{corpus, agent_runtime}` and
`apps/{api, worker, dashboard}`; root `pyproject.toml` carrying the uv workspace plus ruff, mypy and
**import-linter** contracts enforcing the agent boundary.

Deleted: three redundant vendored `contracts.py` (verified byte-identical first), four
`test_contract_integrity.py` (false assurance — `AUDIT.md` 4.8), and root `main.py` /
`github_service.py` / `requirements.txt`.

⚠️ **The tree does not run.** Agent imports still reference the deleted vendored copies. Chapter 2
rewires them as part of the contract rewrite — repointing them at today's known-wrong contract would
only entrench it.

Also delivered: `README.md` rewritten (was `ReadME.md`, describing a placeholder webhook and a
"Judge Agent" not in the design), `.env.example` refreshed, `docker-compose.yml` for Postgres+pgvector
and Redis, Python pinned to 3.12, `.gitignore` rewritten (`uv.lock` deliberately committed —
calibration must be reproducible).

## Chapter 2 — Contracts frozen + workspace green ⬜

**The gate on everything.** Nothing else can start: the DB schema stores `Evidence`, the API
serialises it, the dashboard renders it.

Rewrite `packages/contracts` per `AUDIT.md` Tier 1:

- `finding_key = sha256(f"{file}::{qualified_symbol}::{cwe}")[:16]` — **no sink expression** (D-004)
- Three evidence kinds: `DETECTION` / `SILENCE` / `ABSTENTION` (D-005)
- `covered_cwes` on SILENCE (D-006)
- `IN_SCOPE_CWES` closed set: 22, 78, 79, 89, 94, 502, 639, 798, 862, 918
- `ChangeUnit`: `pre_src` nullable, plus `decorators`, `enclosing_class` (D-013)
- `pr_context` separate, never inside `ChangeUnit` (D-014)
- `analyze(unit) -> list[Evidence]` — **remove `anchors`** (D-008)

Rewire every agent import to `codesheriff_contracts`. Get `uv sync`, `pytest`, `ruff`, `mypy` and
`lint-imports` green.

**Done when:** `uv run lint-imports` passes, a deliberate agent→agent import fails CI, and the twin
fixtures load against the new contract.

## Chapter 3 — Database: SQLAlchemy + Alembic + pgvector ⬜

Schema for repositories, audits, change_units, evidence, findings. pgvector extension enabled.

**Scope caution.** §6 puts *multi-tenancy with billing* out of scope. Keep `users` minimal — GitHub
identity and installation mapping only. No roles, orgs, plans, or seats.

**Never persist full file contents** (§6): findings, evidence and hashes only. Source stays in memory
and ephemeral storage.

**Done when:** migrations apply to a clean DB and roll back cleanly; a 384-dim vector column
round-trips.

## Chapter 4 — Next.js + shadcn scaffold ⬜

Frontend scaffold, Tailwind, shadcn components, layout shell, navigation, route structure, protected
layout.

Rendering layer only — no business logic, no DB access, no detection logic in TypeScript (§6).

**Done when:** the shell builds and renders against mock data with no backend dependency.

## Chapter 5 — GitHub OAuth, App installation, repository listing ⬜

OAuth flow, session handling, App installation, per-repo permission derivation. Repo listing with
infinite scrolling, connect/disconnect, connection status.

Resolves §7 open question 1 — decide and record in `DECISIONS.md`: which permissions and events to
request, behaviour on force-push, one summary comment vs inline review comments, and how to update
rather than duplicate on subsequent pushes.

**Done when:** the App installs against a real account and connected repos persist across sessions.

## Chapter 6 — Webhook, HMAC, Celery — **the v0.1 seam** ⬜

**Replaces** `packages/engine/src/codesheriff_engine/github/webhook.py`.
**Closes** `AUDIT.md` 0.1 (unauthenticated endpoint), 4.3 (inline processing).

Webhook registration. Verify `X-Hub-Signature-256` **before parsing the payload**. Enqueue, return
202. Celery + Redis worker owns the pipeline. Hardcoded `Evidence` posted to a real PR — no analysis
yet.

**Done when:** a forged signature is rejected 401 with no outbound call; a valid one returns 202 in
under 3s with the job still pending; a real PR receives the comment from the worker.

---

# Phase B — The research core

Goal: four heterogeneous agents producing evidence that fuses into a calibrated posterior. This is
the contribution — protect this phase from schedule pressure.

## Chapter 7 — Corpus and committed splits ⬜

**Gates every numeric claim the project makes.** Fitting likelihood ratios, the prior, or the
threshold without this means asserting them — precisely the failure the paper criticises.

~60 hand-written cases + ~15 cross-PR scenarios. Splits committed once and **immutable**. Twins stay
in the same split or information leaks. Labels carry `detectable_by`. Authz cases (CWE-862/639)
deliberately have no static path — they exist to prove heterogeneity.

> The corpus is not a training set for detecting vulnerabilities. It answers a different question:
> how much each agent should be trusted when it speaks. The learning is about the witnesses, not the
> crime.

**Done when:** every in-scope CWE has ≥1 vulnerable case and ≥1 safe twin, and a test fails if a twin
pair is split across splits.

## Chapter 8 — ChangeUnit extraction ⬜

**Replaces** `packages/engine/src/codesheriff_engine/github/parser.py`.
**Closes** `AUDIT.md` 4.1, 4.2.

tree-sitter over **fetched file blobs** — one unit per changed function. Not diff-fragment
reconstruction: the current parser concatenates hunk fragments into syntactically broken source with
wrong line numbers, and no structural analysis can be correct on that input.

**Done when:** units carry a qualified symbol and valid `post_src` with correct absolute line
numbers; large-diff files (no `patch` from GitHub) are fetched rather than silently skipped.

## Chapter 9 — Static agent I: Semgrep backend + fusion skeleton (v0.3) ⬜

**Replaces** `packages/engine/src/codesheriff_engine/fusion/`.
**Closes** `AUDIT.md` 1.4, 2.2, 2.3, 2.4, 2.6, 2.7.

Semgrep `--sarif` backend — the existing runner is sound, port it. Fusion with **hand-set** ratios,
explicitly marked provisional until Chapter 14:

- Iterate **all** agents, not only those that emitted (D-007)
- SILENCE → LR < 1.0 gated by `covered_cwes`; ABSTENTION → exactly 1.0
- `structural.taint` + `structural.semgrep` → **one** contribution (D-011)
- Clamp the **LRs**, not the posterior
- **Delete** `_heuristic_debate_resolution` outright (D-009)
- Remove the `except Exception: pass` that silently drops evidence

**Done when:** the fusion identity test passes — static and semantic evidence for the same bug land
under one `finding_key` and produce **one** posterior, not two singletons.

## Chapter 10 — Static agent II: the taint engine ⬜

**Replaces** `packages/agent_static/src/static_agent/taint/engine.py`.
**Closes** `AUDIT.md` 3.1–3.6.

Build the def-use graph **and consume it**. On a correct graph the engine is ~150 lines; without one
it becomes 600 lines of special cases.

Worklist propagation and real path finding — not `sink_line >= source_line`. Sinks declare `class:`
(`injection`, `command`, `xss`, `path`, `deserialization`, `code`); sanitizers clear a **list** of
classes, and `clears` is actually read. Parameterised SQL as a **sink property**
(`safe_when: params_passed_separately`), never a sanitizer. Type-coercion sanitizers — `int()`,
`float()`, `uuid.UUID()`, allowlist membership. Rules match **call-expression AST node text**, not raw
source. Test-file findings downweighted, not suppressed.

Ten precise sinks beat sixty sloppy ones. Every sink ships with a vulnerable fixture **and** a safe
twin.

**Done when:** `# TODO: replace os.system with subprocess` yields nothing; a wrong-class sanitizer
does not suppress a sink; every sink has both fixtures.

## Chapter 11 — Semantic agent ⬜

**Closes** `AUDIT.md` 0.3, 0.4, 3.9, 3.10, 3.11, 3.12.

Three-stage prompt: functional intent → trust boundaries → violated safety invariant. **Wire the
exemplars** — they exist on disk and nothing loads them. Complete the hallucination gate: add the
`IN_SCOPE_CWES` check, make the file check exact rather than basename, remove the `+5` line slack.
`unit_too_large` abstention — never truncate. Escape the `<code_to_analyze>` delimiter so untrusted
code cannot close the data region. Screen rationales so injected strings are not echoed. **Abstain,
never stub,** when unconfigured. Keep n=3 with varying seeds.

**Done when:** injection subversion ≤ 10%; safe-twin pass rate ≥ 85%; zero hallucinated sinks reach
output; zero live API calls in the suite.

## Chapter 12 — Context agent ⬜

**Replaces** `packages/agent_context/src/context_agent/reasoning/analyzer.py`.
**Closes** `AUDIT.md` 0.2, 3.7, 3.8.

**Per-symbol** embeddings into pgvector — not per-PR: `bge-small-en-v1.5` truncates at 512 tokens, so
PR-level documents are silently cut and match poorly against function-level queries. Repository filter
with `repo` in metadata. Real retrieval-driven cross-PR regression reasoning. Emit under the
**incoming** `finding_key` — it corroborates, it does not solo (D-012). Embedding failure must be
loud, never a silent MD5 fallback.

**Done when:** a cross-PR bypass fixture produces evidence *through `ContextAgent.analyze()`*, and
cross-repository retrieval is impossible.

## Chapter 13 — Runtime agent ⬜

Wasmtime + WASI. **Isolation infrastructure first, detection agent second** — the sandbox earns its
place because running untrusted PR code is how CI systems get compromised; evidence is a secondary
benefit.

Deny-by-default: no network, ephemeral read-only filesystem, CPU/memory/wall-clock caps, never on a
host holding DB credentials. Abstains widely (`no_safe_entrypoint`, `dependency_unavailable`) —
expected, not a defect.

**Done when:** a network-attempting fixture is observed and denied, and the sandbox holds no
credentials.

## Chapter 14 — Bayesian fusion and empirical calibration ⬜

**The thesis. Everything before this is setup.**
**Closes** `AUDIT.md` 2.1.

Fit likelihood ratios on the **calibration split** with Laplace smoothing and clamps. Measure the
prior, then rescale from the balanced corpus (~50%) to the real base rate (~2–5%) — and **record the
rescaling**. Select the threshold from a precision-recall sweep on the **validation split**. Emit
`calibration.json` recording the corpus commit hash.

Research integrity (§6, non-negotiable): weights fitted only on calibration, threshold only on
validation, **test split untouched until Chapter 18**.

**Done when:** `calibration.json` is reproducible from its recorded corpus hash, and no hardcoded LR,
prior, or threshold remains anywhere in the codebase.

---

# Phase C — Surface and evaluation

## Chapter 15 — Dashboard API, dashboard UI, settings ⬜

FastAPI REST endpoints, audit and finding queries, dashboard data contracts. Stats, recent audits,
verdict summaries, charts. Per-repo config: alert threshold, enabled agents, CWE scope.

**Confidence must read as calibrated.** A bare "87%" repeats the failure this project attacks —
surface the reliability the number rests on.

## Chapter 16 — Findings page ⬜

Finding detail, per-agent evidence breakdown, posterior display, taint path rendering.

Show **abstentions and silences**, not only detections. That an agent could not look is part of why
the posterior is what it is; hiding it makes the number unexplainable.

## Chapter 17 — Patch generation and verification ⬜

Draft → verify → retry. Syntax check, regression check, test-suite run where available. Posted as a
GitHub suggestion. **Suggestions only — never commit or merge** (§2).

Resolves §7 open question 3 — record in `DECISIONS.md` what "verified" means when a repository has no
test suite.

## Chapter 18 — Evaluation and ablations ⬜

**The research payload.** Held-out test run — **evaluated exactly once**.

ECE, Brier score, reliability diagram. Fusion vs. majority voting. Anchored vs. blind execution as a
labelled ablation. Baselines against Semgrep, Bandit, and a single-LLM reviewer.

**Done when:** calibration metrics are reported as acceptance criteria, and every claim in the
abstract is backed by a number in this chapter.

---

## Deferred, not scheduled

- **v0.9 learned scorer** — logistic regression over path length, sink danger, sanitizer presence,
  source type, test-file flag and unknown-call count, replacing the hand-tuned formula. Trains on
  hundreds not thousands of examples and outputs a natively calibrated probability (Platt scaling
  *is* logistic regression on scores). Slots after Chapter 14 if time allows.
- **Fine-tuned semantic model** — §7 open question 8; not confirmed as committed.
- **JS/TS support** — §7 open question 7; Python-first until explicitly decided.

---

## Salvage list — port these, rewrite the rest

| Asset | Why it survives |
|---|---|
| `semgrep/runner.py` | Real `--sarif` subprocess call; the one working detection backend |
| `taint/parse.py` | Correct tree-sitter usage; replace the silent `_fallback_parse` with an abstention |
| `prompts/system_v1.md`, `user_v1.jinja`, `exemplars/*` | Content is sound; only the wiring is missing |
| `llm/{base,hosted,stub,cache,budget}.py` | Genuinely provider-agnostic protocol, testable |
| `github/reporter.py` | Formatting logic; add pipe-escaping and rationale screening |
| `rules/*.yml` | Starting vocabulary; every sink needs a `class:` and a safe twin |
| Test scaffolding | Structure is fine; assertions must stop bypassing `analyze()` |

---

## Proposed defaults — revisit with real data, do not treat as settled

Corpus size (~60 cases + ~15 cross-PR scenarios) · the 0.70 alert threshold · per-agent likelihood
ratio values · LR clamp bounds · cosine similarity floor · top-K retrieval depth · per-agent
oversized-unit thresholds.

---

## Open questions (PROJECT_CONTEXT.md §7)

Several are better answered by observing the real API than by deciding now. Each is attached to the
chapter that should resolve it.

| # | Question | Resolved in |
|---|---|---|
| 1 | GitHub App permissions and events; force-push behaviour; summary vs inline comments; update vs duplicate | Ch 5 |
| 2 | Dashboard scope beyond the agreed minimum | Ch 15 |
| 3 | Patch mechanics; what "verified" means with no test suite; retry count; suggestion block format | Ch 17 |
| 4 | Local development — smee.io vs ngrok; Docker Compose layout | Ch 6 |
| 5 | Demo repository — needs real merged PRs for the context agent plus craftable PRs for detection | Ch 7 / Ch 12 |
| 6 | Abstract wording — "confidential execution" implies a hardware TEE; soften to "isolated execution layer" or define as SFI | Ch 13 / Ch 18 |
| 7 | JS/TS support — unscheduled | deferred |
| 8 | Fine-tuned semantic model — not confirmed | deferred |

---

## Per-session checklist

1. Read `CLAUDE.md`, then this file; take the first non-✅ chapter
2. Read the `AUDIT.md` entries that chapter closes — know what you are replacing and why
3. If the chapter replaces existing code, **delete it first**; do not patch
4. Write tests for the "Done when" criteria before the implementation
5. Update this file's status; append to `DECISIONS.md` if a decision was made; log any FP/FN in
   `DEFECTS.md` as it is found
6. If anything conflicts with `PROJECT_CONTEXT.md` §5 — **stop and raise it** (§8 conflict rule)

---

## What changed from the original 17-chapter outline, and why

| Change | Reason |
|---|---|
| Contracts moved 11 → **2** | The DB schema, the API and the dashboard all serialise `Evidence`. Designing them against a contract that is later rewritten guarantees rework — and the current contract is known wrong on six counts (`AUDIT.md` Tier 1). |
| Dashboard/findings UI moved 6, 7, 15 → **15, 16** | These render findings. Findings do not exist until Chapter 14. The original Chapter 6 defined "dashboard data contracts" five chapters before contracts were frozen. |
| Corpus moved 11 → **7**, own chapter | It gates every calibrated number. Bundled with contracts it would have been rushed. |
| Static agent split 12 → **9 + 10** | Diff extraction, a Semgrep backend and a full taint engine is three sessions of work, not one. |
| Agents split 13 → **11, 12, 13** | Semantic, context and runtime are one chapter each. The runtime sandbox alone is a chapter. |
| Scaffold + auth kept early (**4, 5**) | Genuine prerequisites — without repo connection no PR ever arrives. Only the *result-rendering* UI moved late. |
| 17 → 18 chapters | Net of the splits and merges above. |

The ordering principle: **build what is needed to receive a pull request early; defer what renders
results until results exist.**
