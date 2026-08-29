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

Roughly: **v0.1 partially built, v0.2 contract frozen, v0.3–v0.5 built as facades.**

Four packages exist with a passing test suite and a webhook that reaches GitHub. But the conformance
audit found three of four analysis components non-functional, the fusion engine implementing the
pre-reversal form of nearly every finalized decision, and the webhook unauthenticated. Nothing
numeric is calibrated, because no corpus exists.

The test suite reports 100% and cannot detect any of this.

As of Chapter 2 the workspace installs, runs and passes its gates, and the contract every other
component serialises is frozen at v2.0.0. As of Chapter 6 the seam around the analysis is real: a
signature-verified delivery becomes a queued audit becomes one comment posted by a worker, and the
unauthenticated endpoint is deleted rather than patched. As of Chapter 7 there is ground truth to
measure against, and as of Chapter 8 the pipeline hands over the right objects: one `ChangeUnit`
per changed function, cut from the real file at real line numbers.

As of Chapter 9 the seam is **closed**: every extracted unit reaches four blind agents, what each
one says is persisted against the function it is about, and fusion turns it into a posterior that
can go down as well as up. The pipeline is end to end for the first time.

**Two of the four analysis components now do the work their names claim.** As of Chapter 10 the
structural witness runs worklist taint propagation over a def-use graph it actually consumes, and is
measured against ground truth: 13/13 on the cases the corpus predicts for it, 0 false positives
across 18 safe twins, on the calibration split. As of Chapter 11 the semantic witness reads its
exemplars, bounds the untrusted region with a sentinel the code author cannot forge, and is measured
the same way — 0% injection subversion, a 94% safe-twin pass rate, and zero hallucinated sinks
reaching output, from model responses recorded once and committed.

The two are also **heterogeneous in the way the thesis needs**, and the two measurements are the
first evidence for it rather than an argument about it. Their errors do not coincide. The semantic
agent's single false positive is `format_html`, whose escaping guarantee lives in a library it
cannot see, and the taint engine — which knows that callee by rule — is correctly quiet on the same
case. Its miss is a hardcoded credential, which it fails on for a structural reason: the three-stage
prompt asks what untrusted input reaches a dangerous sink, and a literal password is neither. Agents
that failed the same way would add nothing to a probability estimate.

The other two remain the shells the audit described — the context agent's reasoning is still four
substring tests, and the runtime agent still does not exist. Each has a chapter, and both are in
Phase B. What Chapter 9 changed is the frame around them: an agent that is not built abstains under
its own name, at a likelihood ratio of exactly 1.0, on the record, per unit — so a missing witness
costs the posterior nothing and hides from nobody.

The shells are also **measurable** now. Chapter 7 supplied the labels, Chapter 8 supplies units of
the same shape the corpus holds, and Chapter 9 supplies the arithmetic that turns their statements
into a number. "This agent found nothing" is a result rather than an absence of one — and it is a
result with a price, since a silence carries a likelihood ratio below 1.0.

| Version | Goal | Status |
|---|---|---|
| v0.1 | webhook → diff parsed → comment posted | ✅ **complete** (Ch 6, Ch 8) — HMAC verified before parsing, enqueued, worker posts. Extraction is one unit per changed function, from fetched blobs |
| v0.2 | contracts frozen + corpus with committed splits | ⚠️ contracts frozen at v2.0.0 (Ch 2); corpus 60 units / 30 pairs with committed splits (Ch 7); **cross-PR scenarios pending Ch 12** |
| v0.3 | Semgrep backend + fusion engine | ✅ **complete** (Ch 9) — all 7 fusion defects closed; four witnesses, one factor each. Ratios still asserted until Ch 14 |
| v0.4 | taint engine | ✅ **complete** (Ch 10) — worklist propagation over a real def-use graph; 13/13 recall and 0/18 false positives on the calibration split |
| v0.5 | semantic agent | ✅ **complete** (Ch 11) — exemplars wired, gate complete, sentinel-bounded prompt; 0% injection subversion and 94% safe-twin pass on the calibration split |
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

## Chapter 2 — Contracts frozen + workspace green ✅

**The gate on everything.** Nothing else can start: the DB schema stores `Evidence`, the API
serialises it, the dashboard renders it.

**Delivered.** Contract v2.0.0 (`packages/contracts`), D-019 through D-024:

- `finding_key(file, qualified_symbol, cwe)` — **no sink expression** (D-004)
- Three evidence kinds: `DETECTION` / `SILENCE` / `ABSTENTION` (D-005)
- `covered_cwes` on SILENCE, rejected if empty (D-006, D-020)
- `IN_SCOPE_CWES` closed set: 22, 78, 79, 89, 94, 502, 639, 798, 862, 918
- `ChangeUnit`: `pre_src` nullable, plus `decorators`, `enclosing_class` (D-013)
- `PRContext` separate, never inside `ChangeUnit` (D-014)
- `analyze(unit) -> list[Evidence]` — `anchors` removed from all three agents, the orchestrator and
  the context CLI; the orchestrator now fans out in one `asyncio.gather` (D-008, D-022)

Beyond the plan, each forced by the above and recorded in `DECISIONS.md`:

- **Non-detections carry no `finding_key`**, enforced by a validator. Closes both raw-string
  bypasses (`abstain:{unit_id}:{reason}` and `abstention:all_agents`) in one move (D-019).
- **`ChangeUnit.key_for(cwe)` is the only sanctioned way to build a key.** Removing the sink
  expression closes one route to divergent keys; leaving each agent to assemble the symbol name
  would open another (D-019).
- **Both static backends deduplicate per key** — with the sink expression gone, several source-sink
  pairs in one function collapse onto one key, and emitting each would apply one agent's likelihood
  ratio several times to a single finding (D-019).
- **Out-of-scope CWEs are dropped, not relabelled.** Semgrep's `CWE-200` default is gone (D-021).
- **Agents emit SILENCE where they returned `[]`**, so evidence can lower a posterior at all.

**Closes** `AUDIT.md` 1.1, 1.2, 1.3, 1.5, and 3.10 early (see D-021 — the hallucination gate is where
`IN_SCOPE_CWES` is enforced for the LLM path, and the other two weakened checks sat on adjacent
lines). `AUDIT.md` 1.4 stays open by design: iterating all agents needs fitted ratios for SILENCE,
so it lands with Chapter 9 and Chapter 14. The marker is in `fusion/bayes.py`.

**Two defects found by running the toolchain for the first time** (D-020, D-023). The static agent's
`rules_dir` was CWD-relative *and* the rules sat outside the package, so the installed agent could
never have loaded them — from the workspace root the catalog loaded empty and the taint engine
reported silence on every unit. And three package distributions were named such that `uv sync` could
not resolve the workspace at all. Chapter 1 wrote the workspace config but never ran it.

**Verified.** 69 tests pass · `ruff check` and `ruff format --check` clean · `mypy --strict` clean
across 57 source files · `lint-imports` 3 contracts kept · a deliberate `static_agent ->
semantic_agent` import was added and correctly failed `lint-imports`, then removed.

## Chapter 3 — Database: SQLAlchemy + Alembic + pgvector ✅

Schema for repositories, audits, change_units, evidence, findings. pgvector extension enabled.

**Scope caution.** §6 puts *multi-tenancy with billing* out of scope. Keep `users` minimal — GitHub
identity and installation mapping only. No roles, orgs, plans, or seats.

**Never persist full file contents** (§6): findings, evidence and hashes only. Source stays in memory
and ephemeral storage.

**Done when:** migrations apply to a clean DB and roll back cleanly; a 384-dim vector column
round-trips.

**Delivered.** `packages/storage` (`codesheriff_storage`), D-025 through D-029:

- Nine tables: `installations`, `repositories`, `calibration_runs`, `audits`, `change_units`,
  `evidence`, `findings`, `pr_precedents`, `precedent_chunks`. One Alembic chain, extension created
  by the migration rather than left to the docker init script.
- **Persistence is its own package and the engine cannot reach it** — `lint-imports` now forbids
  `codesheriff_engine` and `codesheriff_contracts` from importing `sqlalchemy`, `alembic`, `psycopg`
  or `codesheriff_storage`, so §6 reproducibility is CI-enforced rather than honoured (D-025).
- **Contract invariants restated as CHECK constraints** — the three evidence kinds, the closed CWE
  set, and `finding_key ~ '^[0-9a-f]{16}$'` (D-026). That last one is also what stops
  `fuse_all_evidence`'s `abstention:all_agents` marker being stored as a finding; `mapping.py` drops
  it first, with a warning, and Chapter 9 removes it at source.
- **No source column anywhere**, asserted against the metadata rather than by review. Excerpts are
  capped in one module and permitted only in `evidence.artifacts` and `precedent_chunks.content`
  (D-027).
- `calibration_runs.is_provisional`, and `prior_probability` / `alert_threshold` stored per finding,
  so a threshold selected later cannot retroactively rewrite which past findings were alerts (§6).
- Vector retrieval (`precedents.py`) is scoped to one repository and returned behind a plain
  dataclass, ready for Chapter 12 to inject into `context.rag` — which still may not import a
  database client.

**Verified.** 123 tests pass against `pgvector/pgvector:pg16` (106 pass and 17 skip without a
database) · `ruff` and `ruff format --check` clean across 105 files · `mypy --strict` clean across 66
source files · `lint-imports` 4 contracts kept, with a deliberate `codesheriff_engine -> sqlalchemy`
import added, correctly broken, and removed. Both "Done when" criteria hold: `upgrade head` →
`downgrade base` → `upgrade head` on a clean database, and a 384-dim vector round-trips with correct
nearest-neighbour ordering.

**Two defects found by running against a real database** — both invisible to the non-db tests:

- The HNSW index was created by raw SQL in the migration and not declared on the model, so Alembic's
  comparison read it as drift and wanted to drop it. It is now declared in both places. This is
  exactly what `test_no_pending_schema_changes` exists to catch, on its first run.
- `search_precedents` defaulted `min_similarity` to `0.0`, silently discarding negatively-similar
  neighbours — so a query could return fewer rows than `limit` and read as "this repository has no
  precedent", which is a different claim. The floor is now opt-in; choosing it is Chapter 12's
  judgement and eventually a fitted number.

```bash
docker compose up -d postgres
docker exec codesheriff-postgres psql -U codesheriff -d codesheriff -c "CREATE DATABASE codesheriff_test"
export CODESHERIFF_TEST_DB=postgresql+psycopg://codesheriff:codesheriff@localhost:5432/codesheriff_test
uv run pytest packages/storage -m db
```

## Chapter 4 — Next.js + shadcn scaffold ✅

Frontend scaffold, Tailwind, shadcn components, layout shell, navigation, route structure, protected
layout.

Rendering layer only — no business logic, no DB access, no detection logic in TypeScript (§6).

**Done when:** the shell builds and renders against mock data with no backend dependency.

**Delivered.** `apps/dashboard` — Next.js 16.3.3 (App Router), React 19, TypeScript, Tailwind v4,
shadcn/ui. D-031 through D-033:

- Seven routes: `/` → `/repositories`, `/audits`, `/audits/[id]`, `/findings/[key]`, `/settings`,
  plus `_not-found`. All render from `src/lib/mock-data.ts`; nothing fetches.
- `src/lib/types.ts` mirrors contract v2.0.0 — the three evidence kinds, `covered_cwes`,
  `IN_SCOPE_CWES`. It is **not** the dashboard API contract; that is Chapter 15's to define, and
  defining it early is the mistake the original outline made.
- **`<Posterior>` is the only way a probability reaches the screen** (D-032). While no fitted
  calibration artifact exists it marks the number "provisional — not calibrated", so the UI cannot
  grow a bare "87%" before Chapter 14 gives it one.
- **Silences and abstentions render alongside detections** on the finding page, each with the
  reason it means what it means.
- `(protected)` is route structure, not a security boundary: `getPlaceholderSession()` cannot fail
  and says so in its name, its types and a banner in the header (D-033). Chapter 5 replaces it.
- Two new gates: `npm run lint` and `npm run build` in `apps/dashboard`.

**Verified.** `npm run lint` clean · `npm run build` compiles and type-checks 7 routes · every route
returns 200 against `next start` and an unknown finding key returns 404 · the rendered finding page
contains detections, silences, abstentions and the provisional marker.

**Note on the framework.** Next 16 postdates the model's training data and `create-next-app` writes
an `AGENTS.md` saying so. Conventions that differ: typed `PageProps<'/route'>` and `LayoutProps`,
`params` awaited, and shadcn/ui now built on **Base UI** (`render={<X/>}`) rather than Radix
(`asChild`) — which is what the first build failed on. The bundled docs in
`apps/dashboard/node_modules/next/dist/docs/` are authoritative; read them before writing
components.

## Chapter 5 — GitHub OAuth, App installation, repository listing 🔨

OAuth flow, session handling, App installation, per-repo permission derivation. Repo listing with
infinite scrolling, connect/disconnect, connection status.

Resolves §7 open question 1 — decide and record in `DECISIONS.md`: which permissions and events to
request, behaviour on force-push, one summary comment vs inline review comments, and how to update
rather than duplicate on subsequent pushes.

**Done when:** the App installs against a real account and connected repos persist across sessions.

**Delivered.** The first vertical slice: dashboard → FastAPI → GitHub and Postgres. D-034 through
D-037.

- **§7 open question 1 is closed (D-034).** Metadata: read, Contents: read, Pull requests: read and
  write — nothing else, and no Contents: write, because §6 puts auto-commit out of scope. Events:
  `pull_request`, `installation`, `installation_repositories`, not `push`. Each head SHA is a new
  audit; a superseded run is abandoned. **One summary comment, edited in place** via
  `audits.github_comment_id`, rather than inline review comments — calibration has to be legible in
  one place, and inline anchors go stale on the force-push that this project's users make most.
- **Authorisation is derived from GitHub, never stored (D-035).** `GET /user/installations` at
  sign-in; the ids live on the session row and scope every query. No permissions table. An empty
  list returns nothing rather than everything, tested at both layers.
- **No GitHub credential and no session token reach the database (D-036).** The OAuth token is spent
  on two reads and dropped — the gateway interface has no method that returns one. `sessions` holds
  a SHA-256 of the cookie, so logout can revoke server-side and a stolen copy stops working.
- **The install callback grants nothing (D-037).** `?installation_id=` is user-controlled, so it is
  logged and ignored; the handler redirects into OAuth, which re-derives the list from GitHub.
- Storage gains `users` and `sessions` (migration `0002`), `identity.py` for every sign-in query,
  and `testing.py` so `apps/api` shares the migrate-and-roll-back fixtures instead of copying them.
- Dashboard gains `/sign-in`, a real session-backed shell, and a repository list with keyset
  infinite scroll and an analysis toggle. Chapter 4's placeholder session is deleted.

**Verified.** 167 Python tests pass against Postgres · `ruff`, `ruff format`, `mypy --strict` clean
across 74 source files · `lint-imports` 4 contracts kept · dashboard `lint` and `build` clean across
8 routes · both services run together: unknown cookie → 401, no credentials → 501 naming the missing
variable, CORS allows `localhost:3000` and refuses `evil.example`.

Tests never touch the network: an autouse fixture fails any non-loopback socket, GitHub is
substituted at the `GitHubGateway` interface, and `test_github_gateway.py` drives the **real**
`githubkit` client against an httpx `MockTransport` — which is what pins the `redirect_uri` and the
pagination behaviour that a fake would have let slide.

⚠️ **Not ✅ until the App is registered.** The acceptance criterion is "the App installs against a
real account and connected repos persist across sessions", and registering a GitHub App is an
account-owner action nobody else can do. Everything up to that point is verified.
`docs/github-app-setup.md` is the twenty-minute checklist: create the App with the D-034 permissions,
fill five values into `.env`, install it, sign in, and confirm the repository list survives a sign-out
and back in.

## Chapter 6 — Webhook, HMAC, Celery — **the v0.1 seam** ✅

**Replaced** `packages/engine/src/codesheriff_engine/github/webhook.py`.
**Closes** `AUDIT.md` 0.1 (unauthenticated endpoint) and 4.3 (inline processing).

Webhook registration. Verify `X-Hub-Signature-256` **before parsing the payload**. Enqueue, return
202. Celery + Redis worker owns the pipeline. Hardcoded `Evidence` posted to a real PR — no analysis
yet.

**Done when:** a forged signature is rejected 401 with no outbound call; a valid one returns 202 in
under 3s with the job still pending; a real PR receives the comment from the worker.

**Delivered.** The v0.1 seam, end to end: a signed delivery becomes a queued audit becomes one
comment posted by the worker. D-038 through D-043.

- **The signature is checked against the raw body before anything else** — before `json.loads`,
  before a row is read or written, before the broker is touched. `hmac.compare_digest`, never `==`.
  A missing `GITHUB_WEBHOOK_SECRET` answers **501 and accepts nothing**; it never degrades to
  accepting unsigned payloads. The ordering is pinned by a test: malformed JSON under a *bad*
  signature must return 401, not 400, because a 400 would prove the parser saw attacker bytes first.
- **The edge writes one row and publishes one id.** `celery.send_task("codesheriff.run_audit")` by
  name — `import-linter` forbids `apps/api` from importing `apps/worker`, which is what keeps the
  agents, the LLM client and tree-sitter out of the process that must answer in 3s (D-040). The
  message carries an audit id and nothing else (D-041); Redis holds no PR payload, and `json` is
  the only accepted serialiser.
- **Redelivery is designed for, not tolerated.** `audits.delivery_id` is UNIQUE (migration 0003), so
  GitHub's at-least-once delivery cannot open a second run — the handler answers `202 duplicate`
  (D-038). The broker being unreachable is a 503 *after* the row is committed, so the retry finds
  the existing audit rather than duplicating it.
- **`superseded` is a status of its own** (D-039). D-034 said a superseded audit is abandoned; this
  says the row must not call that a failure. Pushing again is the most ordinary thing a developer
  does, and four red audits per five-commit branch would make the real error rate unreadable. The
  worker re-checks immediately before writing to GitHub, because the window between claiming and
  posting is the whole pipeline.
- **All three subscribed events now do something.** `installation` writes suspensions and removes
  uninstalled accounts; `installation_repositories` syncs the set. A `pull_request` payload may
  only `ensure_*` — insert-if-absent — because it carries no `suspended_at`, so an upsert would
  clear a suspension on every push, and `analysis_enabled` is never rewritten from a webhook.
- **A verified delivery for an unknown repository is recorded and analysed.** That is not the
  D-037 case: `?installation_id=` in a URL is chosen by whoever clicks the link, a body carrying a
  valid HMAC is GitHub speaking. No session gains visibility of anything — that still comes only
  from `GET /user/installations` at sign-in (D-035).
- **The comment says nothing it cannot support.** Five abstentions, one per backend, built through
  `Evidence.abstention()` — the honest report of four agents that do not exist. **No probability
  appears**, because nothing is calibrated (D-032), and the comment says why. Nothing from the pull
  request is echoed: no title, no branch, no description, no source. The evidence is deliberately
  not persisted — `evidence` rows hang off a `change_units` row, and inventing one would put a
  function nobody analysed into the table that records what was analysed.
- Storage gains `audits.py` (the lifecycle: open, claim, supersede, finish, fail) and migration
  0003. Every state change is one conditional UPDATE, so a task delivered twice cannot run twice.
- **Deleted, not patched:** `engine/github/webhook.py`; `engine/main.py`, a *second* FastAPI app
  that mounted the unauthenticated webhook; the `serve` CLI command that booted it;
  `reporter.post_pr_review_comment`, which used a personal access token over blocking `requests`
  and **skipped silently** when the token was absent. `EngineConfig` loses `github_token`,
  `github_webhook_secret`, `github_api_base`, `host` and `port` — `github_webhook_secret` was the
  one `AUDIT.md` 0.1 named, defined there and read nowhere. The engine no longer depends on
  `fastapi`, `uvicorn` or `requests`.

**Verified.** 254 Python tests pass against Postgres (140 pass and 114 skip without a database) ·
`ruff check` and `ruff format --check` clean across 134 files · `mypy --strict` clean across 81
source files · `lint-imports` 4 contracts kept. The webhook returns 202 well inside the 3s budget,
asserted in a test. Migration 0003 applies to a clean database and rolls back, including the data
migration that folds `superseded` rows into `failed` — exercised with a real row, because every
other migration test runs against an empty `audits` and cannot catch a data migration at all.

**Two things worth knowing about the migration.** Postgres refuses `ALTER TYPE ... ADD VALUE` inside
the transaction that adds it, so the enum is replaced rather than extended; and the CHECK constraint
from 0001 has to come off first, because Postgres stores it with the literal already bound to the
old type ("operator does not exist: audit_status_new <> audit_status").

⚠️ **Not fully proven until the App is registered.** The third acceptance criterion — "a real PR
receives the comment from the worker" — needs a GitHub App and a tunnel, which only the account
owner can set up. Everything up to that point is verified against a real database and a real
`githubkit` client driven through an httpx `MockTransport`. `docs/webhook-setup.md` is the
checklist; it shares the blocker with Chapter 5.

---

# Phase B — The research core

Goal: four heterogeneous agents producing evidence that fuses into a calibrated posterior. This is
the contribution — protect this phase from schedule pressure.

## Chapter 7 — Corpus and committed splits ⚠️

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

**Delivered.** `packages/corpus` (`codesheriff_corpus`), D-044 through D-047. Both "Done when"
criteria hold, asserted by tests over the whole corpus rather than a sample.

- **60 units in 30 twin pairs** — three pairs for each of the ten in-scope CWEs. Each pair is one
  function, one file, one symbol, once vulnerable and once safe. A case is a directory of
  `case.yaml` + `post.py` + optional `pre.py`, shipped inside the wheel and read through
  `importlib.resources`, so an installed corpus loads the same as a checkout (D-046).
- **Twins share a `finding_key` by construction** and a test proves it. Fusion groups by key; twins
  that keyed differently would make "the agent fired on the safe twin" and "the agent found the bug"
  statements about different findings, and precision uncomputable by lookup.
- **The twins are deliberately near.** The safe member of `cwe-089-order-sort` still builds its
  query with an f-string; the safe `cwe-798-warehouse-connect` still passes a string literal to
  `psycopg.connect`; the safe `cwe-918-link-preview` still calls `urlopen`. Each is there so a rule
  keyed on the shape rather than the flaw fires on both members and is measured for it.
- **Splits assigned by `pair_id`, 60/20/20** — 18/6/6 pairs, seed recorded, stratified by CWE. A
  twin cannot straddle a split because the pair is the unit of assignment; the test PLAN.md asks
  for exists anyway (D-045).
- **`corpus_hash` and `split_hash` now have a definition.** `calibration_runs` has held both columns
  since Chapter 3 with nothing to put in them, which made §6's reproducibility requirement a
  sentence rather than a check. Both are computed over the canonical loaded form and are independent
  of git, so they can be recomputed from a wheel.
- **A fifth import-linter contract**: no agent may import `codesheriff_corpus`. Separate from the
  layering contract because the reason differs in kind — an agent that can read `label` is being
  told the answer, and one that can read `detectable_by` can be excused by the field that exists to
  excuse it fairly (D-047).

**Closes** `AUDIT.md` 4.7. **Partially closes** 2.1: the corpus, the splits and the hashes now
exist, so the artifacts §6 requires are present. The ratios, prior and threshold are still the
hardcoded values in `engine/config.py` — fitting them is Chapter 14, and until then D-010 requires
they be presented as provisional.

**Verified.** 540 Python tests pass against Postgres (426 pass and 114 skip without one); 286 of
them are new · `ruff check`
and `ruff format --check` clean across 144 files · `mypy --strict` clean across 86 source files ·
`lint-imports` 5 contracts kept, with a deliberate `static_agent -> codesheriff_corpus` import added,
correctly broken, and removed.

⚠️ **Not ✅ — the ~15 cross-PR scenarios are not here.** A cross-PR scenario is a case plus a
precedent history, and the shape of a precedent document is Chapter 12's to design (§5 fixes only
that indexing is per-symbol, not per-PR). Authoring fifteen histories against a guessed schema now
would mean rewriting them later. They land with the context agent; `corpus_hash` changes when they
do, which is safe only because Chapter 12 precedes Chapter 14 and no calibration artifact exists
yet. **If those two chapters are ever reordered, the scenarios must be authored first.**

**One defect found by running the CLI twice** (D-045). `corpus_hash` differed on every invocation:
`detectable_by` is a `frozenset`, and Python randomises string hashing per process, so it serialised
in a different order each run. The contract had already solved this for `Evidence.covered_cwes`
(D-024) and the corpus reintroduced it. No in-process assertion can catch it —
`test_hashes_are_stable_across_processes` runs the hash in subprocesses under fixed and random
`PYTHONHASHSEED`, and yields five distinct hashes if the sort is removed.

**Two limitations recorded rather than engineered away** (D-045):

- Six pairs cannot cover ten CWEs. Every CWE has a calibration pair, asserted by a test, but the
  validation and test splits reach six of ten each, and under this seed CWE-89 falls entirely inside
  calibration. Final ECE and Brier are therefore **aggregate claims across CWEs, not per-CWE
  claims**, and the paper must report them as such. The seed was fixed before the draw was inspected
  and has not been rerolled.
- Immutability is **detectable, not prevented**. The obvious mechanism — a committed checksum
  verified by a test — is the one this repository already defeated (`AUDIT.md` 4.8, where the
  expected hash was rewritten to make the test pass). Instead `assign` refuses to move a settled
  pair, and `split_hash` on each calibration run makes a later edit show up as a run that no longer
  matches the splits it claims.

```bash
uv run codesheriff-corpus validate    # loads every case, prints both hashes
uv run codesheriff-corpus stats       # coverage by CWE, split and agent
uv run codesheriff-corpus show cwe-862-admin-export-vuln
```

## Chapter 8 — ChangeUnit extraction ✅

**Replaces** `packages/engine/src/codesheriff_engine/github/parser.py`.
**Closes** `AUDIT.md` 4.1, 4.2.

tree-sitter over **fetched file blobs** — one unit per changed function. Not diff-fragment
reconstruction: the current parser concatenates hunk fragments into syntactically broken source with
wrong line numbers, and no structural analysis can be correct on that input.

**Done when:** units carry a qualified symbol and valid `post_src` with correct absolute line
numbers; large-diff files (no `patch` from GitHub) are fetched rather than silently skipped.

**Delivered.** Both criteria hold, asserted by tests. D-048 through D-051.

- **`codesheriff_engine.extraction`** — pure, with no HTTP client, no GitHub client and no database
  session. `python.py` walks one whole file with tree-sitter; `diffing.py` derives `changed_lines`;
  `units.py` assembles `ChangeUnit`s. The split is what lets Chapter 14 run extraction over corpus
  cases with no credentials (D-051).
- **GitHub's `patch` is read nowhere, and `PullRequestFile` has no field for it** (D-048).
  `changed_lines` comes from `difflib` over the two fetched blobs. The large-diff skip at
  `parser.py:102` is gone *structurally* — there is no branch that can behave differently for a file
  with no patch. It is also the same derivation `CorpusCase.changed_lines` already used, so a corpus
  unit and a production unit are built the same way; every ratio fitted on the first and applied to
  the second depends on that.
- **The unit is the outermost function** — a top-level `def` or a method, never a nested closure,
  whose free variables are bound outside it. A change with no enclosing function produces one
  `<module>` unit carrying the whole file, because CWE-798 sits at module scope more often than not
  and that unit is the only way an agent ever sees one (D-049).
- **One unit per qualified name.** `@overload` stubs and conditional redefinitions name the same
  function twice; two units would apply one agent's likelihood ratio twice to a single
  `finding_key`, and would collide on `change_units`' UNIQUE (audit_id, unit_id). The last
  definition wins — the one Python binds.
- **A removed decorator survives the diff.** A deletion is anchored to the nearest line of *code*,
  including the `replace`-with-a-blank-line form, which is how a dropped `@login_required` usually
  appears. That deletion is the whole D-013 signal for CWE-862 and CWE-639.
- **Every file that yields no unit is recorded with a reason** — deleted, not Python, unreadable or
  over the fetch budget, unchanged in content. The old parser dropped each with a bare `continue`
  (D-050). The comment reports coverage as **counts and words, never paths**: a path is chosen by
  whoever opened the pull request, which is `AUDIT.md` 0.4's attacker-controlled text.
- **`MAX_BLOB_BYTES` skips a file whole, never part of one.** A cap on the *fetch* is a different
  thing from truncating a unit; oversized units are for the agent to abstain on.
- The worker gains `list_pull_request_files` and `get_file_at_ref` (raw media type, not the
  base64 JSON representation) and `pipeline.py`, which fetches both images of every changed file —
  one call for an added file, none for a deleted or non-Python one, and a rename's pre-image from
  its *old* path. Extracted units are written to `change_units` through `to_change_unit_row`, so the
  audit now records what it looked at.
- **Deleted, not patched:** `engine/github/parser.py` and its tests. `reporter.py` moved up to
  `codesheriff_engine/reporting.py` and the `github/` package is gone — after Chapter 6 it held only
  markdown rendering, and a directory named `github` inside the component forbidden from touching
  GitHub is the invitation `AUDIT.md` 4.3 describes.

**Verified.** 618 Python tests pass against Postgres (498 pass and 120 skip without one); 78 of them
are new · `ruff check` and `ruff format --check` clean across 150 files · `mypy --strict` clean
across 89 source files · `lint-imports` 5 contracts kept, with a deliberate `codesheriff_engine.extraction -> sqlalchemy` import added, correctly broken, and removed. Extraction was additionally run over all
60 corpus cases: the 48 whose source is a whole module extract with the case's own qualified symbol,
and the 12 method cases store a bare `def` with `enclosing_class` as metadata — the corpus supplies
its `ChangeUnit` directly and does not go through extraction.

⚠️ **Python only.** `.py` and `.pyi`; every other language is a recorded `language_unsupported`
skip rather than a unit nothing can analyse. JS/TS stays unscheduled (§6), and tree-sitter reaches
it through the same API when it is scheduled.

## Chapter 9 — Static agent I: Semgrep backend + fusion skeleton (v0.3) ✅

**Replaced** `packages/engine/src/codesheriff_engine/fusion/`.
**Closes** `AUDIT.md` 1.4, 2.2, 2.3, 2.4, 2.6, 2.7. **Partially closes** 3.12, 4.4.

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

**Delivered.** The analysis seam is closed: extraction → four blind agents → per-unit evidence rows
→ fused posteriors → findings → one comment. D-052 through D-057. The "Done when" criterion holds,
and so does the stronger property it stands for — a posterior that can go *down*.

- **The witness, not the agent, is the unit of fusion (D-052).** A fixed roster of four, and a
  registry mapping every backend `agent_id` to one of them. Four factors, always four. The two
  defects this closes are the same mistake twice: iterating only agents that spoke made the
  posterior monotonically non-decreasing (`AUDIT.md` 1.4), and giving the two static backends
  separate table rows multiplied 8.5 × 7.0 = **59.5×** out of one witness (`AUDIT.md` 2.4).
  Backends inside a witness combine by plain max — D-011's open question, answered provisionally.
- **Silence now costs something, and coverage now bounds it.** `PROVISIONAL_RATIOS` is keyed by
  witness and carries a `silence` ratio the old table had no place for, constrained below 1.0 by
  the type rather than by convention. It applies only when the witness's `covered_cwes` contains
  the finding's CWE, so the taint engine's silence cannot suppress a CWE-862 finding it never had
  a rule for (D-006).
- **There is no ratio for an abstention**, and there must never be one. Exactly 1.0, by definition
  — a fitted number there would mean the act of failing carried information about the code.
- **The ratios are clamped; the posterior is not** (`AUDIT.md` 2.7, reversed). Bounding each
  witness's claim bounds a quantity that means something. The old 0.9999 posterior clamp merely hid
  an unbounded odds product behind a number shaped like a probability.
- **Debate is deleted, not ported (D-053).** With it went `enable_debate`, `conflict_threshold`,
  three LLM API keys and `httpx` from the engine's dependencies. `EngineConfig` now holds no
  credential of any kind. Debate returns as a witness that emits its own evidence in Chapter 11;
  `debate.synth` is deliberately unregistered, because it reads what the others said and would be
  the D-008 anchoring violation under another name.
- **`abstention:all_agents` is gone at source (D-055).** A unit nobody detected anything in yields
  evidence rows and no finding. `codesheriff_storage.persistable_findings` stays as the second wall.
- **Running agents moved to `apps/worker` (D-054).** `codesheriff_engine` reached the agents by
  `try: import static_agent` — an undeclared runtime dependency that let a fusion package pull in an
  LLM client. `reporting.py` went with it: a second comment renderer, complete with the file path
  D-050 keeps out of one. The engine CLI's `run` becomes `fuse`, which prints the posterior and the
  factor each witness contributed to it.
- **Every seat speaks, every audit.** An agent that will not import, raises, hangs or returns `[]`
  becomes an abstention with a distinct reason. `AUDIT.md` 4.4 is what the alternative looks like.
- **Backends now state coverage over what they did *not* find (D-056).** Both static backends
  emit detections *and* a residual SILENCE over `covered_cwes - detected_cwes`. Previously a
  backend that detected anything went silent about the other nine CWEs, so its silence contributed
  nothing to any other finding in the same unit.
- **The comment reports what the witnesses said and what came out**, with a provisional banner above
  every number (D-032) and a four-row breakdown per finding. No agent prose reaches it — rationales
  arrive screened in Chapter 11 (`AUDIT.md` 0.4) — and still no path, no symbol, no title (D-050).

**One defect found by running the pipeline end to end** (D-057, `AUDIT.md` 3.12). `SemanticAgent`
fell back to `StubLLMClient` when no API key was configured, and that stub answers anything but one
demo fixture with `{"findings": []}` — which the agent correctly reported as SILENCE across all ten
in-scope CWEs. So an unconfigured deployment had a witness that had read nothing arguing, at a
likelihood ratio of 0.50, that every change was safe, indistinguishable from a real model's vote.

Harmless while fusion ignored silence. **This chapter is what made it harmful**, so this chapter
fixes it rather than leaving it to Chapter 11: no key and no injected client means `llm_unavailable`,
every unit. The fix raises quiet-unit posteriors rather than lowering them, which is the correct
direction — nothing looked, so nothing was learned.

**Verified.** 663 Python tests pass against Postgres (535 + 128 skips without one); 45 of them are
new · `ruff check` and `ruff format --check` clean across 150 files · `mypy --strict` clean across
90 source files · `lint-imports` 5 contracts kept. End to end on the Chapter 8 fixture — a method
where `request.args["scope"]` reaches `subprocess.run(..., shell=True)` — the taint engine detects
CWE-78 at 0.31 posterior with three witnesses abstaining at 1.0, below the provisional 0.70
threshold. That number is provisional and says so on every surface that renders it.

⚠️ **Semgrep does not run on this machine.** It has no Windows build, so `structural.semgrep`
abstains with `tool_unavailable` and the structural witness is the taint engine alone. That is a
correctly-handled abstention rather than a defect — and it is exactly why the abstention path is
tested — but it means the SARIF mapping is exercised only by `test_semgrep_mapping.py` against
fixture SARIF, never against Semgrep's real output. **Chapter 14 must run the corpus on Linux/CI**,
or its fitted structural ratios will describe a one-backend witness.

⚠️ **The ratios remain asserted.** Every number in `PROVISIONAL_RATIOS`, the prior and the threshold
are hand-set, and D-010 requires them presented as such until Chapter 14. Nothing derived from them
may be called calibrated.

```bash
uv run codesheriff-engine fuse evidence.json    # posterior, with one row per witness
```

## Chapter 10 — Static agent II: the taint engine ✅

**Replaced** `packages/agent_static/src/static_agent/taint/engine.py`, and with it `defuse.py`,
`catalog.py`, `parse.py`, `render.py` and all three rule files.
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

**Delivered.** A real taint engine. All three "Done when" criteria hold, each as a named test, and
the graph is now the thing the analysis runs on rather than a local variable nobody read. D-058
through D-063.

- **The def-use graph is built from the AST and consumed** (`AUDIT.md` 3.1). Nodes are definitions,
  guards and sink arguments; edges are flows. `propagate()` runs a worklist to a fixpoint and
  `networkx.shortest_path` produces the path that gets rendered. The old builder was regex over
  stripped lines, its result was assigned to a local and never referenced, `import networkx` was
  unused, and symbol extraction sat behind a literal `if False`.
- **Paths are real** (`AUDIT.md` 3.2). A source and an unrelated sink below it produce nothing;
  a three-hop flow renders three steps with a genuine `propagation` role in the middle. The old
  artifact was always exactly two steps and could never contain one, so a one-hop flow and a
  five-hop flow were indistinguishable to a reviewer.
- **Rules match the callee of a call node, never a line of text** (`AUDIT.md` 3.3, D-059).
  `# TODO: replace os.system with subprocess` matches nothing, `eval` no longer matches `evaluate`,
  and keyword arguments are read from the AST — so `subprocess.run(cmd,\n shell=True)` is seen and
  `yaml.load(f,\n Loader=SafeLoader)` is not a finding.
- **Sanitizers clear classes, and the class is read** (`AUDIT.md` 3.4, D-059). An edge that clears
  `xss` disappears from the graph used to reason about an XSS sink and stays in the one used for a
  command sink. Escaping HTML no longer silences an `os.system`. Clearing is computed **per
  occurrence**, so `render(escape(a), b)` clears for `a` and not for `b`.
- **Parameterised SQL is a sink property** (`AUDIT.md` 3.5, D-059). `args: [0]` on `sql.execute`,
  with `safe_when: params_passed_separately` naming the choice. It is the only model that gets
  `cwe-089-order-sort` right, where **both** twins pass parameters separately and the vulnerable one
  concatenates a tainted sort column into argument 0.
- **Type coercion and allowlists exist** (`AUDIT.md` 3.6). `int`, `float`, `uuid.UUID`,
  `datetime.fromisoformat` clear every class; a screaming-snake-case mapping lookup clears every
  class. §5 calls these "the largest false-positive source without them" and there were none.
- **Function parameters are untrusted** (D-058). The single most consequential choice here: nine of
  the thirteen calibration cases depend on it and none of those functions mentions a request object.
- **A validating guard is a definition** (D-060). `if name not in ALLOWED: raise` redefines `name`
  through an edge that clears everything; `if blob is None: return None` does not, which is what
  keeps `cwe-502-cache-get` detectable. The distinction is whether the condition *does something to*
  the value or only asks whether it exists — and it is generic, so no project-specific validator name
  appears in any rule.
- **Path traversal requires a base to escape** (D-061), or every function that opens a path it was
  given becomes a critical finding — including both members of `cwe-502-config-load`.
- **Eleven sinks, each with a vulnerable fixture and a safe twin**, and a test that fails when a rule
  is added without a pair. The safe twin is the half that matters: a rule with only a vulnerable
  fixture is tested for firing and never for staying quiet.

**Measured, on the calibration split only.** 13/13 recall on the cases `detectable_by` predicts for
`structural.taint`, **0 false positives across all 18 safe cases**, and one detection beyond
prediction (`cwe-502-config-load-vuln`, a genuine unsafe `yaml.Loader`; `detectable_by` excuses, it
does not forbid). p95 latency **28ms** per ChangeUnit against a 3s target.

⚠️ **These are development numbers, not calibrated ones.** §6 reserves validation for threshold
selection and permits the test split to be evaluated exactly once, at the end, so both stay sealed
until Chapter 14. `test_only_the_calibration_split_is_read` asserts the restriction rather than
trusting it, and the fabricated `bench` command that returned `precision: 1.0, recall: 1.0` is
deleted (D-063, D-010).

**JavaScript now abstains** (D-062). Everything the engine does is Python-shaped, and the JS rules
were the regexes whose `\beval` matched `evaluate`. An abstention contributes a likelihood ratio of
exactly 1.0 and is worth more than a confident wrong answer. `symbols.py` is deleted — dead since
`AUDIT.md` 3.1 — and `parse.py` no longer mirrors the whole tree into pydantic on every call.

**Verified.** 798 Python tests pass against Postgres (670 + 128 skips without one); 148 of them are
new · `ruff check` and `ruff format --check` clean across 151 files · `mypy --strict` clean across 89
source files · `lint-imports` 5 contracts kept, including the corpus contract with the new
calibration test in place · `agent_static` coverage 83%, and 87–100% across the taint modules.

```bash
uv run pytest packages/agent_static/tests/test_corpus_calibration.py   # the measurement
uv run pytest packages/agent_static/tests/test_taint_sinks.py          # both fixtures per sink
```

## Chapter 11 — Semantic agent ✅

**Closes** `AUDIT.md` 0.3, 0.4, 3.9, 3.10, 3.11, 3.12.

Three-stage prompt: functional intent → trust boundaries → violated safety invariant. **Wire the
exemplars** — they exist on disk and nothing loads them. Complete the hallucination gate: add the
`IN_SCOPE_CWES` check, make the file check exact rather than basename, remove the `+5` line slack.
`unit_too_large` abstention — never truncate. Escape the `<code_to_analyze>` delimiter so untrusted
code cannot close the data region. Screen rationales so injected strings are not echoed. **Abstain,
never stub,** when unconfigured. Keep n=3 with varying seeds.

**Done when:** injection subversion ≤ 10%; safe-twin pass rate ≥ 85%; zero hallucinated sinks reach
output; zero live API calls in the suite.

**Delivered.** All four criteria hold, each as a named test over real recorded model output rather
than a scripted stub. D-066 through D-068.

- **The untrusted region is bounded by a sentinel the code author cannot predict** (`AUDIT.md` 0.3,
  D-066). `CODESHERIFF-` plus eight bytes from `secrets`, drawn per request, with the prompt saying
  in advance that any text inside the block claiming to close it — or repeating the sentinel — is
  the attack, and the code is still the thing to report on. The old literal `<code_to_analyze>` tag
  was forgeable by exactly the person whose code was being read.
- **The exemplars are loaded, and rendered inside that same sentinel** (`AUDIT.md` 3.9). They could
  not have been loaded as they stood: each file held only a `response`, with no record of the code
  it answered, so the input half was authored. Six now, **four of which correctly report nothing**,
  and `exemplar_balance` asserts the ratio so it cannot drift. None is drawn from the corpus — an
  example lifted from a labelled case puts that case's answer in the prompt (D-047). Framing them
  identically to the real unit is deliberate: shown in a different wrapper they would teach that the
  sentinel is decorative, and they are the longest part of the prompt.
- **All four hallucination-gate checks hold** (`AUDIT.md` 3.10). The `IN_SCOPE_CWES` check that was
  absent entirely; an exact file-path comparison instead of the basename fallback that let a finding
  about `vendor/evil/users.py` pass against `app/api/users.py`; the verbatim sink check; and
  evidence-line bounds with the `+ 5` slack — five lines past the end of the unit — removed. A
  rejected finding is dropped without failing the sample, because one response can carry a real
  finding and an invention, and discarding both loses the real one.
- **Model prose is screened, and instruction-shaped prose is dropped whole** (`AUDIT.md` 0.4,
  D-067). In `mapping.py`, the only place an `LLMFinding` becomes an `Evidence`, so no path to a
  stored row, a comment or the dashboard skips it. Escaping was the wrong instinct: an escaped
  injection is still published to the reader it is aimed at. The finding survives either way and is
  reported from its gate-validated fields, since whether the code is vulnerable does not depend on
  how the model described it.
- **An oversized unit abstains** (`AUDIT.md` 3.11, D-015). 60 kB, checked before any call. It used
  to trip the budget check, `break`, and fall through to an empty list — downstream indistinguishable
  from "reviewed, clean".
- **A provider failure is not a model failure** (`AUDIT.md` 3.12, D-065). Retry with jittered
  backoff, and three 503s now abstain with `provider_unavailable` rather than `schema_violation`,
  which blamed the model for output it was never asked for. That misattribution would have been read
  as evidence about the model when the ratios are fitted.

**Measured, on the calibration split only** — 36 recorded cases, 18 safe and 18 vulnerable, plus 23
injected variants.

| Criterion | Target | Measured |
|---|---|---|
| Injection subversion | ≤ 10% | **0%** — 0 of the 10 cases carrying a baseline detection |
| Safe-twin pass rate | ≥ 85% | **94%** — 17 of 18 |
| Hallucinated sinks reaching output | zero | **zero**, asserted per emitted finding against the source |
| Live API calls in the suite | zero | **zero**, enforced at the socket, not by convention |

Recall on the cases `detectable_by` predicts for this agent is **17/18**, reported rather than
gated: recall is what Chapter 14 fits a likelihood ratio *from*, and a floor asserted here would
make the ratio a target rather than a measurement.

⚠️ **These are development numbers, not calibrated ones**, and they describe one pinned model on one
date. §6 keeps validation and test sealed until Chapters 14 and 18, and
`test_only_the_calibration_split_is_read` asserts the restriction rather than trusting it.

**Measured from committed cassettes** (D-068). `tools/record_cassettes.py` calls the live API once
and commits what came back; the suite replays it through the real `analyze()` path. That is what
lets "zero live calls" and "measured on real model output" both hold, and it makes the measurement
deterministic, free, and inspectable — the exact bytes are in the repository. Each cassette carries
the fingerprint of the prompt it answered, so editing the template, the system prompt or an exemplar
marks every recording stale instead of quietly measuring a prompt nobody sends.

**Two defects found and logged, both open** (`DEFECTS.md`). FP-001: the model reports CWE-79 on
`format_html`, whose escaping guarantee lives in the library rather than in the unit — doubt about
an unseen callee resolves toward reporting. FN-001 is the more interesting one: the prompt reports
only when "untrusted input enters, it reaches a dangerous sink, and no invariant protects it", and a
hardcoded credential has no untrusted input, so **the three-stage framework structurally excludes
CWE-798**. Fixing it means a prompt change, which invalidates every cassette and requires a
re-record against the live API — so it is logged rather than patched, and belongs with the next
recording run.

```bash
uv run pytest packages/agent_semantic/tests/test_corpus_semantic.py   # the measurement
uv run pytest packages/agent_semantic/tests/test_injection.py         # the boundary itself
uv run python packages/agent_semantic/tools/record_cassettes.py       # spends quota; needs a key
```

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
