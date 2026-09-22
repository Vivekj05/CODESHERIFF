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

Roughly: **v0.1–v0.8 built and measured; the dashboard reads them (Ch 15). v0.9 and v1.0 not
started.**

Four packages exist with a passing test suite and a webhook that reaches GitHub. But the conformance
audit found three of four analysis components non-functional, the fusion engine implementing the
pre-reversal form of nearly every finalized decision, and the webhook unauthenticated. Nothing
numeric was calibrated, because no corpus existed.

The test suite reported 100% and could not detect any of this. *(That paragraph is the state the
audit found, kept as written. Every finding in it is now closed — see below and `AUDIT.md`.)*

As of Chapter 2 the workspace installs, runs and passes its gates, and the contract every other
component serialises is frozen at v2.0.0. As of Chapter 6 the seam around the analysis is real: a
signature-verified delivery becomes a queued audit becomes one comment posted by a worker, and the
unauthenticated endpoint is deleted rather than patched. As of Chapter 7 there is ground truth to
measure against, and as of Chapter 8 the pipeline hands over the right objects: one `ChangeUnit`
per changed function, cut from the real file at real line numbers.

As of Chapter 9 the seam is **closed**: every extracted unit reaches four blind agents, what each
one says is persisted against the function it is about, and fusion turns it into a posterior that
can go down as well as up. The pipeline is end to end for the first time.

**All four analysis components now do the work their names claim.** As of Chapter 10 the
structural witness runs worklist taint propagation over a def-use graph it actually consumes, and is
measured against ground truth: 13/13 on the cases the corpus predicts for it, 0 false positives
across 23 safe twins, on the calibration split. As of Chapter 11 the semantic witness reads its
exemplars, bounds the untrusted region with a sentinel the code author cannot forge, and is measured
the same way — 0% injection subversion, a 94% safe-twin pass rate, and zero hallucinated sinks
reaching output, from model responses recorded once and committed. As of Chapter 12 the context
witness reasons from retrieved merged code rather than from four substring tests: 5/5 on the cases
the corpus predicts for it and 0 false positives across 11 twins and negative controls. As of
Chapter 13 the runtime witness executes the changed function inside a Wasmtime sandbox that denies
the network at link time and hands the guest an empty environment, and reports what an untrusted
value actually reached: 9/9 on the cases the corpus predicts for it and 0 false positives across 23
safe twins.

**As of Chapter 15 the numbers are legible.** The dashboard reads real audits, and the
calibration page shows what every posterior rests on: the reliability bins the ECE was computed
over, the observation counts behind each likelihood ratio, the whole validation threshold sweep,
and which backends were actually running when the observations were made. Settings reports those
numbers and cannot change them (D-089).

**As of Chapter 16 a single posterior is legible too.** The odds product is stored beside the
finding it produced, so a number can be taken apart factor by factor: four witnesses always, each
with the ratio it contributed, the `calibration.json` cell that ratio was read from, and the
statement its backends made — including the two kinds of statement that report finding nothing.
Nothing on that page is recomputed, so an audit that ran under an earlier calibration is still
explained by the ratios it used (D-090).

**As of Chapter 17 a finding can carry a repair.** An alert-worthy finding gets a drafted patch,
checked against a fixed ladder — it parses, it keeps the signature its callers depend on, it
references no name the file does not have, it changes something, and the deterministic witnesses
re-examine the repaired function — and, if it survives, posted as a GitHub suggested change anchored
inside the diff. Suggestions only: nothing commits, merges or pushes. §7 open question 3 is answered
and the answer is a refusal — CodeSheriff does not run the repository's test suite, and the ladder
does not change when one exists, because a test suite needs the network and the filesystem the
sandbox exists to deny (D-094). A rung has three outcomes rather than two, so a check that could not
run is never published as one that passed.

**As of Chapter 14 the numbers are fitted.** Every likelihood ratio comes from the calibration
split, the alert threshold from a weighted precision–recall sweep on the validation split, and both
travel in `calibration.json` with the corpus hash they were measured against. There is no hand-set
prior, threshold or ratio table left anywhere in the codebase — not renamed, deleted — so a missing
artifact raises rather than quietly producing a number nobody measured. Weighted ECE is 0.027 and
Brier 0.013 at selection time; the honest version of both is the test split's, which stays sealed
until Chapter 18.

The four are **heterogeneous in the way the thesis needs**, and the measurements are the first
evidence for it rather than an argument about it. Their errors do not coincide. The semantic agent's
single false positive is `format_html`, whose escaping guarantee lives in a library it cannot see,
and the taint engine — which knows that callee by rule — is correctly quiet on the same case. Its
miss is a hardcoded credential, which it fails on for a structural reason: the three-stage prompt
asks what untrusted input reaches a dangerous sink, and a literal password is neither. The context
agent's blind spot is different again and is by construction: it sees nothing whatsoever in a
repository with no relevant history, which is most repositories most of the time, and it sees
authorization failures that leave no syntactic trace at all — the two CWEs for which the taint
engine holds no rules. The runtime agent's blind spot is the sharpest of the four and the easiest to
state: it sees only what a function does when it runs, so it is silent on the two CWEs whose sinks
are methods on objects it had to fabricate, and it abstains outright whenever a guard it could not
evaluate stood between the value and the sink. Agents that failed the same way would add nothing to
a probability estimate.

**No shells remain.** All four witnesses run, and all four are measured on the calibration split
against ground truth that was written before any of them existed. What Chapter 9 built is still the
frame around them — an agent that cannot run abstains under its own name, at a likelihood ratio of
exactly 1.0, on the record, per unit — and that frame is now what carries a machine with no WASI
interpreter rather than what carried an agent that did not exist.

Chapter 12 also closed Chapter 7's outstanding caveat. The corpus is 76 cases in 38 twin pairs, and
the cross-PR scenarios — a case plus a precedent history — exist now that the shape of a precedent
document is fixed. Everything Chapter 14 needs to fit ratios on is in place.

Every witness is **measurable**, and all four now are. Chapter 7 supplied the labels, Chapter 8
supplies units of the same shape the corpus holds, and Chapter 9 supplies the arithmetic that turns
their statements into a number. "This agent found nothing" is a result rather than an absence of one — and it is a
result with a price, since a silence carries a likelihood ratio below 1.0.

| Version | Goal | Status |
|---|---|---|
| v0.1 | webhook → diff parsed → comment posted | ✅ **complete** (Ch 6, Ch 8) — HMAC verified before parsing, enqueued, worker posts. Extraction is one unit per changed function, from fetched blobs |
| v0.2 | contracts frozen + corpus with committed splits | ⚠️ contracts frozen at v2.0.0 (Ch 2); corpus 60 units / 30 pairs with committed splits (Ch 7); **cross-PR scenarios pending Ch 12** |
| v0.3 | Semgrep backend + fusion engine | ✅ **complete** (Ch 9) — all 7 fusion defects closed; four witnesses, one factor each. Ratios still asserted until Ch 14 |
| v0.4 | taint engine | ✅ **complete** (Ch 10) — worklist propagation over a real def-use graph; 13/13 recall and 0/18 false positives on the calibration split |
| v0.5 | semantic agent | ✅ **complete** (Ch 11) — exemplars wired, gate complete, sentinel-bounded prompt; 0% injection subversion and 94% safe-twin pass on the calibration split |
| v0.6 | empirical calibration | ✅ **complete** (Ch 14) — ratios fitted on calibration, threshold selected on validation, `calibration.json` committed; weighted ECE 0.027 / Brier 0.013 at selection. No unfitted number remains |
| v0.7 | context agent | ✅ **complete** (Ch 12) — control vocabulary mined from retrieved merged code; 5/5 recall and 0 false positives across 11 twins and negative controls |
| v0.8 | runtime agent (Wasmtime + WASI) | ✅ **complete** (Ch 13) — network denied at link time, guest environment empty, four caps enforced; 9/9 recall and 0/23 false positives on the calibration split |
| v0.9 | learned scorer + fine-tuned semantic model | ⬜ |
| v1.0 | dashboard, patch loop, full evaluation | 🔨 dashboard done (Ch 15, Ch 16); patch loop done (Ch 17) — draft, verify, anchored suggestion, 9 recorded outcomes. Evaluation is Ch 18 |

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

## Chapter 7 — Corpus and committed splits ✅

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

✅ **Closed by Chapter 12.** The cross-PR scenarios were deferred because a scenario is a case *plus a precedent history*, and the shape of a precedent document was Chapter 12's to fix (§5 fixed only that indexing is per-symbol, not per-PR); authoring fifteen histories against a guessed schema would have meant rewriting them. They landed with the context agent as **eight new twin pairs**, taking the corpus to 76 cases in 38 pairs, plus histories on six existing calibration cases as negative controls (D-070). `corpus_hash` changed, which was safe only because Chapter 12 preceded Chapter 14 and no calibration artifact exists yet — the ordering the original note insisted on.

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

## Chapter 12 — Context agent ✅

**Replaced** `packages/agent_context/src/context_agent/reasoning/analyzer.py`, and `rag/`,
`retrieval/` and `reasoning/` with it.
**Closes** `AUDIT.md` 0.2, 3.7, 3.8. **Closes Chapter 7's ⚠️** — the cross-PR scenarios are here.

**Delivered.** D-069 through D-072. Both "Done when" criteria hold, and the agent is measured the
way Chapters 10 and 11 measured theirs.

- **The reasoning is retrieval-driven, and mechanical.** `controls.py` reads a control surface off
  the syntax tree — decorators and called names — for the unit and for each retrieved excerpt alike.
  `regression.py` mines which controls this repository's own merged history establishes, either by
  the same qualified symbol carrying one, or by two or more distinct sibling symbols sharing one.
  `classify.py` decides which of those are authorization controls. With an empty history the agent
  produces nothing: every input to the decision comes from what was retrieved.
- **No LLM, deliberately.** `CLAUDE.md` gives this witness the basis "this repository's own
  precedent" and the failure mode "repo has no relevant history". A model-driven version would share
  `semantic.hosted`'s failure mode and heterogeneity is the whole argument for four witnesses
  (D-071). `reasoning/prompts/cross_pr_v1.md` — referenced by no code since it was written — is
  deleted rather than wired up.
- **CWE-862 and CWE-639 only.** A mined control that maps to no in-scope CWE cannot be reported at
  all, which is the mechanism that stops a real convention from becoming this witness's finding.
- **Cross-repository retrieval is impossible structurally.** `repository_id` is bound at
  construction, `retrieve(unit, limit)` takes no repository, and the filter is in SQL (D-072).
- **Embedding failure is loud.** There is no fallback branch: the agent embeds nothing, and a
  missing library or wrong dimension raises, arriving as a `retrieval_unavailable` abstention that
  is distinct from `no_precedent`.
- **Precedent has one shape in three places** (D-070) — the pgvector chunk, the corpus record, and
  the value the agent reads. An agent measured against a corpus history shaped differently from a
  stored one would not be the agent production runs.
- **`apps/worker/precedent/`**: the embedder, the pgvector retriever, and a backfill command
  (`codesheriff-worker precedent backfill`). Nothing in the audit path writes precedent.

**The corpus grew, which is Chapter 7's deferred deliverable.** 60 → **76 cases in 38 pairs**.
Eight new twin pairs, all authorization CWEs, in which the unit alone carries no evidence and only
the repository's history does — an added endpoint whose merged siblings all carry the guard, a
handler that moved modules and lost its decorator, a service method added beside two that have one.
Five landed in calibration and between them cover all three ways a control gets established.

Six existing calibration cases additionally gained histories as **negative controls**, where
precedent establishes a convention that is real and that the unit really breaks, and that this
witness must decline to report: `escape()` on the CWE-79 pair, `@rate_limit` on the CWE-918 pair,
and a history with no controls at all on the CWE-89 pair, which must read as SILENCE rather than as
an abstention.

**Measured** — `packages/agent_context/tests/test_corpus_context.py`, calibration split only, with
`test_only_the_calibration_split_is_read` asserting the restriction:

| | |
|---|---|
| Recall on cases `detectable_by` predicts | **5 / 5** |
| False positives across safe twins and negative controls | **0 / 11** |
| Cases with a history that abstained | **0 / 16** |
| Cases with no history | abstain, every one |

Retrieval in the measurement is a deterministic token-overlap ranking over the case's authored
history — no database, no model download, no network, the same discipline as the semantic agent's
cassettes (D-068). The production `analyze()` path is what runs. What is *not* measured is
pgvector's own nearest-neighbour ordering, which is why the ranking is exercised at all rather than
the history being handed over wholesale: a retriever that returned everything would hide a `top_k`
that silently dropped the second carrier of a convention.

⚠️ **These are development numbers, not calibrated ones** (D-010). Five predicted cases is a small
recall denominator and the report must say so; the false-positive side is the stronger half at 11.

**A serious defect found and fixed — `codesheriff-corpus assign` re-drew the whole corpus** (D-069).
D-045 promises assignment never moves a settled pair, and `assign` honours that — but the CLI fed it
existing assignments via `load_splits()`, which *raises* when any pair is unassigned. That is the
state the corpus is in whenever cases have just been added, which is the only time the command runs.
It caught `CorpusError` and continued with nothing. Adding these eight pairs moved **16 of the 30
settled pairs**, four of them in or out of the sealed test split, before the run was inspected and
reverted. The invariant had a test; the call site did not. Reproducibility is honestly weaker as a
result and is now asserted as a fixed point rather than as a from-scratch redraw — see D-069.

A second, quieter bug in the same area: `test_split_sizes_match_the_recorded_ratios` compared each
split to `round(total * ratio)`, which does not sum to the total. It agreed only because 30 divides
60/20/20 exactly.

**Still open, and deliberately.** `structural.semgrep` remains unavailable on Windows, so the
structural witness is one backend here (Chapter 9's note stands). The context agent has no
`db`-marked end-to-end test against a live pgvector store: the SQL scoping is asserted by compiling
the statement and the mapping by unit tests, but a real round trip through a 384-dimensional index
waits for Chapter 14, which needs a populated store anyway.

**Verified.** 965 Python tests pass with a database (837 + 128 skips without); 91 of them are new in
`packages/agent_context`, 12 in `apps/worker`, 9 in `packages/corpus` · `ruff check` and
`ruff format --check` clean across 162 files · `mypy --strict` clean across 95 source files ·
`lint-imports` **5 contracts kept** — including the two this chapter most risked, agent isolation
and no-agent-reads-the-corpus.

```bash
uv run pytest packages/agent_context/tests/test_corpus_context.py   # the measurement
uv run pytest packages/agent_context packages/corpus apps/worker
uv run codesheriff-corpus validate                                  # 76 cases, 38 pairs
uv run codesheriff-worker precedent backfill --help                 # the only writer
```

## Chapter 13 — Runtime agent ✅

Wasmtime + WASI. **Isolation infrastructure first, detection agent second** — the sandbox earns its
place because running untrusted PR code is how CI systems get compromised; evidence is a secondary
benefit.

Deny-by-default: no network, ephemeral read-only filesystem, CPU/memory/wall-clock caps, never on a
host holding DB credentials. Abstains widely (`no_safe_entrypoint`, `dependency_unavailable`) —
expected, not a defect.

**Done when:** a network-attempting fixture is observed and denied, and the sandbox holds no
credentials.

**Delivered.** D-073 through D-079. Both "Done when" criteria hold, each as a named test, and each
is proved **twice** — once by a hand-written WebAssembly module that calls one WASI function and
exits with its errno, and once by real CPython running real attack code inside the same sandbox.
The first proof needs no interpreter and runs everywhere in milliseconds; the second is what stops
the first from being a statement about a toy.

- **`test_a_module_that_asks_to_connect_cannot_even_load`** — WASI preview1 defines no
  `sock_connect`, so the module **fails to instantiate** and the guest never executes an
  instruction. The test asserts `fuel_used == 0` to say exactly that. `sock_accept` does exist and
  is useless: accepting needs a listening descriptor and nothing creates one. From Python inside,
  `socket.socket().connect(...)` and `urllib.request.urlopen(...)` both fail.
- **`test_the_guest_environment_is_empty_even_when_the_host_is_not`** — the host holds a
  `GITHUB_TOKEN`, a `DATABASE_URL` and an LLM key at the moment the guest runs, and the guest counts
  **zero** environment variables. Emptiness by construction, not by filter (D-075). Asserted against
  a host that genuinely holds them, because the same assertion against an empty host proves nothing.

Also asserted: no filesystem (`/` does not exist from inside; `path_open` on every namable
descriptor returns EBADF), no process spawn, fuel caps a spinning guest deterministically, the
wall clock caps a guest that fuel would not, memory growth stops at the ceiling, and two runs of one
compiled module share no state.

**The detection agent, and it is measured.** `runtime.sfi` executes the changed function once with
every parameter bound to a uniquely tokenised untrusted value, and reports which dangerous
operations that value actually reached (D-073). Taint is a **substring**, not a wrapper: the token
rides through f-strings, `+`, `%`, `.format()` and `os.path.join` for free, so D-061's composition
rule — a path handed over whole is not a traversal — is a string comparison rather than a dataflow
analysis.

On the calibration split, and only that split: **9/9 recall** on the cases the corpus predicts for
this agent, and **0 false positives across 23 safe twins**. 46 cases in ~14 s.

**The five CWEs it claims are the mechanism, not a limitation.** CWE-22, 78, 94, 502 and 918.
CWE-89 and CWE-79 are absent because their sinks are methods on objects the probe itself
fabricated, so an "observation" would be the harness observing itself — a weaker restatement of the
structural witness, which is the correlation D-011 exists to prevent. CWE-862, CWE-639 and CWE-798
are absent because there is nothing to observe: a missing check is the absence of an event. The
corpus pre-registered exactly these five in `detectable_by` before this agent existed (D-047), so
the narrowness is a claim rather than a convenience.

**A guard the probe could not evaluate produces an abstention, not a verdict** (D-079). When the
exact value that reached a sink had first been handed to an unmodelled call, the run reached that
sink only because the harness answered the guard. Reporting would be a false positive on precisely
the code that defends itself; silence would argue that guarded code is clean on the strength of a
guard nobody read. Two safe twins land here rather than as false positives.

**The interpreter is not committed** (D-074). `python-3.12.0.wasm` is 26 MB, lives in a gitignored
`.wasm-runtimes/`, is pinned by SHA-256 and verified on load, and is fetched deliberately by a
person — an agent that downloaded executable code at analysis time would be the supply-chain
problem this project exists to notice. Without it the agent abstains `interpreter_unavailable` on
every unit, under its own name, at exactly 1.0, and `runtime-agent doctor` reports every path it
consulted (D-077). Tests that need it carry the new `wasm` marker and skip, on the `db` precedent
(D-029).

**There is no second execution backend, not even for tests** (D-076). A host executor would be
reached the first time a `wasm`-marked test was inconvenient, and from then on the measurement would
be of untrusted code running on the machine holding the database credentials. This repository has
shipped that shape twice already — the MD5 term-hasher (`AUDIT.md` 3.8) and the substring debate
matcher (D-053) — and both became the default path silently.

**The worker's fourth seat now holds an agent.** `_load_runtime` imports `RuntimeAgent`; the sandbox
is built lazily on the first unit that needs it, because compiling 26 MB costs seconds and a worker
that paid it at start-up would pay it again on every restart. `apps/worker/tests` had a test
asserting the seat held a stand-in *because Chapter 13 had not happened*; it now asserts every seat
holds its real agent, and the stand-in path is tested by a loader that genuinely raises.

⚠️ **Two things this chapter did not measure**, both Chapter 14's by construction:

- **p95 latency.** ~0.3 s per unit after a 2.6 s one-time compile, on this machine, on corpus-sized
  functions. `CLAUDE.md`'s target is stated for the static agent; the runtime agent has none yet,
  and one set from a Windows dev box would not be the number.
- **pgvector-scale units.** Corpus cases are small by design. The behaviour of the fuel budget on a
  600-line function is unknown, and `fuel_exhausted` is the abstention that would report it.

**Gates.** All five Python gates green: **1204 tests** — 1076 passing with 128 skipped on a machine
with no database, and 67 more skipped on one with no WASI interpreter, of which 43 of this chapter's
run regardless because the isolation proofs are hand-written WebAssembly. `ruff` clean, `ruff
format` clean, `mypy --strict` clean across **103 source files**, `lint-imports` **5 contracts
kept** — including the two this chapter most risked, agent isolation and the corpus-label ban.
`agent_runtime` imports `codesheriff_contracts` and `wasmtime` and nothing else.

---

## Chapter 14 — Bayesian fusion and empirical calibration ✅

**The thesis. Everything before this is setup.**
**Closes** `AUDIT.md` 2.1 — the last open Tier 2 finding.

Fitted likelihood ratios on the **calibration split**, selected the alert threshold on the
**validation split**, and left the test split sealed. `packages/engine/src/codesheriff_engine/
calibration/calibration.json` is the artifact, and it is now the only place in the codebase a
likelihood ratio, a prior or a threshold comes from — `PROVISIONAL_RATIOS`, `PROVISIONAL_PRIOR`,
`PROVISIONAL_ALERT_THRESHOLD` and `FALLBACK_RATIOS` are **deleted**, not relabelled (D-080, D-082).

**What was built.**

- **`codesheriff_engine.calibration`** — the fitting arithmetic, and nothing else. No agent, no
  corpus, no session: it takes labelled `Claim`s and returns a table, which is what makes §6's
  "reproducible from the calibration split and a recorded corpus hash" a property of the code
  rather than a promise about how it is used. `observations.py` (what a claim is), `fit.py`
  (Laplace, clamps, per-cell counts), `prior.py` (declared base rate and rescaling), `metrics.py`
  (ECE, Brier, reliability bins), `threshold.py` (the weighted sweep), `artifact.py`.
- **`fusion/cells.py`** — the single definition of *what a witness said*. `bayes.py` reads a cell
  to look a ratio **up**; `fit.py` reads the same cell to count observations and fit that ratio
  **in**. Two implementations would fit one quantity and apply another, and both halves would pass
  their own tests. `posterior_from_cells` is likewise the one piece of arithmetic, shared by the
  audit path and the threshold sweep.
- **`codesheriff-worker calibrate observe|record|fit|show`** — the harness. It runs the
  **production** `load_agents` / `analyse_unit` with per-case bindings (D-085), and refuses the
  test split by name (D-086's sibling: `TestSplitSealedError`).
- **`calibration/observations/{calibration,validation}.jsonl`** — committed, so a fit is
  reproducible without a WASI interpreter, an API key or a Semgrep build. `calibration/responses/`
  holds the 14 validation model responses, recorded once and read by no test.

**The numbers.** 49 claims from 46 calibration cases, 15 from 14 validation cases.

| witness | high | medium | low | silence | spoke (+/−) | abstained |
|---|---|---|---|---|---|---|
| structural | 2.22 | 15.56 | 1.00 | 0.07 | 14 / 16 | 19 |
| semantic | 9.48 | 0.56 | 0.74 | 0.30 | 22 / 25 | 2 |
| context | 2.00 | 4.00 | 2.00 | 0.17 | 5 / 5 | 39 |
| runtime | 6.92 | 1.00 | 1.00 | 0.12 | 9 / 5 | 35 |

Base rate **3%**, declared and recorded as declared (D-083). Alert threshold **0.227**, selected by
maximum weighted F1 on validation: F1 0.923, precision 1.000, recall 0.857, 6 of 15 claims alerting.
Weighted **ECE 0.027** and **Brier 0.013** on validation; 0.009 / 0.010 in-sample on calibration.

**Read the table with its counts, not as four confident rows.** Three things in it are thin, and
all three are recorded in the artifact rather than smoothed away:

- **`structural.detection_medium` (15.56) exceeds `detection_high` (2.22).** Not because a
  confident taint path is weaker evidence — because 13 of the taint engine's 14 true detections
  score in the medium band and exactly one scores high. The high cell is nearly all smoothing
  prior. It says the agent's `raw_score` rarely reaches 0.8, which is a scoring-calibration
  question for the static agent and not a fusion one.
- **`context` fits from 10 claims** and `runtime` from 14. Both witnesses abstain on most units by
  construction — that is the design (a repository with no relevant history, a function that will
  not run in a sandbox), and it means their ratios rest on the fewest observations.
- **A cell nobody selected is exactly 1.0** (D-087), not the smoothed value, which would have made
  `runtime`'s two unobserved detection tiers argue mildly for *safety*.

**Two production defects, found by the harness rather than by the suite** (D-088). The semantic
agent's `budget_usd_per_unit` never reset, so one agent analysing many units enforced a
per-*process* budget — the first few units of a pull request were analysed and every one after them
abstained. And a unit whose budget stopped the loop before its first sample fell through to
**SILENCE**, reporting "reviewed the unit and found nothing" across all ten in-scope CWEs at a
likelihood ratio below 1.0, having read nothing. Both fixed, both with regression tests. Neither is
visible from a single-unit test, which is why 46 units through one production-shaped agent found
them.

⚠️ **Three things this chapter did not do.**

1. **`structural.semgrep` abstained on every unit.** There is no Semgrep build for Windows, so the
   structural ratios describe a **one-backend witness** and the artifact's provenance says so on its
   face. Chapter 18 must re-observe on Linux or CI before any structural number reaches the paper.
2. **The prior is declared, not measured.** A twin-paired corpus cannot supply one — its prevalence
   is 0.5 by construction. The ratios are prevalence-invariant, so changing the base rate rescales
   every posterior by a recorded factor and refits nothing.
3. **p95 latency and the fuel budget on a 600-line function** are still unmeasured, as Chapter 13
   noted. They need CI hardware, not a corpus.

**Done when — all four met.** `calibration.json` is reproducible from its recorded corpus hash
(`test_it_names_the_corpus_it_was_fitted_on_and_that_corpus_is_this_one` compares the artifact's
hash against the live corpus, so an edited case turns the suite red rather than silently
invalidating the fit); no hardcoded LR, prior or threshold remains anywhere
(`test_no_unfitted_numbers.py` parses the tree, and bans `DEFAULT_PRIOR` as well as
`PROVISIONAL_PRIOR`); ratios were fitted only on calibration and the threshold only on validation
(`fit_from_observations` refuses a set from the wrong split); the test split was never read.

**Gates.** All five Python gates green: **1128 tests** passing with 128 skipped on a machine with no
database (the WASI interpreter is present here). `ruff` clean, `ruff format` clean, `mypy --strict`
clean across **117 source files**, `lint-imports` **6 contracts kept** — the sixth is new, and it is
what keeps the audit path blind to the corpus now that the harness shares the worker process (D-086).

---

# Phase C — Surface and evaluation

## Chapter 15 — Dashboard API, dashboard UI, settings ✅

FastAPI REST endpoints, audit and finding queries, dashboard data contracts. Stats, recent audits,
verdict summaries, charts. Per-repo config: alert threshold, enabled agents, CWE scope.

**Confidence must read as calibrated.** A bare "87%" repeats the failure this project attacks —
surface the reliability the number rests on.

**Delivered.** The read side, end to end: a query layer, four routes, and the pages that render
them. **§7 open question 2 is closed (D-089).**

- **`codesheriff_storage.reporting`** — the first queries in this project that read an audit back
  out. Split from `audits.py` because the two have opposite hazards: a lifecycle write must be one
  conditional UPDATE or two workers race, a dashboard read must be scoped or it discloses another
  account's pull requests. Every function takes the session's installation snapshot and returns
  nothing for an empty one, and the counts are correlated subqueries — a join across units,
  evidence and findings would report `units × findings` change units, and the number would look
  plausible.
- **Four routes.** `GET /audits` (keyset-paginated on `(created_at, id)`, cursor opaque so a
  caller cannot construct one), `GET /audits/{id}`, `GET /stats/overview`, `GET /calibration`.
  None of them computes a probability: every posterior, prior and threshold is read from the row
  or the artifact that recorded it, so an audit that ran under an earlier calibration keeps
  reporting what it ran under (§6).
- **A calibration page that is the thesis rendered.** The reliability diagram over the validation
  bins, the whole threshold sweep rather than the winning point, every likelihood ratio beside the
  counts that produced it, and the provenance naming which backends were actually running. Three
  things on it are deliberately unflattering and stay: `structural.detection_high` shows the single
  observation holding it up, `context` and `runtime` show how few claims they were fitted from, and
  the base rate says it was declared rather than measured.
- **Settings is read-only, and says why (D-089).** The chapter as written called for a
  per-repository threshold, per-repository agent toggles and a per-repository CWE scope; all three
  reverse D-080 or D-084, and the conflict was raised before anything was built (§8). The one
  writable per-repository setting stays whether CodeSheriff analyses that repository at all.
- **Overview replaces the repository list as the landing page**, with counts of what happened and
  no aggregate score — an overall grade would be an uncalibrated number rendered in the same
  typeface as the calibrated ones. The per-witness statement table is the part worth reading: an
  agent abstaining on everything is not a quiet agent, it is one that cannot run here.

**Verified.** All five Python gates green — 1134 tests passing with 151 skipped on a machine with
no database, `ruff` and `ruff format` clean, `mypy --strict` clean across **121** source files,
`lint-imports` 6 contracts kept. Both frontend gates green across **10** routes. And, for the first
time in several chapters, **the 145 `db`-marked tests were actually run**: Postgres was started and
they pass.

⚠️ **Four `db`-marked tests were red before this chapter touched anything**, and had been since
Chapter 14 — they were never executed because no database was running when it landed. Three
asserted the deleted "Provisional, not calibrated" banner and the 0.05/0.70 provisional pair; one
called `_run_claimed_audit` with its pre-Chapter-9 signature. All four are fixed here, and the
stale literals are gone: they now assert against `active_artifact()`, so a re-fit moves both sides
together. The lesson is the one this repository keeps re-learning — a gate nobody runs is not a
gate.

## Chapter 16 — Findings page ✅

Finding detail, per-agent evidence breakdown, posterior display, taint path rendering.

Show **abstentions and silences**, not only detections. That an agent could not look is part of why
the posterior is what it is; hiding it makes the number unexplainable.

**Delivered.** The page the thesis rests on: one finding, and the posterior taken apart factor by
factor. D-090 and D-091.

- **The odds product is now persisted (D-090).** `fusion.bayes` has produced a
  `WitnessContribution` per witness since Chapter 9 — the stance, the ratio-table cell, the
  likelihood ratio read from it, the backends that spoke — and it reached the CLI and the pull
  request comment and was then **discarded**. Migration `0004` adds a nullable JSONB
  `findings.contributions`, `mapping.to_finding` writes it, and the route reads it. Nothing
  recomputes it: an audit that ran under an earlier calibration keeps being explained by the ratios
  it used, and no read route computes a probability.
- **NULL, empty and JSON `null` are three states, and the column holds two.** A CHECK forbids an
  empty array; `contributions_recorded` tells the page which of the two it has. Findings written
  before the column show their statements and no ratios, deliberately — four neutral factors drawn
  in place of factors nobody kept is a fabricated explanation of a real number. **The JSON `null`
  case was found by the constraint, not foreseen**: SQLAlchemy persists Python `None` into JSONB as
  `'null'::jsonb` unless the type says `none_as_null=True`, and that value reads back as `None` in
  Python while being NOT NULL in SQL. Model flag plus CHECK, and a regression test that asserts SQL
  NULL rather than a Python-side `is None`.
- **`GET /audits/{id}/findings/{key}` (D-091).** Scoped through the audit, because a `finding_key`
  is a digest of file, symbol and CWE and recurs by design on every new head SHA — a bare key names
  a set. The scaffolded `/findings/[key]` route is deleted rather than kept working.
- **The evidence served is the whole unit's.** A silence and an abstention both carry
  `finding_key IS NULL`; filtering on the key would return only detections, which is the subset
  that makes a posterior look inevitable. Detections of another key are excluded — a DETECTION
  carries no `covered_cwes` and says nothing about this finding.
- **Four witnesses are always drawn**, from `fusion.witnesses` rather than from the evidence. A
  list built from the agents that spoke would shorten to the ones that alerted, and since every
  detection tier exceeds 1.0 that is a page on which the odds can only rise — D-007 rendered in
  HTML. A neutral witness with an abstention under it is the case the page exists for: the odds did
  not move, and the reason is that nobody could look.
- **Taint paths render as an ordered flow**, source to sink, with the line and role of each step —
  the one artifact that is an argument rather than a note, and one a reader can follow and disagree
  with. Other artifact types print as the JSON the agent produced, so an agent that starts emitting
  a new field cannot have it silently dropped. All of it is attacker-authored text rendered as
  text; nothing reaches `dangerouslySetInnerHTML`.
- **The last mock data is gone.** `lib/mock-data.ts` and `components/chapter-placeholder.tsx` had
  no consumer left once the scaffolded findings route was deleted; every page now reads the API.

**Verified.** All five Python gates green — 1136 tests passing with 166 skipped on a machine with
no database, `ruff` and `ruff format` clean across 207 files, `mypy --strict` clean across **122**
source files, `lint-imports` 6 contracts kept. Both frontend gates green across **10** routes. The
**167 `db`-marked tests were run against Postgres and pass**, and migration `0004` was applied,
rolled back to `0003` and re-applied against a real database.

## Chapter 17 — Patch generation and verification ✅

Draft → verify → retry. Syntax check, regression check, test-suite run where available. Posted as a
GitHub suggestion. **Suggestions only — never commit or merge** (§2).

Resolves §7 open question 3 — record in `DECISIONS.md` what "verified" means when a repository has no
test suite.

**Delivered.** `packages/patch` (`codesheriff_patch`), `apps/worker/patching.py`, migration `0005`.
D-092 through D-097. The "Done when" of §2 holds: an alert-worthy finding gets a drafted repair, and
the report fires on both paths.

- **"Test-suite run where available" was not built, and the reason is the deliverable.** §7's
  question was what "verified" means with no test suite; the answer is that it means the same thing
  either way, because **CodeSheriff never runs the repository's suite** (D-094). Doing so means
  executing arbitrary code with its dependencies, its network and its filesystem — everything the
  Chapter 13 sandbox exists to deny — on a host holding the database credentials, which is the shape
  D-076 records this repository shipping twice. A ladder that degraded to "we ran their tests when
  they had some" would report two meanings of one word depending on a property of the repository,
  and the stronger meaning would be the unsafe one. The pull request says so, in the reviewer's own
  repository, rather than only in `DECISIONS.md`.
- **Six rungs, three outcomes each.** `parses` (`ast`, not tree-sitter — a parser that tolerates
  broken syntax would pass a broken patch), `signature_unchanged`, `names_resolve`,
  `changes_something`, and per witness `regression:` and `no_new_weakness:`. `passed`, `failed`,
  `not_run` — the D-005 distinction applied to verification, so a machine with no WASI interpreter
  cannot publish a suggestion described as sandbox-verified. `verified` additionally requires that
  at least one witness actually re-examined the patch: four passing text checks over code nothing
  looked at is not evidence.
- **A witness that never detected the weakness cannot certify its removal.** `regression:` is
  emitted only by witnesses that detected the CWE before the patch; the rest contribute
  `no_new_weakness:` only. `semantic.hosted` never rechecks — the drafter's own family grading the
  drafter, and non-deterministic besides — and `context.rag` never does either, because a proposed
  patch is not part of the repository's merged history.
- **`names_resolve` is the rung that earns its place.** A suggestion replaces lines *inside* one
  function and cannot add an import, so a repair reaching for `shlex.quote` in a file that never
  imported `shlex` is a `NameError` on the first request — invisible to a syntax check and to a
  reviewer skimming a green suggestion block.
- **Anchored inside `changed_lines`, or not published (D-095).** GitHub rejects a review comment
  outside a diff hunk, and D-048 keeps this system from ever reading `patch`, so `changed_lines` is
  the only span known to be in the diff. A verified repair that reaches outside records
  `not_anchorable` and posts nothing; a fenced block in the summary comment was rejected because to
  be useful it would carry the path and the source, and that comment carries neither (D-050).
  Anchoring works at all because `post_src` is built from whole file lines, so the replacement
  already carries the file's own indentation.
- **Retries carry reasons, never drafts (D-093).** Three drafts, each fresh from the same unit with
  an accumulating list of rejection reasons in this system's words. The rejected draft is model
  output shaped by attacker-controlled source; returning it as instruction would put untrusted text
  outside the sentinel. A transport failure ends the loop rather than retrying — the client owns its
  own retry budget (D-065), and multiplying the two spends nine free-tier requests on one finding.
- **No model prose is published (D-096).** The response carries one field, the repaired function.
  There is no summary and no rationale, so unlike `semantic.hosted` there is nothing to screen on the
  way out — the same place D-078 reached from the other direction. A response repeating the request
  sentinel is discarded outright.
- **Nine outcomes, none collapsed.** The pull request comment reports which one happened.
  "The function was over the size budget so nothing was requested" and "three repairs were drafted
  and every one failed a check" are different facts, and only the second is a defect report waiting
  to be written.
- **The patch is hashed, not stored (D-097).** `patch_proposals` holds the outcome, the ladder and a
  SHA-256; §6 keeps source out of the database, and a repaired function is somebody else's file with
  our edit in it. A row exists for every alert-worthy finding, including the ones that produced
  nothing.
- **Not a fifth witness (D-092).** `patch.hosted` emits no `Evidence` and is absent from
  `WITNESS_OF_AGENT` deliberately: it reads the finding, so it is maximally dependent on the four
  witnesses that produced it. A seventh `import-linter` contract keeps the package away from the
  agents, both apps, `httpx`, `githubkit` and `celery` — which is what lets the whole
  draft-verify-retry loop be tested against a scripted model with no key and no interpreter.

⚠️ **Three things this chapter did not do.**

1. **No live model has drafted a patch.** Every test replays a scripted model, per `CLAUDE.md`'s
   "zero live API calls". The ladder is measured against hand-written drafts that exercise each
   rung; what is *not* measured is the rate at which a real model produces a repair that survives
   it, or how often a verified repair lands inside the diff. That is a number Chapter 18 can take
   from the corpus, and it belongs beside the detection figures rather than asserted here.
2. **Nothing on the dashboard reads `patch_proposals`.** The place a suggestion is consumed is the
   pull request, where it already appears; the row is the audit record. Surfacing it is a read route
   and a panel on the finding page. Named in D-097 so it is a known gap rather than a silent one.
3. **`not_anchorable` has no measured frequency.** It depends on how much of a function a model
   rewrites versus how much of it a pull request changed, and both come from real diffs.

**Verified.** All five Python gates green — 1249 tests passing with 177 skipped on a machine with no
database, `ruff` and `ruff format` clean across 224 files, `mypy --strict` clean across **131**
source files, `lint-imports` **7** contracts kept. The **178 `db`-marked tests were run against
Postgres and pass**, and migration `0005` was applied, rolled back to `0004` and re-applied against
a real database. Both frontend gates green, unchanged.

## Chapter 18 — Evaluation and ablations 🔨

**The research payload.** Held-out test run — **evaluated exactly once**.

**Started: the measurement host.** The corpus can now be run somewhere all four witnesses are
live. `docker/corpus-run/` builds a pinned Linux image with `semgrep==1.176.1` and
`bandit==1.9.4` in it, reached through a `corpus` compose profile and carrying no default
command (D-098). Verified inside it: the corpus hashes match the host exactly, the WASI sandbox
loads its mounted interpreter and the digest checks out, and Semgrep runs 201 rules and produces
**22 findings across 6 distinct vulnerable corpus cases** — so the second structural backend is
real signal, not a formality.

Three things were fixed on the way there, each of which would have corrupted a measurement:

- **`uv.lock` was stale.** `codesheriff-patch` was absent entirely — Chapter 17 added the package
  and never relocked — so `uv sync --all-packages --frozen` failed on any fresh checkout,
  including CI and this image. Relocked; the diff is 22 additive lines with no version churn.
- **The committed semantic default named the wrong model** (D-099). Both `config.py` and
  `.env.example` said `gemini-3.5-flash`, while every recorded response — and therefore every
  fitted `semantic.hosted` ratio — came from `gemini-3.1-flash-lite`, supplied only by an
  uncommitted `.env`. A fresh checkout would have recorded the held-out split under a witness the
  ratios were never fitted for, silently.
- **torch pulled the CUDA runtime on Linux** (D-100), taking the image to 9.15 GB for code that
  cannot use a GPU. Pinned to the CPU index: 2.63 GB.

**Not yet done, and in this order.** Re-observe calibration and validation in the image and
**re-fit** — the committed artifact describes a one-backend structural witness, and a test split
scored against it would be measuring a system that no longer exists. Then the comparators, built
and debugged against those two splits: majority voting, the anchored-vs-blind ablation, and the
Semgrep/Bandit/single-LLM baselines. The test split is opened last, once, with the image id
recorded beside the result.

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
| 3 | Patch mechanics; what "verified" means with no test suite; retry count; suggestion block format | ✅ Ch 17 — D-093, D-094, D-095, D-096 |
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
