# DECISIONS.md

A living record. Every entry states the decision **and the reason** — in four months the reason is
what matters, and each entry becomes a paragraph in the report.

**Format.** Append new entries at the bottom. Never rewrite history; supersede with a new entry and
link back. Each entry carries: context (what forced the decision), decision, rationale,
consequences, and status.

**Conflict rule.** If a new decision conflicts with a finalized decision in `PROJECT_CONTEXT.md`
§5, identify the conflict and discuss it before changing anything. Several §5 entries reverse
earlier drafts and exist to fix specific bugs; reverting one silently reintroduces its bug.

**Status values:** `ACTIVE` · `SUPERSEDED by D-nnn` · `PROPOSED` (agreed in principle, not yet
implemented).

---

## D-001 — `PROJECT_CONTEXT.md` §5 is authoritative; `00-START-HERE.md` is superseded

**Date:** 2026-08-27 · **Status:** ACTIVE

**Context.** The repository contains two specs that contradict each other.
`00-START-HERE.md` sits in the repo root and mandates three independent projects with vendored
`contracts.py`, `analyze(unit, anchors=...)`, anchored execution, and three agents.
`PROJECT_CONTEXT.md` §5 reverses all four. The committed code was built against the older file.

**Decision.** `PROJECT_CONTEXT.md` is authoritative, and its §5 overrides any other document in the
repository. `00-START-HERE.md` is historical only.

**Rationale.** §5 is explicitly described as a set of decisions that "reverse earlier drafts and
exist to fix specific identified bugs." The audit (`AUDIT.md`) confirms that every reversal it
makes corresponds to a real defect present in the code built from the older spec. The older
document is not merely out of date — following it reproduces known bugs.

**Consequences.** `00-START-HERE.md` must carry a superseded banner or be deleted. Contributors and
LLM sessions need this hierarchy stated up front — it is now in `CLAUDE.md`. `01-static-agent-BUILD.md`
is partially superseded and must be checked against §5 before use.

---

## D-002 — Monorepo with one shared `contracts` package, not four vendored copies

**Date:** 2026-08-27 · **Status:** ACTIVE · **Supersedes** the vendoring scheme in `00-START-HERE.md` §1

**Context.** The code ships four standalone packages, each with its own `contracts.py`, kept in
sync by a SHA-256 checksum test in each package.

**Decision.** Migrate to a `uv` workspace monorepo: `packages/{contracts, corpus, agent_*, engine}`
+ `apps/{api, worker, dashboard}`. One `contracts` package, imported by everything. Agent isolation
enforced by `import-linter` in CI — agents may import `contracts` and nothing else.

**Rationale.** Vendoring existed to solve multi-person schema drift. This is a small team with no
such drift to solve, and `import-linter` preserves the isolation benefit of separate repos without
the ceremony. The audit also showed the checksum mechanism does not work as intended: the expected
hash was rewritten to make the test pass (`00-START-HERE.md:40` pins `bf88600b…`, all four tests
carry `7176be9e…`) — verbatim what that file's own comment forbids. A mechanism that can be
silenced by editing one constant is not a safeguard.

**Consequences.** Four `pyproject.toml` files collapse into a workspace. The `sys.path` mutation in
root `main.py:14-23` disappears. `test_contract_integrity.py` becomes unnecessary and should be
deleted rather than ported — it would give false assurance.

**Note.** `PROJECT_CONTEXT.md` originally lived *outside* the repository, in the parent directory —
the authoritative spec was not version-controlled alongside the code it governed. It has since been
moved into the repo root. Resolved.

**Implemented by D-018.**

---

## D-003 — Rebuild the core; do not mechanically migrate

**Date:** 2026-08-27 · **Status:** ACTIVE

**Context.** With the monorepo chosen, the question was whether to move existing code into the new
layout or rewrite it there.

**Decision.** Rebuild the analysis core following the `PLAN.md` build order. Port specific assets
deliberately (see `PLAN.md` salvage list): the Semgrep SARIF runner, the tree-sitter wrapper, the
prompt assets, the LLM client protocol, the reporter's formatting, and the rule vocabulary.

**Rationale.** A mechanical port preserves directory structure, which is the one thing already
fine. What is broken is the analysis logic and the contract beneath it — and those are broken in
ways that pass their own tests (`AUDIT.md` Tier 1–3). Moving them into `packages/` would launder
the defects behind a better layout and make them harder to find. Agent isolation is clean
(`AUDIT.md`, "What conforms"), which is what makes a rebuild cheap rather than catastrophic.

**Consequences.** Contributor authorship is preserved in git history. Work proceeds on a branch,
in-place, so the audit trail of what changed and why is itself report material.

---

## D-004 — `finding_key` excludes the sink expression

**Date:** 2026-08-27 (restating `PROJECT_CONTEXT.md` §5) · **Status:** PROPOSED — not yet implemented

**Decision.** `finding_key = sha256(f"{file}::{qualified_symbol}::{cwe}")[:16]`, computed **only**
by the `contracts` package. Agents never construct it.

**Rationale.** With the sink included, the taint engine reports `cursor.execute(query)` while the
LLM reports `cursor.execute` — different hashes, different groups, and the agents never fuse. Every
finding becomes a singleton and the Bayesian engine never performs an update.

The audit found this is not hypothetical. Current `contracts.py:82` is
`f"{file}:{symbol or ''}:{cwe.upper()}:{sink_expr.strip()}"`. Worse, *within the static agent
alone*, `taint/engine.py:120` passes an AST-derived expression while `semgrep/mapping.py:50` passes
a SARIF text snippet — two backends in one package cannot collide on the same bug.

**Accepted trade-off.** Two independent bugs of the same CWE in one function collapse into one
group. This is deliberate and preferable to never fusing at all.

**Consequences.** `ChangeUnit` must carry `enclosing_class` so the symbol can be *qualified* — the
current contract has no qualifier, which is why the existing key uses a bare symbol.

---

## D-005 — Three evidence kinds: `DETECTION`, `SILENCE`, `ABSTENTION`

**Date:** 2026-08-27 (restating §5) · **Status:** PROPOSED — not yet implemented

**Decision.** Replace `abstained: bool` with a three-valued kind. SILENCE (ran, found nothing) gets
a likelihood ratio below 1.0. ABSTENTION (could not run) gets exactly 1.0.

**Rationale.** Conflating them is a wrong-sign bug: an agent that *could not look* would penalise
the finding. The audit found no evidence-kind concept exists at all — an agent that ran cleanly has
no contract-legal way to say so, which removes the entire mechanism for evidence that *lowers* a
posterior. Several code paths currently return a bare `[]` on failure
(`semantic-agent/agent.py:189`, `context-agent/agent.py:109`), so "did not analyse" is
indistinguishable from "analysed, clean".

**Consequences.** Returning `[]` from `analyze()` on a failure path becomes a lint-able bug. Every
agent needs an explicit SILENCE emission when it completes with no findings.

---

## D-006 — `SILENCE` carries `covered_cwes`; the silence ratio applies only inside that set

**Date:** 2026-08-27 (restating §5) · **Status:** PROPOSED — not yet implemented

**Rationale.** Otherwise the taint engine's silence on CWE-862 — which it has no rules for — would
systematically suppress every semantic-only finding. The audit confirms the risk is live: only 6 of
the 10 in-scope CWEs have any detection path, and CWE-862/639 are precisely the authorization cases
§5 says "exist to prove heterogeneity."

---

## D-007 — Every agent contributes exactly one likelihood ratio per finding group

**Date:** 2026-08-27 (restating §5) · **Status:** PROPOSED — not yet implemented

**Decision.** Fusion iterates over **all** agents, not only those that emitted evidence.

**Rationale.** Otherwise odds can only ever increase. Confirmed in `fusion/bayes.py:93-96,113`,
which filters to `active_evidence` before the update loop. Since every "high" tier LR exceeds 1.0,
the current engine's posterior is monotonically non-decreasing in the number of agents that spoke.

---

## D-008 — Agents run blind; no anchors

**Date:** 2026-08-27 (restating §5) · **Status:** PROPOSED — not yet implemented

**Decision.** Orchestration is a plain `asyncio.gather` fan-out. The `anchors` parameter is removed
from `analyze()`. Anchored execution becomes a labelled ablation, not the default.

**Rationale.** Running static first and passing its finding keys downstream correlates the agents
and breaks the conditional independence the fusion math assumes. Confirmed in
`orchestrator.py:111-124`, explicitly labelled "Phase 1"/"Phase 2".

The audit found a second, worse consequence: because the context agent constructs its own key from
a hard-coded CWE-862 literal and static has no CWE-862 sink, the two key spaces are disjoint, so
the anchor filter at `context-agent/agent.py:107` deletes *every* context finding. The agent
contributes nothing at all under the orchestrator — and does not abstain either.

---

## D-009 — Debate emits its own evidence; it never overwrites the posterior

**Date:** 2026-08-27 (restating §5) · **Status:** PROPOSED — not yet implemented

**Decision.** Debate emits evidence with `agent_id="debate.synth"` carrying its own calibrated LR,
fused like any other witness.

**Rationale.** Overwriting destroys calibration exactly on the contested cases and makes the debate
step unmeasurable. Confirmed at `fusion/debate.py:176`.

**Additional decision: delete `_heuristic_debate_resolution` outright** rather than porting it.
Because `llm_api_key` defaults to `None`, that heuristic is the *default* path: it substring-matches
lowercased source and assigns a hard-coded 0.25 or 0.85, replacing the posterior with a magic
constant. It also lists `"int("` as a sanitizer keyword — and `"int("` is a substring of `print(`,
so any code containing a print statement is classified sanitized and scored 0.25. There is no
version of this function worth keeping.

---

## D-010 — Likelihood ratios, prior, and threshold are measured, never hardcoded

**Date:** 2026-08-27 (restating §5/§6) · **Status:** PROPOSED — not yet implemented

**Decision.** LRs fitted on the calibration split with Laplace smoothing and clamping. Prior
measured, then rescaled from the balanced corpus (~50%) to the real base rate (~2–5% of changed
functions), with the rescaling recorded. Threshold selected from a precision-recall sweep on the
validation split. All of it emitted to `calibration.json`, which records the corpus commit hash
that produced it.

**Rationale.** This *is* the project. A stated 87% that was not measured is exactly the failure the
paper criticises in existing tools. Currently LRs, prior (`0.05`) and threshold (`0.70`) are all
hardcoded in `engine/config.py`, and no corpus, splits, or `calibration.json` exist.

**Consequences.** Nothing numeric can be fixed before the corpus exists — this is why corpus
construction gates fusion work in `PLAN.md`. Also: delete the `bench` command's fabricated metrics
(`static-agent/cli.py:90-96` returns hard-coded `precision: 1.0, recall: 1.0, fpr: 0.0`) so nothing
can report perfect scores again.

---

## D-011 — `structural.taint` and `structural.semgrep` contribute **one** LR between them

**Date:** 2026-08-27 · **Status:** PROPOSED — **new decision, not covered by §5**

**Context.** Not addressed in `PROJECT_CONTEXT.md`. Surfaced by the audit.

**Decision.** The static agent is one witness. Its two backends are combined into a single evidence
contribution before fusion, not fused as independent agents.

**Rationale.** `engine/config.py:11-20` gives them separate LR table entries, so two "high" hits
multiply to 8.5 × 7.0 = **59.5×** from what is really one agent. Both are rule-based analyses of the
same source text in the same package — maximally correlated, and precisely the kind of shared
failure mode the four-agent heterogeneity argument exists to avoid. This is an independence
violation distinct from anchoring (D-008), and it inflates posteriors exactly where the project
claims rigor.

**Open.** How to combine them — max, noisy-OR, or a learned combination — should be decided with
corpus data rather than now.

---

## D-012 — The context agent emits under the incoming `finding_key`

**Date:** 2026-08-27 (restating §5) · **Status:** PROPOSED — not yet implemented

**Rationale.** With its own key it is architecturally inert: prior odds 0.0526 × its best ratio 4.2
= posterior 0.18 against a 0.70 threshold. It could never alert and never corroborate. It is a
corroborating witness, not a soloist.

**Consequences.** Its reasoning must be genuinely retrieval-driven. The audit found the current
"cross-PR regression evaluator" is four hard-coded substring tests for `stripe_charge`, with no LLM
client; `prompts/cross_pr_v1.md` is referenced by no code, and retrieved documents never influence
what is detected. This is a rewrite, not a fix.

---

## D-013 — `ChangeUnit` is one changed function, not one changed file

**Date:** 2026-08-27 (restating §5) · **Status:** PROPOSED — not yet implemented

**Decision.** Extract units with tree-sitter over fetched file blobs — one per changed function or
method, carrying `pre_src` (nullable), `post_src`, `imports`, `decorators`, `enclosing_class`,
`is_test_file`.

**Rationale.** `github/parser.py:111-118` currently emits one unit per file with `symbol=None`, and
reconstructs `post_src` by concatenating diff hunk fragments. The result is syntactically broken,
line numbers are wrong, and every finding in a file shares a key component of `''`. No structural
analysis can be correct on that input, so this blocks the taint engine.

Fetching real blobs also fixes a silent data-loss path: files for which GitHub omits `patch` (large
diffs) are currently skipped without a trace (`parser.py:102`).

---

## D-014 — PR title and description travel as separate optional `pr_context`

**Date:** 2026-08-27 (restating §5) · **Status:** PROPOSED — not yet implemented

**Rationale.** They are PR-level not unit-level, attacker-controlled and unverifiable, and absent
from corpus cases. Embedding them would make agents behave differently on corpus runs than in
production, corrupting calibration. The context agent currently embeds PR title and description
into its indexed document (`rag/ingest.py:10-28`), which does exactly this.

---

## D-015 — Oversized units abstain with `unit_too_large`; never truncate

**Date:** 2026-08-27 (restating §5) · **Status:** PROPOSED — not yet implemented

**Rationale.** Truncated analysis produces confident-looking findings from half-read code, biased
toward over-reporting, and silently invalidates calibration. Per-agent thresholds.

**Audit note.** The semantic agent has no size check of any kind. It does not truncate — but it does
not abstain either: an oversized unit trips the budget `break` and returns `[]`, which reads
downstream as "analysed, clean". See D-005.

---

## D-016 — pgvector, not ChromaDB

**Date:** 2026-08-27 (restating §4) · **Status:** PROPOSED — not yet implemented

**Rationale.** Survives restarts, one less service, and allows metadata filtering and similarity
search in one query — which is what makes per-repository filtering cheap.

**Consequences.** Repository isolation must be enforced at query time and `repo` stored in metadata.
Currently all repositories share one global Chroma collection, `unit.repo` is never queried, and it
is not even *stored* — so a filter cannot be added without a full re-ingest. One repo's PR diffs can
surface as another repo's review context.

**Also:** `sentence-transformers` is absent from the context agent's `pyproject.toml`, so the
default install silently falls back to an MD5 term-hashing vector — 384 floats with no semantic
meaning. Whatever replaces it must fail loudly, not degrade silently.

---

## D-017 — HMAC verification before anything else

**Date:** 2026-08-27 (restating §2/§6) · **Status:** PROPOSED — not yet implemented

**Decision.** The API verifies `X-Hub-Signature-256` before parsing the payload, enqueues, and
returns 202. It performs no analysis.

**Rationale.** `github/webhook.py` has no signature verification anywhere;
`github_webhook_secret` is defined at `config.py:70` and never read. Anyone who learns the URL can
forge a `pull_request` payload, make the bot fetch arbitrary repositories, post comments under the
project's token, and drive LLM spend. This is the most urgent item in the audit and is independent
of every other decision here.

Processing also runs entirely inline — with a blocking `requests.get` inside an `async def`, which
stalls the event loop — so GitHub's 10s limit will be exceeded on any non-trivial PR.

---

## D-018 — Repository restructured to the workspace layout, as a pure move

**Date:** 2026-08-27 · **Status:** ACTIVE · **Implements** D-002 · **Branch:** `refactor/monorepo-layout`

**Decision.** Move the four standalone packages into `packages/`, add the missing workspace members
as documented stubs, and archive superseded specs — **without changing any analysis code**.

| From | To |
|---|---|
| `codesheriff-static-agent/` | `packages/agent_static/` |
| `codesheriff-semantic-agent/` | `packages/agent_semantic/` |
| `codesheriff-context-agent/` | `packages/agent_context/` |
| `codesheriff-engine/` | `packages/engine/` |
| `codesheriff-engine/src/codesheriff_engine/contracts.py` | `packages/contracts/src/codesheriff_contracts/contracts.py` |
| `00-START-HERE.md`, `01-static-agent-BUILD.md`, 3 × `*_implementation_summary.md` | `docs/history/` |

Deleted: the three remaining vendored `contracts.py` copies, four `test_contract_integrity.py`,
and the root `main.py` / `github_service.py` / `requirements.txt`. Added as stubs:
`packages/{corpus,agent_runtime}`, `apps/{api,worker,dashboard}`.

**Rationale for keeping it a pure move.** Restructuring and rewriting at once produces a diff nobody
can review, and this project's central problem is that plausible-looking code went unexamined.
`git mv` preserves per-file history — 124 renames — so contributor authorship survives, which
matters for a final-year project's provenance (D-003).

The three vendored `contracts.py` copies were verified byte-identical to the promoted canonical
copy (`9a4b2337af7c9678…`) before deletion, so nothing was lost. `test_contract_integrity.py` was
deleted rather than ported: it gave false assurance, having been silenced by rewriting its expected
hash (`AUDIT.md` 4.8). `import-linter` contracts in the root `pyproject.toml` replace it — an agent
importing a sibling, the engine, or infrastructure now fails CI.

**Consequences — the tree does not run.** Agent imports still point at the deleted vendored copies.
This is deliberate: `PLAN.md` Chapter 2 rewires them as part of rewriting the contract, and pointing
them at the *current* `contracts.py` would only re-entrench a contract known to be wrong
(D-004…D-006). The test suite fails until Chapter 2 lands.

`apps/api` deliberately does **not** mount the existing webhook router. It has no HMAC
verification, and wiring it unchanged would carry a live security hole (`AUDIT.md` 0.1) into the new
layout under a name — "the API app" — implying it had been reviewed. It stays a health endpoint
until D-017 is implemented.

**Archived rather than deleted.** `docs/history/` keeps the superseded specs with a README
explaining what each gets wrong and why. Deleting them would remove the paper trail for the report's
account of how the design diverged from its implementation — and that account is the most useful
thing this repository currently contains.

---

## D-019 — Contract v2.0.0: three evidence kinds, and a key that two agents can agree on

**Date:** 2026-08-27 · **Status:** ACTIVE · **Implements** D-004, D-005, D-006, D-013, D-014 ·
**Closes** `AUDIT.md` 1.1, 1.2, 1.3, 1.5 · **Chapter:** 2

**Decision.** Rewrite `packages/contracts` and rewire all four packages onto it. The contract now
carries `EvidenceKind` (`DETECTION` / `SILENCE` / `ABSTENTION`), `covered_cwes` on SILENCE, the
closed `IN_SCOPE_CWES` set, `PRContext` as a separate model, `pre_src` nullable, `decorators` and
`enclosing_class` on `ChangeUnit`, and `finding_key(file, qualified_symbol, cwe)` — no sink
expression.

**Non-detections carry no `finding_key` at all.** This is the part that goes beyond the plan and is
worth stating plainly. SILENCE and ABSTENTION are statements about a *unit*, not about a finding, so
there is nothing for them to be keyed by. Making the field `None` and enforcing it in a validator
closes both raw-string bypasses in one move — `contracts.py`'s `f"abstain:{unit_id}:{reason}"` and
`fusion/bayes.py`'s `"abstention:all_agents"` — and means no non-finding can ever enter the key
space again. A test asserts the rejection.

**`ChangeUnit.qualified_symbol` and `ChangeUnit.key_for(cwe)` are the only sanctioned way to build a
key.** Removing the sink expression fixes one route to divergent keys; leaving each agent to
assemble the symbol name itself would immediately open another. Every call site now goes through the
unit.

**Consequence — the static agent had to learn to deduplicate.** Once the key excludes the sink
expression, several source-sink pairs inside one function collapse onto one key. Emitting each
would apply one agent's likelihood ratio several times to a single finding, which is not what
conditional independence *across agents* licenses. Both static backends now keep the
highest-scoring evidence per key.

---

## D-020 — SILENCE requires a non-empty `covered_cwes`, so an agent with no rules must abstain

**Date:** 2026-08-27 · **Status:** ACTIVE · **Refines** D-006 · **Chapter:** 2

**Decision.** The contract rejects a SILENCE with empty `covered_cwes`. An agent that ran but
covered nothing has not produced evidence of absence — it has failed to look, which is ABSTENTION.

**Why this surfaced.** `StaticConfig.rules_dir` defaulted to a bare relative `Path("rules")`,
resolved against the current working directory. It only ever worked when tests were run from inside
`packages/agent_static/`. From the workspace root the catalog loaded empty, and the taint engine
reported *silence* on every unit — an agent with zero rules loaded telling the fusion engine it had
checked and found the code clean. That is the most dangerous statement an agent in this design can
make, and it took the contract validator to expose it.

Two fixes: the rules moved to `src/static_agent/rules/` (they were outside the package and therefore
absent from the built wheel — the installed agent could never have found them), `rules_dir` now
defaults package-relative, and the engine returns an explicit `rules_unavailable` abstention when the
catalog is empty for the unit's language.

---

## D-021 — Out-of-scope CWEs are dropped, never relabelled

**Date:** 2026-08-27 · **Status:** ACTIVE · **Implements** the `IN_SCOPE_CWES` closed set ·
**Chapter:** 2

**Decision.** `Evidence.detection()` rejects any CWE outside `IN_SCOPE_CWES`. The Semgrep mapper,
which previously defaulted unmatched rules to `CWE-200`, now returns `None` and the runner drops the
result.

**Why.** `CWE-200` is not in the closed set, so every such finding was an assertion about a CWE the
project has never calibrated against and does not claim to cover. Inventing scope is worse than
missing a finding: a miss shows up in recall, an invention corrupts the denominator of every
calibrated number.

The semantic agent's hallucination gate gained the same check. That check is listed under Chapter 11
in `PLAN.md`, but the gate is where `IN_SCOPE_CWES` has to be enforced for the LLM path, so it landed
here — along with the other two weakened checks in `AUDIT.md` 3.10, since they sat on adjacent lines:
the file comparison is now exact rather than basename (which accepted a finding about
`app/models/user.py` against `tests/user.py`), and the `+ 5` line-number slack is gone, since
accepting evidence lines that do not exist in the unit is precisely the hallucination the gate is
for. `AUDIT.md` 3.9, 3.11 and 3.12 remain open for Chapter 11.

---

## D-022 — Agents run blind: the orchestrator's two-phase anchor pass is deleted

**Date:** 2026-08-27 · **Status:** ACTIVE · **Implements** D-008 · **Closes** `AUDIT.md` 1.5 ·
**Chapter:** 2

**Decision.** Remove the `anchors` parameter from `analyze()` in all three agents, the engine's
`Orchestrator`, and the context agent's `--anchor` CLI flag. `Orchestrator.analyze_change_unit` now
runs every agent in one `asyncio.gather` fan-out.

**Why the parameter had to go rather than default to `None`.** As long as the signature accepted
anchors, the anchored path remained reachable and would be reintroduced by the first person who
found it convenient. The context agent's `no_anchor` abstention is gone with it — that abstention
made the agent architecturally incapable of contributing anything the static agent had not already
found, and the static agent has no CWE-862 sink, so the anchor set could never contain the only key
the context agent produces. It returned `[]` on every input, and its test suite never noticed
because the test called the internal function directly instead of `analyze()`.

---

## D-023 — One toolchain configuration, at the workspace root

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 2

**Decision.** Delete the per-package `[tool.ruff]` and `[tool.mypy]` sections from the three agent
packages. The root `pyproject.toml` configures both for the whole workspace.

**Why.** Those sections declared only `line-length` and `target-version`, but a local `[tool.ruff]`
shadows the root config for that package's files and silently applies a *different* rule set — the
agent packages were being linted without the root's import-sorting and naming rules at all. Four
copies of a configuration drifting apart is the same failure mode as four copies of `contracts.py`,
and it is worth fixing the same way.

Also settled here, all of it discovered by running the tools for the first time:

- Three agent distributions renamed to `codesheriff-agent-{static,semantic,context}`, matching their
  directories and the names the root workspace config and `apps/worker` already referenced.
  `uv sync` could not resolve the workspace until they agreed.
- `pytest` runs with `--import-mode=importlib`: several packages have a `tests/test_agent.py`, and
  the default prepend mode collides on module name.
- `mypy` excludes `tests/` — every package has a `tests/conftest.py`, and mypy resolves them to one
  module name and refuses to continue. There is no way to disambiguate while each package keeps a
  directory called `tests`. Strict checking covers all 57 source files.
- `import-linter` needs `include_external_packages = true`, because the forbidden-modules contract
  names third-party packages.
- `ruff format` was run across the tree once, establishing a formatted baseline.

**Verified, not assumed.** A deliberate `static_agent -> semantic_agent` import was added and
`lint-imports` failed on it with the expected message; the probe was then removed.

---

## D-024 — `covered_cwes` serialises as a sorted list

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 2

**Decision.** `Evidence.covered_cwes` is a `frozenset` in Python and a sorted list on the wire, via a
Pydantic field serialiser.

**Why.** A `frozenset` is not JSON-serialisable, and `Evidence` has to survive a round trip through
PostgreSQL (Chapter 3), the REST API (Chapter 15) and the dashboard (Chapter 16) — the CLI crashed
on `json.dumps` the first time an agent emitted a SILENCE. Sorted rather than arbitrary order
because serialised evidence must be byte-stable: snapshot tests and any content hash over an
evidence record depend on it.


---

## D-025 — Persistence is its own package, and the engine may not import a database client

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 3

**Context.** Chapter 3 needed a home for SQLAlchemy models, Alembic and the pgvector store. The
obvious one was `codesheriff_engine/db/`: no new package, and the existing layers contract already
put both apps above the engine.

**Decision.** Persistence lives in `packages/storage` (`codesheriff_storage`). The layers contract
becomes `api | worker → storage → engine → contracts`, and a new `forbidden` contract stops
`codesheriff_engine` and `codesheriff_contracts` importing `codesheriff_storage`, `sqlalchemy`,
`alembic` or `psycopg` at all. `apps/worker` gains the dependency (it owns the pipeline, so it owns
the writes); `apps/api` gains it in Chapter 15 when the dashboard needs reads.

**Why.** §6 requires every fitted number to be reproducible from the calibration split and a
recorded corpus hash. A fusion or calibration module that *can* open a session makes that an
honour system — the next person who needs a lookup adds one, and the reproducibility claim quietly
stops being checkable by anything but review. Agent isolation is already a CI-enforced property
rather than a convention; this is the same move for research integrity. It also keeps the fusion
package a pure function of its inputs, which is what makes a corpus run and a production run
comparable at all.

**Consequences.** Storage may import the engine (it maps `FusionResult` to rows); the engine can
never import storage. A future calibration job reads its corpus from files, not from the database.
Verified by adding `import sqlalchemy` to `fusion/bayes.py` and watching `lint-imports` break, then
removing it.

---

## D-026 — Contract invariants are CHECK constraints as well as Pydantic validators

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 3

**Decision.** The three-kind evidence rules, the closed CWE set and the `finding_key` format are
restated in the schema: `kind = 'detection'` requires a key and an in-scope CWE, SILENCE requires a
non-empty `covered_cwes`, ABSTENTION requires a reason, `finding_key` must match `^[0-9a-f]{16}$`,
and `cwe` must be one of `IN_SCOPE_CWES`. The model constraints are generated from
`IN_SCOPE_CWES`; the migration writes the same list out literally, and a `db`-marked test compares
the migrated database against the metadata so the two cannot drift apart unnoticed.

**Why.** Every Tier 1 defect in `AUDIT.md` was an invariant enforced in exactly one place and then
bypassed from another. The vendored contract's checksum test was defeated by rewriting the expected
hash. Raw keys such as `abstain:{unit_id}:{reason}` passed a Pydantic model that had no opinion
about the string it was handed. A second, independent enforcement point costs one migration.

**Consequences.** Widening `IN_SCOPE_CWES` now requires a migration — intended friction for a change
that invalidates every number fitted against the old set. The `findings.finding_key` regex is also
what stops `fuse_all_evidence`'s synthetic `abstention:all_agents` key from being stored as if an
agent had produced it; `mapping.persistable_findings` drops it earlier, with a warning, and
Chapter 9 removes it at source.

---

## D-027 — Source code is never persisted; bounded excerpts only, capped at write time

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 3

**Context.** §6 says persisted records hold findings, evidence and hashes — never full file
contents. Two things resist that literally. A taint-path artifact names the lines it walked, and
that artifact *is* the explanation rendered into the PR comment. A RAG precedent chunk must hold the
text it was embedded from, or retrieval can neither be shown as evidence nor re-embedded when the
embedding model changes.

**Decision.** `change_units` stores `post_src_sha256`, `pre_src_sha256`, byte and line counts,
symbol names and decorator names — there is no source column, and a metadata-level test fails if one
appears under any of the usual names. Excerpts are permitted in exactly two places,
`evidence.artifacts` and `precedent_chunks.content`, capped by `redaction.py` at 300 characters per
line, 20 lines per artifact, 8 KiB of serialised artifacts per evidence row, and 4 KiB / 60 lines
per precedent chunk. The chunk cap is a CHECK constraint as well. Every cut is marked in the text.

**Why.** Storing whole files would put customers' private source in a database that also holds
credentials — the thing §6 exists to prevent. Storing nothing would make findings unexplainable and
the precedent store un-rebuildable. A cap is the smallest thing that satisfies both, and putting it
in one module means it cannot be forgotten at a call site.

**Note.** This is not the truncation D-015 forbids. That rule protects *analysis input*: an agent
must abstain rather than reason about half a function. This clips an explanation already produced
from the whole unit, and says where it clipped.

---

## D-028 — Synchronous sessions

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 3

**Decision.** One synchronous engine and session factory, psycopg3, `postgresql+psycopg://`.

**Why.** Celery is synchronous and owns the pipeline; the API only verifies, enqueues and returns
202 until Chapter 15. An async stack would mean two engines, two session factories and two test
harnesses to serve one real consumer. `expire_on_commit=False`, because the worker commits an audit
and then goes on using its id. Revisit when the dashboard's read path justifies it; the models are
shared either way.

---

## D-029 — Database tests run against real Postgres, or they do not run

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 3

**Decision.** Tests that touch Postgres carry `@pytest.mark.db` and are skipped unless
`CODESHERIFF_TEST_DB` names a throwaway database. `uv run pytest` stays green on a machine with no
services running. Alembic builds the schema in those tests — never `Base.metadata.create_all`.

**Why.** pgvector cannot be faked on SQLite, and a schema built from metadata is not the schema
production runs: the difference is exactly where a missing migration hides. Skipping loudly is
better than a fake backend that passes for the wrong reason — this repository already has a test
suite that reports 100% while three of four components are shells.

**Consequences.** CI needs a Postgres service container for the `db` job. Anyone who never starts
Docker sees 16 skips, not 16 failures — and never sees the migration or vector coverage either, so
CI must run it.

---

## D-030 — Vector indexes are declared on the model, not only in the migration

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 3

**Context.** The HNSW index on `precedent_chunks.embedding` was first created with raw SQL in the
migration, because `CREATE INDEX ... USING hnsw (embedding vector_cosine_ops)` has no obvious
declarative form. Alembic's comparison against `Base.metadata` then reported it as drift and wanted
to drop it — caught by `test_no_pending_schema_changes` on its first run against a real database.

**Decision.** Every index, including operator-class indexes, is declared in `__table_args__` with
`postgresql_using` / `postgresql_ops` **and** created through `op.create_index` in the migration.
No schema object exists only as raw SQL.

**Why.** Anything the models do not know about is drift as far as autogenerate is concerned, and the
first `--autogenerate` in a later chapter would have quietly proposed dropping the index that makes
retrieval fast. A schema object that exists in the database but not the metadata is a schema object
nobody is comparing.

**Note.** `CREATE EXTENSION IF NOT EXISTS vector` stays raw — an extension is not a metadata object,
and it is idempotent.

---

## D-031 — The dashboard is a separate npm project, not a workspace member

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 4

**Decision.** `apps/dashboard` is a standalone Next.js 16 / React 19 / Tailwind v4 / shadcn/ui
project with its own `package.json` and lockfile. It is not in the `uv` workspace, shares no build
step with Python, and adds two gates of its own: `npm run lint` and `npm run build` (which includes
the TypeScript check).

**Why.** There is nothing for the two toolchains to share. §6 already forbids Next.js API routes as
a backend and forbids business logic in TypeScript, so the only coupling is the shape of the JSON
the API will return — and that is a contract, not a build dependency. Keeping them separate means a
Python change can never break the frontend build and vice versa.

**Consequences.** CI grows a Node job. `apps/dashboard/node_modules` is gitignored; the lockfile is
committed. The generated `AGENTS.md` / `CLAUDE.md` in that directory are committed too — `next dev`
rewrites them if removed, and they point at the bundled version-correct docs, which matter because
Next 16 changed App Router conventions (typed `PageProps`, awaited `params`, and a shadcn built on
Base UI's `render` prop rather than Radix's `asChild`).

---

## D-032 — No probability reaches the screen without its calibration state

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 4

**Decision.** Every posterior renders through one component, `<Posterior>`, which reads the audit's
calibration artifact. While `isProvisional` is true the number is labelled "provisional — not
calibrated" in the markup itself; once a fitted artifact exists the same component shows its ECE and
sample size. No page formats a percentage on its own.

**Why.** The thesis is that a stated 87% must correspond to being right 87% of the time. Existing
tools emit confident numbers with no reliability behind them, which is exactly why developers learn
to ignore them — a dashboard that renders a bare "87%" before Chapter 14 fits anything would be the
same failure with nicer typography. D-010 already forbids treating hand-set ratios as calibrated;
this makes it structural rather than a rule someone has to remember on every new page.

**Consequences.** Chapter 15 may make this display richer. It may not make it quieter, and any new
surface showing a probability goes through the same component.

---

## D-033 — The `(protected)` route group is structure, and says so until Chapter 5

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 4

**Context.** Chapter 4's deliverable includes a "protected layout", but authentication is Chapter 5.
A layout that calls `getSession()` and renders looks like a security boundary whether or not one
exists behind it.

**Decision.** The session helper is named `getPlaceholderSession()`, returns a type with
`isPlaceholder: true`, cannot fail, and carries a file-level comment saying it protects nothing. The
layout renders a visible "mock data · no backend · not signed in" banner. Chapter 5 replaces the
helper and adds the redirect the route group's name implies.

**Why.** The alternative — a plausible-looking `getSession()` that always succeeds — is how a
placeholder survives into a release. Making the absence of auth loud in the name, the type and the
UI means the day it becomes real is a day someone deletes an obvious lie, not a day nobody notices.

---

## D-034 — GitHub App configuration: permissions, events, and one comment that gets edited

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 5

Resolves `PROJECT_CONTEXT.md` §7 open question 1.

**Permissions requested.** Repository level only, and the smallest set that lets the pipeline work:

| Permission | Level | Why |
|---|---|---|
| Metadata | Read | Mandatory for every App |
| Contents | Read | The changed file contents the agents analyse |
| Pull requests | Read & write | Read the diff; post and edit the review comment |

Nothing else. In particular **no Checks**, no Actions, no Administration, no Members, and no write
access to Contents. §6 puts auto-merge and auto-commit of patches out of scope, so an App that could
write to a branch would hold a capability the product deliberately does not use — and Chapter 17's
patches are suggestions inside a comment, which Pull requests: write already covers.

**Events subscribed.** `pull_request`, `installation`, `installation_repositories`. Not `push`: a
force-push to a PR branch already arrives as `pull_request` with action `synchronize`, and
subscribing to `push` would deliver every commit on every branch, most of which is not under review.

**Force-push behaviour.** Each head SHA is a new audit. `audits` is deliberately not unique on
`(repository_id, head_sha)` — re-analysing a commit under a new calibration artifact is how a
recalibration gets evaluated. An audit still running for a superseded head is abandoned rather than
finished: its findings would describe code that is no longer at the head of the branch, and a
posterior about a commit nobody can see is worse than no posterior.

**One summary comment, edited in place — not inline review comments.** `audits.github_comment_id`
holds the comment id, and each subsequent push edits that comment rather than adding another. Three
reasons, in order of weight:

1. **Calibration has to be legible in one place.** The claim this project makes is about the
   posterior and the reliability behind it. Scattered across inline threads, there is nowhere to
   state "this number is provisional" once, and a reader assembles their own impression from
   fragments.
2. **Inline comments cannot be updated as a set.** They anchor to `(path, line)` in a specific
   commit. After a force-push the anchors are stale, GitHub marks them outdated, and the only way
   to refresh them is to post a new review — which is precisely the duplication this decision
   exists to prevent.
3. **A single edited comment is the quietest thing a bot can be.** The failure mode this project
   attacks is developers learning to ignore an alerting tool.

Inline comments are reconsidered in Chapter 16 or 17, when there is a fitted threshold and a reason
to point at an exact line. Until then, the summary comment links to the finding page.

---

## D-035 — Authorisation is derived from GitHub at sign-in, never stored as an ACL

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 5

**Decision.** At sign-in, the user's OAuth token is used to read `GET /user/installations`, and that
list of installation ids is stored on their session row. Every query is scoped by it — repository
listing and the analysis toggle both take `installation_ids` and return nothing for an empty list.
There is no permissions table, no roles, no per-repository grants.

**Why.** GitHub is the authority on who may see what, and it already answers the question. A stored
ACL is a copy of that answer which begins going stale the moment somebody's access changes on
GitHub, and reconciling it is the kind of background job that fails silently. §6 also puts
multi-tenancy out of scope; a permissions table is where that scope creep would start.

**The trade-off, stated plainly.** Access is a snapshot, so a revocation on GitHub is reflected at
the user's next sign-in rather than immediately. Sessions therefore last 8 hours and are never
extended. The alternative — storing a GitHub credential so the question can be re-asked on every
request — trades a bounded staleness window for a permanent secret at rest (D-036).

**Consequences.** The empty-list case is the whole access check, so it is tested at both layers:
`list_repositories(installation_ids=[])` returns `[]` rather than falling through to every row, and
the API returns 404 — not 403 — for a repository outside the session, which avoids confirming that
it exists.

---

## D-036 — The database holds no GitHub credential and no session token

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 5

**Decision.** Two absences, both enforced by the shape of the code rather than by care:

- **No GitHub token is stored.** `GitHubGateway.sign_in()` takes an authorisation code and returns
  identity plus installation ids. There is no method on the interface that hands a caller a token,
  so there is nothing to persist by accident. `githubkit` performs the exchange inside its auth
  strategy, and the client goes out of scope when the call returns.
- **The session token is stored only as a SHA-256.** The cookie holds 256 random bits; `sessions`
  holds a one-way image of it. Reading the table does not hand over live sessions. Plain SHA-256
  rather than a password hash on purpose: the token is random, not human-chosen, so there is
  nothing for a slow KDF to defend against.

Sessions are rows rather than signed tokens specifically so that logout can revoke server-side.
Clearing a cookie only asks a browser to forget; a copy taken beforehand must stop working, and
there is a test that steals one and checks that it does.

**Why.** §6 keeps credentials out of persisted records. A leaked database that yields replayable
GitHub access is a far worse outcome than one that yields findings, and the only reliable way to
prevent it is to never have the credential in the first place.

---

## D-037 — The installation callback grants nothing

**Date:** 2026-08-27 · **Status:** ACTIVE · **Chapter:** 5

**Context.** After installing the App, GitHub redirects the user to the configured setup URL with
`?installation_id=...`. The obvious implementation adds that id to the current session.

**Decision.** `/auth/install/callback` logs the parameter and ignores it, then redirects into
`/auth/login`, which re-derives the whole installation list from GitHub.

**Why.** That parameter arrives in a URL the user controls. Anyone could request the endpoint with
somebody else's installation id, and if the handler trusted it, a session would gain visibility of
repositories it was never granted. Re-running OAuth makes GitHub the authority, which is the only
source that cannot be forged by editing an address bar. For a user who has already authorised the
App the redirect is silent, so the cost is one hop.

**Consequences.** The path that widens a session is the same path that created it, so there is one
place to audit rather than two. The repository sync also happens there, which means no unauthenticated
request can cause writes on behalf of an installation.

---

## D-038 — `X-GitHub-Delivery` is an idempotency key, stored and unique

**Date:** 2026-08-28 · **Status:** ACTIVE · **Chapter:** 6

**Context.** GitHub delivers webhooks *at least* once. A delivery that times out, or that answers
with a 5xx, is redelivered — and Chapter 6 deliberately answers 503 when the broker is unreachable,
which makes redelivery a designed-for path rather than an edge case.

**Decision.** `audits.delivery_id` holds the `X-GitHub-Delivery` header and carries a UNIQUE
constraint. The handler looks for an existing audit with that id before opening a new one and, if
it finds one, answers 202 with `{"status": "duplicate"}` and does not enqueue again.

**Why the constraint and not just the lookup.** The lookup makes the common case correct; the
constraint makes the racing case correct. Two deliveries arriving together both find nothing and
both insert, and only a database-level guarantee stops the second. Same reasoning as D-026: an
invariant the application checks is an invariant until somebody adds a second writer.

**Why not dedupe on `(repository_id, head_sha)` instead.** Because D-034 requires that pair *not*
to be unique — re-analysing one commit under a new calibration artifact is how a recalibration gets
evaluated. Delivery id is orthogonal to that: it identifies one HTTP request GitHub made, which is
exactly the thing that must not happen twice.

**Consequences.** `delivery_id` is nullable, because an audit opened by any other route — a corpus
replay, a manual re-run in Chapter 15 — has no delivery behind it. A redelivery after a broker
failure finds the existing row and does **not** republish it; recovering a stranded `queued` audit
is a sweep's job, and the row is visible and diagnosable in the meantime.

---

## D-039 — `superseded` is a status, not a failure

**Date:** 2026-08-28 · **Status:** ACTIVE · **Chapter:** 6

**Context.** D-034 settled that an audit still running for a superseded head is abandoned rather
than finished. It did not say what the row then says. The four statuses in migration 0001 were
`queued`, `running`, `succeeded`, `failed`, so the cheap option was `failed` with an
`error_reason` of "superseded".

**Decision.** `audit_status` gains a fifth value, `superseded`, in migration 0003.

**Why.** Pushing again is the single most ordinary thing a developer does to a pull request. Under
the cheap option a five-commit branch produces four failed audits, the dashboard is mostly red, and
the genuine failure rate — the number that says whether this system works — becomes unreadable by
anyone who has not memorised the convention. A distinct state costs one migration and keeps
"failed" meaning failed.

**Cost, recorded honestly.** Postgres will not let `ALTER TYPE ... ADD VALUE` be used inside the
transaction that adds it, and Alembic runs a migration in one transaction, so the enum is replaced
rather than extended: create a new type, cast the column across, drop the old one, rename. The
CHECK constraint from 0001 has to come off first and go back on afterwards, because Postgres stores
it with the literal already bound to the old type — without that, the ALTER fails with "operator
does not exist: audit_status_new <> audit_status". The downgrade folds `superseded` rows into
`failed` with a reason, exercised by a test with a real row in it: every other migration test runs
against an empty `audits` and cannot catch a data migration at all.

**Consequences.** `fail_audit` refuses to move a superseded audit — being overtaken is not a
failure, and a worker that crashes on an already-abandoned run must not relabel it. `claim_audit`
refuses it too, so an in-flight task stops at the claim.

---

## D-040 — The API addresses the worker's task by name, never by import

**Date:** 2026-08-28 · **Status:** ACTIVE · **Chapter:** 6

**Decision.** `apps/api` publishes with `celery.send_task("codesheriff.run_audit", [audit_id])`. It
does not import `codesheriff_worker`. The name is duplicated as a constant in each package, with a
test asserting the two are equal.

**Why.** The `import-linter` layers contract puts both apps on the same layer, so the import is
already forbidden — but the contract is right rather than merely inconvenient. Importing the worker
would pull the agents, the LLM client, `tree-sitter` and Wasmtime into the process that has to
answer GitHub in under three seconds, and would put a directly callable pipeline function in scope
of the request handler. That is `AUDIT.md` 4.3 with one import statement standing between it and
recurring.

**The cost, and what pays for it.** A duplicated string can drift, and drift is silent: the API
keeps queueing audits, the worker keeps waiting for a task nobody sends, and the symptom is
indistinguishable from a worker that is not running.
`apps/api/tests/test_task_name_contract.py` asserts the two constants match *and* that Celery
registered the task under that name — naming it in a constant is not the same as registering it,
and forgetting `name=` registers it under a module path instead. A test is not part of the import
graph the contract constrains, which is exactly why it may see both sides.

---

## D-041 — The queue carries an audit id and nothing else

**Date:** 2026-08-28 · **Status:** ACTIVE · **Chapter:** 6

**Decision.** The Celery message is a single UUID string. Repository, pull request number, head
SHA, installation and the previous comment id are all read from Postgres by the worker.

**Why.**

1. **A second copy can disagree with the first.** The audit row is written before the message is
   published. A message carrying the same facts is a snapshot that ages, and the first time the two
   differ nothing will say which is right.
2. **Redis is not storage.** No schema, no constraints, no retention guarantee. The `audits` table
   has CHECK constraints enforcing contract invariants (D-026); a message body has none.
3. **The payload is attacker-authored.** A pull request title and branch name are chosen by whoever
   opened the PR. Serialising them into a broker puts untrusted text in a component with no
   validation, waiting for the next consumer to trust it.

Celery is configured `json`-only for serialisation and accepted content, for the same reason: a
pickle deserialiser reachable from a queue is remote code execution for anyone who reaches Redis.

**Consequences.** The worker cannot run without a database, which is correct — it cannot write its
result anywhere else either. The order in the handler is fixed and only one order is safe: commit
the row, then publish. Committing first can strand a queued audit nothing was told about, which is
visible and recoverable; publishing first can hand a worker an id that a rollback removed, which
fails forever for reasons nothing records.

---

## D-042 — Each process loads only the credentials it can use

**Date:** 2026-08-28 · **Status:** ACTIVE · **Chapter:** 6

**Context.** `apps/api` and `apps/worker` both talk to GitHub as the same App, and the obvious move
is one settings object and one gateway shared between them.

**Decision.** Two settings classes (`ApiConfig`, `WorkerConfig`) and two gateways, with disjoint
contents. The API holds the OAuth client secret and the webhook secret; the worker holds neither.
The worker holds the LLM credentials from Chapter 11 onward; the API holds none. The App id and
private key are in both, because both mint installation tokens — shared as environment values, not
as a Python object.

**Why.** The union of two processes' credentials is a strictly larger blast radius than either, and
it grows by default: the next person adding a setting adds it to the shared object, and it reaches
a process with no use for it. The two also authenticate differently — the API acts as a *user*
through OAuth to answer "what may this person see" (D-035), the worker acts as an *installation* to
read a diff and write a comment — so a merged gateway would be one interface every implementation
had to satisfy in both roles.

**The duplication, stated plainly.** `require_github_app()` exists in both configs,
near-identically: about forty lines. That is cheaper than the alternative and, unlike the
alternative, it does not get worse as either side grows. A third consumer would be worth
revisiting; two is not enough to justify a shared package.

Also duplicated: `apps/worker/tests/payloads.py`, a copy of the API's schema-driven fixture
generator. The two test trees cannot import each other for the same reason the two packages cannot.
The module is generic and knows nothing about either app, so there is nothing app-specific to drift.

---

## D-043 — smee.io for local webhook delivery

**Date:** 2026-08-28 · **Status:** ACTIVE · **Chapter:** 6

Resolves the webhook-tunnelling half of `PROJECT_CONTEXT.md` §7 open question 4. The Docker Compose
half was settled in Chapter 1: Postgres and Redis in containers, the API and worker on the host.

**Decision.** Local development uses a smee.io channel, forwarded with `npx smee-client`. ngrok
stays documented as the alternative for when raw HTTP has to be inspected.

**Why smee.** The channel URL is permanent and needs no account, so the App's webhook URL is entered
once and never again — with ngrok's free tier the URL is per-session unless an account is created
and a static domain claimed, and a stale URL means deliveries that silently go nowhere. smee is
also GitHub's own tool for this, and it replays past deliveries, which matters here: the signature
is computed over exact bytes, and the cheapest way to debug a mismatch is to send the same bytes
again.

**Why ngrok is still worth naming.** It shows the full request and response, which smee does not. A
signature that verifies in a test and fails against GitHub is almost always a body-encoding
difference, and that is visible in ngrok's inspector and nowhere else.

**Consequences.** `PUBLIC_WEBHOOK_URL` is gone from `.env.example`. Nothing in either process needs
to know its own public address — the URL lives on the GitHub App, and the tunnel is a client the
developer runs, not configuration the application reads.

---

## D-044 — The corpus is 60 hand-written units in 30 twin pairs; cross-PR scenarios wait for Chapter 12

**Date:** 2026-08-29 · **Status:** ACTIVE · **Chapter:** 7

**Decision.** `packages/corpus` ships 60 units: three twin pairs for each of the ten CWEs in
`IN_SCOPE_CWES`. Every pair is the same function, in the same file, under the same symbol, once
vulnerable and once safe. The ~15 cross-PR scenarios that `PROJECT_CONTEXT.md` §5 also names are
**not** in this chapter; they land with the context agent in Chapter 12.

**Why 60 and not 20.** The chapter's stated bar is one vulnerable case and one safe twin per CWE,
which is 20 units. Twenty cannot carry a 60/20/20 split: validation and test would hold four units
each, and an ECE computed on four items is not a measurement. Three pairs per CWE is the smallest
number that leaves every split non-trivial.

**Why the cases are hand-written.** §5 already settled this — at this size every label must be
certain, and clean twins cannot be reliably extracted from real commits. Writing them also forced
the twins to be *near*: the safe member of `cwe-089-order-sort` still builds its query with an
f-string, and the safe member of `cwe-798-warehouse-connect` still passes a string literal to
`psycopg.connect`. A twin that differs only in the presence of the bug is what makes a false
positive measurable; a twin that also differs in style measures style.

**Why cross-PR scenarios wait.** A cross-PR scenario is a case plus a precedent history for the
context agent to retrieve against. §5 fixes that the agent indexes *per-symbol documents*, not
per-PR ones, but the document shape itself is Chapter 12's to design. Authoring fifteen histories
against a guessed schema now would mean rewriting them later, and a corpus rewritten after it has
been used to fit anything is worse than a corpus that arrives late.

**Consequences.** `corpus_hash` changes when they land. That is safe *only* because Chapter 14
fits the ratios and Chapter 12 precedes it — no calibration artifact will exist yet to invalidate.
If the order of those chapters ever changes, this becomes a real problem and the scenarios must be
authored first. `context.rag` is listed on only 6 of the 30 vulnerable cases (the CWE-862 and
CWE-639 ones) until then, which is the smallest positive count of any agent and is expected: it is
a corroborating witness, not a soloist.

**Also decided here.** One vulnerability per vulnerable case, never two. A unit carrying two
findings would need two labels and two keys, and the "did the agent find it" question would stop
being a lookup.

---

## D-045 — Splits are assigned by twin pair, and immutability is made detectable rather than claimed

**Date:** 2026-08-29 · **Status:** ACTIVE · **Chapter:** 7

**Decision.** `splits.json` assigns **`pair_id`**, never `case_id`, at 60/20/20 —
18 / 6 / 6 pairs, 36 / 12 / 12 units. Assignment is stratified by CWE from a recorded seed
(`20260829`). `codesheriff-corpus assign` will place unassigned pairs and **refuses to move a pair
that already has a split**.

**Why by pair.** PLAN.md asks for a test that fails if a twin pair is split. Assigning the pair
makes that unrepresentable rather than merely tested: twins differ by a sanitizer call, so a
vulnerable member in calibration and its safe twin in test would mean a ratio fitted on all but a
few characters of the case it is later scored against. The test exists anyway, because the
construction is a choice a later change could reverse while the other tests kept passing.

**Why 60/20/20.** Calibration has twelve cells to fill — four agents times three evidence kinds —
and a cell with two observations in it produces a ratio that Laplace smoothing is holding up
unaided. Validation and test each answer one scalar question and can afford to be smaller.

**Immutability is not enforced, and saying so matters.** The obvious mechanism is a committed
checksum verified by a test. That is precisely the mechanism this repository already defeated:
`AUDIT.md` 4.8 records the expected SHA-256 being rewritten to make the test pass. A guard whose
cheapest bypass is editing the guard is not a guard. What exists instead:

- `assign` will not move a settled pair, so growing the corpus cannot silently rebalance it;
- `split_hash` is recorded on every `calibration_runs` row, so a run fitted before an edit no
  longer matches the splits it claims to have been fitted on.

The property is **detection after the fact**, not prevention. That is honest and it is enough:
the failure this guards against is drift, not sabotage.

**The limitation, stated rather than engineered away.** Six pairs cannot cover ten CWEs. Every CWE
has at least one calibration pair — asserted by a test — but the validation and test splits each
reach only six of ten, and under this seed CWE-89 falls entirely inside calibration. So the final
ECE and Brier numbers are **aggregate claims across CWEs, not per-CWE claims**, and the paper must
report them that way. The seed was fixed before the draw was inspected and has not been rerolled;
reseeding until the distribution looked better is the exact behaviour §6 exists to prevent.

**Consequences.** `calibration_runs.corpus_hash` and `.split_hash` — nullable since Chapter 3 with
nothing to put in them — now have computable values. Both are defined over the *canonical loaded
form*, not raw file bytes: reflowing a comment in a `case.yaml` is not a change to the corpus and
must not invalidate a fitted run, while a line of `post.py`, a label, or a `detectable_by` entry is
and does. Both are independent of git, so they can be recomputed from an installed wheel.


**One defect found by running the CLI twice.** `corpus_hash` was different on every invocation.
`CorpusCase.detectable_by` is a `frozenset`, a frozenset iterates in an order derived from its
members' hashes, and Python randomises string hashing per process — so the serialised case, and the
hash over it, changed run to run. A calibration run could never have been shown to match the corpus
it was fitted on, which is the hash's only job.

Fixed with a field serialiser that sorts, which is the identical mechanism and identical reason
`Evidence.covered_cwes` carries one (D-024) — the contract had already solved this exact problem and
the corpus reintroduced it. No in-process test could catch it: `corpus_hash() == corpus_hash()` is
true within one interpreter. `test_hashes_are_stable_across_processes` runs the hash in subprocesses
under fixed and random `PYTHONHASHSEED` values, and produces five distinct hashes if the serialiser
is removed.

---

## D-046 — Corpus case sources are real `.py` files, and are data rather than code

**Date:** 2026-08-29 · **Status:** ACTIVE · **Chapter:** 7

**Decision.** A case is a directory holding `case.yaml`, `post.py`, and optionally `pre.py`, inside
the package so it ships in the wheel. `packages/corpus/src/codesheriff_corpus/cases/` is excluded
from `ruff` and from `mypy` in the root `pyproject.toml`.

**Why not source embedded in YAML.** The alternative was one YAML file per case with the code as a
block scalar. The code is the case: it has to survive tree-sitter, carry honest line numbers, and
be reviewable in a diff. Indentation inside a block scalar is none of those, and an indentation
error in a corpus case is a mislabelled case rather than a syntax error someone notices.

**Why excluded from the linters.** These files are deliberately vulnerable by construction.
Linting them either fails the gate or — much worse — creates steady pressure to fix the
vulnerability the case exists to contain. `ruff` would rewrite `os.system(f"ping {host}")` given
the chance, and that case would then be silently mislabelled.

Excluding them costs a real check, so `test_case_sources_are_valid_python` compiles every `pre.py`
and `post.py` instead. It only parses; nothing executes. That check matters more here than
elsewhere: tree-sitter tolerates broken syntax by design, so a stray indent would not fail the
static agent — it would quietly analyse a fragment.

**Directory names are hyphenated** (`cwe-089-user-lookup-vuln`), which is how every Python tool is
told a directory is not a package. Verified: `grimp` walks the tree for `lint-imports` without
attempting to import them.

---

## D-047 — `detectable_by` is authored from a pre-registered rule, before any agent runs

**Date:** 2026-08-29 · **Status:** ACTIVE · **Chapter:** 7

**Decision.** Every vulnerable case names the agents that could in principle find it. The field is
assigned at authoring time from the rule below, and is **not** revised after seeing what an agent
actually did. Safe twins carry the field empty, and the schema rejects a safe case that sets it.

| Agent | Listed when |
|---|---|
| `structural.taint` | a source reaches a modelled sink through the function, so a path exists to prove |
| `structural.semgrep` | a syntactic pattern identifies it without needing a path |
| `semantic.hosted` | always, on every vulnerable case — it reasons about intent |
| `context.rag` | repository precedent is the signal: the CWE-862 and CWE-639 cases |
| `runtime.sfi` | a sandbox could *observe* it — a process spawned, a file opened outside the root, a network attempt, code compiled. Not XSS (no browser), not SQL injection (no database), not a hardcoded credential (nothing happens) |

**Why this is the most dangerous field in the schema.** It exists for a good reason — §5 requires
that a static miss on a semantic-only case not be scored as a failure — and it is exactly the field
that could excuse any miss whatsoever if it were edited after the fact. Widening one entry after a
disappointing run is a single-word change that no test would catch and that would raise a measured
number. Writing the rule down first is what makes that edit visible as a deviation rather than
invisible as a judgement call.

**Enforced mechanically where it can be.** `lint-imports` forbids every agent package from
importing `codesheriff_corpus` — a separate contract from the layering one, because the reason is
different in kind. An agent that can read `label` is being told the answer rather than measured; an
agent that can read `detectable_by` can be excused by the field designed to excuse it fairly. The
leak would not look like cheating; it would look like a convenient import in a test helper that
someone later reached for from the agent itself.

`test_the_authorisation_cwes_have_no_static_path` additionally pins the heterogeneity claim: no
CWE-862 or CWE-639 case may ever list a static backend. That claim is the clearest evidence the
four-agent argument has, and it would be lost to a single well-meaning edit.

---

## D-048 — Extraction reads whole fetched blobs; GitHub's `patch` is read nowhere

**Date:** 2026-08-29 · **Status:** ACTIVE · **Chapter:** 8

**Decision.** `codesheriff_engine.extraction` receives both versions of every changed file as
complete source and derives `changed_lines` by `difflib` over the two. Nothing in the package —
and nothing in `apps/worker` that feeds it — reads the `patch` field, and `PullRequestFile` does
not carry one.

**Rationale.** The superseded `github/parser.py` used the patch for two different jobs and got both
wrong. It concatenated hunk fragments into a synthetic `post_src` that was syntactically broken and
carried wrong line numbers (`AUDIT.md` 4.2), and it skipped outright any file GitHub declined to
send a patch for, which is exactly the large diffs where a review matters most (`parser.py:102`).
Both failures come from the same mistake: treating a summary of the code as the code.

Diffing the blobs removes the large-diff branch **structurally**. There is no code path that can
behave differently for a file with no patch, so there is nothing to remember and nothing to
regress. The cost is one extra API call per modified file, which is affordable against 5,000 per
hour per installation and is not paid at all for added, copied, deleted or non-Python files.

It also puts production extraction on the *same* derivation as
`codesheriff_corpus.models.CorpusCase.changed_lines`, which already used `difflib`. That parity is
load-bearing rather than tidy: every likelihood ratio is fitted on corpus units and applied to
production units, and that is only sound if the two are the same kind of object.

**Consequences.** A whitespace-only change yields no units at all, and a deletion is anchored to
the nearest line of code — including the `replace`-with-a-blank-line form, which is how a removed
decorator usually appears in a real diff and which is the entire D-013 signal for CWE-862 and
CWE-639.

---

## D-049 — The unit is the outermost function; a module-scope change gets a `<module>` unit

**Date:** 2026-08-29 · **Status:** ACTIVE · **Chapter:** 8

**Decision.** A changed line is attributed to the outermost enclosing `def` — a top-level function
or a method, never a nested closure. A changed line with no enclosing function produces one
`<module>` unit per file, whose `post_src` is the **whole file**, untruncated, and whose
`changed_lines` are only the lines outside every function.

**Rationale.** §5 makes the changed function the unit of analysis, and `AUDIT.md` 4.1 records what
happens without one: units were per-file with `symbol=None`, so `qualified_symbol` was always
`<module>` and every finding anywhere in a file collapsed onto a single `finding_key`. That is the
D-004 bug reached by another route, and the frozen contract cannot prevent it on its own, because a
null symbol is legitimate for a genuinely module-scope change.

**Outermost, not innermost.** A closure's free variables are bound in its parent, so a unit
containing only the closure is a fragment whose taint sources are invisible and whose intent the
semantic agent has to guess — `AUDIT.md` 4.2's failure arrived at from the opposite direction. The
cost is a larger `post_src` for the semantic agent, which is the cheaper mistake.

**A module unit at all.** CWE-798 is in the closed set and hard-coded credentials sit at module
scope more often than not. Emitting only function units would make that CWE structurally
undetectable in production while the corpus scores it fine — a gap between the measured system and
the shipped one, which is the failure mode this project exists to argue against.

**The whole file, never a slice.** Assembling "the module-scope statements" would be synthesising
source again. Oversized units are for the agent to abstain on and never for extraction to trim
(CLAUDE.md); the fetch budget in `MAX_BLOB_BYTES` is a separate mechanism that skips a file whole
rather than analysing part of one.

**One unit per qualified name.** `@overload` stubs and conditional redefinitions define the same
name twice in one file. Both would produce the same `finding_key`, so two units would apply one
agent's likelihood ratio twice to a single finding, and would collide on `change_units`' UNIQUE
(audit_id, unit_id). The **last** definition wins, because that is the one Python binds — choosing
the longest instead reads as reasonable and silently picks the stub whenever the two are the same
length.

---

## D-050 — The comment reports coverage as counts; a file path never reaches it

**Date:** 2026-08-29 · **Status:** ACTIVE · **Chapter:** 8

**Decision.** The pull request comment states how many functions were extracted and how many files
were not analysed, with a plain-English reason for each. It names no file. Every file that produces
no unit is recorded with a `SkipReason` rather than dropped.

**Rationale.** Two separate problems, one answer.

A file path is chosen by whoever opened the pull request, so it is attacker-controlled text of
exactly the kind `AUDIT.md` 0.4 describes — a name like `` x](javascript:…).py `` escapes a
markdown table cell. Chapter 6 established that nothing from the pull request is echoed, and a path
is from the pull request. The dashboard is where paths belong, behind rendering that escapes them
(Chapter 16).

Separately, the superseded parser dropped files for three different reasons with a bare `continue`
each and told nobody. "This pull request is clean" and "we did not look at this pull request"
rendered identically, which is `AUDIT.md` 4.4 in another module. Coverage is a fact about the audit
and belongs in its record; `SKIP_WORDING` is asserted to be total over `SkipReason`, so a reason
added later cannot reach a comment as a `KeyError`.

---

## D-051 — `packages/engine` gains extraction; the `github/` package is deleted

**Date:** 2026-08-29 · **Status:** ACTIVE · **Chapter:** 8

**Decision.** Extraction lives in `codesheriff_engine.extraction` and holds no HTTP client, no
GitHub client and no database session. Fetching lives in `apps/worker` — two new `GitHubGateway`
methods and `pipeline.py`. `codesheriff_engine/github/` is deleted: `parser.py` outright, and
`reporter.py` moved up to `codesheriff_engine/reporting.py`.

**Rationale.** The split is what lets Chapter 14 run extraction over corpus cases with no
credentials at all. A single module that both fetched and extracted would make the calibration
harness need an installation token to build a `ChangeUnit`, and §6's reproducibility requirement
would quietly become unmeetable.

The package deletion is bookkeeping with a point behind it: after Chapter 6 removed the webhook and
the API client, `codesheriff_engine/github/` contained only markdown rendering, and CLAUDE.md
already warns that a GitHub client reappearing in `packages/engine` is the `AUDIT.md` 4.3 mistake. A
directory named `github` inside the component forbidden from touching GitHub is an invitation.

**Considered and rejected: a separate `packages/extraction`.** It would keep tree-sitter out of the
package §6 wants reproducible, at the cost of a sixth workspace member and a new `import-linter`
layer. PLAN.md Chapter 8 names the engine, the layering already permits it, and the boundary that
actually matters — extraction cannot reach the network or the database — is enforced by the
existing "Fusion and calibration cannot reach the database" contract either way.
