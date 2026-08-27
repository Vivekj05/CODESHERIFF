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

