# CLAUDE.md

Guidance for Claude Code sessions working in this repository.

---

## What this project is

CodeSheriff is a GitHub App that security-reviews pull requests. Four specialist agents analyse
each changed function independently, and a Bayesian inference engine fuses their evidence into a
**calibrated** posterior probability that the change introduces a vulnerability.

The thesis is not detection coverage. It is calibration: a stated 87% must correspond to being
right about 87% of the time, measured against ground truth. Existing PR security tools emit binary
alerts with no reliability measure, so developers learn to ignore them.

> An AI code reviewer tells you what it thinks. CodeSheriff tells you how often it is right when
> it thinks that.

Final-year academic project. Solo maintainer plus contributors, part-time, no fixed deadline. A
research paper is a deliverable; calibration metrics (ECE, Brier) are **mandatory acceptance
criteria**, not optional analysis.

---

## Document hierarchy — read this before trusting any spec in this repo

| Document | Status | Use for |
|---|---|---|
| `PROJECT_CONTEXT.md` | **AUTHORITATIVE** | The finalized design. §5 "Finalized Decisions" overrides everything else. |
| `DECISIONS.md` | **AUTHORITATIVE**, living | Decisions taken since, each with its rationale. Append here as you go. |
| `AUDIT.md` | Current | What the code actually does vs. what it should. The gap list. |
| `PLAN.md` | Current | The roadmap: 18 chapters, one per session, with live status. **Start here each session.** |
| `DEFECTS.md` | Current, living | One line per false positive / false negative, written as found. |
| `docs/history/**` | **SUPERSEDED — DO NOT BUILD FROM THESE** | Archived drafts, kept for provenance. See `docs/history/README.md`. |

### Why `docs/history/00-START-HERE.md` is dangerous

It is an earlier draft that `PROJECT_CONTEXT.md` §5 explicitly reverses on four points: it
mandates independent repos with vendored contracts, `analyze(unit, anchors=...)`, anchored
execution, and three agents. §5 reverses all four, and each reversal exists to fix a specific
identified bug.

The entire non-conformance documented in `AUDIT.md` traces to that file sitting in the repo root
looking authoritative while three contributors built against it. It has been moved to
`docs/history/` for exactly that reason. **If a spec in this repo contradicts
`PROJECT_CONTEXT.md` §5, §5 wins.**

---

## The conflict rule (from PROJECT_CONTEXT.md §8)

> If a new decision conflicts with a finalized decision in Section 5, **identify the conflict and
> discuss it before changing anything.**

Several §5 entries reverse earlier drafts and exist to fix specific bugs. Reverting one silently
reintroduces its bug. This is not a style preference — it is how this codebase got into its
current state.

**Do not "simplify" any of the following without raising the conflict first.** Each looks like an
odd choice and is load-bearing:

| Invariant | Why it looks wrong | Why it is right |
|---|---|---|
| `finding_key` **excludes** the sink expression | Seems to lose precision | With it, taint reports `cursor.execute(query)` and the LLM reports `cursor.execute` → different keys → every finding a singleton → the Bayesian engine never performs a single update |
| Three evidence kinds, not two | `abstained: bool` seems sufficient | SILENCE (ran, found nothing) gets LR < 1.0; ABSTENTION (could not run) gets exactly 1.0. Conflating them means an agent that *could not look* penalises the finding |
| SILENCE carries `covered_cwes` | Extra field for little gain | Without it, the taint engine's silence on CWE-862 (which it has no rules for) systematically suppresses every semantic-only finding |
| Fusion iterates **all** agents, not just those that emitted | Wasteful loop | Otherwise odds can only ever increase |
| Fusion multiplies one LR per **witness**, not per agent | Four backends, four factors seems natural | `structural.taint` and `structural.semgrep` analyse the same source text with the same technique. Two "high" hits multiplied to 8.5 x 7.0 = **59.5x** out of one witness (D-052) |
| ABSTENTION has no entry in the ratio table | An unfitted constant looks like an oversight | It is exactly 1.0 *by definition*. A fitted number there would mean the act of failing carried information about the code |
| An unregistered `agent_id` raises in fusion | Harsh; a warning would do | It would otherwise become a fifth witness and multiply in a factor nobody calibrated. `apps/worker` catches it at agent load, so the cost is one log line at start-up |
| Agents run **blind** — no anchors | Anchoring is obviously more efficient | It correlates the agents and breaks the conditional independence the fusion math assumes |
| Debate emits its own evidence, never overwrites the posterior | Overwriting is simpler | Overwriting destroys calibration exactly on the contested cases and makes the debate step unmeasurable |
| Oversized units **abstain**, never truncate | Truncating gets partial signal | Truncated analysis produces confident findings from half-read code, biased toward over-reporting, and silently invalidates calibration |
| The exemplars sit **inside** the same sentinel as the unit | An example is not untrusted data; wrapping it looks like a category error | They are the longest, most attended-to part of the prompt. Framed differently they would teach that the sentinel is decorative formatting, which is exactly the belief an injection needs |
| Instruction-shaped model prose is **dropped**, not escaped | Escaping preserves the information and fixes the rendering bug | An escaped injection is still published to the reader it targets. The finding survives on its validated fields — whether the code is vulnerable does not depend on how the model described it |
| Editing a prompt turns the semantic suite **red** | A test that fails on an intended edit looks broken | The cassettes measure the old prompt. A green suite reporting a rate for a prompt nobody sends any more is worse than a red one; re-record, do not touch the fingerprint |
| The runtime witness reports **five** CWEs, not ten | Half the scope, from the witness with the most direct evidence | Its SQL and XSS sinks are methods on objects the probe itself fabricated, so an "observation" there is the harness observing itself — a weaker restatement of the structural witness, correlated with it (D-073) |
| A guard the probe could not evaluate produces an **abstention**, not a detection | The value demonstrably reached the sink | The run reached it only because the harness answered the guard. Reporting is a false positive on exactly the code that defends itself; silence argues that guarded code is clean on the strength of a guard nobody read (D-079) |
| There is **no** second execution backend, not even for tests | A subprocess runner would make the suite portable | It would be reached the first time a `wasm` test was inconvenient, and the measurement would then be of untrusted code running beside the database credentials. This repo has shipped that shape twice (D-076) |
| The fitted artifact is the **only** source of a ratio, prior or threshold | A hand-set fallback would keep the system running when `calibration.json` is missing | A fallback is reached the first time the artifact fails to load, and the system then produces numbers nobody measured while still calling them posteriors. Missing artifact raises (D-080, D-082) |
| A cell with **no observations** contributes exactly 1.0 | Laplace smoothing already gives it a value | The smoothed value reduces to the class balance of *other* cells: `runtime`'s never-observed tiers came out at 0.69, mild evidence of safety on a tier nothing has ever selected (D-087) |
| The prior is **declared**, never measured from the corpus | The corpus is right there and its prevalence is computable | It is 0.5 by construction, because every case has a twin. Reading it as a prior states that one changed function in two is vulnerable. The ratios are prevalence-invariant, which is what makes a balanced corpus the right shape for fitting them (D-083) |
| The alert threshold is **read-only** in the dashboard | Every tool has a sensitivity slider; a noisy repository is a real problem | A per-repository threshold makes `findings.alert_threshold` a description of a setting rather than of a run, and the column exists so a threshold chosen later cannot rewrite which past findings were alerts. Per-repo agent toggles are the same argument: a switched-off witness is not a recorded abstention (D-089) |
| PR title/description passed as separate `pr_context` | Convenient inside `ChangeUnit` | Attacker-controlled, and absent from corpus cases — embedding it makes corpus runs behave differently from production, corrupting calibration |

---

## Current state — read `AUDIT.md` before writing code

**The committed code did not implement the design above.** A full conformance audit found that
three of four analysis components were shells. **None still are** — Chapter 13 built the last of
them, and every witness is now measured against the corpus on the calibration split.

The static agent's taint engine *was* the worst of them — the def-use graph was built and discarded,
and "taint paths" were a line-number cross-product. Chapter 10 replaced it (`AUDIT.md` 3.1–3.6). The
semantic agent's anti-sycophancy exemplars *were* on disk and never loaded, its prompt delimiter was
forgeable by the code it analysed, and its hallucination gate had three of four checks with two of
them weakened; Chapter 11 closed all of it (`AUDIT.md` 0.3, 0.4, 3.9–3.12).

The context agent *was* four hard-coded substring tests over a vector store its reasoning never
consulted, sharing one global collection across every repository; Chapter 12 replaced all of it
(`AUDIT.md` 0.2, 3.7, 3.8).

The runtime agent *did not exist at all*; Chapter 13 built it, sandbox first.

The extraction *was* per-file diff fragments; Chapter 8 closed that (`AUDIT.md` 4.1 and 4.2). The
webhook *was* unauthenticated; Chapter 6 closed that (`AUDIT.md` 0.1 and 4.3). The fusion engine
*was* seven defects; Chapter 9 closed all of them (`AUDIT.md` 1.4, 2.2, 2.3, 2.4, 2.6, 2.7). See
"Closure status" at the top of `AUDIT.md` for what each chapter has actually fixed — the findings
themselves are left as audited, because they are the record of how far the implementation had
drifted.

The test suite passes and reports 100%. It could not detect any of this. `static-agent/cli.py`
`bench` returns hard-coded `precision: 1.0, recall: 1.0`.

**Do not assume a component works because it has a plausible filename or a passing test.** Read
the implementation.

---

## Repository layout

`uv` workspace monorepo, per `PROJECT_CONTEXT.md` §5.

```
CODESHERIFF/
├── pyproject.toml        # uv workspace + ruff/mypy/import-linter config
├── packages/
│   ├── contracts/        # THE single shared contract. Never vendored.
│   ├── corpus/           # 76 labelled units, 38 twin pairs, committed splits (Ch 7, Ch 12)
│   ├── agent_static/     # structural.taint (Ch 10) + structural.semgrep
│   ├── agent_semantic/   # semantic.hosted
│   ├── agent_context/    # context.rag (Ch 12)
│   ├── agent_runtime/    # runtime.sfi — Wasmtime + WASI sandbox (Ch 13)
│   ├── engine/           # ChangeUnit extraction, fusion, calibration. No DB client, no agents.
│   └── storage/          # SQLAlchemy models, Alembic, pgvector store, dashboard reads (Ch 15)
├── apps/
│   ├── api/              # FastAPI: sign-in (Ch 5), HMAC + enqueue (Ch 6), dashboard reads (Ch 15)
│   ├── worker/           # Celery: owns the pipeline and all agents. Runs them + fuses (Ch 9)
│   └── dashboard/        # Next.js 16 — rendering layer only. Real audits + calibration (Ch 15)
└── docs/history/         # Superseded specs, kept for provenance
```

✅ **The pipeline runs end to end, and all four agents exist and are measured.**
Chapter 2 froze the contract at v2.0.0 and got every gate green. Chapter 6 made the plumbing real —
verified webhook, queued audit, worker-posted comment. Chapter 7 built the ground truth every number
will be fitted against. Chapter 8 made the pipeline hand over the right objects. Chapter 9 closed
the seam: agents run per unit, their statements are persisted against the function they are about,
and fusion turns them into a posterior that can go down as well as up.

Chapter 10 made the first agent do real work: `structural.taint` propagates over a def-use graph
it consumes, and is measured — 13/13 on the calibration cases the corpus predicts for it, 0 false
positives across 23 safe twins. Chapter 11 made the second: `semantic.hosted` loads its exemplars,
bounds the untrusted region with an unforgeable sentinel, and is measured the same way — 0%
injection subversion, a 94% safe-twin pass rate, zero hallucinated sinks. Chapter 12 made the
third: `context.rag` mines the control vocabulary of retrieved merged code instead of running four
substring tests, and is measured on cross-PR scenarios the same chapter added to the corpus — 5/5
recall, 0 false positives across 11 twins and negative controls. Chapter 13 made the fourth:
`runtime.sfi` executes the changed function inside a Wasmtime sandbox that denies the network at
link time and hands the guest an empty environment, and reports what an untrusted value actually
reached — 9/9 recall, 0 false positives across 23 safe twins. On a machine with no WASI interpreter
it abstains under its own name, at a likelihood ratio of exactly 1.0, on the record, per unit — so a
witness that cannot run costs the posterior nothing and hides from nobody.

Chapter 14 fitted the numbers. Every likelihood ratio comes from the calibration split with its
per-cell counts recorded, the alert threshold from a base-rate-weighted precision–recall sweep on
the validation split, and both travel in `calibration.json` with the corpus hash they were measured
against. **The hand-set constants are deleted, not relabelled** — there is no `PROVISIONAL_RATIOS`,
`PROVISIONAL_PRIOR`, `PROVISIONAL_ALERT_THRESHOLD` or `FALLBACK_RATIOS` anywhere, and
`packages/engine/tests/test_no_unfitted_numbers.py` parses the source tree to keep it that way.

Two caveats travel with those numbers. `structural.semgrep` has no Windows build and abstained on
every unit, so the structural ratios describe a **one-backend witness** — Chapter 18 must re-observe
on Linux or CI. And the **prior is declared, not measured**: a twin-paired corpus has a prevalence
of 0.5 by construction, so the base rate is a stated 3% that rescales every posterior by a recorded
factor and refits nothing (D-083).

**The webhook is `apps/api/src/codesheriff_api/webhooks.py`.** It verifies `X-Hub-Signature-256`
against the raw body *before* parsing it, writes an `audits` row, publishes the id to Celery and
answers 202. The old `packages/engine/.../github/webhook.py` is deleted, along with
`codesheriff_engine/main.py` — a second FastAPI app that mounted it — and the `serve` CLI command
that booted them. If you find yourself adding an HTTP server or a GitHub client back into
`packages/engine`, that is the mistake `AUDIT.md` 4.3 describes.

**Two processes, two credential sets** (D-042). `apps/api` holds the OAuth client secret and the
webhook secret; `apps/worker` holds neither, and holds the LLM key that the API must never have.
The API cannot import the worker — `import-linter` puts them on the same layer — so it publishes
the task **by name** (D-040), and the message carries an audit id and nothing else (D-041).

**Persisting anything.** All database access lives in `packages/storage`, and `codesheriff_engine`
is forbidden from importing `sqlalchemy`, `alembic`, `psycopg` or `codesheriff_storage` — enforced
by `import-linter` (D-025). Fitted numbers must be reproducible from the calibration split and a
recorded corpus hash; a fusion module that can open a session makes that unverifiable. Never write a
row by hand: `mapping.py` is the only writer, it hashes source rather than storing it, and it drops
fusion results whose key no agent could have produced (D-026, D-027).

**Ground truth.** `packages/corpus` holds 60 hand-written units in 30 twin pairs — the same
function, once vulnerable and once safe, sharing a `finding_key` so a false positive is a lookup.
No agent may import it, enforced by a dedicated `import-linter` contract (D-047): an agent that can
read `label` is being told the answer, and one that can read `detectable_by` can be excused by the
field that exists to excuse it fairly. `detectable_by` is authored from a pre-registered rule before
any agent runs and is never widened afterwards.

Splits are assigned by **`pair_id`**, never `case_id`, so a twin cannot straddle a split (D-045).
Immutability is **detectable, not prevented**: `assign` refuses to move a settled pair, and
`split_hash` on each `calibration_runs` row makes a later edit show up as a stale fit. A committed
checksum verified by a test is deliberately *not* used — that is the mechanism `AUDIT.md` 4.8 records
being defeated by rewriting the expected hash.

Case sources are real `.py` files and are **data, not code**: `cases/` is excluded from `ruff` and
`mypy`, because linting deliberately vulnerable samples pressures you into fixing the very thing the
case exists to contain (D-046). A test compiles every one instead — tree-sitter tolerates broken
syntax, so a stray indent would silently analyse a fragment rather than fail.

**Extracting units.** `codesheriff_engine.extraction` turns two fetched file blobs into one
`ChangeUnit` per changed function. It holds no HTTP client, no GitHub client and no database session:
`apps/worker` fetches and this decides what a unit is, which is what lets Chapter 14 run extraction
over corpus cases with no credentials (D-051).

**GitHub's `patch` is read nowhere, and there is no field for it on `PullRequestFile`** (D-048).
`changed_lines` comes from `difflib` over the base and head blobs — the same derivation
`CorpusCase.changed_lines` uses, so a corpus unit and a production unit are the same kind of object,
which is the whole basis for applying a ratio fitted on one to the other. It also means a file
GitHub sends no patch for takes no special path; the `AUDIT.md` 4.2 skip is gone structurally rather
than by a fix that can be forgotten.

The unit is the **outermost** function — never a nested closure, whose free variables are bound
outside it. A change with no enclosing function gets one `<module>` unit carrying the whole file,
because CWE-798 lives at module scope more often than not (D-049). One unit per qualified name, last
definition winning: `@overload` stubs would otherwise apply one agent's ratio twice to one
`finding_key`. A file that yields no unit is recorded with a `SkipReason`, never dropped silently,
and `MAX_BLOB_BYTES` skips an oversized file *whole* — capping the fetch is not truncating a unit.

**Taint analysis.** `static_agent.taint` is an AST analysis, not a text one. Rules `fullmatch` the
**callee** of a call node — never a line of source, which is how a comment came to register a
critical sink (`AUDIT.md` 3.3). Every sink declares a `class` and its dangerous argument **positions**;
`args: [0]` on `sql.execute` is how parameterised SQL is modelled, and §5 forbids it being a
sanitizer (D-059). Sanitizer edges clear classes, so escaping HTML cannot silence an `os.system`.

Three choices there look aggressive and are load-bearing. **Every function parameter is an untrusted
source** (D-058) — the unit is one function, so its signature is the trust boundary, and nine of the
thirteen calibration cases depend on it. **A validating guard is a definition** (D-060): `if x not in
ALLOWED: raise` clears taint, `if x is None: return` does not, because the second establishes nothing
about the value. **Path sinks require a composition** (D-061), or every function that opens a path it
was handed becomes a critical finding.

Rule models are `extra="forbid"`. A mistyped field must fail loudly, not analyse quietly.

**Semantic analysis.** `semantic_agent` asks a hosted model for intent, trust boundaries and the
violated invariant, and everything defensive around it exists to bound the one failure mode a model
has that a rule engine does not: being confidently wrong, or agreeable.

The untrusted region is delimited by a **per-request random sentinel** (D-066) — `secrets`, never
`random`, because this is the whole injection boundary. Nothing else in the prompt is a delimiter,
and the exemplars use the same one. Model prose is **screened in `mapping.py`**, the only place an
`LLMFinding` becomes an `Evidence`, and prose that reads as an instruction is dropped rather than
sanitised (D-067). The **hallucination gate** rejects a finding whose CWE is out of scope, whose
file is not exactly the unit's, whose sink is not verbatim in `post_src`, or whose evidence lines
fall outside the unit — a rejection drops that finding and not the whole sample, because one
response can carry a real finding and an invention.

Never construct a prompt without `build_prompt`, and never add a field to the template that carries
attacker-controlled text outside the sentinel. `n_samples` is 3 with varying seeds, and the spread
between them is what `raw_score` is derived from — replaying one answer three times would look like
unanimous confidence.

**Repository precedent.** `context_agent` reports a security control that this repository's own
merged history establishes and the unit under analysis does not apply. Which controls a repository
applies is **learned** from retrieved merged code; which of them are authorization controls is a
**fixed** table (D-071). Making both halves learned would mean inferring a CWE from a name whose
meaning the agent was never told; making both halves fixed would be a second rule engine with a
hard-coded guard list, correlated with the one that already exists.

There is **no LLM in this agent**, deliberately. Its basis is precedent and its failure mode is a
repository with no relevant history; a model-driven version would fail the way `semantic.hosted`
fails, and heterogeneity is the whole argument for four witnesses.

A control is established either by **the same qualified symbol** carrying it in one merge — matched
on the symbol, never the path, because a move is what changes the path — or by **two or more
distinct sibling symbols** sharing it. One neighbour's habit is a coincidence, and treating it as a
rule would make every added function a regression against whichever neighbour retrieval returned.

It reports **CWE-862 and CWE-639 only**, and that narrowness is the mechanism, not a limitation. A
mined control that maps to no in-scope CWE cannot be reported at all, so a repository where every
merged view calls `escape()` has a real convention, a unit that drops it has really regressed, and
this witness still says nothing — escaping is not authorization. `rate_limit` and `throttle` are
absent from the table rather than excluded from it, and there is no bare `access`, `check`,
`verify`, `validate` or `require` token; corpus pairs fire both traps on both twins.

**Retrieval is a Protocol the agent declares and `apps/worker` implements** (D-072). The agent holds
no store, no session and no embedding model — `lint-imports` fails the build for an agent that
reaches a database client, and the split is also what lets the corpus measurement run the production
`analyze()` path with no database and no model download. Cross-repository retrieval is impossible
structurally: `repository_id` is bound when the retriever is constructed, `retrieve(unit, limit)`
takes no repository, and the filter is in SQL. `unit.repo` is deliberately not consulted.

**Embedding failure is loud, and there is no fallback branch.** A missing library, an unloadable
model or a wrong output dimension raises `RetrievalUnavailableError`, which the agent records as a
`retrieval_unavailable` abstention — distinct from `no_precedent`, because a store that is down is
not a repository that is new. `AUDIT.md` 3.8 is what conflating them looked like: a 384-dimensional
MD5 term-hasher, the default path for a normal install, reporting noise with no log line.

**Precedent is written by a backfill command, never by the audit path** —
`codesheriff-worker precedent backfill`. One chunk per **symbol**, never per pull request, and only
the merged side: the base version is already precedent from an earlier merge, and indexing both
would let a control a pull request deliberately removed go on establishing itself forever.

**Runtime observation.** `runtime_agent` executes the changed function **once**, inside a Wasmtime +
WASI sandbox, with every parameter bound to a uniquely tokenised untrusted value, and reports which
dangerous operations that value actually reached. It observes; it never proves (D-073).

**The sandbox is the deliverable and the agent is second.** Running a pull request's code is how CI
systems get compromised, so `sandbox.py` would be worth having if `agent.py` did not exist. The
guest gets an argv, three file descriptors, and nothing else. **Capabilities are absent, not
filtered** (D-075): `os.environ` is `{}` because `WasiConfig` inherits nothing, not because a
deny-list removed the interesting keys, and WASI preview1 defines no `sock_connect`, so a module
that asks to connect **fails to instantiate** — denial before the first instruction. Never add
`inherit_env`, `preopen_dir` or a field to `SandboxPolicy` that grants rather than bounds.

**Four caps, each covering another's blind spot.** Fuel is deterministic and is what a calibration
run needs; epoch interruption is the wall-clock backstop, because a guest blocked in a host call
burns no fuel; memory keeps an allocation loop a guest `MemoryError` rather than a host OOM.

**Taint is a substring, not a wrapper.** The untrusted value is a `str` subclass whose text is a
random token, so f-strings, `+`, `%`, `.format()` and `os.path.join` carry it for free and D-061's
composition rule is a string comparison. The proxy answers as a **module** when clean and as a
**string** when tainted — `os.path.join` resolving to `str.join` is the bug that split fixed, and it
cost a real detection while it lasted.

**The interpreter is pinned, verified and never committed** (D-074). 26 MB, gitignored in
`.wasm-runtimes/`, checked against `INTERPRETER_SHA256` on load, and fetched by a person — an agent
that downloaded executable code at analysis time would be the supply-chain problem this project
exists to notice. A digest mismatch is fatal, not a warning. Without it the agent abstains
`interpreter_unavailable` per unit and `wasm`-marked tests skip; `runtime-agent doctor` reports
every path it consulted (D-077).

**The guest driver is data, not an import** (D-078). `guest/driver.py` is read as text and handed to
another interpreter; it has no importer on the host and is excluded from `mypy` only. Nothing it
says is taken on trust: the trace is found behind a per-request `secrets` sentinel, an unknown sink
name is dropped, and the **CWE is re-derived from our table** — analysed code cannot invent a
finding or relabel one. Every published word comes from `sinks.py` and the agent's own verbs, which
is why the explanation needs no screening pass of the kind model prose needs (D-067).

**Reading it back.** `codesheriff_storage.reporting` holds every dashboard query and nothing
else. It is separate from `audits.py` because the two have opposite hazards: a lifecycle write must
be a single conditional UPDATE or two workers race, and a dashboard read must be scoped or it
discloses another account's pull requests. **Every function takes `installation_ids` and returns
nothing when it is empty** (D-035) — the scoping lives in the query so a route has nothing to
forget. Counts are correlated subqueries, never joins: an audit has many units, many statements and
many findings, and joining all three would report `units x findings` change units, which is a
plausible wrong number.

`apps/api` serves four read routes — `GET /audits`, `GET /audits/{id}`, `GET /stats/overview`,
`GET /calibration` — and **none of them computes a probability**. Every posterior, prior and
threshold is read from the row or the artifact that recorded it, so an audit that ran under an
earlier calibration keeps reporting what it ran under (§6). The audit page renders one statement
per witness per unit with its kind intact, because collapsing silence and abstention into "found
nothing" is what makes a posterior unexplainable.

**The dashboard reports the fitted numbers and cannot choose them** (D-089). The threshold, the
four-witness roster and the closed CWE set are read-only facts with their provenance; the one
writable per-repository setting is whether CodeSheriff analyses that repository at all. The
calibration page shows the reliability bins, the per-cell observation counts and the whole
validation sweep — a ratio held up by smoothing has to look like one on screen.

**Fusing evidence.** `codesheriff_engine.fusion` multiplies one likelihood ratio per **witness**
— four factors, always four, whatever the agents said. `fusion/witnesses.py` is the only place that
decides how many witnesses there are, and an `agent_id` it does not know raises rather than becoming
a fifth (D-052). Backends inside a witness combine by plain max, which is D-011's open question
answered provisionally. The ratios are clamped; the posterior is not. A unit nobody detected anything
in yields evidence rows and **no** `FusionResult` — there is no `abstention:all_agents` marker any
more (D-055).

There is no debate module. It overwrote the posterior it was meant to explain, and its default path
was substring matching in which `"int("` — a substring of `print(` — counted as a sanitizer. It
returns as a witness that emits its own evidence in Chapter 11 (D-053).

**Running agents is `apps/worker`'s job, never the engine's** (D-054). `apps/worker/analysis.py`
holds four slots, fills every one of them, and guarantees at least one statement per agent per unit:
an agent that will not import, raises, hangs or returns `[]` becomes an abstention with a distinct
reason. If you find yourself adding `import static_agent` to `packages/engine`, that is the
undeclared dependency Chapter 9 removed — and it is what let a fusion package pull in an LLM client.

**Fitting the numbers.** `codesheriff_engine.calibration` fits one likelihood ratio per witness per
cell from labelled claims — no agent, no corpus, no session, so §6's "reproducible from the
calibration split and a recorded corpus hash" is a property of the code. The harness that produces
those claims is `apps/worker`'s, because running agents is `apps/worker`'s job (D-054, D-085): it
calls the **production** `load_agents` and `analyse_unit`, rebinding each case's retriever and
recorded model responses rather than rebuilding the agents, and it refuses the test split by name.

`fusion/cells.py` is the seam. `bayes.py` reads a cell to look a ratio **up**; `fit.py` reads the
same cell to count observations and fit that ratio **in**. Two implementations of "what did this
witness say" would fit one quantity and apply another, and both halves would pass their own tests.
`posterior_from_cells` is the same arithmetic for the same reason — the threshold sweep scores
exactly what an audit computes.

The order is §6 and it is not negotiable: **ratios on calibration, threshold on validation, test
split untouched until Chapter 18.** `fit_from_observations` refuses an observation set from the
wrong split, and `codesheriff_worker.calibration.runner` cannot produce a test-split one at all.

**The audit path cannot import the corpus** (D-086), even though the worker process now can. D-047
stops the agents; this contract stops `tasks`, `pipeline`, `analysis`, `comment` and all of
`apps/api`. The leak would look like a convenient import in the pipeline for "just checking"
whether a unit matches a known case.

**No file path reaches the pull request comment** (D-050). A path is chosen by whoever opened the
pull request; coverage is reported as counts and plain words. Paths belong on the dashboard, behind
escaping.

**Building evidence.** Never construct `Evidence(...)` directly — use `Evidence.detection()`,
`.silence()` or `.abstention()`. Never build a `finding_key` by hand — use `unit.key_for(cwe)`. Both
rules exist because hand-rolled variants are exactly how the same bug came to have two keys
(`AUDIT.md` 1.1). Returning `[]` from a successful analysis is a bug; that is what SILENCE is for.

---

## Architectural rules

**Agent isolation.** Every agent implements exactly `analyze(unit: ChangeUnit) -> list[Evidence]`.
No agent knows another exists, or knows about GitHub, the database, or fusion. Agents may import
`contracts` and nothing else — enforced by `import-linter` in CI once Chapter 2 lands.

*This is the one property the current code got right.* No agent imports a sibling, the engine,
GitHub, or a DB client. It is why a rebuild is cheap rather than catastrophic. Do not break it.

**Agents never raise.** Every failure path returns an abstention with a distinct reason. Returning
an empty list on a failure path is a bug — it is indistinguishable from "analysed, found nothing",
which is what SILENCE is for.

**The four agents must fail differently.** Heterogeneity is the entire justification for the
project; agents that failed the same way would add nothing to a probability estimate.

| Agent | Basis for decision | Fails when |
|---|---|---|
| `structural.taint` / `structural.semgrep` | Mechanical reachability proof. No LLM. | Bug has no syntactic pattern |
| `semantic.hosted` | Absorbed model knowledge: intent → trust boundaries → violated invariant | Model hallucinates or is over-agreeable |
| `context.rag` | This repository's own precedent | Repo has no relevant history |
| `runtime.sfi` | Direct observation in a sandbox | Code will not run in a sandbox |

**Research integrity — non-negotiable (§6).**
- Scoring weights and likelihood ratios fitted **only** on the calibration split
- Threshold selected **only** on the validation split
- Test split evaluated **exactly once**, at the end

**Sign-in and access.** The dashboard never talks to GitHub and holds no secret; `apps/api` owns the
OAuth flow. What a user may see is read from `GET /user/installations` at sign-in and stored on their
session — there is no permissions table, and an empty installation list returns nothing rather than
everything (D-035). The database holds no GitHub token and no session token, only a SHA-256 of the
cookie (D-036). A URL parameter never widens a session: the installation callback re-derives
everything through OAuth (D-037).

**Security.** Untrusted PR code executes only in the sandbox (deny-by-default network, ephemeral
filesystem, resource caps) and never on a host holding database credentials. Source code lives in
memory and ephemeral storage only; persisted records hold findings, evidence and hashes — never
full file contents.

---

## Stack

Python 3.12 · `uv` workspace · FastAPI · Pydantic v2 · Celery + Redis · PostgreSQL 16 with
**pgvector** · SQLAlchemy + Alembic · `githubkit` · `tree-sitter` + `tree-sitter-language-pack` ·
`semgrep` CLI (`--sarif`) · `networkx` · `scikit-learn` · `sentence-transformers`
(`BAAI/bge-small-en-v1.5`, 384-dim, local) · Gemini Flash free tier · **Wasmtime + WASI** ·
`typer` · `pytest` + `pytest-cov` + `syrupy` + `hypothesis` · `ruff` + `mypy --strict` ·
`import-linter` · Next.js + TypeScript + Tailwind + shadcn/ui + Recharts · Docker Compose

**Explicitly rejected** — do not reintroduce:

- **LangGraph** — agents are pure functions with no shared state; a shared-state framework fights
  the independence requirement and obscures the exact prompt bytes needed for cache keys
- **ChromaDB** — pgvector instead: survives restarts, one less service, metadata filtering and
  similarity search in one query. *(ChromaDB is currently in `requirements.txt` — that is drift.)*
- **Python's built-in `ast`** — tree-sitter handles JS/TS through the same API and tolerates the
  syntax errors PR diffs frequently contain
- **Docker as the sandbox** — containers are OS-level isolation, not software fault isolation; the
  SFI claim requires Wasmtime
- **Prisma / Inngest / Pinecone / Next.js API routes as backend** — the backend must be Python
  because tree-sitter, scikit-learn and Wasmtime bindings have no viable JS equivalent

**Constraints.** Zero recurring cost (free-tier LLM, local embeddings, self-hosted). No dedicated
GPU — any fine-tuning must fit free Colab/Kaggle tiers. Webhook acknowledged in < 3s (GitHub's
hard limit is 10s) — enqueue, never process inline. GitHub API 5,000 req/hr per installation.

**Scope.** GitHub only, Python-first. `IN_SCOPE_CWES` is a **closed set**: CWE-22, 78, 79, 89, 94,
502, 639, 798, 862, 918. Out of scope: dependency/supply-chain scanning, container and IaC
scanning, binary analysis, auto-merge or auto-commit of patches, compliance reporting,
multi-tenancy with billing, IDE plugins. JS/TS support is unscheduled until explicitly decided.

---

## Commands

```bash
uv sync --all-packages           # install the workspace  (--all-packages, or members are skipped)
uv run pytest                    # all packages
uv run pytest packages/agent_static
uv run ruff check . && uv run ruff format --check . && uv run mypy .
uv run lint-imports              # agent + storage + corpus boundary enforcement — must stay green

uv run codesheriff-corpus validate   # loads every case; prints corpus_hash and split_hash
uv run codesheriff-corpus stats      # coverage by CWE, split and agent
uv run codesheriff-corpus show cwe-862-admin-export-vuln

uv run codesheriff-engine fuse evidence.json       # posterior + one row per witness. No agents.

# Calibration (Ch 14). `observe` is the slow half and writes committed JSONL; `fit` reads it, so a
# re-fit needs no interpreter, no API key and no Semgrep build. `record` is the only command here
# that calls a provider, and only for cases with no recorded response.
uv run codesheriff-worker calibrate observe --split calibration
uv run codesheriff-worker calibrate observe --split validation
uv run codesheriff-worker calibrate fit            # -> packages/engine/.../calibration/calibration.json
uv run codesheriff-worker calibrate show           # what the active artifact says, and where it is

# The runtime witness's sandbox. `doctor` says whether this machine can run it at all, and where
# it looked; without the pinned interpreter the agent abstains per unit and `wasm` tests skip.
uv run runtime-agent doctor
curl -L -o .wasm-runtimes/python-3.12.0.wasm \n  https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/python%2F3.12.0%2B20231211-040d5a6/python-3.12.0.wasm

# The precedent store context.rag reasons from. The ONLY writer; the audit path never ingests.
uv run codesheriff-worker precedent backfill --repository-id 1 --repo-full-name owner/name \n    --installation-id 42 --pr 118 --head-sha <sha>

uv run uvicorn codesheriff_api.main:app --reload   # /health, /auth/*, /repositories, /webhooks/github

# The worker. Needs Redis; without it the API answers 503 on the webhook rather than losing work.
docker compose up -d redis
uv run celery -A codesheriff_worker.celery_app worker --loglevel=info --queues=audits

# Local webhook delivery (D-043). The channel URL goes in the App's webhook settings, once.
npx smee-client --url https://smee.io/<channel> --path /webhooks/github --port 8000

# Database (Chapter 3). Alembic owns the schema; never Base.metadata.create_all.
docker compose up -d postgres
uv run alembic -c packages/storage/alembic.ini upgrade head
uv run alembic -c packages/storage/alembic.ini downgrade base

# Tests that touch Postgres are marked `db` and SKIP unless this is set (D-029).
export CODESHERIFF_TEST_DB=postgresql+psycopg://codesheriff:codesheriff@localhost:5432/codesheriff
uv run pytest packages/storage -m db
```

The dashboard is a separate npm project, not a uv workspace member (Chapter 4):

```bash
cd apps/dashboard
npm run dev                      # http://localhost:3000 — sign-in needs the API on :8000
npm run lint && npm run build    # the two frontend gates — must stay green
```

`NEXT_PUBLIC_API_BASE_URL` is inlined at **build** time, not read at runtime. Changing which API the
dashboard talks to means rebuilding it.

Signing in needs a registered GitHub App — `docs/github-app-setup.md`. Without one the API answers
`501` naming the missing variable rather than failing at import, so `/health` works on a machine
that has never seen a `.pem`.

All five Python gates and both frontend gates are green as of Chapter 14 (1128 tests passing with
the WASI interpreter and no database, 128 skipped; the database-marked tests add more). `mypy
--strict` covers 117 source files and `lint-imports` keeps **six** contracts — the sixth is what
holds the audit path away from the corpus now that the calibration harness shares the worker
process (D-086).

**Measuring an agent.** `packages/agent_static/tests/test_corpus_calibration.py` runs the taint
engine over the corpus and asserts recall and false positives per case. It reads the **calibration
split only**, and asserts that it does: §6 reserves validation for threshold selection and permits
the test split to be evaluated exactly once, at the end, and a suite that runs on every commit is the
most thorough possible way to violate that. A test may import `codesheriff_corpus`; the `static_agent`
package may not (D-047, D-063). There is no `bench` command — it returned `precision: 1.0` (D-010).

`packages/agent_semantic/tests/test_corpus_semantic.py` does the same for `semantic.hosted`, under
the same calibration-split restriction, but replays **committed cassettes** rather than calling the
model: the criteria demand a rate measured on real model output *and* zero live API calls, and
recording once is how both hold (D-068). Editing the prompt, the system prompt or an exemplar
changes each cassette's recorded fingerprint and turns the suite red — deliberately. A prompt edit
invalidates every number measured against the old prompt, so re-record with
`tools/record_cassettes.py` rather than reaching for the fingerprint.

`packages/agent_runtime/tests/test_corpus_runtime.py` does the same for `runtime.sfi`, under the
same calibration-split restriction, executing the production `analyze()` path inside the real
sandbox — 9/9 recall on the nine calibration cases the corpus predicts for it, 0 false positives
across 23 safe twins. It is marked `wasm` and skips without the interpreter, on the `db` precedent
(D-029). `test_a_runnable_case_is_never_an_abstention` is the guard that keeps it from passing
vacuously against an agent whose sandbox is broken — without it, every false-positive assertion
would pass on an agent that abstained on everything. What it does not measure is p95 latency or the
fuel budget's behaviour on a 600-line function; both wait for Chapter 14 and CI hardware.

`packages/agent_context/tests/test_corpus_context.py` does the same for `context.rag`, under the
same restriction, injecting a deterministic token-overlap retriever over each case's authored
history — no database, no model download, no network, and the production `analyze()` path. What it
does not measure is pgvector's own nearest-neighbour ordering; that waits for Chapter 14, which
needs a populated store anyway. `test_a_case_with_a_history_is_never_an_abstention` is the guard
that keeps the measurement from passing vacuously against an agent that never ran.

**Semgrep has no Windows build**, so `structural.semgrep` abstains with `tool_unavailable` on a
Windows dev machine and the structural witness is the taint engine alone. That is a correctly
handled abstention, not a defect — but it means the SARIF mapping is exercised only against fixture
SARIF. Chapter 14 must run the corpus on Linux or CI, or its fitted structural ratios will describe
a one-backend witness. `ruff` and `mypy` are
configured **once**, in the root `pyproject.toml` — a per-package `[tool.ruff]` silently shadows it
with a different rule set, which is how the agent packages went unlinted (D-023).

**Tests must never make live API calls.** `apps/api/tests/conftest.py` and
`apps/worker/tests/conftest.py` fail any non-loopback socket connection unless
`CODESHERIFF_ALLOW_LIVE_CALLS` is set — a guard at the socket layer, so a forgotten
mock cannot leak a real request. GitHub is substituted at the `GitHubGateway` interface rather than
at the HTTP layer; the real `githubkit` client is exercised separately against an httpx
`MockTransport`, with response bodies generated from githubkit's own schemas.

---

## Working practice (PROJECT_CONTEXT.md §8)

1. Understand the existing repository state before proposing anything
2. Divide work into logical phases based on what actually exists
3. Inspect the current implementation before a significant phase
4. Brainstorm approaches and evaluate trade-offs
5. Agree the approach before implementing, when the decision is significant
6. Implement → test → review
7. **Record the decision and its reason in `DECISIONS.md`**
8. Create or update documentation only when it becomes useful

Record every false positive and false negative in `DEFECTS.md` with a one-line cause **as it is
found**, not reconstructed at the end.

Targets worth keeping in view: static agent p95 ≤ 3s per ChangeUnit; semantic agent ≤ $0.01 per
ChangeUnit at n=3; full audit < 5 min; coverage ≥ 80% per package; `mypy --strict` and `ruff`
clean; zero unhandled exceptions across a full corpus run.
