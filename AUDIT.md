# AUDIT.md — Spec Conformance Audit

**Date:** 2026-08-27 · **Commit audited:** `30ce335` (Merge pull request #2 from Vivekj05/feature/vivek)
**Audited against:** `PROJECT_CONTEXT.md` §5 "Finalized Decisions" and §6 "Constraints"

Method: full read of all four packages' source. Contracts and agent packages audited by dedicated
subagents; the engine read directly. Every claim below carries a `file:line` citation.

This document is the baseline the rebuild is measured against, and is direct report material.
**The findings below are left exactly as audited** — they describe commit `30ce335`, and rewriting
them as they are fixed would destroy the record of how far the implementation had drifted.

---

## Closure status

Which entries have been closed, and by what. Anything not listed is still open.

| Entry | Closed by | What replaced it |
|---|---|---|
| 1.1, 1.2, 1.3, 1.5, 3.10 | Chapter 2 | Contract v2.0.0 — `finding_key` without the sink expression, three evidence kinds, `covered_cwes`, `key_for()` as the only key builder (D-019 … D-024) |
| **0.1 — unauthenticated webhook** | **Chapter 6** | `apps/api/src/codesheriff_api/webhooks.py`. `X-Hub-Signature-256` verified with `hmac.compare_digest` against the raw body **before** it is parsed and before any row is read or written. A missing secret answers 501 and accepts nothing rather than falling back to accepting everything. `packages/engine/.../github/webhook.py` and `codesheriff_engine/main.py` are deleted, along with the `serve` command that booted them |
| **4.3 — everything runs inline; no queue** | **Chapter 6** | The API verifies, writes an `audits` row and publishes an id to Celery (D-040, D-041), then answers 202. `apps/worker` owns the pipeline. No blocking `requests` call remains anywhere in the engine, and the engine no longer depends on `fastapi`, `uvicorn` or `requests` at all |
| **4.7 — two fixtures; no corpus** | **Chapter 7** | `packages/corpus`: 60 hand-written units in 30 twin pairs, three per in-scope CWE, with committed splits assigned by pair. Every **Python** sink named in 4.7 now has both — `subprocess` with `shell=True`, an unsafe YAML loader, and `open()` on a joined path — and twins share a `finding_key`, so a false positive is a lookup rather than a judgement (D-044, D-046). The two JavaScript sinks it also named, `child_process.exec` and `dom.innerHTML`, have **no** corpus case: the corpus is Python-only, matching the Python-first scope, and JS/TS remains unscheduled |
| 2.1 — LRs, prior and threshold hardcoded | Chapter 7, **partially** | The artifacts §6 requires now exist: a corpus, immutable splits, and computable `corpus_hash` / `split_hash` filling the `calibration_runs` columns that had held nothing since Chapter 3 (D-045). The numbers themselves are still `engine/config.py`'s hand-set values — fitting them is Chapter 14, and D-010 requires they be shown as provisional until then |
| **4.1 — ChangeUnits are per-file, not per-function** | **Chapter 8** | `codesheriff_engine.extraction`: tree-sitter over the whole fetched blob, one unit per changed **function**, carrying `symbol`, `enclosing_class` and `decorators`. A module-scope change gets a `<module>` unit whose `post_src` is the whole file — that case is legitimate and is why the null symbol could never simply be forbidden (D-049). A file that yields no unit is recorded with a `SkipReason` instead of a bare `continue` (D-050) |
| **4.2 — `post_src` is reconstructed from the diff patch** | **Chapter 8** | `post_src` is the function's real source sliced by line from the head blob, at absolute line numbers. **Nothing reads `patch` anywhere** — `changed_lines` comes from `difflib` over the two fetched blobs, the same derivation `CorpusCase.changed_lines` already used, so a corpus unit and a production unit are the same kind of object (D-048). The large-diff skip at `parser.py:102` is gone structurally: there is no branch that can behave differently for a file GitHub sends no patch for |
| **1.4 — fusion iterates only agents that emitted** | **Chapter 9** | Fusion multiplies one likelihood ratio per **witness**, from a fixed roster of four, whatever the agents did or did not say. A SILENCE contributes a ratio below 1.0 when its `covered_cwes` contains the finding's CWE; an ABSTENTION contributes exactly 1.0, which is not a table entry and never will be. The posterior can now go down, which under the old engine was arithmetically impossible (D-052) |
| **2.4 — the static agent counted as two witnesses** | **Chapter 9** | `structural.taint` and `structural.semgrep` map to one witness in `fusion/witnesses.py` and combine by plain max before the odds are touched, so two "high" hits contribute 8.5 rather than 8.5 × 7.0 = 59.5. An `agent_id` in no registry entry raises rather than becoming a witness nobody calibrated. The combination rule answers D-011's open question provisionally; Chapter 14 chooses it on corpus data (D-052) |
| **2.2, 2.3 — debate overwrites the posterior; its default path is substring matching** | **Chapter 9** | `fusion/debate.py` is **deleted**, not ported, along with `enable_debate`, `conflict_threshold`, three LLM API keys and `httpx` from the engine's dependencies. Debate returns as a witness that emits its own evidence in Chapter 11, never as a step that assigns a posterior. `debate.synth` is deliberately unregistered: it reads what the other witnesses said, so counting it as independent is the D-008 anchoring violation under another name (D-053) |
| **2.7 — the posterior is clamped; the LRs are not** | **Chapter 9** | Reversed. Each witness's contribution is clamped to `[LR_MIN, LR_MAX]` and the posterior is not clamped at all — with bounded ratios and a prior in (0, 1) it stays strictly inside (0, 1) on its own. Bounding the factor bounds a quantity that has a meaning; the old 0.9999 ceiling hid an unbounded odds product behind a number shaped like a probability (D-052) |
| **2.6 — evidence is silently dropped** | Chapter 2, **confirmed Chapter 9** | The `except Exception: pass` in `normalize_evidence` was gone by Chapter 2; Chapter 9 keeps the property and extends it — an agent that raises, hangs, or returns `[]` becomes an abstention with a distinct reason rather than a gap, and nothing anywhere discards a statement silently |
| 4.4 — missing agents degrade silently to "clean" | Chapter 9, **partially** | `apps/worker/analysis.py` fills every one of four slots, substituting an abstaining stand-in for any agent that will not import, and guarantees at least one statement per agent per unit. The comment says "no finding" only when agents actually ran and found nothing, and never on the strength of agents that could not run. Still partial because three of the four agents are shells — Chapters 10 to 13 |
| 3.12 — a missing API key reports "clean" | Chapter 9, **partially** | `SemanticAgent` no longer substitutes `StubLLMClient` when no key is configured: it abstains with `llm_unavailable` on every unit. Found by running the pipeline end to end, and fixed here rather than in Chapter 11 because Chapter 9 is what made it harmful — once fusion consumed silence, a witness that had read nothing was arguing at LR 0.50 that every change was safe (D-057). The rest of that agent is Chapter 11's |

2.1 stays **partially** open, and that is the whole of what is left in Tier 2: the artifacts exist
and the arithmetic that consumes them is correct, but every likelihood ratio, the prior and the
threshold are still hand-set. Chapter 14 fits them. Until then D-010 requires every number derived
from them to be presented as provisional, and `apps/worker/comment.py` has no code path that renders
a posterior without saying so.

---

## Verdict

**The system does not do what it claims, and its test suite cannot detect that.**

This is not drift around the edges. Three of the four analysis components are shells:

- The **static agent has no taint engine** — the def-use graph is built and discarded, symbol
  extraction is disabled by a literal `if False`, and "taint paths" are a line-number cross-product
  gated on `sink_line >= source_line`.
- The **context agent has no RAG reasoning** — its analyzer is four hard-coded substring tests for
  `stripe_charge`; retrieved documents never influence what is detected.
- The **semantic agent's anti-sycophancy exemplars are never loaded** by any code.
- The **runtime agent does not exist** at all.

The fusion engine — the component carrying the project's entire thesis — implements the
pre-reversal form of nearly every §5 decision, so its posteriors are not calibrated in any sense
the paper could defend.

`static-agent/cli.py:90-96` `bench` returns hard-coded `precision: 1.0, recall: 1.0, fpr: 0.0`.
`TEST_CASES_AND_OUTPUTS.md:4` reports "14/14 PASSED (100%)". Both statements are true and both are
meaningless — there is no corpus.

### Root cause

`00-START-HERE.md` is an **earlier draft spec still sitting in the repo root**, and the code was
built against it. `PROJECT_CONTEXT.md` §5 reverses it on four points:

| `00-START-HERE.md` | `PROJECT_CONTEXT.md` §5 |
|---|---|
| "three completely independent projects", vendored `contracts.py` + SHA-256 checksum test | Monorepo, one shared `contracts` package; vendoring **explicitly dropped** |
| `analyze(unit, anchors: set[str] \| None = None)` | **No anchors — agents run blind** |
| Context agent "abstains with `no_anchor` unless given the static agent's finding_key" | Anchoring "correlates the agents and breaks the conditional independence the fusion math assumes" |
| Three agents | Four agents (runtime/Wasmtime absent entirely) |

Each §5 reversal exists to fix a specific identified bug. The code contains the bug each one fixes.

---

## Tier 0 — Security holes

Fix regardless of which architectural path is chosen.

### 0.1 — The webhook is unauthenticated

`engine/github/webhook.py` — **no HMAC verification anywhere.** `github_webhook_secret` is defined
at `config.py:70` and never read.

Anyone who learns the URL can forge a `pull_request` payload, make the bot fetch arbitrary
repositories, post comments under the project's GitHub token, and drive LLM spend. §6 lists
signature verification as the API's first action.

### 0.2 — No repository isolation in the vector store

`context-agent/rag/store.py:91-128`, `ingest.py:41-46` — all repositories share one global Chroma
collection named `accepted_pull_requests`. `unit.repo` is never queried, and never even **stored**
in metadata, so a filter cannot be added without a full re-ingest. One repository's PR diffs can
surface as another repository's review context.

### 0.3 — Prompt-injection delimiter can be closed by untrusted input

`semantic-agent/prompts/user_v1.jinja:11-17` — `pre_src` and `post_src` are interpolated raw into
`<code_to_analyze>`. Untrusted code containing a literal `</code_to_analyze>` closes the data region;
everything after it reads as trusted instruction. No sentinel, no nonce, no escaping.

The system prompt's boundary instruction (`system_v1.md:14-17`) is well written and does not help
once the delimiter itself is forgeable.

### 0.4 — No rationale screening

`semantic-agent/consistency.py:46` → `mapping.py:60-63` → `engine/github/reporter.py:63`.
Model-authored `rationale`, `functional_intent` and `violated_safety_invariant` flow verbatim into
the PR comment, and into a markdown table with no pipe-escaping. The only control is a
`max_length=400` truncation. §5 requires rationales screened so injected strings are not echoed.

---

## Tier 1 — The system cannot fuse

### 1.1 — `finding_key` includes the sink expression

`contracts.py:82` (all four copies, byte-identical):

```python
def finding_key(file: str, symbol: Optional[str], cwe: str, sink_expr: str) -> str:
    normalized = f"{file}:{symbol or ''}:{cwe.upper()}:{sink_expr.strip()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
```

Three deviations from the mandated `sha256(f"{file}::{qualified_symbol}::{cwe}")[:16]`: the sink
expression is **included** (deliberately excluded by §5), the separator is `:` not `::`, and the
symbol is unqualified. Propagated to six call sites, so this is load-bearing, not dead code.

§5 predicts the consequence verbatim: taint reports `cursor.execute(query)`, the LLM reports
`cursor.execute`, keys differ, every finding becomes a singleton, and the Bayesian engine never
performs a single update.

**It is worse than cross-agent.** Within the static agent alone, `taint/engine.py:120` passes an
AST-derived `snk["expr"]` while `semgrep/mapping.py:50` passes a SARIF text `snippet` — two backends
in one package cannot collide on the same bug.

Two further key formats bypass the function entirely: `contracts.py:71` builds a raw unhashed
`f"abstain:{unit_id}:{reason}"`, and `fusion/bayes.py:200` builds `"abstention:all_agents"`.

### 1.2 — No evidence-kind concept exists

Not "SILENCE is missing" — `DETECTION` / `SILENCE` / `ABSTENTION` are absent entirely. Repo-wide
grep for `EvidenceKind`, `evidence_kind`, `SILENCE`: zero hits.

What exists is a two-state boolean, `contracts.py:54-55`:

```python
    abstained: bool = False
    abstain_reason: Optional[str] = None
```

`fusion/bayes.py:176-201` partitions into two buckets; `debate.py:57,156` filter on
`if not ev.abstained`. There is no third branch. **An agent that ran successfully and found nothing
has no contract-legal way to say so** — which removes the entire mechanism for evidence that
*lowers* a posterior.

### 1.3 — `covered_cwes`, `IN_SCOPE_CWES`, `pr_context` do not exist

Repo-wide greps return zero hits for each. `contracts.py` declares exactly one module-level
constant, `CONTRACT_VERSION`.

### 1.4 — Fusion iterates only over agents that emitted evidence

`fusion/bayes.py:93-96` filters to `active_evidence`, then `:113` loops over it. Confirms the §5
warning: **odds can only ever increase.** Since every "high" tier LR exceeds 1.0 and an agent is
only in the group if it alerted, the posterior is monotonically non-decreasing in the number of
agents that spoke.

### 1.5 — The context agent contributes nothing at all

`context-agent/reasoning/analyzer.py:30-31` builds its key from a **string literal**:

```python
                sink_expr = "stripe_charge(request.json)"
                f_key = finding_key(unit.file, unit.symbol, "CWE-862", sink_expr)
```

The static agent has no CWE-862 sink in `rules/sinks.yml`, so the two key spaces are **disjoint**
and the anchor filter at `agent.py:107` (`if ev.finding_key in anchors`) can never match. Every
finding is deleted and `analyze()` returns a bare `[]`.

This is worse than §5's predicted "architecturally inert at posterior 0.18": the agent contributes
*nothing*, and does not abstain either. `tests/test_cross_pr_regression.py:13` calls
`evaluate_cross_pr_regression()` directly, bypassing `analyze()` entirely — which is why the suite
never sees it.

---

## Tier 2 — The calibration claim is unsupported

### 2.1 — LRs, prior, and threshold are all hardcoded

`engine/config.py:10-58`. `DEFAULT_LIKELIHOOD_TABLE` carries hand-written values (8.5 / 3.2 / 0.8
for `structural.taint`, etc.), `prior_probability: float = 0.05`, `alert_threshold: float = 0.70`.

No corpus, no splits, no `calibration.json`, no corpus commit hash exists anywhere in the
repository. §6's research-integrity constraints — fit on calibration split, threshold from a
validation sweep, test split evaluated once — cannot be satisfied because none of those artifacts
exist.

**This is the project's headline claim, and nothing supports it.**

### 2.2 — Debate overwrites the posterior

`fusion/debate.py:176`:

```python
        fusion.posterior_probability = round(outcome["final_score"], 4)
```

§5 forbids this: overwriting "destroys calibration exactly on the contested cases and makes the
debate step unmeasurable."

### 2.3 — The default debate path is substring matching with magic constants

`fusion/debate.py:52-97`. Because `llm_api_key` defaults to `None` (`config.py:62`),
`_heuristic_debate_resolution` is the **normal** path, not a fallback. It substring-matches
lowercased source and returns a hard-coded `final_score` of `0.25` or `0.85`.

`debate.py:69` lists `"int("` among the sanitizer keywords. **`"int("` is a substring of `print(`**
— so any code containing a print statement is classified as sanitized, `resolved_vulnerable=False`,
posterior forced to 0.25. The keywords also match inside comments and string literals, the same
raw-text trap §5 warns about for static rules.

### 2.4 — The static agent is counted as two independent witnesses

`engine/config.py:11-20` gives `structural.taint` and `structural.semgrep` separate LR table
entries. Both are rule-based analyses of the same source text in the same package — maximally
correlated. Two "high" hits multiply: **8.5 × 7.0 = 59.5×** from what is really one agent.

An independence violation distinct from anchoring, and it inflates posteriors precisely where the
project claims rigor. Not addressed by §5 — see `DECISIONS.md` D-011.

### 2.5 — Anchoring

`engine/orchestrator.py:111-124`, explicitly labelled "Phase 1" / "Phase 2":

```python
        static_evidence = await self._run_agent_safe(self.static_agent, unit, anchors=None)
        anchor_keys: Set[str] = {ev.finding_key for ev in static_evidence if not ev.abstained ...}
        semantic_task = self._run_agent_safe(self.semantic_agent, unit, anchor_keys)
        context_task = self._run_agent_safe(self.context_agent, unit, anchor_keys)
```

§5: breaks the conditional independence the fusion math assumes.

### 2.6 — Evidence is silently dropped

`fusion/bayes.py:61-62` — `except Exception: pass` inside `normalize_evidence`. Evidence that fails
to normalize vanishes, corrupting the posterior with no signal to any caller.

### 2.7 — The posterior is clamped; the LRs are not

`fusion/bayes.py:119` clamps `posterior_p` to [0.0001, 0.9999]. §5 requires the **likelihood
ratios** clamped, with Laplace smoothing. Neither exists.

---

## Tier 3 — Components that do not do what their names say

### 3.1 — The def-use graph is built and discarded

`static-agent/taint/engine.py:88-90`:

```python
        defuse = build_defuse_graph(unit.post_src, language=lang_key)
        symbols = extract_symbols(CodeParser().parse(unit.post_src, lang_key) or None) if False else []
```

`defuse` is never referenced again. `import networkx as nx` (`engine.py:6`) is unused. `symbols` is
hard-wired to `[]` by the literal `if False else []`, so `enclosing_symbol()` at `:119` can only
ever return `None` — which is why `finding_key`'s symbol component is always empty.

`build_defuse_graph` itself (`defuse.py:56,72`) is regex over stripped lines, handles only
single-target simple assignment, and its `add_edge` results are never queried.

### 3.2 — "Taint paths" are a line-number cross-product

`engine.py:94-115`. Nested loop over sources × sinks; the only reachability test is
`if snk["line"] < src["line"]: continue`. **No variable is tracked from source to sink.** A source
on line 2 and an unrelated sink on line 40 touching a different variable produces a finding.

The emitted `taint_path` artifact always has exactly two steps and never contains a `propagation`
role, despite `render.py:16` defaulting to it.

### 3.3 — Detection is raw regex over untokenised lines

`engine.py:44-47` (sources), `:61-68` (sinks), `:83-86` (sanitizers) all iterate
`unit.post_src.splitlines()` and call `re.search` (`catalog.py:82-89`). tree-sitter is correctly
wired at `parse.py:40-41` but is unreachable from the analysis path — it is called only from the
dead `if False` branch and from `tests/test_parse.py`.

Concrete consequences:

- `# TODO: replace os.system with subprocess` matches `os\.(system|popen)` and registers a
  **critical CWE-78 sink**
- JS sink `\beval` (`sinks.yml:26`) matches the identifiers `evaluate`, `evalContext`
- `requires_arg` / `forbids_arg` are same-line-only, so `subprocess.run(cmd,\n shell=True)` is
  missed, and `yaml.load(f)` with `Loader=SafeLoader` on the next line is reported as CWE-502

This is exactly the trap named in the repo's own `01-static-agent-BUILD.md:331-332`.

### 3.4 — Sanitizers ignore their class

`engine.py:101-109` kills taint if **any** sanitizer matched **any** line between source and sink:

```python
                for line_num in range(src["line"], snk["line"] + 1):
                    if line_num in sanitizer_lines:
                        hit_sanitizer = True
```

`RuleSanitizer.clears: List[str]` is declared at `catalog.py:34` and **never read** — one grep hit
repo-wide, the declaration itself. Sinks have no `class:` field at all, and `RuleSink`'s
`model_config = ConfigDict(extra="ignore")` (`catalog.py:19`) means adding one to the YAML would be
silently dropped.

So an `html.escape` call (clears `xss`) anywhere between a source and an `os.system` line suppresses
the CWE-78 finding.

### 3.5 — Parameterised SQL is modelled as a sanitizer

`rules/sanitizers.yml:2-4`. §5 explicitly forbids this — it is a property of the sink call, to be
modelled as `safe_when: params_passed_separately`. Repo-wide grep for `safe_when` /
`params_passed_separately`: zero hits.

Consequence: a safe `execute(q, (uid,))` on line 5 clears taint for a genuinely vulnerable
`execute(f"...{x}")` on line 9 in the same function.

### 3.6 — No type-coercion sanitizers

`rules/sanitizers.yml` contains five entries total: `sql.parameterized`, `shlex.quote`,
`html.escape`, `path.safe_join`, `encodeURIComponent`. No `int()`, `float()`, `uuid.UUID()`, or
allowlist-membership rule exists. §5 calls these "the largest false-positive source without them."

### 3.7 — The context agent's reasoning is four substring tests

`context-agent/reasoning/analyzer.py:25-56`. No LLM client, no jinja import.
`reasoning/prompts/cross_pr_v1.md` exists and is referenced by **no code**. The retrieved document
is used only as a gate (`:27`) and as a 300-character artifact excerpt (`:45`) — its content never
influences what is detected. `analyzer.py:29` recovers decorators by substring-scanning source
because `ChangeUnit` has no `decorators` field.

### 3.8 — Embeddings silently degrade to MD5 hashing

`context-agent/rag/embedder.py:13-46`. `sentence-transformers` is **not** in the package's
`pyproject.toml:11-16` (only in root `requirements.txt:25`), so a normal install of that package
takes the `except ImportError` branch and produces a 384-dim **MD5 term-hashing** vector — numbers
with no semantic meaning, cosine ≈ 0 between paraphrases. No log line, no abstention.

`chromadb` is likewise absent from the package's dependencies, so the default path is the SQLite
fallback: a full table scan with pure-Python cosine (`store.py:103-121`), O(n) per query.

### 3.9 — The anti-sycophancy exemplars are never loaded

`semantic-agent/prompts/exemplars/` contains three correct files, two returning `{"findings": []}`.
Repo-wide grep for `exemplar`: three hits, **all in Markdown**. Zero Python references.
`agent.py:59-69` loads only `system_v1.md` and `user_v1.jinja`, neither of which contains few-shot
examples. The mechanism §5 specifies to teach "safe-by-default is an acceptable answer" is inert;
only a prose instruction survives.

### 3.10 — The hallucination gate has 3 of 4 checks, two weakened

`semantic-agent/mapping.py:16-46`.

| §5 check | Status |
|---|---|
| Sink expression verbatim in `post_src` | ✅ present and strict (`:32`) |
| Evidence lines within unit range | ⚠️ allows `post_lines_count + 5` (`:43`) — five lines past the end |
| File path differs | ⚠️ falls back to **basename** (`:25-27`) — `vendor/evil/users.py` passes against `app/api/users.py` |
| CWE outside `IN_SCOPE_CWES` | ❌ **absent entirely** |

`LLMFinding.cwe` is a free-form `str` (`schema.py:26-29`), so any string the model emits is
upper-cased and shipped into `Evidence.cwe`. `finding.start_line` / `end_line` are never validated —
only `evidence_lines`.

### 3.11 — No size check; oversized units return silence, not abstention

Repo-wide grep for `unit_too_large`, `truncat`, `max_lines`, `MAX_UNIT`: zero hits. The agent does
not truncate (correct) but does not abstain either. An oversized unit trips the budget check at
`agent.py:121-128` and `break`s; because `parse_failures` was never incremented, the guard at `:166`
is False, `aggregate_self_consistency([])` returns `[]`, and `analyze()` returns an **empty list**.
Downstream that is indistinguishable from "reviewed, clean."

### 3.12 — A missing API key reports "clean"

`semantic-agent/agent.py:41-49` falls back to `StubLLMClient`, which returns `{"findings": []}`
(`stub.py:55`). A misconfigured production deploy silently reports every PR clean, with no abstention
and no warning.

---

## Tier 4 — Pipeline and infrastructure

### 4.1 — ChangeUnits are per-file, not per-function

`engine/github/parser.py:111-118` — `unit_id = f"pr-{pr_number}-file-{idx}"`, `symbol=None`. §5's
unit of analysis is the changed function. With `symbol=None`, the key's symbol component is always
`''`, so all findings in a file collapse together.

### 4.2 — `post_src` is reconstructed from the diff patch

`parser.py:42-83` concatenates hunk fragments (added lines + context lines) into a synthetic
`post_src`. The result is not real source: syntactically broken, line numbers wrong. No structural
analysis can be correct on this input. Files for which GitHub omits `patch` (large diffs) are
silently skipped at `:102`.

### 4.3 — Everything runs inline; no queue

`engine/github/webhook.py:85`. The handler fetches PR files, runs all agents, calls the LLM, and
posts the comment before returning. `fetch_pr_files` uses blocking `requests.get` inside an
`async def`, stalling the event loop. No Celery, Redis, PostgreSQL, SQLAlchemy or Alembic anywhere
in the repository. GitHub's 10s limit will be exceeded on any non-trivial PR.

### 4.4 — Missing agents degrade silently to "clean"

`engine/orchestrator.py:37-61` — an import failure yields a `DummyAgent` returning an abstention,
logged at `INFO`. Combined with `main.py:14-23`'s `sys.path` mutation, agents could fail to load in
production and the system would still post **"✅ No security vulnerabilities detected."**

### 4.5 — Units processed sequentially

`orchestrator.py:168` — `for unit in units:` awaiting each in turn. No concurrency across units,
against a < 5 min full-audit target.

### 4.6 — Only 6 of 10 in-scope CWEs have any detection path

`rules/sinks.yml` covers CWE-22, 78, 79, 89, 94, 502. **CWE-639, 798, 918 have no path at all**;
CWE-862 exists only as the hard-coded literal in 3.7. §5 notes that CWE-862/639 authz cases "exist
to prove heterogeneity" — so the heterogeneity argument currently has no supporting evidence.

`semgrep/mapping.py:40` emits `CWE-200` as a fallback, outside any mandated set.

### 4.7 — Two fixtures; no corpus

`tests/fixtures/sample_unit.json` (vulnerable, CWE-89) and `sample_unit_safe.json` (parameterised
twin). Three further vulnerable units are inline in tests with **no safe counterparts**. Sinks with
zero fixtures of any kind: `subprocess.shell`, `yaml.unsafe_load`, `path.open`, `child_process.exec`,
`dom.innerHTML`. **7 of 8 sinks have no safe twin; 5 have no fixture at all.** No corpus directory
exists.

### 4.8 — The contract integrity mechanism was defeated

`00-START-HERE.md:40` pins `EXPECTED_SHA256 = "bf88600b0f4ec571f2247a5e13a083a4ede9b9d9525e77c678abca0d447483f4"`.
All four `test_contract_integrity.py:6` carry `7176be9e1d36850bd6a2f4d79332d40a5fdc7812a81faa8313ebe3bfe6a19846`.

The hash constant was rewritten to make the test pass — verbatim what that file's own comment
forbids ("Do NOT update this hash to make the test pass"). The hashing method was also changed from
raw bytes to LF-normalized (`test_contract_integrity.py:12`).

### 4.9 — Stack drift

Static agent requires Python `>=3.12`; the other three declare `>=3.10` while linting and
type-checking as py312. The engine has no `[tool.ruff]` or `[tool.mypy]` section at all.

**Missing entirely:** `uv`, Celery, Redis, PostgreSQL/pgvector, SQLAlchemy, Alembic,
scikit-learn, wasmtime, githubkit, import-linter, syrupy, hypothesis.
**Present but explicitly rejected by §4:** ChromaDB (`requirements.txt:26`).
Root `main.py:14-23` resolves packages by mutating `sys.path`.

---

## What conforms

Worth stating precisely, because little does.

- **Agent isolation is clean.** No agent imports a sibling, the engine, GitHub, or any DB client.
  Full import inventory across all three `src/` trees confirms it. Dependency direction is correct:
  the engine imports the agents, guarded. **This is the one architectural property that survived,
  and it is what makes a rebuild cheap rather than catastrophic.**
- **`analyze()` never raises** in any of the three agents. Each has a top-level `try/except` returning
  an abstention (`static:40-49`, `semantic:191-201`, `context:111-121`), plus nested guards in
  `engine.py:150-159` and `semgrep/runner.py:72-82`.
- **The four `contracts.py` copies are byte-identical** (`9a4b2337af7c9678…`). The vendoring
  discipline held; all four drifted *together*, away from spec, not apart from each other.
- **`reporter.py:25-30` fires on the clean path** — a genuine §2 requirement met.
- **Test-file findings are downweighted, not suppressed** (`scoring.py:30-31`, `-0.20`). Correct per §5.
- **`raw_score` is present and agent-internal**, as specified.
- **n=3 self-consistency uses varying seeds** — `agent.py:97-137`, `seed = 100 + i` → 100/101/102.
  (Caveat: Gemini's `generateContent` ignores a `seed` field, so real variation comes from
  `temperature=0.3`. The seed does genuine work in the cache key, which is what stops the cache
  collapsing three samples into one.)
- **The LLM cache key includes all six mandated components** (`llm/cache.py:33-44`); sample_index
  arrives transitively via seed. Two latent weaknesses: `{seed or 0}` collides `seed=0` with `None`,
  and the bare `|` separator is unescaped and appears in code.
- **Cold start and similarity floor both abstain** (`context/agent.py:39-49`, `:85-95`) — though the
  floor defaults to 0.2 so near-noise passes, `.env.example` disagrees at 0.5, and only
  `distances[0]` is tested while documents 2..k pass unfiltered.
- **Scoring is a hand-tuned formula** (`scoring.py:14-33`), which §5 permits until v0.9. Note three
  of its inputs are effectively constant at the call site: `network_facing=True` unconditionally
  (`engine.py:126`), `path_length` always 2, and `partial_sanitizer` never assigned — so the score
  collapses to {0.60, 0.70, 0.80} minus 0.20 for test files.

---

## Priority

1. **0.1 (unauthenticated webhook)** — live exposure, independent of everything else, small fix
2. **1.1 + 1.2 (contract)** — everything downstream is written against these; fix before building on them
3. **2.1 (no corpus)** — gates every numeric claim the project makes
4. **4.1 + 4.2 (per-file units from diff fragments)** — blocks all structural analysis
5. Tier 3 rewrites, in `PLAN.md` build order

## What the test suite must learn to catch

Each of these would have caught a defect above, and none exists today:

- Static and semantic evidence for the same bug land under **one** `finding_key` and fuse into one
  posterior (would catch 1.1)
- `ContextAgent.analyze()` — not the internal function — returns non-empty on the bypass fixture
  (would catch 1.5)
- A forged webhook signature is rejected before any outbound call (would catch 0.1)
  — **exists as of Chapter 6**: `apps/api/tests/test_webhooks.py`, including the ordering case where
  malformed JSON under a bad signature must return 401 rather than 400, since a 400 would prove the
  parser ran on attacker bytes first
- An agent that ran cleanly emits SILENCE, not `[]` (would catch 1.2, 3.11)
- A sanitizer of the wrong class does not suppress a sink (would catch 3.4)
- A sink pattern inside a comment produces no finding (would catch 3.3)
