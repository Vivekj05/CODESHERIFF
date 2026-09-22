# codesheriff-corpus

Ground truth. 60 hand-written units in 30 twin pairs, three pairs for each of the ten CWEs in
`IN_SCOPE_CWES`, with committed splits.

> The corpus is not a training set for detecting vulnerabilities. It answers a different question:
> how much each agent should be trusted when it speaks. The learning is about the witnesses, not the
> crime.

Every likelihood ratio, the prior, and the alert threshold are fitted here — or they are asserted,
and asserting them is the failure the paper exists to criticise.

## The shape of a case

```
cases/<cwe-slug>/<pair>-{vuln,safe}/
    case.yaml     labels and unit metadata
    post.py       the unit under analysis
    pre.py        optional — omit for an added function
```

A **pair** is one function, one file, one symbol, once vulnerable and once safe. Both members carry
the same `cwe`: the safe twin is not "about nothing", it is the case where that specific CWE must
*not* be reported. Because they share file, symbol and CWE, they share a `finding_key` — so "did
this agent fire on the safe twin" is a lookup rather than a judgement.

`case_id` must be `<pair_id>-vuln` or `<pair_id>-safe`, and must equal its directory name. Pairing
is derived from the id rather than declared, so a rename cannot orphan a twin.

## Adding a case

1. Create both directories. **Never add a vulnerable case without its safe twin** — the loader
   raises on an incomplete pair, and an unpaired case measures recall with nothing to say about
   precision.
2. Make the twin *near*. The safe member should differ by the flaw and nothing else. The safe
   `cwe-089-order-sort` still builds its query with an f-string; the safe `cwe-918-link-preview`
   still calls `urlopen`. A twin that also differs in style measures style.
3. Write `rationale` on both. If it is hard to write, the label is not certain enough to keep.
4. Set `detectable_by` on the vulnerable member only, from the rule in `DECISIONS.md` D-047 —
   **before** running any agent, and never widened afterwards. It decides whose miss is forgiven.
5. `uv run codesheriff-corpus validate`, then `uv run codesheriff-corpus assign --seed <n>`. Assign
   places new pairs and **refuses to move** ones that already have a split.
6. `uv run pytest packages/corpus`.

Case sources are deliberately vulnerable and are excluded from `ruff` and `mypy` (D-046) — linting
them would pressure you into fixing the very thing the case exists to contain. A test compiles every
one instead, because tree-sitter tolerates broken syntax and would quietly analyse a fragment.

## Splits

60/20/20 by **pair**, never by case, so a twin cannot straddle a split by construction. Each split
answers exactly one question (`PROJECT_CONTEXT.md` §6):

| Split | Pairs | Question |
|---|---|---|
| `calibration` | 18 | likelihood ratios and the prior are fitted here |
| `validation` | 6 | the alert threshold is swept here, ratios already frozen |
| `test` | 6 | evaluated exactly once, at the very end |

Immutability is **detectable, not prevented**. `assign` will not move a settled pair, and
`split_hash` is recorded on every `calibration_runs` row, so a later edit shows up as a fit that no
longer matches the splits it claims. A committed checksum verified by a test is deliberately not
used: that is the mechanism `AUDIT.md` 4.8 records being defeated by rewriting the expected hash.

Six pairs cannot cover ten CWEs. Every CWE has a calibration pair, but validation and test reach six
of ten each — so final ECE and Brier are **aggregate claims across CWEs, not per-CWE claims**.

## Hashes

`corpus_hash` and `split_hash` fill the `calibration_runs` columns that have held nothing since
Chapter 3. Both are computed over the canonical *loaded* form, not raw file bytes: reflowing a
comment in a `case.yaml` is not a change to the corpus, while a line of `post.py`, a label, or a
`detectable_by` entry is. Both are independent of git, so they recompute from an installed wheel.

## Nothing that analyses code may import this package

Enforced by a dedicated `import-linter` contract. An agent that can read `label` is being told the
answer rather than measured; one that can read `detectable_by` can be excused by the field that
exists to excuse it fairly. The leak would not look like cheating — it would look like a convenient
import in a test helper that someone later reached for from the agent itself.
