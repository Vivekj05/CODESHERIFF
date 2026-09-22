# CodeSheriff context agent (`codesheriff-agent-context`)

`context.rag` — the witness that reasons from **this repository's own merged history**.

## What it decides

It reports a security control that the repository's precedent establishes and the unit under
analysis does not apply. That is a bug no other witness can see: nothing in the changed function
says a guard is missing, and there is no taint path to prove and no sink to reach. Only the
repository's history says so.

Its failure mode is the flip side of that basis, and it is common: a repository with no relevant
history. That is an **abstention**, not a silence — at a likelihood ratio of exactly 1.0, costing
the posterior nothing.

## How

1. **Retrieve** merged excerpts for this unit, through a `PrecedentRetriever` the caller injects.
   The agent holds no store, no session and no embedding model.
2. **Read the control surface** of the unit and of each excerpt — decorators and called names, off
   the syntax tree, never by scanning source text.
3. **Mine what the repository establishes**: a control carried by *the same qualified symbol* in a
   merge, or shared by *two or more distinct sibling symbols*.
4. **Subtract what the unit applies**, and keep only what classifies as an authorization control.
5. Emit under `unit.key_for(cwe)`, so it corroborates an existing finding rather than opening one.

There is deliberately **no LLM here**. A model-driven version would fail the way `semantic.hosted`
fails, and four witnesses are only worth fusing if they fail differently.

It reports **CWE-862 and CWE-639 only**. A mined control that maps to no in-scope CWE cannot be
reported at all — that is what stops a real convention (every merged view calls `escape()`) from
becoming this witness's finding.

## Statements it can make

| Kind | When |
|---|---|
| DETECTION | An established authorization control is absent from this unit |
| SILENCE | Precedent was read and nothing this witness reports has regressed |
| ABSTENTION `no_precedent` | The repository holds no merged precedent |
| ABSTENTION `no_relevant_precedent` | Excerpts came back, none close enough to this unit |
| ABSTENTION `retrieval_unavailable` | The store or the embedding model could not be reached |
| ABSTENTION `unit_too_large` | Above `max_unit_bytes`; never truncated (D-015) |
| ABSTENTION `runtime_error` | Anything else. The agent never raises |

`retrieval_unavailable` and `no_precedent` are deliberately distinct: a store that is down is not a
repository that is new.

## Using it

```python
from context_agent.agent import ContextAgent

agent = ContextAgent(retriever=my_retriever)   # no retriever -> abstains on every unit
evidence = agent.analyze(unit)
```

`apps/worker` injects the pgvector-backed retriever, scoped to one repository at construction.

```bash
context-agent run unit.json --precedent history.json
context-agent version
```

There is no `ingest` or `search` command any more. Precedent is written by
`codesheriff-worker precedent backfill`, which owns the database and the embedding model.

## Measured

`tests/test_corpus_context.py`, on the **calibration split only** — 5/5 recall on the cases
`detectable_by` predicts for this agent, 0 false positives across 11 twins and negative controls.
Provisional development numbers, not calibrated ones (D-010).

See `DECISIONS.md` D-070 … D-072 and `PLAN.md` Chapter 12.
