# `calibration/` — the inputs a fit is reproducible from

Committed on purpose. PROJECT_CONTEXT.md §6 requires every fitted number to be reproducible from
the calibration split and a recorded corpus hash, and a fit whose inputs lived only on the machine
that ran it would satisfy that requirement in the same way a comment satisfies a type checker.

```
observations/calibration.jsonl   what all four agents said about each of the 46 calibration cases
observations/validation.jsonl    the same for the 14 validation cases
responses/<case_id>.json         the semantic witness's recorded model output, validation only
```

**The output does not live here.** The fitted artifact is
`packages/engine/src/codesheriff_engine/calibration/calibration.json`, inside the package, so that
an installed wheel carries the numbers it fuses with.

## Why the observations are committed rather than re-derived

Producing them needs a WASI interpreter, a Gemini key and — for the structural witness's second
backend — a Semgrep build that does not exist on Windows. Committing them means `calibrate fit`
needs none of those, that a re-fit is a readable diff, and that a disputed ratio can be argued
about from the same bytes it was computed from.

Each file's first line is a header carrying the `corpus_hash`, the `split_hash` and the provenance
of the run — platform, Python version, agent versions, which backends were silent on every unit,
and where the semantic responses came from. `runner.read` refuses a file whose hashes no longer
match the corpus in the working tree, because fitting on stale observations would produce an
artifact whose recorded hash describes ground truth it was never measured against.

## Regenerating

```bash
uv run codesheriff-worker calibrate record --split validation   # only cases with no response yet
uv run codesheriff-worker calibrate observe --split calibration
uv run codesheriff-worker calibrate observe --split validation
uv run codesheriff-worker calibrate fit
```

`record` is the only command that calls a provider. The calibration split's model responses are
**not** here — they are the semantic agent's cassettes in
`packages/agent_semantic/tests/cassettes/`, shared with that agent's own corpus measurement, and
recorded by `packages/agent_semantic/tools/record_cassettes.py`. Two recordings of the same case
against the same prompt would be two answers to one question, and the first time they disagreed
nobody would know which one had been fitted on.

Validation responses are deliberately **not** cassettes. The semantic suite runs on every commit,
and a suite that could reach validation recordings would be iterating against the split §6 reserves
for selecting the threshold.

## The test split is not here, and must not be

It is evaluated exactly once, at the end (PLAN.md Chapter 18). `runner.cases_in_split` raises
`TestSplitSealedError` rather than returning it — a harness that would run on the test split if
asked is a harness that eventually will be.
