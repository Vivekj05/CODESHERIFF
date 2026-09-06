# `codesheriff-patch` — draft, verify, suggest

One finding in, one suggested change out — or a recorded reason there is none.

```
propose(unit, cwe, finding_key, model, config, rechecks, ...) -> PatchProposal
```

**Suggestions only.** Nothing here commits, merges, pushes a branch or writes to a repository
(`PROJECT_CONTEXT.md` §2). What it produces is a review comment body carrying a fenced
` ```suggestion ` block, which a human applies or does not.

## What "verified" means

The question §7 left open was *what verification means when a repository has no test suite*. The
answer is that it means the same thing either way, because **CodeSheriff never runs the
repository's test suite** (D-094). Untrusted pull request code executes inside the Wasmtime sandbox
or it does not execute at all (§5, D-076), and a test suite needs the dependencies, the network and
the filesystem that the sandbox exists to deny.

So the ladder is fixed, and every rung is something this system can do against any repository:

| Rung | What it asserts |
|---|---|
| `parses` | The repaired function is valid Python. `ast`, not tree-sitter — a parser that tolerates broken syntax would pass a broken patch |
| `signature_unchanged` | Same name, parameters and async-ness. Callers live in files this audit never fetched |
| `names_resolve` | Every name the patch reads already exists in the file. A suggestion replaces lines *inside* a function and cannot add an import |
| `changes_something` | The draft is not the original. That is how the model says "no repair" |
| `regression:<witness>` | A witness that **detected** this CWE before the patch does not detect it after |
| `no_new_weakness:<witness>` | The patch introduced no in-scope weakness the original did not have |

Three outcomes per rung — `passed`, `failed`, `not_run` — for the reason evidence has three kinds
(D-005). A check that could not run is never rendered as one that passed, and the whole ladder is
published with the suggestion so a reader can see which rungs were empty.

Only the **deterministic** witnesses recheck. `semantic.hosted` is excluded: re-asking a hosted
model whether the repair it drafted is a repair is the drafter's own family grading the drafter,
and a non-deterministic rung would make the same draft publishable on one run and not on the next.

## What this package holds

Nothing that talks to anything. The model arrives through the `PatchModel` protocol and the
witnesses through `Rechecker`, both implemented by `apps/worker` (D-072) — `lint-imports` fails the
build for a patcher that reaches `httpx`, `githubkit`, a database client or an agent package. The
practical consequence is that the whole draft-verify-retry loop runs against a scripted model with
no key, no quota and no interpreter, which is what its tests do.

## What it never does

- **Never feeds a rejected draft back to the model** (D-093). Retries carry CodeSheriff's own
  rejection reasons; the draft itself is model output shaped by attacker-controlled source, and
  returning it as instruction would put untrusted text outside the sentinel.
- **Never publishes model prose** (D-096). The response carries exactly one field — the repaired
  function — so there is nothing to screen on the way out.
- **Never publishes a repair it cannot anchor inside the diff** (D-095). GitHub rejects a review
  comment on a line outside a hunk, and this system deliberately never reads GitHub's `patch`
  field (D-048), so `ChangeUnit.changed_lines` is the only span known to be in the diff.
- **Never truncates** an oversized function to fit the drafting budget (D-015).
- **Never becomes a fifth witness.** `patch.hosted` emits no `Evidence` and is absent from
  `WITNESS_OF_AGENT` deliberately: it reads the finding, so it is maximally dependent on the four
  witnesses that produced it (D-008, D-052).

## Configuration

`PATCH_ENABLED`, `PATCH_MODEL`, `PATCH_TEMPERATURE`, `PATCH_MAX_DRAFTS`, `PATCH_MAX_UNIT_BYTES`,
and the shared `GEMINI_API_KEY`. See `.env.example`. With no key the patcher records
`patcher_unavailable` per finding and the pull request comment says a suggestion was not attempted
— there is no stub fallback, because a suggestion nobody's model wrote must never be published.
