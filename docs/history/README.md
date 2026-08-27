# Archived specifications — superseded

⛔ **Nothing in this directory is authoritative. Do not build from these files.**

They are kept for provenance: the report needs to show how the design evolved, and one of these
documents is the direct cause of the non-conformance recorded in `AUDIT.md`. They are archived
here rather than deleted so that history is legible, and moved out of the repository root so
nothing in it looks authoritative any more.

**Authoritative order:** `PROJECT_CONTEXT.md` → `DECISIONS.md` → `AUDIT.md` → `PLAN.md`.
Start with `CLAUDE.md`.

---

## `00-START-HERE.md` — superseded in full

The earlier draft the committed code was built against. `PROJECT_CONTEXT.md` §5 reverses it on
four points, and **each reversal exists to fix a specific identified bug**:

| This file says | `PROJECT_CONTEXT.md` §5 says |
|---|---|
| Three independent repos, vendored `contracts.py` + SHA-256 checksum test | Monorepo, one shared `contracts` package; vendoring **explicitly dropped** |
| `analyze(unit, anchors=...)`; static runs first, passes finding keys downstream | **No anchors — agents run blind.** Anchoring correlates the agents and breaks the conditional independence the fusion math assumes |
| Context agent "abstains with `no_anchor` unless given the static agent's finding_key" | Context agent emits under the **incoming** `finding_key` — it corroborates, it does not solo |
| Three agents | Four — the runtime (Wasmtime/WASI) agent is part of the design |

The audit found the code contains the bug each reversal fixes, including one — `finding_key`
hashing the sink expression — that prevents the Bayesian engine from ever performing a single
update (`AUDIT.md` 1.1).

Two specific traps if you read it:

- The `contracts.py` snippet in §1 is the non-conformant contract.
- The checksum test in §1 did not work. Its expected hash was later rewritten to make it pass —
  verbatim what the file's own comment forbids (`AUDIT.md` 4.8). This is why `import-linter`
  replaced it (`DECISIONS.md` D-002).

## `01-static-agent-BUILD.md` — partially superseded

Genuinely useful detail on sinks, sanitizers and the def-use graph; check every claim against §5
first. Known conflicts:

- Line 166 specifies `finding_key` from `(file, symbol, cwe, sink_expr)` — wrong, see D-004.
- It models parameterised SQL as a sanitizer; §5 requires a sink property
  (`safe_when: params_passed_separately`), because as a sanitizer it clears taint for every
  injection sink in the function (`AUDIT.md` 3.5).

Its warnings are worth heeding — line 331 warns that text regex matches inside comments and
strings, which is exactly the defect the implementation shipped (`AUDIT.md` 3.3).

## `*_implementation_summary.md` — descriptive, and partly false

Three documents describing what each component was *intended* to do. They do not describe what
the code does, and several specific claims are contradicted by it:

| Claim | Reality |
|---|---|
| Semantic: "n=3 calls with **fixed seeds**" | Seeds actually vary (100/101/102) — the doc is wrong in the code's favour here |
| Semantic: three few-shot exemplars, two returning `[]` | The files exist; **no code loads them** (`AUDIT.md` 3.9) |
| Context: "Successfully retrieves related past PRs" | The analyzer is four hard-coded substring tests; retrieved documents never influence detection (`AUDIT.md` 3.7) |
| Context: acceptance criteria all ticked `[x]` | Several are not met |
| Fusion: `AGENT_LIKELIHOOD_TABLE` presented as "Calibrated Likelihood Ratios" | Hand-written constants; nothing was calibrated, and no corpus exists (`AUDIT.md` 2.1) |

Useful as a record of intent and as report material on how a plausible-looking spec diverged from
its implementation. Not useful as a description of the system.
