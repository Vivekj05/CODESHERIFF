# BUILD SPEC — CodeSheriff Static Agent (standalone repo)

**Repo:** `codesheriff-static-agent` · **Package:** `static_agent`
**Agent IDs:** `structural.semgrep`, `structural.taint` · **Est. 2.5–3 weeks part-time**
**Depends on:** nothing else in the CodeSheriff project. Fully self-contained.

---

## 0. Context for whoever/whatever is reading this

This repo builds **one component** of a larger system called CodeSheriff, which reviews
GitHub pull requests for security vulnerabilities using several independent analysers whose
opinions are later fused with Bayesian inference. This repo is one analyser. It knows
nothing about the rest of the system and must never depend on it.

**Its job:** given one changed function (a `ChangeUnit`), decide whether that change
introduces a vulnerability, and emit structured `Evidence` explaining why.

**Two detection backends, one package:**

- `structural.semgrep` — runs Semgrep's community rulesets. Broad coverage, noisy.
- `structural.taint` — a taint engine you write: source → sanitizer → sink reachability
  over a tree-sitter AST. Narrower, but it produces **the path**.

**Why write the taint engine when Semgrep exists** (you'll be asked this):

1. **Explainability.** Semgrep says "line 47 matches rule X." Your engine says
   "`request.args['q']` at line 42 → `q` at 45 → `cursor.execute` at 47, no sanitizer."
   Developers act on paths and ignore rule IDs.
2. **A differently-wrong second witness.** Fusion is only valuable if analysers fail
   differently. Semgrep is pattern-based; yours is flow-based. Two analysers wrong in the
   same way add nothing to a probability estimate.
3. **It's the actual contribution.** "We integrated Semgrep" is a config file.

**Explicitly out of scope** (keep this list current in the README — it becomes the paper's
Limitations section, and stating limits precisely reads as competence):
no inter-procedural analysis, no alias/pointer analysis, no framework-internal resolution
(Django ORM, Express middleware chains), no path-sensitivity, no type inference.

---

## 1. Folder structure (create exactly this)

```
codesheriff-static-agent/
├── README.md                       # what it detects + what it does NOT
├── CHANGELOG.md                    # every agent_version bump, with the reason
├── pyproject.toml
├── .python-version                 # 3.12
├── src/static_agent/
│   ├── __init__.py                 # exports StaticAgent, __version__
│   ├── contracts.py                # VENDORED — never edit
│   ├── config.py                   # pydantic-settings
│   ├── cli.py                      # typer: run | bench | explain | version
│   ├── agent.py                    # StaticAgent.analyze(unit, anchors=None) -> list[Evidence]
│   ├── scoring.py                  # features -> raw_score
│   ├── semgrep/
│   │   ├── __init__.py
│   │   ├── runner.py               # subprocess + SARIF parse
│   │   └── mapping.py              # rule_id -> CWE, confidence -> score
│   └── taint/
│       ├── __init__.py
│       ├── parse.py                # tree-sitter -> normalised node view
│       ├── symbols.py              # symbol extraction, enclosing_symbol(line)
│       ├── defuse.py               # def-use graph per symbol
│       ├── engine.py               # worklist taint propagation
│       ├── catalog.py              # loads rules/*.yml
│       └── render.py               # path -> Artifact
├── rules/
│   ├── sources.yml
│   ├── sanitizers.yml
│   ├── sinks.yml
│   └── semgrep/                    # custom .yaml rules beyond the registry packs
├── corpus/                         # this repo's own labelled mini-benchmark
│   ├── python/
│   │   ├── 001_sqli_fstring/{unit.json,label.json}
│   │   ├── 001_sqli_fstring_SAFE/{unit.json,label.json}
│   │   └── ...
│   └── javascript/
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   │   ├── sample_unit.json
│   │   ├── sample_unit_safe.json
│   │   ├── python/                 # *_vuln.py / *_safe.py pairs
│   │   └── javascript/
│   ├── test_contract_integrity.py  # the SHA-256 check from 00-START-HERE §1
│   ├── test_parse.py
│   ├── test_defuse.py
│   ├── test_engine_python.py
│   ├── test_engine_js.py
│   ├── test_scoring.py
│   ├── test_semgrep_mapping.py
│   ├── test_evidence_contract.py   # all output validates as Evidence
│   └── test_failure_modes.py       # every boundary failure -> abstain, never raise
└── bench/
    ├── run.py                      # metrics over corpus/
    └── reports/
```

## 2. Stack

| Concern | Choice | Note |
|---------|--------|------|
| Python | 3.12 | Best wheel availability for tree-sitter |
| Env/deps | `uv` | `uv init`, `uv add`, `uv run` |
| Models | `pydantic>=2.7` | Required by `contracts.py` |
| Parsing | `tree-sitter` + `tree-sitter-language-pack` | One wheel, many grammars; error-tolerant (PRs contain broken code); byte-accurate ranges |
| Pattern scan | `semgrep` CLI via subprocess, `--sarif` | Subprocess not the Python API — clean timeouts, process isolation |
| Rules | `pyyaml`, validated into pydantic models | Rules are data, not code |
| Graphs | `networkx` | Def-use graph + path extraction; don't hand-roll |
| CLI | `typer` | |
| Tests | `pytest`, `pytest-cov`, `syrupy` (snapshots), `hypothesis` | Snapshots suit taint paths well |
| Lint/types | `ruff`, `mypy --strict` | |

Not Python's `ast`: tree-sitter handles JS/TS with the same API, tolerates syntax errors,
and gives byte ranges you'll need later for comment anchoring.

## 3. Public interface (must match exactly)

```python
class StaticAgent:
    id: str = "structural.taint"          # or "structural.semgrep" per backend
    version: str = "0.1.0"

    def __init__(self, config: StaticConfig | None = None) -> None: ...

    def analyze(
        self, unit: ChangeUnit, anchors: set[str] | None = None
    ) -> list[Evidence]:
        """Never raises. Returns [] or [Evidence(...)] or [Evidence.abstention(...)]."""
```

CLI:
```bash
static-agent run tests/fixtures/sample_unit.json     # Evidence[] JSON to stdout
static-agent run -                                   # read ChangeUnit from stdin
static-agent run --pretty <file>                     # human table
static-agent explain <file>                          # taint path, rendered as a chain
static-agent bench --corpus corpus/                  # metrics.json
static-agent version                                 # {"agent_id":..., "agent_version":...}
```
Exit codes: `0` success (including no findings and abstentions), `2` bad input, `3` internal.
**Never exit non-zero because nothing was found.**

---

## 4. Build steps

### Step 1 — Scaffold and prove the seam (day 1)
- [ ] `uv init`, folder structure, `pyproject.toml` with the `static-agent` console script
- [ ] Drop in `contracts.py` unchanged; add `tests/test_contract_integrity.py`
- [ ] `cli.py run` reads a ChangeUnit and emits **one hardcoded** Evidence
- [ ] `tests/test_evidence_contract.py`: output parses as `list[Evidence]`
- [ ] `static-agent run tests/fixtures/sample_unit.json` prints valid JSON

*Why a fake Evidence first:* it proves input parsing, output serialisation, and the CLI
protocol before any analysis exists. End day 1 with a working seam and every later day is
pure detection work.

### Step 2 — Semgrep backend (days 2–3)
- [ ] `runner.py`: write `post_src` to a temp file with the right extension, run
      `semgrep --sarif --config p/security-audit --config p/owasp-top-ten --timeout 30 --quiet`
- [ ] Parse SARIF → `Evidence`; map rule → CWE in `mapping.py` (YAML table first, fall back
      to the rule's own `cwe` metadata)
- [ ] `finding_key` from `(file, symbol, cwe, sink_expr)` using `contracts.finding_key`
- [ ] `raw_score` from rule confidence + severity metadata; document the mapping in a docstring
- [ ] Cap at 10 Evidence per ChangeUnit (log what was dropped)
- [ ] Semgrep missing/timeout/crash → `Evidence.abstention(reason=tool_unavailable|timeout)`
- [ ] Tests: 6 fixtures, snapshot the mapped Evidence

### Step 3 — Parse, symbols, def-use (days 4–6, Python only)
- [ ] `parse.py`: language → parser; normalised node view (kind, byte range, line range, text, children)
- [ ] `symbols.py`: extract functions/methods/classes with ranges; `enclosing_symbol(line)`
- [ ] `defuse.py`: per symbol, walk statements in order; build `Def`/`Use` nodes and edges for
      assignment, augmented assignment, f-string and `%`/`.format` interpolation, call
      arguments, returns, subscripts, attribute access
- [ ] Tests: 12 small snippets with **hand-written expected edges**

*Why the graph before the taint:* taint propagation is a graph traversal. Get the graph
right first and the engine is ~150 lines instead of a 600-line pile of special cases.

### Step 4 — The taint engine (days 7–9)
- [ ] `catalog.py`: load and validate the three YAML files. Start small and precise:

```yaml
# rules/sources.yml
python:
  - id: flask.request.args
    match: "request\\.(args|form|json|values|cookies)"
    cwe_hint: injection
  - id: os.environ
    match: "os\\.environ"
  - id: sys.argv
    match: "sys\\.argv"
javascript:
  - id: express.req
    match: "req\\.(query|body|params|headers)"
```
```yaml
# rules/sinks.yml
python:
  - id: sql.execute
    match: "(cursor|conn|db|session)\\.execute"
    cwe: CWE-89
    danger: high
  - id: os.system
    match: "os\\.(system|popen)"
    cwe: CWE-78
    danger: critical
  - id: subprocess.shell
    match: "subprocess\\.(run|call|check_output|Popen)"
    requires_arg: "shell=True"
    cwe: CWE-78
    danger: critical
  - id: yaml.unsafe_load
    match: "yaml\\.load"
    forbids_arg: "Loader=SafeLoader"
    cwe: CWE-502
    danger: high
  - id: path.open
    match: "(open|os\\.remove|shutil\\.rmtree)"
    cwe: CWE-22
    danger: medium
javascript:
  - id: eval
    match: "\\beval"
    cwe: CWE-94
    danger: critical
  - id: child_process.exec
    match: "child_process\\.exec"
    cwe: CWE-78
    danger: critical
  - id: dom.innerHTML
    match: "(innerHTML|dangerouslySetInnerHTML)"
    cwe: CWE-79
    danger: high
```
```yaml
# rules/sanitizers.yml
python:
  - id: sql.parameterized
    match: "execute\\([^,]+,\\s*[\\(\\[]"     # params passed separately
    clears: [injection]
  - id: shlex.quote
    match: "shlex\\.quote"
    clears: [command]
  - id: html.escape
    match: "(html\\.escape|markupsafe\\.escape)"
    clears: [xss]
  - id: path.safe_join
    match: "(werkzeug\\.utils\\.secure_filename|os\\.path\\.basename)"
    clears: [path]
```

- [ ] `engine.py`: worklist algorithm — seed taint at source defs, propagate along def-use
      edges, kill taint at a sanitizer whose `clears` covers the sink's class, record a hit
      when tainted data reaches a sink
- [ ] Emit the ordered path as a `taint_path` artifact:
      `[{"file":..., "line":..., "expr":..., "role":"source|propagation|sink"}]`
- [ ] Unknown function calls: propagate taint through by default (conservative) but lower
      `raw_score`. **Record this decision in the README** — it's a real precision/recall
      lever and a good discussion point
- [ ] Tests: every `*_vuln.py` fixture produces a path; every `*_safe.py` twin produces none

### Step 5 — Scoring (day 10)
- [ ] `scoring.py` — explicit and testable, not a black box:

```python
score = clamp(
    0.45
    + 0.20 * (sink.danger == "critical")
    + 0.10 * (sink.danger == "high")
    - 0.25 * partial_sanitizer_on_path
    - 0.05 * min(path_length - 2, 4) / 4      # long chains are less certain
    + 0.15 * source_is_network_facing
    - 0.20 * unit.is_test_file
)
```
- [ ] Unit-test each term's effect independently
- [ ] **Never tune these weights on your validation or test data.** Record the split used

### Step 6 — JavaScript / TypeScript (days 11–12)
- [ ] Same pipeline with JS/TS grammars
- [ ] Template-literal interpolation as a propagation edge
- [ ] Unsupported language → `abstention(unsupported_language)`

### Step 7 — Failure modes (day 13)
- [ ] Parse error, semgrep binary missing, timeout, >5k-line source, empty `post_src` →
      each abstains with its own distinct reason, none raise
- [ ] 30s global budget per ChangeUnit; return partial results on timeout
- [ ] Hypothesis property test: random source strings never crash the parse path

### Step 8 — Build the corpus and measure (days 14–15)
- [ ] 40 corpus cases: 20 vulnerable + 20 safe twins across CWE-89/78/79/22/502

```json
// corpus/python/001_sqli_fstring/label.json
{"label": "vulnerable", "cwe": "CWE-89", "note": "f-string interpolation into execute()"}
```
- [ ] `bench/run.py` → precision, recall, FPR, safe-twin pass rate, p95 latency, by CWE class
- [ ] Fill in the results table below for three configurations
- [ ] Error analysis: list every FP and FN with a one-line cause

---

## 5. Acceptance — "does it work?"

| Check | Target |
|-------|--------|
| Safe-twin pass rate (no finding on the sanitised twin) | ≥ 90% |
| Vulnerable-fixture detection (taint backend) | ≥ 75% |
| Every detection carries a non-empty `taint_path` artifact | 100% |
| `finding_key` stable across a ±3-line shift of the same bug | 100% (test it) |
| p95 latency per ChangeUnit | ≤ 3s |
| Crashes over the whole corpus | 0 |
| `mypy --strict` + `ruff check` | clean |
| Coverage | ≥ 80% |

### Results (fill in — this table goes in your paper)
| Backend | Precision | Recall | FPR | Safe-twin pass | p95 latency |
|---------|-----------|--------|-----|----------------|-------------|
| Semgrep only | | | | | |
| Taint only | | | | | |
| Both merged | | | | | |

## 6. Traps

- **Sink catalogue creep.** Ten precise sinks beat sixty sloppy ones. Every new sink ships
  with a vulnerable fixture *and* a safe twin, or it doesn't get added.
- **Regex on raw source text.** Match on AST node structure where you can. Text regex will
  match inside comments and strings and quietly destroy your precision.
- **Test-file findings.** Downweight (`is_test_file`), don't suppress — suppressing hides
  the signal from the fusion stage downstream.
- **Editing `contracts.py`.** If you need a field it doesn't have, you almost certainly
  need an artifact instead. Artifacts are the extension point.
