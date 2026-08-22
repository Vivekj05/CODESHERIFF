# Standalone Agent Repos — Start Here

You are building three completely independent projects. Each one has its own folder, its
own git repo, its own virtualenv, its own tests, and its own build spec. None of them
imports from a shared package. You can open any one of them in a fresh chat with any LLM
and hand it a single build file.

```
~/projects/
├── codesheriff-static-agent/      ← build from 01-static-agent-BUILD.md
├── codesheriff-semantic-agent/    ← build from 02-semantic-agent-BUILD.md
└── codesheriff-context-agent/     ← build from 03-context-agent-BUILD.md
```

---

## 1. The one thing that must stay shared: `contracts.py`

Three independent programs still have to agree on what an input and an output look like,
or you can never combine them. Since you don't want a shared package, the answer is
**vendoring**: the same file, copied byte-for-byte into each repo.

```
codesheriff-static-agent/src/static_agent/contracts.py     ← identical
codesheriff-semantic-agent/src/semantic_agent/contracts.py ← identical
codesheriff-context-agent/src/context_agent/contracts.py   ← identical
```

**The obvious risk:** in week 9, at 1am, you add a field to one copy to unblock yourself,
forget the others, and three weeks later your fusion engine produces numbers that look
fine and mean nothing.

**The fix — a checksum test in every repo:**

```python
# tests/test_contract_integrity.py   (identical in all three repos)
import hashlib
from pathlib import Path

EXPECTED_SHA256 = "bf88600b0f4ec571f2247a5e13a083a4ede9b9d9525e77c678abca0d447483f4"

def test_vendored_contract_is_unmodified():
    p = Path(__file__).parent.parent / "src" / "<your_package>" / "contracts.py"
    actual = hashlib.sha256(p.read_bytes()).hexdigest()
    assert actual == EXPECTED_SHA256, (
        "contracts.py was edited locally. Contract changes must be made to the canonical "
        "copy and re-vendored into ALL agent repos together. Do NOT update this hash "
        "to make the test pass."
    )
```

The hash above is for the `contracts.py` shipped alongside this file. When you genuinely
need to change the contract (which should be rare after your static agent works):

1. Edit the canonical `contracts.py`
2. Bump `CONTRACT_VERSION`
3. Copy into all three repos
4. Recompute: `sha256sum contracts.py`
5. Update `EXPECTED_SHA256` in all three repos in the same sitting

Treat step 5 across all three as a single atomic task. A contract change that lands in two
of three repos is worse than no change at all.

## 2. Sample input — every repo gets this file

Save as `tests/fixtures/sample_unit.json` in each repo. It's your day-1 smoke test.

```json
{
  "contract_version": "1.0.0",
  "unit_id": "demo-001",
  "repo": "acme/webapp",
  "language": "python",
  "file": "app/api/users.py",
  "symbol": "get_user",
  "pre_src": "def get_user(user_id):\n    return db.query(User).get(user_id)\n",
  "post_src": "def get_user():\n    uid = request.args.get('id')\n    q = f\"SELECT * FROM users WHERE id = {uid}\"\n    return cursor.execute(q).fetchone()\n",
  "changed_lines": [1, 2, 3, 4],
  "start_line": 42,
  "neighbours": [
    {"relation": "caller", "symbol": "user_route", "file": "app/api/routes.py",
     "src": "@app.route('/users')\ndef user_route():\n    return jsonify(get_user())\n"}
  ],
  "imports": ["flask.request", "app.db.cursor"],
  "base_sha": "aaaaaaa",
  "head_sha": "bbbbbbb",
  "is_test_file": false,
  "repo_path": null
}
```

Expected behaviour once each agent works:

| Agent | On this input |
|-------|---------------|
| Static | One finding: CWE-89, taint path `request.args.get` → `uid` → `q` → `cursor.execute` |
| Semantic | One finding: CWE-89, `sink_expression` = `cursor.execute`, high severity |
| Context | Abstains with `no_anchor` unless given the static agent's `finding_key` as an anchor |

Make a **safe twin** of this file (`sample_unit_safe.json`) where line 3 is
`cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))`. Both static and semantic
must produce **zero** findings on it. That pair is the fastest sanity check you have.

## 3. Kickoff prompt for a fresh chat

Paste this into a new Antigravity / Claude / ChatGPT session, with the build file attached:

> I'm building a standalone Python agent that is one component of a larger security-review
> system, but this repo is fully independent — no shared packages, no imports from other
> repos.
>
> Attached: `<NN>-<agent>-BUILD.md` — the complete spec, and `contracts.py` — a vendored
> file I will drop into `src/<package>/contracts.py` unchanged.
>
> Rules for you:
> - Never modify `contracts.py`. Import from it; don't extend it.
> - Follow the folder structure in the spec exactly.
> - Work one numbered step at a time. Stop after each step and wait for me.
> - Write the tests for a step before the implementation for that step.
> - The agent must never raise. Every failure path returns an abstention Evidence.
> - Don't add dependencies that aren't in the spec's stack table without asking.
>
> Start with Step 1 and stop.

The "one step, then stop" instruction matters more than it looks. LLMs given a 15-step
plan will produce all 15 steps at once, and you'll get 2,000 lines you haven't read and
can't debug. Small steps that you actually review are how you stay able to answer
questions about your own project in the viva.

## 4. How these become one system later

Each repo is a normal installable package. When you build the orchestrator, it installs
all three:

```toml
# apps/engine/pyproject.toml
dependencies = [
  "codesheriff-static-agent @ file:///../codesheriff-static-agent",
  "codesheriff-semantic-agent @ file:///../codesheriff-semantic-agent",
  "codesheriff-context-agent @ file:///../codesheriff-context-agent",
]
```

(Or `git+https://github.com/you/codesheriff-static-agent@v0.4.0` once they're pushed —
which is better, because pinning a tag means the version that produced your calibration
data is the version that runs.)

Each agent exposes the same entry point:

```python
class Agent:
    id: str
    version: str
    def analyze(self, unit: ChangeUnit, anchors: set[str] | None = None) -> list[Evidence]: ...
```

Integration is then about 200 lines of orchestrator code. Full sequence and the checks to
run are in `agents/04-integration.md`.

## 5. Build order

**Static → Context → Semantic.**

Static first because it defines the findings the others attach to, and building it forces
you to exercise `finding_key` and the sink catalogue. Context second: cheap, deterministic,
and it tests `finding_key` from a second direction, which surfaces identity bugs while
they're still cheap to fix. Semantic last, because it's the only metered, non-deterministic
one — build it against a settled contract so your API budget goes on evaluation instead of
plumbing.

You can parallelise across teammates. The vendored contract is what makes that safe.
