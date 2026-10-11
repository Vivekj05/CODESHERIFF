# 🧪 Test Cases & Execution Results Report

> **CodeSheriff Static Agent (`codesheriff-static-agent`)**  
> *Report Generated:* 2026-08-18 | *Test Status:* **14 / 14 PASSED (100%)** | *Suite Duration:* **0.12s**

---

## 📊 1. Test Suite Summary Table

| Category | File | Test Name | Purpose | Result |
| :--- | :--- | :--- | :--- | :---: |
| **Integrity** | `test_contract_integrity.py` | `test_vendored_contract_is_unmodified` | Verify SHA-256 integrity of vendored `contracts.py` | `PASSED` |
| **Graph** | `test_defuse.py` | `test_defuse_graph_building` | Verify Def-Use data flow graph construction | `PASSED` |
| **Engine (Py)** | `test_engine_python.py` | `test_python_sqli_detection` | Detect SQL Injection in Python (`CWE-89`) | `PASSED` |
| **Engine (Py)** | `test_engine_python.py` | `test_python_os_command_injection` | Detect Command Injection in Python (`CWE-78`) | `PASSED` |
| **Engine (JS)** | `test_engine_js.py` | `test_js_eval_injection` | Detect `eval()` Code Injection in JS (`CWE-94`) | `PASSED` |
| **Contracts** | `test_evidence_contract.py` | `test_sample_unit_vulnerable_detection` | Verify Evidence payload schema on vulnerable code | `PASSED` |
| **Contracts** | `test_evidence_contract.py` | `test_sample_unit_safe_twin_zero_findings` | Verify 0 findings on safe parameterized twin | `PASSED` |
| **Fault Mode** | `test_failure_modes.py` | `test_unsupported_language_abstains` | Abstain cleanly on unsupported language | `PASSED` |
| **Fault Mode** | `test_failure_modes.py` | `test_empty_post_src_does_not_raise` | Handle empty code without throwing exceptions | `PASSED` |
| **AST Parser** | `test_parse.py` | `test_code_parser_python` | Verify Tree-sitter AST parsing | `PASSED` |
| **AST Parser** | `test_parse.py` | `test_symbol_extraction` | Verify function scope and line range resolution | `PASSED` |
| **Scoring** | `test_scoring.py` | `test_clamp` | Bounded raw score clamping to `[0.0, 1.0]` | `PASSED` |
| **Scoring** | `test_scoring.py` | `test_scoring_weights` | Verify danger & test file scoring weight terms | `PASSED` |
| **Semgrep** | `test_semgrep_mapping.py` | `test_semgrep_mapping_sqli` | Map SARIF rule output to Evidence contract | `PASSED` |

---

## 🔍 2. Detailed Input vs Output Test Cases

### Case 1: SQL Injection Detection (`CWE-89`)

#### 📝 Code Under Analysis (`sample_unit.json`)
```python
def get_user():
    uid = request.args.get('id')                # Line 2: Untrusted Source
    q = f"SELECT * FROM users WHERE id = {uid}" # Line 3: String Interpolation
    return cursor.execute(q).fetchone()         # Line 4: Dangerous Sink
```

#### 💻 Command
```bash
static-agent run tests/fixtures/sample_unit.json
```

#### 🎯 Detected Evidence Output
```json
[
  {
    "agent_id": "structural.taint",
    "unit_id": "demo-001",
    "finding_key": "d74383367c4b07a1",
    "cwe": "CWE-89",
    "raw_score": 0.7,
    "confidence": 0.9,
    "explanation": "Taint path detected from source 'flask.request.args' at line 2 reaching sink 'sql.execute' at line 4 (CWE-89).",
    "artifacts": [
      {
        "artifact_type": "taint_path",
        "content": {
          "steps": [
            { "line": 2, "role": "source", "expr": "uid = request.args.get('id')" },
            { "line": 4, "role": "sink",   "expr": "return cursor.execute(q).fetchone()" }
          ]
        }
      }
    ],
    "abstained": false
  }
]
```

---

### Case 2: Safe Parameterized Query Twin (`0 Vulnerabilities`)

#### 📝 Code Under Analysis (`sample_unit_safe.json`)
```python
def get_user():
    uid = request.args.get('id')
    # Safe! Query uses %s parameterization instead of string concatenation
    return cursor.execute("SELECT * FROM users WHERE id = %s", (uid,)).fetchone()
```

#### 💻 Command
```bash
static-agent run tests/fixtures/sample_unit_safe.json
```

#### 🎯 Output
```json
[]
```
> **Verdict:** **SAFE (0 Active Findings)**  
> The taint engine detected the parameterized query sanitizer and correctly cleared the taint flow.

---

### Case 3: Human-Readable Taint Chain (`explain`)

#### 💻 Command
```bash
static-agent explain tests/fixtures/sample_unit.json
```

#### 🎯 Formatted Terminal Output
```text
--------------------------------------------------------------------------------
Finding #1: [CWE-89] Key: d74383367c4b07a1 | Score: 0.70 | Confidence: 0.90
--------------------------------------------------------------------------------
Explanation: Taint path detected from source 'flask.request.args' at line 2 
             reaching sink 'sql.execute' at line 4 (CWE-89).

Execution Chain:
  📍 Line 2 [ SOURCE ]: uid = request.args.get('id')
  📍 Line 4 [ SINK   ]: return cursor.execute(q).fetchone()
--------------------------------------------------------------------------------
```

---

### Case 4: OS Command Injection (`CWE-78`)

#### 📝 Code Under Analysis
```python
import os
def run_cmd():
    cmd = request.args['cmd']   # Line 3: Untrusted Source
    os.system(cmd)              # Line 4: System Command Sink
```

#### 🎯 Detected Evidence Output
```json
{
  "cwe": "CWE-78",
  "raw_score": 0.8,
  "explanation": "Taint path detected from source 'flask.request.args' at line 3 reaching sink 'os.system' at line 4 (CWE-78)."
}
```

---

### Case 5: JavaScript Code Injection / Eval (`CWE-94`)

#### 📝 Code Under Analysis
```javascript
function handler(req, res) {
    let code = req.query.code;  // Line 2: Untrusted Source
    eval(code);                 // Line 3: Dangerous Eval Sink
}
```

#### 🎯 Detected Evidence Output
```json
{
  "cwe": "CWE-94",
  "raw_score": 0.8,
  "explanation": "Taint path detected from source 'express.req' at line 2 reaching sink 'eval' at line 3 (CWE-94)."
}
```

---

### Case 6: Unsupported Language Graceful Abstention

#### 📝 Code Under Analysis
```cobol
DISPLAY 'HELLO WORLD'
```

#### 🎯 Detected Evidence Output
```json
[
  {
    "agent_id": "structural.taint",
    "unit_id": "test-fail-01",
    "finding_key": "abstain:test-fail-01:unsupported_language",
    "cwe": null,
    "raw_score": 0.0,
    "abstained": true,
    "abstain_reason": "unsupported_language",
    "explanation": "Abstained due to: unsupported_language"
  }
]
```
