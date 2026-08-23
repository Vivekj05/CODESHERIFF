# Technical Implementation Spec: CodeSheriff Patch Generator & Verifier Agent

**Package:** `patch_verifier` · **Repo:** `codesheriff-patch-verifier`  
**Agent IDs:** `patch.llm` (Patch Generator) & `verifier.static` (Simplified Verifier)  
**Language:** Python 3.12 (`uv`) / LLM (GPT-4o) + Static AST Verifier  
**Purpose:** Once the **Bayesian Judge Agent** confirms a vulnerability verdict, the **Patch Agent** generates an automated, secure code fix (`git diff`) using an LLM with few-shot historical CVE exemplars. The **Simplified Verifier Agent** then re-evaluates the patch to guarantee that the vulnerability is resolved and no syntax or regression errors were introduced.

---

## 1. Executive Summary & Core Philosophy

Detecting vulnerabilities is only half the battle. Developers need actionable, verified code fixes directly inside their Pull Request review workflow.

The **Patch & Verifier System**:
1. **Trigger Condition:** Activates automatically when the Bayesian Judge computes a joint posterior probability $P(\text{vulnerable} \mid \mathbf{E}) \ge \text{Threshold}$ (default `0.70`).
2. **Patch Generation (`patch.llm`):** Formulates a specialized security prompt including the vulnerable `ChangeUnit`, multi-agent evidence (Static, Semantic, Context, Runtime), and few-shot CVE patch exemplars to synthesize a clean, minimal code patch.
3. **Automated Verification (`verifier.static`):** Applies the patch in-memory to `ChangeUnit.post_src` and runs static taint analysis + AST parsing to prove that `raw_score == 0.0` and code syntax is valid.
4. **GitHub PR Reporting:** Formats and posts the full evidence breakdown, posterior confidence score, disagreement index, and verified `git diff` patch directly onto the GitHub PR review thread.

---

## 2. System Architecture & Folder Structure

```
codesheriff-patch-verifier/
├── README.md
├── pyproject.toml
├── .python-version                 # 3.12
├── .env.example
├── src/patch_verifier/
│   ├── __init__.py
│   ├── contracts.py                # VENDORED — contracts.py (SHA-256 integrity checked)
│   ├── config.py                   # Pydantic settings (LLM provider, model name, max tokens)
│   ├── cli.py                      # generate | verify | report | version
│   ├── patch/
│   │   ├── __init__.py
│   │   ├── generator.py            # LLM Patch Generator using GPT-4o
│   │   ├── prompt.py               # Prompt builder with few-shot CVE exemplars
│   │   └── exemplars/
│   │       ├── cwe_89_sql_injection.json
│   │       ├── cwe_79_xss.json
│   │       └── cwe_22_path_traversal.json
│   ├── verifier/
│   │   ├── __init__.py
│   │   ├── engine.py               # Applies diff & re-runs static taint analysis
│   │   └── syntax_check.py         # AST parser confirming zero syntax errors
│   └── reporter/
│       ├── __init__.py
│       └── github_comment.py       # Formats markdown PR comment with Diff + Bayesian Verdict
└── tests/
    ├── conftest.py
    ├── test_patch_generator.py     # Tests LLM patch synthesis on vulnerable sample
    ├── test_verifier_pass.py       # Verifies successful fix verification (raw_score -> 0.0)
    ├── test_verifier_fail.py       # Tests rejection of bad/incomplete patches
    └── test_github_formatter.py    # Tests GitHub PR comment markdown rendering
```

---

## 3. Technology Stack ($0 Open-Source / Standard LLM API Stack)

| Component | Selected Tool | Purpose / Benefit |
| :--- | :--- | :--- |
| **Patch Engine** | **GPT-4o / Claude 3.5 Sonnet / Qwen-2.5-Coder** | State-of-the-art code synthesis for security remediation |
| **Prompt Framework** | `jinja2` | Formats structured system prompts with few-shot CVE before/after pairs |
| **Verification Engine** | `codesheriff-static-agent` engine | Re-evaluates post-patch code for zero remaining taint paths |
| **Syntax Validator** | Python `ast` / `tree-sitter` | Confirms code compiles/parses without syntax errors |
| **Diff Application** | `patch-match-diff` / standard diff | Applies unified `git diff` patches in-memory |

---

## 4. Key Implementation Modules

### A. Few-Shot Patch Generator (`src/patch_verifier/patch/generator.py`)

```python
import jinja2
from typing import Dict, Any, Optional
from patch_verifier.contracts import ChangeUnit, Evidence
from patch_verifier.config import PatchConfig

SYSTEM_PROMPT = """You are CodeSheriff Patch Agent (patch.llm), an expert security engineer.
Your task is to fix the reported security vulnerability in the code diff below.
RULES:
1. Provide a minimal, secure code fix.
2. Maintain existing business logic and code formatting.
3. Return ONLY a valid unified git diff snippet wrapped in standard ```diff blocks.
"""

class PatchGenerator:
    """Generates LLM security patches for confirmed vulnerabilities."""

    def __init__(self, llm_client: Any, config: PatchConfig):
        self.llm = llm_client
        self.config = config

    def generate_patch(self, unit: ChangeUnit, evidence: Evidence) -> str:
        """Generates a unified git diff patch resolving the evidence finding."""
        user_prompt = f"""
VULNERABILITY TO FIX:
- CWE: {evidence.cwe}
- Finding Key: {evidence.finding_key}
- Explanation: {evidence.explanation}

VULNERABLE CODE (post_src):
```python
{unit.post_src}
```

Generate a secure code fix as a unified diff.
"""
        response = self.llm.generate(
            system=SYSTEM_PROMPT,
            prompt=user_prompt,
            temperature=0.1,  # Low temperature for deterministic fixes
            max_tokens=1000,
        )
        return response.text
```

---

### B. Simplified Verifier (`src/patch_verifier/verifier/engine.py`)

```python
import ast
from typing import Tuple
from patch_verifier.contracts import ChangeUnit, Evidence

class PatchVerifier:
    """Verifies that a generated patch eliminates structural vulnerabilities."""

    def __init__(self, static_analyzer_fn: Any):
        self.analyze_taint = static_analyzer_fn

    def verify_patch(self, original_unit: ChangeUnit, patch_diff: str, patched_code: str) -> Tuple[bool, str]:
        """
        Applies patch and re-evaluates static taint engine.
        Returns (is_verified, explanation).
        """
        # 1. Syntax Check
        try:
            ast.parse(patched_code)
        except SyntaxError as e:
            return False, f"Patch failed verification: Syntax error in generated fix - {str(e)}"

        # 2. Re-run Static Taint Engine on Patched Code
        patched_unit = original_unit.model_copy(update={"post_src": patched_code})
        new_evidence_list = self.analyze_taint(patched_unit)

        # 3. Check if the original vulnerability is gone (raw_score == 0.0)
        vulnerable_findings = [
            ev for ev in new_evidence_list 
            if not ev.abstained and ev.raw_score > 0.0
        ]

        if not vulnerable_findings:
            return True, "Verification successful: Vulnerability eliminated with 0 remaining taint paths."
        
        return False, f"Verification failed: Patched code still contains {len(vulnerable_findings)} vulnerability findings."
```

---

### C. GitHub PR Comment Reporter (`src/patch_verifier/reporter/github_comment.py`)

```python
from typing import Dict, Any

def format_github_pr_comment(
    unit: Any,
    posterior_prob: float,
    disagreement_index: float,
    verdict: str,
    evidence_summary: str,
    verified_patch_diff: Optional[str] = None
) -> str:
    """Formats a beautiful Markdown GitHub PR comment."""
    
    badge = "🔴 VULNERABLE" if verdict == "VULNERABLE" else "🟢 SAFE"
    
    comment = f"""## 🛡️ CodeSheriff Security Audit Verdict: {badge}

**Joint Posterior Vulnerability Confidence:** `{posterior_prob * 100:.1f}%`  
**Agent Disagreement Index (Posterior Variance):** `{disagreement_index:.4f}`

---

### 📋 Agent Evidence Summary
{evidence_summary}
"""

    if verified_patch_diff:
        comment += f"""
---

### 🛠️ Verified Automated Security Patch (`patch.llm` + `verifier.static`)
> ✅ **Verified:** Fix eliminates taint path with zero remaining vulnerabilities.

```diff
{verified_patch_diff}
```
*Posted automatically by CodeSheriff Agentic Pipeline before human review.*
"""
    return comment
```

---

## 5. End-to-End Workflow Verification

```
[Bayesian Judge Verdict: VULNERABLE]
               │
               ▼
   [1. LLM Patch Generator] ──(Generates git diff)──► [2. AST Syntax Check]
                                                              │ (Pass)
                                                              ▼
   [GitHub PR Comment Posted] ◄──(Confirmed Safe)── [3. Static Taint Re-check]
```
