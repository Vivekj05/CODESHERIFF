# CodeSheriff Patch & Verifier Agent (`patch.llm` / `verifier.static`)

The **Patch & Verifier Agent** automatically synthesizes secure code patches (`git diff`) using an LLM (`patch.llm`) with few-shot historical CVE exemplars whenever the Bayesian Judge confirms a vulnerability verdict. The **Simplified Verifier Agent** (`verifier.static`) re-evaluates the patch in-memory to guarantee syntax correctness and zero remaining vulnerability findings.

## Features

- **LLM Security Patch Generation (`patch.llm`):** Synthesizes minimal unified `git diff` patches addressing reported CWE security findings.
- **Automated Patch Verification (`verifier.static`):** Parses AST syntax and re-runs structural taint analysis to prove `raw_score == 0.0`.
- **GitHub PR Comment Reporter:** Renders Markdown PR comments containing Joint Posterior Vulnerability Confidence, Disagreement Index, agent evidence, and verified `git diff` patches.

## Installation

```bash
cd codesheriff-patch-verifier
pip install -e .
```

## CLI Usage

```bash
# Generate patch for a ChangeUnit payload
patch-verifier generate tests/fixtures/sample_unit.json

# Check agent health
patch-verifier health
```
