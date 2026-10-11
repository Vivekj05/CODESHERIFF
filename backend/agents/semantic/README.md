# CodeSheriff Semantic Agent (`codesheriff-semantic-agent`)

Standalone, LLM-powered security review agent for CodeSheriff.

## Overview
The Semantic Agent evaluates Pull Request changes (`ChangeUnit`) using a 3-stage universal security analysis framework:
1. **Functional Intent**: What is the code trying to accomplish?
2. **Trust Boundaries**: Where does untrusted data enter and flow?
3. **Safety Invariants**: What security guarantee is missing or broken?

It enforces Pydantic structured output, filters hallucinated findings through a **Hallucination Gate**, calculates self-consistency scores ($n=3$ sampling), tracks USD API budgets, and emits canonical `Evidence` JSON contracts.

## Setup & Running
```bash
pip install -e .
semantic-agent run tests/fixtures/sample_unit.json
```
