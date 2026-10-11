# CodeSheriff Examples & Evaluation

This directory contains benchmark evaluation scripts, paper reproducibility tools, and sample pull request diffs for testing CodeSheriff's multi-agent Bayesian audit engine.

---

## Contents

- **`baseline_eval.py`**: Comparative evaluation of CodeSheriff's Bayesian fusion against baseline models (heuristic, LLM-only, and single-agent detectors).
- **`paper_eval.py`**: Generates calibration curves, Expected Calibration Error (ECE), Brier scores, and LaTeX tables for publication.
- **`sample_prs/`**: Sample pull request diffs containing known vulnerabilities (e.g. SQL injection, path traversal, IDOR) and safe twins for testing.

---

## Running Evaluations

From the repository root:

```bash
# Run baseline evaluation
python examples/baseline_eval.py

# Generate paper calibration metrics and tables
python examples/paper_eval.py
```

Or use the Windows launcher:
```cmd
codesheriff.bat eval
```
