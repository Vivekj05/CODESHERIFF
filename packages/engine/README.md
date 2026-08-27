# CodeSheriff Fusion & Integration Engine (`codesheriff-engine`)

Orchestrates the **Static Agent**, **Semantic Agent**, and **Context Agent**, computes final posterior vulnerability probabilities using **Bayesian Likelihood Ratio Fusion**, resolves inter-agent conflicts via **Multi-Agent Debate**, and posts structured review comments to GitHub Pull Requests.

## Features

- **Bayesian Odds Updating**: Combines evidence from heterogeneous analyzers using calibrated likelihood ratio matrices.
- **Multi-Agent Parallel Orchestration**: Runs Static taint analysis (Phase 1) to derive anchor keys, followed by parallel Semantic and Context evaluation (Phase 2).
- **Debate Synthesizer**: Re-evaluates edge cases where agents severely disagree ($\Delta \text{score} \ge 0.50$) to separate genuine vulnerabilities from false alarms.
- **GitHub PR Integration**: Automated webhook endpoint and rich Markdown reporter formatting findings and consensus rationales.
- **Zero-Crash Resilience**: Handles agent failures, schema violations, and rate limits gracefully with typed abstentions.

## Usage

```bash
# Run analysis on a ChangeUnit JSON file
codesheriff-engine run tests/fixtures/sample_unit.json

# Start the webhook server
codesheriff-engine serve --port 8000
```
