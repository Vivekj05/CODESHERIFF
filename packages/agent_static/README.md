# CodeSheriff Static Agent (`codesheriff-static-agent`)

Standalone static analysis security review agent for CodeSheriff.

## Overview
Analyzes code changes (`ChangeUnit`) in Python and JS/TS to detect vulnerabilities using flow-based AST taint analysis and pattern-based Semgrep scanning.

## What It Detects
- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-79: Cross-Site Scripting (XSS)
- CWE-22: Path Traversal
- CWE-502: Insecure Deserialization
- CWE-94: Code Injection / Eval

## Out of Scope (Limitations)
- Inter-procedural analysis across file boundaries
- Alias / pointer analysis
- Framework-internal dependency resolution (Django ORM internals, Express middleware chains)
- Path sensitivity & complex constraint solving
- Type inference

## CLI Usage
```bash
static-agent run tests/fixtures/sample_unit.json
static-agent explain tests/fixtures/sample_unit.json
static-agent bench --corpus corpus/
static-agent version
```
