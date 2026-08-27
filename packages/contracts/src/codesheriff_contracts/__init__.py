"""The single shared CodeSheriff contract.

This package is imported by every agent, the engine, and the apps. It is the ONLY
thing an agent is permitted to import (enforced by import-linter; see the root
pyproject.toml).

Do not vendor this file. Four byte-identical copies previously existed, kept in
sync by a SHA-256 test whose expected hash was rewritten to make it pass.
See DECISIONS.md D-002 and AUDIT.md 4.8.

`contracts.py` as it stands is the pre-refactor contract and is NON-CONFORMANT.
It is preserved here as the migration starting point, not as the target. Before
building on it, read AUDIT.md Tier 1 and rewrite per PLAN.md Chapter 2:

  - finding_key must EXCLUDE the sink expression and use `::` (D-004)
  - three evidence kinds: DETECTION / SILENCE / ABSTENTION (D-005)
  - SILENCE carries covered_cwes (D-006)
  - IN_SCOPE_CWES as a closed set of 10
  - ChangeUnit: pre_src nullable, plus decorators and enclosing_class (D-013)
  - pr_context as a separate model, never inside ChangeUnit (D-014)
  - analyze(unit) -> list[Evidence]; no `anchors` parameter (D-008)
"""
