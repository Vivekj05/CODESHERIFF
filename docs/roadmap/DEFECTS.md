# DEFECTS.md — False positive / false negative log

One line per false positive and false negative, **written as it is found** rather than
reconstructed at the end (`PROJECT_CONTEXT.md` §8).

## Why this file exists

Reconstructed failure analysis is fiction. Four months from now the *cause* of a miss is
unrecoverable from the finding alone — you will remember that the taint engine missed a case, not
that it missed it because the sanitizer matched inside a docstring. This file is where the
report's error-analysis section comes from, and it is only worth anything if entries are written
the day the defect is seen.

Keep entries to one line. If a defect needs a paragraph, it is a *decision* — put it in
`DECISIONS.md` and link to it from here.

## Scope

Detection errors only — cases where an agent or the fused posterior reached the wrong verdict on
real code.

Not for: crashes, contract violations, or spec non-conformance. Those go to `AUDIT.md` (if found by
audit) or the issue tracker (if found in normal work). The distinction matters because this file
feeds calibration analysis, and a crash is not a miscalibration.

## Format

| Column | Meaning |
|---|---|
| **ID** | `FP-nnn` or `FN-nnn`, sequential, never reused |
| **Date** | ISO date found |
| **Case** | Corpus case ID, or `repo#PR` for one seen in the wild |
| **CWE** | The CWE involved |
| **Agent** | Which agent got it wrong — or `fusion` if the agents were individually right and the posterior was not |
| **Posterior** | The fused probability, so calibration error is visible at a glance |
| **Cause** | One line. The *mechanism*, not the symptom. |
| **Fixed** | Commit SHA, or `open` |

**"Cause" means the mechanism.** "Missed SQL injection" is a symptom. "Sanitizer matched inside a
docstring, killed taint before the sink" is a cause. Only the second is useful later.

---

## False positives

| ID | Date | Case | CWE | Agent | Posterior | Cause | Fixed |
|---|---|---|---|---|---|---|---|
| FP-001 | 2026-08-29 | `cwe-079-search-summary-safe` | CWE-79 | `semantic.hosted` | n/a — agent-level, fusion ratios unfitted until Ch 14 | `format_html` escapes its arguments, but the guarantee lives in the library and not in the unit; the model hedged on the off-screen contract ("while format_html in frameworks like Django is intended to be safe...") and reported anyway. Doubt about an unseen callee resolves toward reporting | open |
| FP-002 | 2026-09-03 | `cwe-862-xpr-audit-export-safe` and `-vuln` | CWE-89 (the pair is CWE-862) | `semantic.hosted` | 0.0015 at the fitted ratios; threshold 0.23, so no alert | Fires on **both** twins, the signature of a rule keyed on the shape of the code rather than on the flaw: the export builds a query string, and the model called it injection on the safe twin too. Both land in `detection_low`, whose fitted ratio for this witness is 0.74 - the fit discounts this witness's weak alerts, which is what a low tier below 1.0 is for | open |
| FP-003 | 2026-09-03 | `cwe-639-document-delete-vuln` | CWE-862 (the pair is CWE-639) | `semantic.hosted` | 0.017 at the fitted ratios; no alert | The case *is* an authorization bug and the model reported it under the neighbouring authz CWE. Scored as a false claim because the corpus states what each pair is about and a finding key is a CWE. Whether CWE-862/639 confusion should score as a miss or as a hit under a coarser label is a scoring question to settle **before** Chapter 18 - answering it after seeing the test split would be fitting on it | open |

## False negatives

| ID | Date | Case | CWE | Agent | Posterior | Cause | Fixed |
|---|---|---|---|---|---|---|---|
| FN-001 | 2026-08-29 | `cwe-798-warehouse-connect-vuln` | CWE-798 | `semantic.hosted` | n/a — agent-level, fusion ratios unfitted until Ch 14 | The prompt reports only when "untrusted input enters, it reaches a dangerous sink, and no invariant protects it". A hardcoded DSN has no untrusted input, so the three-stage gate structurally excludes CWE-798 — all three samples returned no findings on a literal password. The framework, not the model, is what missed it | open |
| FN-002 | 2026-09-01 | `cwe-022-template-delete-vuln` | CWE-22 | `runtime.sfi` | n/a — agent-level, fusion ratios unfitted until Ch 14 | The taint proxy subclasses `str` so tokens ride through string operations, and `str` therefore answered for every attribute the proxy did not define. `os.path.join(dir, name)` resolved to `str.join` with two arguments, raised `TypeError`, and the unit reported `unit_raised` instead of the composed path it had built — losing the composition rule (D-061) on the one function everybody uses to build a path. Fixed by splitting `__getattribute__`: a *tainted* proxy stands in for a string and keeps `str`'s methods, a *clean* one stands in for a module and does not (D-073) | fixed 2026-09-01, same session |

---

## Periodic review

Before each calibration run (`PLAN.md` Chapter 14), scan this file for clusters. A repeated cause is a
rule or prompt change; a scattered set of one-offs is usually threshold work. Record which of the
two you concluded, and why, in `DECISIONS.md`.

Note for the report: false *discovery* rate is the headline number this project exists to attack.
Count FP entries against total alerts fired, not against corpus size.
