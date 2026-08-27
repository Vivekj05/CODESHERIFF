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
| _none recorded yet_ | | | | | | | |

## False negatives

| ID | Date | Case | CWE | Agent | Posterior | Cause | Fixed |
|---|---|---|---|---|---|---|---|
| _none recorded yet_ | | | | | | | |

---

## Example entries

Illustrative only — delete once real entries exist. Both are drawn from defects `AUDIT.md`
predicts the current code would produce, so they show the intended level of detail.

| ID | Date | Case | CWE | Agent | Posterior | Cause | Fixed |
|---|---|---|---|---|---|---|---|
| FP-000 | 2026-08-27 | `demo-001` | CWE-78 | `structural.taint` | 0.81 | Sink regex matched `os.system` inside a `# TODO:` comment; rules run on raw lines, not call-expression nodes | open |
| FN-000 | 2026-08-27 | `authz-004` | CWE-862 | `fusion` | 0.18 | Context agent emitted under its own `finding_key`, so its evidence never joined the group and could not corroborate | open |

---

## Periodic review

Before each calibration run (`PLAN.md` Chapter 14), scan this file for clusters. A repeated cause is a
rule or prompt change; a scattered set of one-offs is usually threshold work. Record which of the
two you concluded, and why, in `DECISIONS.md`.

Note for the report: false *discovery* rate is the headline number this project exists to attack.
Count FP entries against total alerts fired, not against corpus size.
