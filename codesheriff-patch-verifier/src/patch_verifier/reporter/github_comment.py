"""GitHub PR Comment Reporter for CodeSheriff Verdicts."""

from typing import List, Optional
from patch_verifier.contracts import ChangeUnit, Evidence


def format_pr_comment(
    unit: ChangeUnit,
    posterior_prob: float,
    disagreement_index: float,
    verdict: str,
    evidence_list: List[Evidence],
    patch_diff: Optional[str] = None,
    verified: bool = False,
) -> str:
    """Formats Markdown GitHub Pull Request Comment."""
    badge = "🔴 VULNERABLE" if verdict == "VULNERABLE" else "🟢 SAFE"

    comment = f"""## 🛡️ CodeSheriff Security Audit Verdict: {badge}

**Joint Posterior Vulnerability Probability:** `{posterior_prob * 100:.1f}%`  
**Agent Disagreement Index (Posterior Variance):** `{disagreement_index:.4f}`

---

### 📋 Agent Evidence Summary
"""

    for ev in evidence_list:
        if ev.abstained:
            comment += f"- ⚪ **{ev.agent_id}**: Abstained ({ev.abstain_reason})\n"
        elif ev.raw_score > 0.0:
            comment += f"- 🔴 **{ev.agent_id}**: Reported `{ev.cwe}` (Score: {ev.raw_score:.2f}) — {ev.explanation}\n"
        else:
            comment += f"- 🟢 **{ev.agent_id}**: Clean pass\n"

    if patch_diff and verified:
        comment += f"""
---

### 🛠️ Verified Automated Security Patch (`patch.llm` + `verifier.static`)
> ✅ **Verified:** Fix eliminates structural vulnerability with valid AST syntax.

```diff
{patch_diff}
```
*Posted automatically by CodeSheriff Agent System before human review.*
"""

    return comment
