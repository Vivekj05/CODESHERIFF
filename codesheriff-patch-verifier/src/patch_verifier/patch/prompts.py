"""Prompt Templates and Few-Shot CVE Exemplars for Security Patching."""

from typing import Any
from jinja2 import Template


SYSTEM_PATCH_PROMPT = """You are CodeSheriff Patch Agent (patch.llm), a world-class security engineer.
Your sole job is to fix reported security vulnerabilities by synthesizing clean, minimal unified git diff patches.

RULES:
1. Provide a secure fix for the reported CWE vulnerability.
2. Preserve original business logic, variable names, and code style.
3. Return ONLY a valid unified diff snippet inside ```diff code blocks.
"""

USER_PATCH_TEMPLATE = Template("""
VULNERABILITY REPORT:
- Target File: {{ unit.file }}
- Symbol: {{ unit.symbol or 'N/A' }}
- CWE: {{ evidence.cwe or 'CWE-89' }}
- Finding Key: {{ evidence.finding_key }}
- Explanation: {{ evidence.explanation }}

VULNERABLE SOURCE CODE (post_src):
```{{ unit.language }}
{{ unit.post_src }}
```

FEW-SHOT SECURITY PATCH EXEMPLAR (SQL Injection Example):
--- Before
+++ After
@@ -1,3 +1,3 @@
 def get_user(uid):
-    query = f"SELECT * FROM users WHERE id = {uid}"
-    return db.execute(query)
+    query = "SELECT * FROM users WHERE id = %s"
+    return db.execute(query, (uid,))

Now synthesize a verified git diff patch for the vulnerable code above.
""")


def build_patch_prompt(unit: Any, evidence: Any) -> str:
    """Builds the full user prompt for patch synthesis."""
    return USER_PATCH_TEMPLATE.render(unit=unit, evidence=evidence)
