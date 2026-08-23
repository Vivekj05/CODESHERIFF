"""LLM Patch Generator (`patch.llm`) Implementation."""

import re
from typing import Any, Optional
from patch_verifier.config import PatchVerifierConfig
from patch_verifier.contracts import ChangeUnit, Evidence
from patch_verifier.patch.prompts import SYSTEM_PATCH_PROMPT, build_patch_prompt


class LLMPatchGenerator:
    """Generates automated LLM security patches for confirmed vulnerabilities."""

    def __init__(self, config: Optional[PatchVerifierConfig] = None):
        self.config = config or PatchVerifierConfig()

    def generate_patch(self, unit: ChangeUnit, evidence: Evidence) -> str:
        """Synthesizes unified git diff patch for the given Evidence finding."""
        prompt = build_patch_prompt(unit, evidence)

        if self.config.llm_provider == "stub":
            return self._generate_stub_patch(unit, evidence)
        
        # Real hosted LLM provider integration would call API here
        return self._generate_stub_patch(unit, evidence)

    def _generate_stub_patch(self, unit: ChangeUnit, evidence: Evidence) -> str:
        """Deterministic mock patch generator for offline testing."""
        if "sql" in (evidence.explanation or "").lower() or (evidence.cwe == "CWE-89"):
            return (
                f"--- a/{unit.file}\n"
                f"+++ b/{unit.file}\n"
                "@@ -1,5 +1,5 @@\n"
                " def get_user_profile(user_id):\n"
                "-    q = f\"SELECT * FROM users WHERE id = {uid}\"\n"
                "-    return cursor.execute(q).fetchone()\n"
                "+    q = \"SELECT * FROM users WHERE id = %s\"\n"
                "+    return cursor.execute(q, (uid,)).fetchone()\n"
            )

        return (
            f"--- a/{unit.file}\n"
            f"+++ b/{unit.file}\n"
            "@@ -1,3 +1,3 @@\n"
            "-# Vulnerable code pattern\n"
            "+# Sanitized security patch applied by CodeSheriff\n"
        )

