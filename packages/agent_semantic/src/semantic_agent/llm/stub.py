"""Stub LLM client for offline unit testing without live API calls."""

from __future__ import annotations

import json
from typing import List, Type
from pydantic import BaseModel

DEFAULT_SQLI_RESPONSE = {
    "findings": [
        {
            "functional_intent": "Fetch user details from database",
            "untrusted_data_sources": ["request.args.get('id')"],
            "violated_safety_invariant": "Interpolates untrusted user ID into raw SQL query without escaping.",
            "cwe": "CWE-89",
            "title": "SQL Injection in get_user",
            "file": "app/api/users.py",
            "start_line": 42,
            "end_line": 46,
            "sink_expression": "cursor.execute(q).fetchone()",
            "severity": "critical",
            "rationale": "Direct string formatting into cursor.execute manifests SQL injection.",
            "evidence_lines": [2, 3],
            "exploitability": "direct",
        }
    ]
}


class StubLLMClient:
    """Scripted LLM client returning predefined responses for unit testing."""

    def __init__(self, responses: List[str] | None = None) -> None:
        self.responses = responses or []
        self.call_count = 0

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: Type[BaseModel],
        temperature: float = 0.3,
        seed: int | None = None,
    ) -> str:
        """Return next scripted response or default mock finding for demo units."""
        self.call_count += 1
        if self.responses:
            idx = (self.call_count - 1) % len(self.responses)
            return self.responses[idx]

        # Smart default for sample units
        if "cursor.execute(q)" in user_prompt or "SELECT * FROM users WHERE id =" in user_prompt:
            return json.dumps(DEFAULT_SQLI_RESPONSE)

        return json.dumps({"findings": []})
