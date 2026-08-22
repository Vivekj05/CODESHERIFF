"""SQLite-backed local LLM response cache."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path
from typing import Optional


class LLMCache:
    """Local SQLite response cache keyed by hash of prompt + model settings."""

    def __init__(self, db_path: str = ".cache/llm_cache.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    response TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()

    @staticmethod
    def compute_key(
        system_prompt: str,
        user_prompt: str,
        model: str,
        agent_version: str,
        temperature: float,
        seed: Optional[int] = None,
    ) -> str:
        """Compute stable SHA-256 cache key."""
        raw = f"{system_prompt}|{user_prompt}|{model}|{agent_version}|{temperature}|{seed or 0}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[str]:
        """Retrieve cached response if exists."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT response FROM cache WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row[0] if row else None

    def set(self, key: str, response: str) -> None:
        """Store response in cache."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, response) VALUES (?, ?)",
                (key, response),
            )
            conn.commit()
