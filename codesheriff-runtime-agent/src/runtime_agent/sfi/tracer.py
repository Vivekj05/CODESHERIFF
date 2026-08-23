"""Execution trace and syscall output parser."""

from typing import List, Set
from runtime_agent.sfi.sandbox import SFISandboxResult


class ExecutionTrace:
    """Parsed events from sandbox execution."""

    def __init__(self, result: SFISandboxResult):
        self.raw_result = result
        self.exit_code = result.exit_code
        self.stdout = result.stdout
        self.stderr = result.stderr
        self.timed_out = result.timed_out

    def contains_pattern(self, pattern: str) -> bool:
        """Returns True if stdout or stderr contains pattern."""
        return pattern.lower() in self.stdout.lower() or pattern.lower() in self.stderr.lower()

    def is_segfault(self) -> bool:
        """Checks for segmentation faults or memory crashes."""
        if self.exit_code in (-11, 139):
            return True
        crash_keywords = ["segmentation fault", "segfault", "access violation", "memory corruption"]
        combined = f"{self.stdout}\n{self.stderr}".lower()
        return any(kw in combined for kw in crash_keywords)
