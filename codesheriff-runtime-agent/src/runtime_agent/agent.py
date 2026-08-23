"""Main RuntimeAgent Security Analysis Implementation."""

import logging
from typing import List, Optional
from runtime_agent.config import RuntimeConfig
from runtime_agent.contracts import ChangeUnit, Evidence, finding_key
from runtime_agent.rules.detectors import analyze_trace
from runtime_agent.sfi.sandbox import SFISandbox
from runtime_agent.sfi.tracer import ExecutionTrace

logger = logging.getLogger(__name__)


class RuntimeAgent:
    """Runtime SFI Security Analysis Agent."""

    def __init__(self, config: Optional[RuntimeConfig] = None):
        self.config = config or RuntimeConfig()
        self.sandbox = SFISandbox(self.config)

    def analyze(self, unit: ChangeUnit) -> List[Evidence]:
        """Runs ChangeUnit inside SFI sandbox and evaluates runtime behavior."""
        lang = unit.language.lower()
        if lang not in ("python", "py", "javascript", "js", "typescript", "ts"):
            return [
                Evidence.abstention(
                    agent_id="runtime.sfi",
                    agent_version="0.1.0",
                    unit_id=unit.unit_id,
                    reason="unsupported_language",
                    explanation=f"Language {unit.language} is not supported by runtime.sfi",
                )
            ]

        try:
            # Execute post_src code payload in SFI Sandbox
            sandbox_result = self.sandbox.execute_code(unit.post_src, unit.language)
            trace = ExecutionTrace(sandbox_result)

            # Detect vulnerabilities from execution trace
            findings = analyze_trace(unit.unit_id, unit.file, trace, self.config)

            if not findings:
                # Clean execution pass
                clean_key = finding_key(unit.file, unit.symbol, "CLEAN", "sfi_passed")
                return [
                    Evidence(
                        agent_id="runtime.sfi",
                        agent_version="0.1.0",
                        unit_id=unit.unit_id,
                        finding_key=clean_key,
                        cwe=None,
                        raw_score=0.0,
                        confidence=1.0,
                        explanation="Runtime SFI sandbox execution passed without crashes, leaks, or abnormal syscalls.",
                    )
                ]
            return findings

        except Exception as e:
            logger.exception("Runtime SFI execution error")
            return [
                Evidence.abstention(
                    agent_id="runtime.sfi",
                    agent_version="0.1.0",
                    unit_id=unit.unit_id,
                    reason="runtime_error",
                    explanation=f"SFI sandbox execution error: {str(e)}",
                )
            ]
