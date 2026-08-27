"""Main StaticAgent interface class."""

from typing import List, Optional, Set
from static_agent.config import StaticConfig
from static_agent.contracts import ChangeUnit, Evidence
from static_agent.semgrep.runner import run_semgrep
from static_agent.taint.engine import analyze_taint


class StaticAgent:
    """Static analysis agent for CodeSheriff."""
    id: str = "structural.taint"
    version: str = "0.1.0"

    def __init__(self, config: Optional[StaticConfig] = None) -> None:
        self.config = config or StaticConfig()

    def analyze(
        self, unit: ChangeUnit, anchors: Optional[Set[str]] = None
    ) -> List[Evidence]:
        """Analyze a ChangeUnit for vulnerabilities.
        
        Never raises exceptions. Returns list of Evidence or Evidence.abstention.
        """
        try:
            # 1. Run Taint Engine
            taint_evidence = analyze_taint(unit, self.config)

            # 2. Run Semgrep Subprocess Runner
            semgrep_evidence = run_semgrep(unit, self.config)

            # Combine evidence, filtering out duplicate abstentions if findings exist
            findings = [e for e in taint_evidence + semgrep_evidence if not e.abstained]
            if findings:
                return findings

            abstentions = [e for e in taint_evidence + semgrep_evidence if e.abstained]
            return abstentions

        except Exception as e:
            return [
                Evidence.abstention(
                    agent_id=self.id,
                    agent_version=self.version,
                    unit_id=unit.unit_id,
                    reason="internal_error",
                    explanation=f"StaticAgent analysis failed unexpectedly: {str(e)}",
                )
            ]
