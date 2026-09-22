"""Main StaticAgent interface class."""

from codesheriff_contracts import ChangeUnit, Evidence
from static_agent.config import StaticConfig
from static_agent.semgrep.runner import run_semgrep
from static_agent.taint.engine import analyze_taint


class StaticAgent:
    """Static analysis agent for CodeSheriff."""

    id: str = "structural.taint"
    version: str = "0.1.0"

    def __init__(self, config: StaticConfig | None = None) -> None:
        self.config = config or StaticConfig()

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        """Analyse a ChangeUnit for vulnerabilities.

        Runs blind: no `anchors` parameter (D-008). Anchoring on another agent's
        findings correlates the agents and breaks the conditional independence the
        fusion math assumes, which is the one thing that makes a fused posterior
        mean anything.

        Never raises. Every failure path returns an abstention with a distinct reason.
        """
        try:
            taint_evidence = analyze_taint(unit, self.config)
            semgrep_evidence = run_semgrep(unit, self.config)

            # Return everything both backends said, detections and silences alike.
            # Collapsing `structural.taint` and `structural.semgrep` into a single
            # fused contribution is the engine's job (D-011, PLAN.md Chapter 9);
            # discarding one backend's statement here would hide it from that step.
            return taint_evidence + semgrep_evidence

        except Exception as e:
            return [
                Evidence.abstention(
                    agent_id=self.id,
                    agent_version=self.version,
                    unit_id=unit.unit_id,
                    reason="internal_error",
                    explanation=f"StaticAgent analysis failed unexpectedly: {e}",
                )
            ]
