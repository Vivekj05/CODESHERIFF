"""End-to-end tests for SemanticAgent."""

import json
from pathlib import Path
from semantic_agent.agent import SemanticAgent
from semantic_agent.config import SemanticConfig
from semantic_agent.contracts import ChangeUnit
from semantic_agent.llm.stub import StubLLMClient


def test_semantic_agent_vulnerable_unit(sample_unit: ChangeUnit, tmp_path: Path) -> None:
    finding_json = {
        "findings": [
            {
                "functional_intent": "Fetch user by ID",
                "untrusted_data_sources": ["request.args.get('id')"],
                "violated_safety_invariant": "Concatenates untrusted user ID into SQL string.",
                "cwe": "CWE-89",
                "title": "SQL Injection in get_user",
                "file": "app/api/users.py",
                "start_line": 42,
                "end_line": 46,
                "sink_expression": "cursor.execute(q).fetchone()",
                "severity": "critical",
                "rationale": "Direct string interpolation into raw SQL query allows SQL injection.",
                "evidence_lines": [2, 3],
                "exploitability": "direct",
            }
        ]
    }
    stub_client = StubLLMClient(responses=[json.dumps(finding_json)])
    cfg = SemanticConfig(cache_path=str(tmp_path / "cache.db"), n_samples=3)
    agent = SemanticAgent(config=cfg, llm_client=stub_client)

    ev_list = agent.analyze(sample_unit)
    assert len(ev_list) == 1
    ev = ev_list[0]
    assert not ev.abstained
    assert ev.cwe == "CWE-89"
    assert ev.raw_score == 1.0
    assert ev.unit_id == sample_unit.unit_id


def test_semantic_agent_safe_unit(sample_unit_safe: ChangeUnit, tmp_path: Path) -> None:
    stub_client = StubLLMClient(responses=[json.dumps({"findings": []})])
    cfg = SemanticConfig(cache_path=str(tmp_path / "cache.db"), n_samples=3)
    agent = SemanticAgent(config=cfg, llm_client=stub_client)

    ev_list = agent.analyze(sample_unit_safe)
    assert len(ev_list) == 0


def test_semantic_agent_budget_exceeded(sample_unit: ChangeUnit, tmp_path: Path) -> None:
    cfg = SemanticConfig(budget_usd_per_unit=0.0001, cache_path=str(tmp_path / "cache.db"))
    agent = SemanticAgent(config=cfg, llm_client=StubLLMClient())
    agent.budget_tracker.record_expenditure(1.0)

    ev_list = agent.analyze(sample_unit)
    assert len(ev_list) == 1
    assert ev_list[0].abstained
    assert ev_list[0].abstain_reason == "budget_exceeded"


def test_semantic_agent_schema_violation(sample_unit: ChangeUnit, tmp_path: Path) -> None:
    stub_client = StubLLMClient(responses=["INVALID_JSON_CORRUPTED_RESPONSE"])
    cfg = SemanticConfig(cache_path=str(tmp_path / "cache.db"), n_samples=1)
    agent = SemanticAgent(config=cfg, llm_client=stub_client)

    ev_list = agent.analyze(sample_unit)
    assert len(ev_list) == 1
    assert ev_list[0].abstained
    assert ev_list[0].abstain_reason == "schema_violation"


def test_semantic_agent_never_raises(sample_unit: ChangeUnit, tmp_path: Path) -> None:
    class FailingLLMClient:
        def generate(self, *args, **kwargs):
            raise RuntimeError("Catastrophic connection failure")

    cfg = SemanticConfig(cache_path=str(tmp_path / "cache.db"), n_samples=1)
    agent = SemanticAgent(config=cfg, llm_client=FailingLLMClient())

    ev_list = agent.analyze(sample_unit)
    assert len(ev_list) == 1
    assert ev_list[0].abstained
    assert "schema_violation" in ev_list[0].abstain_reason or "runtime_error" in ev_list[0].abstain_reason
