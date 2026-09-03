"""End-to-end tests for SemanticAgent."""

import json
from pathlib import Path

from codesheriff_contracts import ChangeUnit, EvidenceKind
from semantic_agent.agent import SemanticAgent
from semantic_agent.config import SemanticConfig
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
    assert ev.kind is EvidenceKind.DETECTION
    assert ev.cwe == "CWE-89"
    assert ev.finding_key == sample_unit.key_for("CWE-89")
    assert ev.raw_score == 1.0
    assert ev.unit_id == sample_unit.unit_id


def test_semantic_agent_safe_unit(sample_unit_safe: ChangeUnit, tmp_path: Path) -> None:
    stub_client = StubLLMClient(responses=[json.dumps({"findings": []})])
    cfg = SemanticConfig(cache_path=str(tmp_path / "cache.db"), n_samples=3)
    agent = SemanticAgent(config=cfg, llm_client=stub_client)

    ev_list = agent.analyze(sample_unit_safe)
    # SILENCE, not []. The model looked and found nothing, which is evidence that
    # should lower a posterior — an empty list throws that away (D-005).
    assert len(ev_list) == 1
    assert ev_list[0].kind is EvidenceKind.SILENCE
    assert ev_list[0].covered_cwes


def test_semantic_agent_budget_exceeded(sample_unit: ChangeUnit, tmp_path: Path) -> None:
    """A budget too small for even the first sample abstains, and never falls silent.

    The budget is **per unit** and resets at the top of every `analyze`, so exhaustion can
    only happen inside a unit — charging the tracker beforehand, as this test used to, was
    exercising a per-process budget that no longer exists. A ceiling below the cost of one
    sample reaches the same state the honest way.

    What it must not do is return SILENCE. An agent that stopped before its first call has
    not "reviewed the unit and found nothing"; that report would push a posterior down across
    all ten in-scope CWEs on the strength of having read none of them (D-088).
    """
    cfg = SemanticConfig(budget_usd_per_unit=1e-12, cache_path=str(tmp_path / "cache.db"))
    agent = SemanticAgent(config=cfg, llm_client=StubLLMClient())

    ev_list = agent.analyze(sample_unit)

    assert len(ev_list) == 1
    assert ev_list[0].kind is EvidenceKind.ABSTENTION
    assert ev_list[0].reason == "budget_exceeded"


def test_the_budget_does_not_leak_between_units(sample_unit: ChangeUnit, tmp_path: Path) -> None:
    """One agent analyses every unit of an audit, so the ceiling has to reset per unit.

    Without the reset the first few units of a pull request are analysed and every unit after
    them abstains `budget_exceeded` — a per-process budget wearing a per-unit name. The
    Chapter 14 harness found it by running 46 corpus cases through one agent.
    """
    cfg = SemanticConfig(budget_usd_per_unit=0.01, cache_path=str(tmp_path / "cache.db"))
    agent = SemanticAgent(config=cfg, llm_client=StubLLMClient())

    kinds = [agent.analyze(sample_unit)[0].kind for _ in range(5)]

    assert all(kind is not EvidenceKind.ABSTENTION for kind in kinds), (
        f"the agent stopped analysing after the first unit(s): {kinds}"
    )


def test_semantic_agent_schema_violation(sample_unit: ChangeUnit, tmp_path: Path) -> None:
    stub_client = StubLLMClient(responses=["INVALID_JSON_CORRUPTED_RESPONSE"])
    cfg = SemanticConfig(cache_path=str(tmp_path / "cache.db"), n_samples=1)
    agent = SemanticAgent(config=cfg, llm_client=stub_client)

    ev_list = agent.analyze(sample_unit)
    assert len(ev_list) == 1
    assert ev_list[0].kind is EvidenceKind.ABSTENTION
    assert ev_list[0].reason == "schema_violation"


def test_semantic_agent_never_raises(sample_unit: ChangeUnit, tmp_path: Path) -> None:
    class FailingLLMClient:
        def generate(self, *args, **kwargs):
            raise RuntimeError("Catastrophic connection failure")

    cfg = SemanticConfig(cache_path=str(tmp_path / "cache.db"), n_samples=1)
    agent = SemanticAgent(config=cfg, llm_client=FailingLLMClient())

    ev_list = agent.analyze(sample_unit)
    assert len(ev_list) == 1
    assert ev_list[0].kind is EvidenceKind.ABSTENTION
    # `provider_unavailable`, not `schema_violation`: the client never returned output, so there
    # was nothing for the model to get wrong. Reporting a transport failure as a schema failure
    # blames the model for something it was never asked, and that misattribution would be read as
    # evidence about the model when the likelihood ratios are fitted (D-065).
    assert ev_list[0].reason == "provider_unavailable"
