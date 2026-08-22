"""Tests for budget tracker module."""

from semantic_agent.llm.budget import BudgetTracker


def test_budget_tracker_cost_and_spending() -> None:
    bt = BudgetTracker(budget_usd_per_unit=0.01)
    cost = bt.estimate_cost(prompt_tokens=1000, completion_tokens=500, model="gpt-4o-mini")
    assert cost > 0.0
    assert bt.check_budget(cost)

    bt.record_expenditure(0.012)
    assert bt.is_exceeded()
    assert not bt.check_budget(0.001)
