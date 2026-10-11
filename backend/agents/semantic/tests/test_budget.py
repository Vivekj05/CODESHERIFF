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


def test_the_budget_is_per_unit_and_resets() -> None:
    """The ceiling is named per unit, and one agent analyses every unit in an audit.

    Without the reset, `budget_usd_per_unit` is a per-*process* budget: the first few units of
    a pull request are analysed and every one after them abstains `budget_exceeded`. The
    Chapter 14 harness found it by running 46 corpus cases through one agent and watching the
    last thirty report "Budget reached after 0 of 3 samples".
    """
    bt = BudgetTracker(budget_usd_per_unit=0.01)
    bt.record_expenditure(0.012)
    assert bt.is_exceeded()

    bt.reset()

    assert not bt.is_exceeded()
    assert bt.check_budget(0.001)
    assert bt.spent_usd == 0.0
