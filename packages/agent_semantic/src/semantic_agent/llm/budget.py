"""LLM budget tracking and USD cost enforcement module."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Pricing per 1K tokens in USD (Gemini Free Tier is $0, but tracked for reference)
MODEL_PRICING = {
    "gemini-1.5-flash": {"input": 0.000075 / 1000, "output": 0.00030 / 1000},
    "gemini-2.0-flash": {"input": 0.00010 / 1000, "output": 0.00040 / 1000},
    "gemini-1.5-pro": {"input": 0.00125 / 1000, "output": 0.0050 / 1000},
    "default": {"input": 0.0001 / 1000, "output": 0.0003 / 1000},
}


class BudgetTracker:
    """Pre-call USD budget tracker and cumulative cost monitor."""

    def __init__(self, budget_usd_per_unit: float = 0.05) -> None:
        self.budget_usd_per_unit = budget_usd_per_unit
        self.spent_usd: float = 0.0

    def estimate_cost(
        self, prompt_tokens: int, completion_tokens: int, model: str = "gemini-1.5-flash"
    ) -> float:
        """Calculate estimated cost in USD based on model pricing."""
        rates = MODEL_PRICING.get(model, MODEL_PRICING["default"])
        cost = (prompt_tokens * rates["input"]) + (completion_tokens * rates["output"])
        return cost

    def check_budget(self, estimated_next_cost: float = 0.0) -> bool:
        """Check if projected expenditure exceeds budget ceiling."""
        return (self.spent_usd + estimated_next_cost) <= self.budget_usd_per_unit

    def record_expenditure(self, cost: float) -> None:
        """Record spent USD."""
        self.spent_usd += cost
        logger.debug(f"Budget update: spent ${self.spent_usd:.5f} / ${self.budget_usd_per_unit:.5f}")

    def is_exceeded(self) -> bool:
        """Check if total spent has met or exceeded the budget."""
        return self.spent_usd >= self.budget_usd_per_unit
