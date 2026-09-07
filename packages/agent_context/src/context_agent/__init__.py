"""CodeSheriff context witness: cross-PR security control regressions."""

from context_agent.agent import ContextAgent
from context_agent.config import AGENT_ID, AGENT_VERSION, ContextConfig
from context_agent.precedent import (
    NoPrecedentRetriever,
    Precedent,
    PrecedentRetriever,
    RetrievalUnavailableError,
)

__version__ = AGENT_VERSION

__all__ = [
    "AGENT_ID",
    "AGENT_VERSION",
    "ContextAgent",
    "ContextConfig",
    "NoPrecedentRetriever",
    "Precedent",
    "PrecedentRetriever",
    "RetrievalUnavailableError",
    "__version__",
]
