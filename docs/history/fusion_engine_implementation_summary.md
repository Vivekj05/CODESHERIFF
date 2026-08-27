# Technical Implementation Spec: CodeSheriff Fusion & Integration Engine

**Package:** `codesheriff_engine` · **Repo:** `codesheriff-engine` (or `APPS/ENGINE`)  
**Purpose:** Orchestrates the **Static Agent**, **Semantic Agent**, and **Context Agent**, computes final posterior vulnerability probabilities using **Bayesian Likelihood Ratio Fusion**, resolves agent conflicts via **Multi-Agent Debate**, and posts actionable review comments to GitHub Pull Requests.

---

## 1. Executive Summary & System Flow

```
                     [ GitHub PR Webhook Payload ]
                                   │
                                   ▼
                       [ ChangeUnit Extraction ]
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│  STATIC AGENT   │       │ SEMANTIC AGENT  │       │  CONTEXT AGENT  │
│ (AST & Taint)   │       │ (LLM & Intent)  │       │  (RAG History)  │
└────────┬────────┘       └────────┬────────┘       └────────┬────────┘
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   ▼
                   [ BAYESIAN FUSION & DEBATE ENGINE ]
                   • Step 1: Group by `finding_key`
                   • Step 2: Calculate Posterior P(Vulnerable)
                   • Step 3: Debate Protocol (if conflict)
                                   │
                                   ▼
                   [ GitHub Review Comment Post ]
```

---

## 2. System Architecture & Folder Structure

```
codesheriff-engine/
├── pyproject.toml                  # Installs static, semantic, context agents
├── .python-version                 # 3.12
├── .env.example                    # GITHUB_TOKEN, GITHUB_WEBHOOK_SECRET
├── src/codesheriff_engine/
│   ├── __init__.py
│   ├── contracts.py                # Canonical vendored contracts.py
│   ├── config.py                   # Prior probability P(V), Agent likelihood tables
│   ├── orchestrator.py             # Runs 3 agents in parallel, collects Evidence
│   ├── fusion/
│   │   ├── __init__.py
│   │   ├── bayes.py                # Bayesian Odds & Likelihood Ratio calculation
│   │   └── debate.py               # Multi-Agent Debate LLM conflict resolution
│   ├── github/
│   │   ├── __init__.py
│   │   ├── webhook.py              # FastAPI webhook endpoint
│   │   ├── parser.py               # PR payload -> ChangeUnit converter
│   │   └── reporter.py             # Posts formatted Markdown reviews & diffs
│   └── main.py                     # FastAPI service entrypoint
└── tests/
    ├── test_bayes_math.py
    ├── test_debate.py
    ├── test_orchestrator.py
    └── test_github_reporter.py
```

---

## 3. Package Dependencies (`pyproject.toml`)

```toml
[project]
name = "codesheriff-engine"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "codesheriff-static-agent @ file://../codesheriff-static-agent",
    "codesheriff-semantic-agent @ file://../codesheriff-semantic-agent",
    "codesheriff-context-agent @ file://../codesheriff-context-agent",
    "fastapi>=0.110.0",
    "uvicorn>=0.28.0",
    "httpx>=0.27.0",
    "pydantic>=2.7.0",
    "pydantic-settings>=2.2.0"
]
```

---

## 4. Key Implementation Modules

### A. Bayesian Odds & Fusion Engine (`src/codesheriff_engine/fusion/bayes.py`)

```python
import math
from dataclasses import dataclass
from codesheriff_engine.contracts import Evidence

# Calibrated Likelihood Ratios per agent score tier
AGENT_LIKELIHOOD_TABLE = {
    "structural.taint": {
        "high": 8.5,     # score >= 0.8
        "medium": 3.2,   # score >= 0.5
        "low": 0.8       # score < 0.5
    },
    "semantic.hosted": {
        "high": 12.0,    # score >= 0.8 (3/3 agreement)
        "medium": 4.5,   # score >= 0.5 (2/3 agreement)
        "low": 0.5       # score < 0.5 (1/3 agreement)
    },
    "context.rag": {
        "high": 4.2,     # score >= 0.8 (direct security control bypass)
        "medium": 2.1,   # score >= 0.5
        "low": 0.9       # score < 0.5
    }
}

@dataclass
class FusionResult:
    finding_key: str
    posterior_probability: float
    is_alert_worthy: bool
    evidence_list: list[Evidence]
    consensus_rationale: str

def get_likelihood_ratio(agent_id: str, score: float) -> float:
    table = AGENT_LIKELIHOOD_TABLE.get(agent_id, {"high": 3.0, "medium": 1.5, "low": 1.0})
    if score >= 0.8:
        return table["high"]
    elif score >= 0.5:
        return table["medium"]
    return table["low"]

def compute_bayesian_fusion(
    finding_key: str, 
    evidence_list: list[Evidence], 
    prior_p: float = 0.05
) -> FusionResult:
    """Computes posterior vulnerability probability using Bayesian Odds updating."""
    prior_odds = prior_p / (1.0 - prior_p)
    current_odds = prior_odds

    for ev in evidence_list:
        lr = get_likelihood_ratio(ev.agent_id, ev.raw_score)
        current_odds *= lr

    posterior_p = current_odds / (1.0 + current_odds)
    is_alert = posterior_p >= 0.70  # Threshold for posting alert on PR

    return FusionResult(
        finding_key=finding_key,
        posterior_probability=round(posterior_p, 4),
        is_alert_worthy=is_alert,
        evidence_list=evidence_list,
        consensus_rationale=""
    )
```

---

### B. Multi-Agent Debate & Conflict Synthesizer (`src/codesheriff_engine/fusion/debate.py`)

When agents disagree (e.g. Static score > 0.8 but Semantic score < 0.3), the Debate Synthesizer cross-examines evidence:

```python
from codesheriff_engine.fusion.bayes import FusionResult
from codesheriff_engine.contracts import Evidence

DEBATE_PROMPT_TEMPLATE = """
You are the CodeSheriff Multi-Agent Debate Synthesizer. Two analyzers disagree on a security finding:

- Static Agent Finding: {static_evidence}
- Semantic Agent Finding: {semantic_evidence}

CODE BEING REVIEWED:
{code_snippet}

TASK:
1. Determine if the Semantic Agent's intent rationale proves the Static Agent's finding is a FALSE ALARM (e.g. valid sanitization, type-casting, or framework protection).
2. Or determine if the Static Agent's taint path proves a REAL VULNERABILITY that the Semantic Agent missed.
3. Emit final JSON: {{"resolved_vulnerable": bool, "final_score": float, "consensus_explanation": str}}
"""

def resolve_agent_conflict(fusion: FusionResult, code_snippet: str) -> FusionResult:
    scores = [ev.raw_score for ev in fusion.evidence_list]
    max_score = max(scores)
    min_score = min(scores)

    # Trigger debate ONLY if there is a severe conflict (> 0.5 gap)
    if (max_score - min_score) > 0.5:
        # Calls LLM Debate Synthesizer
        debate_outcome = run_llm_debate_prompt(fusion.evidence_list, code_snippet)
        fusion.posterior_probability = debate_outcome["final_score"]
        fusion.is_alert_worthy = debate_outcome["resolved_vulnerable"] and (fusion.posterior_probability >= 0.70)
        fusion.consensus_rationale = debate_outcome["consensus_explanation"]

    return fusion
```

---

### C. Multi-Agent Parallel Orchestrator (`src/codesheriff_engine/orchestrator.py`)

```python
import asyncio
from codesheriff_engine.contracts import ChangeUnit, Evidence
from static_agent import StaticAgent
from semantic_agent import SemanticAgent
from context_agent import ContextAgent

class Orchestrator:
    def __init__(self) -> None:
        self.static_agent = StaticAgent()
        self.semantic_agent = SemanticAgent()
        self.context_agent = ContextAgent()

    async def analyze_change_unit(self, unit: ChangeUnit) -> list[Evidence]:
        # Phase 1: Run Static Agent first to get primary findings and anchor keys
        static_evidence = await asyncio.to_thread(self.static_agent.analyze, unit)
        
        anchor_keys = {ev.finding_key for ev in static_evidence if ev.finding_key}

        # Phase 2: Run Semantic & Context Agents in parallel using anchors
        semantic_task = asyncio.to_thread(self.semantic_agent.analyze, unit, anchor_keys)
        context_task = asyncio.to_thread(self.context_agent.analyze, unit, anchor_keys)

        semantic_evidence, context_evidence = await asyncio.gather(semantic_task, context_task)

        # Merge all evidence
        return static_evidence + semantic_evidence + context_evidence
```

---

### D. GitHub Webhook & Review Comment Reporter (`src/codesheriff_engine/github/reporter.py`)

Formats and posts the final review markdown to GitHub:

```python
def format_github_comment(fusion_results: list[FusionResult]) -> str:
    comment = "## 🛡️ CodeSheriff Security Review\n\n"
    
    alert_findings = [f for f in fusion_results if f.is_alert_worthy]
    
    if not alert_findings:
        return comment + "✅ **No security vulnerabilities detected.** All safety checks passed."

    for f in alert_findings:
        ev = f.evidence_list[0]
        prob_pct = f"{f.posterior_probability * 100:.1f}%"
        
        comment += f"### 🚨 Vulnerability Detected (Probability: `{prob_pct}`)\n"
        comment += f"**CWE:** `{ev.cwe}` · **Title:** {ev.title}\n\n"
        
        comment += "| Agent | Opinion | Score | Rationale / Evidence |\n"
        comment += "| :--- | :--- | :--- | :--- |\n"
        
        for item in f.evidence_list:
            comment += f"| `{item.agent_id}` | ⚠️ Alert | `{item.raw_score:.2f}` | {item.rationale} |\n"
        
        if f.consensus_rationale:
            comment += f"\n**Debate Resolution:** {f.consensus_rationale}\n"
            
        comment += "\n---\n"
        
    return comment
```

---

## 5. Acceptance & Verification Plan

| Check | Target |
| :--- | :--- |
| **All 3 Agents Executed** | 100% parallel execution without thread blockages |
| **Bayesian Math Correctness** | Tested via `test_bayes_math.py` unit tests |
| **Debate Triggering** | Activates only on conflict ($\Delta \text{score} > 0.5$) |
| **GitHub Webhook Response** | Posts review comment to GitHub PR in $< 5$ seconds |
| **Clean Exit** | Zero unhandled exceptions or crashes |
