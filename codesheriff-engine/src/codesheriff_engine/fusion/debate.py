"""Multi-Agent Debate & Conflict Synthesizer for CodeSheriff."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

import httpx

from codesheriff_engine.config import EngineConfig
from codesheriff_engine.contracts import Evidence
from codesheriff_engine.fusion.bayes import FusionResult

logger = logging.getLogger(__name__)

DEBATE_PROMPT_TEMPLATE = """You are the CodeSheriff Multi-Agent Security Debate Synthesizer.
Two or more independent security analyzers disagree on whether the following code change is vulnerable:

{agent_breakdown}

CODE CHANGE UNDER REVIEW:
```
{code_snippet}
```

TASK:
1. Cross-examine the evidence. Determine if one analyzer identified a real sanitization/type-cast that makes this a FALSE ALARM, or if the taint path is a TRUE VULNERABILITY that another analyzer overlooked.
2. Return ONLY a valid JSON object matching this structure:
{{
  "resolved_vulnerable": true/false,
  "final_score": 0.0 - 1.0,
  "consensus_explanation": "Concise 1-2 sentence explanation of the debate conclusion."
}}
"""


def _build_agent_breakdown(evidence_list: List[Evidence]) -> str:
    """Format agent findings into structured debate input."""
    lines: List[str] = []
    for ev in evidence_list:
        if ev.abstained:
            continue
        lines.append(
            f"- [{ev.agent_id}] Score: {ev.raw_score:.2f} | CWE: {ev.cwe or 'N/A'} | "
            f"Rationale: {ev.explanation}"
        )
    return "\n".join(lines)


def _heuristic_debate_resolution(
    evidence_list: List[Evidence],
    code_snippet: str,
) -> Dict[str, Any]:
    """Offline deterministic fallback to synthesize agent conflicts when LLM is unavailable."""
    scores = [ev.raw_score for ev in evidence_list if not ev.abstained]
    if not scores:
        return {
            "resolved_vulnerable": False,
            "final_score": 0.1,
            "consensus_explanation": "Agents abstained; default to non-vulnerable.",
        }

    # Inspect code snippet for common sanitizers / protections
    code_lower = code_snippet.lower()
    has_sanitizer = any(
        kw in code_lower
        for kw in ["escape", "sanitize", "parameterized", "prepare", "int(", "float(", "quote", "urlencode", "whitelist"]
    )
    has_danger_sink = any(
        kw in code_lower
        for kw in ["os.system", "eval(", "exec(", "cursor.execute(f", "cursor.execute(\"\"\" +", "subprocess.call(cmd"]
    )

    if has_sanitizer and not has_danger_sink:
        return {
            "resolved_vulnerable": False,
            "final_score": 0.25,
            "consensus_explanation": "Debate resolved as False Alarm: Sanitization / parameterization detected in code flow.",
        }
    elif has_danger_sink:
        return {
            "resolved_vulnerable": True,
            "final_score": 0.85,
            "consensus_explanation": "Debate confirmed Vulnerability: Direct unsanitized input reaches high-danger execution sink.",
        }
    else:
        avg_score = sum(scores) / len(scores)
        is_vuln = avg_score >= 0.60
        return {
            "resolved_vulnerable": is_vuln,
            "final_score": round(avg_score, 2),
            "consensus_explanation": (
                f"Debate resolved via weighted consensus (mean score: {avg_score:.2f})."
            ),
        }


def _call_llm_debate_sync(
    prompt: str,
    config: EngineConfig,
) -> Optional[Dict[str, Any]]:
    """Call LLM provider synchronously for debate synthesis."""
    if not config.llm_api_key:
        return None

    try:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {config.llm_api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": config.debate_model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": "You are a precise security arbiter that resolves disagreements between static analysis and LLM analyzers. Always respond in JSON.",
                },
                {"role": "user", "content": prompt},
            ],
        }

        with httpx.Client(timeout=config.debate_timeout_seconds) as client:
            resp = client.post(url, headers=headers, json=body)
            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                return {
                    "resolved_vulnerable": bool(parsed.get("resolved_vulnerable", False)),
                    "final_score": float(parsed.get("final_score", 0.5)),
                    "consensus_explanation": str(parsed.get("consensus_explanation", "")),
                }
            else:
                logger.warning("Debate LLM returned status %s: %s", resp.status_code, resp.text)
    except Exception as e:
        logger.warning("Debate LLM call failed: %s", e)

    return None


def resolve_agent_conflict(
    fusion: FusionResult,
    code_snippet: str,
    config: Optional[EngineConfig] = None,
) -> FusionResult:
    """Examine evidence for severe disagreement; trigger multi-agent debate if necessary."""
    cfg = config or EngineConfig.load()
    if not cfg.enable_debate:
        return fusion

    active_scores = [ev.raw_score for ev in fusion.evidence_list if not ev.abstained]
    if len(active_scores) < 2:
        return fusion

    max_score = max(active_scores)
    min_score = min(active_scores)
    score_delta = max_score - min_score

    # Trigger debate ONLY if there is a severe conflict >= conflict_threshold
    if score_delta >= cfg.conflict_threshold:
        agent_breakdown = _build_agent_breakdown(fusion.evidence_list)
        prompt = DEBATE_PROMPT_TEMPLATE.format(
            agent_breakdown=agent_breakdown,
            code_snippet=code_snippet,
        )

        outcome = _call_llm_debate_sync(prompt, cfg)
        if not outcome:
            outcome = _heuristic_debate_resolution(fusion.evidence_list, code_snippet)

        fusion.posterior_probability = round(outcome["final_score"], 4)
        fusion.is_alert_worthy = outcome["resolved_vulnerable"] and (
            fusion.posterior_probability >= cfg.alert_threshold
        )
        fusion.consensus_rationale = outcome["consensus_explanation"]

    return fusion
