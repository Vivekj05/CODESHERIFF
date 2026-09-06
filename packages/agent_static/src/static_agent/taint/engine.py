"""Worklist taint propagation engine over Def-Use graph."""

from typing import Any

from codesheriff_contracts import IN_SCOPE_CWES, ChangeUnit, Evidence
from static_agent.config import StaticConfig
from static_agent.scoring import calculate_raw_score
from static_agent.taint.catalog import Catalog, RuleSink
from static_agent.taint.defuse import build_defuse_graph
from static_agent.taint.render import render_taint_path

AGENT_ID = "structural.taint"
AGENT_VERSION = "0.1.0"


def _covered_cwes(catalog: Catalog, lang_key: str) -> frozenset[str]:
    """The CWEs this agent's loaded rules can actually reach.

    SILENCE is only evidence about CWEs an agent can detect (D-006). The taint
    rules carry no sink for CWE-862 or CWE-639, so silence here must not be read
    as reassurance about authorisation bugs — that is precisely the semantic
    agent's territory, and suppressing it would collapse the heterogeneity the
    project rests on.
    """
    return frozenset(sr.cwe.strip().upper() for sr in catalog.sinks.get(lang_key, []))


def analyze_taint(unit: ChangeUnit, config: StaticConfig) -> list[Evidence]:
    """Run flow-based taint analysis on ChangeUnit. Never raises."""
    try:
        lang = unit.language.lower()
        if lang not in ("python", "py", "javascript", "js", "typescript", "ts"):
            return [
                Evidence.abstention(
                    agent_id=AGENT_ID,
                    agent_version=AGENT_VERSION,
                    unit_id=unit.unit_id,
                    reason="unsupported_language",
                    explanation=f"Language {unit.language} is not supported by structural.taint",
                )
            ]

        catalog = Catalog.load_from_dir(config.rules_dir)
        lang_key = "python" if lang in ("python", "py") else "javascript"

        sources = catalog.sources.get(lang_key, [])
        sinks = catalog.sinks.get(lang_key, [])
        sanitizers = catalog.sanitizers.get(lang_key, [])

        # No rules loaded means the agent could not look, which is an ABSTENTION.
        # Reporting SILENCE here would tell the fusion engine "I checked and this is
        # clean" on the strength of an empty rule set — the single most dangerous
        # thing an agent in this design can say (D-005).
        if not sinks or not sources:
            return [
                Evidence.abstention(
                    agent_id=AGENT_ID,
                    agent_version=AGENT_VERSION,
                    unit_id=unit.unit_id,
                    reason="rules_unavailable",
                    explanation=(f"No {lang_key} sources/sinks loaded from {config.rules_dir}."),
                )
            ]

        code_lines = unit.post_src.splitlines()

        # Step 1: Detect sources
        source_matches: list[dict[str, Any]] = []
        for idx, line in enumerate(code_lines, start=1):
            for src_rule in sources:
                if catalog.matches_pattern(src_rule.match, line):
                    source_matches.append(
                        {
                            "line": idx,
                            "expr": line.strip(),
                            "rule_id": src_rule.id,
                            "cwe_hint": src_rule.cwe_hint,
                        }
                    )

        if not source_matches:
            # Ran to completion; no untrusted source reaches this unit. That is a
            # finding about the code, not a failure to look (D-005).
            return [
                Evidence.silence(
                    agent_id=AGENT_ID,
                    agent_version=AGENT_VERSION,
                    unit_id=unit.unit_id,
                    covered_cwes=_covered_cwes(catalog, lang_key),
                    explanation="No untrusted source matched in this unit.",
                )
            ]

        # Step 2: Detect sinks
        sink_matches: list[dict[str, Any]] = []
        for idx, line in enumerate(code_lines, start=1):
            for sink_rule in sinks:
                if catalog.matches_pattern(sink_rule.match, line):
                    # Check for requires_arg / forbids_arg conditions
                    if sink_rule.requires_arg and not catalog.matches_pattern(
                        sink_rule.requires_arg, line
                    ):
                        continue
                    if sink_rule.forbids_arg and catalog.matches_pattern(
                        sink_rule.forbids_arg, line
                    ):
                        continue
                    sink_matches.append(
                        {
                            "line": idx,
                            "expr": line.strip(),
                            "sink_rule": sink_rule,
                        }
                    )

        if not sink_matches:
            return [
                Evidence.silence(
                    agent_id=AGENT_ID,
                    agent_version=AGENT_VERSION,
                    unit_id=unit.unit_id,
                    covered_cwes=_covered_cwes(catalog, lang_key),
                    explanation="No dangerous sink matched in this unit.",
                )
            ]

        # Step 3: Check for sanitizers
        sanitizer_lines: set[int] = set()
        partial_sanitizers = False
        for idx, line in enumerate(code_lines, start=1):
            for s_rule in sanitizers:
                if catalog.matches_pattern(s_rule.match, line):
                    sanitizer_lines.add(idx)

        # NOT A TAINT ENGINE. The graph is built here and never read: propagation
        # below is a line-number cross-product gated on `sink_line >= source_line`,
        # and symbol extraction sat behind a literal `if False` (AUDIT.md 3.1-3.6).
        # PLAN.md Chapter 10 replaces this module and consumes the graph. The build
        # call stays so the defect remains visible rather than quietly tidied away.
        defuse = build_defuse_graph(unit.post_src, language=lang_key)  # noqa: F841

        # Keyed, not appended. Now that finding_key excludes the sink expression
        # (D-004), several source-sink pairs in one unit collapse onto one key.
        # Emitting each would let one agent's likelihood ratio be applied several
        # times over for a single finding, which is not what conditional
        # independence across *agents* licenses. Keep the strongest per key.
        by_key: dict[str, Evidence] = {}

        for src in source_matches:
            for snk in sink_matches:
                if snk["line"] < src["line"]:
                    continue

                rule: RuleSink = snk["sink_rule"]

                # Check if sink line or intermediate lines hit a valid sanitizer
                hit_sanitizer = False
                for line_num in range(src["line"], snk["line"] + 1):
                    if line_num in sanitizer_lines:
                        hit_sanitizer = True
                        break

                if hit_sanitizer:
                    continue  # Sanitized! Safe.

                # Taint path step rendering
                path_steps = [
                    {
                        "line": src["line"],
                        "expr": src["expr"],
                        "var_name": "source",
                        "role": "source",
                    },
                    {"line": snk["line"], "expr": snk["expr"], "var_name": "sink", "role": "sink"},
                ]

                artifact = render_taint_path(path_steps)

                # Key through the unit, never a locally reassembled symbol, and never
                # the sink expression: the taint engine writes `cursor.execute(query)`
                # where the LLM writes `cursor.execute`, and including it gave the same
                # bug two keys (D-004, AUDIT.md 1.1).
                if rule.cwe.strip().upper() not in IN_SCOPE_CWES:
                    continue
                f_key = unit.key_for(rule.cwe)

                score = calculate_raw_score(
                    danger=rule.danger,
                    partial_sanitizer=partial_sanitizers,
                    path_length=len(path_steps),
                    network_facing=True,
                    is_test_file=unit.is_test_file,
                )

                evidence = Evidence.detection(
                    agent_id=AGENT_ID,
                    agent_version=AGENT_VERSION,
                    unit_id=unit.unit_id,
                    finding_key=f_key,
                    cwe=rule.cwe,
                    raw_score=score,
                    confidence=0.90,
                    explanation=(
                        f"Taint path detected from source '{src['rule_id']}' at line {src['line']} "
                        f"reaching sink '{rule.id}' at line {snk['line']} ({rule.cwe})."
                    ),
                    artifacts=[artifact],
                )
                existing = by_key.get(f_key)
                if existing is None or evidence.raw_score > existing.raw_score:
                    by_key[f_key] = evidence

        evidence_list = sorted(by_key.values(), key=lambda e: e.raw_score, reverse=True)
        if not evidence_list:
            return [
                Evidence.silence(
                    agent_id=AGENT_ID,
                    agent_version=AGENT_VERSION,
                    unit_id=unit.unit_id,
                    covered_cwes=_covered_cwes(catalog, lang_key),
                    explanation="Sources and sinks present, but no unsanitised path between them.",
                )
            ]

        return evidence_list[: config.max_evidence_per_unit]

    except Exception as e:
        return [
            Evidence.abstention(
                agent_id=AGENT_ID,
                agent_version=AGENT_VERSION,
                unit_id=unit.unit_id,
                reason="internal_error",
                explanation=f"Taint analysis encountered unexpected error: {e!s}",
            )
        ]
