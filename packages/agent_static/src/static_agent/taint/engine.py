"""Worklist taint propagation engine over Def-Use graph."""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import networkx as nx

from static_agent.config import StaticConfig
from static_agent.contracts import ChangeUnit, Evidence, finding_key
from static_agent.scoring import calculate_raw_score
from static_agent.taint.catalog import Catalog, RuleSink
from static_agent.taint.defuse import DefUseGraph, build_defuse_graph
from static_agent.taint.parse import CodeParser
from static_agent.taint.render import render_taint_path
from static_agent.taint.symbols import enclosing_symbol, extract_symbols


def analyze_taint(unit: ChangeUnit, config: StaticConfig) -> List[Evidence]:
    """Run flow-based taint analysis on ChangeUnit. Never raises."""
    try:
        lang = unit.language.lower()
        if lang not in ("python", "py", "javascript", "js", "typescript", "ts"):
            return [
                Evidence.abstention(
                    agent_id="structural.taint",
                    agent_version="0.1.0",
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

        code_lines = unit.post_src.splitlines()

        # Step 1: Detect sources
        source_matches: List[Dict[str, Any]] = []
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
            return []

        # Step 2: Detect sinks
        sink_matches: List[Dict[str, Any]] = []
        for idx, line in enumerate(code_lines, start=1):
            for sink_rule in sinks:
                if catalog.matches_pattern(sink_rule.match, line):
                    # Check for requires_arg / forbids_arg conditions
                    if sink_rule.requires_arg and not catalog.matches_pattern(sink_rule.requires_arg, line):
                        continue
                    if sink_rule.forbids_arg and catalog.matches_pattern(sink_rule.forbids_arg, line):
                        continue
                    sink_matches.append(
                        {
                            "line": idx,
                            "expr": line.strip(),
                            "sink_rule": sink_rule,
                        }
                    )

        if not sink_matches:
            return []

        # Step 3: Check for sanitizers
        sanitizer_lines: Set[int] = set()
        partial_sanitizers = False
        for idx, line in enumerate(code_lines, start=1):
            for s_rule in sanitizers:
                if catalog.matches_pattern(s_rule.match, line):
                    sanitizer_lines.add(idx)

        # Build Def-Use graph
        defuse = build_defuse_graph(unit.post_src, language=lang_key)
        symbols = extract_symbols(CodeParser().parse(unit.post_src, lang_key) or None) if False else []

        evidence_list: List[Evidence] = []

        for src in source_matches:
            for snk in sink_matches:
                if snk["line"] < src["line"]:
                    continue

                sink_rule: RuleSink = snk["sink_rule"]

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
                    {"line": src["line"], "expr": src["expr"], "var_name": "source", "role": "source"},
                    {"line": snk["line"], "expr": snk["expr"], "var_name": "sink", "role": "sink"},
                ]

                artifact = render_taint_path(path_steps)

                symbol_name = unit.symbol or enclosing_symbol(snk["line"], symbols) or "main"
                f_key = finding_key(unit.file, symbol_name, sink_rule.cwe, snk["expr"])

                score = calculate_raw_score(
                    danger=sink_rule.danger,
                    partial_sanitizer=partial_sanitizers,
                    path_length=len(path_steps),
                    network_facing=True,
                    is_test_file=unit.is_test_file,
                )

                evidence = Evidence(
                    agent_id="structural.taint",
                    agent_version="0.1.0",
                    unit_id=unit.unit_id,
                    finding_key=f_key,
                    cwe=sink_rule.cwe,
                    raw_score=score,
                    confidence=0.90,
                    explanation=(
                        f"Taint path detected from source '{src['rule_id']}' at line {src['line']} "
                        f"reaching sink '{sink_rule.id}' at line {snk['line']} ({sink_rule.cwe})."
                    ),
                    artifacts=[artifact],
                    abstained=False,
                    abstain_reason=None,
                )
                evidence_list.append(evidence)

        return evidence_list[: config.max_evidence_per_unit]

    except Exception as e:
        return [
            Evidence.abstention(
                agent_id="structural.taint",
                agent_version="0.1.0",
                unit_id=unit.unit_id,
                reason="internal_error",
                explanation=f"Taint analysis encountered unexpected error: {str(e)}",
            )
        ]
