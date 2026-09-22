"""Subprocess runner for Semgrep CLI analysis."""

import contextlib
import json
import os
import subprocess
import tempfile

from codesheriff_contracts import ChangeUnit, Evidence
from static_agent.config import StaticConfig
from static_agent.emission import with_residual_silence
from static_agent.semgrep.mapping import (
    AGENT_ID,
    COVERED_CWES,
    map_sarif_result_to_evidence,
)


def run_semgrep(unit: ChangeUnit, config: StaticConfig) -> list[Evidence]:
    """Run Semgrep CLI against unit post_src in a temporary file and return list of Evidence."""
    ext = (
        ".py"
        if unit.language.lower() == "python"
        else ".js"
        if unit.language.lower() in ("javascript", "js")
        else ".txt"
    )

    with tempfile.NamedTemporaryFile("w", suffix=ext, delete=False, encoding="utf-8") as tmp:
        tmp.write(unit.post_src)
        tmp_path = tmp.name

    try:
        cmd = [
            config.semgrep_binary,
            "--sarif",
            "--quiet",
            "--timeout",
            str(config.semgrep_timeout),
        ]
        for cfg in config.semgrep_configs:
            cmd.extend(["--config", cfg])
        cmd.append(tmp_path)

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.semgrep_timeout + 5,
        )

        if res.returncode not in (0, 1):
            return [
                Evidence.abstention(
                    agent_id=AGENT_ID,
                    agent_version="0.1.0",
                    unit_id=unit.unit_id,
                    reason="tool_unavailable",
                    explanation=(
                        f"Semgrep exited with return code {res.returncode}: {res.stderr[:200]}"
                    ),
                )
            ]

        sarif_data = json.loads(res.stdout or "{}")
        runs = sarif_data.get("runs", [])
        results = runs[0].get("results", []) if runs else []

        # Semgrep completed. Nothing matched is evidence about the code, not a
        # failure to look — returning [] here made the two indistinguishable (D-005).
        if not results:
            return [
                Evidence.silence(
                    agent_id=AGENT_ID,
                    agent_version="0.1.0",
                    unit_id=unit.unit_id,
                    covered_cwes=COVERED_CWES,
                    explanation="Semgrep ran to completion with no matching rule.",
                )
            ]

        by_key: dict[str, Evidence] = {}
        for r in results[: config.max_evidence_per_unit]:
            ev = map_sarif_result_to_evidence(result=r, unit=unit)
            if ev is None or ev.finding_key is None:
                continue  # out of scope; dropped, never relabelled
            existing = by_key.get(ev.finding_key)
            if existing is None or ev.raw_score > existing.raw_score:
                by_key[ev.finding_key] = ev

        if not by_key:
            return [
                Evidence.silence(
                    agent_id=AGENT_ID,
                    agent_version="0.1.0",
                    unit_id=unit.unit_id,
                    covered_cwes=COVERED_CWES,
                    explanation="Semgrep matched only rules outside IN_SCOPE_CWES.",
                )
            ]

        return with_residual_silence(
            sorted(by_key.values(), key=lambda e: e.raw_score, reverse=True),
            agent_id=AGENT_ID,
            agent_version="0.1.0",
            unit_id=unit.unit_id,
            covered_cwes=COVERED_CWES,
            silent_explanation="Semgrep ran to completion with no matching rule for these CWEs.",
        )

    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, Exception) as e:
        reason = "timeout" if isinstance(e, subprocess.TimeoutExpired) else "tool_unavailable"
        return [
            Evidence.abstention(
                agent_id=AGENT_ID,
                agent_version="0.1.0",
                unit_id=unit.unit_id,
                reason=reason,
                explanation=f"Semgrep execution failed: {e!s}",
            )
        ]
    finally:
        if os.path.exists(tmp_path):
            with contextlib.suppress(OSError):
                os.remove(tmp_path)
