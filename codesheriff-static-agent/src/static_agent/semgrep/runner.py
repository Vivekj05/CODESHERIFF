"""Subprocess runner for Semgrep CLI analysis."""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List

from static_agent.config import StaticConfig
from static_agent.contracts import ChangeUnit, Evidence
from static_agent.semgrep.mapping import map_sarif_result_to_evidence


def run_semgrep(unit: ChangeUnit, config: StaticConfig) -> List[Evidence]:
    """Run Semgrep CLI against unit post_src in a temporary file and return list of Evidence."""
    ext = ".py" if unit.language.lower() == "python" else ".js" if unit.language.lower() in ("javascript", "js") else ".txt"

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
                    agent_id="structural.semgrep",
                    agent_version="0.1.0",
                    unit_id=unit.unit_id,
                    reason="tool_unavailable",
                    explanation=f"Semgrep exited with return code {res.returncode}: {res.stderr[:200]}",
                )
            ]

        sarif_data = json.loads(res.stdout or "{}")
        runs = sarif_data.get("runs", [])
        if not runs:
            return []

        results = runs[0].get("results", [])
        evidence_list: List[Evidence] = []
        for r in results[: config.max_evidence_per_unit]:
            ev = map_sarif_result_to_evidence(
                result=r,
                unit_id=unit.unit_id,
                file_path=unit.file,
                symbol=unit.symbol,
                is_test_file=unit.is_test_file,
            )
            evidence_list.append(ev)

        return evidence_list

    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, Exception) as e:
        reason = "timeout" if isinstance(e, subprocess.TimeoutExpired) else "tool_unavailable"
        return [
            Evidence.abstention(
                agent_id="structural.semgrep",
                agent_version="0.1.0",
                unit_id=unit.unit_id,
                reason=reason,
                explanation=f"Semgrep execution failed: {str(e)}",
            )
        ]
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
