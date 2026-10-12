"""Subprocess runner for Semgrep CLI analysis.

Semgrep runs against **pinned** rules and a **pinned** build (D-104). Both are checked before the
unit is analysed, and either one failing is an abstention under its own reason: the structural
ratios were fitted on one set of rules from one build, and a run on anything else would be scored
by numbers measured on a different backend while still calling the result a posterior.
"""

import contextlib
import functools
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from codesheriff_contracts import ChangeUnit, Evidence
from static_agent.config import SEMGREP_VERSION, StaticConfig
from static_agent.emission import with_residual_silence
from static_agent.semgrep.mapping import (
    AGENT_ID,
    AGENT_VERSION,
    COVERED_CWES,
    map_sarif_result_to_evidence,
    rule_cwes,
)


class _UnavailableError(Exception):
    """Semgrep cannot run as fitted. Carries the abstention reason."""

    def __init__(self, reason: str, explanation: str) -> None:
        super().__init__(explanation)
        self.reason = reason
        self.explanation = explanation


def _abstain(unit: ChangeUnit, reason: str, explanation: str) -> list[Evidence]:
    return [
        Evidence.abstention(
            agent_id=AGENT_ID,
            agent_version=AGENT_VERSION,
            unit_id=unit.unit_id,
            reason=reason,
            explanation=explanation,
        )
    ]


def verified_rule_paths(rules_dir: Path, pins: dict[str, str]) -> list[Path]:
    """Every pinned ruleset, each checked against its digest. Raises `_UnavailableError` otherwise.

    Hashed on every call rather than cached: the files are about 2 MB together, which costs a few
    milliseconds, and a cache keyed on anything weaker than the bytes would let an edited ruleset
    through until the process restarted.
    """
    paths: list[Path] = []
    for name, expected in sorted(pins.items()):
        path = rules_dir / name
        if not path.is_file():
            raise _UnavailableError(
                "rules_unavailable",
                f"Pinned Semgrep ruleset {name} is not in {rules_dir}. Fetch it as the corpus-run "
                "README describes; Semgrep never fetches rules at analysis time.",
            )
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise _UnavailableError(
                "rules_mismatch",
                f"Semgrep ruleset {name} has digest {actual[:12]}, not the pinned "
                f"{expected[:12]}. A different ruleset is a different backend from the one the "
                "structural ratios were fitted on.",
            )
        paths.append(path)
    return paths


@functools.cache
def _installed_version(binary: str) -> str:
    """`semgrep --version`, once per process per binary. Raises if Semgrep cannot run."""
    try:
        res = subprocess.run(
            [binary, "--version", "--disable-version-check"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise _UnavailableError("tool_unavailable", f"Semgrep could not be started: {e!s}") from e
    if res.returncode != 0:
        raise _UnavailableError(
            "tool_unavailable",
            f"semgrep --version exited with {res.returncode}: {res.stderr[:200]}",
        )
    return res.stdout.strip().splitlines()[-1].strip() if res.stdout.strip() else ""


def _check_version(binary: str) -> None:
    version = _installed_version(binary)
    if version != SEMGREP_VERSION:
        raise _UnavailableError(
            "tool_version_mismatch",
            f"Semgrep {version or '(unknown)'} is installed; the structural ratios were fitted "
            f"with {SEMGREP_VERSION}.",
        )


def run_semgrep(unit: ChangeUnit, config: StaticConfig) -> list[Evidence]:
    """Run Semgrep CLI against unit post_src in a temporary file and return list of Evidence."""
    try:
        _check_version(config.semgrep_binary)
        rule_paths = verified_rule_paths(config.semgrep_rules_dir, config.semgrep_rulesets)
    except _UnavailableError as e:
        return _abstain(unit, e.reason, e.explanation)

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
            # The unit is somebody's source code. Semgrep reports usage metrics by default, and an
            # analysis of untrusted code should not report itself to anyone (D-104).
            "--metrics=off",
            "--disable-version-check",
            "--timeout",
            str(config.semgrep_timeout),
        ]
        for path in rule_paths:
            cmd.extend(["--config", str(path)])
        cmd.append(tmp_path)

        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.semgrep_timeout + 5,
        )

        if res.returncode not in (0, 1):
            return _abstain(
                unit,
                "tool_unavailable",
                f"Semgrep exited with return code {res.returncode}: {res.stderr[:200]}",
            )

        sarif_data = json.loads(res.stdout or "{}")
        runs = sarif_data.get("runs", [])
        results = runs[0].get("results", []) if runs else []
        cwes_by_rule = rule_cwes(runs[0]) if runs else {}

        # Semgrep completed. Nothing matched is evidence about the code, not a
        # failure to look — returning [] here made the two indistinguishable (D-005).
        if not results:
            return [
                Evidence.silence(
                    agent_id=AGENT_ID,
                    agent_version=AGENT_VERSION,
                    unit_id=unit.unit_id,
                    covered_cwes=COVERED_CWES,
                    explanation="Semgrep ran to completion with no matching rule.",
                )
            ]

        by_key: dict[str, Evidence] = {}
        for r in results[: config.max_evidence_per_unit]:
            ev = map_sarif_result_to_evidence(result=r, unit=unit, cwes_by_rule=cwes_by_rule)
            if ev is None or ev.finding_key is None:
                continue  # out of scope; dropped, never relabelled
            existing = by_key.get(ev.finding_key)
            if existing is None or ev.raw_score > existing.raw_score:
                by_key[ev.finding_key] = ev

        if not by_key:
            return [
                Evidence.silence(
                    agent_id=AGENT_ID,
                    agent_version=AGENT_VERSION,
                    unit_id=unit.unit_id,
                    covered_cwes=COVERED_CWES,
                    explanation="Semgrep matched only rules outside IN_SCOPE_CWES.",
                )
            ]

        return with_residual_silence(
            sorted(by_key.values(), key=lambda e: e.raw_score, reverse=True),
            agent_id=AGENT_ID,
            agent_version=AGENT_VERSION,
            unit_id=unit.unit_id,
            covered_cwes=COVERED_CWES,
            silent_explanation="Semgrep ran to completion with no matching rule for these CWEs.",
        )

    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, Exception) as e:
        reason = "timeout" if isinstance(e, subprocess.TimeoutExpired) else "tool_unavailable"
        return _abstain(unit, reason, f"Semgrep execution failed: {e!s}")
    finally:
        if os.path.exists(tmp_path):
            with contextlib.suppress(OSError):
                os.remove(tmp_path)
