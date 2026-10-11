"""Semgrep runs on pinned rules from a pinned build, or abstains under its own reason (D-104).

None of these needs a Semgrep binary: they check what happens *before* one would be started, which
is the part that keeps a structural ratio from scoring a backend it was never fitted on.
"""

import hashlib
from pathlib import Path

import pytest

from codesheriff_contracts import ChangeUnit, EvidenceKind
from static_agent.config import SEMGREP_RULESETS, SEMGREP_VERSION, StaticConfig
from static_agent.semgrep import runner


def _unit() -> ChangeUnit:
    return ChangeUnit(
        unit_id="u-1",
        repo="acme/app",
        file="app/net.py",
        language="python",
        symbol="ping",
        base_sha="a" * 40,
        head_sha="b" * 40,
        pre_src="def ping(host):\n    return 0\n",
        post_src="import os\n\ndef ping(host):\n    return os.system('ping ' + host)\n",
        changed_lines=[4],
        start_line=1,
    )


def _pinned_dir(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    pins: dict[str, str] = {}
    for name in ("a.yml", "b.yml"):
        body = f"rules: []  # {name}\n".encode()
        (tmp_path / name).write_bytes(body)
        pins[name] = hashlib.sha256(body).hexdigest()
    return tmp_path, pins


@pytest.fixture
def right_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "_installed_version", lambda binary: SEMGREP_VERSION)


def test_the_registry_is_never_named() -> None:
    """`p/...` fetched whatever the registry served that day; the config now names files."""
    assert all(name.endswith(".yml") for name in SEMGREP_RULESETS)
    assert all(len(digest) == 64 for digest in SEMGREP_RULESETS.values())


def test_pinned_rules_are_returned_in_a_stable_order(tmp_path: Path) -> None:
    rules_dir, pins = _pinned_dir(tmp_path)

    paths = runner.verified_rule_paths(rules_dir, pins)

    assert [p.name for p in paths] == ["a.yml", "b.yml"]


def test_a_missing_ruleset_abstains_as_rules_unavailable(
    tmp_path: Path, right_version: None
) -> None:
    _, pins = _pinned_dir(tmp_path)
    config = StaticConfig(semgrep_rules_dir=tmp_path / "elsewhere", semgrep_rulesets=pins)

    [ev] = runner.run_semgrep(_unit(), config)

    assert ev.kind is EvidenceKind.ABSTENTION
    assert ev.reason == "rules_unavailable"
    assert ev.agent_id == "structural.semgrep"


def test_an_edited_ruleset_abstains_as_rules_mismatch(tmp_path: Path, right_version: None) -> None:
    """An edited ruleset is a different backend, so it says so rather than running quietly."""
    rules_dir, pins = _pinned_dir(tmp_path)
    (rules_dir / "b.yml").write_text("rules: []  # edited\n")
    config = StaticConfig(semgrep_rules_dir=rules_dir, semgrep_rulesets=pins)

    [ev] = runner.run_semgrep(_unit(), config)

    assert ev.kind is EvidenceKind.ABSTENTION
    assert ev.reason == "rules_mismatch"


def test_a_different_semgrep_build_abstains_as_a_version_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules_dir, pins = _pinned_dir(tmp_path)
    monkeypatch.setattr(runner, "_installed_version", lambda binary: "1.0.0")
    config = StaticConfig(semgrep_rules_dir=rules_dir, semgrep_rulesets=pins)

    [ev] = runner.run_semgrep(_unit(), config)

    assert ev.kind is EvidenceKind.ABSTENTION
    assert ev.reason == "tool_version_mismatch"


def test_no_binary_at_all_abstains_as_tool_unavailable(tmp_path: Path) -> None:
    rules_dir, pins = _pinned_dir(tmp_path)
    config = StaticConfig(
        semgrep_binary=str(tmp_path / "no-such-semgrep"),
        semgrep_rules_dir=rules_dir,
        semgrep_rulesets=pins,
    )

    [ev] = runner.run_semgrep(_unit(), config)

    assert ev.kind is EvidenceKind.ABSTENTION
    assert ev.reason == "tool_unavailable"


def test_metrics_are_off_and_only_pinned_files_are_passed(
    tmp_path: Path, right_version: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The command line is the contract: no registry name, no metrics, the verified paths."""
    rules_dir, pins = _pinned_dir(tmp_path)
    seen: list[list[str]] = []

    class _Done:
        returncode = 0
        stdout = '{"runs": [{"results": []}]}'
        stderr = ""

    def fake_run(cmd: list[str], **_: object) -> _Done:
        seen.append(cmd)
        return _Done()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    config = StaticConfig(semgrep_rules_dir=rules_dir, semgrep_rulesets=pins)

    [ev] = runner.run_semgrep(_unit(), config)

    assert ev.kind is EvidenceKind.SILENCE
    [cmd] = seen
    assert "--metrics=off" in cmd
    configs = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--config"]
    assert configs == [str(rules_dir / "a.yml"), str(rules_dir / "b.yml")]
    assert not any(arg.startswith("p/") for arg in cmd)
