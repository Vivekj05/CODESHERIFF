"""Tests for execution trace detectors."""

from runtime_agent.config import RuntimeConfig
from runtime_agent.rules.detectors import analyze_trace
from runtime_agent.sfi.sandbox import SFISandboxResult
from runtime_agent.sfi.tracer import ExecutionTrace


def test_sensitive_file_leak_detector() -> None:
    config = RuntimeConfig()
    result = SFISandboxResult(
        exit_code=0,
        stdout="",
        stderr="Attempting to open file: /etc/passwd",
    )
    trace = ExecutionTrace(result)
    findings = analyze_trace("unit-01", "app/api.py", trace, config)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-200"
    assert "sensitive pattern" in findings[0].explanation


def test_segfault_detector() -> None:
    config = RuntimeConfig()
    result = SFISandboxResult(
        exit_code=139,
        stdout="",
        stderr="Segmentation fault (core dumped)",
    )
    trace = ExecutionTrace(result)
    findings = analyze_trace("unit-02", "app/api.py", trace, config)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-119"
    assert "Segmentation Fault" in findings[0].explanation


def test_timeout_detector() -> None:
    config = RuntimeConfig()
    result = SFISandboxResult(
        exit_code=-1,
        stdout="",
        stderr="Execution timed out",
        timed_out=True,
    )
    trace = ExecutionTrace(result)
    findings = analyze_trace("unit-03", "app/api.py", trace, config)

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-400"
    assert "Denial of Service" in findings[0].explanation
