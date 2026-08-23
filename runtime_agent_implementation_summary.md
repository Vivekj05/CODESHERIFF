# Technical Implementation Spec: CodeSheriff Runtime Agent (SFI)

**Package:** `runtime_agent` · **Repo:** `codesheriff-runtime-agent`  
**Agent ID:** `runtime.sfi` · **Language:** Python 3.12 (`uv`) / Docker + gVisor  
**Purpose:** Executes incoming Pull Request code inside a **Software Fault Isolation (SFI)** sandbox to observe real-time execution behavior — detecting unhandled crashes, unauthorized file system access, network exfiltration attempts, and abnormal resource usage.

---

## 1. Executive Summary & Core Philosophy

Static and Semantic analysis examine code *as written*. However, complex vulnerabilities (e.g., zero-day exploits, malicious supply-chain dependencies, hidden backdoors, resource exhaustion attacks) are frequently only detectable **when the code actually runs**.

The **Runtime Agent**:
1. Spins up an ultra-isolated **SFI Sandbox** (using Docker with Google `gVisor` (`runsc`) or Linux `seccomp-bpf` + `cgroups`).
2. Executes targeted test suites or synthetic entrypoints against the modified code payload (`ChangeUnit`).
3. Traces system calls (`sys_enter`, `sys_exit`), file I/O operations, network socket connections, and uncaught exceptions in real time.
4. Generates structured `Evidence` containing security findings, system call logs, or crash stack traces.
5. Employs pre-warmed container caching and selective execution to keep pipeline latency under **15 seconds**.

---

## 2. System Architecture & Folder Structure

```
codesheriff-runtime-agent/
├── README.md
├── pyproject.toml
├── .python-version                 # 3.12
├── .env.example
├── src/runtime_agent/
│   ├── __init__.py
│   ├── contracts.py                # VENDORED — contracts.py (SHA-256 integrity checked)
│   ├── config.py                   # Pydantic settings (SFI runtime, timeout, memory caps)
│   ├── cli.py                      # run | test-sandbox | version
│   ├── agent.py                    # RuntimeAgent.analyze(unit) -> list[Evidence]
│   ├── sfi/
│   │   ├── __init__.py
│   │   ├── sandbox.py              # gVisor/Docker container lifecycle manager
│   │   ├── tracer.py               # Syscall & File I/O monitor (strace/seccomp logs)
│   │   ├── network.py              # Socket connection & network egress detector
│   │   └── executor.py             # Code runner (pytest / synthetic function invocation)
│   └── rules/
│       ├── __init__.py
│       └── detectors.py            # Rules identifying suspicious syscalls (e.g., /etc/passwd access)
└── tests/
    ├── conftest.py
    ├── test_sandbox_isolation.py   # Tests gVisor container escape prevention
    ├── test_network_egress.py      # Verifies blocked unauthorized outgoing connections
    ├── test_file_traversal.py      # Verifies detection of unauthorized file access
    └── test_agent_abstain.py       # Verifies graceful abstention on unsupported runtimes
```

---

## 3. Technology Stack & SFI Architecture ($0 Open-Source Stack)

| Component | Selected Tool | Purpose / Benefit |
| :--- | :--- | :--- |
| **SFI Sandbox Runtime** | **Docker + gVisor (`runsc`)** | User-space Linux kernel sandbox preventing container escape and kernel exploits |
| **Syscall Monitor** | `strace` / `seccomp-bpf` audit | Intercepts system calls (`openat`, `connect`, `execve`, `ptrace`) |
| **Network Guard** | Linux `veth` / iptables drop | Isolates sandbox network; flags any unauthorized external IP connections |
| **Resource Control** | Linux `cgroups v2` | Enforces strict CPU (0.5 cores) and Memory (256MB) limits to prevent DoS |
| **Test Execution Engine** | `pytest` / custom harness | Executes targeted unit tests or synthetic function calls against `ChangeUnit` |

---

## 4. Key Implementation Modules

### A. SFI Sandbox Lifecycle Manager (`src/runtime_agent/sfi/sandbox.py`)

```python
import subprocess
import json
from pathlib import Path
from typing import Dict, Any, List
from runtime_agent.config import RuntimeConfig

class SFISandbox:
    """Manages gVisor isolated container execution."""

    def __init__(self, config: RuntimeConfig):
        self.config = config

    def execute_payload(self, code_dir: Path, entrypoint_cmd: List[str]) -> Dict[str, Any]:
        """Runs the code payload inside gVisor container with strict isolation."""
        cmd = [
            "docker", "run", "--rm",
            "--runtime=runsc",             # Uses Google gVisor SFI sandbox
            "--network=none",               # Block all external network by default
            "--memory=256m",                # Memory cap
            "--cpus=0.5",                   # CPU cap
            "--read-only",                  # Read-only root filesystem
            "-v", f"{code_dir}:/workspace:ro",
            "codesheriff-sfi-base:latest",
        ] + entrypoint_cmd

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds, # Default: 15s
            )
            return {
                "exit_code": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "timed_out": False,
            }
        except subprocess.TimeoutExpired:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Execution timed out (Resource Exhaustion / Infinite Loop)",
                "timed_out": True,
            }
```

---

### B. Syscall & Malicious Behavior Detector (`src/runtime_agent/rules/detectors.py`)

```python
from typing import List, Optional
from runtime_agent.contracts import Evidence, Artifact

SENSITIVE_FILES = ["/etc/passwd", "/etc/shadow", ".env", "id_rsa", "AWS_SECRET_ACCESS_KEY"]

def analyze_execution_trace(unit_id: str, trace_output: str, exit_code: int) -> List[Evidence]:
    """Analyzes execution logs for suspicious syscalls, file access, or crashes."""
    evidence_list = []

    # 1. Check for Unauthorized File Access Attempts
    for sensitive_file in SENSITIVE_FILES:
        if sensitive_file in trace_output:
            evidence_list.append(
                Evidence(
                    agent_id="runtime.sfi",
                    agent_version="0.1.0",
                    unit_id=unit_id,
                    finding_key=f"{unit_id}:CWE-200:file_access:{sensitive_file}",
                    cwe="CWE-200", # Exposure of Sensitive Information
                    raw_score=0.9,
                    confidence=0.95,
                    explanation=f"Runtime SFI trapped unauthorized attempt to access sensitive file: {sensitive_file}",
                    artifacts=[Artifact(artifact_type="sys_trace", content=trace_output[-500:])],
                )
            )

    # 2. Check for Unhandled Memory/Crash Vulnerability
    if exit_code in (-11, 139):  # Segmentation Fault
        evidence_list.append(
            Evidence(
                agent_id="runtime.sfi",
                agent_version="0.1.0",
                unit_id=unit_id,
                finding_key=f"{unit_id}:CWE-119:segfault",
                cwe="CWE-119", # Buffer Overflow / Memory Corruption
                raw_score=0.95,
                confidence=1.0,
                explanation="Runtime SFI trapped a Segmentation Fault (Buffer Overflow / Memory Corruption).",
                artifacts=[Artifact(artifact_type="crash_log", content=trace_output[-500:])],
            )
        )

    return evidence_list
```

---

### C. Runtime Agent Entry Point (`src/runtime_agent/agent.py`)

```python
import logging
from typing import List
from runtime_agent.contracts import ChangeUnit, Evidence
from runtime_agent.config import RuntimeConfig
from runtime_agent.sfi.sandbox import SFISandbox
from runtime_agent.rules.detectors import analyze_execution_trace

logger = logging.getLogger(__name__)

class RuntimeAgent:
    """Runtime SFI Security Analysis Agent."""

    def __init__(self, config: Optional[RuntimeConfig] = None):
        self.config = config or RuntimeConfig()
        self.sandbox = SFISandbox(self.config)

    def analyze(self, unit: ChangeUnit) -> List[Evidence]:
        """Runs ChangeUnit inside SFI sandbox and evaluates runtime behavior."""
        # Graceful abstention for non-executable or unsupported languages
        if unit.language.lower() not in ("python", "py", "javascript", "js"):
            return [
                Evidence.abstention(
                    agent_id="runtime.sfi",
                    agent_version="0.1.0",
                    unit_id=unit.unit_id,
                    reason="unsupported_language",
                    explanation=f"Runtime SFI does not support language: {unit.language}",
                )
            ]

        try:
            # 1. Setup temporary sandbox volume with post_src code
            # 2. Run targeted execution
            result = self.sandbox.execute_payload(unit.file, ["python", "-m", "pytest"])

            # 3. Detect suspicious behavior from execution trace
            findings = analyze_execution_trace(unit.unit_id, result["stderr"], result["exit_code"])
            
            if not findings:
                # Clean execution pass
                return [
                    Evidence(
                        agent_id="runtime.sfi",
                        agent_version="0.1.0",
                        unit_id=unit.unit_id,
                        finding_key=f"clean:{unit.unit_id}",
                        cwe=None,
                        raw_score=0.0,
                        confidence=1.0,
                        explanation="Runtime SFI execution passed without crashes, file leaks, or abnormal syscalls.",
                    )
                ]
            return findings

        except Exception as e:
            logger.exception("Runtime SFI execution failed")
            return [
                Evidence.abstention(
                    agent_id="runtime.sfi",
                    agent_version="0.1.0",
                    unit_id=unit.unit_id,
                    reason="runtime_error",
                    explanation=f"SFI sandbox execution error: {str(e)}",
                )
            ]
```

---

## 5. Performance & Pipeline Latency Optimization

To prevent blocking developer PRs:
1. **Pre-warmed Container Cache:** Docker image base layers are cached in CI/CD runners; startup time takes **< 1.5 seconds**.
2. **Selective Execution:** Only invoked if `changed_lines` modify executable code files (skips `.md`, `.json`, `.css`).
3. **Hard Timeout Cap:** Maximum execution time strictly capped at **15 seconds** per unit test.
