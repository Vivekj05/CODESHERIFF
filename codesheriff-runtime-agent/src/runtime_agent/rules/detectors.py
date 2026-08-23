"""Security detectors analyzing SFI execution traces."""

from typing import List
from runtime_agent.config import RuntimeConfig
from runtime_agent.contracts import Artifact, Evidence, finding_key
from runtime_agent.sfi.tracer import ExecutionTrace


def analyze_trace(unit_id: str, file_path: str, trace: ExecutionTrace, config: RuntimeConfig) -> List[Evidence]:
    """Analyzes execution trace and returns Evidence findings."""
    evidence_list: List[Evidence] = []

    # 1. Check for Unauthorized Sensitive File Access Attempts
    for pattern in config.sensitive_file_patterns:
        if trace.contains_pattern(pattern):
            key = finding_key(file_path, None, "CWE-200", f"file_access:{pattern}")
            evidence_list.append(
                Evidence(
                    agent_id="runtime.sfi",
                    agent_version="0.1.0",
                    unit_id=unit_id,
                    finding_key=key,
                    cwe="CWE-200",
                    raw_score=0.9,
                    confidence=0.95,
                    explanation=f"Runtime SFI trapped unauthorized attempt to access sensitive pattern: '{pattern}'",
                    artifacts=[
                        Artifact(
                            artifact_type="execution_trace",
                            content={"stderr": trace.stderr[-300:], "stdout": trace.stdout[-300:]},
                        )
                    ],
                )
            )

    # 2. Check for Segmentation Faults / Memory Corruption
    if trace.is_segfault():
        key = finding_key(file_path, None, "CWE-119", "memory_segfault")
        evidence_list.append(
            Evidence(
                agent_id="runtime.sfi",
                agent_version="0.1.0",
                unit_id=unit_id,
                finding_key=key,
                cwe="CWE-119",
                raw_score=0.95,
                confidence=1.0,
                explanation="Runtime SFI trapped a Segmentation Fault / Memory Access Violation.",
                artifacts=[
                    Artifact(
                        artifact_type="crash_log",
                        content={"exit_code": trace.exit_code, "stderr": trace.stderr[-300:]},
                    )
                ],
            )
        )

    # 3. Check for Timeout / DoS / Resource Exhaustion
    if trace.timed_out:
        key = finding_key(file_path, None, "CWE-400", "resource_timeout")
        evidence_list.append(
            Evidence(
                agent_id="runtime.sfi",
                agent_version="0.1.0",
                unit_id=unit_id,
                finding_key=key,
                cwe="CWE-400",
                raw_score=0.85,
                confidence=0.9,
                explanation=f"Runtime SFI trapped execution timeout exceeding cap ({config.sfi_timeout_seconds}s). Potential Denial of Service.",
                artifacts=[
                    Artifact(
                        artifact_type="timeout_info",
                        content={"timeout_seconds": config.sfi_timeout_seconds},
                    )
                ],
            )
        )

    # 4. Check for Unauthorized Socket / Network Egress Attempts
    if trace.contains_pattern("socket.connect") or trace.contains_pattern("urllib.request"):
        key = finding_key(file_path, None, "CWE-912", "network_egress")
        evidence_list.append(
            Evidence(
                agent_id="runtime.sfi",
                agent_version="0.1.0",
                unit_id=unit_id,
                finding_key=key,
                cwe="CWE-912",
                raw_score=0.8,
                confidence=0.85,
                explanation="Runtime SFI trapped unauthorized network egress / outbound socket connection attempt.",
                artifacts=[
                    Artifact(
                        artifact_type="network_trace",
                        content={"stderr": trace.stderr[-300:]},
                    )
                ],
            )
        )

    return evidence_list
