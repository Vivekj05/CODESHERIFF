# CodeSheriff Runtime Agent (`runtime.sfi`)

The **Runtime Agent** executes Pull Request code payloads (`ChangeUnit`) inside an isolated **Software Fault Isolation (SFI)** sandbox environment to monitor real-time execution behavior — detecting unhandled crashes, unauthorized file system access, network egress attempts, and abnormal resource usage.

## Features

- **Software Fault Isolation (SFI):** Executes code in an isolated container sandbox (gVisor / process-isolated workspace).
- **Sensitive File Protection:** Flags unauthorized access attempts to `/etc/passwd`, `.env`, SSH keys, AWS credentials.
- **Network Egress Guard:** Intercepts unapproved external socket connections (telemetry leaks / backdoors).
- **Crash & Segfault Monitor:** Detects segmentation faults (exit code 139 / -11) and uncaught memory errors.
- **Resource Control:** Enforces strict execution timeout caps (15s) to prevent Denial of Service (DoS).

## Installation

```bash
cd codesheriff-runtime-agent
pip install -e .
```

## CLI Usage

```bash
# Run runtime analysis on a ChangeUnit JSON payload
python -m runtime_agent.cli run tests/fixtures/sample_unit.json

# Check agent health
python -m runtime_agent.cli health
```
