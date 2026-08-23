"""SFI Sandbox Execution Manager."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from runtime_agent.config import RuntimeConfig


class SFISandboxResult:
    """Captured result of SFI execution."""

    def __init__(
        self,
        exit_code: int,
        stdout: str,
        stderr: str,
        timed_out: bool = False,
    ):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


class SFISandbox:
    """Manages Software Fault Isolation execution of payload code."""

    def __init__(self, config: RuntimeConfig):
        self.config = config

    def execute_code(self, code_str: str, language: str) -> SFISandboxResult:
        """Executes code payload inside an isolated workspace."""
        with tempfile.TemporaryDirectory(prefix="codesheriff_sfi_") as tmpdir:
            tmppath = Path(tmpdir)
            
            if language.lower() in ("python", "py"):
                file_path = tmppath / "payload.py"
                file_path.write_text(code_str, encoding="utf-8")
                cmd = [sys.executable, str(file_path)]
            elif language.lower() in ("javascript", "js", "typescript", "ts"):
                file_path = tmppath / "payload.js"
                file_path.write_text(code_str, encoding="utf-8")
                cmd = ["node", str(file_path)]
            else:
                return SFISandboxResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"Unsupported language for SFI sandbox: {language}",
                )

            try:
                env = os.environ.copy()
                env["PYTHONPATH"] = str(tmppath)
                
                proc = subprocess.run(
                    cmd,
                    cwd=str(tmppath),
                    capture_output=True,
                    text=True,
                    timeout=self.config.sfi_timeout_seconds,
                    env=env,
                )
                return SFISandboxResult(
                    exit_code=proc.returncode,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    timed_out=False,
                )
            except subprocess.TimeoutExpired as e:
                stdout_str = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
                stderr_str = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
                return SFISandboxResult(
                    exit_code=-1,
                    stdout=stdout_str,
                    stderr=f"{stderr_str}\nExecution timed out after {self.config.sfi_timeout_seconds}s",
                    timed_out=True,
                )
            except Exception as e:
                return SFISandboxResult(
                    exit_code=-1,
                    stdout="",
                    stderr=str(e),
                )
