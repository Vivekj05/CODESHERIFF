"""Runtime Agent Configuration Module."""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class RuntimeConfig(BaseSettings):
    """Configuration settings for Runtime SFI Agent."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    sfi_mode: str = "process_isolated"  # 'docker_gvisor' or 'process_isolated'
    sfi_timeout_seconds: int = 15
    sfi_memory_limit_mb: int = 256
    sensitive_file_patterns: List[str] = [
        "/etc/passwd",
        "/etc/shadow",
        ".env",
        "id_rsa",
        "AWS_SECRET_ACCESS_KEY",
        "credentials",
    ]
