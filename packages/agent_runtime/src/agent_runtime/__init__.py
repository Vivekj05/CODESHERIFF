"""Runtime agent (`runtime.sfi`) - Wasmtime + WASI software fault isolation.

Built as **isolation infrastructure first, detection agent second**. The sandbox earns its
place because running untrusted pull request code is how continuous integration systems get
compromised; the evidence it produces is a secondary benefit. That ordering also makes the
software-fault-isolation claim in this project's title honest immediately, rather than
conditional on the agent detecting well.

Deny-by-default: no network, no filesystem, no inherited environment, and deterministic
fuel, wall-clock and memory caps. Wasmtime rather than Docker, because a container is
OS-level isolation and the SFI claim requires the other kind (`PROJECT_CONTEXT.md` §5).

Abstains widely - `no_safe_entrypoint`, `interpreter_unavailable`, `guard_unresolved`,
`unit_raised`. Expected, not a defect: an abstention contributes a likelihood ratio of
exactly 1.0, so a witness that could not look costs the posterior nothing.
"""

from agent_runtime.agent import RuntimeAgent
from agent_runtime.config import AGENT_ID, AGENT_VERSION, COVERED_CWES, RuntimeConfig

__all__ = ["AGENT_ID", "AGENT_VERSION", "COVERED_CWES", "RuntimeAgent", "RuntimeConfig"]
