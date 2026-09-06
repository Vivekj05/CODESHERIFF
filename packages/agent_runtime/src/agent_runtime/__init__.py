"""Runtime agent (`runtime.sfi`). Not yet built - PLAN.md Chapter 13.

Built as isolation infrastructure FIRST, detection agent second. The sandbox
earns its place because running untrusted PR code is how CI systems get
compromised; evidence is a secondary benefit. This also makes the SFI claim in
the title honest immediately, rather than conditional on the agent detecting well.

Deny-by-default: no network, ephemeral read-only filesystem, CPU/memory/wall-clock
caps, and never on a host holding database credentials. Abstains widely
(no_safe_entrypoint, dependency_unavailable) - expected, not a defect.

Wasmtime, not Docker: containers are OS-level isolation, not software fault
isolation, and the SFI claim requires the latter.
"""
