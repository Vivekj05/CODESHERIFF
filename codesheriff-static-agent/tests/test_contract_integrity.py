"""Contract integrity test verifying vendored contracts.py SHA-256."""

import hashlib
from pathlib import Path

EXPECTED_SHA256 = "7176be9e1d36850bd6a2f4d79332d40a5fdc7812a81faa8313ebe3bfe6a19846"


def test_vendored_contract_is_unmodified() -> None:
    p = Path(__file__).parent.parent / "src" / "static_agent" / "contracts.py"
    assert p.exists(), f"contracts.py file not found at {p}"
    actual = hashlib.sha256(p.read_bytes()).hexdigest().lower()
    assert actual == EXPECTED_SHA256, (
        "contracts.py was edited locally. Contract changes must be made to the canonical "
        "copy and re-vendored into ALL agent repos together. Do NOT update this hash "
        "to make the test pass."
    )
