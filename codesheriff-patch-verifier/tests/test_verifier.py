"""Tests for Simplified Verifier Engine."""

from patch_verifier.contracts import ChangeUnit
from patch_verifier.verifier.engine import SimplifiedVerifier


def test_verifier_pass(sample_change_unit: ChangeUnit) -> None:
    verifier = SimplifiedVerifier()
    mock_diff = (
        "--- a/app/api/users.py\n"
        "+++ b/app/api/users.py\n"
        "@@ -1,3 +1,3 @@\n"
        "-    q = f\"SELECT * FROM users WHERE id = {uid}\"\n"
        "+    q = \"SELECT * FROM users WHERE id = %s\"\n"
    )
    result = verifier.verify_patch(sample_change_unit, mock_diff)

    assert result.verified is True
    assert "Verification successful" in result.explanation


def test_verifier_fail_remaining_vulnerability(sample_change_unit: ChangeUnit) -> None:
    verifier = SimplifiedVerifier()
    bad_diff = (
        "--- a/app/api/users.py\n"
        "+++ b/app/api/users.py\n"
        "@@ -1,3 +1,3 @@\n"
        "+    q = f\"SELECT * FROM users WHERE id = {uid}\"\n"
    )
    # Post_src still contains vulnerable pattern
    result = verifier.verify_patch(sample_change_unit, bad_diff)

    assert result.verified is False
    assert "un-sanitized pattern" in result.explanation
