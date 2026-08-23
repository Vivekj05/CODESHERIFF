"""Tests for LLM Patch Generator."""

from patch_verifier.contracts import ChangeUnit, Evidence
from patch_verifier.patch.generator import LLMPatchGenerator


def test_generator_synthesis(sample_change_unit: ChangeUnit, sample_evidence: Evidence) -> None:
    generator = LLMPatchGenerator()
    patch_diff = generator.generate_patch(sample_change_unit, sample_evidence)

    assert "--- a/app/api/users.py" in patch_diff
    assert "+++ b/app/api/users.py" in patch_diff
    assert "SELECT * FROM users WHERE id = %s" in patch_diff
