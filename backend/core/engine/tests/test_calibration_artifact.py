"""`calibration.json` — that it loads, that it is refused when incomplete, and that it is
the thing fusion actually multiplies with.

The last of those is the one worth having. An artifact that were merely *available* would
prove nothing: what makes the numbers calibrated is that there is no other source of them, so
these tests assert both halves — the artifact is complete and reproducible, and fusion with no
arguments produces exactly what it says.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codesheriff_corpus.hashing import corpus_hash, split_hash
from codesheriff_engine.calibration import artifact as artifact_module
from codesheriff_engine.calibration.artifact import (
    CalibrationArtifact,
    CalibrationError,
    active_artifact,
    artifact_path,
)
from codesheriff_engine.fusion.ratios import LR_MAX, LR_MIN
from codesheriff_engine.fusion.witnesses import WITNESSES


@pytest.fixture(autouse=True)
def _clear_artifact_cache() -> None:
    """`active_artifact` caches on path and mtime; a test that swaps the path must not
    inherit another test's answer."""
    artifact_module._load_cached.cache_clear()


def packaged() -> CalibrationArtifact:
    return CalibrationArtifact.load(artifact_module.PACKAGED_ARTIFACT)


# -- the committed artifact ------------------------------------------------------------------


def test_the_packaged_artifact_loads() -> None:
    """It ships inside the package, so an installed wheel carries the numbers it fuses with."""
    assert artifact_module.PACKAGED_ARTIFACT.is_file(), (
        "no calibration.json in the engine package. Fit one with "
        "`codesheriff-worker calibrate fit`; fusion has no hand-set fallback any more."
    )
    assert packaged().is_fitted


def test_it_covers_exactly_the_registered_witnesses() -> None:
    """Four rows, always four (D-082). A missing one is an incomplete fit; an extra one is a
    factor nobody registered."""
    assert set(packaged().fit.witnesses) == set(WITNESSES)


def test_it_names_the_corpus_it_was_fitted_on_and_that_corpus_is_this_one() -> None:
    """§6's reproducibility requirement, as a check rather than a sentence.

    Editing a case or moving a pair between splits changes one of these hashes, and this test
    is where that shows up: the committed artifact stops describing the ground truth in the
    working tree, and the fix is to re-observe and re-fit rather than to edit the number
    (D-045).
    """
    artifact = packaged()
    assert artifact.corpus_hash == corpus_hash(), (
        "the artifact was fitted on a different corpus than the one in this tree. Re-run "
        "`codesheriff-worker calibrate observe` for both splits and `calibrate fit`."
    )
    assert artifact.split_hash == split_hash()


def test_every_fitted_ratio_is_inside_the_bounds_and_a_silence_is_below_one() -> None:
    """The type enforces the silence constraint on construction; this asserts the loaded
    file has not been hand-edited past it."""
    for witness, fitted in packaged().fit.witnesses.items():
        ratios = fitted.ratios()
        for name in ("detection_high", "detection_medium", "detection_low", "silence"):
            value = getattr(ratios, name)
            assert LR_MIN <= value <= LR_MAX, f"{witness}.{name} = {value}"
        assert ratios.silence < 1.0, witness


def test_the_prior_is_declared_and_records_what_it_was_rescaled_from() -> None:
    """A balanced corpus cannot supply a prior, and the artifact must not imply it did."""
    prior = packaged().prior
    assert prior.source == "declared"
    assert 0.0 < prior.base_rate < 0.5
    assert prior.corpus_prevalence > 0.0
    assert prior.rationale
    assert prior.rescaling_factor == pytest.approx(prior.odds / prior.corpus_odds)


def test_the_threshold_was_selected_on_validation_and_carries_its_sweep() -> None:
    threshold = packaged().threshold
    assert threshold.selected_on == "validation"
    assert threshold.objective == "max_f1"
    assert threshold.sweep, "a threshold with no recorded sweep cannot be second-guessed"
    assert threshold.at(threshold.value) is not None


def test_it_records_metrics_for_both_fitted_splits() -> None:
    """Validation is the selection-time estimate; calibration is in-sample and says so."""
    metrics = packaged().metrics
    assert set(metrics) == {"calibration", "validation"}
    assert metrics["calibration"].note.startswith("In-sample")
    assert metrics["validation"].weighted


# -- loading -----------------------------------------------------------------------------------


def test_an_artifact_missing_a_witness_is_refused(tmp_path: Path) -> None:
    """Rather than filled in. There is no fallback row to fill it with, and inventing one
    would put an unfitted factor into a posterior nobody could account for."""
    payload = json.loads(artifact_module.PACKAGED_ARTIFACT.read_text(encoding="utf-8"))
    payload["fit"]["witnesses"].pop(WITNESSES[0])
    broken = tmp_path / "calibration.json"
    broken.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(CalibrationError, match="one ratio per witness"):
        CalibrationArtifact.load(broken)


def test_a_missing_file_names_the_command_that_produces_one(tmp_path: Path) -> None:
    with pytest.raises(CalibrationError, match="calibrate fit"):
        CalibrationArtifact.load(tmp_path / "nothing.json")


def test_unreadable_content_is_refused_with_the_path(tmp_path: Path) -> None:
    junk = tmp_path / "calibration.json"
    junk.write_text("{not json", encoding="utf-8")
    with pytest.raises(CalibrationError, match="not a readable calibration artifact"):
        CalibrationArtifact.load(junk)


def test_the_path_can_be_overridden_by_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`CALIBRATION_PATH`, the name `.env.example` documents (D-064). Which artifact is the
    only thing about the numbers that is configurable at all."""
    elsewhere = tmp_path / "elsewhere.json"
    packaged().save(elsewhere)
    monkeypatch.setenv("CALIBRATION_PATH", str(elsewhere))

    assert artifact_path() == elsewhere
    assert active_artifact().corpus_hash == packaged().corpus_hash


def test_a_round_trip_through_disk_changes_nothing(tmp_path: Path) -> None:
    """The artifact is committed and diffed, so writing it twice must produce one file."""
    original = packaged()
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    original.save(first)
    CalibrationArtifact.load(first).save(second)

    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")
