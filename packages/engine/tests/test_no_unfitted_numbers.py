"""The Chapter 14 acceptance criterion, asserted rather than believed.

    "No hardcoded LR, prior, or threshold remains anywhere in the codebase."

That is a claim about the whole tree, so it is checked against the whole tree. Every one of
these numbers existed as a module constant before this chapter, each with a comment saying it
was provisional, and the comment is exactly what made them survivable: a value that announces
its own dishonesty still gets multiplied into a posterior. The check is structural — the
source is parsed, not grepped — because a constant renamed to `DEFAULT_PRIOR` would pass a
grep for "PROVISIONAL" while being the identical mistake.

What remains legitimately hardcoded is stated explicitly below, with the reason each is not a
fitted quantity. Anything else fails.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from codesheriff_engine.fusion import bayes, ratios

REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOTS = (REPO_ROOT / "packages", REPO_ROOT / "apps")

BANNED_NAMES = frozenset(
    {
        "PROVISIONAL_RATIOS",
        "PROVISIONAL_PRIOR",
        "PROVISIONAL_ALERT_THRESHOLD",
        "FALLBACK_RATIOS",
        "DEFAULT_PRIOR",
        "DEFAULT_ALERT_THRESHOLD",
        "DEFAULT_RATIOS",
        "LIKELIHOOD_TABLE",
    }
)
"""Every name a fitted quantity has worn, or would plausibly wear next.

`DEFAULT_*` is in the list because renaming is the cheapest possible way to satisfy this
chapter without doing it: the objection to `PROVISIONAL_PRIOR` was never the word
"provisional".
"""

ALLOWED_CONSTANTS = {
    "LR_MIN": "a bound on what one witness may claim; policy, and the fit records when it bit",
    "LR_MAX": "as above",
    "SILENCE_CEILING": "the type's own constraint, applied to a fitted value that exceeded it",
    "LAPLACE_ALPHA": "the smoothing constant, recorded in the artifact beside every count",
    "ABSTENTION_LR": "exactly 1.0 by definition (D-005); a fitted value here would be wrong",
    "MIN_THRESHOLD": "a floor on the sweep, not a selection",
    "DEFAULT_BASE_RATE": "the declared base rate, recorded as declared and overridable per fit",
    "DEFAULT_BINS": "how many reliability bins to draw",
}
"""Numbers that are not measurements of the corpus, each with why."""


def _source_files() -> list[Path]:
    files: list[Path] = []
    for root in SOURCE_ROOTS:
        for path in root.rglob("*.py"):
            parts = set(path.parts)
            if parts & {"tests", "cases", ".venv", "__pycache__", "tools"}:
                continue
            files.append(path)
    return files


def test_no_module_defines_a_prior_threshold_or_ratio_table() -> None:
    """No assignment anywhere in the source tree names a fitted quantity."""
    offences: list[str] = []
    for path in _source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
                if isinstance(node, ast.AnnAssign)
                else []
            )
            for target in targets:
                if isinstance(target, ast.Name) and target.id in BANNED_NAMES:
                    offences.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno} {target.id}")

    assert not offences, (
        "these are fitted quantities and belong in calibration.json, which records the corpus "
        f"hash they were measured against: {offences}"
    )


def test_the_ratios_module_holds_no_numbers_beyond_its_bounds() -> None:
    """`fusion/ratios.py` is where the four hand-set tables lived. It now holds a type.

    Its remaining floats are the clamp bounds, which are policy about what any single witness
    may claim rather than a measurement of what one did.
    """
    numeric = {
        name: value
        for name, value in vars(ratios).items()
        if isinstance(value, (int, float)) and not name.startswith("_")
    }
    unexplained = sorted(set(numeric) - set(ALLOWED_CONSTANTS))
    assert not unexplained, f"unexplained numeric constants in fusion.ratios: {unexplained}"


def test_fusion_takes_its_numbers_from_the_artifact_not_from_a_default() -> None:
    """The public entry points default to `None` and resolve the artifact per call.

    A parameter default holding a float would be a hardcoded prior with extra steps, and one
    evaluated at import time would additionally freeze whichever artifact was on disk when the
    module was first imported.
    """
    for function in (bayes.compute_bayesian_fusion, bayes.fuse_all_evidence):
        signature = inspect.signature(function)
        for name in ("prior_p", "alert_threshold", "ratios"):
            assert signature.parameters[name].default is None, (
                f"{function.__name__}({name}=...) carries a hardcoded default"
            )


def test_a_partial_ratio_table_raises_rather_than_filling_itself_in() -> None:
    """There is no fallback row (D-082). A witness with no ratios cannot be fused."""
    with pytest.raises(KeyError, match="no likelihood ratios for witness"):
        bayes.posterior_from_cells(
            {"structural": bayes.RatioCell.DETECTION_HIGH},
            {},
            0.03,
        )
