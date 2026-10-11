"""Contract objects to rows, without a database.

The two behaviours worth locking down here are refusals: source must not survive the trip into a
row, and a fusion result whose key no agent could have produced must not become a finding.
"""

from __future__ import annotations

import uuid

import pytest

from codesheriff_contracts import Artifact, ChangeUnit, Evidence
from codesheriff_engine.fusion.bayes import FusionResult, Stance, WitnessContribution
from codesheriff_engine.fusion.cells import RatioCell
from codesheriff_storage.mapping import (
    is_wellformed_finding_key,
    persistable_findings,
    sha256_text,
    to_change_unit_row,
    to_evidence_row,
    to_finding,
)
from codesheriff_storage.redaction import MAX_EXCERPT_LINE_CHARS, TRUNCATION_MARKER

SECRET_SOURCE = "def login(u):\n    return db.execute(f'select * from users where u={u}')\n"


def make_unit(**overrides: object) -> ChangeUnit:
    defaults: dict[str, object] = {
        "unit_id": "u1",
        "repo": "acme/app",
        "language": "python",
        "file": "app/auth.py",
        "symbol": "login",
        "enclosing_class": "AuthService",
        "post_src": SECRET_SOURCE,
        "pre_src": "def login(u):\n    return db.execute('select 1')\n",
        "changed_lines": [12, 13],
        "start_line": 10,
        "decorators": ["require_login"],
        "base_sha": "a" * 40,
        "head_sha": "b" * 40,
    }
    defaults.update(overrides)
    return ChangeUnit(**defaults)  # type: ignore[arg-type]


def test_change_unit_row_carries_hashes_not_source() -> None:
    row = to_change_unit_row(uuid.uuid4(), make_unit())

    assert row.post_src_sha256 == sha256_text(SECRET_SOURCE)
    assert row.pre_src_sha256 is not None
    assert row.post_src_bytes == len(SECRET_SOURCE.encode("utf-8"))
    assert row.post_src_lines == 2

    # No attribute on the row holds the source, under any name.
    values = [v for v in vars(row).values() if isinstance(v, str)]
    assert all("select * from users" not in v for v in values)


def test_change_unit_row_keeps_the_qualified_symbol_the_unit_reported() -> None:
    """Never reassembled from `symbol` + `enclosing_class` — that is the D-004 divergence again."""
    unit = make_unit()
    row = to_change_unit_row(uuid.uuid4(), unit)
    assert row.qualified_symbol == unit.qualified_symbol == "AuthService.login"


def test_added_function_has_no_pre_hash() -> None:
    row = to_change_unit_row(uuid.uuid4(), make_unit(pre_src=None))
    assert row.pre_src_sha256 is None


def test_detection_evidence_maps_with_its_key() -> None:
    unit = make_unit()
    evidence = Evidence.detection(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id=unit.unit_id,
        finding_key=unit.key_for("CWE-89"),
        cwe="CWE-89",
        raw_score=0.9,
    )
    row = to_evidence_row(uuid.uuid4(), evidence)

    assert row.kind.value == "detection"
    assert row.finding_key == unit.key_for("CWE-89")
    assert row.covered_cwes == []


def test_silence_evidence_maps_its_covered_cwes_sorted() -> None:
    evidence = Evidence.silence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id="u1",
        covered_cwes={"CWE-89", "CWE-22", "CWE-78"},
    )
    row = to_evidence_row(uuid.uuid4(), evidence)

    assert row.kind.value == "silence"
    assert row.covered_cwes == ["CWE-22", "CWE-78", "CWE-89"]
    assert row.finding_key is None


def test_abstention_evidence_keeps_its_reason() -> None:
    evidence = Evidence.abstention(
        agent_id="semantic.hosted",
        agent_version="0.1.0",
        unit_id="u1",
        reason="unit_too_large",
    )
    row = to_evidence_row(uuid.uuid4(), evidence)

    assert row.kind.value == "abstention"
    assert row.reason == "unit_too_large"
    assert row.finding_key is None


def test_artifacts_are_clipped_to_the_excerpt_budget() -> None:
    """A taint path is an explanation containing code. Bounded excerpts only (D-027)."""
    evidence = Evidence.detection(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id="u1",
        finding_key="0" * 16,
        cwe="CWE-89",
        raw_score=0.9,
        artifacts=[
            Artifact(
                artifact_type="taint_path",
                content={"steps": [{"line": 12, "code": "x" * 5000}]},
            )
        ],
    )
    row = to_evidence_row(uuid.uuid4(), evidence)

    code = row.artifacts[0]["content"]["steps"][0]["code"]
    assert len(code) <= MAX_EXCERPT_LINE_CHARS + len(TRUNCATION_MARKER)
    assert code.endswith(TRUNCATION_MARKER)


@pytest.mark.parametrize(
    ("key", "wellformed"),
    [
        ("0123456789abcdef", True),
        ("abstention:all_agents", False),
        ("abstain:u1:unit_too_large", False),
        ("0123456789ABCDEF", False),
        ("0123456789abcde", False),
        (None, False),
        ("", False),
    ],
)
def test_finding_key_wellformedness(key: str | None, wellformed: bool) -> None:
    assert is_wellformed_finding_key(key) is wellformed


def test_the_all_agents_abstention_marker_is_never_a_finding() -> None:
    """`fuse_all_evidence` emits this marker when nothing detected. It is not a finding.

    Persisting it would put a row in `findings` keyed by a string no agent produced — AUDIT.md 1.1
    one layer up, in `FusionResult`, where the Evidence validator cannot see it.
    """
    marker = FusionResult(
        finding_key="abstention:all_agents",
        posterior_probability=0.05,
        is_alert_worthy=False,
        evidence_list=[],
    )
    real = FusionResult(
        finding_key="0123456789abcdef",
        posterior_probability=0.91,
        is_alert_worthy=True,
        evidence_list=[],
        cwe="CWE-89",
        severity="critical",
    )

    kept = persistable_findings([marker, real])

    assert [r.finding_key for r in kept] == ["0123456789abcdef"]
    with pytest.raises(ValueError, match=r"not a contracts\.finding_key"):
        to_finding(uuid.uuid4(), marker, prior_probability=0.05, alert_threshold=0.7)


def test_finding_without_a_cwe_is_dropped() -> None:
    keyed_but_cweless = FusionResult(
        finding_key="0123456789abcdef",
        posterior_probability=0.8,
        is_alert_worthy=True,
        evidence_list=[],
    )
    assert persistable_findings([keyed_but_cweless]) == []


def test_finding_records_the_threshold_it_was_judged_against() -> None:
    """A threshold chosen later must not retroactively rewrite which findings were alerts (§6)."""
    result = FusionResult(
        finding_key="0123456789abcdef",
        posterior_probability=0.72,
        is_alert_worthy=True,
        evidence_list=[],
        cwe="cwe-89",
        severity="high",
    )
    row = to_finding(uuid.uuid4(), result, prior_probability=0.05, alert_threshold=0.70)

    assert row.alert_threshold == 0.70
    assert row.prior_probability == 0.05
    assert row.is_alert_worthy is True
    assert row.cwe == "CWE-89"


def test_alert_flag_is_recomputed_from_the_threshold_not_trusted() -> None:
    """`FusionResult.is_alert_worthy` is an input, not an authority — the DB constrains this too."""
    lying = FusionResult(
        finding_key="0123456789abcdef",
        posterior_probability=0.30,
        is_alert_worthy=True,
        evidence_list=[],
        cwe="CWE-89",
    )
    row = to_finding(uuid.uuid4(), lying, prior_probability=0.05, alert_threshold=0.70)
    assert row.is_alert_worthy is False


def test_finding_records_the_factors_the_run_multiplied() -> None:
    """The breakdown is stored, not recomputed later (Chapter 16).

    Same argument as the threshold above. A posterior explained with today's ratios rather than
    the ones the run used would contradict the number stored beside it.
    """
    result = FusionResult(
        finding_key="0123456789abcdef",
        posterior_probability=0.72,
        is_alert_worthy=True,
        evidence_list=[],
        cwe="CWE-89",
        contributions=[
            WitnessContribution(
                witness="structural",
                stance=Stance.DETECTED,
                cell=RatioCell.DETECTION_MEDIUM,
                likelihood_ratio=6.5,
                agent_ids=["structural.taint"],
            ),
            WitnessContribution(
                witness="runtime",
                stance=Stance.NEUTRAL,
                cell=None,
                likelihood_ratio=1.0,
                note="abstained: interpreter_unavailable",
            ),
        ],
    )
    row = to_finding(uuid.uuid4(), result, prior_probability=0.03, alert_threshold=0.70)

    assert row.contributions is not None
    assert [item["witness"] for item in row.contributions] == ["structural", "runtime"]
    assert row.contributions[0]["cell"] == "detection_medium"
    assert row.contributions[0]["likelihood_ratio"] == 6.5
    # JSON, not a Pydantic object: the column is JSONB and psycopg has to be able to adapt it.
    assert row.contributions[1]["cell"] is None
    assert row.contributions[1]["stance"] == "neutral"


def test_a_result_with_no_breakdown_is_null_rather_than_empty() -> None:
    """NULL means "not recorded"; an empty list would mean "no witness contributed".

    Only the first is true of a run that predates the column, and the two must not be the same
    value in the database — it is the silence-versus-abstention distinction one layer up (D-005).
    """
    result = FusionResult(
        finding_key="0123456789abcdef",
        posterior_probability=0.30,
        is_alert_worthy=False,
        evidence_list=[],
        cwe="CWE-89",
    )
    row = to_finding(uuid.uuid4(), result, prior_probability=0.03, alert_threshold=0.70)

    assert row.contributions is None
