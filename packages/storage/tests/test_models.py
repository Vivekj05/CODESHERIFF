"""Schema-level guards that need no database.

These assert the properties that would otherwise only be caught by a reviewer reading the models:
that the DB enum still mirrors the contract, that the closed CWE set is the contract's set, and —
the one that matters most — that no table anywhere can hold source code.
"""

from __future__ import annotations

import pytest

from codesheriff_contracts import IN_SCOPE_CWES, EvidenceKind
from codesheriff_storage.models import (
    EMBEDDING_DIM,
    Base,
    EvidenceKindDB,
    EvidenceRow,
    Finding,
    PrecedentChunk,
)

FORBIDDEN_COLUMN_NAMES = {
    "post_src",
    "pre_src",
    "source",
    "src",
    "file_contents",
    "body",
    "patch",
    "diff",
}


def test_evidence_kind_db_mirrors_the_contract() -> None:
    """The Postgres enum and the contract enum must name the same three states.

    They are separate types on purpose — a Postgres enum is schema, and the contract must not be
    able to require a migration nobody wrote. This test is the price of that separation.
    """
    assert {member.value for member in EvidenceKindDB} == {member.value for member in EvidenceKind}


def test_no_table_can_store_source_code() -> None:
    """§6: persisted records hold findings, evidence and hashes — never full file contents.

    Checked against the metadata rather than by review, because the failure mode is a well-meaning
    column added in a later chapter to 'make the findings page easier'.
    """
    offenders = [
        f"{table.name}.{column.name}"
        for table in Base.metadata.sorted_tables
        for column in table.columns
        if column.name in FORBIDDEN_COLUMN_NAMES
    ]
    assert offenders == [], (
        f"columns that would persist source code: {offenders}. Store a sha256 and line metadata "
        f"instead, or a bounded excerpt via redaction.py if it must be shown to a human."
    )


def test_change_unit_stores_a_hash_and_not_the_unit() -> None:
    columns = {column.name for column in Base.metadata.tables["change_units"].columns}
    assert "post_src_sha256" in columns
    assert "post_src" not in columns


@pytest.mark.parametrize(
    ("table", "constraint"),
    [
        ("evidence", "ck_evidence_finding_key_format"),
        ("findings", "ck_findings_finding_key_format"),
    ],
)
def test_finding_key_format_is_constrained(table: str, constraint: str) -> None:
    """Sixteen hex characters or nothing — the wall against hand-rolled keys (AUDIT.md 1.1)."""
    names = {c.name for c in Base.metadata.tables[table].constraints}
    assert constraint in names


def test_evidence_constraints_cover_all_three_kinds() -> None:
    names = {c.name for c in EvidenceRow.__table__.constraints}
    for expected in (
        "ck_evidence_detection_shape",
        "ck_evidence_non_detection_has_no_key",
        "ck_evidence_silence_has_covered_cwes",
        "ck_evidence_abstention_has_reason",
        "ck_evidence_reason_is_abstention_only",
    ):
        assert expected in names, f"missing {expected}"


def test_cwe_constraints_are_generated_from_the_contract() -> None:
    """The SQL literal list must be the contract's closed set, not a copy that has drifted."""
    constraint = next(
        c
        for c in Finding.__table__.constraints
        if getattr(c, "name", None) == "ck_findings_cwe_in_scope"
    )
    sql = str(constraint.sqltext)  # type: ignore[attr-defined]
    for cwe in IN_SCOPE_CWES:
        assert f"'{cwe}'" in sql
    assert sql.count("CWE-") == len(IN_SCOPE_CWES)


def test_embedding_column_is_384_dim() -> None:
    """bge-small-en-v1.5. The dimension is schema, so a model swap is a migration (D-016)."""
    assert EMBEDDING_DIM == 384
    assert PrecedentChunk.__table__.columns["embedding"].type.dim == 384  # type: ignore[attr-defined]


def test_alert_flag_cannot_disagree_with_the_stored_threshold() -> None:
    """A finding whose `is_alert_worthy` contradicts its own threshold is unfalsifiable."""
    names = {c.name for c in Finding.__table__.constraints}
    assert "ck_findings_alert_matches_threshold" in names
