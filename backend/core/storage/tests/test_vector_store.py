"""pgvector round-trip, similarity search, and the CHECK constraints — against a real database.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

The constraint tests insert through raw SQL on purpose. Going through the ORM would prove that
Pydantic works, which is already tested in `packages/contracts`. What matters here is that the
database refuses a malformed row when nothing validated it first (D-026).
"""

from __future__ import annotations

import math
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session

from codesheriff_storage.models import (
    EMBEDDING_DIM,
    Audit,
    AuditStatus,
    ChangeUnitRow,
    Installation,
    PrecedentChunk,
    PRPrecedent,
    Repository,
)
from codesheriff_storage.precedents import build_chunk, search_precedents

pytestmark = pytest.mark.db

VALID_KEY = "0123456789abcdef"


def unit_vector(seed: int) -> list[float]:
    """A deterministic normalised 384-dim vector — the shape bge-small-en-v1.5 produces."""
    raw = [math.sin(seed * (i + 1) * 0.001) for i in range(EMBEDDING_DIM)]
    norm = math.sqrt(sum(v * v for v in raw))
    return [v / norm for v in raw]


def vector_at(cosine: float) -> list[float]:
    """A normalised vector whose cosine similarity to `vector_at(1.0)` is `cosine`.

    Built on two axes rather than from `sin()` so the expected ordering is arithmetic rather than
    whatever the trig happened to produce — a similarity test that cannot state its own expected
    values is not testing ordering.
    """
    axis = [0.0] * EMBEDDING_DIM
    axis[0] = cosine
    axis[1] = math.sqrt(max(0.0, 1.0 - cosine * cosine))
    return axis


@pytest.fixture
def repository(session: Session) -> Repository:
    installation = Installation(id=9001, account_login="acme", account_type="Organization")
    repo = Repository(id=5001, installation_id=9001, full_name="acme/app")
    session.add(installation)
    session.flush()
    session.add(repo)
    session.flush()
    return repo


@pytest.fixture
def audit(session: Session, repository: Repository) -> Audit:
    row = Audit(
        repository_id=repository.id,
        pr_number=7,
        base_sha="a" * 40,
        head_sha="b" * 40,
        status=AuditStatus.RUNNING,
        contract_version="2.0.0",
        prior_probability=0.05,
        alert_threshold=0.70,
    )
    session.add(row)
    session.flush()
    return row


def test_384_dim_vector_round_trips(session: Session, repository: Repository) -> None:
    """The Chapter 3 acceptance criterion: a 384-dim column stores and returns the same vector."""
    precedent = PRPrecedent(repository_id=repository.id, pr_number=41, head_sha="c" * 40)
    session.add(precedent)
    session.flush()

    embedding = unit_vector(7)
    chunk = build_chunk(
        precedent_id=precedent.id,
        file="app/views.py",
        content="def search(request):\n    return render(request.GET['q'])",
        embedding=embedding,
        qualified_symbol="search",
    )
    session.add(chunk)
    session.flush()
    session.expire(chunk)

    stored = session.get(PrecedentChunk, chunk.id)
    assert stored is not None
    assert len(stored.embedding) == EMBEDDING_DIM
    for original, returned in zip(embedding, list(stored.embedding), strict=True):
        assert original == pytest.approx(returned, abs=1e-6)


def test_similarity_search_returns_the_nearest_precedent_first(
    session: Session, repository: Repository
) -> None:
    precedent = PRPrecedent(repository_id=repository.id, pr_number=42, head_sha="d" * 40)
    session.add(precedent)
    session.flush()

    for index, cosine in enumerate([0.2, 1.0, 0.7]):
        session.add(
            build_chunk(
                precedent_id=precedent.id,
                file=f"app/mod{index}.py",
                content=f"def handler_{index}(): ...",
                embedding=vector_at(cosine),
                chunk_index=index,
            )
        )
    session.flush()

    matches = search_precedents(session, repository.id, vector_at(1.0), limit=3)

    assert [m.file for m in matches] == ["app/mod1.py", "app/mod2.py", "app/mod0.py"]
    assert [round(m.similarity, 3) for m in matches] == [1.0, 0.7, 0.2]
    assert all(m.pr_number == 42 for m in matches)


def test_similarity_search_returns_the_nearest_k_with_no_floor_by_default(
    session: Session, repository: Repository
) -> None:
    """No default floor: fewer rows than `limit` must mean "no precedent", not "none close enough".

    Deciding what counts as close enough is the context agent's judgement in Chapter 12, and
    eventually a fitted number — not a default in a query helper.
    """
    precedent = PRPrecedent(repository_id=repository.id, pr_number=44, head_sha="f" * 40)
    session.add(precedent)
    session.flush()

    for index, cosine in enumerate([0.9, -0.4]):
        session.add(
            build_chunk(
                precedent_id=precedent.id,
                file=f"app/far{index}.py",
                content=f"def far_{index}(): ...",
                embedding=vector_at(cosine),
                chunk_index=index,
            )
        )
    session.flush()

    unfiltered = search_precedents(session, repository.id, vector_at(1.0), limit=5)
    filtered = search_precedents(
        session, repository.id, vector_at(1.0), limit=5, min_similarity=0.5
    )

    assert len(unfiltered) == 2
    assert [m.file for m in filtered] == ["app/far0.py"]


def test_similarity_search_is_scoped_to_one_repository(
    session: Session, repository: Repository
) -> None:
    """Precedent is *this* repository's history. Borrowing another's would be a different claim."""
    other_install = Installation(id=9002, account_login="other", account_type="User")
    other_repo = Repository(id=5002, installation_id=9002, full_name="other/app")
    session.add_all([other_install])
    session.flush()
    session.add(other_repo)
    session.flush()

    for repo_id, pr in ((repository.id, 1), (other_repo.id, 2)):
        precedent = PRPrecedent(repository_id=repo_id, pr_number=pr, head_sha=f"{pr}" * 40)
        session.add(precedent)
        session.flush()
        session.add(
            build_chunk(
                precedent_id=precedent.id,
                file="app/same.py",
                content="def same(): ...",
                embedding=unit_vector(3),
            )
        )
    session.flush()

    mine = search_precedents(session, repository.id, unit_vector(3), limit=10)
    theirs = search_precedents(session, other_repo.id, unit_vector(3), limit=10)

    assert [m.pr_number for m in mine] == [1]
    assert [m.pr_number for m in theirs] == [2]


def test_wrong_dimension_embedding_is_refused_before_it_reaches_the_column() -> None:
    with pytest.raises(ValueError, match="384"):
        build_chunk(
            precedent_id=uuid.uuid4(),
            file="app/x.py",
            content="def x(): ...",
            embedding=[0.1] * 768,
        )


def test_oversized_chunk_is_clipped_to_the_column_budget(
    session: Session, repository: Repository
) -> None:
    precedent = PRPrecedent(repository_id=repository.id, pr_number=43, head_sha="e" * 40)
    session.add(precedent)
    session.flush()

    session.add(
        build_chunk(
            precedent_id=precedent.id,
            file="app/big.py",
            content="x = 1\n" * 50_000,
            embedding=unit_vector(11),
        )
    )
    session.flush()  # the CHECK constraint would reject anything redaction let through


# ---------------------------------------------------------------------------
# Contract invariants, enforced by the database rather than by Pydantic (D-026).
# ---------------------------------------------------------------------------


@pytest.fixture
def change_unit(session: Session, audit: Audit) -> ChangeUnitRow:
    row = ChangeUnitRow(
        audit_id=audit.id,
        unit_id="u1",
        file="app/auth.py",
        qualified_symbol="AuthService.login",
        symbol="login",
        enclosing_class="AuthService",
        language="python",
        post_src_sha256="f" * 64,
    )
    session.add(row)
    session.flush()
    return row


def insert_evidence(session: Session, change_unit_id: uuid.UUID, **columns: object) -> None:
    """Raw INSERT, bypassing the ORM and the contract, to test the database's own refusals."""
    defaults: dict[str, object] = {
        "id": uuid.uuid4(),
        "change_unit_id": change_unit_id,
        "agent_id": "structural.taint",
        "agent_version": "0.1.0",
        "kind": "detection",
        "finding_key": VALID_KEY,
        "cwe": "CWE-89",
        "covered_cwes": [],
        "reason": None,
        "raw_score": 0.9,
        "confidence": 1.0,
        "explanation": "",
        "artifacts": "[]",
    }
    defaults.update(columns)
    session.execute(
        text(
            "INSERT INTO evidence (id, change_unit_id, agent_id, agent_version, kind, finding_key, "
            "cwe, covered_cwes, reason, raw_score, confidence, explanation, artifacts) VALUES "
            "(:id, :change_unit_id, :agent_id, :agent_version, :kind, :finding_key, :cwe, "
            ":covered_cwes, :reason, :raw_score, :confidence, :explanation, "
            "CAST(:artifacts AS jsonb))"
        ),
        defaults,
    )


def test_detection_without_a_cwe_is_rejected(session: Session, change_unit: ChangeUnitRow) -> None:
    with pytest.raises(IntegrityError, match="ck_evidence_detection_shape"):
        insert_evidence(session, change_unit.id, cwe=None)


def test_out_of_scope_cwe_is_rejected(session: Session, change_unit: ChangeUnitRow) -> None:
    """The closed set is closed in the database too. Widening it takes a migration (§6)."""
    with pytest.raises(IntegrityError, match="ck_evidence_cwe_in_scope"):
        insert_evidence(session, change_unit.id, cwe="CWE-200")


def test_hand_rolled_finding_key_is_rejected(session: Session, change_unit: ChangeUnitRow) -> None:
    """`abstain:{unit_id}:{reason}` was the AUDIT.md 1.1 bypass. It does not fit the column."""
    with pytest.raises((IntegrityError, DataError)):
        insert_evidence(session, change_unit.id, finding_key="abstain:u1:unit_too_large")


def test_silence_without_covered_cwes_is_rejected(
    session: Session, change_unit: ChangeUnitRow
) -> None:
    """Silence about CWEs an agent cannot detect is not evidence (D-006, D-020)."""
    with pytest.raises(IntegrityError, match="ck_evidence_silence_has_covered_cwes"):
        insert_evidence(
            session,
            change_unit.id,
            kind="silence",
            finding_key=None,
            cwe=None,
            covered_cwes=[],
        )


def test_silence_carrying_a_finding_key_is_rejected(
    session: Session, change_unit: ChangeUnitRow
) -> None:
    with pytest.raises(IntegrityError, match="ck_evidence_non_detection_has_no_key"):
        insert_evidence(
            session,
            change_unit.id,
            kind="silence",
            cwe=None,
            covered_cwes=["CWE-89"],
        )


def test_abstention_without_a_reason_is_rejected(
    session: Session, change_unit: ChangeUnitRow
) -> None:
    with pytest.raises(IntegrityError, match="ck_evidence_abstention_has_reason"):
        insert_evidence(
            session,
            change_unit.id,
            kind="abstention",
            finding_key=None,
            cwe=None,
            reason=None,
        )


def test_failed_audit_must_say_why(session: Session, repository: Repository) -> None:
    """An audit that failed silently is indistinguishable from one that found nothing."""
    session.add(
        Audit(
            repository_id=repository.id,
            pr_number=8,
            base_sha="a" * 40,
            head_sha="c" * 40,
            status=AuditStatus.FAILED,
            contract_version="2.0.0",
            prior_probability=0.05,
            alert_threshold=0.70,
        )
    )
    with pytest.raises(IntegrityError, match="ck_audits_failure_has_reason"):
        session.flush()


def test_provisional_calibration_may_omit_hashes_but_fitted_may_not(session: Session) -> None:
    """D-010: nothing hand-set is presented as calibrated; anything fitted is reproducible (§6)."""
    with pytest.raises(IntegrityError, match="ck_calibration_fitted_is_reproducible"):
        session.execute(
            text(
                "INSERT INTO calibration_runs (id, contract_version, is_provisional, "
                "fitted_likelihoods, prior_probability, alert_threshold, notes) VALUES "
                "(:id, '2.0.0', false, CAST('{}' AS jsonb), 0.05, 0.7, '')"
            ),
            {"id": uuid.uuid4()},
        )
