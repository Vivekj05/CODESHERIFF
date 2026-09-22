"""Audit history and audit detail — the dashboard's read side.

This is the first route family that serves analysis results, and the shapes it returns are the
answer to §7 open question 2 (D-089). Three properties hold across all of them.

**No number is invented here.** Every posterior, prior and threshold is read from the row that
recorded it at run time, never recomputed from today's artifact. An audit that ran under an
earlier calibration must keep reporting what it ran under, or the record stops being auditable
(§6). That is also why `alert_threshold` is per finding rather than per response.

**Silence and abstention survive the serialisation.** A unit reports one statement per witness
with its kind, and an abstention carries the reason it gave. Collapsing the three kinds into
"found something / found nothing" here would make the posterior unexplainable one layer up, which
is the failure PLAN.md Chapter 16 exists to prevent and this endpoint would have made
unavoidable.

**Scope is the storage layer's, not this module's.** Every query takes the session's installation
snapshot and returns nothing for an empty one (D-035). A route here cannot widen it, because it
has no query of its own to widen.
"""

from __future__ import annotations

import base64
import binascii
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from codesheriff_api.deps import DbDep, SessionDep
from codesheriff_engine.fusion.witnesses import WITNESSES, witness_for
from codesheriff_storage import (
    AuditSummary,
    CalibrationRun,
    ChangeUnitRow,
    EvidenceRow,
    Finding,
    FindingDetail,
    audit_detail,
    finding_detail,
    list_audit_summaries,
)

router = APIRouter(prefix="/audits", tags=["audits"])

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 25


class CursorError(ValueError):
    """The cursor did not come from this API, or was edited on the way back."""


def encode_cursor(created_at: datetime, audit_id: uuid.UUID) -> str:
    """`(created_at, id)` as one opaque token.

    Opaque, and not because the values are secret — they are both on the page. It is so that the
    client cannot construct one. A cursor a caller can build is a filter a caller can widen, and
    the next reader of this file would have to notice that `before` reaches a WHERE clause.
    """
    raw = f"{created_at.isoformat()}|{audit_id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    """Reverse of `encode_cursor`. Raises `CursorError` on anything else.

    A malformed cursor is a 400, never a silently ignored one: paging from the top after a bad
    cursor would repeat rows the caller has already scrolled past, which reads as duplicated
    audits rather than as an error.
    """
    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        stamp, _, ident = raw.partition("|")
        return datetime.fromisoformat(stamp), uuid.UUID(ident)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise CursorError(str(exc)) from exc


class CalibrationOut(BaseModel):
    """The calibration artifact one audit ran under, as the row recorded it.

    `is_provisional` is the field the UI may not ignore (D-010). Chapter 14 deleted the
    provisional constants, so every row written since is fitted — but a database that predates
    that still holds provisional rows, and an audit that ran under one must keep saying so.
    """

    id: str
    is_provisional: bool
    corpus_hash: str | None
    split_hash: str | None
    ece: float | None
    brier: float | None
    n_cases: int | None


class AuditSummaryOut(BaseModel):
    id: str
    repository_id: int
    repository_full_name: str
    pr_number: int
    head_sha: str
    status: str
    created_at: datetime
    duration_seconds: float | None
    error_reason: str | None
    prior_probability: float
    alert_threshold: float
    units: int
    findings: int
    alerts: int
    top_posterior: float | None


class AuditPage(BaseModel):
    items: list[AuditSummaryOut]
    next_cursor: str | None


class EvidenceOut(BaseModel):
    """One agent's statement about one unit.

    `covered_cwes` and `reason` are both present and both usually empty, because which one is
    populated *is* the difference between the two non-detections: a silence names what the agent
    was capable of finding, an abstention names why it could not look (§5).
    """

    agent_id: str
    agent_version: str
    kind: str
    finding_key: str | None
    cwe: str | None
    covered_cwes: list[str]
    reason: str | None
    raw_score: float
    confidence: float
    explanation: str


class EvidenceDetailOut(EvidenceOut):
    """A statement with its artifacts — the finding page's version of `EvidenceOut`.

    Artifacts are the witness showing its work: a taint path, a sink location, the merged
    precedent behind a claim, what the sandbox observed. They are omitted from the audit page,
    where one response carries every statement of every unit, and included here, where the
    response is about one function.

    The content is whatever the agent produced, already clipped to the excerpt budget by
    `codesheriff_storage.redaction` at write time. It reaches the browser as data and is rendered
    as text — a taint path quotes expressions from the pull request, which is attacker-authored,
    and the dashboard is the layer that escapes rather than the layer that trusts (D-050).
    """

    artifacts: list[dict[str, Any]]


class ChangeUnitOut(BaseModel):
    """One analysed function. Hashes and metadata, never source (§6, D-027)."""

    unit_id: str
    file: str
    qualified_symbol: str
    language: str
    start_line: int
    changed_lines: list[int]
    decorators: list[str]
    is_test_file: bool
    post_src_lines: int
    evidence: list[EvidenceOut]


class FindingOut(BaseModel):
    finding_key: str
    cwe: str
    posterior_probability: float
    is_alert_worthy: bool
    severity: str
    prior_probability: float
    alert_threshold: float
    file: str | None
    qualified_symbol: str | None
    line_numbers: list[int]
    title: str
    consensus_rationale: str


class FindingUnitOut(BaseModel):
    """The analysed function, without its statements.

    `ChangeUnitOut` carries `evidence`; this deliberately does not. On this page the statements
    are grouped under the witness whose factor they justify, and a second flat copy of the same
    rows would be a list a reader could diff against the grouped one and find disagreeing.
    """

    unit_id: str
    file: str
    qualified_symbol: str
    language: str
    start_line: int
    changed_lines: list[int]
    decorators: list[str]
    is_test_file: bool
    post_src_lines: int


class WitnessBreakdownOut(BaseModel):
    """One factor of the odds product, and the statements behind it.

    `likelihood_ratio` is read from the finding's stored breakdown, never recomputed — it is the
    number this run multiplied in, and `cell` names the entry of `calibration.json` it came from
    so a reader can check the factor against the fit rather than take it on trust.

    `statements` is every row from this witness's backends, whatever they said. A witness with a
    neutral factor and an abstention beneath it is the case the page exists to make legible: the
    odds did not move, and the reason they did not move is that nobody could look.
    """

    witness: str
    stance: str
    cell: str | None
    likelihood_ratio: float
    note: str
    agent_ids: list[str]
    statements: list[EvidenceDetailOut]


class FindingDetailOut(BaseModel):
    """One finding, and the arithmetic that produced its posterior.

    `contributions_recorded` is the field a renderer may not ignore. False means the finding
    predates the column that stores the breakdown (migration 0004), and the witnesses carry their
    statements with no ratio attached. Rendering those as four neutral factors would be inventing
    an explanation for a number that was produced by factors nobody kept — which is precisely the
    unfalsifiable confidence this project exists to argue against.
    """

    audit_id: str
    repository_full_name: str
    pr_number: int
    head_sha: str
    finding: FindingOut
    calibration: CalibrationOut | None
    unit: FindingUnitOut | None
    contributions_recorded: bool
    witnesses: list[WitnessBreakdownOut]


class AuditDetailOut(BaseModel):
    """One audit, with what it looked at and what it concluded.

    `units_returned` sits beside `unit_count` so a capped list says it is capped. An audit that
    analysed 900 functions and shows 200 of them must not read as an audit that found 200.
    """

    id: str
    repository_id: int
    repository_full_name: str
    pr_number: int
    head_sha: str
    base_sha: str
    status: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None
    error_reason: str | None
    github_comment_id: int | None
    contract_version: str
    prior_probability: float
    alert_threshold: float
    calibration: CalibrationOut | None
    unit_count: int
    units_returned: int
    units: list[ChangeUnitOut]
    findings: list[FindingOut]


def _to_calibration(run: CalibrationRun | None) -> CalibrationOut | None:
    if run is None:
        return None
    return CalibrationOut(
        id=str(run.id),
        is_provisional=run.is_provisional,
        corpus_hash=run.corpus_hash,
        split_hash=run.split_hash,
        ece=run.ece,
        brier=run.brier,
        n_cases=run.n_cases,
    )


def _to_evidence(row: EvidenceRow) -> EvidenceOut:
    return EvidenceOut(
        agent_id=row.agent_id,
        agent_version=row.agent_version,
        kind=str(row.kind.value),
        finding_key=row.finding_key,
        cwe=row.cwe,
        covered_cwes=list(row.covered_cwes),
        reason=row.reason,
        raw_score=row.raw_score,
        confidence=row.confidence,
        explanation=row.explanation,
    )


def _to_unit(row: ChangeUnitRow) -> ChangeUnitOut:
    return ChangeUnitOut(
        unit_id=row.unit_id,
        file=row.file,
        qualified_symbol=row.qualified_symbol,
        language=row.language,
        start_line=row.start_line,
        changed_lines=list(row.changed_lines),
        decorators=list(row.decorators),
        is_test_file=row.is_test_file,
        post_src_lines=row.post_src_lines,
        # Sorted by agent id so the four witnesses appear in the same order on every unit. An
        # order that follows insertion would reshuffle whenever the thread pool finished in a
        # different sequence, and a reader comparing two units would be comparing two layouts.
        evidence=[_to_evidence(item) for item in sorted(row.evidence, key=lambda e: e.agent_id)],
    )


def _to_finding(row: Finding) -> FindingOut:
    return FindingOut(
        finding_key=row.finding_key,
        cwe=row.cwe,
        posterior_probability=row.posterior_probability,
        is_alert_worthy=row.is_alert_worthy,
        severity=row.severity,
        prior_probability=row.prior_probability,
        alert_threshold=row.alert_threshold,
        file=row.file,
        qualified_symbol=row.qualified_symbol,
        line_numbers=list(row.line_numbers),
        title=row.title,
        consensus_rationale=row.consensus_rationale,
    )


def _to_evidence_detail(row: EvidenceRow) -> EvidenceDetailOut:
    return EvidenceDetailOut(
        **_to_evidence(row).model_dump(),
        artifacts=[dict(item) for item in row.artifacts],
    )


def _to_finding_unit(row: ChangeUnitRow) -> FindingUnitOut:
    return FindingUnitOut(
        unit_id=row.unit_id,
        file=row.file,
        qualified_symbol=row.qualified_symbol,
        language=row.language,
        start_line=row.start_line,
        changed_lines=list(row.changed_lines),
        decorators=list(row.decorators),
        is_test_file=row.is_test_file,
        post_src_lines=row.post_src_lines,
    )


def _breakdown(detail: FindingDetail) -> list[WitnessBreakdownOut]:
    """One entry per witness, in `WITNESSES` order, whether or not it spoke.

    The roster comes from `fusion.witnesses` rather than from the stored breakdown or the
    statements, so the page shows four rows for the same reason fusion multiplies four factors
    (D-007): a witness that said nothing is part of the answer, and a list built from what was
    said would quietly shorten to the agents that alerted.

    Ratios are read from the finding's stored `contributions`. Nothing here computes one. Where
    the column is NULL the statements are still grouped and shown, and the factor is reported as
    absent rather than as 1.0 — an unrecorded ratio and a neutral witness are different claims.
    """
    recorded = {str(item.get("witness", "")): item for item in (detail.finding.contributions or [])}
    statements: dict[str, list[EvidenceDetailOut]] = {witness: [] for witness in WITNESSES}
    for row in detail.evidence:
        # An agent_id no witness claims cannot be shown under an invented heading — the same
        # refusal fusion makes, for the same reason (D-052). It is a 500, and it should be: an
        # unregistered agent got its statements into the database.
        statements[witness_for(row.agent_id)].append(_to_evidence_detail(row))

    out: list[WitnessBreakdownOut] = []
    for witness in WITNESSES:
        item = recorded.get(witness, {})
        out.append(
            WitnessBreakdownOut(
                witness=witness,
                stance=str(item.get("stance", "")),
                cell=(str(item["cell"]) if item.get("cell") is not None else None),
                likelihood_ratio=float(item.get("likelihood_ratio", 0.0)),
                note=str(item.get("note", "")),
                agent_ids=[str(a) for a in item.get("agent_ids", [])],
                statements=statements[witness],
            )
        )
    return out


def _to_summary(summary: AuditSummary) -> AuditSummaryOut:
    return AuditSummaryOut(
        id=str(summary.id),
        repository_id=summary.repository_id,
        repository_full_name=summary.repository_full_name,
        pr_number=summary.pr_number,
        head_sha=summary.head_sha,
        status=str(summary.status.value),
        created_at=summary.created_at,
        duration_seconds=summary.duration_seconds,
        error_reason=summary.error_reason,
        prior_probability=summary.prior_probability,
        alert_threshold=summary.alert_threshold,
        units=summary.units,
        findings=summary.findings,
        alerts=summary.alerts,
        top_posterior=summary.top_posterior,
    )


@router.get("", response_model=AuditPage)
def list_audits(
    db: DbDep,
    session: SessionDep,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: str | None = Query(default=None),
    repository_id: int | None = Query(default=None),
) -> AuditPage:
    """Audit history, newest first.

    A full page implies there may be more and a short page is the end — one extra request at the
    end of a scroll, rather than a `COUNT(*)` over the whole history on every page.
    """
    before: tuple[datetime, uuid.UUID] | None = None
    if cursor:
        try:
            before = decode_cursor(cursor)
        except CursorError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="That page cursor is not one this API issued.",
            ) from exc

    summaries = list_audit_summaries(
        db,
        installation_ids=list(session.visible_installation_ids),
        limit=limit,
        before=before,
        repository_id=repository_id,
    )
    next_cursor = (
        encode_cursor(summaries[-1].created_at, summaries[-1].id)
        if len(summaries) == limit
        else None
    )
    return AuditPage(items=[_to_summary(row) for row in summaries], next_cursor=next_cursor)


@router.get("/{audit_id}/findings/{finding_key}", response_model=FindingDetailOut)
def get_finding(
    audit_id: uuid.UUID, finding_key: str, db: DbDep, session: SessionDep
) -> FindingDetailOut:
    """One finding, and the posterior taken apart factor by factor.

    Scoped through its audit, because `finding_key` is unique per audit and not globally: the
    same key recurs by design when the same function is re-analysed on a new head SHA. 404 covers
    "no such audit", "no such finding" and "not yours" alike.
    """
    detail = finding_detail(
        db,
        audit_id=audit_id,
        finding_key=finding_key,
        installation_ids=list(session.visible_installation_ids),
    )
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    return FindingDetailOut(
        audit_id=str(detail.audit.id),
        repository_full_name=detail.repository_full_name,
        pr_number=detail.audit.pr_number,
        head_sha=detail.audit.head_sha,
        finding=_to_finding(detail.finding),
        calibration=_to_calibration(detail.calibration),
        unit=_to_finding_unit(detail.unit) if detail.unit is not None else None,
        contributions_recorded=detail.finding.contributions is not None,
        witnesses=_breakdown(detail),
    )


@router.get("/{audit_id}", response_model=AuditDetailOut)
def get_audit(audit_id: uuid.UUID, db: DbDep, session: SessionDep) -> AuditDetailOut:
    """One audit in full.

    404 covers both "no such audit" and "not yours", for the same reason the repository routes do:
    distinguishing them confirms the existence of an audit on a repository the caller cannot see.
    """
    detail = audit_detail(
        db, audit_id=audit_id, installation_ids=list(session.visible_installation_ids)
    )
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found.")

    audit = detail.audit
    duration = (
        (audit.finished_at - audit.started_at).total_seconds()
        if audit.started_at and audit.finished_at
        else None
    )
    return AuditDetailOut(
        id=str(audit.id),
        repository_id=audit.repository_id,
        repository_full_name=detail.repository_full_name,
        pr_number=audit.pr_number,
        head_sha=audit.head_sha,
        base_sha=audit.base_sha,
        status=str(audit.status.value),
        created_at=audit.created_at,
        started_at=audit.started_at,
        finished_at=audit.finished_at,
        duration_seconds=duration,
        error_reason=audit.error_reason,
        github_comment_id=audit.github_comment_id,
        contract_version=audit.contract_version,
        prior_probability=audit.prior_probability,
        alert_threshold=audit.alert_threshold,
        calibration=_to_calibration(detail.calibration),
        unit_count=detail.unit_count,
        units_returned=len(detail.units),
        units=[_to_unit(row) for row in detail.units],
        findings=[_to_finding(row) for row in detail.findings],
    )
