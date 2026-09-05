"""Read queries for the dashboard. Nothing here writes.

`audits.py` moves the audit through its lifecycle; this module reads the result back out. They
are split because the two have opposite hazards. A lifecycle write must be a single conditional
UPDATE or two workers race; a dashboard read must be scoped to what the caller may see or it
discloses another account's pull requests. One module would mean one set of review habits for
both.

**Every function takes `installation_ids` and returns nothing when it is empty.** That asymmetry
is the access check itself (D-035): a session that can see no installations must not fall through
to an unfiltered `SELECT`. The scoping lives here rather than in the route for the same reason it
does in `identity.py` — a route can forget a filter, and this way there is no query for it to
forget it from.

**Counts are correlated subqueries, not joins.** An audit has many units, many evidence rows and
many findings; joining all three and counting would multiply the rows by each other and report
`units x findings` change units. The bug would look like a plausible number.

Nothing here reads source code, because none is stored (§6, D-027). A finding carries a file path
and a symbol; the dashboard is where those are allowed to be shown, since it escapes them and a
pull request comment does not (D-050).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import Select, func, select, tuple_
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import selectinload

from codesheriff_storage.models import (
    Audit,
    AuditStatus,
    CalibrationRun,
    ChangeUnitRow,
    EvidenceKindDB,
    EvidenceRow,
    Finding,
    Repository,
)

MAX_UNITS_PER_AUDIT = 200
"""How many change units one audit detail response carries.

A pull request that rewrites a package can produce hundreds of units, each with one statement per
witness. The detail reports the true count separately, so a truncated list says so rather than
quietly under-reporting what was analysed.
"""


@dataclass(frozen=True, slots=True)
class AuditSummary:
    """One row of the audit history.

    Aggregates rather than relationships: the history page shows counts, and loading every
    finding of every audit to call `len()` on it is the query that gets slow first.
    """

    id: uuid.UUID
    repository_id: int
    repository_full_name: str
    pr_number: int
    head_sha: str
    status: AuditStatus
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error_reason: str | None
    prior_probability: float
    alert_threshold: float
    calibration_run_id: uuid.UUID | None
    units: int
    findings: int
    alerts: int
    top_posterior: float | None

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock time the worker spent, or None while it has not finished."""
        if self.started_at is None or self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()


@dataclass(frozen=True, slots=True)
class AuditDetail:
    """One audit, with what it looked at and what it concluded.

    `units` may be shorter than `unit_count` — see `MAX_UNITS_PER_AUDIT`. The two are separate
    fields so a truncated response cannot be mistaken for a small audit.
    """

    audit: Audit
    repository_full_name: str
    calibration: CalibrationRun | None
    units: list[ChangeUnitRow]
    unit_count: int
    findings: list[Finding]


@dataclass(frozen=True, slots=True)
class CweCount:
    cwe: str
    findings: int
    alerts: int


@dataclass(frozen=True, slots=True)
class WitnessActivity:
    """What one agent has actually done in production, counted by evidence kind.

    Detections, silences and abstentions are counted separately because they are three different
    statements, and the project's whole fusion argument rests on not conflating the last two
    (§5). An agent whose abstentions dominate is not a quiet agent, it is an agent that cannot run
    here — `structural.semgrep` on a Windows host being the standing example.
    """

    agent_id: str
    detections: int
    silences: int
    abstentions: int

    @property
    def statements(self) -> int:
        return self.detections + self.silences + self.abstentions


@dataclass(frozen=True, slots=True)
class OverviewStats:
    """The numbers on the overview page.

    Counts of things that happened, deliberately, and not a score. There is no "security grade"
    here and there should not be one: this project's claim is about the reliability of individual
    posteriors, and an aggregate letter grade would be an uncalibrated number sitting next to
    calibrated ones.
    """

    repositories: int
    repositories_analysing: int
    audits: int
    audits_by_status: dict[str, int] = field(default_factory=dict)
    units_analysed: int = 0
    findings: int = 0
    alerts: int = 0
    by_cwe: list[CweCount] = field(default_factory=list)
    witnesses: list[WitnessActivity] = field(default_factory=list)
    latest_audit_at: datetime | None = None


def _visible_audit_ids(installation_ids: list[int]) -> Select[tuple[uuid.UUID]]:
    """Audit ids this session may read.

    One definition, reused by every aggregate below. A second copy of this filter is how one
    statistic comes to count another account's pull requests while the rest do not.
    """
    return (
        select(Audit.id)
        .join(Repository, Repository.id == Audit.repository_id)
        .where(Repository.installation_id.in_(installation_ids))
    )


def list_audit_summaries(
    db: DbSession,
    *,
    installation_ids: list[int],
    limit: int = 25,
    before: tuple[datetime, uuid.UUID] | None = None,
    repository_id: int | None = None,
) -> list[AuditSummary]:
    """Audit history, newest first, keyset-paginated by `(created_at, id)`.

    Keyset rather than OFFSET, and on a *pair* rather than on the timestamp alone: audits opened
    by one push share a `created_at` often enough, and a cursor on the timestamp alone would drop
    whichever of them sorted second.

    `repository_id` narrows the list without widening access — it is applied on top of the
    installation scope, never instead of it.
    """
    if not installation_ids:
        return []

    units = (
        select(func.count(ChangeUnitRow.id))
        .where(ChangeUnitRow.audit_id == Audit.id)
        .correlate(Audit)
        .scalar_subquery()
    )
    findings = (
        select(func.count(Finding.id))
        .where(Finding.audit_id == Audit.id)
        .correlate(Audit)
        .scalar_subquery()
    )
    alerts = (
        select(func.count(Finding.id))
        .where(Finding.audit_id == Audit.id, Finding.is_alert_worthy.is_(True))
        .correlate(Audit)
        .scalar_subquery()
    )
    top = (
        select(func.max(Finding.posterior_probability))
        .where(Finding.audit_id == Audit.id)
        .correlate(Audit)
        .scalar_subquery()
    )

    stmt = (
        select(Audit, Repository.full_name, units, findings, alerts, top)
        .join(Repository, Repository.id == Audit.repository_id)
        .where(Repository.installation_id.in_(installation_ids))
        .order_by(Audit.created_at.desc(), Audit.id.desc())
        .limit(limit)
    )
    if repository_id is not None:
        stmt = stmt.where(Audit.repository_id == repository_id)
    if before is not None:
        stmt = stmt.where(tuple_(Audit.created_at, Audit.id) < before)

    return [
        AuditSummary(
            id=audit.id,
            repository_id=audit.repository_id,
            repository_full_name=full_name,
            pr_number=audit.pr_number,
            head_sha=audit.head_sha,
            status=audit.status,
            created_at=audit.created_at,
            started_at=audit.started_at,
            finished_at=audit.finished_at,
            error_reason=audit.error_reason,
            prior_probability=audit.prior_probability,
            alert_threshold=audit.alert_threshold,
            calibration_run_id=audit.calibration_run_id,
            units=n_units,
            findings=n_findings,
            alerts=n_alerts,
            top_posterior=top_posterior,
        )
        for audit, full_name, n_units, n_findings, n_alerts, top_posterior in db.execute(stmt).all()
    ]


def audit_detail(
    db: DbSession, *, audit_id: uuid.UUID, installation_ids: list[int]
) -> AuditDetail | None:
    """One audit and everything the dashboard renders about it, or None.

    None covers both "no such audit" and "not yours", and the route answers 404 to both. Telling
    them apart would confirm that an audit id exists on a repository the caller cannot see.

    Evidence is loaded with `selectinload` rather than a join: a unit carries one statement per
    witness, and joining them onto the units multiplies the unit rows by four before Python sees
    them.
    """
    if not installation_ids:
        return None

    stmt = (
        select(Audit, Repository.full_name)
        .join(Repository, Repository.id == Audit.repository_id)
        .where(Audit.id == audit_id, Repository.installation_id.in_(installation_ids))
        .options(selectinload(Audit.calibration_run))
    )
    row = db.execute(stmt).first()
    if row is None:
        return None
    audit, full_name = row

    unit_count = db.execute(
        select(func.count(ChangeUnitRow.id)).where(ChangeUnitRow.audit_id == audit.id)
    ).scalar_one()
    units = list(
        db.execute(
            select(ChangeUnitRow)
            .where(ChangeUnitRow.audit_id == audit.id)
            .order_by(ChangeUnitRow.file, ChangeUnitRow.start_line, ChangeUnitRow.unit_id)
            .limit(MAX_UNITS_PER_AUDIT)
            .options(selectinload(ChangeUnitRow.evidence))
        )
        .scalars()
        .all()
    )
    findings = list(
        db.execute(
            select(Finding)
            .where(Finding.audit_id == audit.id)
            .order_by(Finding.posterior_probability.desc(), Finding.finding_key)
        )
        .scalars()
        .all()
    )

    return AuditDetail(
        audit=audit,
        repository_full_name=full_name,
        calibration=audit.calibration_run,
        units=units,
        unit_count=unit_count,
        findings=findings,
    )


def overview_stats(db: DbSession, *, installation_ids: list[int]) -> OverviewStats:
    """The overview page, in one place.

    An empty installation list returns zeros rather than totals for the whole database — the same
    asymmetry every other query here has, and the one that matters most: a statistics endpoint
    that ignored scope would leak counts without ever naming a repository.
    """
    if not installation_ids:
        return OverviewStats(repositories=0, repositories_analysing=0, audits=0)

    repositories, analysing = db.execute(
        select(
            func.count(Repository.id),
            func.count(Repository.id).filter(Repository.analysis_enabled.is_(True)),
        ).where(Repository.installation_id.in_(installation_ids))
    ).one()

    visible = select(_visible_audit_ids(installation_ids).subquery().c.id)

    by_status = {
        str(status.value): count
        for status, count in db.execute(
            select(Audit.status, func.count(Audit.id))
            .where(Audit.id.in_(visible))
            .group_by(Audit.status)
        ).all()
    }
    latest_audit_at = db.execute(
        select(func.max(Audit.created_at)).where(Audit.id.in_(visible))
    ).scalar_one_or_none()

    units_analysed = db.execute(
        select(func.count(ChangeUnitRow.id)).where(ChangeUnitRow.audit_id.in_(visible))
    ).scalar_one()

    findings, alerts = db.execute(
        select(
            func.count(Finding.id),
            func.count(Finding.id).filter(Finding.is_alert_worthy.is_(True)),
        ).where(Finding.audit_id.in_(visible))
    ).one()

    by_cwe = [
        CweCount(cwe=cwe, findings=n_findings, alerts=n_alerts)
        for cwe, n_findings, n_alerts in db.execute(
            select(
                Finding.cwe,
                func.count(Finding.id),
                func.count(Finding.id).filter(Finding.is_alert_worthy.is_(True)),
            )
            .where(Finding.audit_id.in_(visible))
            .group_by(Finding.cwe)
            .order_by(func.count(Finding.id).desc(), Finding.cwe)
        ).all()
    ]

    witnesses = [
        WitnessActivity(
            agent_id=agent_id,
            detections=detections,
            silences=silences,
            abstentions=abstentions,
        )
        for agent_id, detections, silences, abstentions in db.execute(
            select(
                EvidenceRow.agent_id,
                func.count(EvidenceRow.id).filter(EvidenceRow.kind == EvidenceKindDB.DETECTION),
                func.count(EvidenceRow.id).filter(EvidenceRow.kind == EvidenceKindDB.SILENCE),
                func.count(EvidenceRow.id).filter(EvidenceRow.kind == EvidenceKindDB.ABSTENTION),
            )
            .join(ChangeUnitRow, ChangeUnitRow.id == EvidenceRow.change_unit_id)
            .where(ChangeUnitRow.audit_id.in_(visible))
            .group_by(EvidenceRow.agent_id)
            .order_by(EvidenceRow.agent_id)
        ).all()
    ]

    return OverviewStats(
        repositories=repositories,
        repositories_analysing=analysing,
        audits=sum(by_status.values()),
        audits_by_status=by_status,
        units_analysed=units_analysed,
        findings=findings,
        alerts=alerts,
        by_cwe=by_cwe,
        witnesses=witnesses,
        latest_audit_at=latest_audit_at,
    )
