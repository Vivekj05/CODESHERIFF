"""The overview: what this installation has actually analysed.

Counts of things that happened, and no score. There is deliberately no security grade, no
letter, and no percentage-safe figure: this project's claim is about the reliability of one
posterior about one function, and an aggregate that summarises a repository into a single number
would be an uncalibrated statistic printed in the same typeface as calibrated ones — the exact
confusion the thesis is about.

The per-witness activity counts are the useful half. They say how often each agent detected,
stayed silent and abstained *in production*, which is the number to compare against the fit's own
`n_abstained` before believing a ratio applies here. A witness abstaining on everything is how
`structural.semgrep` behaves on a host with no Semgrep build, and it should be visible on the
front page rather than inferred from a quiet dashboard.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel

from codesheriff_api.deps import DbDep, SessionDep
from codesheriff_storage import overview_stats

router = APIRouter(prefix="/stats", tags=["stats"])


class CweCountOut(BaseModel):
    cwe: str
    findings: int
    alerts: int


class WitnessActivityOut(BaseModel):
    """One agent's statements, by kind.

    Three counts, never two. A UI that added silences and abstentions into "found nothing" would
    be undoing the distinction the whole evidence contract is built on (§5).
    """

    agent_id: str
    detections: int
    silences: int
    abstentions: int
    statements: int


class OverviewOut(BaseModel):
    repositories: int
    repositories_analysing: int
    audits: int
    audits_by_status: dict[str, int]
    units_analysed: int
    findings: int
    alerts: int
    by_cwe: list[CweCountOut]
    witnesses: list[WitnessActivityOut]
    latest_audit_at: datetime | None


@router.get("/overview", response_model=OverviewOut)
def get_overview(db: DbDep, session: SessionDep) -> OverviewOut:
    """Everything on the overview page, in one round trip.

    One endpoint rather than six, because these numbers are read together and a page that fired
    six requests would render six times, each with a different subset of the truth on screen.
    """
    stats = overview_stats(db, installation_ids=list(session.visible_installation_ids))
    return OverviewOut(
        repositories=stats.repositories,
        repositories_analysing=stats.repositories_analysing,
        audits=stats.audits,
        audits_by_status=stats.audits_by_status,
        units_analysed=stats.units_analysed,
        findings=stats.findings,
        alerts=stats.alerts,
        by_cwe=[
            CweCountOut(cwe=row.cwe, findings=row.findings, alerts=row.alerts)
            for row in stats.by_cwe
        ],
        witnesses=[
            WitnessActivityOut(
                agent_id=row.agent_id,
                detections=row.detections,
                silences=row.silences,
                abstentions=row.abstentions,
                statements=row.statements,
            )
            for row in stats.witnesses
        ],
        latest_audit_at=stats.latest_audit_at,
    )
