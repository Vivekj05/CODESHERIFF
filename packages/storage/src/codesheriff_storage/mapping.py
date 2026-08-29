"""Contract objects to rows. The only writer of analysis results.

Two rules are enforced here rather than left to callers.

**Source never reaches a row.** `to_change_unit_row` hashes `post_src` and `pre_src` and keeps the
metadata; there is no code path from a `ChangeUnit` to a stored function body (§6, D-027).

**A `finding_key` that no agent could have produced is never persisted.** Until Chapter 9
`fuse_all_evidence` synthesised `finding_key="abstention:all_agents"` when nothing was detected —
a raw string in the key space `contracts.finding_key()` owns, and the AUDIT.md 1.1 bypass one layer
up in `FusionResult`, where the Evidence validator cannot reach. Chapter 9 removed it at source: a
unit nobody detected anything in now yields no `FusionResult` at all, and what records that the
unit was looked at is its evidence rows.

`persistable_findings` stays anyway. It is cheap, it is the only thing standing between a
hand-built key and the `findings` table, and the mechanism it guards against is one this repository
has already reintroduced once by another route (AUDIT.md 1.1). A wall is not made redundant by
nothing currently running into it.
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from typing import Any

from codesheriff_contracts import ChangeUnit, Evidence
from codesheriff_engine.fusion.bayes import FusionResult
from codesheriff_storage.models import (
    FINDING_KEY_PATTERN,
    ChangeUnitRow,
    EvidenceKindDB,
    EvidenceRow,
    Finding,
)
from codesheriff_storage.redaction import redact_artifact_content

logger = logging.getLogger(__name__)

_FINDING_KEY_RE = re.compile(FINDING_KEY_PATTERN)


def sha256_text(text: str) -> str:
    """Hex digest of UTF-8 text. The only form source code is stored in."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_wellformed_finding_key(key: str | None) -> bool:
    """Whether `key` could have come from `contracts.finding_key()`."""
    return bool(key) and _FINDING_KEY_RE.fullmatch(key or "") is not None


def to_change_unit_row(audit_id: uuid.UUID, unit: ChangeUnit) -> ChangeUnitRow:
    """One analysed function as a row: hashes, line metadata, symbol names. No source."""
    return ChangeUnitRow(
        audit_id=audit_id,
        unit_id=unit.unit_id,
        file=unit.file,
        qualified_symbol=unit.qualified_symbol,
        symbol=unit.symbol,
        enclosing_class=unit.enclosing_class,
        language=unit.language,
        start_line=unit.start_line,
        changed_lines=list(unit.changed_lines),
        decorators=list(unit.decorators),
        is_test_file=unit.is_test_file,
        post_src_sha256=sha256_text(unit.post_src),
        pre_src_sha256=sha256_text(unit.pre_src) if unit.pre_src is not None else None,
        post_src_bytes=len(unit.post_src.encode("utf-8")),
        post_src_lines=len(unit.post_src.splitlines()),
    )


def to_evidence_row(change_unit_row_id: uuid.UUID, evidence: Evidence) -> EvidenceRow:
    """One agent statement as a row, with its artifacts clipped to the excerpt budget."""
    artifacts: list[dict[str, Any]] = [
        {
            "artifact_type": artifact.artifact_type,
            "content": redact_artifact_content(artifact.content),
        }
        for artifact in evidence.artifacts
    ]
    return EvidenceRow(
        change_unit_id=change_unit_row_id,
        agent_id=evidence.agent_id,
        agent_version=evidence.agent_version,
        kind=EvidenceKindDB(evidence.kind.value),
        finding_key=evidence.finding_key,
        cwe=evidence.cwe,
        covered_cwes=sorted(evidence.covered_cwes),
        reason=evidence.reason,
        raw_score=evidence.raw_score,
        confidence=evidence.confidence,
        explanation=evidence.explanation,
        artifacts=artifacts,
    )


def to_finding(
    audit_id: uuid.UUID,
    result: FusionResult,
    prior_probability: float,
    alert_threshold: float,
    calibration_run_id: uuid.UUID | None = None,
    file: str | None = None,
    qualified_symbol: str | None = None,
) -> Finding:
    """One fused posterior as a row.

    `prior_probability` and `alert_threshold` are stored per finding rather than looked up from
    configuration at read time. A threshold selected later on the validation split must not
    retroactively change which past findings counted as alerts (§6).
    """
    if not is_wellformed_finding_key(result.finding_key):
        raise ValueError(
            f"refusing to persist finding_key {result.finding_key!r}: not a "
            f"contracts.finding_key() digest. Filter with persistable_findings() first."
        )
    if not result.cwe:
        raise ValueError(
            f"refusing to persist finding {result.finding_key} with no CWE: a finding without a "
            f"CWE cannot be scored against IN_SCOPE_CWES"
        )
    return Finding(
        audit_id=audit_id,
        finding_key=result.finding_key,
        cwe=result.cwe.strip().upper(),
        posterior_probability=result.posterior_probability,
        is_alert_worthy=result.posterior_probability >= alert_threshold,
        severity=result.severity or "medium",
        prior_probability=prior_probability,
        alert_threshold=alert_threshold,
        calibration_run_id=calibration_run_id,
        file=file if file is not None else result.file,
        qualified_symbol=qualified_symbol,
        line_numbers=list(result.line_numbers),
        title=result.title or "",
        consensus_rationale=result.consensus_rationale,
    )


def persistable_findings(results: list[FusionResult]) -> list[FusionResult]:
    """Drop fusion results that are not findings.

    Anything whose key did not come from `contracts.finding_key()`, and anything carrying no CWE.
    Both are logged at WARNING — silently discarding a result is how evidence goes missing without
    trace, which is the one thing a calibration claim cannot survive (AUDIT.md 2.6).
    """
    keepers: list[FusionResult] = []
    for result in results:
        if not is_wellformed_finding_key(result.finding_key):
            logger.warning(
                "Not persisting fusion result with non-contract key %r (posterior %.4f): this is a "
                "unit-level marker, not a finding.",
                result.finding_key,
                result.posterior_probability,
            )
            continue
        if not result.cwe:
            logger.warning(
                "Not persisting finding %s: no CWE on the fused result.", result.finding_key
            )
            continue
        keepers.append(result)
    return keepers
