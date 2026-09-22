"""The GitHub webhook. Verify, record, enqueue, return.

Replaces `packages/engine/src/codesheriff_engine/github/webhook.py`, which had no signature check
at all (`AUDIT.md` 0.1) and ran the entire pipeline inline before answering (`AUDIT.md` 4.3).

**Order is the security property.** The signature is checked against the raw request body before
the body is parsed, before a row is read or written, and before anything is enqueued. Parsing first
and verifying second would still reject the request — after an attacker had already chosen which
code path ran and which parser saw their bytes. The handler is written top to bottom in the order
the checks must happen, and nothing above the check touches the payload.

**What a verified delivery is allowed to do.** It may write installation and repository rows. That
is not the D-037 situation: `?installation_id=` in a browser URL is chosen by whoever clicks the
link, whereas a body carrying a valid HMAC is GitHub speaking. What it still may not do is widen
what any *user* can see — visibility comes only from `GET /user/installations` at sign-in (D-035),
and nothing here touches a session.

**Why it answers so quickly.** The endpoint does three round trips at most — upsert, insert,
publish — and hands GitHub a 202. §6 budgets under 3s against a 10s hard limit, and the pipeline it
is starting takes minutes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Header, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session as DbSession

from codesheriff_api.config import MissingCredentialError
from codesheriff_api.deps import ConfigDep, DbDep
from codesheriff_api.queue import QueueDep, QueueError, TaskQueue
from codesheriff_contracts import CONTRACT_VERSION
from codesheriff_engine.calibration import active_artifact
from codesheriff_storage import (
    audit_for_delivery,
    calibration_run_for,
    delete_installation,
    delete_repositories,
    ensure_installation,
    ensure_repository,
    open_audit,
    repository_by_id,
    supersede_open_audits,
    upsert_installation,
    upsert_repository,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])

SIGNATURE_PREFIX = "sha256="

ANALYSED_PR_ACTIONS = frozenset({"opened", "reopened", "synchronize"})
"""The actions that mean the head commit changed or is newly under review.

Not `ready_for_review` or `edited`: neither changes a line of code, and each would open a second
audit for a head that already has one. Not `push` as an event at all — a force-push to a PR branch
already arrives here as `synchronize` (D-034)."""


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    """Whether `header` is GitHub's HMAC-SHA256 of `body` under `secret`.

    `compare_digest` rather than `==`: the comparison runs on attacker-supplied input, and the
    early exit of a normal string comparison leaks how many leading bytes were right, which is
    enough to build a valid signature one byte at a time.

    A missing or malformed header is false, never an exception — this is called before anything
    else and must have exactly one failure mode.
    """
    if not header or not header.startswith(SIGNATURE_PREFIX):
        return False
    expected = SIGNATURE_PREFIX + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def _bad_request(reason: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=reason)


def _acknowledge(reason: str, **extra: Any) -> JSONResponse:
    """200 for a delivery that was understood and deliberately not acted on.

    A 2xx tells GitHub to stop redelivering. Anything else queues a retry of a request that would
    be ignored again, and repeated failures eventually disable the webhook on the App."""
    return JSONResponse(status_code=status.HTTP_200_OK, content={"status": reason, **extra})


@router.post("/github")
async def receive_github_webhook(
    request: Request,
    config: ConfigDep,
    db: DbDep,
    queue: QueueDep,
    x_github_event: Annotated[str | None, Header()] = None,
    x_github_delivery: Annotated[str | None, Header()] = None,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
) -> Response:
    """Verify the signature, then act.

    `async def` for one reason: the raw body has to be read before it is parsed, and reading it is
    an await. Everything after the check is synchronous database work and goes to a threadpool
    rather than blocking the event loop for every other request in the process (D-028).
    """
    body = await request.body()

    try:
        secret = config.require_webhook_secret()
    except MissingCredentialError as exc:
        # 501, not 401. The request may well be genuine; this instance simply cannot tell. A 5xx
        # also means GitHub redelivers, so the deliveries that arrive while the secret is missing
        # are not lost — they land once an operator sets it.
        logger.error("Webhook received but no secret is configured: %s", exc)
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc

    if not verify_signature(secret, body, x_hub_signature_256):
        # Nothing has been parsed, read or written at this point, and nothing will be.
        logger.warning(
            "Rejected webhook delivery %s: bad or missing signature", x_github_delivery or "?"
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature.")

    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise _bad_request("Body is not valid JSON.") from exc
    if not isinstance(payload, dict):
        raise _bad_request("Body is not a JSON object.")

    event = x_github_event or ""
    delivery_id = x_github_delivery or None

    if event == "ping":
        return _acknowledge("pong", zen=str(payload.get("zen", "")))

    if event == "pull_request":
        return await run_in_threadpool(_handle_pull_request, db, queue, payload, delivery_id)
    if event == "installation":
        return await run_in_threadpool(_handle_installation, db, payload)
    if event == "installation_repositories":
        return await run_in_threadpool(_handle_installation_repositories, db, payload)

    return _acknowledge("ignored", event=event)


def _handle_pull_request(
    db: DbSession,
    queue: TaskQueue,
    payload: dict[str, Any],
    delivery_id: str | None,
) -> JSONResponse:
    """Open an audit for a changed head and hand it to a worker.

    Every early return here is a 200 rather than an error. "This repository has analysis turned
    off" and "this action does not change code" are correct outcomes, and telling GitHub they were
    failures would earn a redelivery of a request that would take the same branch again.
    """
    action = str(payload.get("action", ""))
    if action not in ANALYSED_PR_ACTIONS:
        return _acknowledge("ignored", action=action)

    pull_request = payload.get("pull_request") or {}
    repository = payload.get("repository") or {}
    installation = payload.get("installation") or {}
    if not (pull_request and repository and installation.get("id")):
        raise _bad_request(
            "pull_request payload is missing pull_request, repository or installation."
        )

    try:
        installation_id = int(installation["id"])
        repo_id = int(repository["id"])
        pr_number = int(pull_request["number"])
        head_sha = str(pull_request["head"]["sha"])
        base_sha = str(pull_request["base"]["sha"])
    except (KeyError, TypeError, ValueError) as exc:
        raise _bad_request("pull_request payload is missing required fields.") from exc

    # The App can be installed on a repository nobody has ever signed in to see. Recording it here
    # is what stops those pull requests being silently ignored; `ensure_*` never overwrites, so a
    # PR event cannot clear a suspension or re-enable analysis somebody turned off.
    owner = repository.get("owner") or {}
    ensure_installation(
        db,
        installation_id=installation_id,
        account_login=str(owner.get("login") or "unknown"),
        account_type=str(owner.get("type") or "User"),
    )
    upsert_repository(
        db,
        repo_id=repo_id,
        installation_id=installation_id,
        full_name=str(repository.get("full_name") or ""),
        default_branch=str(repository.get("default_branch") or "main"),
        is_private=bool(repository.get("private", False)),
    )

    repo = repository_by_id(db, repo_id)
    if repo is None:  # pragma: no cover - the upsert above just wrote it
        raise _bad_request("Unknown repository.")
    if not repo.analysis_enabled:
        return _acknowledge("analysis_disabled", repository=repo.full_name)

    if delivery_id is not None:
        existing = audit_for_delivery(db, delivery_id)
        if existing is not None:
            # GitHub delivers at least once, and a redelivery of a request already answered must
            # not open a second run (D-038). The unique constraint would refuse it anyway; this
            # turns that error into the correct answer.
            logger.info("Duplicate delivery %s for audit %s", delivery_id, existing.id)
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={"status": "duplicate", "audit_id": str(existing.id)},
            )

    # The fitted artifact, read here rather than in the worker, because the numbers an audit
    # runs under are decided when it is opened and recorded on the row (§6). A re-fit between
    # opening and running must not change what this audit claims to have used.
    calibration = calibration_run_for(db, active_artifact())
    audit = open_audit(
        db,
        repository_id=repo_id,
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        contract_version=CONTRACT_VERSION,
        calibration_run=calibration,
        delivery_id=delivery_id,
    )
    abandoned = supersede_open_audits(
        db,
        repository_id=repo_id,
        pr_number=pr_number,
        superseding_head_sha=head_sha,
        keep_audit_id=audit.id,
    )

    _enqueue(db, queue, audit.id)

    logger.info(
        "Queued audit %s for %s#%s at %s (superseded %d)",
        audit.id,
        repo.full_name,
        pr_number,
        head_sha[:7],
        abandoned,
    )
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "status": "queued",
            "audit_id": str(audit.id),
            "superseded": abandoned,
        },
    )


def _enqueue(db: DbSession, queue: TaskQueue, audit_id: uuid.UUID) -> None:
    """Publish the task, committing the audit row first.

    The order matters and only one order is safe. Committing first can leave an audit queued in the
    database that no worker was told about — visible, diagnosable, and recoverable by a redelivery
    or a sweep. Publishing first can hand a worker an id that does not exist yet, or that a
    rollback removes entirely, which is a task that fails forever for reasons nothing records.
    """
    db.commit()
    try:
        queue.enqueue_audit(audit_id)
    except QueueError as exc:
        # A 5xx here is deliberate: the audit row exists and GitHub's redelivery will find it by
        # `delivery_id` and enqueue again rather than duplicate it.
        logger.error("Audit %s is queued in the database but was not published: %s", audit_id, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not reach the job queue.",
        ) from exc


def _handle_installation(db: DbSession, payload: dict[str, Any]) -> JSONResponse:
    """The App was installed, suspended, unsuspended or removed.

    This is the only handler allowed to write an installation's real state — see
    `ensure_installation` for why the pull request path is not.
    """
    action = str(payload.get("action", ""))
    installation = payload.get("installation") or {}
    try:
        installation_id = int(installation["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise _bad_request("installation payload is missing installation.id.") from exc

    if action == "deleted":
        removed = delete_installation(db, installation_id)
        db.commit()
        logger.info("Installation %s deleted (existed=%s)", installation_id, removed)
        return _acknowledge("installation_deleted", installation_id=installation_id)

    account = installation.get("account") or {}
    upsert_installation(
        db,
        installation_id=installation_id,
        account_login=str(account.get("login") or "unknown"),
        account_type=str(account.get("type") or "User"),
        suspended_at=_parse_timestamp(installation.get("suspended_at")),
    )
    for repo in payload.get("repositories") or []:
        _ensure_payload_repository(db, installation_id, repo)
    db.commit()

    logger.info("Installation %s %s", installation_id, action or "updated")
    return _acknowledge("installation_synced", installation_id=installation_id, action=action)


def _handle_installation_repositories(db: DbSession, payload: dict[str, Any]) -> JSONResponse:
    """Repositories were added to or removed from an installation."""
    installation = payload.get("installation") or {}
    try:
        installation_id = int(installation["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise _bad_request("installation_repositories payload is missing installation.id.") from exc

    for repo in payload.get("repositories_added") or []:
        _ensure_payload_repository(db, installation_id, repo)

    removed_ids: list[int] = []
    for repo in payload.get("repositories_removed") or []:
        try:
            removed_ids.append(int(repo["id"]))
        except (KeyError, TypeError, ValueError):
            logger.warning("Skipping a removed repository with no usable id")
    removed = delete_repositories(db, installation_id, removed_ids)
    db.commit()

    logger.info("Installation %s: repository set changed, %d removed", installation_id, removed)
    return _acknowledge("repositories_synced", installation_id=installation_id, removed=removed)


def _ensure_payload_repository(db: DbSession, installation_id: int, repo: dict[str, Any]) -> None:
    """Record one repository from an installation payload, if it is not already known."""
    try:
        repo_id = int(repo["id"])
        full_name = str(repo["full_name"])
    except (KeyError, TypeError, ValueError):
        logger.warning("Skipping a repository entry with no usable id or full_name")
        return
    ensure_repository(
        db,
        repo_id=repo_id,
        installation_id=installation_id,
        full_name=full_name,
        is_private=bool(repo.get("private", False)),
    )


def _parse_timestamp(value: object) -> datetime | None:
    """GitHub's ISO-8601 timestamp, or None.

    Anything unparseable becomes None rather than an error. This value decides whether an
    installation is treated as suspended, and a malformed timestamp should leave that unchanged
    rather than reject a delivery GitHub will then retry forever.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        logger.warning("Unparseable timestamp in installation payload")
        return None
