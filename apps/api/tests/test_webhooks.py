"""The webhook, through the real routes.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

The first group is the one that matters most. `AUDIT.md` 0.1 was a live, unauthenticated endpoint
that would fetch repositories and post comments for anybody who learned the URL, and the reason it
survived a passing test suite is that nothing ever sent it a bad signature. These do.

The signature tests assert two separate things and it is worth being explicit about the second:
that a forged request is rejected, *and* that it is rejected before the body is parsed and before
any row is written. `test_a_forged_delivery_is_rejected_before_the_body_is_parsed` is the one that
pins the ordering — malformed JSON under a bad signature must be a 401, not a 400, because a 400
would mean the parser saw attacker bytes first.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from codesheriff_engine.calibration import active_artifact
from codesheriff_storage import upsert_installation, upsert_repository
from codesheriff_storage.models import Audit, AuditStatus, Installation, Repository

from .conftest import WEBHOOK_SECRET, FakeTaskQueue

pytestmark = pytest.mark.db

WEBHOOK_URL = "/webhooks/github"

INSTALLATION_ID = 9001
REPO_ID = 5001
REPO_FULL_NAME = "acme/payments-api"


def sign(body: bytes, secret: str = WEBHOOK_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def deliver(
    client: TestClient,
    payload: dict[str, Any] | bytes,
    *,
    event: str = "pull_request",
    delivery: str = "delivery-1",
    signature: str | None = None,
    secret: str = WEBHOOK_SECRET,
) -> Any:
    """POST a payload the way GitHub does: raw bytes, with the signature over those exact bytes."""
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery,
        "Content-Type": "application/json",
        "X-Hub-Signature-256": signature if signature is not None else sign(body, secret),
    }
    return client.post(WEBHOOK_URL, content=body, headers=headers)


def pull_request_payload(
    *,
    action: str = "opened",
    head_sha: str = "a" * 40,
    pr_number: int = 7,
    repo_id: int = REPO_ID,
    full_name: str = REPO_FULL_NAME,
) -> dict[str, Any]:
    return {
        "action": action,
        "number": pr_number,
        "pull_request": {
            "number": pr_number,
            "title": "Add a query helper",
            "head": {"sha": head_sha, "ref": "feature"},
            "base": {"sha": "b" * 40, "ref": "main"},
        },
        "repository": {
            "id": repo_id,
            "full_name": full_name,
            "private": True,
            "default_branch": "main",
            "owner": {"login": "acme", "type": "Organization"},
        },
        "installation": {"id": INSTALLATION_ID},
    }


def installation_payload(
    *,
    action: str = "created",
    suspended_at: str | None = None,
    repositories: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "action": action,
        "installation": {
            "id": INSTALLATION_ID,
            "account": {"login": "acme", "type": "Organization"},
            "suspended_at": suspended_at,
        },
        "repositories": repositories if repositories is not None else [],
    }


@pytest.fixture
def known_repo(db: DbSession) -> Repository:
    """An installation and repository already recorded, as a sign-in would have left them."""
    upsert_installation(
        db, installation_id=INSTALLATION_ID, account_login="acme", account_type="Organization"
    )
    repo = upsert_repository(
        db,
        repo_id=REPO_ID,
        installation_id=INSTALLATION_ID,
        full_name=REPO_FULL_NAME,
        default_branch="main",
        is_private=True,
    )
    db.flush()
    return repo


def audits(db: DbSession) -> list[Audit]:
    return list(db.execute(select(Audit).order_by(Audit.created_at)).scalars().all())


def audit_for_head(db: DbSession, head_sha: str) -> Audit:
    """One audit by head, rather than by position.

    `created_at` is `now()`, which inside a single transaction is the transaction's start time — so
    every row a test writes carries the same timestamp and ordering by it is arbitrary. Production
    opens each audit in its own transaction; the test fixture does not.
    """
    return db.execute(select(Audit).where(Audit.head_sha == head_sha)).scalars().one()


# ---------------------------------------------------------------------------
# Signature verification — AUDIT.md 0.1
# ---------------------------------------------------------------------------


def test_a_forged_signature_is_rejected(
    client: TestClient, db: DbSession, known_repo: Repository, queue: FakeTaskQueue
) -> None:
    response = deliver(client, pull_request_payload(), signature="sha256=" + "0" * 64)

    assert response.status_code == 401
    assert audits(db) == []
    assert queue.published == []


def test_a_delivery_with_no_signature_at_all_is_rejected(
    client: TestClient, db: DbSession, known_repo: Repository, queue: FakeTaskQueue
) -> None:
    """The failure the old endpoint had: no header, and it processed the request anyway."""
    body = json.dumps(pull_request_payload()).encode()
    response = client.post(
        WEBHOOK_URL,
        content=body,
        headers={"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "d-1"},
    )

    assert response.status_code == 401
    assert audits(db) == []
    assert queue.published == []


def test_a_signature_under_the_wrong_secret_is_rejected(
    client: TestClient, db: DbSession, known_repo: Repository, queue: FakeTaskQueue
) -> None:
    response = deliver(client, pull_request_payload(), secret="not-the-secret")

    assert response.status_code == 401
    assert audits(db) == []


def test_a_signature_over_different_bytes_is_rejected(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    """Signing the payload and then editing it is the whole attack. The HMAC is over the bytes
    that arrived, not over the object they parse into."""
    original = json.dumps(pull_request_payload()).encode()
    tampered = json.dumps(pull_request_payload(pr_number=99)).encode()

    response = deliver(client, tampered, signature=sign(original))

    assert response.status_code == 401
    assert audits(db) == []


def test_a_malformed_signature_header_is_rejected(
    client: TestClient, known_repo: Repository
) -> None:
    """No prefix, no hex, nothing to compare — and still exactly one failure mode."""
    for header in ("garbage", "sha1=abc", "sha256=", "sha256=nothex"):
        response = deliver(client, pull_request_payload(), signature=header)
        assert response.status_code == 401, header


def test_a_forged_delivery_is_rejected_before_the_body_is_parsed(
    client: TestClient, known_repo: Repository
) -> None:
    """The ordering test. Unparseable bytes under a bad signature must be a 401, not a 400.

    A 400 would prove the parser ran on attacker-controlled input before the check that decides
    whether the input is trustworthy at all.
    """
    response = deliver(client, b"{not json", signature="sha256=" + "0" * 64)

    assert response.status_code == 401


def test_a_valid_signature_over_unparseable_bytes_is_a_bad_request(
    client: TestClient, known_repo: Repository
) -> None:
    """The mirror image: once the sender is authenticated, a broken body is their mistake."""
    response = deliver(client, b"{not json")

    assert response.status_code == 400


def test_with_no_secret_configured_nothing_is_accepted(
    client: TestClient, api_config: Any, db: DbSession, known_repo: Repository
) -> None:
    """A missing secret must stop the request, never weaken the check.

    501 rather than 401 because the request may be perfectly genuine and this instance simply
    cannot tell — and because a 5xx makes GitHub redeliver once an operator sets it.
    """
    api_config.github_webhook_secret = None

    response = deliver(client, pull_request_payload())

    assert response.status_code == 501
    assert "GITHUB_WEBHOOK_SECRET" in response.json()["detail"]
    assert audits(db) == []


# ---------------------------------------------------------------------------
# The seam: verified delivery becomes a queued audit
# ---------------------------------------------------------------------------


def test_a_verified_pull_request_is_queued_and_published(
    client: TestClient, db: DbSession, known_repo: Repository, queue: FakeTaskQueue
) -> None:
    response = deliver(client, pull_request_payload())

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"

    rows = audits(db)
    assert len(rows) == 1
    assert str(rows[0].id) == body["audit_id"]
    assert rows[0].status is AuditStatus.QUEUED
    assert rows[0].head_sha == "a" * 40
    assert rows[0].delivery_id == "delivery-1"
    assert queue.published == [rows[0].id]


def test_the_audit_records_the_calibration_it_will_be_scored_under(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    """D-032: nothing may present a probability without its calibration state.

    Written when that state was `is_provisional=True` with no corpus hash. Chapter 14 fitted the
    artifact and deleted the provisional constants (D-080), so the same rule now has the opposite
    expected values: a fitted run, naming the corpus it was fitted on. The audit still has to cite
    one at the moment it is opened, which is the part that never changed.
    """
    deliver(client, pull_request_payload())

    audit = audits(db)[0]
    assert audit.calibration_run is not None
    assert audit.calibration_run.is_provisional is False
    assert audit.calibration_run.corpus_hash == active_artifact().corpus_hash
    assert audit.prior_probability == pytest.approx(active_artifact().base_rate)


def test_the_response_is_well_inside_the_three_second_budget(
    client: TestClient, known_repo: Repository
) -> None:
    """§6 budgets under 3s against GitHub's 10s hard limit. The endpoint does three round trips."""
    started = time.monotonic()
    response = deliver(client, pull_request_payload())
    elapsed = time.monotonic() - started

    assert response.status_code == 202
    assert elapsed < 3.0


def test_the_worker_is_told_nothing_but_an_id(
    client: TestClient, db: DbSession, known_repo: Repository, queue: FakeTaskQueue
) -> None:
    """D-041. Everything else is a row; a second copy in Redis can only disagree with the first."""
    deliver(client, pull_request_payload())

    assert len(queue.published) == 1
    assert queue.published[0] == audits(db)[0].id


@pytest.mark.parametrize("action", ["opened", "reopened", "synchronize"])
def test_the_three_code_changing_actions_are_analysed(
    client: TestClient, db: DbSession, known_repo: Repository, action: str
) -> None:
    response = deliver(client, pull_request_payload(action=action))

    assert response.status_code == 202
    assert len(audits(db)) == 1


@pytest.mark.parametrize("action", ["edited", "labeled", "closed", "ready_for_review"])
def test_actions_that_change_no_code_are_acknowledged_and_dropped(
    client: TestClient, db: DbSession, known_repo: Repository, queue: FakeTaskQueue, action: str
) -> None:
    """200, not an error: a retry would take this same branch again and eventually GitHub disables
    the webhook."""
    response = deliver(client, pull_request_payload(action=action))

    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
    assert audits(db) == []
    assert queue.published == []


def test_a_ping_is_answered(client: TestClient) -> None:
    response = deliver(client, {"zen": "Non-blocking is better than blocking."}, event="ping")

    assert response.status_code == 200
    assert response.json()["status"] == "pong"


def test_an_unsubscribed_event_is_acknowledged(client: TestClient, db: DbSession) -> None:
    response = deliver(client, {"action": "created"}, event="issue_comment")

    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
    assert audits(db) == []


def test_a_pull_request_payload_missing_its_fields_is_a_bad_request(
    client: TestClient, known_repo: Repository
) -> None:
    response = deliver(client, {"action": "opened", "pull_request": {}})

    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Redelivery and supersession — D-034, D-038, D-039
# ---------------------------------------------------------------------------


def test_a_redelivered_webhook_does_not_open_a_second_audit(
    client: TestClient, db: DbSession, known_repo: Repository, queue: FakeTaskQueue
) -> None:
    """GitHub delivers at least once. The same delivery id must find the audit it already made."""
    first = deliver(client, pull_request_payload(), delivery="delivery-42")
    second = deliver(client, pull_request_payload(), delivery="delivery-42")

    assert first.status_code == 202
    assert second.status_code == 202
    assert second.json()["status"] == "duplicate"
    assert second.json()["audit_id"] == first.json()["audit_id"]
    assert len(audits(db)) == 1
    assert len(queue.published) == 1


def test_a_push_supersedes_the_audit_for_the_previous_head(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    """D-034: findings about a commit that is no longer at the head describe code nobody can see."""
    deliver(client, pull_request_payload(head_sha="a" * 40), delivery="d-1")
    response = deliver(
        client, pull_request_payload(action="synchronize", head_sha="f" * 40), delivery="d-2"
    )

    assert response.json()["superseded"] == 1
    assert len(audits(db)) == 2
    old = audit_for_head(db, "a" * 40)
    new = audit_for_head(db, "f" * 40)
    assert old.status is AuditStatus.SUPERSEDED
    assert old.error_reason is not None and "f" * 40 in old.error_reason
    assert new.status is AuditStatus.QUEUED


def test_superseding_is_not_a_failure(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    """A red dashboard for every second push would make the real error rate unreadable (D-039)."""
    deliver(client, pull_request_payload(head_sha="a" * 40), delivery="d-1")
    deliver(client, pull_request_payload(action="synchronize", head_sha="f" * 40), delivery="d-2")

    assert audit_for_head(db, "a" * 40).status is not AuditStatus.FAILED


def test_a_push_to_another_pull_request_supersedes_nothing(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    deliver(client, pull_request_payload(pr_number=7), delivery="d-1")
    response = deliver(client, pull_request_payload(pr_number=8), delivery="d-2")

    assert response.json()["superseded"] == 0
    assert all(row.status is AuditStatus.QUEUED for row in audits(db))


# ---------------------------------------------------------------------------
# What a verified delivery may and may not write
# ---------------------------------------------------------------------------


def test_a_repository_nobody_has_signed_in_to_see_is_still_analysed(
    client: TestClient, db: DbSession, queue: FakeTaskQueue
) -> None:
    """Installed but never synced. Dropping these would silently review nothing at all.

    The payload carries a valid HMAC, so this is GitHub speaking rather than a user — the D-037
    reasoning does not apply, and no session gains visibility of anything here.
    """
    response = deliver(client, pull_request_payload(repo_id=7777, full_name="acme/brand-new"))

    assert response.status_code == 202
    repo = db.get(Repository, 7777)
    assert repo is not None
    assert repo.full_name == "acme/brand-new"
    assert len(queue.published) == 1


def test_a_pull_request_cannot_clear_a_suspension(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    """A `pull_request` payload carries no `suspended_at`, so writing one would always clear it."""
    installation = db.get(Installation, INSTALLATION_ID)
    assert installation is not None
    installation.suspended_at = datetime(2026, 6, 1, tzinfo=UTC)
    db.flush()

    deliver(client, pull_request_payload())

    db.refresh(installation)
    assert installation.suspended_at is not None


def test_a_pull_request_cannot_re_enable_analysis_somebody_turned_off(
    client: TestClient, db: DbSession, known_repo: Repository, queue: FakeTaskQueue
) -> None:
    known_repo.analysis_enabled = False
    db.flush()

    response = deliver(client, pull_request_payload())

    db.refresh(known_repo)
    assert response.status_code == 200
    assert response.json()["status"] == "analysis_disabled"
    assert known_repo.analysis_enabled is False
    assert audits(db) == []
    assert queue.published == []


# ---------------------------------------------------------------------------
# Installation events — D-034 subscribes to them, so they have to do something
# ---------------------------------------------------------------------------


def test_an_installation_is_recorded_with_its_repositories(
    client: TestClient, db: DbSession
) -> None:
    response = deliver(
        client,
        installation_payload(
            repositories=[{"id": 4242, "full_name": "acme/new-service", "private": False}]
        ),
        event="installation",
    )

    assert response.status_code == 200
    assert db.get(Installation, INSTALLATION_ID) is not None
    assert db.get(Repository, 4242) is not None


def test_a_suspension_is_recorded(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    response = deliver(
        client,
        installation_payload(action="suspend", suspended_at="2026-06-01T00:00:00Z"),
        event="installation",
    )

    assert response.status_code == 200
    installation = db.get(Installation, INSTALLATION_ID)
    assert installation is not None and installation.suspended_at is not None


def test_an_unsuspension_clears_it(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    deliver(
        client,
        installation_payload(action="suspend", suspended_at="2026-06-01T00:00:00Z"),
        event="installation",
    )
    deliver(client, installation_payload(action="unsuspend"), event="installation")

    installation = db.get(Installation, INSTALLATION_ID)
    assert installation is not None and installation.suspended_at is None


def test_uninstalling_removes_the_installation_and_its_repositories(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    """The grant is gone. Keeping the rows would leave the dashboard listing repositories the App
    can no longer read, which D-035 exists to prevent."""
    response = deliver(client, installation_payload(action="deleted"), event="installation")

    # The repository row goes by ON DELETE CASCADE in Postgres, which the session's identity map
    # knows nothing about — without expiring it, `get` answers from memory and the cascade is
    # invisible.
    db.expire_all()
    assert response.status_code == 200
    assert db.get(Installation, INSTALLATION_ID) is None
    assert db.get(Repository, REPO_ID) is None


def test_repositories_added_to_an_installation_are_recorded(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    response = deliver(
        client,
        {
            "action": "added",
            "installation": {"id": INSTALLATION_ID},
            "repositories_added": [{"id": 6001, "full_name": "acme/added", "private": True}],
            "repositories_removed": [],
        },
        event="installation_repositories",
    )

    assert response.status_code == 200
    assert db.get(Repository, 6001) is not None


def test_repositories_removed_from_an_installation_are_dropped(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    response = deliver(
        client,
        {
            "action": "removed",
            "installation": {"id": INSTALLATION_ID},
            "repositories_added": [],
            "repositories_removed": [{"id": REPO_ID, "full_name": REPO_FULL_NAME}],
        },
        event="installation_repositories",
    )

    db.expire_all()
    assert response.json()["removed"] == 1
    assert db.get(Repository, REPO_ID) is None


def test_a_removal_cannot_reach_another_installations_repository(
    client: TestClient, db: DbSession, known_repo: Repository
) -> None:
    """The delete is scoped by installation as well as by id — one verification bug away from
    otherwise being able to remove somebody else's rows."""
    upsert_installation(
        db, installation_id=9999, account_login="other", account_type="Organization"
    )
    db.flush()

    response = deliver(
        client,
        {
            "action": "removed",
            "installation": {"id": 9999},
            "repositories_removed": [{"id": REPO_ID, "full_name": REPO_FULL_NAME}],
        },
        event="installation_repositories",
    )

    assert response.json()["removed"] == 0
    assert db.get(Repository, REPO_ID) is not None


# ---------------------------------------------------------------------------
# When the broker is down
# ---------------------------------------------------------------------------


def test_a_broker_failure_leaves_the_audit_recorded(
    client: TestClient, db: DbSession, known_repo: Repository, queue: FakeTaskQueue
) -> None:
    """Commit first, publish second. An audit nothing was told about is diagnosable; a task
    pointing at a row that was rolled back is not."""
    queue.failing = True

    response = deliver(client, pull_request_payload())

    assert response.status_code == 503
    rows = audits(db)
    assert len(rows) == 1
    assert rows[0].status is AuditStatus.QUEUED


def test_a_redelivery_after_a_broker_failure_publishes_the_same_audit(
    client: TestClient, db: DbSession, known_repo: Repository, queue: FakeTaskQueue
) -> None:
    """Which is why the 503 is safe: GitHub retries, and `delivery_id` finds the existing row.

    Note what this does *not* do — it does not publish again, because the duplicate branch returns
    before the enqueue. Recovering a stranded audit is a sweep's job, not a redelivery's; the row
    is queued and visible, which is what Chapter 15 needs to surface it.
    """
    queue.failing = True
    deliver(client, pull_request_payload(), delivery="d-1")

    queue.failing = False
    response = deliver(client, pull_request_payload(), delivery="d-1")

    assert response.status_code == 202
    assert response.json()["status"] == "duplicate"
    assert len(audits(db)) == 1
