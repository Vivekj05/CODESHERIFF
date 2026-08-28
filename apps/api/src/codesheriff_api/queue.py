"""Handing an audit to the worker.

**The API does not import the worker.** `import-linter` puts `codesheriff_api` and
`codesheriff_worker` on the same layer, so neither can import the other, and the task is therefore
addressed by name rather than by reference (D-040). That constraint is doing real work: an import
would give the edge process the agents, the LLM client and the whole analysis dependency tree, and
the first thing anyone would then do is call a pipeline function directly — which is `AUDIT.md` 4.3
coming back.

**The message carries an id, never a payload** (D-041). Everything the worker needs is already a
row in Postgres. A second copy in Redis can disagree with the first, and it would put
attacker-authored GitHub JSON into a broker that has no schema, no constraints and no retention
policy.
"""

from __future__ import annotations

import logging
import uuid
from functools import lru_cache
from typing import TYPE_CHECKING, Annotated, Protocol

from fastapi import Depends

from codesheriff_api.config import ApiConfig
from codesheriff_api.deps import get_config

if TYPE_CHECKING:
    from celery import Celery

logger = logging.getLogger(__name__)

RUN_AUDIT_TASK = "codesheriff.run_audit"
"""Must equal `codesheriff_worker.tasks.RUN_AUDIT_TASK`.

Duplicated rather than imported, because the layers contract forbids the import. The two constants
are asserted equal in `apps/api/tests/test_task_name_contract.py`, which is allowed to import both
because it is a test rather than a module inside either package. A silent divergence here would
look exactly like a worker that is not running: deliveries accepted, audits queued, nothing ever
picked up.
"""


class QueueError(RuntimeError):
    """The broker would not take the task."""


class TaskQueue(Protocol):
    """The one thing the edge asks of the queue."""

    def enqueue_audit(self, audit_id: uuid.UUID) -> None:
        """Ask a worker to run this audit. Raises `QueueError` if the broker refused."""
        ...


class CeleryTaskQueue:
    """The real queue, on Celery over Redis."""

    def __init__(self, config: ApiConfig) -> None:
        self._config = config

    def enqueue_audit(self, audit_id: uuid.UUID) -> None:
        client = _celery_client(
            self._config.celery_broker_url, self._config.enqueue_timeout_seconds
        )
        try:
            client.send_task(
                RUN_AUDIT_TASK,
                args=[str(audit_id)],
                queue=self._config.audit_queue_name,
            )
        except Exception as exc:
            raise QueueError(f"could not enqueue audit: {type(exc).__name__}") from exc


@lru_cache(maxsize=1)
def _celery_client(broker_url: str, timeout_seconds: float) -> Celery:
    """One Celery client per process, built on first use.

    Imported inside the function so that importing this module — which `main.py` does at startup —
    does not require a reachable broker. `/health` has to answer on a machine with nothing running.

    Every timeout here exists because of the 3s budget. Celery's defaults retry a publish several
    times with a widening interval, which against a dead Redis holds the request open long past the
    point where GitHub has given up. One quick retry, then fail and let GitHub's own redelivery be
    the recovery mechanism — the unique `delivery_id` is what makes that safe.
    """
    from celery import Celery

    client = Celery(broker=broker_url)
    client.conf.broker_transport_options = {
        "socket_timeout": timeout_seconds,
        "socket_connect_timeout": timeout_seconds,
    }
    client.conf.broker_connection_retry_on_startup = False
    client.conf.task_publish_retry_policy = {
        "max_retries": 1,
        "interval_start": 0.0,
        "interval_step": 0.2,
        "interval_max": 0.5,
    }
    # The edge never reads a result: an audit's state is the `audits` row, which the dashboard can
    # query and a human can read. A result backend would be a second, weaker copy of that with an
    # expiry on it.
    client.conf.task_ignore_result = True
    return client


def get_queue(config: Annotated[ApiConfig, Depends(get_config)]) -> TaskQueue:
    return CeleryTaskQueue(config)


QueueDep = Annotated[TaskQueue, Depends(get_queue)]
