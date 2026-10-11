"""The Celery application.

Started with:

    uv run celery -A codesheriff_worker.celery_app worker --loglevel=info --queues=audits

Every setting below is here because of something specific about this workload, not because it is a
common default.

`task_acks_late` — an audit takes minutes and the worker holding it can die. Acknowledging on
completion rather than on receipt means a killed worker's task is redelivered instead of lost. It
is only safe because the task is idempotent at the row level: `claim_audit` is a conditional
UPDATE, so a redelivered task for an audit already running does nothing.

`worker_prefetch_multiplier = 1` — the default reserves several tasks per process. For work
measured in seconds that is a throughput win; for work measured in minutes it means tasks sitting
in a dead worker's private queue while other workers idle.

`task_ignore_result` — an audit's state is the `audits` row. A result backend would be a second,
weaker copy with an expiry on it, and the dashboard already reads the first one.
"""

from __future__ import annotations

from celery import Celery

from codesheriff_worker.config import WorkerConfig

config = WorkerConfig.load()

app = Celery("codesheriff", broker=config.celery_broker_url)

app.conf.update(
    task_default_queue=config.audit_queue_name,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_ignore_result=True,
    task_serializer="json",
    accept_content=["json"],
    # Never unpickle. The broker carries an audit id and nothing else (D-041), and a pickle
    # deserialiser reachable from a queue is remote code execution for anyone who reaches Redis.
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

# Import for the side effect of registering the task. Last, because the task module reads `app`.
from codesheriff_worker import tasks as _tasks  # noqa: E402,F401
