"""The one thing the API and the worker share, asserted.

`import-linter` puts `codesheriff_api` and `codesheriff_worker` on the same layer, so neither can
import the other. The API therefore publishes the audit task **by name**, and that name is the
entire interface between the two processes — duplicated as a constant in each.

A duplicated constant needs something watching it. If the two drift apart, nothing raises: the API
keeps accepting deliveries and queueing audits, the worker keeps waiting on a task nobody sends,
and the symptom is indistinguishable from a worker that is not running. This test is what turns
that into a failing build.

It lives in a test rather than in either package because a test is not part of the import graph the
layers contract constrains — which is exactly why it is allowed to see both sides.
"""

from __future__ import annotations

from codesheriff_api.queue import RUN_AUDIT_TASK as API_TASK_NAME
from codesheriff_worker.tasks import RUN_AUDIT_TASK as WORKER_TASK_NAME


def test_the_api_and_the_worker_agree_on_the_task_name() -> None:
    assert API_TASK_NAME == WORKER_TASK_NAME


def test_the_worker_registered_the_task_under_that_name() -> None:
    """Naming it in a constant is not the same as registering it. `@app.task(name=...)` is what
    binds the two, and forgetting the argument silently registers it under a module path instead."""
    from codesheriff_worker.celery_app import app

    assert API_TASK_NAME in app.tasks
