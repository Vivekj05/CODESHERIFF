"""What the worker fetches, and what it declines to fetch.

The extraction itself is tested in `packages/engine`. These tests are about the half that talks to
GitHub: which blobs are asked for, at which refs, and how many API calls one pull request costs
against a 5,000/hour budget.
"""

from __future__ import annotations

from codesheriff_engine.extraction import ExtractionResult, SkipReason
from codesheriff_worker.github_gateway import PullRequestFile
from codesheriff_worker.pipeline import fetch_and_extract

from .conftest import FakeGitHubGateway

BASE = "b" * 40
HEAD = "h" * 40
REPO = "acme/payments-api"

BEFORE = "def charge(amount):\n    return gateway.pay(amount)\n"
AFTER = "import os\n\n\ndef charge(amount):\n    return os.system(f'pay {amount}')\n"


def run(gateway: FakeGitHubGateway) -> ExtractionResult:
    return fetch_and_extract(
        gateway,
        installation_id=9001,
        repo_full_name=REPO,
        pr_number=7,
        base_sha=BASE,
        head_sha=HEAD,
    )


def test_both_images_of_a_modified_file_are_fetched() -> None:
    """The diff is never parsed, so the pre-image has to come from the base commit. Fetching only
    the head would leave every line looking new."""
    gateway = FakeGitHubGateway(
        files=[PullRequestFile("billing/pay.py", "modified")],
        blobs={(HEAD, "billing/pay.py"): AFTER, (BASE, "billing/pay.py"): BEFORE},
    )

    result = run(gateway)

    assert gateway.fetched == [(HEAD, "billing/pay.py"), (BASE, "billing/pay.py")]
    unit = next(u for u in result.units if u.symbol == "charge")
    assert unit.pre_src == BEFORE.rstrip("\n")


def test_an_added_file_costs_one_call_not_two() -> None:
    """There is nothing on the base commit to ask for, and asking anyway spends an API call to be
    told 404 on every file of every new module."""
    gateway = FakeGitHubGateway(
        files=[PullRequestFile("billing/new.py", "added")],
        blobs={(HEAD, "billing/new.py"): AFTER},
    )

    run(gateway)

    assert gateway.fetched == [(HEAD, "billing/new.py")]


def test_a_renamed_file_reads_its_pre_image_from_the_old_path() -> None:
    """Reading the new path on the base commit would 404, the file would look new, and the audit
    would report a rename as a rewrite."""
    gateway = FakeGitHubGateway(
        files=[PullRequestFile("billing/pay.py", "renamed", previous_path="billing/old.py")],
        blobs={(HEAD, "billing/pay.py"): AFTER, (BASE, "billing/old.py"): BEFORE},
    )

    result = run(gateway)

    assert gateway.fetched == [(HEAD, "billing/pay.py"), (BASE, "billing/old.py")]
    unit = next(u for u in result.units if u.symbol == "charge")
    assert unit.pre_src is not None, "a rename is not a rewrite"


def test_a_deleted_file_costs_no_call_at_all() -> None:
    gateway = FakeGitHubGateway(files=[PullRequestFile("billing/gone.py", "removed")])

    result = run(gateway)

    assert gateway.fetched == []
    assert [s.reason for s in result.skipped] == [SkipReason.FILE_REMOVED]


def test_a_file_this_extractor_cannot_read_is_never_fetched() -> None:
    """One predicate decides what to fetch and what to extract. Two would drift, and the drift
    would show up as blobs fetched and thrown away — or files skipped without being considered."""
    gateway = FakeGitHubGateway(
        files=[PullRequestFile("ui/app.tsx", "modified"), PullRequestFile("logo.png", "modified")]
    )

    result = run(gateway)

    assert gateway.fetched == []
    assert {s.reason for s in result.skipped} == {SkipReason.LANGUAGE_UNSUPPORTED}


def test_an_unfetchable_head_blob_is_recorded_rather_than_dropped() -> None:
    """Oversized, binary or gone. The gateway answers None for all three; the audit records that
    the file was not analysed instead of counting it as clean."""
    gateway = FakeGitHubGateway(files=[PullRequestFile("billing/huge.py", "modified")], blobs={})

    result = run(gateway)

    assert result.units == []
    assert [s.reason for s in result.skipped] == [SkipReason.CONTENT_UNAVAILABLE]


def test_a_missing_base_blob_still_yields_a_unit() -> None:
    """A pre-image that cannot be read degrades to `pre_src=None` — everything reads as new. That
    is a worse analysis, not a failed one, and refusing to analyse the head would be worse still."""
    gateway = FakeGitHubGateway(
        files=[PullRequestFile("billing/pay.py", "modified")],
        blobs={(HEAD, "billing/pay.py"): AFTER},
    )

    result = run(gateway)

    unit = next(u for u in result.units if u.symbol == "charge")
    assert unit.pre_src is None


def test_a_pull_request_with_nothing_analysable_produces_no_units_and_says_so() -> None:
    gateway = FakeGitHubGateway(files=[PullRequestFile("README.md", "modified")])

    result = run(gateway)

    assert result.units == []
    assert result.skipped
