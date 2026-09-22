"""The host half of the probe: what it takes on trust from the guest, and what it does not.

The guest shares an address space with code from a pull request. It cannot *do* anything -
that is `test_sandbox.py`'s subject - but it can *say* anything, and a trace is a message
from inside the blast radius. These tests are about the second problem.

None of them need an interpreter. They feed `_read` and `_extract` the traces a hostile
guest would write, which is the only way to test the gate: a real guest running the real
driver cannot be made to lie, so it cannot demonstrate that lying fails.
"""

from __future__ import annotations

import json

from agent_runtime.probe import (
    MAX_OBSERVATIONS,
    ProbeOutcome,
    _extract,
    _read,
    aliases_for,
    driver_source,
)
from agent_runtime.sinks import SINKS
from codesheriff_contracts import ChangeUnit

SENTINEL = "##CODESHERIFF-TRACE-deadbeef##"


def unit(**overrides: object) -> ChangeUnit:
    fields: dict[str, object] = {
        "unit_id": "u1",
        "repo": "o/r",
        "language": "python",
        "file": "app/x.py",
        "symbol": "f",
        "post_src": "def f(a):\n    return a\n",
        "base_sha": "b" * 40,
        "head_sha": "h" * 40,
    }
    fields.update(overrides)
    return ChangeUnit(**fields)  # type: ignore[arg-type]


def trace(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "outcome": "completed",
        "hits": [],
        "near_misses": [],
        "guarded": [],
        "calls": 3,
        "detail": "",
    }
    body.update(overrides)
    return body


# -- import aliases --------------------------------------------------------------------


def test_a_from_import_binds_the_bare_name_to_its_full_path() -> None:
    """`from flask import send_file` makes the bare `send_file` a CWE-22 sink.

    Most path sinks in real code arrive this way. Without this the probe would watch for
    `flask.send_file` while the unit calls `send_file`, and see nothing.
    """
    assert aliases_for(unit(imports=["flask.send_file"]))["send_file"] == "flask.send_file"


def test_a_plain_module_import_maps_to_itself() -> None:
    assert aliases_for(unit(imports=["os"])) == {"os": "os"}


def test_a_submodule_import_keeps_its_root() -> None:
    """`import urllib.request` binds `urllib`, and `urllib.request.urlopen` resolves through it."""
    table = aliases_for(unit(imports=["urllib.request"]))

    assert table["urllib"] == "urllib"
    assert table["request"] == "urllib.request"


def test_an_empty_import_is_ignored() -> None:
    assert aliases_for(unit(imports=["", "   "])) == {}


# -- finding the trace -----------------------------------------------------------------


def test_the_trace_is_found_behind_the_sentinel() -> None:
    stdout = f"some output from the unit\n{SENTINEL}{json.dumps(trace())}\n"

    assert _extract(stdout, SENTINEL) is not None


def test_output_with_no_sentinel_yields_nothing() -> None:
    assert _extract('{"outcome": "completed", "hits": []}', SENTINEL) is None


def test_a_unit_that_prints_a_forged_trace_cannot_displace_the_real_one() -> None:
    """The unit printed a full detection before the driver wrote the real, empty trace.

    The last occurrence wins, and the unit cannot write after the driver because the driver
    writes on its way out. Guessing the sentinel is the only remaining route, and it is 128
    bits from `secrets` per request - the same decision, for the same reason, as the
    semantic agent's prompt delimiter (D-066).
    """
    forged = json.dumps(trace(hits=[{"sink": "os.system", "cwe": "CWE-78", "position": "arg0"}]))
    real = json.dumps(trace())
    stdout = f"{SENTINEL}{forged}\n{SENTINEL}{real}\n"

    found = _extract(stdout, SENTINEL)

    assert found is not None
    assert found["hits"] == []


def test_a_guessed_sentinel_does_not_match_this_run() -> None:
    stdout = f"##CODESHERIFF-TRACE-0000##{json.dumps(trace(hits=[{'sink': 'eval'}]))}"

    assert _extract(stdout, SENTINEL) is None


def test_unparsable_output_behind_the_sentinel_is_not_a_trace() -> None:
    assert _extract(f"{SENTINEL}not json at all", SENTINEL) is None


def test_a_json_scalar_behind_the_sentinel_is_not_a_trace() -> None:
    """`json.loads("7")` succeeds. A trace has to be an object, not merely valid JSON."""
    assert _extract(f"{SENTINEL}7", SENTINEL) is None


# -- the gate on what the guest reported -------------------------------------------------


def test_a_sink_this_table_does_not_hold_is_dropped() -> None:
    """The guest cannot invent a finding by naming an operation nobody registered.

    This is the hallucination gate `semantic_agent` applies to model output, applied to the
    other component here that processes attacker-adjacent text.
    """
    result = _read(trace(hits=[{"sink": "os.definitely_not_real", "cwe": "CWE-78"}]), None)

    assert result.observations == ()


def test_the_cwe_comes_from_our_table_not_the_guest() -> None:
    """A guest that relabels a path traversal as a command injection is ignored, not obeyed.

    The CWE decides which finding this evidence joins and which likelihood ratio it earns.
    Taking it from the guest would let analysed code choose its own charge sheet.
    """
    result = _read(trace(hits=[{"sink": "os.system", "cwe": "CWE-22", "position": "arg0"}]), None)

    assert [o.cwe for o in result.observations] == ["CWE-78"]


def test_one_sink_and_position_is_reported_once() -> None:
    """A sink reached in a loop is one finding, not two hundred."""
    hit = {"sink": "eval", "cwe": "CWE-94", "position": "arg0"}

    result = _read(trace(hits=[hit] * 50), None)

    assert len(result.observations) == 1


def test_the_observation_count_is_capped() -> None:
    hits = [
        {"sink": sink.name, "cwe": sink.cwe, "position": f"arg{i}"} for i, sink in enumerate(SINKS)
    ]

    result = _read(trace(hits=hits * 3), None)

    assert len(result.observations) <= MAX_OBSERVATIONS


def test_a_guarded_observation_is_kept_but_marked() -> None:
    """It is not dropped: the agent needs it to abstain rather than fall silent (D-079)."""
    hit = {"sink": "requests.post", "cwe": "CWE-918", "position": "arg0", "guarded": ["tk1z"]}

    result = _read(trace(hits=[hit]), None)

    assert result.guarded and not result.sound


def test_an_unknown_outcome_is_a_probe_error_not_a_completion() -> None:
    """An outcome this host does not recognise must never read as 'ran and found nothing'."""
    assert _read(trace(outcome="everything_is_fine"), None).outcome is ProbeOutcome.PROBE_ERROR


def test_a_non_list_hits_field_is_survivable() -> None:
    assert _read(trace(hits="not a list"), None).observations == ()


def test_a_non_integer_call_count_does_not_propagate() -> None:
    assert _read(trace(calls="lots"), None).calls == 0


# -- the driver is data, not an import ----------------------------------------------------


def test_the_driver_is_read_as_text() -> None:
    """It targets a different interpreter and is never imported here (D-078)."""
    source = driver_source()

    assert "class Probe(str)" in source
    assert "def main()" in source


def test_the_driver_imports_nothing_outside_the_guest_standard_library() -> None:
    """The guest has no site-packages and no filesystem to install into.

    A driver that grew a third-party import would fail inside the sandbox with a traceback
    on stderr and no trace on stdout, which the agent would report as `probe_error` on every
    single unit - a silent, total outage that this catches at the source.
    """
    allowed = {"ast", "json", "sys", "traceback", "builtins"}
    imported = {
        line.split()[1].split(".")[0]
        for line in driver_source().splitlines()
        if line.strip().startswith("import ") and not line.strip().startswith("import(")
    }

    assert imported <= allowed, f"driver imports {imported - allowed} which the guest lacks"
