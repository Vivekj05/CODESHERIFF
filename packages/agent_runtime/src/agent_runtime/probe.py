"""Driving one unit through the sandbox, and reading back what it did.

The host half of the probe. It builds the payload, runs the guest once, finds the trace in
whatever the guest wrote, and **re-derives every fact it is going to act on from its own
tables** rather than from the guest's report.

That last part is the point of this module. The guest shares an address space with code
from a pull request. It is isolated from the host, so it cannot do anything, but it can
*say* anything - and a trace is a message from inside the blast radius. So:

* The trace is located by a **per-request sentinel** generated with `secrets`, not by
  parsing the last line of stdout. The unit can print, and a unit that has read this file
  would print a trace of its own (D-066 is the same decision in the semantic agent's
  prompt, for the same reason).
* A reported sink name that is **not in `SINKS`** is dropped, and so is a reported CWE that
  is not the one this table gives that sink. The guest cannot invent a finding, and it
  cannot relabel a real one as a different CWE, because neither field is taken on trust.
  This is the hallucination gate `semantic_agent` applies to model output, applied to the
  one other component here that processes attacker-adjacent text.
* No free text from the guest reaches an explanation or an artifact. Everything published
  comes from the sink table, which is ours.
"""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from agent_runtime.sandbox import SandboxRun, SandboxStatus, WasmSandbox
from agent_runtime.sinks import PROPAGATORS, SINKS
from codesheriff_contracts import ChangeUnit

logger = logging.getLogger(__name__)

_DRIVER = Path(__file__).with_name("guest") / "driver.py"

MAX_OBSERVATIONS = 32
"""Cap on observations carried out of one run. Artifacts are persisted (D-027), and a unit
that reaches a sink in a loop describes one finding, not two hundred."""


class ProbeOutcome(StrEnum):
    """How the probe ended - the host's reading, not the guest's word for it."""

    COMPLETED = "completed"
    """The function ran to its own return."""

    RAISED = "raised"
    """The function raised before returning. The run explored less of it than it looks."""

    NO_ENTRYPOINT = "no_entrypoint"
    """Nothing here to drive: unparsable, no such symbol, or an `async def`."""

    PROBE_ERROR = "probe_error"
    """The driver itself failed. A bug here, not a fact about the unit."""

    UNREADABLE = "unreadable"
    """The guest produced no trace behind the sentinel."""

    FUEL_EXHAUSTED = "fuel_exhausted"
    TIMED_OUT = "timed_out"
    TRAPPED = "trapped"


@dataclass(frozen=True)
class Observation:
    """One dangerous operation an untrusted value actually reached.

    Every field is re-derived host-side from `SINKS`. Nothing here originated in the guest
    except the fact that the call happened and which argument carried the token.
    """

    sink: str
    cwe: str
    position: str
    composed: bool
    guarded: bool
    """The exact value that reached this sink was earlier handed to a call the probe could
    not evaluate. The observation stands, but it is not sound enough to report (D-079)."""


@dataclass(frozen=True)
class ProbeResult:
    """One unit, one run, everything the agent above is allowed to reason about."""

    outcome: ProbeOutcome
    observations: tuple[Observation, ...]
    detail: str
    calls: int
    run: SandboxRun | None

    @property
    def sound(self) -> tuple[Observation, ...]:
        """Observations no unevaluated guard stands in front of."""
        return tuple(o for o in self.observations if not o.guarded)

    @property
    def guarded(self) -> tuple[Observation, ...]:
        return tuple(o for o in self.observations if o.guarded)


@lru_cache(maxsize=1)
def driver_source() -> str:
    """The guest program, read once. Never imported - it targets another interpreter."""
    return _DRIVER.read_text(encoding="utf-8")


def aliases_for(unit: ChangeUnit) -> dict[str, str]:
    """Which fully qualified name each free name in the unit stands for.

    `ChangeUnit.imports` carries `flask.send_file`, so the bare `send_file` the unit calls
    is that sink and not some local helper. Without this the CWE-22 sinks behind a
    `from ... import ...` are invisible, which is most of them in real code.

    A name the unit's imports do not explain maps to itself, and a name that maps to
    nothing in `SINKS` is not a sink - there is no partial matching here (see `sinks.py`).
    """
    table: dict[str, str] = {}
    for imported in unit.imports:
        dotted = imported.strip()
        if not dotted:
            continue
        head = dotted.partition(".")[0]
        table.setdefault(head, head)
        bound = dotted.rpartition(".")[2]
        if bound and bound != head:
            table[bound] = dotted
    return table


def run_probe(unit: ChangeUnit, sandbox: WasmSandbox) -> ProbeResult:
    """Execute the unit once inside the sandbox and return what it reached."""
    sentinel = f"##CODESHERIFF-TRACE-{secrets.token_hex(16)}##"
    payload = {
        "sentinel": sentinel,
        "token_prefix": f"tk{secrets.token_hex(6)}n",
        "source": unit.post_src,
        "symbol": unit.symbol or "",
        "aliases": aliases_for(unit),
        "sinks": [sink.as_payload() for sink in SINKS],
        "propagators": sorted(PROPAGATORS),
    }

    run = sandbox.run(
        argv=["python", "-I", "-B", "-c", driver_source()],
        stdin_bytes=json.dumps(payload).encode("utf-8"),
    )

    if run.status is SandboxStatus.FUEL_EXHAUSTED:
        return _empty(ProbeOutcome.FUEL_EXHAUSTED, run, run.detail)
    if run.status is SandboxStatus.TIMED_OUT:
        return _empty(ProbeOutcome.TIMED_OUT, run, run.detail)
    if run.status is SandboxStatus.TRAPPED:
        return _empty(ProbeOutcome.TRAPPED, run, run.detail)

    trace = _extract(run.stdout, sentinel)
    if trace is None:
        # A guest that exited non-zero without a trace failed before it could write one;
        # stderr holds the guest's traceback and is logged, never published.
        logger.info("no trace behind sentinel for unit %s: %s", unit.unit_id, run.stderr[-400:])
        return _empty(ProbeOutcome.UNREADABLE, run, run.detail or "no trace")

    return _read(trace, run)


def _empty(outcome: ProbeOutcome, run: SandboxRun, detail: str) -> ProbeResult:
    return ProbeResult(outcome=outcome, observations=(), detail=detail[:300], calls=0, run=run)


def _extract(stdout: str, sentinel: str) -> dict[str, object] | None:
    """The trace behind the sentinel, or nothing.

    The **last** occurrence wins. A unit that echoed a forged sentinel would have to do so
    after the driver wrote the real one, which it cannot: the driver writes on the way out.
    """
    index = stdout.rfind(sentinel)
    if index < 0:
        return None
    try:
        parsed = json.loads(stdout[index + len(sentinel) :].strip())
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _read(trace: dict[str, object], run: SandboxRun) -> ProbeResult:
    """Turn a guest trace into observations, re-deriving every published field."""
    by_name = {sink.name: sink for sink in SINKS}
    observations: list[Observation] = []
    seen: set[tuple[str, str, str]] = set()

    raw = trace.get("hits")
    for hit in raw if isinstance(raw, list) else []:
        if not isinstance(hit, dict) or len(observations) >= MAX_OBSERVATIONS:
            continue
        sink = by_name.get(str(hit.get("sink", "")))
        if sink is None:
            # The guest named something this table does not hold. It cannot invent a
            # finding, so this is dropped rather than reported under an unknown sink.
            logger.warning("probe reported unknown sink %r; dropped", hit.get("sink"))
            continue
        position = str(hit.get("position", ""))[:32]
        key = (sink.name, sink.cwe, position)
        if key in seen:
            continue
        seen.add(key)
        observations.append(
            Observation(
                sink=sink.name,
                # From our table, never from the guest: relabelling a path traversal as a
                # command injection must not be something the analysed code can do.
                cwe=sink.cwe,
                position=position,
                composed=bool(hit.get("composed")),
                guarded=bool(hit.get("guarded")),
            )
        )

    outcome = _outcome(str(trace.get("outcome", "")))
    calls = trace.get("calls")
    return ProbeResult(
        outcome=outcome,
        observations=tuple(observations),
        detail=str(trace.get("detail", ""))[:120],
        calls=calls if isinstance(calls, int) else 0,
        run=run,
    )


def _outcome(reported: str) -> ProbeOutcome:
    try:
        return ProbeOutcome(reported)
    except ValueError:
        return ProbeOutcome.PROBE_ERROR
