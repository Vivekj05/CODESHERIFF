"""The runtime witness: what the code actually did, not what it could be shown to do.

Its basis for a decision is **direct observation**. The other three witnesses reason about
source text - a reachability proof over a def-use graph, a model's reading of intent, this
repository's own precedent. This one runs the function and reports which dangerous
operations an untrusted value reached. That is a different kind of claim, and it fails
differently: it sees through the dynamic dispatch and string-built call names a syntactic
analysis cannot follow, and it sees nothing at all when the function will not run.

**It abstains widely, and that is the design.** Most changed functions do not execute in
isolation. A unit with no callable entrypoint, one that raises before reaching anything, one
whose value passed through a guard the probe could not evaluate - each is an abstention
under its own reason, at a likelihood ratio of exactly 1.0. `PLAN.md` says this in advance
so that a low detection count is not later mistaken for a defect: an abstention costs the
posterior nothing, and a witness that guessed instead would cost it everything.

**Isolation first, detection second.** `sandbox.py` is the deliverable this agent is built
on top of, and it would be worth having if this file did not exist. Running a pull request's
code is how continuous integration systems get compromised; the sandbox is the answer to
that whether or not the observation above it ever fires.

**What it never claims.** Five CWEs, listed in `config.COVERED_CWES`, and the five it leaves
out are left out for reasons the module records. SQL injection and cross-site scripting are
absent because their sinks are methods on objects the probe itself fabricated, so any
"observation" would be the harness observing itself - the correlation D-011 exists to
prevent, wearing the costume of a fourth witness.
"""

from __future__ import annotations

import logging

from agent_runtime.config import AGENT_ID, AGENT_VERSION, COVERED_CWES, RuntimeConfig
from agent_runtime.interpreter import InterpreterUnavailableError, locate
from agent_runtime.probe import Observation, ProbeOutcome, ProbeResult, run_probe
from agent_runtime.sandbox import SandboxPolicy, SandboxUnavailableError, WasmSandbox
from codesheriff_contracts import Artifact, ChangeUnit, Evidence

logger = logging.getLogger(__name__)

OBSERVED_SCORE = 0.85
"""The raw score of a sound observation. Provisional, and singular (D-010).

There is one tier because there is one kind of fact here: the untrusted value reached the
dangerous argument, or it did not. The structural and semantic witnesses grade themselves
because a taint path can be longer or shorter and a model can be more or less sure; an
execution either happened or it did not. `WitnessRatios.for_score` has medium and low tiers
this witness never uses, and Chapter 14 may find it wants them - inventing a spread here to
fill them in would be inventing a confidence the probe does not measure.
"""

MAX_ARTIFACT_OBSERVATIONS = 4
"""How many observations to name in an artifact. Artifacts are persisted (D-027), and a
reader checking the claim needs the operations that were reached, not every call."""


class RuntimeAgent:
    """Software-fault-isolated dynamic analysis. Never raises; abstains with a reason."""

    def __init__(
        self, config: RuntimeConfig | None = None, sandbox: WasmSandbox | None = None
    ) -> None:
        self.config = config or RuntimeConfig.load()
        self.agent_id = AGENT_ID
        self.agent_version = AGENT_VERSION
        self._sandbox = sandbox
        self._unavailable: tuple[str, str] | None = None

    # -- the sandbox ---------------------------------------------------------------------

    def sandbox(self) -> WasmSandbox:
        """The compiled interpreter, built once and reused across units.

        Compiling the 26 MB CPython module costs seconds and instantiating it costs
        milliseconds, so this is built lazily and kept. Each unit still runs in a fresh
        `Store`, which is where guest state lives - two units cannot see each other.
        """
        if self._sandbox is None:
            path = locate(self.config)
            self._sandbox = WasmSandbox(
                module_path=path,
                policy=SandboxPolicy(
                    fuel=self.config.fuel,
                    wall_clock_seconds=self.config.wall_clock_seconds,
                    memory_bytes=self.config.memory_bytes,
                ),
            )
            logger.info("runtime.sfi sandbox ready: %s", path)
        return self._sandbox

    # -- the contract --------------------------------------------------------------------

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        """This agent's statement about one unit. Always at least one, never an exception.

        Runs blind (D-008): one argument, no anchors. Nothing here is told what another
        witness found, which is what keeps the four likelihood ratios multipliable.
        """
        try:
            return self._analyse(unit)
        except Exception as exc:
            logger.exception("unhandled exception in runtime.sfi on unit %s", unit.unit_id)
            return [self._abstain(unit, "runtime_error", f"{type(exc).__name__}: {exc}"[:400])]

    def _analyse(self, unit: ChangeUnit) -> list[Evidence]:
        if unit.language.lower() not in {"python", "py"}:
            return [
                self._abstain(
                    unit,
                    "unsupported_language",
                    f"The sandbox runs a CPython build; {unit.language} needs its own guest.",
                )
            ]

        if unit.symbol is None or unit.symbol == "<module>":
            # A module-scope unit (D-049) has no function to call. Executing the module body
            # instead would be a different analysis of a different thing, and its findings
            # would not be about the changed function this evidence is keyed to.
            return [
                self._abstain(
                    unit,
                    "no_safe_entrypoint",
                    "The unit is module scope, so there is no function to drive.",
                )
            ]

        if len(unit.post_src.encode("utf-8")) > self.config.max_unit_bytes:
            return [
                self._abstain(
                    unit,
                    "unit_too_large",
                    f"{len(unit.post_src)} characters exceeds the "
                    f"{self.config.max_unit_bytes} byte budget (D-015).",
                )
            ]

        try:
            sandbox = self.sandbox()
        except InterpreterUnavailableError as exc:
            # The expected state on a machine that has not fetched the artifact. Distinct
            # reasons for "absent" and "wrong digest", because they need different fixes.
            logger.info("runtime.sfi unavailable: %s", exc)
            return [self._abstain(unit, exc.reason, str(exc)[:400])]
        except SandboxUnavailableError as exc:
            return [self._abstain(unit, "sandbox_unavailable", str(exc)[:400])]

        return self._interpret(unit, run_probe(unit, sandbox))

    # -- reading the run -----------------------------------------------------------------

    def _interpret(self, unit: ChangeUnit, result: ProbeResult) -> list[Evidence]:
        """One run becomes evidence. Detections first; every other path is a statement too."""
        if result.sound:
            return self._detections(unit, result)

        if result.guarded:
            # The value reached the sink, but it had already been handed to a call the probe
            # could not evaluate - which may well have been the validator that makes this
            # safe. Reporting would be a false positive on exactly the well-guarded code;
            # staying silent would argue, below 1.0, that guarded code is clean. Neither is
            # honest, so the witness says it could not tell (D-079).
            return [
                self._abstain(
                    unit,
                    "guard_unresolved",
                    "An untrusted value reached a dangerous operation, but it had first "
                    "passed through a call this probe cannot evaluate, so the observation "
                    "is not sound enough to report.",
                )
            ]

        return [self._non_detection(unit, result)]

    def _detections(self, unit: ChangeUnit, result: ProbeResult) -> list[Evidence]:
        """One detection per CWE observed, keyed the way every other witness keys.

        `unit.key_for(cwe)` and nothing else (D-004). A runtime observation of the same bug
        the taint engine proved has to land on the same finding, or the Bayesian engine
        never performs an update and the whole thesis stops working.
        """
        by_cwe: dict[str, list[Observation]] = {}
        for observation in result.sound:
            by_cwe.setdefault(observation.cwe, []).append(observation)

        evidence: list[Evidence] = []
        for cwe, observations in sorted(by_cwe.items()):
            if cwe not in COVERED_CWES:  # pragma: no cover - sinks.py checks this at import
                continue
            evidence.append(
                Evidence.detection(
                    agent_id=AGENT_ID,
                    agent_version=AGENT_VERSION,
                    unit_id=unit.unit_id,
                    finding_key=unit.key_for(cwe),
                    cwe=cwe,
                    raw_score=OBSERVED_SCORE,
                    explanation=self._explain(observations),
                    artifacts=[
                        Artifact(
                            artifact_type="runtime_observation",
                            content={
                                "outcome": result.outcome.value,
                                "calls": result.calls,
                                "observations": [
                                    {
                                        "sink": o.sink,
                                        "position": o.position,
                                        "composed": o.composed,
                                    }
                                    for o in observations[:MAX_ARTIFACT_OBSERVATIONS]
                                ],
                            },
                        )
                    ],
                )
            )
        return evidence

    def _explain(self, observations: list[Observation]) -> str:
        """Prose assembled entirely from our own sink table.

        No substring of this sentence comes from the unit, the guest's trace or a model.
        The sink names are `sinks.py`'s, the verbs are this method's, and the numbers are
        counts. That is what makes it safe to publish to a pull request comment without a
        screening pass of the kind `semantic_agent` needs (D-067).
        """
        names = sorted({o.sink for o in observations})
        listed = ", ".join(names[:3]) + (", ..." if len(names) > 3 else "")
        return (
            f"Executed the function in a WebAssembly sandbox with every parameter bound to "
            f"a distinct untrusted value. That value reached {listed} "
            f"({len(observations)} observation{'s' if len(observations) != 1 else ''})."
        )

    def _non_detection(self, unit: ChangeUnit, result: ProbeResult) -> Evidence:
        """Nothing was reached. Which of the three things that can mean, though?"""
        if result.outcome is ProbeOutcome.COMPLETED:
            # The one path that earns SILENCE: the function ran to its own return, with
            # untrusted values in every parameter, and reached nothing dangerous. That is
            # evidence of absence and is allowed to push a posterior down - across
            # COVERED_CWES only, never the five this witness cannot see (D-006).
            return Evidence.silence(
                agent_id=AGENT_ID,
                agent_version=AGENT_VERSION,
                unit_id=unit.unit_id,
                covered_cwes=COVERED_CWES,
                explanation=(
                    "Executed the function to completion in a WebAssembly sandbox with "
                    "untrusted values in every parameter; no dangerous operation was "
                    f"reached across {result.calls} observed calls."
                ),
            )

        reason, detail = _ABSTENTIONS.get(
            result.outcome, ("probe_error", "The probe did not produce a usable run.")
        )
        return self._abstain(unit, reason, detail)

    def _abstain(self, unit: ChangeUnit, reason: str, detail: str) -> Evidence:
        return Evidence.abstention(
            agent_id=AGENT_ID,
            agent_version=AGENT_VERSION,
            unit_id=unit.unit_id,
            reason=reason,
            explanation=detail,
        )


_ABSTENTIONS: dict[ProbeOutcome, tuple[str, str]] = {
    ProbeOutcome.RAISED: (
        "unit_raised",
        "The function raised before reaching any dangerous operation. A run that ended in "
        "an exception explored less of the function than one that returned, so this is not "
        "silence about the code - it is a run that did not finish looking.",
    ),
    ProbeOutcome.NO_ENTRYPOINT: (
        "no_safe_entrypoint",
        "Nothing in the unit could be driven: it did not parse, it defines no function "
        "under the changed symbol, or the function is a coroutine.",
    ),
    ProbeOutcome.FUEL_EXHAUSTED: (
        "fuel_exhausted",
        "The guest used its whole instruction budget. Deterministic - the same unit does "
        "this every time - and never a claim about the code.",
    ),
    ProbeOutcome.TIMED_OUT: (
        "timed_out",
        "The guest passed the wall-clock deadline and was interrupted.",
    ),
    ProbeOutcome.TRAPPED: (
        "sandbox_trapped",
        "The guest trapped. A capability it reached for does not exist inside the sandbox.",
    ),
    ProbeOutcome.UNREADABLE: (
        "probe_error",
        "The guest wrote no trace behind this run's sentinel.",
    ),
    ProbeOutcome.PROBE_ERROR: (
        "probe_error",
        "The probe driver failed inside the guest.",
    ),
}
"""Every non-detection outcome that is not SILENCE, with a distinct machine-readable reason.

Distinct, because these are the strings a later chapter groups runs by. `fuel_exhausted` and
`timed_out` describe a budget; `unit_raised` and `no_safe_entrypoint` describe the unit;
`sandbox_trapped` describes the sandbox. Collapsing them into one `analysis_failed` would
make the difference between "this agent needs more fuel" and "this code does not run"
invisible in exactly the data Chapter 14 reads.
"""
