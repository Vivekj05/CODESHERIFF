"""What "verified" means, and — just as loadbearing — what it does not mean.

This module is the answer to §7 open question 3, "what does verified mean when a repository has no
test suite". The answer is that it means the same thing either way, because **CodeSheriff never
runs the repository's test suite** (D-094). Untrusted pull request code executes in the Wasmtime
sandbox or it does not execute at all (§5, D-076), and a repository's suite needs its dependencies,
its network and its filesystem — everything the sandbox exists to deny. A verification ladder that
degraded to "we ran their tests when they had some" would report two different meanings of the same
word depending on a property of the repository, and the stronger of the two would be the one that
executed arbitrary code beside the database credentials.

So the ladder is fixed, and it is made of checks this system can perform against any repository:
the patch parses, it keeps the signature its callers depend on, it references no name the file does
not have, it changes something — and then the deterministic witnesses re-examine the patched
function and say whether the weakness is still there.

**A check has three outcomes, for the reason evidence has three kinds (D-005).** PASSED, FAILED,
and NOT_RUN. A check that could not run must never read as one that passed: the runtime witness is
unavailable on a machine with no WASI interpreter, and a suggestion published as "verified in a
sandbox" on such a machine would be claiming an observation nobody made. Every published suggestion
carries the whole ladder, outcomes included, so the reader can see which rungs were empty.

**A witness that never detected the weakness cannot certify its removal.** Its silence on the
patched function is the same silence it gave the original, and reporting that as a regression check
would be a self-graded exam with no exam. The two are separated here: `regression:` is emitted only
by a witness that detected the CWE before the patch, and `no_new_weakness:` by all of them.

**The semantic witness is not a rechecker, deliberately.** Re-asking a hosted model whether the
repair it drafted is a repair is the drafter's own family grading the drafter, and it is
non-deterministic — a patch would pass on one sample and fail on the next, so the same draft would
be publishable or not depending on nothing. Rechecks are the witnesses whose answer is a function
of the code alone.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from codesheriff_contracts import ChangeUnit, Evidence, EvidenceKind
from codesheriff_patch.source import (
    STAR_IMPORT,
    Signature,
    free_names,
    line_replacement,
    names_available_from,
    parse,
    signature_of,
)

PARSES = "parses"
SIGNATURE_UNCHANGED = "signature_unchanged"
NAMES_RESOLVE = "names_resolve"
CHANGES_SOMETHING = "changes_something"
REGRESSION = "regression"
NO_NEW_WEAKNESS = "no_new_weakness"


class CheckStatus(StrEnum):
    """Three outcomes, never two (D-005 applied to verification)."""

    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"
    """The check could not be performed. Not a pass, and never rendered as one."""


@dataclass(frozen=True)
class CheckResult:
    """One rung of the ladder, and why it came out that way."""

    name: str
    status: CheckStatus
    detail: str = ""

    @property
    def failed(self) -> bool:
        return self.status is CheckStatus.FAILED


@dataclass(frozen=True)
class Rechecker:
    """One deterministic witness, ready to re-examine a patched unit.

    `analyse` is the witness's production `analyze()`, bound by `apps/worker`. This package holds
    no agent and imports none: the four witnesses are the analysis system's, and a patcher that
    could construct one would be a second place deciding what a witness is.
    """

    witness: str
    analyse: Callable[[ChangeUnit], list[Evidence]]


@dataclass(frozen=True)
class VerificationRequest:
    """Everything the ladder needs about one candidate repair."""

    unit: ChangeUnit
    patched_src: str
    cwe: str

    rechecks: tuple[Rechecker, ...] = ()
    detecting_witnesses: frozenset[str] = frozenset()
    """Witnesses that detected `cwe` on the original unit.

    Only these can produce a regression check. A witness absent from this set was already silent,
    so its silence afterwards says nothing about the repair."""

    pre_existing_cwes: frozenset[str] = frozenset()
    """In-scope CWEs already detected on the original unit, other than `cwe`.

    Excluded from `no_new_weakness`, because a patch is not answerable for a second weakness that
    was there before it. Blaming it for one would reject every repair to a function with two."""


@dataclass(frozen=True)
class Verification:
    """The whole ladder for one draft."""

    results: tuple[CheckResult, ...] = ()
    checked_lines: int = 0

    @property
    def failures(self) -> tuple[CheckResult, ...]:
        return tuple(r for r in self.results if r.failed)

    @property
    def verified(self) -> bool:
        """No rung failed, and at least one witness actually re-examined the patch.

        The second half is what stops a draft passing on the strength of four checks that all
        parsed text. If every rechecker abstained — no interpreter, a broken roster — nothing has
        looked at the repaired code, and "verified" would be describing the absence of evidence.
        """
        if self.failures:
            return False
        return any(
            r.status is CheckStatus.PASSED and r.name.startswith((REGRESSION, NO_NEW_WEAKNESS))
            for r in self.results
        )

    @property
    def feedback(self) -> tuple[str, ...]:
        """The rejection reasons, as this system's own words.

        Fed back into the next draft. Note what is *not* fed back: the rejected draft itself. It is
        model output shaped by attacker-controlled source, and returning it to the model as
        instruction would put untrusted text outside the sentinel — the boundary the whole prompt
        is built around (D-066). Each attempt is drafted fresh from the same unit, with an
        accumulating list of constraints in our voice.
        """
        return tuple(f"{r.name}: {r.detail}" for r in self.failures)


def verify(request: VerificationRequest) -> Verification:
    """Run every rung. Later rungs still run after an earlier one fails.

    Deliberately not short-circuiting: the failures are fed back into the next draft, and one
    rejection reason per attempt would spend the draft budget learning the constraints one at a
    time.
    """
    unit = request.unit
    results: list[CheckResult] = []

    parsed = parse(request.patched_src)
    if parsed is None:
        results.append(
            CheckResult(
                PARSES,
                CheckStatus.FAILED,
                "the patched function is not valid Python and would not import",
            )
        )
    else:
        results.append(CheckResult(PARSES, CheckStatus.PASSED, "parses as valid Python"))

    results.append(_signature_check(unit, request.patched_src))
    results.append(_names_check(unit, request.patched_src))

    replacement = line_replacement(unit.post_src, request.patched_src)
    if replacement is None:
        results.append(
            CheckResult(
                CHANGES_SOMETHING,
                CheckStatus.FAILED,
                "the patch is identical to the code under review, so it repairs nothing",
            )
        )
    else:
        results.append(
            CheckResult(
                CHANGES_SOMETHING,
                CheckStatus.PASSED,
                f"replaces {replacement.replaced_line_count} line(s)",
            )
        )

    # The rechecks are skipped only when the text is not even parseable — an agent handed
    # unparseable source would abstain, and four abstentions would read as four witnesses that
    # could not look rather than as a draft that was never valid.
    if parsed is not None:
        results.extend(_recheck_all(request))

    return Verification(
        results=tuple(results),
        checked_lines=replacement.replaced_line_count if replacement else 0,
    )


def _signature_check(unit: ChangeUnit, patched_src: str) -> CheckResult:
    """The patch must still define the same function, callable the same way.

    A `<module>` unit has no signature to preserve and the check reports NOT_RUN rather than
    inventing a pass — the whole file is the unit there, and what its callers depend on is not
    something one signature describes.
    """
    if unit.symbol is None:
        return CheckResult(
            SIGNATURE_UNCHANGED,
            CheckStatus.NOT_RUN,
            "the unit is module scope, so there is no single signature to preserve",
        )

    before = signature_of(unit.post_src)
    after = signature_of(patched_src)

    if before is None:
        return CheckResult(
            SIGNATURE_UNCHANGED,
            CheckStatus.NOT_RUN,
            "the original unit does not resolve to exactly one function definition",
        )
    if after is None:
        return CheckResult(
            SIGNATURE_UNCHANGED,
            CheckStatus.FAILED,
            "the patch does not define exactly one function; return the same function, repaired",
        )
    if after != before:
        return CheckResult(
            SIGNATURE_UNCHANGED,
            CheckStatus.FAILED,
            f"the signature changed from {_render(before)} to {_render(after)}; callers this "
            "review never fetched would break, and the reviewer cannot see them from this hunk",
        )
    return CheckResult(SIGNATURE_UNCHANGED, CheckStatus.PASSED, f"still {_render(before)}")


def _names_check(unit: ChangeUnit, patched_src: str) -> CheckResult:
    """Every name the patch reads must already exist in the file.

    A suggestion replaces lines *inside* one function. It cannot add an import at the top of the
    file, so a repair that reaches for `shlex.quote` in a file that never imported `shlex` is a
    `NameError` waiting for the first request — invisible to a syntax check and to a reviewer
    skimming a green suggestion block.

    A `from x import *` anywhere in the file makes the available set unknowable, and the check
    says so rather than guessing in the direction that rejects correct patches.
    """
    available = _names_available(unit)
    if STAR_IMPORT in available:
        return CheckResult(
            NAMES_RESOLVE,
            CheckStatus.NOT_RUN,
            "the file uses a star import, so the names it has cannot be enumerated",
        )

    unresolved = sorted(free_names(patched_src) - available)
    if unresolved:
        return CheckResult(
            NAMES_RESOLVE,
            CheckStatus.FAILED,
            f"references {', '.join(unresolved)}, which this file neither imports nor defines; a "
            "suggestion replaces lines inside the function and cannot add an import",
        )
    return CheckResult(NAMES_RESOLVE, CheckStatus.PASSED, "every name it reads already exists")


def _names_available(unit: ChangeUnit) -> frozenset[str]:
    """Names the patch may use: the file's imports, plus whatever the original already read.

    The second half matters more than it looks. `post_src` is one function out of a file that also
    holds module-level constants, helpers and classes, and none of those are in `imports`. A name
    the original function already referenced is demonstrably resolvable at that point in that file,
    whatever defines it — so carrying it forward is evidence, not an assumption.
    """
    if any("import *" in statement for statement in unit.imports):
        return frozenset({STAR_IMPORT})
    return names_available_from(list(unit.imports)) | free_names(unit.post_src)


def _recheck_all(request: VerificationRequest) -> list[CheckResult]:
    """Every deterministic witness, re-examining the repaired function."""
    patched_unit = request.unit.model_copy(update={"post_src": request.patched_src})
    target = request.cwe.strip().upper()
    results: list[CheckResult] = []

    for recheck in request.rechecks:
        evidence = _safely(recheck, patched_unit)
        detected = {
            (ev.cwe or "").strip().upper() for ev in evidence if ev.kind is EvidenceKind.DETECTION
        }
        looked = any(ev.kind is not EvidenceKind.ABSTENTION for ev in evidence)

        if recheck.witness in request.detecting_witnesses:
            results.append(_regression_result(recheck.witness, target, detected, looked))

        results.append(_new_weakness_result(recheck.witness, target, detected, looked, request))
    return results


def _regression_result(witness: str, target: str, detected: set[str], looked: bool) -> CheckResult:
    name = f"{REGRESSION}:{witness}"
    if not looked:
        return CheckResult(
            name,
            CheckStatus.NOT_RUN,
            f"`{witness}` abstained on the patched function, so it did not re-examine it",
        )
    if target in detected:
        return CheckResult(
            name,
            CheckStatus.FAILED,
            f"`{witness}` still detects {target} in the patched function",
        )
    return CheckResult(
        name,
        CheckStatus.PASSED,
        f"`{witness}` detected {target} before the patch and does not after it",
    )


def _new_weakness_result(
    witness: str,
    target: str,
    detected: set[str],
    looked: bool,
    request: VerificationRequest,
) -> CheckResult:
    name = f"{NO_NEW_WEAKNESS}:{witness}"
    if not looked:
        return CheckResult(
            name,
            CheckStatus.NOT_RUN,
            f"`{witness}` abstained on the patched function, so it did not re-examine it",
        )
    introduced = sorted(detected - {target} - request.pre_existing_cwes)
    if introduced:
        return CheckResult(
            name,
            CheckStatus.FAILED,
            f"`{witness}` detects {', '.join(introduced)} in the patched function, which it did "
            "not detect before; a repair that trades one weakness for another is not a repair",
        )
    return CheckResult(
        name, CheckStatus.PASSED, f"`{witness}` finds no weakness the original did not have"
    )


def _safely(recheck: Rechecker, unit: ChangeUnit) -> list[Evidence]:
    """Agents never raise (`CLAUDE.md`); this is the belt to that braces.

    A rechecker that throws produces no evidence, which reads as an abstention and therefore as
    NOT_RUN — the honest outcome for a witness that fell over, and never a pass.
    """
    try:
        return list(recheck.analyse(unit))
    except Exception:
        return []


def _render(signature: Signature) -> str:
    prefix = "async def " if signature.is_async else "def "
    return f"`{prefix}{signature.name}({', '.join(signature.parameters)})`"
