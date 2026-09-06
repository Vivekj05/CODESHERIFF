"""The verification ladder, rung by rung — and the three outcomes it refuses to collapse."""

from __future__ import annotations

from collections.abc import Callable

from codesheriff_contracts import ChangeUnit, Evidence
from codesheriff_patch.verify import (
    CHANGES_SOMETHING,
    NAMES_RESOLVE,
    PARSES,
    SIGNATURE_UNCHANGED,
    CheckStatus,
    Rechecker,
    VerificationRequest,
    verify,
)

STRUCTURAL = "structural"
RUNTIME = "runtime"


def detection(unit: ChangeUnit, cwe: str) -> Evidence:
    return Evidence.detection(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id=unit.unit_id,
        finding_key=unit.key_for(cwe),
        cwe=cwe,
        raw_score=0.9,
    )


def silence(unit: ChangeUnit) -> Evidence:
    return Evidence.silence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id=unit.unit_id,
        covered_cwes={"CWE-89", "CWE-78"},
    )


def abstention(unit: ChangeUnit) -> Evidence:
    return Evidence.abstention(
        agent_id="runtime.sfi",
        agent_version="0.1.0",
        unit_id=unit.unit_id,
        reason="interpreter_unavailable",
    )


def status_of(results: object, name: str) -> CheckStatus:
    assert isinstance(results, tuple)
    for result in results:
        if result.name == name:
            return CheckStatus(result.status)
    raise AssertionError(f"no check named {name!r} in {[r.name for r in results]}")


def a_silent_witness(unit: ChangeUnit) -> Rechecker:
    return Rechecker(witness=STRUCTURAL, analyse=lambda u: [silence(unit)])


class TestStaticRungs:
    def test_a_patch_that_does_not_parse_fails_the_first_rung(self, unit: ChangeUnit) -> None:
        result = verify(
            VerificationRequest(unit=unit, patched_src="def lookup(self, user_id:", cwe="CWE-89")
        )
        assert status_of(result.results, PARSES) is CheckStatus.FAILED
        assert not result.verified

    def test_a_changed_signature_fails_even_when_the_repair_is_sound(
        self, unit: ChangeUnit, indent_like_a_file: Callable[..., str]
    ) -> None:
        # Adding a parameter — even with a default — breaks callers in files this review never
        # fetched, and the reviewer applying the suggestion sees only this hunk.
        widened = indent_like_a_file(
            """
            def lookup(self, user_id, escape=True):
                return self.cursor.execute("SELECT 1 WHERE id = ?", (user_id,)).fetchone()
            """,
            indent=4,
        )
        result = verify(
            VerificationRequest(
                unit=unit,
                patched_src=widened,
                cwe="CWE-89",
                rechecks=(a_silent_witness(unit),),
            )
        )
        assert status_of(result.results, SIGNATURE_UNCHANGED) is CheckStatus.FAILED
        assert not result.verified
        assert any("signature changed" in reason for reason in result.feedback)

    def test_a_name_the_file_does_not_import_fails(
        self, unit: ChangeUnit, indent_like_a_file: Callable[..., str]
    ) -> None:
        # The single most common way an LLM repair fails to even run, and it is invisible to a
        # syntax check: the suggestion replaces lines inside the function and cannot add an import.
        reaching = indent_like_a_file(
            """
            def lookup(self, user_id):
                return self.cursor.execute("SELECT 1", (shlex.quote(user_id),)).fetchone()
            """,
            indent=4,
        )
        result = verify(VerificationRequest(unit=unit, patched_src=reaching, cwe="CWE-89"))
        assert status_of(result.results, NAMES_RESOLVE) is CheckStatus.FAILED
        assert any("shlex" in reason for reason in result.feedback)

    def test_a_name_the_original_already_used_is_available(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        # `self.cursor` is not in `imports` and nothing else declares it, but the original
        # function already read it at this point in this file, so it demonstrably resolves.
        result = verify(VerificationRequest(unit=unit, patched_src=repaired, cwe="CWE-89"))
        assert status_of(result.results, NAMES_RESOLVE) is CheckStatus.PASSED

    def test_a_star_import_makes_the_name_check_unrunnable_not_failed(
        self, unit: ChangeUnit, indent_like_a_file: Callable[..., str]
    ) -> None:
        starred = unit.model_copy(update={"imports": ["from helpers import *"]})
        reaching = indent_like_a_file(
            """
            def lookup(self, user_id):
                return self.cursor.execute("SELECT 1", (sanitise(user_id),)).fetchone()
            """,
            indent=4,
        )
        result = verify(VerificationRequest(unit=starred, patched_src=reaching, cwe="CWE-89"))
        assert status_of(result.results, NAMES_RESOLVE) is CheckStatus.NOT_RUN

    def test_an_unchanged_draft_repairs_nothing(self, unit: ChangeUnit) -> None:
        result = verify(VerificationRequest(unit=unit, patched_src=unit.post_src, cwe="CWE-89"))
        assert status_of(result.results, CHANGES_SOMETHING) is CheckStatus.FAILED

    def test_a_module_unit_has_no_signature_to_preserve(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        module_unit = unit.model_copy(update={"symbol": None, "enclosing_class": None})
        result = verify(VerificationRequest(unit=module_unit, patched_src=repaired, cwe="CWE-89"))
        assert status_of(result.results, SIGNATURE_UNCHANGED) is CheckStatus.NOT_RUN

    def test_every_rung_runs_even_after_one_fails(self, unit: ChangeUnit) -> None:
        # One rejection reason per attempt would spend the draft budget learning the constraints
        # one at a time.
        broken = "def lookup(self, other, extra):\n    return shlex.quote(other"
        result = verify(VerificationRequest(unit=unit, patched_src=broken, cwe="CWE-89"))
        assert len(result.failures) >= 2


class TestRechecks:
    def test_a_witness_that_still_detects_the_cwe_fails_the_regression_rung(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        recheck = Rechecker(witness=STRUCTURAL, analyse=lambda u: [detection(u, "CWE-89")])
        result = verify(
            VerificationRequest(
                unit=unit,
                patched_src=repaired,
                cwe="CWE-89",
                rechecks=(recheck,),
                detecting_witnesses=frozenset({STRUCTURAL}),
            )
        )
        assert status_of(result.results, f"regression:{STRUCTURAL}") is CheckStatus.FAILED
        assert not result.verified

    def test_a_witness_that_falls_silent_passes_it(self, unit: ChangeUnit, repaired: str) -> None:
        result = verify(
            VerificationRequest(
                unit=unit,
                patched_src=repaired,
                cwe="CWE-89",
                rechecks=(a_silent_witness(unit),),
                detecting_witnesses=frozenset({STRUCTURAL}),
            )
        )
        assert status_of(result.results, f"regression:{STRUCTURAL}") is CheckStatus.PASSED
        assert result.verified

    def test_a_witness_that_never_detected_it_produces_no_regression_rung(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        # Its silence on the patched function is the same silence it gave the original. Reporting
        # that as a regression check would be a self-graded exam with no exam.
        result = verify(
            VerificationRequest(
                unit=unit,
                patched_src=repaired,
                cwe="CWE-89",
                rechecks=(a_silent_witness(unit),),
                detecting_witnesses=frozenset(),
            )
        )
        assert not any(r.name.startswith("regression:") for r in result.results)
        assert status_of(result.results, f"no_new_weakness:{STRUCTURAL}") is CheckStatus.PASSED

    def test_an_abstaining_witness_is_not_run_and_never_a_pass(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        recheck = Rechecker(witness=RUNTIME, analyse=lambda u: [abstention(u)])
        result = verify(
            VerificationRequest(
                unit=unit,
                patched_src=repaired,
                cwe="CWE-89",
                rechecks=(recheck,),
                detecting_witnesses=frozenset({RUNTIME}),
            )
        )
        assert status_of(result.results, f"regression:{RUNTIME}") is CheckStatus.NOT_RUN
        # Not a failure either — the patch is not to blame for a machine with no interpreter.
        assert not result.failures
        # But it is not verified: nothing looked at the repaired code.
        assert not result.verified

    def test_a_rechecker_that_raises_is_not_run_rather_than_fatal(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        def explode(_: ChangeUnit) -> list[Evidence]:
            raise RuntimeError("the witness fell over")

        result = verify(
            VerificationRequest(
                unit=unit,
                patched_src=repaired,
                cwe="CWE-89",
                rechecks=(Rechecker(witness=RUNTIME, analyse=explode), a_silent_witness(unit)),
                detecting_witnesses=frozenset({STRUCTURAL}),
            )
        )
        assert status_of(result.results, f"no_new_weakness:{RUNTIME}") is CheckStatus.NOT_RUN
        assert result.verified

    def test_a_repair_that_trades_one_weakness_for_another_is_rejected(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        recheck = Rechecker(witness=STRUCTURAL, analyse=lambda u: [detection(u, "CWE-78")])
        result = verify(
            VerificationRequest(
                unit=unit,
                patched_src=repaired,
                cwe="CWE-89",
                rechecks=(recheck,),
                detecting_witnesses=frozenset({STRUCTURAL}),
            )
        )
        assert status_of(result.results, f"no_new_weakness:{STRUCTURAL}") is CheckStatus.FAILED

    def test_a_weakness_the_original_already_had_is_not_blamed_on_the_patch(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        recheck = Rechecker(witness=STRUCTURAL, analyse=lambda u: [detection(u, "CWE-78")])
        result = verify(
            VerificationRequest(
                unit=unit,
                patched_src=repaired,
                cwe="CWE-89",
                rechecks=(recheck,),
                detecting_witnesses=frozenset({STRUCTURAL}),
                pre_existing_cwes=frozenset({"CWE-78"}),
            )
        )
        assert status_of(result.results, f"no_new_weakness:{STRUCTURAL}") is CheckStatus.PASSED
        assert result.verified


class TestVerifiedMeansSomethingLooked:
    def test_a_draft_with_no_recheckers_at_all_is_not_verified(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        # Four static rungs all passed. Nothing examined the repaired code, so "verified" would
        # be describing the absence of evidence.
        result = verify(VerificationRequest(unit=unit, patched_src=repaired, cwe="CWE-89"))
        assert not result.failures
        assert not result.verified

    def test_unparseable_source_is_not_handed_to_a_rechecker(self, unit: ChangeUnit) -> None:
        # An agent given unparseable source would abstain, and the abstentions would read as
        # witnesses that could not look rather than as a draft that was never valid.
        calls: list[ChangeUnit] = []

        def record(u: ChangeUnit) -> list[Evidence]:
            calls.append(u)
            return [silence(unit)]

        verify(
            VerificationRequest(
                unit=unit,
                patched_src="def lookup(self, user_id:",
                cwe="CWE-89",
                rechecks=(Rechecker(witness=STRUCTURAL, analyse=record),),
            )
        )
        assert calls == []

    def test_the_rechecker_sees_the_patched_source_under_the_same_unit_id(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        seen: list[ChangeUnit] = []

        def record(u: ChangeUnit) -> list[Evidence]:
            seen.append(u)
            return [silence(unit)]

        verify(
            VerificationRequest(
                unit=unit,
                patched_src=repaired,
                cwe="CWE-89",
                rechecks=(Rechecker(witness=STRUCTURAL, analyse=record),),
            )
        )
        assert len(seen) == 1
        assert seen[0].post_src == repaired
        assert seen[0].unit_id == unit.unit_id
        # The original is untouched: a witness must not be handed a mutated shared object.
        assert unit.post_src != repaired
