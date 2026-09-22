"""The prompt boundary, and reading a model's answer without believing any of it."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from codesheriff_contracts import ChangeUnit
from codesheriff_patch.drafting import (
    MAX_RESPONSE_BYTES,
    DraftRequest,
    DraftUnavailableError,
    build_prompt,
    draft,
    load_system_prompt,
    new_nonce,
    parse_response,
)


class TestSentinel:
    def test_two_nonces_differ(self) -> None:
        assert new_nonce() != new_nonce()

    def test_the_nonce_is_not_drawn_from_a_seedable_generator(self) -> None:
        # `random` is seedable and its state is inferable from enough output. This is the whole
        # prompt-injection boundary, so it comes from `secrets`.
        import random

        random.seed(0)
        first = new_nonce()
        random.seed(0)
        assert new_nonce() != first

    def test_the_unit_sits_inside_the_sentinel(self, unit: ChangeUnit) -> None:
        nonce = new_nonce()
        prompt = build_prompt(DraftRequest(unit=unit, cwe="CWE-89"), nonce)
        # `rindex`: the paragraph explaining the boundary names both markers before either one is
        # used, which is deliberate — the model is told what the sentinel means before it meets it.
        begin = prompt.rindex(f"BEGIN {nonce}")
        end = prompt.rindex(f"END {nonce}")
        assert begin < prompt.index(unit.post_src) < end

    def test_the_prompt_names_the_finding_and_the_file_s_imports(self, unit: ChangeUnit) -> None:
        prompt = build_prompt(DraftRequest(unit=unit, cwe="cwe-89"), new_nonce())
        assert "CWE-89" in prompt
        assert "import sqlite3" in prompt

    def test_constraints_are_rendered_outside_the_sentinel(self, unit: ChangeUnit) -> None:
        # They are this system's words, not the model's and not the author's.
        nonce = new_nonce()
        prompt = build_prompt(
            DraftRequest(unit=unit, cwe="CWE-89", constraints=("names_resolve: no shlex",)),
            nonce,
        )
        assert prompt.index("no shlex") < prompt.index(f"BEGIN {nonce}")

    def test_the_system_prompt_ships_with_the_package(self) -> None:
        assert "patched_function" in load_system_prompt()


class TestParsingTheAnswer:
    def test_a_well_formed_answer_yields_the_function(
        self, repaired: str, response_for: Callable[[str], str]
    ) -> None:
        assert parse_response(response_for(repaired), new_nonce()) == repaired

    def test_a_fenced_value_is_unwrapped(
        self, repaired: str, response_for: Callable[[str], str]
    ) -> None:
        fenced = f"```python\n{repaired}\n```"
        assert parse_response(response_for(fenced), new_nonce()) == repaired

    def test_bare_code_is_refused_rather_than_re_parsed(self, repaired: str) -> None:
        # A fallback parser here would be reached the first time the model wandered, and it would
        # extract something from output that had stopped following instructions — which is
        # precisely the output an injection produces.
        with pytest.raises(DraftUnavailableError, match="did not return JSON"):
            parse_response(repaired, new_nonce())

    def test_a_missing_field_names_what_came_back_instead(self) -> None:
        with pytest.raises(DraftUnavailableError, match="patched_function"):
            parse_response(json.dumps({"summary": "fixed it"}), new_nonce())

    def test_an_empty_function_is_refused(self, response_for: Callable[[str], str]) -> None:
        with pytest.raises(DraftUnavailableError):
            parse_response(response_for("   \n  "), new_nonce())

    def test_a_response_repeating_the_sentinel_is_discarded(
        self, response_for: Callable[[str], str]
    ) -> None:
        # The sentinel is ours and random per request. Code that repeats it did not come from the
        # file; it came from something in the file trying to look like the frame around it.
        nonce = new_nonce()
        with pytest.raises(DraftUnavailableError, match="sentinel"):
            parse_response(response_for(f"def f():\n    # {nonce}\n    pass"), nonce)

    def test_an_oversized_response_is_refused_before_it_is_parsed(self) -> None:
        with pytest.raises(DraftUnavailableError, match="ceiling"):
            parse_response("x" * (MAX_RESPONSE_BYTES + 1), new_nonce())


class TestDraft:
    def test_a_transport_failure_becomes_a_draft_unavailable_error(
        self, unit: ChangeUnit, scripted: Any
    ) -> None:
        # Not a rejected repair. One is a patcher that could not run and the other is a repair
        # that did not hold up.
        model = scripted([ConnectionError("no route to host")])
        with pytest.raises(DraftUnavailableError, match="ConnectionError"):
            draft(model, DraftRequest(unit=unit, cwe="CWE-89"), temperature=0.2)

    def test_a_new_sentinel_is_used_for_every_draft(
        self, unit: ChangeUnit, repaired: str, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        model = scripted([response_for(repaired), response_for(repaired)])
        request = DraftRequest(unit=unit, cwe="CWE-89")
        draft(model, request, temperature=0.2)
        draft(model, request, temperature=0.2)
        sentinels = [p.split("BEGIN ", 1)[1].split("\n", 1)[0] for p in model.prompts]
        assert sentinels[0] != sentinels[1]
