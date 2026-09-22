"""Fixtures for the patcher's tests.

Everything shared is a **fixture**, not a module-level import. The root `pytest` runs with
`--import-mode=importlib` so that four packages can each have a `tests/test_agent.py`, and the cost
is that `from conftest import ...` resolves when the suite is narrowed to this package and fails
when it is run from the root. Fixtures work in both.

The unit under repair is a *method*, deliberately. `post_src` is built from whole file lines
(`extraction/python.py`), so a method's source arrives carrying the indentation it has in the file
— which is the fact every anchoring and parsing decision in this package depends on. A fixture
using a module-level function would be indented at zero and would pass tests that a real method
fails.
"""

from __future__ import annotations

import json
import textwrap
from collections.abc import Callable

import pytest

from codesheriff_contracts import ChangeUnit


def as_file_lines(source: str, indent: int = 4) -> str:
    """A dedented snippet re-indented the way a file holds it."""
    return textwrap.indent(textwrap.dedent(source).strip("\n"), " " * indent)


VULNERABLE = as_file_lines(
    """
    def lookup(self, user_id):
        query = "SELECT * FROM users WHERE id = " + user_id
        return self.cursor.execute(query).fetchone()
    """
)

REPAIRED = as_file_lines(
    """
    def lookup(self, user_id):
        query = "SELECT * FROM users WHERE id = ?"
        return self.cursor.execute(query, (user_id,)).fetchone()
    """
)


class ScriptedModel:
    """A `PatchModel` that answers from a script. No network, no key, no quota.

    Records every prompt it was given, which is what the tests about retry feedback assert
    against: the constraint has to reach the model, and the rejected draft has to not.
    """

    def __init__(self, answers: list[str | Exception]) -> None:
        self.answers = answers
        self.prompts: list[str] = []
        self.system_prompts: list[str] = []

    def complete(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        self.system_prompts.append(system_prompt)
        self.prompts.append(user_prompt)
        answer = self.answers[min(len(self.prompts) - 1, len(self.answers) - 1)]
        if isinstance(answer, Exception):
            raise answer
        return answer


def as_response(patched_function: str) -> str:
    """The one-field JSON document the patcher asks for."""
    return json.dumps({"patched_function": patched_function})


@pytest.fixture
def indent_like_a_file() -> Callable[..., str]:
    return as_file_lines


@pytest.fixture
def vulnerable() -> str:
    return VULNERABLE


@pytest.fixture
def repaired() -> str:
    return REPAIRED


@pytest.fixture
def scripted() -> type[ScriptedModel]:
    return ScriptedModel


@pytest.fixture
def response_for() -> Callable[[str], str]:
    return as_response


@pytest.fixture
def unit() -> ChangeUnit:
    """One changed method, every line of it inside the pull request's diff."""
    return ChangeUnit(
        unit_id="app/db.py::Users.lookup",
        repo="acme/app",
        language="python",
        file="app/db.py",
        symbol="lookup",
        enclosing_class="Users",
        post_src=VULNERABLE,
        start_line=10,
        changed_lines=[10, 11, 12],
        imports=["import sqlite3"],
        base_sha="a" * 40,
        head_sha="b" * 40,
    )
