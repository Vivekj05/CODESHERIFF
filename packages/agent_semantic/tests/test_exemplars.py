"""The few-shot exemplars, and the property that makes them worth having.

`AUDIT.md` 3.9: three exemplar files existed and a repo-wide grep for `exemplar` returned three
hits, all in Markdown. Zero Python referenced them. §5's mechanism for teaching "safe-by-default is
an acceptable answer" was inert, and only a prose instruction survived.

They also could not have been loaded as they stood — each file held a `response` and no record of
the code it responded to, so half of every example was missing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codesheriff_contracts import IN_SCOPE_CWES, ChangeUnit
from semantic_agent.agent import SemanticAgent
from semantic_agent.config import SemanticConfig
from semantic_agent.exemplars import (
    EXEMPLARS_DIR,
    exemplar_balance,
    load_exemplars,
    render_exemplars,
)
from semantic_agent.mapping import HallucinationGate

EXEMPLARS = load_exemplars()


def test_the_exemplars_load() -> None:
    """The whole of `AUDIT.md` 3.9 in one assertion."""
    assert len(EXEMPLARS) == 6


def test_every_exemplar_carries_the_code_it_answers() -> None:
    """Response-only files cannot be few-shot examples; half of each was missing."""
    for exemplar in EXEMPLARS:
        assert exemplar.post_src.strip(), f"{exemplar.name} has no code"
        assert exemplar.file
        assert exemplar.note, "an exemplar should say what it is teaching"


def test_most_exemplars_report_nothing() -> None:
    """The anti-sycophancy ratio, asserted so it cannot drift.

    A model shown only findings learns that finding something is what a good answer looks like.
    The silent examples are what make `{"findings": []}` a demonstrated answer rather than a
    permitted one — and the measured failure was over-reporting, so silence is the majority.

    Not *all* silent, deliberately: 06 is 04 with the guard removed. Without a reporting example of
    the same shape, the safe ones would teach that a fetch is never worth reporting, which trades
    one bias for the other.
    """
    reporting, silent = exemplar_balance(EXEMPLARS)

    assert (reporting, silent) == (2, 4)
    assert silent > reporting


def test_the_safe_exemplars_still_contain_a_dangerous_sink() -> None:
    """An example where nothing looks alarming teaches nothing.

    Both safe exemplars call something that is a sink in the static agent's catalog; they are safe
    because of an invariant on the path, which is the distinction being taught.
    """
    safe = [e for e in EXEMPLARS if not e.reports_a_finding]
    assert len(safe) == 4

    joined = " ".join(e.post_src for e in safe)
    for sink in ("Response(", "subprocess.run", "requests.get"):
        assert sink in joined, f"no safe exemplar exercises {sink}"


def test_every_exemplar_finding_would_pass_the_hallucination_gate() -> None:
    """An exemplar the gate would reject is teaching the model to produce rejects."""
    for exemplar in EXEMPLARS:
        unit = ChangeUnit(
            unit_id=exemplar.name,
            repo="acme/exemplar",
            language=exemplar.language,
            file=exemplar.file,
            symbol=exemplar.symbol,
            post_src=exemplar.post_src,
            base_sha="b" * 40,
            head_sha="h" * 40,
        )
        for finding in exemplar.response.findings:
            ok, reason = HallucinationGate.validate(finding, unit)
            assert ok, f"{exemplar.name}: {reason}"


def test_every_exemplar_cwe_is_in_scope() -> None:
    for exemplar in EXEMPLARS:
        for finding in exemplar.response.findings:
            assert finding.cwe in IN_SCOPE_CWES


def test_no_exemplar_is_lifted_from_the_corpus() -> None:
    """An example taken from a labelled case puts that case's answer in the prompt.

    That is label leakage into the thing being measured, and it would inflate exactly the numbers
    Chapter 14 fits (D-047).
    """
    from codesheriff_corpus.loader import load_cases

    corpus_sources = {" ".join(case.post_src.split()) for case in load_cases()}
    for exemplar in EXEMPLARS:
        assert " ".join(exemplar.post_src.split()) not in corpus_sources, (
            f"{exemplar.name} duplicates a corpus case"
        )


# -- rendering ---------------------------------------------------------------------------------


def test_exemplars_are_rendered_inside_the_same_sentinel() -> None:
    """Presenting an example in a different frame teaches that the sentinel is decorative."""
    rendered = render_exemplars(EXEMPLARS, "CODESHERIFF-TESTSENTINEL")

    assert rendered.count("BEGIN CODESHERIFF-TESTSENTINEL") == len(EXEMPLARS)
    assert rendered.count("END CODESHERIFF-TESTSENTINEL") == len(EXEMPLARS)


def test_the_rendering_states_the_balance() -> None:
    rendered = render_exemplars(EXEMPLARS, "CODESHERIFF-X")

    assert "4 correctly report nothing" in rendered


def test_no_exemplars_renders_to_nothing() -> None:
    assert render_exemplars((), "CODESHERIFF-X") == ""


def test_the_prompt_actually_contains_them(tmp_path: Path) -> None:
    """The end of `AUDIT.md` 3.9: they reach the model, not just the loader."""

    class RecordingClient:
        def __init__(self) -> None:
            self.prompt = ""

        def generate(
            self, system_prompt: str, user_prompt: str, schema: object, **kw: object
        ) -> str:
            self.prompt = user_prompt
            return json.dumps({"findings": []})

    client = RecordingClient()
    config = SemanticConfig(cache_path=str(tmp_path / "cache.db"), n_samples=1)
    agent = SemanticAgent(config=config, llm_client=client)
    agent.analyze(
        ChangeUnit(
            unit_id="u1",
            repo="r",
            language="python",
            file="a.py",
            symbol="f",
            post_src="def f():\n    return 1\n",
            base_sha="b" * 40,
            head_sha="h" * 40,
        )
    )

    assert "Worked examples" in client.prompt
    for exemplar in EXEMPLARS:
        assert exemplar.post_src.strip().splitlines()[0] in client.prompt


# -- resilience --------------------------------------------------------------------------------


def test_a_malformed_exemplar_is_skipped_not_fatal(tmp_path: Path) -> None:
    """One bad file must not cost the model every worked example."""
    (tmp_path / "good.json").write_text(
        json.dumps(
            {
                "note": "n",
                "unit": {"file": "a.py", "symbol": "f", "post_src": "def f(): pass"},
                "response": {"findings": []},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "bad.json").write_text("{ not json", encoding="utf-8")

    load_exemplars.cache_clear()
    try:
        loaded = load_exemplars(tmp_path)
    finally:
        load_exemplars.cache_clear()

    assert len(loaded) == 1
    assert loaded[0].name == "good"


def test_a_missing_directory_is_survivable() -> None:
    load_exemplars.cache_clear()
    try:
        assert load_exemplars(Path("no/such/directory")) == ()
    finally:
        load_exemplars.cache_clear()


@pytest.mark.parametrize("path", sorted(EXEMPLARS_DIR.glob("*.json")))
def test_each_exemplar_file_is_valid_json(path: Path) -> None:
    """The files are data shipped in the wheel; a stray comma breaks them silently."""
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert {"note", "unit", "response"} <= set(payload)
