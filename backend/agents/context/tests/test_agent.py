"""The context witness end to end, through `ContextAgent.analyze()`.

Every assertion here goes through the public method the worker calls. The superseded suite
tested a vector store and an embedder that the reasoning did not consult, which is how a
package with a green suite came to hold four substring tests (`AUDIT.md` 3.7).
"""

from __future__ import annotations

import pytest

from codesheriff_contracts import IN_SCOPE_CWES, EvidenceKind
from context_agent.agent import ContextAgent
from context_agent.classify import COVERED_CWES
from context_agent.config import AGENT_ID, ContextConfig
from context_agent.precedent import Precedent

from .context_support import (
    GUARDED_DELETE,
    UNGUARDED_DELETE,
    BrokenRetriever,
    ListRetriever,
    make_precedent,
    make_unit,
)


def test_a_control_the_repository_established_and_this_unit_dropped_is_reported(
    guarded_history: list[Precedent],
) -> None:
    """The Chapter 12 acceptance criterion: evidence produced *through* `analyze()`.

    Nothing in the unit says a control is missing — `pre_src` is None, so no line was
    removed by this change. Only the two merged siblings say so.
    """
    agent = ContextAgent(retriever=ListRetriever(guarded_history))
    evidence = agent.analyze(make_unit(UNGUARDED_DELETE))

    assert len(evidence) == 1
    found = evidence[0]
    assert found.kind is EvidenceKind.DETECTION
    assert found.cwe == "CWE-639"
    assert "require_owner" in found.explanation


def test_the_same_unit_with_the_control_applied_is_silent(
    guarded_history: list[Precedent],
) -> None:
    """The twin. Identical body, identical history, guard present.

    A rule keyed on the shape of the code rather than on the missing guard fires on both
    members of this pair, which is the whole reason the corpus is built out of twins.
    """
    agent = ContextAgent(retriever=ListRetriever(guarded_history))
    evidence = agent.analyze(make_unit(GUARDED_DELETE))

    assert [e.kind for e in evidence] == [EvidenceKind.SILENCE]
    assert evidence[0].covered_cwes == COVERED_CWES


def test_evidence_is_keyed_through_the_unit_so_it_lands_on_an_existing_finding() -> None:
    """D-012: it corroborates, it does not solo.

    A key built from a string literal — which is what the superseded analyzer did — collides
    with nothing, so every finding is a permanent singleton and the Bayesian engine never
    performs a single update (`AUDIT.md` 1.1, 1.5).
    """
    unit = make_unit(UNGUARDED_DELETE)
    history = [
        make_precedent(
            "@require_owner\ndef get_note(note_id):\n    return Note.query.get_or_404(note_id)\n",
            qualified_symbol="get_note",
        ),
        make_precedent(
            "@require_owner\ndef list_notes():\n    return Note.query.all()\n",
            qualified_symbol="list_notes",
        ),
    ]
    evidence = ContextAgent(retriever=ListRetriever(history)).analyze(unit)

    assert evidence[0].finding_key == unit.key_for("CWE-639")


def test_one_merge_of_the_same_symbol_establishes_the_control() -> None:
    """A function moved between modules, losing its guard on the way.

    Frequency cannot decide this: the symbol has no siblings in the history. Matching is on
    the qualified symbol rather than the path, because the move is what changed the path.
    """
    unit = make_unit(
        '@bp.post("/jobs/drain")\ndef drain():\n    return jsonify(n=DeadLetter.drain())\n',
        symbol="drain",
        file="app/jobs/queue.py",
    )
    history = [
        make_precedent(
            '@bp.post("/jobs/drain")\n'
            "@admin_required\n"
            "def drain():\n"
            "    return jsonify(n=DeadLetter.drain())\n",
            qualified_symbol="drain",
            file="app/jobs/legacy_queue.py",
            pr_number=95,
        )
    ]
    evidence = ContextAgent(retriever=ListRetriever(history)).analyze(unit)

    assert evidence[0].kind is EvidenceKind.DETECTION
    assert evidence[0].cwe == "CWE-862"
    # Same-symbol precedent is the strong form and must clear the 0.8 tier boundary in
    # `WitnessRatios.for_score`, or the strongest claim this witness can make is a medium one.
    assert evidence[0].raw_score >= 0.8


def test_one_sibling_doing_something_once_is_not_a_convention() -> None:
    """`MIN_SUPPORTING_SYMBOLS`. Every function calls something no other function calls.

    Treating a single neighbour's habit as a rule would make every added function a
    regression against whichever neighbour retrieval happened to return.
    """
    history = [
        make_precedent(
            "@require_owner\ndef get_note(note_id):\n    return Note.query.get_or_404(note_id)\n",
            qualified_symbol="get_note",
        )
    ]
    evidence = ContextAgent(retriever=ListRetriever(history)).analyze(make_unit(UNGUARDED_DELETE))

    assert [e.kind for e in evidence] == [EvidenceKind.SILENCE]


def test_a_mined_convention_that_is_not_authorization_is_not_reported() -> None:
    """The narrowness in `classify.py`, exercised.

    Both merged siblings escape interpolated text and this unit does not, so the mining is
    correct and the regression is real. It is still not this witness's finding: escaping is
    not authorization, and CWE-79 has a witness that reads the code itself.
    """
    unit = make_unit(
        "def render_greeting(request):\n"
        '    name = request.args.get("name", "friend")\n'
        '    return Response(f"<h1>Hello {name}</h1>")\n',
        symbol="render_greeting",
        file="app/web/pages.py",
    )
    history = [
        make_precedent(
            "def render_profile(request, user):\n"
            '    return Response(f"<p>{escape(user.bio)}</p>")\n',
            qualified_symbol="render_profile",
            file="app/web/pages.py",
        ),
        make_precedent(
            "def render_header(request):\n"
            "    return Response(f\"<h2>{escape(request.args.get('q'))}</h2>\")\n",
            qualified_symbol="render_header",
            file="app/web/pages.py",
        ),
    ]
    evidence = ContextAgent(retriever=ListRetriever(history)).analyze(unit)

    assert [e.kind for e in evidence] == [EvidenceKind.SILENCE]


def test_rate_limiting_is_not_an_access_control() -> None:
    """A decorator convention that looks security-shaped and enforces no entitlement.

    Mapping it to CWE-862 would be a false positive dressed as thoroughness.
    """
    unit = make_unit(
        "def fetch(self, target):\n    return urlopen(target).read()\n",
        symbol="fetch",
        enclosing_class="LinkPreview",
        file="app/previews/fetcher.py",
    )
    history = [
        make_precedent(
            '    @rate_limit("30/minute")\n'
            "    def fetch_favicon(self, target):\n"
            "        return urlopen(target).read()\n",
            qualified_symbol="LinkPreview.fetch_favicon",
            file="app/previews/fetcher.py",
        ),
        make_precedent(
            '    @rate_limit("30/minute")\n'
            "    def discover(self, target):\n"
            "        return urlopen(target).read()\n",
            qualified_symbol="OEmbedClient.discover",
            file="app/previews/oembed.py",
        ),
    ]
    evidence = ContextAgent(retriever=ListRetriever(history)).analyze(unit)

    assert [e.kind for e in evidence] == [EvidenceKind.SILENCE]


def test_the_same_guard_spelled_as_a_call_still_counts_as_applied() -> None:
    """One control, two spellings. A decorator on some endpoints, an entry call on others.

    Reporting the decorator missing from a function that calls it reads, to whoever gets the
    comment, as the agent not having read the code.
    """
    unit = make_unit(
        '@bp.post("/flags/<name>")\n'
        "def set_flag(name):\n"
        "    ensure_staff(request.user)\n"
        "    return jsonify(ok=True)\n",
        symbol="set_flag",
        file="app/flags/views.py",
    )
    history = [
        make_precedent(
            "@ensure_staff\ndef list_flags():\n    return jsonify([])\n",
            qualified_symbol="list_flags",
            file="app/flags/views.py",
        ),
        make_precedent(
            "@ensure_staff\ndef delete_flag(name):\n    return jsonify(ok=True)\n",
            qualified_symbol="delete_flag",
            file="app/flags/views.py",
        ),
    ]
    evidence = ContextAgent(retriever=ListRetriever(history)).analyze(unit)

    assert [e.kind for e in evidence] == [EvidenceKind.SILENCE]


# -- the three ways of saying nothing ------------------------------------------------------


def test_no_history_abstains_rather_than_reporting_the_repository_clean() -> None:
    """The documented failure mode, on the record and costing the posterior nothing."""
    evidence = ContextAgent(retriever=ListRetriever([])).analyze(make_unit(UNGUARDED_DELETE))

    assert [e.kind for e in evidence] == [EvidenceKind.ABSTENTION]
    assert evidence[0].reason == "no_precedent"


def test_a_broken_retriever_abstains_under_its_own_reason() -> None:
    """`AUDIT.md` 3.8, closed. A store or a model that is down is not a repository that is new.

    Conflating the two would let a broken embedding model report, quietly and forever, that
    every repository it was pointed at happened to have no relevant history.
    """
    evidence = ContextAgent(retriever=BrokenRetriever()).analyze(make_unit(UNGUARDED_DELETE))

    assert evidence[0].kind is EvidenceKind.ABSTENTION
    assert evidence[0].reason == "retrieval_unavailable"
    assert evidence[0].reason != "no_precedent"


def test_no_retriever_at_all_abstains_and_never_invents_a_store() -> None:
    """The default. An agent that assembled its own history would answer about a repository
    nobody pointed it at, and its silence would argue that code it had no context for is fine."""
    evidence = ContextAgent().analyze(make_unit(UNGUARDED_DELETE))

    assert evidence[0].kind is EvidenceKind.ABSTENTION
    assert evidence[0].reason == "no_precedent"


def test_precedent_below_the_similarity_floor_is_not_precedent_about_this_unit(
    guarded_history: list[Precedent],
) -> None:
    distant = [
        Precedent(
            pr_number=p.pr_number,
            file=p.file,
            qualified_symbol=p.qualified_symbol,
            accepted_src=p.accepted_src,
            similarity=0.05,
        )
        for p in guarded_history
    ]
    evidence = ContextAgent(retriever=ListRetriever(distant)).analyze(make_unit(UNGUARDED_DELETE))

    assert evidence[0].kind is EvidenceKind.ABSTENTION
    assert evidence[0].reason == "no_relevant_precedent"


def test_an_oversized_unit_abstains_rather_than_being_analysed(
    guarded_history: list[Precedent],
) -> None:
    """D-015. Truncating would produce a confident finding from half-read code."""
    agent = ContextAgent(
        config=ContextConfig(max_unit_bytes=1_000), retriever=ListRetriever(guarded_history)
    )
    evidence = agent.analyze(make_unit(UNGUARDED_DELETE + "\n# padding" * 500))

    assert evidence[0].kind is EvidenceKind.ABSTENTION
    assert evidence[0].reason == "unit_too_large"


def test_an_empty_list_is_never_returned_from_a_successful_analysis(
    guarded_history: list[Precedent],
) -> None:
    """D-005. `[]` is indistinguishable from a failure and throws away the one statement that
    can lower a posterior."""
    agent = ContextAgent(retriever=ListRetriever(guarded_history))
    for source in (UNGUARDED_DELETE, GUARDED_DELETE, "def f():\n    return 1\n"):
        assert agent.analyze(make_unit(source)), source


# -- contract conformance ------------------------------------------------------------------


def test_the_agent_never_raises_however_broken_its_input() -> None:
    """`CLAUDE.md`: every failure path is an abstention with a distinct reason."""

    class Exploding:
        def retrieve(self, unit: object, limit: int) -> list[Precedent]:
            raise RuntimeError("boom")

    evidence = ContextAgent(retriever=Exploding()).analyze(make_unit(UNGUARDED_DELETE))

    assert evidence[0].kind is EvidenceKind.ABSTENTION
    assert evidence[0].reason == "runtime_error"


def test_a_language_this_agent_has_no_control_model_for_does_not_crash_the_audit(
    guarded_history: list[Precedent],
) -> None:
    """Decorators and entry guards are Python-shaped. Reading a JavaScript tree with them
    produces confident nonsense, so the surface comes back empty rather than wrong."""
    unit = make_unit("function f(){ return 1; }", language="javascript")
    evidence = ContextAgent(retriever=ListRetriever(guarded_history)).analyze(unit)

    assert evidence[0].kind in {EvidenceKind.SILENCE, EvidenceKind.ABSTENTION}


def test_every_reported_cwe_is_in_scope_and_covered(guarded_history: list[Precedent]) -> None:
    evidence = ContextAgent(retriever=ListRetriever(guarded_history)).analyze(
        make_unit(UNGUARDED_DELETE)
    )
    for item in evidence:
        if item.cwe is not None:
            assert item.cwe in IN_SCOPE_CWES
            assert item.cwe in COVERED_CWES


def test_the_agent_declares_the_id_fusion_registered() -> None:
    """An unregistered `agent_id` raises in fusion, by design — it would otherwise become a
    fifth witness multiplying in a factor nobody calibrated."""
    assert ContextAgent().agent_id == AGENT_ID == "context.rag"


@pytest.mark.parametrize("limit_field", ["top_k"])
def test_the_configured_top_k_is_what_the_retriever_is_asked_for(
    guarded_history: list[Precedent], limit_field: str
) -> None:
    retriever = ListRetriever(guarded_history)
    ContextAgent(config=ContextConfig(top_k=3), retriever=retriever).analyze(
        make_unit(UNGUARDED_DELETE)
    )
    assert retriever.calls[0][1] == 3
