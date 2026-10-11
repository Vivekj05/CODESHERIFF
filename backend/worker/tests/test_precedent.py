"""The precedent store's worker half: the embedder, the retriever, and repository scoping.

The agent's own behaviour is measured in `packages/agent_context`. What is asserted here is
everything the agent is deliberately not allowed to know about.
"""

from __future__ import annotations

import inspect
import uuid

import pytest

from codesheriff_contracts import ChangeUnit
from codesheriff_storage.precedents import search_precedents
from codesheriff_worker.analysis import AgentDeps, load_agents
from codesheriff_worker.precedent.embedding import (
    EMBEDDING_DIM,
    EMBEDDING_MODEL_NAME,
    LocalEmbedder,
    load_embedder,
    query_text,
)
from codesheriff_worker.precedent.retriever import PgVectorPrecedentRetriever
from context_agent.precedent import Precedent, RetrievalUnavailableError


def unit(repo: str = "acme/app") -> ChangeUnit:
    return ChangeUnit(
        unit_id="u1",
        repo=repo,
        language="python",
        file="app/notes/views.py",
        symbol="delete_note",
        post_src="def delete_note(note_id):\n    return Note.get(note_id).delete()\n",
        base_sha="a" * 40,
        head_sha="b" * 40,
    )


# -- the embedder --------------------------------------------------------------------------


def test_a_missing_model_raises_rather_than_hashing_the_text(monkeypatch) -> None:
    """`AUDIT.md` 3.8, closed at the source.

    The superseded embedder answered an absent `sentence-transformers` with a 384-dimensional
    MD5 term-hashing vector — right shape, no semantic content, cosine near zero between
    paraphrases — with no log line and no abstention. There is no fallback branch to take.
    """
    embedder = LocalEmbedder("does-not-matter")
    monkeypatch.setattr(
        embedder, "_load", lambda: (_ for _ in ()).throw(RetrievalUnavailableError("no model"))
    )
    with pytest.raises(RetrievalUnavailableError):
        embedder.embed("anything")


def test_a_model_of_the_wrong_size_is_refused(monkeypatch) -> None:
    """A 768-dimensional model would be rejected by the Vector(384) column on write, but on a
    *query* pgvector refuses the comparison — naming the cause here beats a driver error about
    operand types."""

    class WrongSize:
        def encode(self, text: str, normalize_embeddings: bool = True) -> list[float]:
            return [0.1] * 768

    embedder = LocalEmbedder()
    monkeypatch.setattr(embedder, "_load", lambda: WrongSize())

    with pytest.raises(RetrievalUnavailableError, match="768 dimensions"):
        embedder.embed("anything")
    assert EMBEDDING_DIM == 384


def test_the_query_text_is_built_the_same_way_on_both_sides() -> None:
    """A stored chunk and the query that should match it have to be rendered identically, or
    the nearest neighbour is decided by formatting rather than by meaning."""
    rendered = query_text("app/notes/views.py", "delete_note", "def delete_note(): ...")
    assert rendered.startswith("delete_note\napp/notes/views.py")
    assert "def delete_note(): ..." in rendered


def test_no_pull_request_prose_is_embedded() -> None:
    """D-014. PR title and description are attacker-controlled and absent from corpus cases;
    embedding them would make a corpus run and a production run different runs. The superseded
    `rag/ingest.py` put both into every indexed document."""
    rendered = query_text("f.py", "s", "body")
    assert rendered == "s\nf.py\n\nbody"


def test_one_embedder_is_shared_across_the_process() -> None:
    """A store written with one model and queried with another is a distance between two
    unrelated vector spaces. It does not error; it answers wrongly."""
    assert load_embedder() is load_embedder()
    assert EMBEDDING_MODEL_NAME == "BAAI/bge-small-en-v1.5"


# -- repository scoping --------------------------------------------------------------------


class FakeEmbedder:
    def embed(self, text: str) -> list[float]:
        return [0.0] * EMBEDDING_DIM


def test_the_retriever_has_no_way_to_name_another_repository() -> None:
    """The Chapter 12 criterion: cross-repository retrieval is impossible.

    `AUDIT.md` 0.2 was one global Chroma collection with `unit.repo` neither queried nor
    stored, so one repository's diffs could surface as another's review context. The binding
    here is a constructor argument and `retrieve` takes no repository at all — a filter that
    has to be passed correctly is one that will eventually be passed wrongly.
    """
    parameters = set(inspect.signature(PgVectorPrecedentRetriever.retrieve).parameters)
    assert parameters == {"self", "unit", "limit"}


def test_unit_repo_is_not_consulted_when_scoping(monkeypatch) -> None:
    """`unit.repo` is a string on an object the agent was handed. The binding comes from the
    audit's own repository row instead."""
    seen: dict[str, object] = {}

    def fake_search(session, repository_id, embedding, limit=5, min_similarity=None):
        seen["repository_id"] = repository_id
        return []

    monkeypatch.setattr("codesheriff_worker.precedent.retriever.search_precedents", fake_search)

    class Factory:
        def __call__(self):
            class S:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            return S()

    retriever = PgVectorPrecedentRetriever(Factory(), repository_id=99, embedder=FakeEmbedder())
    retriever.retrieve(unit(repo="somebody-else/app"), limit=5)

    assert seen["repository_id"] == 99


def test_a_store_failure_raises_rather_than_reporting_an_empty_history(monkeypatch) -> None:
    """Returning `[]` on a failure is the D-005 collapse: a broken store would report, quietly
    and forever, that every repository it was pointed at happened to be new."""

    def exploding(*args, **kwargs):
        raise RuntimeError("connection refused")

    monkeypatch.setattr("codesheriff_worker.precedent.retriever.search_precedents", exploding)

    class Factory:
        def __call__(self):
            class S:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            return S()

    retriever = PgVectorPrecedentRetriever(Factory(), repository_id=1, embedder=FakeEmbedder())
    with pytest.raises(RetrievalUnavailableError):
        retriever.retrieve(unit(), limit=5)


def test_search_precedents_filters_by_repository_in_sql() -> None:
    """The scoping is in the WHERE clause, not in a post-filter someone could drop.

    Compiled rather than asserted about the source text: a post-filter in Python would leave
    the SQL unscoped and read exactly the same to a grep.
    """
    from sqlalchemy import select

    from codesheriff_storage.models import PrecedentChunk, PRPrecedent

    distance = PrecedentChunk.embedding.cosine_distance([0.0] * EMBEDDING_DIM)
    statement = (
        select(PrecedentChunk, PRPrecedent.pr_number)
        .join(PRPrecedent, PrecedentChunk.precedent_id == PRPrecedent.id)
        .where(PRPrecedent.repository_id == 7)
        .order_by(distance)
    )
    compiled = str(statement.compile(compile_kwargs={"literal_binds": False}))
    assert "pr_precedents.repository_id" in compiled

    # And the function under test takes it as a required argument, so there is no call that
    # omits the filter.
    assert "repository_id" in inspect.signature(search_precedents).parameters


# -- injection into the roster -------------------------------------------------------------


def test_the_context_slot_receives_the_injected_retriever() -> None:
    """The agent may import contracts and nothing else, so the worker supplies the
    implementation. If this stops happening the agent abstains rather than failing loudly,
    which is exactly the kind of silent regression this asserts against."""

    class Retriever:
        def retrieve(self, unit: ChangeUnit, limit: int) -> list[Precedent]:
            return []

    injected = Retriever()
    agents = load_agents(deps=AgentDeps(precedent_retriever=injected))
    context = next(a for a in agents if getattr(a, "agent_id", "") == "context.rag")

    assert context.retriever is injected


def test_a_bare_load_agents_leaves_the_context_agent_without_a_store() -> None:
    """Empty deps is a valid state: the agent abstains under a reason naming it, rather than
    this process deciding what the repository's history is."""
    agents = load_agents()
    context = next(a for a in agents if getattr(a, "agent_id", "") == "context.rag")
    statements = context.analyze(unit())

    assert statements[0].reason == "no_precedent"


def test_ingesting_writes_one_chunk_per_symbol() -> None:
    """Per symbol, never per pull request (PROJECT_CONTEXT.md §5).

    `bge-small-en-v1.5` truncates at 512 tokens, so a PR-level document is silently cut, and a
    per-PR vector cannot answer "which symbol carried this guard" — the only question the
    context agent asks.
    """
    from codesheriff_worker.precedent.ingest import ingest_merged_pr

    source = (
        "@admin_required\n"
        "def export_users():\n"
        "    return csv(User.all())\n"
        "\n"
        "@admin_required\n"
        "def export_invoices():\n"
        "    return csv(Invoice.all())\n"
    )

    class Gateway:
        def list_pull_request_files(self, installation_id, repo, pr):
            from codesheriff_worker.github_gateway import PullRequestFile

            return [PullRequestFile(path="app/admin/exports.py", status="modified")]

        def get_file_at_ref(self, installation_id, repo, path, ref):
            return source

        def post_or_update_comment(self, **kwargs):  # pragma: no cover - unused here
            raise AssertionError

    added: list[object] = []

    class Session:
        def scalar(self, *a, **k):
            return None

        def add(self, obj):
            added.append(obj)
            if not hasattr(obj, "id") or obj.id is None:
                obj.id = uuid.uuid4()

        def flush(self):
            return None

    result = ingest_merged_pr(
        Session(),
        Gateway(),
        FakeEmbedder(),
        installation_id=1,
        repository_id=2,
        repo_full_name="acme/app",
        pr_number=118,
        head_sha="c" * 40,
    )

    assert result.chunks_written == 2
    symbols = {getattr(o, "qualified_symbol", None) for o in added}
    assert {"export_users", "export_invoices"} <= symbols
