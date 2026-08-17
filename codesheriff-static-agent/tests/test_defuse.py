"""Tests for Def-Use graph construction."""

from static_agent.taint.defuse import build_defuse_graph


def test_defuse_graph_building() -> None:
    code = (
        "uid = request.args.get('id')\n"
        "q = f'SELECT * FROM users WHERE id = {uid}'\n"
        "cursor.execute(q)\n"
    )
    g = build_defuse_graph(code, "python")
    assert len(g.nodes) > 0
