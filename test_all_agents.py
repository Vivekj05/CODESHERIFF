import sys
from pathlib import Path

_root = Path(__file__).parent
for pkg_dir in [
    _root / "codesheriff-engine" / "src",
    _root / "codesheriff-static-agent" / "src",
    _root / "codesheriff-semantic-agent" / "src",
    _root / "codesheriff-context-agent" / "src",
    _root / "codesheriff-runtime-agent" / "src",
    _root / "codesheriff-patch-verifier" / "src",
]:
    sys.path.insert(0, str(pkg_dir))

from codesheriff_engine.contracts import ChangeUnit

unit = ChangeUnit(
    unit_id="unit-001",
    repo="acme/webapp",
    language="python",
    file="app/api/users.py",
    post_src="""def get_user_profile(user_id):
    # Unsanitized SQL Query vulnerability
    uid = request.args.get('id')
    q = f"SELECT * FROM users WHERE id = {uid}"
    return cursor.execute(q).fetchone()
""",
    pre_src="def placeholder(): pass\n",
    changed_lines=[1, 2, 3, 4, 5],
    base_sha="aaaaaaa",
    head_sha="bbbbbbb",
)

print("--- Testing Static Agent ---")
try:
    from static_agent.agent import StaticAgent
    sa = StaticAgent()
    ev_static = sa.analyze(unit)
    print("Static agent results count:", len(ev_static))
    for ev in ev_static:
        print(" ", ev.model_dump())
except Exception as e:
    import traceback
    traceback.print_exc()

print("--- Testing Semantic Agent ---")
try:
    from semantic_agent.agent import SemanticAgent
    sema = SemanticAgent()
    ev_sem = sema.analyze(unit)
    print("Semantic agent results count:", len(ev_sem))
    for ev in ev_sem:
        print(" ", ev.model_dump())
except Exception as e:
    import traceback
    traceback.print_exc()

print("--- Testing Context Agent ---")
try:
    from context_agent.agent import ContextAgent
    ca = ContextAgent()
    ev_ctx = ca.analyze(unit)
    print("Context agent results count:", len(ev_ctx))
    for ev in ev_ctx:
        print(" ", ev.model_dump())
except Exception as e:
    import traceback
    traceback.print_exc()

print("--- Testing Runtime Agent ---")
try:
    from runtime_agent.agent import RuntimeAgent
    ra = RuntimeAgent()
    ev_rt = ra.analyze(unit)
    print("Runtime agent results count:", len(ev_rt))
    for ev in ev_rt:
        print(" ", ev.model_dump())
except Exception as e:
    import traceback
    traceback.print_exc()
