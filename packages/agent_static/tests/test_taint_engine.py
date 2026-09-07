"""What the taint engine must and must not report.

Every test names the `AUDIT.md` finding it holds down. The three at the top are Chapter 10's stated
acceptance criteria; the rest are the properties that make those three mean something rather than
being satisfied by an engine that reports nothing at all.
"""

from __future__ import annotations

import pytest

from codesheriff_contracts import ChangeUnit, Evidence, EvidenceKind
from static_agent.config import StaticConfig
from static_agent.taint.engine import MAX_UNIT_BYTES, analyze_taint

CONFIG = StaticConfig()


def unit(source: str, *, language: str = "python", is_test_file: bool = False) -> ChangeUnit:
    return ChangeUnit(
        unit_id="u1",
        repo="acme/app",
        language=language,
        file="app/service.py",
        symbol="handle",
        post_src=source,
        changed_lines=list(range(1, source.count("\n") + 2)),
        start_line=1,
        base_sha="b" * 40,
        head_sha="h" * 40,
        is_test_file=is_test_file,
    )


def detections(source: str, **kwargs: object) -> list[Evidence]:
    evidence = analyze_taint(unit(source, **kwargs), CONFIG)  # type: ignore[arg-type]
    return [e for e in evidence if e.kind is EvidenceKind.DETECTION]


def cwes(source: str) -> set[str]:
    return {e.cwe for e in detections(source) if e.cwe}


# ---------------------------------------------------------------------------------------------
# Chapter 10's acceptance criteria
# ---------------------------------------------------------------------------------------------


def test_a_comment_mentioning_a_sink_is_not_a_sink() -> None:
    """`AUDIT.md` 3.3, stated exactly as PLAN.md states it.

    Detection was `re.search` over raw lines, so this comment registered a *critical* CWE-78 sink.
    Rules now match the callee of a call expression in the AST, and a comment contains no call.
    """
    source = (
        "def handle(request):\n"
        "    cmd = request.args['cmd']\n"
        "    # TODO: replace os.system with subprocess\n"
        "    return cmd\n"
    )
    assert detections(source) == []


def test_a_wrong_class_sanitizer_does_not_suppress_a_sink() -> None:
    """`AUDIT.md` 3.4. Escaping HTML does not make a shell command safe.

    The old engine killed taint if *any* sanitizer matched *any* line between source and sink, so
    the `escape` below silenced the `os.system`. `clears` is now read, and `html.escape` clears
    `xss` only.
    """
    source = (
        "def handle(request):\n"
        "    name = request.args['name']\n"
        "    page = escape(name)\n"
        "    os.system('ping ' + name)\n"
        "    return page\n"
    )
    assert "CWE-78" in cwes(source)


def test_the_right_class_sanitizer_does_suppress_its_own_sink() -> None:
    """The other half of the same property — `clears` has to work in both directions."""
    source = (
        "def handle(request):\n"
        "    name = request.args['name']\n"
        "    os.system('ping ' + shlex.quote(name))\n"
    )
    assert "CWE-78" not in cwes(source)


# ---------------------------------------------------------------------------------------------
# AUDIT.md 3.2 — paths are real
# ---------------------------------------------------------------------------------------------


def test_an_unrelated_sink_below_a_source_is_not_a_finding() -> None:
    """`AUDIT.md` 3.2, stated directly.

    The only reachability test used to be `sink_line >= source_line`, so a source on one line and
    an unrelated sink on a later line touching a different variable produced a finding. No variable
    connects these two.
    """
    source = (
        "def handle(request):\n"
        "    name = request.args['name']\n"
        "    audit_log(name)\n"
        "    os.system(BACKUP_COMMAND)\n"
    )
    assert detections(source) == []


def test_a_sink_above_its_source_is_not_a_finding() -> None:
    source = (
        "def handle(request):\n"
        "    os.system(DEFAULT_COMMAND)\n"
        "    cmd = request.args['cmd']\n"
        "    return cmd\n"
    )
    assert detections(source) == []


def test_the_path_names_every_hop_it_took() -> None:
    """A three-hop flow renders three steps with a real `propagation` in the middle.

    The old artifact was always exactly two steps and could never contain a `propagation` role,
    so a one-hop flow and a five-hop flow were indistinguishable to a reviewer.
    """
    source = (
        "def handle(request):\n"
        "    raw = request.args['id']\n"
        "    query = f'SELECT * FROM users WHERE id = {raw}'\n"
        "    return cursor.execute(query)\n"
    )
    found = detections(source)
    assert len(found) == 1
    steps = found[0].artifacts[0].content["steps"]

    roles = [step["role"] for step in steps]
    assert roles[0] == "source"
    assert roles[-1] == "sink"
    assert "propagation" in roles
    assert len(steps) >= 3
    assert [step["line"] for step in steps] == sorted(step["line"] for step in steps)


def test_the_artifact_names_the_class_and_the_rule() -> None:
    """A finding a reviewer cannot argue with is not evidence."""
    source = "def handle(request):\n    os.system(request.args['cmd'])\n"
    content = detections(source)[0].artifacts[0].content
    assert content["sink_class"] == "command"
    assert content["rule_id"] == "os.system"


# ---------------------------------------------------------------------------------------------
# AUDIT.md 3.5 — parameterised SQL is a sink property, never a sanitizer
# ---------------------------------------------------------------------------------------------


def test_parameters_passed_separately_are_not_a_sink() -> None:
    source = (
        "def handle(request):\n"
        "    uid = request.args['id']\n"
        "    return cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))\n"
    )
    assert detections(source) == []


def test_a_tainted_statement_is_a_finding_even_when_parameters_are_passed() -> None:
    """The case no whole-call rule can get right.

    Both members of `cwe-089-order-sort` pass parameters separately. The vulnerable one is
    vulnerable because a tainted sort column was concatenated into argument 0, which is only
    visible if argument positions are modelled.
    """
    source = (
        "def handle(request):\n"
        "    sort = request.args['sort']\n"
        "    query = 'SELECT * FROM orders ORDER BY ' + sort\n"
        "    return cursor.execute(query, (request.user.id,))\n"
    )
    assert "CWE-89" in cwes(source)


def test_a_safe_execute_earlier_does_not_excuse_a_vulnerable_one_later() -> None:
    """Modelled as a sanitizer, the first call cleared taint for the whole function."""
    source = (
        "def handle(request):\n"
        "    uid = request.args['id']\n"
        "    cursor.execute('SELECT 1 FROM users WHERE id = %s', (uid,))\n"
        "    return cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
    )
    assert "CWE-89" in cwes(source)


# ---------------------------------------------------------------------------------------------
# AUDIT.md 3.6 — type coercion
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("coercion", ["int", "float", "uuid.UUID"])
def test_type_coercion_clears_taint(coercion: str) -> None:
    """§5 calls these "the largest false-positive source without them". There were none."""
    source = (
        "def handle(request):\n"
        f"    uid = {coercion}(request.args['id'])\n"
        "    return cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
    )
    assert detections(source) == []


def test_an_allowlist_lookup_clears_taint() -> None:
    """The attacker chose which of the program's values to use, not what the value is."""
    source = (
        "def handle(request):\n"
        "    column = SORT_COLUMNS.get(request.args['sort'])\n"
        "    return cursor.execute(f'SELECT * FROM t ORDER BY {column}')\n"
    )
    assert detections(source) == []


# ---------------------------------------------------------------------------------------------
# Keyword arguments are read from the AST, not from one line of text
# ---------------------------------------------------------------------------------------------


def test_shell_true_on_a_later_line_is_still_seen() -> None:
    """`AUDIT.md` 3.3: `requires_arg` was same-line-only, so this call was missed entirely."""
    source = (
        "def handle(request):\n"
        "    cmd = request.args['cmd']\n"
        "    subprocess.run(\n"
        "        cmd,\n"
        "        shell=True,\n"
        "    )\n"
    )
    assert "CWE-78" in cwes(source)


def test_a_list_argv_without_a_shell_is_not_command_injection() -> None:
    """No shell parses it, so there is nothing to inject into however tainted the value is."""
    source = (
        "def handle(request):\n"
        "    host = request.args['host']\n"
        "    subprocess.run(['ping', '-c', '1', host], capture_output=True)\n"
    )
    assert "CWE-78" not in cwes(source)


def test_a_safe_yaml_loader_on_a_later_line_is_still_seen() -> None:
    """`AUDIT.md` 3.3: `yaml.load(f)` with `Loader=SafeLoader` below it was reported as CWE-502."""
    source = (
        "def handle(request):\n"
        "    body = request.args['body']\n"
        "    return yaml.load(\n"
        "        body,\n"
        "        Loader=SafeLoader,\n"
        "    )\n"
    )
    assert "CWE-502" not in cwes(source)


def test_an_unsafe_yaml_loader_is_a_finding() -> None:
    source = (
        "def handle(request):\n"
        "    body = request.args['body']\n"
        "    return yaml.load(body, Loader=yaml.Loader)\n"
    )
    assert "CWE-502" in cwes(source)


def test_a_json_response_is_not_an_xss_sink() -> None:
    """A response is only an XSS sink when it is served as HTML."""
    source = (
        "def handle(request):\n"
        "    name = request.args['name']\n"
        "    return Response(name, mimetype='application/json')\n"
    )
    assert detections(source) == []


# ---------------------------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------------------------


def test_a_membership_guard_that_exits_clears_taint() -> None:
    source = (
        "def handle(request, name):\n"
        "    if name not in ALLOWED_TEMPLATES:\n"
        "        raise KeyError(name)\n"
        "    os.remove(os.path.join(TEMPLATE_DIR, name))\n"
    )
    assert detections(source) == []


def test_a_validator_call_guard_that_exits_clears_taint() -> None:
    source = (
        "def handle(request, url):\n"
        "    if not is_public_https_url(url):\n"
        "        abort(400)\n"
        "    return requests.get(url)\n"
    )
    assert detections(source) == []


def test_a_null_check_is_not_a_guard() -> None:
    """The distinction that keeps `cwe-502-cache-get` detectable.

    `if blob is None: return None` establishes nothing about `blob` except that it exists. Treating
    a bare emptiness test as validation would silently suppress the finding that follows it.
    """
    source = (
        "def handle(self, key):\n"
        "    blob = self.redis.get(key)\n"
        "    if blob is None:\n"
        "        return None\n"
        "    return pickle.loads(blob)\n"
    )
    assert "CWE-502" in cwes(source)


def test_a_guard_that_does_not_exit_clears_nothing() -> None:
    """A condition the function carries on past has not refused anything."""
    source = (
        "def handle(request, name):\n"
        "    if name not in ALLOWED_TEMPLATES:\n"
        "        log.warning('unknown template %s', name)\n"
        "    os.remove(os.path.join(TEMPLATE_DIR, name))\n"
    )
    assert "CWE-22" in cwes(source)


# ---------------------------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------------------------


def test_function_parameters_are_untrusted() -> None:
    """The unit is one function, so its signature is the boundary.

    Nine of the thirteen calibration cases this agent is expected to detect depend on it, and none
    of those functions mentions a request object at all.
    """
    source = (
        "def handle(self, term):\n    return session.execute(f'SELECT * FROM t WHERE a={term}')\n"
    )
    assert "CWE-89" in cwes(source)


def test_the_receiver_is_not_a_source() -> None:
    """`self` is the object, not an argument to it."""
    source = "def handle(self):\n    return os.system(self.command)\n"
    assert detections(source) == []


def test_environment_variables_are_not_a_source() -> None:
    """Operator-controlled, not attacker-controlled. Whoever sets it already has the privilege."""
    source = "def handle():\n    return os.system(os.environ['BACKUP_CMD'])\n"
    assert detections(source) == []


# ---------------------------------------------------------------------------------------------
# Path traversal needs a base to escape
# ---------------------------------------------------------------------------------------------


def test_a_path_handed_in_whole_and_opened_is_not_traversal() -> None:
    """The caller chose the path; that is the interface, not a trick.

    Without this, every function that takes a path and opens it is a critical finding — and it
    would fire on *both* members of `cwe-502-config-load`, whose safe twin also opens `path`.
    """
    source = "def handle(path):\n    return send_file(path)\n"
    assert "CWE-22" not in cwes(source)


def test_a_tainted_component_joined_onto_a_base_is_traversal() -> None:
    source = "def handle(request, filename):\n    return send_file(UPLOAD_DIR + '/' + filename)\n"
    assert "CWE-22" in cwes(source)


def test_a_tainted_component_joined_with_os_path_join_is_traversal() -> None:
    source = (
        "def handle(self, name):\n"
        "    target = os.path.join(self.template_dir, name)\n"
        "    os.remove(target)\n"
    )
    assert "CWE-22" in cwes(source)


# ---------------------------------------------------------------------------------------------
# Evidence discipline
# ---------------------------------------------------------------------------------------------


def test_a_clean_unit_returns_silence_naming_what_was_checked() -> None:
    """Returning `[]` from a successful analysis is a bug; SILENCE is what it is for (D-005)."""
    evidence = analyze_taint(unit("def handle(a, b):\n    return a + b\n"), CONFIG)

    assert len(evidence) == 1
    assert evidence[0].kind is EvidenceKind.SILENCE
    assert evidence[0].covers("CWE-89")
    # Silence is only evidence about CWEs this agent can reach (D-006). It holds no authorisation
    # rules, and claiming otherwise would suppress every semantic-only finding.
    assert not evidence[0].covers("CWE-862")
    assert not evidence[0].covers("CWE-798")


def test_a_detection_still_states_coverage_of_what_it_did_not_find() -> None:
    """D-056: detecting one CWE must not silence this agent about the other six."""
    evidence = analyze_taint(
        unit("def handle(request):\n    os.system(request.args['c'])\n"), CONFIG
    )
    silences = [e for e in evidence if e.kind is EvidenceKind.SILENCE]

    assert [e.cwe for e in evidence if e.kind is EvidenceKind.DETECTION] == ["CWE-78"]
    assert len(silences) == 1
    assert silences[0].covers("CWE-89")
    assert not silences[0].covers("CWE-78"), "it did find that one"


def test_one_finding_per_key_however_many_paths_reach_it() -> None:
    """With the sink expression gone from the key (D-004), several flows collapse onto one.

    Emitting each would apply one agent's likelihood ratio several times over for one finding.
    """
    source = (
        "def handle(request):\n"
        "    a = request.args['a']\n"
        "    b = request.args['b']\n"
        "    cursor.execute(f'SELECT {a}')\n"
        "    cursor.execute(f'SELECT {b}')\n"
    )
    found = detections(source)
    assert len(found) == 1
    assert found[0].finding_key == unit(source).key_for("CWE-89")


def test_javascript_abstains_rather_than_being_guessed_at() -> None:
    """Everything the engine does is Python-shaped, and a wrong answer is worth less than none.

    The superseded JS rules were regexes over raw lines whose `\\beval` matched the identifiers
    `evaluate` and `evalContext` (`AUDIT.md` 3.3).
    """
    evidence = analyze_taint(
        unit("function handler(req) { eval(req.query.code); }", language="javascript"), CONFIG
    )
    assert len(evidence) == 1
    assert evidence[0].kind is EvidenceKind.ABSTENTION
    assert evidence[0].reason == "language_not_modelled"


def test_an_oversized_unit_abstains_rather_than_being_truncated() -> None:
    """D-015. A truncated parse produces confident findings from half-read code."""
    source = "def handle(request):\n" + ("    pad = 1\n" * (MAX_UNIT_BYTES // 10))
    evidence = analyze_taint(unit(source), CONFIG)

    assert len(evidence) == 1
    assert evidence[0].kind is EvidenceKind.ABSTENTION
    assert evidence[0].reason == "unit_too_large"


def test_a_syntactically_broken_unit_does_not_raise() -> None:
    """tree-sitter tolerates broken syntax, which is why it is used (§5). It must not crash."""
    evidence = analyze_taint(unit("def handle(request:\n    os.system(request.args['c']\n"), CONFIG)
    assert isinstance(evidence, list) and evidence


def test_findings_in_test_files_are_downweighted_not_suppressed() -> None:
    """PLAN.md Chapter 10. A vulnerability in a test file is still a vulnerability."""
    source = "def handle(request):\n    os.system(request.args['cmd'])\n"
    production = detections(source)
    tests = detections(source, is_test_file=True)

    assert len(tests) == 1, "suppressed, not downweighted"
    assert tests[0].raw_score < production[0].raw_score
