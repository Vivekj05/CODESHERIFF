"""Every sink, with a vulnerable fixture and a safe twin.

PLAN.md Chapter 10: "Ten precise sinks beat sixty sloppy ones. Every sink ships with a vulnerable
fixture **and** a safe twin." The safe twin is the half that matters. A rule with only a vulnerable
fixture is tested for firing and never for staying quiet, which is how a sink pattern broad enough
to match anything passes its own test suite.

The twins here are deliberately near, in the way the corpus twins are: the safe member usually
still calls something that looks dangerous, and is safe for one specific reason.

`test_every_sink_rule_appears_here` is what keeps this file honest — adding a rule to `sinks.yml`
without a pair below fails, so coverage cannot quietly drift behind the catalog.
"""

from __future__ import annotations

import pytest

from codesheriff_contracts import ChangeUnit, EvidenceKind
from static_agent.config import StaticConfig
from static_agent.taint.catalog import Catalog
from static_agent.taint.engine import analyze_taint

CONFIG = StaticConfig()

#: rule id -> (cwe, vulnerable source, safe twin, why the twin is safe)
SINK_FIXTURES: dict[str, tuple[str, str, str, str]] = {
    "sql.execute": (
        "CWE-89",
        "def handle(request):\n"
        "    uid = request.args['id']\n"
        "    return cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n",
        "def handle(request):\n"
        "    uid = request.args['id']\n"
        "    return cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))\n",
        "the tainted value is in the parameter bag, not the statement",
    ),
    "os.system": (
        "CWE-78",
        "def handle(request):\n    os.system('ping ' + request.args['host'])\n",
        "def handle(request):\n    os.system('ping ' + shlex.quote(request.args['host']))\n",
        "shlex.quote clears the command class",
    ),
    "subprocess.shell": (
        "CWE-78",
        "def handle(request):\n"
        "    host = request.args['host']\n"
        "    subprocess.run('ping ' + host, shell=True)\n",
        "def handle(request):\n"
        "    host = request.args['host']\n"
        "    subprocess.run(['ping', host], capture_output=True)\n",
        "no shell parses an argument vector",
    ),
    "xss.mark_safe": (
        "CWE-79",
        "def handle(request):\n    return mark_safe('<b>' + request.args['q'] + '</b>')\n",
        "def handle(request):\n    return mark_safe('<b>' + escape(request.args['q']) + '</b>')\n",
        "escape clears the xss class",
    ),
    "xss.html_response": (
        "CWE-79",
        "def handle(request):\n"
        "    name = request.args['name']\n"
        "    return Response(f'<h1>{name}</h1>', mimetype='text/html')\n",
        "def handle(request):\n"
        "    name = request.args['name']\n"
        "    return Response(f'<h1>{name}</h1>', mimetype='application/json')\n",
        "a response is only an xss sink when it is served as HTML",
    ),
    "path.filesystem": (
        "CWE-22",
        "def handle(request, filename):\n    return send_file(UPLOAD_DIR + '/' + filename)\n",
        "def handle(request, filename):\n"
        "    return send_file(os.path.join(UPLOAD_DIR, secure_filename(filename)))\n",
        "secure_filename clears the path class",
    ),
    "pickle.loads": (
        "CWE-502",
        "def handle(self, key):\n    blob = self.redis.get(key)\n    return pickle.loads(blob)\n",
        "def handle(self, key):\n"
        "    blob = self.redis.get(key)\n"
        "    return json.loads(blob.decode('utf-8'))\n",
        "json.loads does not construct arbitrary objects",
    ),
    "yaml.unsafe_load": (
        "CWE-502",
        "def handle(request):\n    return yaml.load(request.args['doc'], Loader=yaml.Loader)\n",
        "def handle(request):\n    return yaml.load(request.args['doc'], Loader=SafeLoader)\n",
        "SafeLoader constructs only plain data",
    ),
    "code.exec": (
        "CWE-94",
        "def handle(rule, record):\n    exec(rule.body, {}, {'record': record})\n",
        "def handle(rule, record):\n"
        "    handler = RULE_HANDLERS.get(rule.name)\n"
        "    return handler(record)\n",
        "an allowlist lookup returns a value the program chose",
    ),
    "code.template_from_string": (
        "CWE-94",
        "def handle(template_source, user):\n"
        "    return Template(template_source).render(user=user)\n",
        "def handle(template_name, user):\n"
        "    if template_name not in NOTIFICATION_TEMPLATES:\n"
        "        raise KeyError(template_name)\n"
        "    return ENVIRONMENT.get_template(template_name).render(user=user)\n",
        "looking a template up by name is not building one from a string",
    ),
    "ssrf.fetch": (
        "CWE-918",
        "def handle(request):\n"
        "    url = request.args['url']\n"
        "    return requests.post(url, json={'ping': True})\n",
        "def handle(request):\n"
        "    url = request.args['url']\n"
        "    if not is_public_https_url(url):\n"
        "        abort(400)\n"
        "    return requests.post(url, json={'ping': True})\n",
        "a validating guard that refuses to continue",
    ),
}


def unit(source: str) -> ChangeUnit:
    return ChangeUnit(
        unit_id="u1",
        repo="acme/app",
        language="python",
        file="app/service.py",
        symbol="handle",
        post_src=source,
        changed_lines=[1],
        base_sha="b" * 40,
        head_sha="h" * 40,
    )


def cwes_found(source: str) -> set[str]:
    evidence = analyze_taint(unit(source), CONFIG)
    return {e.cwe for e in evidence if e.kind is EvidenceKind.DETECTION and e.cwe}


@pytest.mark.parametrize("rule_id", sorted(SINK_FIXTURES))
def test_the_vulnerable_fixture_is_detected(rule_id: str) -> None:
    cwe, vulnerable, _, _ = SINK_FIXTURES[rule_id]
    assert cwe in cwes_found(vulnerable), f"{rule_id} missed its own vulnerable fixture"


@pytest.mark.parametrize("rule_id", sorted(SINK_FIXTURES))
def test_the_safe_twin_is_not_detected(rule_id: str) -> None:
    cwe, _, safe, why = SINK_FIXTURES[rule_id]
    assert cwe not in cwes_found(safe), f"{rule_id} fired on its safe twin, though {why}"


def test_every_sink_rule_appears_here() -> None:
    """A rule added to `sinks.yml` without a pair above fails this."""
    catalog = Catalog.load_from_dir(CONFIG.rules_dir)
    declared = {rule.id for rule in catalog.sinks["python"]}

    assert declared == set(SINK_FIXTURES), (
        f"missing fixtures for {sorted(declared - set(SINK_FIXTURES))}; "
        f"fixtures for rules that no longer exist: {sorted(set(SINK_FIXTURES) - declared)}"
    )


def test_the_catalog_stays_small() -> None:
    """Ten precise sinks beat sixty sloppy ones.

    Not an arbitrary ceiling: every rule here has to be maintained with both fixtures and has to
    earn its false-positive budget. A catalog that has quietly grown to sixty is the thing this
    chapter replaced.
    """
    catalog = Catalog.load_from_dir(CONFIG.rules_dir)
    assert len(catalog.sinks["python"]) <= 15
