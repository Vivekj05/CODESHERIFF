"""What counts as a dangerous operation, and in which argument.

This table is the runtime witness's equivalent of `static_agent.taint`'s rule files, and it
follows the same three disciplines for the same reasons - but it is **not** the same table,
and it is deliberately not shared. Two witnesses reading one rule file would fail together
on every rule that file gets wrong, which is precisely the correlation the four-agent
argument exists to avoid (D-011). Where the two overlap, they overlap because both are
describing Python, not because either consulted the other.

**Positions, never whole calls** (D-059). Every sink names the argument indices and keyword
names that are dangerous. `subprocess.run(["ping", host])` passes a list to position 0 and
never reaches a shell, so it is not a hit; `os.system(f"ping {host}")` is. A sink modelled
as "this function is dangerous" would report the safe twin of `cwe-078-host-ping` and the
pair would stop measuring anything.

**Path sinks require a composition** (D-061). `open(path)` where `path` arrives whole from
a parameter is every function that opens a file it was handed; `open(base + "/" + name)` is
a traversal. The runtime probe can tell these apart exactly, because it sees the string:
the argument either *is* a taint token or *contains* one among other text.

**A name this table does not know is not a sink.** There is no "looks dangerous" fallback
and no substring matching on the callee - `"int("` counting as a sanitizer because it is a
substring of `print(` is a defect this project has already shipped once (D-053), and the
mirror-image bug here would be `os.system` matching `os.system_profile`. Lookup is exact,
on the fully qualified name the guest resolved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_runtime.config import COVERED_CWES


@dataclass(frozen=True)
class Sink:
    """One dangerous operation, and the arguments that make it dangerous."""

    name: str
    """The fully qualified dotted name as the guest resolves it - `os.system`,
    `urllib.request.urlopen`, `flask.send_file`. Bare builtins are bare: `eval`."""

    cwe: str
    args: tuple[int, ...] = ()
    """Positional indices whose value reaching this call is the finding."""

    kwargs: tuple[str, ...] = ()
    """Keyword names with the same meaning. `requests.post(url=...)` is `requests.post(...)`."""

    requires_composition: bool = False
    """Fire only when the tainted argument was *built*, not merely passed through (D-061).

    Set on the CWE-22 sinks and nowhere else. A server-side request to a URL it was handed
    whole is the SSRF; a file opened by a path it was handed whole is a file being opened.
    """

    shell_sensitive: bool = False
    """The `subprocess` family: dangerous with a string command or `shell=True`, and not
    dangerous with an argument vector. This is the one place a sink's danger depends on the
    *type* of what it was given rather than only on the value."""

    description: str = ""

    def as_payload(self) -> dict[str, Any]:
        """The guest receives data, never code. Serialised into the probe payload."""
        return {
            "name": self.name,
            "cwe": self.cwe,
            "args": list(self.args),
            "kwargs": list(self.kwargs),
            "requires_composition": self.requires_composition,
            "shell_sensitive": self.shell_sensitive,
        }


def _shell(name: str) -> Sink:
    return Sink(
        name=name,
        cwe="CWE-78",
        args=(0,),
        kwargs=("args", "cmd", "command"),
        shell_sensitive=name.startswith("subprocess."),
        description="a value reached a shell",
    )


def _path(name: str, args: tuple[int, ...] = (0,)) -> Sink:
    return Sink(
        name=name,
        cwe="CWE-22",
        args=args,
        kwargs=("path", "filename", "file", "src", "dst", "name"),
        requires_composition=True,
        description="a composed path reached a filesystem operation",
    )


def _fetch(name: str) -> Sink:
    return Sink(
        name=name,
        cwe="CWE-918",
        args=(0,),
        kwargs=("url", "uri"),
        description="a value reached an outbound request",
    )


def _deserialise(name: str) -> Sink:
    return Sink(
        name=name,
        cwe="CWE-502",
        args=(0,),
        kwargs=("data", "stream", "s", "value"),
        description="a value reached a deserialiser",
    )


def _evaluate(name: str) -> Sink:
    return Sink(
        name=name,
        cwe="CWE-94",
        args=(0,),
        kwargs=("source", "code", "expr", "template", "source_string"),
        description="a value reached an evaluator",
    )


SINKS: tuple[Sink, ...] = (
    # CWE-78 - a shell interprets the string.
    _shell("os.system"),
    _shell("os.popen"),
    _shell("subprocess.run"),
    _shell("subprocess.call"),
    _shell("subprocess.check_call"),
    _shell("subprocess.check_output"),
    _shell("subprocess.getoutput"),
    _shell("subprocess.Popen"),
    # CWE-94 - the string is executed as program text.
    _evaluate("eval"),
    _evaluate("exec"),
    _evaluate("execfile"),
    _evaluate("jinja2.Template"),
    _evaluate("jinja2.Environment.from_string"),
    _evaluate("mako.template.Template"),
    # `compile` is deliberately absent: compiling a string is not running it, and the
    # units that compile also eval, so the eval is the finding and reporting both would
    # double one observation into two.
    # CWE-502 - the bytes decide what objects, and therefore what code, comes back.
    _deserialise("pickle.loads"),
    _deserialise("pickle.load"),
    _deserialise("cPickle.loads"),
    _deserialise("dill.loads"),
    _deserialise("marshal.loads"),
    _deserialise("jsonpickle.decode"),
    _deserialise("shelve.open"),
    Sink(
        name="yaml.load",
        cwe="CWE-502",
        args=(0,),
        kwargs=("stream",),
        description="a value reached yaml.load, which constructs arbitrary Python objects",
    ),
    # `yaml.safe_load` is absent rather than excluded, which is the same discipline
    # `context_agent` applies to `rate_limit`: the safe twin of `cwe-502-config-load`
    # calls it, so its absence is measured on every corpus run rather than asserted here.
    # CWE-918 - the caller chooses where the server connects.
    _fetch("urllib.request.urlopen"),
    _fetch("urllib.request.Request"),
    _fetch("urllib.request.urlretrieve"),
    _fetch("requests.get"),
    _fetch("requests.post"),
    _fetch("requests.put"),
    _fetch("requests.patch"),
    _fetch("requests.delete"),
    _fetch("requests.head"),
    _fetch("requests.request"),
    _fetch("httpx.get"),
    _fetch("httpx.post"),
    _fetch("httpx.request"),
    _fetch("socket.create_connection"),
    # CWE-22 - composition required, every one of them.
    _path("open"),
    _path("io.open"),
    _path("os.remove"),
    _path("os.unlink"),
    _path("os.rmdir"),
    _path("os.rename", args=(0, 1)),
    _path("os.makedirs"),
    _path("os.mkdir"),
    _path("shutil.rmtree"),
    _path("shutil.copy", args=(0, 1)),
    _path("shutil.copyfile", args=(0, 1)),
    _path("shutil.move", args=(0, 1)),
    _path("flask.send_file"),
    _path("flask.send_from_directory", args=(0, 1)),
    _path("pathlib.Path"),
)


PROPAGATORS: frozenset[str] = frozenset(
    {
        "os.path.join",
        "os.path.normpath",
        "os.path.abspath",
        "os.path.expanduser",
        "posixpath.join",
        "ntpath.join",
        "str.join",
        "urllib.parse.urljoin",
        "shlex.quote",
    }
)
"""Names whose result carries its arguments' taint forward, rather than clearing it.

Short by design, and every entry is a function that *composes* rather than decides. An
unmodelled call clears taint (see `probe.py`), so a name that belongs here and is missing
costs a detection - the safe direction. A name that does *not* belong here and is added
costs a false positive, which is why `shlex.quote` sits here rather than among sanitizers:
it composes a shell-safe string, and whether that makes the eventual call safe is a
judgement about the call, not about the quoting. The static engine reaches the opposite
conclusion about `shlex.quote` from its own rules, and the two disagreeing is the point of
running two witnesses.
"""


def sinks_for_payload() -> list[dict[str, Any]]:
    return [sink.as_payload() for sink in SINKS]


SINK_CWES: frozenset[str] = frozenset(sink.cwe for sink in SINKS)


def _check_scope() -> None:
    """Every CWE this table can produce must be one this agent declares it covers.

    A sink whose CWE is outside `COVERED_CWES` would emit a DETECTION the agent's own
    SILENCE never argues about, so the witness would be able to raise a finding on a CWE it
    reports itself as blind to. Checked at import, because the failure is silent otherwise.
    """
    stray = SINK_CWES - COVERED_CWES
    if stray:
        raise ValueError(
            f"sink table produces {sorted(stray)}, which agent_runtime.config.COVERED_CWES "
            "does not declare. Widen COVERED_CWES deliberately or drop the sink."
        )
    unreachable = COVERED_CWES - SINK_CWES
    if unreachable:
        raise ValueError(
            f"COVERED_CWES declares {sorted(unreachable)} but no sink can produce it. Silence "
            "about a CWE this agent cannot detect is not evidence (D-006)."
        )


_check_scope()


@dataclass(frozen=True)
class ProbePayload:
    """Everything the guest is told. Data only - the guest compiles no logic from here."""

    sentinel: str
    source: str
    symbol: str
    aliases: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "sentinel": self.sentinel,
            "source": self.source,
            "symbol": self.symbol,
            "aliases": self.aliases,
            "sinks": sinks_for_payload(),
            "propagators": sorted(PROPAGATORS),
        }
