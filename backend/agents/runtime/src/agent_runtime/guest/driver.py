"""The program that runs *inside* the sandbox. Never imported on the host.

This file is read as text by `agent_runtime.probe` and handed to a WASI CPython build as
`-c` source. It is a real file rather than a string constant so that it is readable,
reviewable and diffable, but nothing on the host may import it: it is a program for a
different interpreter, in the same sense that `packages/corpus/.../cases/` holds data
rather than code (D-046). The root `pyproject.toml` excludes it from `mypy` for that
reason - the proxy below deliberately lies about its own type, and annotating that honestly
is not possible.

**What it does.** It executes one changed function once, with every free name bound to a
proxy and every parameter bound to a uniquely tokenised untrusted value, and reports which
dangerous operations that value actually reached. That is an *observation*, not a proof,
and it is the only witness in this project that gets one.

**Taint is a substring, not a wrapper.** Each untrusted value is a `str` subclass whose
text is a random token. An f-string, a `+`, a `%`, a `.format()` and an `os.path.join` all
carry the token into the result for free, because they carry the characters. Nothing here
has to model Python's string semantics, which is the part a wrapper-based tracker gets
wrong.

**Four propagation rules, and each one is a claim.**

1. *Attribute access on an untrusted object stays untrusted.* `request.args` is still the
   request.
2. *A call on an untrusted receiver returns untrusted data.* `request.args.get("host")`
   reads a value out of the request; that value is the request's.
3. *A call to an unmodelled free function clears taint, and is recorded as a guard.*
   `secure_filename(name)` might be a sanitiser, a validator or a no-op, and the probe
   cannot tell which. Clearing is the safe direction for false positives; recording is what
   stops the *other* direction from being silent - if the exact value that was inspected
   later reaches a sink, the host abstains rather than reporting (D-079).
4. *A sink's result is untrusted.* `open(path)` hands back a handle onto attacker-chosen
   bytes, which is how `yaml.load(handle)` comes to be reached.

**The unit never touches the guest's own standard library.** Every free name resolves to a
proxy, and the five builtins that execute or open things are replaced by proxies too. That
is defence in depth rather than convenience: the sandbox already denies the capabilities,
and this denies the names.
"""

import ast
import json
import sys
import traceback

MAX_HITS = 64
MAX_GUARDS = 256

REPLACED_BUILTINS = ("open", "eval", "exec", "compile", "__import__", "input", "breakpoint")
"""Builtins bound to proxies instead of the real thing.

`open`, `eval` and `exec` are sinks and have to be observed rather than performed.
`__import__` is here because an `import` statement inside a function body would otherwise
reach the guest's real standard library, which is the one namespace this file is trying to
keep the unit out of. Everything else - `len`, `isinstance`, `dict` - stays real, because a
unit whose `len()` returned a proxy would not run at all.
"""


class Trace:
    """Everything observed in one run. The only thing that crosses back to the host."""

    def __init__(self, prefix):
        self.prefix = prefix
        self.hits = []
        self.near_misses = []
        self.guarded = set()
        self.tokens = {}
        self.calls = 0
        self.counter = 0

    def new_token(self, origin):
        self.counter += 1
        token = f"{self.prefix}{self.counter}z"
        self.tokens[token] = origin
        return token

    def tokens_in(self, text):
        if self.prefix not in text:
            return []
        return [t for t in self.tokens if t in text]

    def record_hit(self, sink, cwe, position, composed, tokens):
        if len(self.hits) >= MAX_HITS:
            return
        self.hits.append(
            {
                "sink": sink,
                "cwe": cwe,
                "position": position,
                "composed": composed,
                "origins": sorted({self.tokens.get(t, "?") for t in tokens})[:4],
                "guarded": sorted(t for t in tokens if t in self.guarded),
            }
        )

    def record_near_miss(self, sink, cwe, reason):
        if len(self.near_misses) < MAX_HITS:
            self.near_misses.append({"sink": sink, "cwe": cwe, "reason": reason})

    def record_guard(self, tokens):
        if len(self.guarded) < MAX_GUARDS:
            self.guarded.update(tokens)


class Probe(str):
    """A stand-in for a value the probe could not obtain, tainted or otherwise.

    It subclasses `str` so that string operations in the unit under analysis work without
    the unit noticing, and so that taint travels as characters rather than as a wrapper the
    first `f"{...}"` would discard. `__getattr__` fires only for attributes `str` does not
    already define, which is why `blob.decode(...)` becomes a proxy call while
    `name.strip()` stays a plain string operation - and a plain string operation still
    carries the token, which is the whole reason taint is a substring here.
    """

    def __new__(cls, text, path, tainted, token, trace):
        self = str.__new__(cls, text)
        self._path = path
        self._tainted = tainted
        self._token = token
        self._trace = trace
        return self

    def __getattribute__(self, name):
        """Which of the two things this proxy is standing in for decides who answers.

        A **tainted** proxy stands in for an untrusted string, so `str`'s own methods apply
        and `value.strip()` returns a plain string that still carries the token. That is the
        whole reason taint is a substring here, and taking it away would mean modelling
        every string operation by hand.

        A **clean** proxy stands in for an object or a module - `os`, `UPLOAD_DIR`, a
        request handler this unit was extracted away from. It is a `str` only so that the
        two kinds share one class, and `str`'s methods on it are an accident of that. Before
        this split, `os.path.join(a, b)` resolved to `str.join` and raised `TypeError`
        instead of composing a path, which cost the whole CWE-22 composition rule on any
        unit that used the one function everyone uses to build a path.

        Names beginning with an underscore are this class's own, and always answer here.
        """
        if name.startswith("_"):
            return str.__getattribute__(self, name)
        if str.__getattribute__(self, "_tainted"):
            return str.__getattribute__(self, name)
        return _derive(self, f"{str.__getattribute__(self, '_path')}.{name}", False)

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return _derive(self, f"{self._path}.{name}", self._tainted)

    def __call__(self, *args, **kwargs):
        return _dispatch(self, args, kwargs)

    def __getitem__(self, key):
        return _derive(self, f"{self._path}[]", self._tainted)

    def __iter__(self):
        yield _derive(self, f"{self._path}[*]", self._tainted)

    def __enter__(self):
        return _derive(self, f"{self._path}.entered", self._tainted)

    def __exit__(self, *exc):
        return False

    def __contains__(self, item):
        return str(item) in str.__str__(self)

    def __bool__(self):
        # True, so that `if not value: reject()` takes the path that keeps going. A probe
        # that answered False would make every truthiness guard reject and the run would
        # observe nothing at all on any unit that validates its input.
        return True

    def __eq__(self, other):
        return str.__eq__(self, other)

    def __ne__(self, other):
        return str.__ne__(self, other)

    def __hash__(self):
        return str.__hash__(self)

    def __int__(self):
        return 0

    def __index__(self):
        return 0

    def __float__(self):
        return 0.0


def _derive(node, path, tainted):
    """A value read out of `node`. Untrusted receivers hand back untrusted values."""
    trace = node._trace
    if tainted:
        token = trace.new_token(path)
        return Probe(token, path, True, token, trace)
    return Probe(f"<{path}>", path, False, None, trace)


def _clean(path, trace):
    return Probe(f"<{path}>", path, False, None, trace)


def _untrusted(path, trace):
    token = trace.new_token(path)
    return Probe(token, path, True, token, trace)


def _dispatch(node, args, kwargs):
    trace = node._trace
    trace.calls += 1
    name = _resolve(node._path)

    sink = SINKS.get(name)
    if sink is not None:
        _check_sink(trace, sink, args, kwargs)
        return _derive(node, f"{node._path}()", True)

    if name in PROPAGATORS:
        parts = [str(a) for a in args] + [str(v) for v in kwargs.values()]
        return Probe("/".join(p for p in parts if p), f"{node._path}()", True, None, trace)

    # Unmodelled. Whatever it was - a sanitiser, a validator, a formatter - the probe
    # cannot evaluate it, so it clears taint and says so. Rule 3 in the module docstring.
    consumed = []
    for value in list(args) + list(kwargs.values()):
        consumed.extend(trace.tokens_in(str(value)))
    if consumed:
        trace.record_guard(consumed)

    return _derive(node, f"{node._path}()", node._tainted)


def _check_sink(trace, sink, args, kwargs):
    """Did an untrusted value land in an argument that makes this call dangerous?"""
    if sink["shell_sensitive"] and not _reaches_a_shell(args, kwargs):
        trace.record_near_miss(sink["name"], sink["cwe"], "argument_vector_not_shell")
        return

    positions = []
    for index in sink["args"]:
        if index < len(args):
            positions.append((f"arg{index}", args[index]))
    for key in sink["kwargs"]:
        if key in kwargs:
            positions.append((key, kwargs[key]))

    for position, value in positions:
        text = str(value)
        tokens = trace.tokens_in(text)
        if not tokens:
            continue
        composed = not (len(tokens) == 1 and text == tokens[0])
        if sink["requires_composition"] and not composed:
            # A path handed over whole is a function opening a file it was given (D-061).
            trace.record_near_miss(sink["name"], sink["cwe"], "passed_through_uncomposed")
            continue
        trace.record_hit(sink["name"], sink["cwe"], position, composed, tokens)


def _reaches_a_shell(args, kwargs):
    """`subprocess.run(["ping", host])` never reaches a shell; a string command does."""
    if kwargs.get("shell") is True:
        return True
    if args:
        command = args[0]
    elif "args" in kwargs:
        command = kwargs["args"]
    elif "cmd" in kwargs:
        command = kwargs["cmd"]
    else:
        return False
    return not isinstance(command, (list, tuple))


def _resolve(path):
    """The fully qualified name a dotted path refers to, after import aliases."""
    head, _, tail = path.partition(".")
    root = ALIASES.get(head, head)
    return f"{root}.{tail}" if tail else root


class ProbeNamespace(dict):
    """Globals for the unit. Any name it did not define resolves to a clean proxy.

    CPython consults `__missing__` on a `dict` subclass used as globals, which is what makes
    this work with no pre-pass over the source: `UPLOAD_DIR`, `KNOWN_HOSTS` and every other
    module-level name the unit was extracted away from simply appear, clean.
    """

    def __init__(self, trace):
        dict.__init__(self)
        self._trace = trace

    def __missing__(self, key):
        value = _clean(key, self._trace)
        self[key] = value
        return value


def _strip_decorators(tree):
    """Remove every decorator before compiling.

    A decorator the probe cannot resolve evaluates to a proxy, and calling a proxy returns a
    proxy - so the name the unit defines would be a proxy rather than the function, and
    every unit with a decorator would report `symbol_not_defined`. Dropping them costs this
    witness nothing it claims: the CWEs a decorator carries are the access-control ones, and
    `COVERED_CWES` does not include them precisely because running a function once cannot
    observe an authorisation check that is not there.
    """
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            node.decorator_list = []
    return tree


def _entrypoint(source, symbol, namespace):
    """Compile the unit and hand back the function to drive, or say why there is none."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None, "unparsable"

    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == symbol:
            return None, "async_entrypoint"

    exec(compile(_strip_decorators(tree), "<unit>", "exec", dont_inherit=True), namespace)

    target = dict.get(namespace, symbol)
    if target is None or isinstance(target, Probe) or not callable(target):
        return None, "symbol_not_defined"
    if not hasattr(target, "__code__"):
        return None, "not_a_python_function"
    return target, None


def _arguments(function, trace):
    """One uniquely tokenised untrusted value per parameter, `self` included.

    Every parameter is a source, for the reason the static engine gives (D-058): the unit is
    one function, so its signature is the trust boundary. `self` is a source too - the
    attributes an untrusted caller reached this method through are not a safer place for a
    value to have come from.
    """
    code = function.__code__
    positional = [_untrusted(n, trace) for n in code.co_varnames[: code.co_argcount]]
    keyword_only = code.co_varnames[code.co_argcount : code.co_argcount + code.co_kwonlyargcount]
    return positional, {n: _untrusted(n, trace) for n in keyword_only}


def _builtins(trace):
    """Real builtins, with the ones that execute or open things replaced by proxies."""
    import builtins

    table = {name: getattr(builtins, name) for name in dir(builtins)}
    for name in REPLACED_BUILTINS:
        table[name] = _clean(name, trace)
    return table


def main():
    payload = json.loads(sys.stdin.read())
    sentinel = payload["sentinel"]

    global SINKS, PROPAGATORS, ALIASES
    SINKS = {s["name"]: s for s in payload["sinks"]}
    PROPAGATORS = set(payload["propagators"])
    ALIASES = payload["aliases"]

    trace = Trace(payload["token_prefix"])
    result = {"outcome": "probe_error", "detail": ""}

    try:
        namespace = ProbeNamespace(trace)
        dict.__setitem__(namespace, "__builtins__", _builtins(trace))
        function, why = _entrypoint(payload["source"], payload["symbol"], namespace)
        if function is None:
            result["outcome"], result["detail"] = "no_entrypoint", why
        else:
            args, kwargs = _arguments(function, trace)
            try:
                function(*args, **kwargs)
                result["outcome"] = "completed"
            except BaseException as exc:
                result["outcome"], result["detail"] = "raised", type(exc).__name__[:60]
    except BaseException:
        result["outcome"] = "probe_error"
        result["detail"] = traceback.format_exc(limit=1)[:200]

    result["hits"] = trace.hits
    result["near_misses"] = trace.near_misses
    result["guarded"] = sorted(trace.guarded)
    result["calls"] = trace.calls

    # The sentinel is generated per request on the host with `secrets`, for the reason the
    # semantic agent's prompt delimiter is (D-066): everything above this line ran untrusted
    # code that could print anything it liked, including a line shaped exactly like this one.
    sys.stdout.write(f"\n{sentinel}{json.dumps(result)}\n")
    sys.stdout.flush()


SINKS = {}
PROPAGATORS = set()
ALIASES = {}

if __name__ == "__main__":
    main()
