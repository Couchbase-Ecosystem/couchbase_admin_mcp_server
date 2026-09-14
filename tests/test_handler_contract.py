"""
The contract every handler group must satisfy, checked against all of them.

WHY A SHARED HARNESS RATHER THAN FOURTEEN FILES
==============================================
Coverage measurement found the Couchbase Server handler groups largely untested — several
under 20%. They are also the largest surface in the project: 14 modules, ~134 tools, most of
it inherited code that the Capella work did not touch.

Writing fourteen bespoke suites would mostly duplicate the same handful of assertions, and
would leave the fifteenth module — the one someone adds next year — untested by default.
Instead this file discovers every module and every tool by import and parametrises over
them, so a new handler group is covered the moment it appears in `handlers.__init__`.

WHAT THIS DOES AND DOES NOT CLAIM
=================================
These are contract and safety-posture tests, not behavioural ones. They assert the
properties that are dangerous to get wrong and invisible when you do:

  * a tool whose annotations misdescribe what it does — the read-only catalog and the
    confirmation gate are both built from those flags, so a destructive tool annotated
    read-only loads in the "safe" deployment and skips its gate;
  * a tool advertised in TOOLS that `handle()` does not route — reachable only by calling it;
  * a duplicate tool name across modules — the loser is silently shadowed;
  * a handler that raises instead of returning an error response — a traceback out of the
    transport rather than something the model can read and correct;
  * a schema that declares a required property it does not define — the model is asked for
    a field with no type.

They do NOT assert that any handler produces correct output for a given cluster state. That
needs a live cluster and lives in the live-marked suites.
"""

from __future__ import annotations

import importlib
import inspect
import json
import re

import jsonschema
import pytest
from mcp.types import TextContent

import mcp_compat
from handlers.shared import ERROR_MARKER

#: Every handler group. Derived from the package rather than listed, so a module added to
#: `handlers/` without being added here cannot slip through untested — the discovery test
#: below fails if the two ever disagree.
MODULE_NAMES = [
    "backup",
    # Added 2026-09-14. The guard below did exactly its job: six new tools shipped
    # in a new handler group and every one of the ~134 parametrisations would have
    # passed while testing none of them.
    "backup_catalog",
    "buckets",
    "capella",
    "cluster",
    "collections",
    "diagnostics",
    "eight_x",
    "encryption",
    "eventing",
    "indexes",
    "mcp_status",
    "search_admin",
    "security",
    "stats",
    "xdcr",
]

MODULES = {name: importlib.import_module(f"handlers.{name}") for name in MODULE_NAMES}

#: (module_name, tool) for every tool in every group.
ALL_TOOLS = [(name, tool) for name, module in MODULES.items() for tool in module.TOOLS]

TOOL_IDS = [f"{name}:{tool.name}" for name, tool in ALL_TOOLS]


def test_the_module_list_matches_what_the_package_exposes():
    """Guards every parametrised test below. If a handler group is added and this list is
    not updated, all ~134 parametrisations still pass — they just silently skip the new
    module, which is the failure mode a harness like this is most prone to.
    """
    import pathlib

    import handlers

    on_disk = {
        path.stem
        for path in pathlib.Path(inspect.getsourcefile(handlers)).parent.glob("*.py")
        if not path.stem.startswith("_")
    }
    # Support modules, not handler groups. The exclusion is ASSERTED rather than
    # asserted-by-convention: a module named here that actually exports tools
    # would remove those tools from every parametrised test below, silently,
    # which is the exact failure this function exists to prevent.
    support = {"shared", "egress", "fixture_core"}
    for name in sorted(support):
        module = importlib.import_module(f"handlers.{name}")
        assert not hasattr(module, "TOOLS"), (
            f"handlers/{name}.py is excluded as a support module but exports "
            "TOOLS. Move it into MODULE_NAMES, or the tools it declares are "
            "tested by nothing here."
        )
        assert not hasattr(module, "handle"), (
            f"handlers/{name}.py is excluded as a support module but exports "
            "handle()"
        )
    on_disk -= support
    on_disk.add("capella")  # a subpackage, so not caught by the glob

    assert on_disk == set(MODULE_NAMES), (
        "handlers/ and MODULE_NAMES disagree; a handler group is either untested or gone.\n"
        f"  only on disk: {sorted(on_disk - set(MODULE_NAMES))}\n"
        f"  only listed:  {sorted(set(MODULE_NAMES) - on_disk)}"
    )


def test_there_is_something_to_test():
    """A harness that discovers nothing passes every test it contains."""
    assert len(ALL_TOOLS) > 100, f"only discovered {len(ALL_TOOLS)} tools"


# ── Declarations ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("module_name", "tool"), ALL_TOOLS, ids=TOOL_IDS)
def test_every_tool_has_a_valid_input_schema(module_name, tool):
    """An invalid schema is not rejected by the MCP layer; the model simply gets nonsense
    and calls the tool wrongly."""
    jsonschema.Draft7Validator.check_schema(mcp_compat.input_schema(tool))


@pytest.mark.parametrize(("module_name", "tool"), ALL_TOOLS, ids=TOOL_IDS)
def test_required_properties_are_actually_defined(module_name, tool):
    """A required property with no definition asks the model for a field of unknown type,
    and is usually a rename that missed one of the two places."""
    schema = mcp_compat.input_schema(tool)
    declared = set(schema.get("properties", {}))
    required = set(schema.get("required", []))
    assert required <= declared, (
        f"{tool.name} requires {sorted(required - declared)}, which it does not define"
    )


@pytest.mark.parametrize(("module_name", "tool"), ALL_TOOLS, ids=TOOL_IDS)
def test_every_tool_declares_its_safety_annotations(module_name, tool):
    """The read-only catalog, the confirmation gate and the hard ceiling are all built from
    these. A tool with no annotations is treated as a write — safe, but it also means
    nobody decided, and `_category_of` cannot tell it from a genuine write."""
    assert tool.annotations is not None, f"{tool.name} declares no annotations"


@pytest.mark.parametrize(("module_name", "tool"), ALL_TOOLS, ids=TOOL_IDS)
def test_no_tool_is_both_read_only_and_destructive(module_name, tool):
    """A contradiction, and it resolves in the dangerous direction: `readOnlyHint=True` is
    what loads a tool in read-only mode, so such a tool would be exposed under a read-only
    token while announcing that it destroys data."""
    if mcp_compat.is_read_only(tool):
        assert not mcp_compat.is_destructive(tool), (
            f"{tool.name} is annotated read-only AND destructive"
        )


@pytest.mark.parametrize(("module_name", "tool"), ALL_TOOLS, ids=TOOL_IDS)
def test_every_tool_has_a_description(module_name, tool):
    """The description is the only thing the model has to choose between 134 tools."""
    assert tool.description and tool.description.strip()


def test_tool_names_are_unique_across_all_groups():
    """`server.py` builds one flat list. A duplicate name means one of the two is
    unreachable, and which one depends on module import order."""
    from collections import Counter

    counts = Counter(tool.name for _, tool in ALL_TOOLS)
    duplicates = {name: n for name, n in counts.items() if n > 1}
    assert not duplicates, f"duplicate tool names shadow each other: {duplicates}"


def test_tool_names_are_namespaced():
    """An unprefixed name collides with tools from other MCP servers in the same client,
    where the model has no way to tell them apart."""
    stray = [
        tool.name
        for _, tool in ALL_TOOLS
        if not tool.name.startswith(("cb_", "admin_", "capella_"))
    ]
    assert not stray, f"tool names outside the project's prefixes: {stray}"


# ── Routing: every declared tool is handled ──────────────────────────────────


class _FakeCluster:
    """The one method the SQL++ handlers call on a cluster, plus a record of what they ran.

    `cluster.query` is the entire SDK surface these modules use (verified by grepping for
    attribute access on the cluster, bucket and collection objects), so a stub this small is
    sufficient — and small enough that it cannot quietly diverge from the real thing.
    """

    def __init__(self):
        self.statements: list[str] = []

    def query(self, statement, *args, **kwargs):
        self.statements.append(statement)
        return iter([{"stubbed": True}])


@pytest.fixture
def sdk_available(monkeypatch):
    """Make `from couchbase.options import QueryOptions` succeed.

    `couchbase` is a declared dependency, but it is a C extension and is frequently absent
    from a lint/test environment — and its absence is why the SQL++ handlers had never been
    executed by any test. The real package is preferred when present; the stub only fills in
    when it is not, so this makes the paths reachable everywhere without weakening the run
    where the SDK is installed.

    Only `QueryOptions` is stubbed, and only as a value passed straight through to the
    likewise-stubbed `cluster.query`. Nothing here asserts anything about SDK behaviour.
    """
    try:
        import couchbase.options  # noqa: F401

        return "real"
    except ImportError:
        pass

    import sys
    import types

    package = types.ModuleType("couchbase")
    options = types.ModuleType("couchbase.options")

    class QueryOptions:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    options.QueryOptions = QueryOptions
    package.options = options
    monkeypatch.setitem(sys.modules, "couchbase", package)
    monkeypatch.setitem(sys.modules, "couchbase.options", options)
    return "stub"


@pytest.fixture
def no_cluster(monkeypatch, sdk_available):
    """Cut every path to a real cluster while still letting handlers run to completion.

    Handlers do `from .shared import admin_request`, which binds the name into the module,
    so patching `handlers.shared.admin_request` alone would leave 14 live references. Both
    are patched: the module-level bindings for the handlers, and `shared`'s own for the
    helpers inside it (`get_cluster_version` calls it).

    `get_sdk_connection` is STUBBED, NOT REFUSED. Making it raise seemed safer, and it made
    three modules' tests meaningless: `diagnostics`, `indexes` and `eight_x` call it at the
    top of `handle()`, before the routing switch, so every tool returned "Couchbase
    connection failed" and `test_every_declared_tool_is_routed_by_its_handler` passed
    without ever reaching a route. Coverage was what exposed it — those three sat at 22%,
    23% and 37% while the modules around them were above 90%.
    """
    from handlers import shared

    def _fake_admin_request(method="GET", path="/", *args, **kwargs):
        return {"stubbed": True, "method": method, "path": path}

    cluster = _FakeCluster()

    def _fake_sdk_connection():
        return cluster, object(), object()

    # Every seam, replaced on EVERY module that holds a reference to it — including the
    # derived version predicates, not just the primitives they are built from.
    #
    # Patching `shared.is_version_at_least` and expecting `shared.is_8x` to follow works only
    # if both live in the same module object. Some suites `importlib.reload(handlers.shared)`,
    # which rebinds `sys.modules["handlers.shared"]` to a NEW module while
    # `handlers.eight_x.is_8x` still points at the OLD module's function — whose globals this
    # fixture never touches. Every 8.x tool then hit its version gate and returned "requires
    # Couchbase Server 8.0 or newer", so no query ran.
    #
    # It failed only in a full-suite run and only for `eight_x`, because it needs a reload to
    # have happened earlier in the session. Patching each derived predicate by name on each
    # module removes the dependence on module identity entirely.
    replacements = {
        "admin_request": _fake_admin_request,
        "admin_request_json": _fake_admin_request,
        "get_sdk_connection": _fake_sdk_connection,
        "get_cluster_version": lambda: "8.0.0",
        "is_version_at_least": lambda *a, **k: True,
        "is_8x": lambda: True,
        "is_7x": lambda: False,
    }
    for module in [shared, *MODULES.values()]:
        for attr, replacement in replacements.items():
            if hasattr(module, attr):
                monkeypatch.setattr(module, attr, replacement, raising=False)

    # The fake cluster, so tests can inspect the statements handlers actually ran.
    return cluster


def _sample(fragment: dict):
    """A plausible value for one schema property."""
    if fragment.get("enum"):
        return fragment["enum"][0]
    kind = fragment.get("type", "string")
    if isinstance(kind, list):
        kind = kind[0]
    return {
        "string": "sample",
        "integer": 1,
        "number": 1,
        "boolean": True,
        "array": [],
        "object": {},
        "null": None,
    }.get(kind, "sample")


def _minimal_args(tool) -> dict:
    """The smallest argument dict that satisfies a tool's `required` list."""
    schema = mcp_compat.input_schema(tool)
    properties = schema.get("properties", {})
    args = {key: _sample(properties.get(key, {})) for key in schema.get("required", [])}
    # Destructive tools gate on this. Supplying it keeps the call from stopping at the
    # confirmation check before it has demonstrated that it is routed at all.
    if "confirm" in properties:
        args["confirm"] = True
    return args


def _body(result) -> dict:
    """The handler's JSON, AS A DICT -- and a list payload is not an error.

    This returned `json.loads(...)` unconditionally and every caller then did
    `body.get(...)`. That held only because the fake cluster always answers with
    an object. It is not the contract: plenty of these tools return a bare JSON
    ARRAY, because the endpoint behind them does -- admin_bucket_list,
    admin_role_list, admin_backup_plans_list. The moment one returned a list
    regardless of the fake (admin_xdcr_replications_list, once it stopped
    reading the wrong endpoint on 2026-09-14) these tests raised
    AttributeError: 'list' object has no attribute 'get'.

    That was the TEST's blind spot, not the handler's bug, and it mattered:
    a tool that fell through to "unknown tool" while returning a list would
    have sailed past these checks. Wrapping a list payload preserves what each
    caller is actually asking -- is there an error marker, is there an error
    message -- and a list has neither, which is the correct answer.
    """
    assert isinstance(result, list) and result, "handler returned no content"
    assert all(isinstance(item, TextContent) for item in result)
    payload = json.loads(result[0].text)
    if isinstance(payload, dict):
        return payload
    return {"_payload": payload}


@pytest.mark.parametrize(("module_name", "tool"), ALL_TOOLS, ids=TOOL_IDS)
def test_every_declared_tool_is_routed_by_its_handler(module_name, tool, no_cluster):
    """A tool in TOOLS with no branch in `handle()` is advertised to the model and then
    refused as unknown. Nothing catches that except calling it.

    Any error is acceptable here — missing arguments, a version gate, a refused
    confirmation. What is not acceptable is the fall-through "unknown tool" message, which
    is the specific signature of an unrouted tool.
    """
    body = _body(MODULES[module_name].handle(tool.name, _minimal_args(tool)))
    message = str(body.get("error", ""))
    assert not re.search(r"[Uu]nknown \w+ tool", message), (
        f"{tool.name} is declared in handlers.{module_name}.TOOLS but not routed: {message}"
    )


@pytest.mark.parametrize("module_name", ["diagnostics", "indexes", "eight_x"])
def test_the_sql_modules_are_actually_reached_not_short_circuited(
    module_name, no_cluster
):
    """Proves the routing test above is not vacuous for these three.

    They call `get_sdk_connection()` before the routing switch, so a fixture that made it
    raise produced "Couchbase connection failed" for every tool — and the routing assertion,
    which only looks for the "unknown tool" message, passed without a single route being
    exercised. This asserts the handler got past that point and ran a statement.
    """
    module = MODULES[module_name]
    ran_something = False
    for tool in module.TOOLS:
        no_cluster.statements.clear()
        module.handle(tool.name, _minimal_args(tool))
        if no_cluster.statements:
            ran_something = True
    assert ran_something, (
        f"no tool in handlers.{module_name} reached a query; the fixture is short-circuiting "
        "the handler and the routing test for this module proves nothing"
    )


@pytest.fixture
def sdk_missing(monkeypatch):
    """Make `import couchbase` fail, however it is spelled.

    A `MetaPathFinder` rather than a `sys.modules` deletion, because the handlers import
    inside the function body: deleting the entry only sends the import machinery back to the
    real installed package. This blocks the name at resolution time, which is what an
    environment without the C extension actually looks like.
    """
    import sys

    class _Blocker:
        def find_spec(self, fullname, path=None, target=None):
            if fullname == "couchbase" or fullname.startswith("couchbase."):
                raise ModuleNotFoundError(f"No module named {fullname!r}")

    for name in [n for n in list(sys.modules) if n.split(".")[0] == "couchbase"]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    blocker = _Blocker()
    monkeypatch.setattr(sys, "meta_path", [blocker, *sys.meta_path])
    return blocker


@pytest.mark.parametrize("module_name", ["diagnostics", "indexes", "eight_x"])
def test_a_missing_sdk_becomes_an_error_response_not_a_traceback(
    module_name, monkeypatch, sdk_missing
):
    """`from couchbase.options import QueryOptions` inside `handle()` used to sit OUTSIDE the
    function's try block in `diagnostics`, so an ImportError escaped uncaught and reached the
    MCP transport as a traceback instead of a readable error.

    That is not hypothetical: `couchbase` is a C extension, and a slim image or a partial
    install is exactly how it goes missing. Every other failure in this project comes back
    as `err()`; this one exit did not.
    """
    from handlers import shared

    module = MODULES[module_name]
    cluster = _FakeCluster()
    for target in (shared, module):
        if hasattr(target, "get_sdk_connection"):
            monkeypatch.setattr(
                target,
                "get_sdk_connection",
                lambda: (cluster, object(), object()),
                raising=False,
            )

    for tool in module.TOOLS:
        # Must not raise. That is the whole assertion.
        result = module.handle(tool.name, _minimal_args(tool))
        assert isinstance(result, list) and result, tool.name
        assert isinstance(result[0], TextContent), tool.name


@pytest.mark.parametrize(("module_name", "tool"), ALL_TOOLS, ids=TOOL_IDS)
def test_no_handler_raises_on_empty_arguments(module_name, tool, no_cluster):
    """The model omits required arguments routinely. That has to come back as an error
    response it can read and retry, not an exception out of the transport — and the
    difference is invisible until it happens in front of a user.
    """
    body = _body(MODULES[module_name].handle(tool.name, {}))
    if body.get(ERROR_MARKER):
        assert body.get("error"), f"{tool.name} returned an error with no message"


@pytest.mark.parametrize("module_name", MODULE_NAMES)
def test_an_unknown_tool_name_is_refused_not_ignored(module_name, no_cluster):
    """`server.py` dispatches by prefix. A group that returned success for a name it does
    not implement would make a typo look like a no-op that worked."""
    body = _body(MODULES[module_name].handle("cb_definitely_not_a_real_tool", {}))
    assert body.get(ERROR_MARKER) is True


@pytest.mark.parametrize("module_name", MODULE_NAMES)
def test_error_responses_carry_the_error_marker(module_name, no_cluster):
    """The marker is how `server.py` and the console tell success from failure. An error
    without it is reported to the caller as a success."""
    body = _body(MODULES[module_name].handle("cb_definitely_not_a_real_tool", {}))
    assert ERROR_MARKER in body


# ── The SQL++ write prohibition ──────────────────────────────────────────────


def test_no_handler_embeds_a_mutating_sql_statement():
    """A standing constraint on this project: nothing writes data through SQL++. The query
    tools exist for read-only debugging and block DML internally.

    A literal INSERT/UPDATE/DELETE/UPSERT/MERGE in handler source would be a write path
    that bypasses `is_dml_statement` entirely, because that guard only inspects statements
    arriving as arguments. Index DDL is excluded: CREATE INDEX and DROP INDEX are schema
    operations with their own dedicated guards (`assert_index_create_ddl` /
    `assert_index_drop_ddl`), not data writes.
    """
    import pathlib

    import handlers

    root = pathlib.Path(inspect.getsourcefile(handlers)).parent
    # Clause structure, not keywords. Matching a bare `UPDATE\s+\w` found thirteen tool
    # DESCRIPTIONS — "Update settings on an existing bucket", "Create or update an FTS
    # index" — because every one of these verbs is also an ordinary English word. Requiring
    # the shape of the statement (`UPDATE <target> SET`, `DELETE FROM`) is what separates a
    # SQL++ string from prose about updating something.
    dml = re.compile(
        r"""["'`][^"'`]*\b("""
        r"""INSERT\s+INTO\s|UPSERT\s+INTO\s|DELETE\s+FROM\s|MERGE\s+INTO\s"""
        r"""|UPDATE\s+\S+\s+SET\b"""
        r""")""",
        re.IGNORECASE,
    )

    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if dml.search(line):
                offenders.append(f"{path.name}:{number}: {stripped[:80]}")

    assert not offenders, (
        "these look like data-mutating SQL++ embedded in a handler, which would write "
        "without passing the DML guard:\n  " + "\n  ".join(offenders)
    )


def test_the_dml_scan_would_catch_a_real_offender():
    """Without this the test above passes if the pattern stops matching."""
    # Clause structure, not keywords. Matching a bare `UPDATE\s+\w` found thirteen tool
    # DESCRIPTIONS — "Update settings on an existing bucket", "Create or update an FTS
    # index" — because every one of these verbs is also an ordinary English word. Requiring
    # the shape of the statement (`UPDATE <target> SET`, `DELETE FROM`) is what separates a
    # SQL++ string from prose about updating something.
    dml = re.compile(
        r"""["'`][^"'`]*\b("""
        r"""INSERT\s+INTO\s|UPSERT\s+INTO\s|DELETE\s+FROM\s|MERGE\s+INTO\s"""
        r"""|UPDATE\s+\S+\s+SET\b"""
        r""")""",
        re.IGNORECASE,
    )
    assert dml.search('stmt = "INSERT INTO bucket VALUES (1)"')
    assert dml.search('stmt = "UPSERT INTO b (KEY, VALUE) VALUES (1, 2)"')
    assert dml.search("q = 'delete from `b` where x = 1'")
    assert dml.search('f"UPDATE {bucket} SET x = 1"')
    assert dml.search('stmt = "MERGE INTO a USING b ON a.k = b.k"')
    # Reads and index DDL must not match.
    assert not dml.search('stmt = "SELECT * FROM bucket"')
    assert not dml.search('stmt = "CREATE INDEX ix ON b(x)"')
    assert not dml.search('stmt = "DROP INDEX b.ix"')
    # Prose, which is what the first version of this pattern actually found.
    assert not dml.search('description="Update settings on an existing bucket"')
    assert not dml.search('"Create or update an FTS index. Pass the definition"')
    assert not dml.search('"Update Query Service settings. Common keys: ..."')


# ── Read-only mode is respected by declaration ───────────────────────────────


def test_the_read_only_catalog_contains_no_destructive_tool():
    """What CB_ADMIN_READ_ONLY_MODE actually filters on. This is the property the whole
    read-only deployment rests on, expressed over every tool at once."""
    leaked = [
        tool.name
        for _, tool in ALL_TOOLS
        if mcp_compat.is_read_only(tool) and mcp_compat.is_destructive(tool)
    ]
    assert not leaked


def test_a_meaningful_number_of_tools_are_writes():
    """If every tool were annotated read-only the test above would pass and read-only mode
    would filter nothing. This pins that the annotations discriminate at all."""
    writes = [tool for _, tool in ALL_TOOLS if not mcp_compat.is_read_only(tool)]
    reads = [tool for _, tool in ALL_TOOLS if mcp_compat.is_read_only(tool)]
    assert len(writes) > 20, f"only {len(writes)} write tools — annotations look wrong"
    assert len(reads) > 20, f"only {len(reads)} read tools — annotations look wrong"
