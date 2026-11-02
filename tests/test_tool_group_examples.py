"""One tested, runnable example for each tool group (documentation rule D12, decision Q5).

Component: regression suite, documentation. Spec: docs/spec.md S1 and S3, and
docs/questions.md Q5 in docs/plans/documentation-standard-gap.md.
Main items: `EXAMPLES` (the 17 examples), `test_each_example_runs`,
`test_there_is_one_example_per_tool_group`. Callers: pytest, and the documentation gate
(`tests/test_documentation_gate.py`), which counts the groups listed here against the groups
in `tests/test_handler_contract.py`. Callees: every handler group's `handle()`.

WHAT AN EXAMPLE IS
==================
A reader who wants to know how to call a tool group looks for one short, working call. Each
entry in `EXAMPLES` is that call: a real, read-only tool from the group, realistic
arguments, and the thing the tool must do, either the REST path it asks the cluster for, the
SQL++ statement it runs, or the answer it returns. The call runs against stubs from
`tests/test_handler_contract.py`, so it needs no cluster and no credentials.

WHY THESE ARE TESTS AND NOT ONLY DOCUMENTATION
==============================================
An example in a document goes stale without anyone noticing. This one fails the build when
the tool is renamed, stops being routed, or asks for a different path. The gate in
`test_documentation_gate.py` also fails when a new tool group is added without an example.

WHAT THIS DOES NOT CLAIM
========================
It does not claim the tool works against a real cluster. That needs a live run
(`scripts/verify_mcp_surface.py`). The example proves the call shape, the routing and the
request the handler makes.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from handlers import shared
from tests.test_handler_contract import (  # noqa: F401  (fixtures are used by name)
    MODULE_NAMES,
    MODULES,
    no_cluster,
    sdk_available,
)


def _answer(result) -> object:
    """The handler's JSON payload, whatever its shape (object or list)."""
    return json.loads(result[0].text)


@pytest.fixture
def rest_calls(no_cluster, monkeypatch):  # noqa: F811
    """Record every REST call a handler makes, then let the stub answer it.

    `no_cluster` replaces the HTTP client with a stub that returns an answer and remembers
    nothing. This wraps that stub so an example can assert on the path asked for, which is
    the thing that proves the tool is wired to the right endpoint.
    """
    calls: list[tuple[str, str]] = []
    for module in [shared, *MODULES.values()]:
        for attr in ("admin_request", "admin_request_json"):
            original = getattr(module, attr, None)
            if original is None:
                continue

            def recorder(method="GET", path="/", *args, _inner=original, **kwargs):
                calls.append((method, path))
                return _inner(method, path, *args, **kwargs)

            monkeypatch.setattr(module, attr, recorder, raising=False)
    return calls


# Each example: (tool group, tool, arguments, what it must do).
#   path:  the REST call the handler makes, as (method, path)
#   sql:   the statement the handler runs, as the start of the SQL++ text
EXAMPLES = [
    (
        "backup",
        "admin_backup_repository_list",
        {},
        ("path", ("GET", "/_p/backup/api/v1/cluster/self/repository/active")),
    ),
    ("buckets", "admin_bucket_list", {}, ("path", ("GET", "/pools/default/buckets"))),
    ("cluster", "admin_cluster_info", {}, ("path", ("GET", "/pools"))),
    (
        "collections",
        "admin_scope_list",
        {"bucket_name": "travel-sample"},
        ("path", ("GET", "/pools/default/buckets/travel-sample/scopes/")),
    ),
    (
        "diagnostics",
        "cb_explain_query",
        {"statement": "SELECT 1"},
        ("sql", "EXPLAIN SELECT 1"),
    ),
    (
        "eight_x",
        "admin_xdcr_conflict_log_query",
        {"bucket_name": "travel-sample"},
        ("sql", "SELECT META().id AS conflict_id"),
    ),
    (
        "encryption",
        "admin_encryption_get",
        {},
        ("path", ("GET", "/settings/security/encryptionAtRest")),
    ),
    (
        "eventing",
        "admin_eventing_list",
        {},
        ("path", ("GET", "/_p/event/api/v1/list/functions")),
    ),
    ("indexes", "admin_index_list", {}, ("sql", "SELECT * FROM system:indexes")),
    ("mcp_status", "cb_mcp_status", {}, ("answer", "server")),
    (
        "search_admin",
        "admin_fts_index_list",
        {},
        ("path", ("GET", "/_p/fts/api/index")),
    ),
    (
        "security",
        "admin_user_list",
        {},
        ("path", ("GET", "/settings/rbac/users/local")),
    ),
    (
        "stats",
        "admin_stats_bucket",
        {"bucket_name": "travel-sample"},
        ("path", ("GET", "/pools/default/buckets/travel-sample/stats")),
    ),
    ("xdcr", "admin_xdcr_replications_list", {}, ("answer", None)),
]


def test_there_is_one_example_per_tool_group():
    """Every group in the handler contract has an example, and none is listed twice.

    Three groups need their own set-up (the backup catalogue and the fixtures use files, and
    Capella uses its own client), so they have their own tests below. They are named here so
    the count is checked in one place.
    """
    # A parametrised collection that is empty runs nothing and passes, so say so first.
    assert EXAMPLES, (
        "there are no examples, so the examples test below would run nothing"
    )
    own_setup = {"backup_catalog", "fixture", "capella"}
    listed = [group for group, *_ in EXAMPLES]
    assert len(listed) == len(set(listed)), "a tool group has two examples"
    assert set(listed) | own_setup == set(MODULE_NAMES), (
        "the examples and the handler groups disagree.\n"
        f"  groups without an example: {sorted(set(MODULE_NAMES) - set(listed) - own_setup)}\n"
        f"  examples for no group:     {sorted(set(listed) - set(MODULE_NAMES))}"
    )
    assert not own_setup & set(listed)
    for group in sorted(own_setup):
        assert callable(globals().get(f"test_the_{group}_example")), (
            f"the {group} group has no test_the_{group}_example"
        )


@pytest.mark.parametrize(
    ("group", "tool", "arguments", "expect"), EXAMPLES, ids=[e[0] for e in EXAMPLES]
)
def test_each_example_runs(
    group,
    tool,
    arguments,
    expect,
    rest_calls,
    no_cluster,  # noqa: F811
):
    """Run the example and check the request the handler made."""
    assert tool in {t.name for t in MODULES[group].TOOLS}, f"{tool} is not in {group}"

    result = MODULES[group].handle(tool, arguments)
    answer = _answer(result)
    assert not (isinstance(answer, dict) and answer.get(shared.ERROR_MARKER)), answer

    kind, wanted = expect
    if kind == "path":
        assert wanted in rest_calls, f"asked for {rest_calls}, wanted {wanted}"
    elif kind == "sql":
        assert any(s.strip().startswith(wanted) for s in no_cluster.statements), (
            f"ran {no_cluster.statements}, wanted one starting {wanted!r}"
        )
    elif wanted:
        assert wanted in answer
    else:
        assert answer == [], "an empty cluster answers with an empty list"


def test_the_backup_catalog_example(tmp_path, monkeypatch):
    """List the catalogue: on an empty root it answers with no entries, and writes nothing."""
    monkeypatch.setenv("CB_ADMIN_CATALOG_ROOT", str(tmp_path))
    answer = _answer(MODULES["backup_catalog"].handle("cb_backup_catalog_list", {}))
    assert not (isinstance(answer, dict) and answer.get(shared.ERROR_MARKER)), answer
    assert list(pathlib.Path(tmp_path).iterdir()) == [], "a list must not create files"


def test_the_fixture_example(tmp_path):
    """List the fixtures under a folder: an empty folder holds none."""
    answer = _answer(
        MODULES["fixture"].handle("admin_fixture_list", {"root_path": str(tmp_path)})
    )
    assert not (isinstance(answer, dict) and answer.get(shared.ERROR_MARKER)), answer


def test_the_capella_example(monkeypatch):
    """List organizations: the first call on a new deployment, and it needs no organization id.

    The Capella client is replaced with a recorder, so nothing leaves the machine.
    """
    from handlers import capella
    from handlers.capella import client

    # A placeholder so the client can build a request. It is not a credential, and the
    # recorder below means no request leaves the machine.
    monkeypatch.setenv("CAPELLA_API_KEY_SECRET", "example-placeholder")
    calls: list[tuple[str, str]] = []

    def fake_request(
        method, path, *, params=None, body=None, content_type="application/json"
    ):
        calls.append((method, path))
        return {"data": [{"id": "org-1", "name": "Example"}]}

    # Both names are replaced: the package binds `capella_request` at import, and the
    # listing helpers reach it through the client module. Patching only one let a real
    # request leave the machine on the first run of this test (it got a 401 back, because
    # the secret is a placeholder). The assertion on `calls` below proves the stub was used.
    monkeypatch.setattr(capella, "capella_request", fake_request)
    monkeypatch.setattr(client, "capella_request", fake_request)
    answer = _answer(capella.handle("capella_organizations_list", {}))
    assert not (isinstance(answer, dict) and answer.get(shared.ERROR_MARKER)), answer
    assert calls and calls[0][0] == "GET" and calls[0][1].endswith("/organizations"), (
        calls
    )
