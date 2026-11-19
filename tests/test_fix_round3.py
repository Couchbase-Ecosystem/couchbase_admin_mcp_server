"""Regression tests for the round-3 fixes: export preview, export page cap, introspection scoping.

Component: regression suite; see tests/README.md.
Spec: docs/spec.md S3 steps 3 and 7, S9.
Main items: tests for `dry_run` on the fixture export tools, the `page_size` bound, the audit size cap, and the
    caller-scoped view of the `cb_mcp_*` tools.
Callers: none; collected by pytest
Callees: `audit`, `auth.scope_gate`, `authz`, `dryrun`, `handlers.capella.fixture`, `handlers.fixture`,
    `handlers.fixture_core`, `handlers.mcp_status`, `mcp_compat`, `server`

Each test fails on the code before the fix.
"""

import json

import pytest

import authz
import dryrun
import mcp_compat
import server
from auth import scope_gate
from handlers import fixture, fixture_core, mcp_status
from handlers.capella import fixture as capella_fixture


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, 1000), (1, 1), (5000, 5000), (250, 250)],
)
def test_page_size_accepts_the_documented_range(raw, expected):
    assert fixture_core.bounded_page_size(raw) == (expected, "")


@pytest.mark.parametrize("raw", [0, -1, 5001, 10**9, "1000", 1.5, True, [], {}])
def test_page_size_outside_the_range_is_refused_not_clamped(raw):
    size, problem = fixture_core.bounded_page_size(raw)
    assert size == 0
    assert "page_size" in problem


_EXPORT_TOOLS = [
    t
    for t in (*fixture.TOOLS, *capella_fixture.TOOLS)
    if t.name.endswith("fixture_export")
]


def test_both_export_tools_are_present():
    assert sorted(t.name for t in _EXPORT_TOOLS) == [
        "admin_fixture_export",
        "capella_fixture_export",
    ]


@pytest.mark.parametrize("tool", _EXPORT_TOOLS, ids=lambda t: t.name)
def test_export_tools_declare_dry_run_and_a_bounded_page_size(tool, monkeypatch):
    props = mcp_compat.input_schema(tool)["properties"]
    assert props["dry_run"]["type"] == "boolean"
    assert props["page_size"]["minimum"] == 1
    assert props["page_size"]["maximum"] == 5000
    # Declaring it is what makes the tool handler-owned, so the dispatch no longer strips the
    # caller's flag before the handler can honour it.
    monkeypatch.setattr(dryrun, "_HANDLER_OWNED", set())
    dryrun.register_handler_owned([tool])
    assert tool.name in dryrun.handler_owned_tools()


def test_a_callers_dry_run_on_export_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("CB_ADMIN_FIXTURE_ROOT", str(tmp_path))

    def boom():
        raise AssertionError("a preview must not reach the cluster")

    monkeypatch.setattr(fixture, "get_sdk_cluster", boom, raising=False)
    target = tmp_path / "fx"
    out = fixture.handle(
        "admin_fixture_export",
        {"fixture_id": "x", "fixture_path": str(target), "dry_run": True},
    )
    payload = json.loads(out[0].text)
    assert payload["dry_run"] is True
    assert not target.exists()


def test_an_out_of_range_page_size_is_refused_before_any_work(tmp_path, monkeypatch):
    monkeypatch.setenv("CB_ADMIN_FIXTURE_ROOT", str(tmp_path))
    out = fixture.handle(
        "admin_fixture_export",
        {"fixture_id": "x", "fixture_path": str(tmp_path / "fx"), "page_size": 10**9},
    )
    assert "page_size" in json.loads(out[0].text)["error"]
    assert not (tmp_path / "fx").exists()


@pytest.fixture
def surface(monkeypatch):
    """A tiny catalogue with one read tool and one write tool, so scoping is observable."""
    from mcp.types import Tool, ToolAnnotations

    schema = {"type": "object", "properties": {}}
    read = Tool(
        name="demo_read",
        description="r",
        inputSchema=schema,
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    write = Tool(
        name="demo_write",
        description="w",
        inputSchema=schema,
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False),
    )
    monkeypatch.setattr(server, "_TOOLS", [read, write])
    monkeypatch.setattr(server, "_RAW_TOOLS", [read, write])
    monkeypatch.setenv("CB_ADMIN_SCOPE_READ", "couchbase-admin-mcp:read")
    monkeypatch.setenv("CB_ADMIN_SCOPE_WRITE", "couchbase-admin-mcp:write")
    return read, write


def _reader_claims():
    return {"scope": scope_gate._scope_read()}


def _names(out):
    return {row["name"] for row in json.loads(out[0].text)["tools"]}


def test_list_tools_introspection_is_scoped_to_the_callers_token(surface):
    everything = _names(mcp_status.handle("cb_mcp_list_tools", {}))
    with authz.caller_context(human_present=False, claims=_reader_claims()):
        scoped = _names(mcp_status.handle("cb_mcp_list_tools", {}))
    assert scoped < everything
    assert everything == {"demo_read", "demo_write"}
    assert scoped == {"demo_read"}


def test_get_tool_info_for_a_tool_the_caller_cannot_use_looks_like_no_such_tool(
    surface,
):
    with authz.caller_context(human_present=False, claims=_reader_claims()):
        hidden = json.loads(
            mcp_status.handle("cb_mcp_get_tool_info", {"tool_name": "demo_write"})[
                0
            ].text
        )
        absent = json.loads(
            mcp_status.handle(
                "cb_mcp_get_tool_info", {"tool_name": "no_such_tool_xyz"}
            )[0].text
        )
    assert "error" in hidden
    assert hidden["error"].replace("demo_write", "X") == absent["error"].replace(
        "no_such_tool_xyz", "X"
    )


def test_status_counts_only_what_the_caller_may_see(surface):
    full = json.loads(mcp_status.handle("cb_mcp_status", {})[0].text)
    with authz.caller_context(human_present=False, claims=_reader_claims()):
        scoped = json.loads(mcp_status.handle("cb_mcp_status", {})[0].text)
    assert (full["tools"]["loaded"], scoped["tools"]["loaded"]) == (2, 1)
    assert scoped["tools"]["by_category"]["write"] == 0


def test_claims_do_not_leak_past_the_context():
    with authz.caller_context(human_present=False, claims=_reader_claims()):
        assert authz.caller_claims() is not None
    assert authz.caller_claims() is None


@pytest.mark.parametrize("spelling", ["1", "true", "yes", "on", "y", "t", " Y "])
def test_server_wide_dry_run_reads_every_truthy_spelling(monkeypatch, spelling):
    monkeypatch.setenv(dryrun.ENV, spelling)
    assert dryrun.server_wide() is True


def test_server_wide_dry_run_is_off_for_other_values(monkeypatch):
    for value in ("", "0", "false", "no", "off", "maybe"):
        monkeypatch.setenv(dryrun.ENV, value)
        assert dryrun.server_wide() is False


def test_an_audit_record_cannot_be_made_unbounded():
    import audit

    huge = "A" * 5_000_000
    record = audit.build_record(
        tool=huge,
        decision="denied_scope",
        arguments={"body": {"statement": huge, "items": [huge]}},
        reason=huge,
    )
    line = json.dumps(record)
    assert len(line) < 20_000
    assert "chars not logged" in record["tool"]
    assert "chars not logged" in record["reason"]
    assert "chars not logged" in record["args"]["body"]["statement"]


def test_a_short_audit_record_is_unchanged():
    import audit

    record = audit.build_record(
        tool="admin_bucket_list", decision="allowed", arguments={"a": "b" * 100}
    )
    assert record["args"] == {"a": "b" * 100}
    assert record["tool"] == "admin_bucket_list"
