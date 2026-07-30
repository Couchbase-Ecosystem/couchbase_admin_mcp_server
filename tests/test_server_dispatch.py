"""
`server.py`: tool dispatch, audit classification, and DNS-rebinding host allowlisting.

WHY THESE PARTS
===============
Three things here are load-bearing and were unexercised:

  * `_classify_result` decides what the AUDIT LOG says happened. It once recorded ordinary
    provisioning progress as `denied_handler`, because a Capella phase result carries the
    error marker while being a perfectly successful response. An audit trail that cries wolf
    on every poll is one an operator learns to ignore — and then a real denial goes unread.

  * `call_tool`'s refusal paths distinguish "no such tool" from "disabled by read-only mode"
    from "not available in this deployment mode". Getting that wrong sends someone to the
    wrong configuration file.

  * `_allowed_hosts` builds the DNS-rebinding allowlist. Too narrow and every request is a
    421; too wide and a hostile page can resolve a name it controls to 127.0.0.1 and reach
    the server through the browser.
"""

from __future__ import annotations

import json

import pytest
from mcp.types import TextContent

import server


def _text(payload: dict) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(payload))]


# ── Audit classification ─────────────────────────────────────────────────────


def test_a_plain_success_is_allowed():
    verdict, reason = server._classify_result(_text({"buckets": ["a"]}))
    assert verdict == "allowed"
    assert reason == ""


def test_a_handler_error_is_a_denial():
    verdict, reason = server._classify_result(
        _text({server.shared.ERROR_MARKER: True, "error": "bucket not found"})
    )
    assert verdict == "denied_handler"
    assert "bucket not found" in reason


def test_a_guardrail_refusal_is_classified_separately():
    """It means the project allowlist or name prefix rejected the call, which is a policy
    decision rather than a cluster error — and the two want different responses from whoever
    reads the log."""
    verdict, reason = server._classify_result(
        _text(
            {
                server.shared.ERROR_MARKER: True,
                "error": "project not in CAPELLA_ALLOWED_PROJECTS",
                "guardrail": True,
            }
        )
    )
    assert verdict == "denied_guardrail"
    assert "CAPELLA_ALLOWED_PROJECTS" in reason


def test_an_egress_refusal_is_classified_separately():
    """The cluster was asked to dial a host the operator did not allow. That is the
    reverse-proxy attempt, and it should be findable in the log by name."""
    verdict, _ = server._classify_result(
        _text(
            {
                server.shared.ERROR_MARKER: True,
                "error": "EgressDenied: host not in EGRESS_ALLOWED_HOSTS",
            }
        )
    )
    assert verdict == "denied_egress"


def test_a_non_json_response_is_not_invented_as_a_denial():
    """THE regression this exists for. A handler that returned normally has not denied
    anything, and guessing otherwise fills the log with false alarms."""
    verdict, reason = server._classify_result(
        [TextContent(type="text", text="plain text, not JSON")]
    )
    assert verdict == "allowed"
    assert reason == ""


@pytest.mark.parametrize(
    "result",
    [[], None, "not a list", [object()], _text([1, 2, 3]), _text("a string")],
)
def test_an_unexpected_shape_is_treated_as_success(result):
    """Fail towards silence in the log rather than towards a fabricated denial."""
    assert server._classify_result(result)[0] == "allowed"


def test_the_reason_is_truncated():
    """A handler can return a very long error — a cluster stack trace, say. An audit record
    that grows without bound is a way to make the log unusable, or to push earlier records
    out of a rotation."""
    verdict, reason = server._classify_result(
        _text({server.shared.ERROR_MARKER: True, "error": "x" * 5000})
    )
    assert verdict == "denied_handler"
    assert len(reason) <= 400


def test_a_falsey_error_marker_is_not_a_denial():
    """`_is_error: false` appears on successful responses from some handlers. Treating the
    KEY's presence as the signal rather than its value would deny everything."""
    assert (
        server._classify_result(_text({server.shared.ERROR_MARKER: False, "ok": 1}))[0]
        == "allowed"
    )


# ── Dispatch refusals ────────────────────────────────────────────────────────


@pytest.fixture
def dispatch(monkeypatch):
    """`call_tool` reachable synchronously, capturing what it audits.

    Captured at `audit.emit_tool_call`, NOT at `server._audit`: the latter is a CLOSURE
    defined inside `call_tool` so it can capture the principal and correlation id, which
    means there is no module attribute to patch. Patching a name that does not exist with
    `raising=False` silently did nothing, and three of these tests passed while asserting on
    an empty list.
    """
    import asyncio

    records: list[dict] = []
    monkeypatch.setattr(
        server.audit,
        "emit_tool_call",
        lambda **kwargs: records.append(kwargs),
        raising=False,
    )

    def _call(name, arguments=None):
        return asyncio.get_event_loop().run_until_complete(
            server.call_tool(name, arguments or {})
        )

    return _call, records


def test_an_unregistered_tool_name_is_refused(dispatch):
    call, _records = dispatch
    body = json.loads(call("admin_not_a_real_tool")[0].text)
    assert body[server.shared.ERROR_MARKER] is True
    assert "Unknown tool" in body["error"]


def test_an_unregistered_tool_is_audited(dispatch):
    """A caller probing for tool names is worth seeing in the log."""
    call, records = dispatch
    call("admin_not_a_real_tool")
    assert [r for r in records if r["decision"] == "denied_unknown_tool"]


def test_a_registered_but_unloaded_tool_names_the_reason(dispatch, monkeypatch):
    """The distinction that matters to whoever has to fix it: this tool EXISTS, and is not
    loaded because of configuration. Saying "unknown tool" would send them looking for a
    typo."""
    call, _records = dispatch
    name = next(iter(server._HANDLERS))
    monkeypatch.setattr(server, "_TOOLS", [], raising=False)

    body = json.loads(call(name)[0].text)
    assert body[server.shared.ERROR_MARKER] is True
    assert "not enabled" in body["error"]
    assert "READ_ONLY_MODE" in body["hint"] or "DISABLED_TOOLS" in body["hint"]


def test_an_unloaded_tool_refusal_is_audited(dispatch, monkeypatch):
    call, records = dispatch
    name = next(iter(server._HANDLERS))
    monkeypatch.setattr(server, "_TOOLS", [], raising=False)
    call(name)
    assert [r for r in records if r["decision"] == "denied_read_only"]


def test_a_deployment_gated_tool_says_so_specifically(dispatch, monkeypatch):
    """Pointing at read-only mode when the real reason is "this tool cannot work against
    Capella" wastes the operator's time on the wrong variable."""
    call, records = dispatch
    monkeypatch.setattr(server, "_TOOLS", [], raising=False)
    monkeypatch.setattr(server, "_GATING", True, raising=False)
    monkeypatch.setattr(server, "_DEPLOYMENT_MODE", "capella", raising=False)
    monkeypatch.setattr(
        server.deployment, "tool_is_available", lambda name, mode: False, raising=False
    )
    monkeypatch.setattr(
        server.deployment,
        "unavailable_reason",
        lambda name, mode: "Capella does not expose the management REST API",
        raising=False,
    )

    name = next(iter(server._HANDLERS))
    body = json.loads(call(name)[0].text)
    assert "capella" in body["error"]
    assert body["deployment_mode"] == "capella"
    assert "management REST API" in body["hint"]
    assert [r for r in records if r["decision"] == "denied_deployment"]


# ── Tool filtering ───────────────────────────────────────────────────────────


def test_read_only_mode_filters_out_write_tools():
    """The property the whole read-only deployment rests on."""
    import mcp_compat

    loaded = server._TOOLS
    assert loaded, "no tools loaded"
    # Whatever the ambient configuration, the filter must never contradict itself.
    for tool in loaded:
        if mcp_compat.is_read_only(tool):
            assert not mcp_compat.is_destructive(tool), tool.name


def test_every_loaded_tool_has_a_handler():
    """A tool advertised with no handler is refused as "unknown" the moment it is called —
    discoverable only by calling it."""
    missing = [t.name for t in server._TOOLS if t.name not in server._HANDLERS]
    assert not missing, f"advertised with no handler: {missing}"


def test_every_handler_key_is_a_registered_tool():
    """The inverse: a handler for a name that no tool advertises is dead code, and worse, it
    is REACHABLE — `_HANDLERS` is consulted before the exposed list."""
    raw_names = {t.name for t in server._RAW_TOOLS}
    stray = [name for name in server._HANDLERS if name not in raw_names]
    assert not stray, f"handlers with no corresponding tool: {stray}"


def test_disabled_tools_are_not_loaded(monkeypatch):
    import importlib

    victim = next(t.name for t in server._RAW_TOOLS)
    monkeypatch.setenv("CB_ADMIN_DISABLED_TOOLS", victim)
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "false")
    try:
        import handlers.shared

        importlib.reload(handlers.shared)
        reloaded = importlib.reload(server)
        assert victim not in {t.name for t in reloaded._TOOLS}
    finally:
        monkeypatch.undo()
        import handlers.shared

        importlib.reload(handlers.shared)
        importlib.reload(server)


# ── DNS-rebinding host allowlist ─────────────────────────────────────────────


def test_loopback_names_are_always_allowed(monkeypatch):
    monkeypatch.delenv("CB_ADMIN_ALLOWED_HOSTS", raising=False)
    allowed = server._allowed_hosts("127.0.0.1", 8000)
    assert any("127.0.0.1" in h for h in allowed)
    assert any("localhost" in h for h in allowed)


def test_a_configured_hostname_is_allowed_with_and_without_its_port(monkeypatch):
    """An operator naming a hostname almost never means "only without a port". Requiring both
    spellings would 421 every request from a client that includes one."""
    monkeypatch.setenv("CB_ADMIN_ALLOWED_HOSTS", "cb-admin.internal")
    allowed = server._allowed_hosts("0.0.0.0", 8000)
    assert "cb-admin.internal" in allowed
    assert "cb-admin.internal:8000" in allowed


def test_an_explicit_port_is_not_doubled(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_ALLOWED_HOSTS", "cb-admin.internal:9000")
    allowed = server._allowed_hosts("0.0.0.0", 8000)
    assert "cb-admin.internal:9000" in allowed
    assert "cb-admin.internal:9000:8000" not in allowed


def test_several_hosts_can_be_listed(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_ALLOWED_HOSTS", "a.internal, b.internal ,")
    allowed = server._allowed_hosts("0.0.0.0", 8000)
    assert "a.internal" in allowed
    assert "b.internal" in allowed
    assert "" not in allowed


def test_a_wildcard_bind_with_no_allowlist_warns(monkeypatch, capsys):
    """Every request would 421 with a message from deep inside Starlette. Saying so at
    startup is the difference between a five-minute fix and an afternoon in a proxy log."""
    monkeypatch.delenv("CB_ADMIN_ALLOWED_HOSTS", raising=False)
    server._allowed_hosts("0.0.0.0", 8000)
    assert "CB_ADMIN_ALLOWED_HOSTS" in capsys.readouterr().err


def test_a_loopback_bind_with_no_allowlist_does_not_warn(monkeypatch, capsys):
    """Guards the warning from becoming noise on the default configuration, which is exactly
    how a real warning gets ignored."""
    monkeypatch.delenv("CB_ADMIN_ALLOWED_HOSTS", raising=False)
    server._allowed_hosts("127.0.0.1", 8000)
    assert "CB_ADMIN_ALLOWED_HOSTS" not in capsys.readouterr().err


def test_a_hostile_host_is_not_in_the_allowlist(monkeypatch):
    """The rebinding attack: a page the developer visits resolves attacker.tld to 127.0.0.1
    and posts to the server. The Host header is what distinguishes that from a legitimate
    local client."""
    monkeypatch.delenv("CB_ADMIN_ALLOWED_HOSTS", raising=False)
    allowed = server._allowed_hosts("127.0.0.1", 8000)
    assert "attacker.tld" not in allowed
    assert "*" not in allowed


# ── Correlation ids ──────────────────────────────────────────────────────────


def test_a_correlation_id_argument_is_offered_on_every_tool():
    """It is what ties a child agent's call to the run that spawned it. Absent from one tool,
    that tool's actions cannot be attributed to a pipeline."""
    import mcp_compat

    for tool in server._TOOLS:
        properties = mcp_compat.input_schema(tool).get("properties", {})
        assert "correlation_id" in properties, tool.name


def test_the_correlation_id_is_never_required():
    """An interactive user has no correlation id, and demanding one would make every tool
    unusable by hand."""
    import mcp_compat

    for tool in server._TOOLS:
        required = mcp_compat.input_schema(tool).get("required", [])
        assert "correlation_id" not in required, tool.name
