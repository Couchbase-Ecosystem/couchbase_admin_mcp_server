"""The console and the MCP transport must DECIDE the same way, not merely
advertise the same tools.

tests/test_gui_authorization.py already asserts that both surfaces expose an
IDENTICAL tool set, in both directions. That test exists because
handlers/backup_catalog.py was absent from the console for its entire life and
nothing compared the two lists. But membership parity is the weaker half.
CLAUDE.md put it plainly: "Membership is guarded; behaviour is not."

Behaviour is where this codebase has actually been bitten, repeatedly, and always
the same way -- a policy fixed in one dispatch path and not the other:

  * the ceiling check nested inside `if in_confirm_set and automation_mode`, so
    with automation off a ceiling tool fell through to the caller's own `confirm`
  * `bool(body.get("automation"))` letting a caller self-promote out of the gate
  * every console refusal collapsed to `denied_handler`, so a SIEM rule written
    against the documented vocabulary never fired for console-originated attacks
  * `_HANDLER_OWNED` registered only in server.py, so every capella_env_reap
    through the console was a preview and expired environments billed forever
  * the console stripping `confirm` but not `correlation_id`

Each was found after it shipped. This file drives the SAME call through BOTH
paths and compares the decision, so the next one is found by CI instead.

Where the two paths differ ON PURPOSE, that difference is asserted here too --
see test_the_console_refuses_a_ceiling_tool_the_mcp_path_performs. An intentional
divergence that nothing pins is indistinguishable from drift six months later.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sys

import pytest

import audit
import mcp_compat
from auth.scope_gate import is_read_side

ENV = {
    "CB_ADMIN_PROFILE": "workstation",
    "CB_DEPLOYMENT": "self_managed",
    "CB_ADMIN_REQUIRE_DEPLOYMENT": "self_managed",
    "CB_ADMIN_READ_ONLY_MODE": "false",
    "CB_GUI_INSECURE_NO_AUTH": "1",
    "OAUTH_ENABLED": "false",
    "CB_ADMIN_ALWAYS_CONFIRM": "admin_bucket_flush",
}

READ_TOOL = "admin_bucket_list"
WRITE_TOOL = "admin_bucket_create"
CEILING_TOOL = "admin_bucket_flush"


class _StubHandler:
    """Stands in for a handler module so no call reaches a cluster.

    Records the arguments it was handed, which is how the control-field tests
    see what each dispatch path stripped.
    """

    def __init__(self):
        self.seen: list[dict] = []

    def handle(self, name, arguments):
        self.seen.append(dict(arguments))
        from mcp.types import TextContent

        return [TextContent(type="text", text=json.dumps({"ok": True}))]


@pytest.fixture
def both(monkeypatch, tmp_path):
    """Load both dispatch paths under ONE environment, and capture every audit
    record either of them emits.

    Both paths call audit.emit_tool_call, so a single patch observes both. That
    is not an accident of the test -- it is the property the audit layer was
    refactored to have, and reading it from one place here is what makes the two
    records comparable.
    """
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(tmp_path / "audit.log"))
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    audit.reset_audit_sink()

    for name in ("profile_config", "handlers.shared", "authz", "deployment"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)

    import server

    server = importlib.reload(server)

    sys.modules.pop("gui.gui_server", None)
    gui = importlib.import_module("gui.gui_server")
    gui.app.config.update(TESTING=True)

    records: list[dict] = []
    monkeypatch.setattr(
        audit, "emit_tool_call", lambda **kw: records.append(kw), raising=False
    )

    def via_mcp(tool, **arguments):
        del records[:]
        result = asyncio.run(server.call_tool(tool, dict(arguments)))
        return records[-1] if records else None, result

    def via_console(tool, **arguments):
        del records[:]
        client = gui.app.test_client()
        response = client.post(
            "/api/call", json={"tool": tool, "arguments": dict(arguments)}
        )
        return records[-1] if records else None, response

    yield server, gui, via_mcp, via_console
    audit.reset_audit_sink()


def _stub_both(monkeypatch, server, gui, tool):
    """Replace the handler on BOTH registries with one stub, so the two paths are
    compared on policy rather than on what a handler happens to do."""
    stub = _StubHandler()
    monkeypatch.setitem(server._HANDLERS, tool, stub)
    monkeypatch.setitem(gui.HANDLERS, tool, stub)
    return stub


# ── The classifier that decides "is this a write" must be one answer ──────────


def test_the_two_paths_classify_write_side_tools_identically(both):
    """Three expressions of one policy, which is the drift hazard itself.

    server.py asks `not mcp_compat.is_read_only(t)`. The console's /api/call asks
    `not (t.annotations and mcp_compat.is_read_only(t))`. The scope gate asks
    `not is_read_side(t)`. They agree today on all 284 tools. Nothing said they
    had to, and a tool added with unusual annotations is exactly how they would
    stop agreeing -- silently, with the console gating something the transport
    does not or the reverse.
    """
    server, _gui, _m, _c = both
    raw = server._RAW_TOOLS
    by_server = {t.name for t in raw if not mcp_compat.is_read_only(t)}
    by_console = {
        t.name for t in raw if not (t.annotations and mcp_compat.is_read_only(t))
    }
    by_scope_gate = {t.name for t in raw if not is_read_side(t)}

    assert by_server == by_console, (
        "server.py and the console disagree about which tools are write-side: "
        f"{sorted(by_server ^ by_console)}"
    )
    assert by_server == by_scope_gate, (
        "the dispatch and the scope gate disagree about which tools are "
        f"write-side: {sorted(by_server ^ by_scope_gate)}"
    )


# ── The confirmation gate ─────────────────────────────────────────────────────


def test_a_write_without_confirmation_is_refused_by_both_paths(both):
    server, gui, via_mcp, via_console = both
    mcp_record, _ = via_mcp(WRITE_TOOL, name="parity-test")
    gui_record, response = via_console(WRITE_TOOL, name="parity-test")

    assert mcp_record["decision"] == "denied_confirmation"
    assert gui_record["decision"] == mcp_record["decision"], (
        f"MCP refused with {mcp_record['decision']!r} and the console with "
        f"{gui_record['decision']!r} for the same call"
    )
    assert response.status_code == 403


def test_a_confirmed_write_reaches_the_handler_on_both_paths(both, monkeypatch):
    server, gui, via_mcp, via_console = both
    stub = _stub_both(monkeypatch, server, gui, WRITE_TOOL)

    mcp_record, _ = via_mcp(WRITE_TOOL, name="parity-test", confirm=True)
    gui_record, response = via_console(WRITE_TOOL, name="parity-test", confirm=True)

    assert mcp_record["decision"] == "allowed"
    assert gui_record["decision"] == "allowed"
    assert response.status_code == 200
    assert json.loads(response.data)["ok"] is True
    assert len(stub.seen) == 2, "both paths should have reached the handler once"


def test_a_read_tool_is_allowed_by_both_paths(both, monkeypatch):
    server, gui, via_mcp, via_console = both
    _stub_both(monkeypatch, server, gui, READ_TOOL)

    mcp_record, _ = via_mcp(READ_TOOL)
    gui_record, _ = via_console(READ_TOOL)

    assert mcp_record["decision"] == "allowed"
    assert gui_record["decision"] == "allowed"


# ── Control fields must not reach a handler from either path ──────────────────


def test_both_paths_strip_the_control_fields_before_the_handler(both, monkeypatch):
    """`confirm` and `correlation_id` are dispatch concerns. Either one reaching a
    handler becomes a stray parameter on a REST body or an SDK call.

    The console used to strip `confirm` and not `correlation_id`, so a caller
    following the documented advice to pass a correlation id was refused by the
    mass-assignment allow-list -- the provenance field breaking the very tools it
    annotates.
    """
    server, gui, via_mcp, via_console = both
    stub = _stub_both(monkeypatch, server, gui, WRITE_TOOL)

    via_mcp(WRITE_TOOL, name="parity-test", confirm=True, correlation_id="run-1")
    via_console(WRITE_TOOL, name="parity-test", confirm=True, correlation_id="run-1")

    assert len(stub.seen) == 2
    for seen, path in zip(stub.seen, ("mcp", "console"), strict=False):
        assert "confirm" not in seen, f"{path} leaked `confirm` to the handler"
        assert "correlation_id" not in seen, (
            f"{path} leaked `correlation_id` to the handler"
        )
    assert stub.seen[0] == stub.seen[1], (
        "the two paths handed the handler different arguments: "
        f"{stub.seen[0]} vs {stub.seen[1]}"
    )


# ── Provenance: the same caller-supplied value must be made safe on both ───────


def test_a_correlation_id_is_sanitised_on_both_paths(both, monkeypatch):
    """CR/LF in a correlation id lets whoever drives the agent fabricate whole
    audit records and hide a real operation inside a forged one.

    audit.sanitize_correlation exists for exactly that, and server.py calls it
    before any decision path runs. The console read
    `arguments.get("correlation_id")` raw, so the guard was absent on the second
    dispatch path -- the same shape as every other defect this file is here to
    catch, and this one is on the audit trail itself.
    """
    server, gui, via_mcp, via_console = both
    _stub_both(monkeypatch, server, gui, READ_TOOL)

    forged = 'run-1\r\n2026-01-01T00:00:00Z AUDIT {"decision": "allowed"}'
    mcp_record, _ = via_mcp(READ_TOOL, correlation_id=forged)
    gui_record, _ = via_console(READ_TOOL, correlation_id=forged)

    for record, path in ((mcp_record, "mcp"), (gui_record, "console")):
        value = record["correlation_id"] or ""
        assert "\n" not in value and "\r" not in value, (
            f"{path} wrote an unsanitised correlation id into the audit record: "
            f"{value!r} -- a newline here forges log lines"
        )
    assert gui_record["correlation_id"] == mcp_record["correlation_id"], (
        "the two paths sanitised the same correlation id differently: "
        f"{mcp_record['correlation_id']!r} vs {gui_record['correlation_id']!r}"
    )


# ── The one difference that is deliberate ─────────────────────────────────────


def test_the_console_refuses_a_ceiling_tool_the_mcp_path_performs(both, monkeypatch):
    """ASSERTED DIVERGENCE, not drift.

    The console passes human_present=False unconditionally. A browser click is
    not a human confirmation: in the workstation profile the console is
    unauthenticated, and the origin allowlist necessarily permits any localhost
    port, so any page served from the developer's own machine is an allowed
    origin. The hard ceiling means "a person must approve THIS operation", and
    only the MCP client can surface the specific call and take an answer.

    This test exists so that if someone later "fixes the inconsistency" by
    letting the console satisfy the ceiling, they have to delete a test that says
    why it is not an inconsistency.
    """
    server, gui, via_mcp, via_console = both
    _stub_both(monkeypatch, server, gui, CEILING_TOOL)

    mcp_record, _ = via_mcp(CEILING_TOOL, name="parity-test", confirm=True)
    gui_record, response = via_console(CEILING_TOOL, name="parity-test", confirm=True)

    assert mcp_record["decision"] == "allowed", (
        "an interactive MCP session on a workstation should satisfy the ceiling"
    )
    assert gui_record["decision"].startswith("denied"), (
        "the console must never satisfy the hard ceiling; it got "
        f"{gui_record['decision']!r}"
    )
    assert response.status_code == 403
