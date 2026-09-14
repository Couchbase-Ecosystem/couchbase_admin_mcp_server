"""
The GUI's POST /api/call is a SECOND dispatch path into the same handlers, and every
control the MCP transport enforces has to hold here too.

It did not. Round-2 review found the console:

  * never called check_scope, so any authenticated user in the tenant had the full
    destructive tool surface regardless of the scopes in their token;
  * tested the hard ceiling only INSIDE ``if in_confirm_set and automation_mode``, so
    with automation off a ceiling tool fell through to the ordinary gate and the
    caller's own ``confirm: true`` satisfied it;
  * emitted no audit record for any operation, making the console the one way to act
    without leaving a trace;
  * enforced its loopback posture from GUI_HOST, which the gunicorn entrypoint never
    sets — so the guard read the 127.0.0.1 default while the process served every
    interface.

These tests drive the real Flask app with the real decision code.
"""

from __future__ import annotations

import importlib
import json
import sys

import pytest

flask = pytest.importorskip("flask")


def _load_gui(monkeypatch, **env):
    """Import gui.gui_server under a given environment, fresh each time."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", env.pop("CB_ADMIN_PROFILE", "workstation"))
    for key, value in env.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)

    # RELOAD in place, never sys.modules.pop.
    # Popping rebinds these to NEW module objects, so another test file
    # holding a reference to the old one fails on its own importlib.reload
    # with "module not in sys.modules". That silently disabled 6 tests in
    # test_audit_and_profile.py -- including two enterprise-profile security
    # refusals -- whenever this file collected first. reload re-executes the
    # module body, which is what the pop was for, without breaking identity.
    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)
    # gui.gui_server is POPPED, not reloaded: its posture enforcement runs at IMPORT
    # time and that side effect is what these tests assert on, so it must genuinely
    # re-execute. Popping it is safe -- unlike the shared policy modules, no other test
    # file holds a long-lived reference to this module object.
    sys.modules.pop("gui.gui_server", None)
    import profile_config

    importlib.reload(profile_config)
    module = importlib.import_module("gui.gui_server")
    return importlib.reload(module)


@pytest.fixture
def audit_file(tmp_path, monkeypatch):
    """Point the dedicated audit sink at a real file and reset its memo."""
    path = tmp_path / "audit.log"
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(path))
    import audit

    audit.reset_audit_sink()
    yield path
    audit.reset_audit_sink()


@pytest.fixture
def gui(monkeypatch, audit_file):
    module = _load_gui(
        monkeypatch,
        CB_GUI_INSECURE_NO_AUTH="1",
        OAUTH_ENABLED="false",
        CB_ADMIN_ALWAYS_CONFIRM="admin_bucket_delete",
        CB_ADMIN_READ_ONLY_MODE="false",
    )
    module.app.config.update(TESTING=True)
    return module


def _call(client, tool, **arguments):
    return client.post("/api/call", json={"tool": tool, "arguments": arguments})


def _audit_records(path):
    """Audit records actually written to the dedicated sink FILE.

    Deliberately not caplog. caplog attaches to the ROOT logger, so it observes the
    logger CALL rather than a configured sink — and `couchbase-admin` sets
    propagate=False once configure_from_env() has run. That is exactly why the earlier
    version of these tests passed while the GUI process configured no logging at all
    and dropped every audit record on the floor. Reading the file is the only
    assertion that can tell "emitted" from "discarded".
    """
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if "AUDIT " in line:
            out.append(json.loads(line.split("AUDIT ", 1)[1]))
    return out


# ── The hard ceiling must not be satisfiable by the caller's own confirm ──────


def test_ceiling_tool_is_refused_when_automation_is_off(gui, monkeypatch):
    """The exact drift: the ceiling check was nested under automation_mode, so with
    automation OFF — the default — a ceiling tool reached the ordinary confirmation
    gate, where ``confirm: true`` from the request body satisfied it.

    Forced into the enterprise posture so no human is present; the tool must be
    refused outright rather than gated.
    """
    monkeypatch.setattr(
        gui.profile_config, "PROFILE_NAME", gui.profile_config.ENTERPRISE
    )
    with gui.app.test_client() as client:
        resp = _call(client, "admin_bucket_delete", name="prod", confirm=True)
    assert resp.status_code == 403, resp.get_json()
    body = resp.get_json()
    assert body["hard_ceiling"] is True
    assert "confirm" in body["error"]


def test_a_ceiling_tool_is_refused_through_the_console_even_on_a_workstation(gui):
    """The console is not the interactive channel the ceiling means.

    It is unauthenticated in the workstation profile, and its origin allowlist has to
    permit any localhost port — so any locally-served page is an allowed origin. Both
    facts mean a browser request cannot evidence WHICH human, or any human. Ceiling
    tools go through an interactive MCP session, where the client surfaces the specific
    call and a person answers it.
    """
    with gui.app.test_client() as client:
        resp = _call(client, "admin_bucket_delete", name="prod", confirm=True)
    assert resp.status_code == 403
    body = resp.get_json()
    assert body["hard_ceiling"] is True
    assert "confirm" in body["error"]


def test_automation_cannot_be_claimed_in_the_request_body(gui):
    """`{"automation": true}` in the body must be inert — authorization comes from
    the token's scopes, never from something the caller types."""
    with gui.app.test_client() as client:
        resp = client.post(
            "/api/call",
            json={
                "tool": "admin_bucket_delete",
                "arguments": {"name": "prod"},
                "automation": True,
            },
        )
    assert resp.status_code == 403
    assert resp.get_json()["requires_confirmation"] is True


# ── Every decision leaves an audit record ────────────────────────────────────


def test_a_refusal_is_audited(gui, audit_file):
    """The console emitted nothing at all. An unlogged privileged path defeats the
    entire point of the audit trail.

    Asserted against the FILE, because the GUI process also never configured logging
    — so the records it did emit went to a tree with no handlers and were discarded at
    INFO level. A caplog-based assertion could not see that.
    """
    with gui.app.test_client() as client:
        _call(client, "admin_bucket_delete", name="prod")

    records = _audit_records(audit_file)
    assert records, "no audit record reached the sink for a GUI refusal"
    payload = records[-1]
    assert payload["tool"] == "admin_bucket_delete"
    # denied_hard_ceiling, not denied_confirmation: the console never counts as the
    # human a ceiling tool requires, because in the workstation profile it is
    # unauthenticated and its origin allowlist necessarily admits any localhost port.
    assert payload["decision"] == "denied_hard_ceiling"
    # The record must say the console was the route, so an investigator can tell a
    # console action from an agent one.
    assert payload["via"] == "gui"
    # ...and WHO must be populated even with no token, or the record answers nothing.
    assert payload["principal"], payload


def test_a_disabled_tool_refusal_is_audited(monkeypatch, audit_file):
    module = _load_gui(
        monkeypatch,
        CB_GUI_INSECURE_NO_AUTH="1",
        OAUTH_ENABLED="false",
        CB_ADMIN_DISABLED_TOOLS="admin_bucket_create",
    )
    with module.app.test_client() as client:
        resp = _call(client, "admin_bucket_create", name="x")
    assert resp.status_code == 403
    assert any(r["decision"] == "denied_disabled" for r in _audit_records(audit_file))


# ── The unauthenticated console must refuse non-local callers ────────────────


def test_unauthenticated_console_refuses_a_remote_client(gui):
    """GUI_HOST is unset under `gunicorn -b 0.0.0.0:5173`, so the startup check read
    the loopback default while the socket served every interface. The peer address is
    checked instead, which no launcher can misreport."""
    with gui.app.test_client() as client:
        resp = client.post(
            "/api/call",
            json={"tool": "admin_bucket_list", "arguments": {}},
            environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
        )
    assert resp.status_code == 403
    assert "non-loopback" in resp.get_json()["error"]


def test_a_forwarded_for_header_cannot_claim_to_be_local(gui):
    """Trusting X-Forwarded-For would let any remote client assert it is local."""
    with gui.app.test_client() as client:
        resp = client.post(
            "/api/call",
            json={"tool": "admin_bucket_list", "arguments": {}},
            headers={"X-Forwarded-For": "127.0.0.1"},
            environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
        )
    assert resp.status_code == 403


def test_a_local_client_is_served(gui):
    """The supported case must keep working: the check is on the peer, and the test
    client's default peer is loopback."""
    with gui.app.test_client() as client:
        resp = client.get("/api/tools")
    assert resp.status_code == 200


# ── Scope enforcement ────────────────────────────────────────────────────────


def test_a_read_only_token_cannot_invoke_a_write_tool(monkeypatch, audit_file):
    """check_scope was never called here, so scopes were decorative: any
    authenticated user held the entire tool surface."""
    module = _load_gui(
        monkeypatch,
        OAUTH_ENABLED="false",
        CB_GUI_INSECURE_NO_AUTH="1",
    )
    from auth import scope_gate

    # A principal holding only the read scope.
    monkeypatch.setattr(
        scope_gate,
        "current_claims",
        lambda: {"sub": "svc-reader", "scope": "couchbase-admin-mcp:read"},
    )
    with module.app.test_client() as client:
        resp = _call(client, "admin_bucket_create", name="x", ramQuotaMB=100)

    assert resp.status_code == 403, resp.get_json()
    assert "requires scope" in resp.get_json()["error"]
    assert any(r["decision"] == "denied_scope" for r in _audit_records(audit_file))


def test_claims_do_not_leak_between_requests(gui):
    """Flask serves requests on pooled threads and a contextvar set in a thread
    outlives the request, so without an explicit clear, request N+1 could inherit
    request N's identity and scopes."""
    from auth import scope_gate

    scope_gate.set_token_claims({"sub": "leaked-principal"})
    with gui.app.test_client() as client:
        client.get("/api/tools")
    # before_request clears it; the stale identity must not survive into the next call.
    assert scope_gate.current_claims() is None


# ── The console's SUCCESS badge must reflect the decision ─────────────────────


def test_a_handler_refusal_is_not_reported_to_the_browser_as_a_success(
    gui, monkeypatch
):
    """`{"ok": true}` was hardcoded on this path, for every result.

    The gate refusals above answer 4xx, so they were never the problem. A refusal the
    HANDLER makes -- the egress allowlist, a Capella guardrail, a validation error --
    comes back as a normal 200 payload, and the console's own code renders
    `result.ok ? "SUCCESS" : "ERROR"`. So a blocked exfiltration attempt got a green
    SUCCESS badge and a success entry in the run history, while the payload underneath
    said it had been denied. The MCP transport had the mirror-image defect in its
    isError flag; this is the second half of that fix.
    """
    import handlers.shared as shared_mod

    tool = "admin_bucket_list"
    real = gui.HANDLERS[tool]

    class _Refusing:
        def handle(self, name, arguments):
            return shared_mod.err(
                "EgressDenied: host not in EGRESS_ALLOWED_HOSTS", tool=name
            )

    monkeypatch.setitem(gui.HANDLERS, tool, _Refusing())
    try:
        with gui.app.test_client() as client:
            resp = _call(client, tool)
    finally:
        gui.HANDLERS[tool] = real

    body = resp.get_json()
    assert body["ok"] is False, (
        "the console reported a refused operation as a successful call; index.html "
        "renders a green SUCCESS badge from this field"
    )
    assert "EGRESS_ALLOWED_HOSTS" in json.dumps(body["result"]), (
        "the refusal text must still be returned in full -- it is the part the "
        "operator needs"
    )


def test_a_successful_console_call_is_still_reported_as_a_success(gui, monkeypatch):
    """The other half: a wrapper that always said false would make every call look
    refused, and a badge that is always ERROR is no more informative than one that is
    always SUCCESS."""
    import handlers.shared as shared_mod

    tool = "admin_bucket_list"
    real = gui.HANDLERS[tool]

    class _Succeeding:
        def handle(self, name, arguments):
            return shared_mod.ok({"buckets": []})

    monkeypatch.setitem(gui.HANDLERS, tool, _Succeeding())
    try:
        with gui.app.test_client() as client:
            resp = _call(client, tool)
    finally:
        gui.HANDLERS[tool] = real

    assert resp.get_json()["ok"] is True


def test_a_sub_resource_error_inside_a_success_is_still_a_success(gui, monkeypatch):
    """capella_env_ensure returns phase progress with a top-level "error" while
    succeeding. Reading the "error" KEY rather than the marker would paint those runs
    red -- the same misclassification the shared audit classifier exists to prevent."""
    import handlers.shared as shared_mod

    tool = "admin_bucket_list"
    real = gui.HANDLERS[tool]

    class _Progressing:
        def handle(self, name, arguments):
            return shared_mod.ok(
                {"phase": "deploying", "error": "waiting for the cluster"}
            )

    monkeypatch.setitem(gui.HANDLERS, tool, _Progressing())
    try:
        with gui.app.test_client() as client:
            resp = _call(client, tool)
    finally:
        gui.HANDLERS[tool] = real

    assert resp.get_json()["ok"] is True


# ── The console and the MCP surface must advertise the same tools ────────────


def test_the_console_advertises_every_tool_the_mcp_surface_does():
    """A handler module added to server.py and not to gui_server.py is invisible
    in the console, silently.

    THIS IS NOT HYPOTHETICAL. handlers/backup_catalog.py shipped with six tools,
    a full test suite, and a place in server.py's registry -- and was absent from
    gui/gui_server.py's ALL_TOOLS for its entire life, so every one of its tools
    was unreachable from the console while appearing complete everywhere else.
    tests/test_handler_contract.py's MODULE_NAMES guard caught the equivalent
    omission on the server side immediately; nothing watched this side.

    Equality, not containment, and in both directions:

      * A tool in the MCP surface and not the console is a capability the console
        silently lacks.
      * A tool in the console and not the MCP surface is worse -- it is reachable
        over HTTP without being part of the audited surface, which is the shape
        of a privilege escalation rather than a missing feature.

    If a tool ever SHOULD be console-only or MCP-only, this test is the right
    place to record which and why, as a named allowlist. Until then there are
    none, and the honest assertion is that the two sets are identical.
    """
    import server
    from gui import gui_server

    mcp_tools = {t.name for t in server._RAW_TOOLS}
    console_tools = {t.name for t in gui_server.ALL_TOOLS}

    missing = sorted(mcp_tools - console_tools)
    extra = sorted(console_tools - mcp_tools)
    assert not missing, (
        "these tools are in the MCP surface and NOT in the console -- add the "
        f"handler module to gui_server.ALL_TOOLS and HANDLERS: {missing}"
    )
    assert not extra, (
        "these tools are reachable from the console and are NOT part of the MCP "
        f"surface, so they are outside the audited surface entirely: {extra}"
    )


def test_every_console_tool_can_be_dispatched():
    """ALL_TOOLS and HANDLERS are built from separate expressions, so a module
    added to one and not the other advertises a tool that 500s when called."""
    from gui import gui_server

    undispatchable = sorted(
        t.name for t in gui_server.ALL_TOOLS if t.name not in gui_server.HANDLERS
    )
    assert not undispatchable, (
        "these tools are advertised by the console with no handler behind them: "
        f"{undispatchable}"
    )
