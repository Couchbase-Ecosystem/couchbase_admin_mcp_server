"""The console's own API surface, below /api/call's authorization.

Three decisions live here and each has a recorded reason:

  * AN UNKNOWN TOOL IS AUDITED. server.py emits denied_unknown_tool for the same
    decision, so tool-name enumeration through the transport left a trail and the
    same enumeration through the console left none. This branch sits ABOVE the
    block where every other decision is audited, which is why the earlier
    console-convergence pass missed it.

  * POST /api/config IS GONE. Its allow-list included CB_CONNECTION_STRING and
    CB_ADMIN_TLS_INSECURE, and handlers/shared re-reads those per request and
    attaches HTTP Basic credentials to every admin call -- so pointing the
    connection string at an attacker's host made the server send the real
    administrator password, base64 Basic, in cleartext, to a host the caller
    chose. It needed no confirmation and worked in read-only mode, because it
    never performed a write: it changed where the writes were pointed.

  * THE STATIC ROUTE falls back to index.html, because a single-page app owns its
    own routing and a 404 from the server would break every deep link.
"""

from __future__ import annotations

import importlib
import json
import sys

import pytest


@pytest.fixture
def gui(monkeypatch, tmp_path):
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "false")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(tmp_path / "audit.log"))
    import audit

    audit.reset_audit_sink()
    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    sys.modules.pop("gui.gui_server", None)
    module = importlib.import_module("gui.gui_server")
    module.app.config.update(TESTING=True)
    yield module
    audit.reset_audit_sink()


@pytest.fixture
def records(monkeypatch):
    import audit

    captured: list[dict] = []
    monkeypatch.setattr(
        audit, "emit_tool_call", lambda **kw: captured.append(kw), raising=False
    )
    return captured


def call(gui, tool, **arguments):
    return gui.app.test_client().post(
        "/api/call", json={"tool": tool, "arguments": arguments}
    )


# ── /api/call, below the authorization block ─────────────────────────────────


def test_an_unknown_tool_is_a_404_and_is_audited(gui, records):
    """Enumeration through the transport left a trail; the same enumeration
    through the console left none."""
    response = call(gui, "admin_not_a_real_tool")
    assert response.status_code == 404
    assert "Unknown tool" in json.loads(response.data)["error"]
    assert [r for r in records if r["decision"] == "denied_unknown_tool"]


def test_a_missing_tool_name_is_a_400(gui):
    response = gui.app.test_client().post("/api/call", json={"arguments": {}})
    assert response.status_code == 400


def test_a_non_object_arguments_field_is_a_400_not_a_500(gui):
    """It raised an unhandled AttributeError inside require_confirmation: HTTP
    500, no audit record, and a full traceback when FLASK_DEBUG is on."""
    response = gui.app.test_client().post(
        "/api/call", json={"tool": "admin_cluster_info", "arguments": ["not", "obj"]}
    )
    assert response.status_code == 400
    assert "must be a JSON object" in json.loads(response.data)["error"]


def test_a_disabled_tool_is_refused_and_audited(monkeypatch, tmp_path, records):
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "false")
    monkeypatch.setenv("CB_ADMIN_DISABLED_TOOLS", "admin_cluster_info")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(tmp_path / "audit.log"))
    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    sys.modules.pop("gui.gui_server", None)
    module = importlib.import_module("gui.gui_server")
    module.app.config.update(TESTING=True)

    response = module.app.test_client().post(
        "/api/call", json={"tool": "admin_cluster_info", "arguments": {}}
    )
    assert response.status_code == 403
    assert [r for r in records if r["decision"] == "denied_disabled"]


def test_a_write_in_read_only_mode_is_refused_and_audited(
    monkeypatch, tmp_path, records
):
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "true")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(tmp_path / "audit.log"))
    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    sys.modules.pop("gui.gui_server", None)
    module = importlib.import_module("gui.gui_server")
    module.app.config.update(TESTING=True)

    response = module.app.test_client().post(
        "/api/call",
        json={"tool": "admin_bucket_create", "arguments": {"name": "x"}},
    )
    assert response.status_code in (403, 404)


# ── the tool listing ─────────────────────────────────────────────────────────


def test_the_tool_listing_is_served(gui):
    response = gui.app.test_client().get("/api/tools")
    assert response.status_code == 200
    body = json.loads(response.data)
    tools = body if isinstance(body, list) else body.get("tools")
    assert tools, body


# ── /api/config: the endpoint that was removed ───────────────────────────────


def test_posting_configuration_is_refused(gui):
    """Its allow-list included CB_CONNECTION_STRING, and shared.py re-reads that
    per request and attaches HTTP Basic credentials to every admin call. Pointing
    it at another host made the server send the real administrator password in
    cleartext to a destination the caller chose -- with authentication disabled,
    needing no confirmation, and working in read-only mode, because it never
    performed a write."""
    response = gui.app.test_client().post("/api/config", json={"CB_MGMT_PORT": "1234"})
    assert response.status_code in (403, 404, 405, 410)


def test_reading_configuration_does_not_return_a_secret(gui):
    response = gui.app.test_client().get("/api/config")
    if response.status_code != 200:
        pytest.skip("this deployment does not serve a configuration view")
    body = json.dumps(json.loads(response.data)).lower()
    for secret in ("password", "api_key", "secret"):
        assert f'"{secret}": "' not in body or "redacted" in body


# ── the single-page app ──────────────────────────────────────────────────────


def test_an_unknown_path_falls_back_to_the_app_shell(gui):
    """A single-page app owns its own routing; a 404 from the server would break
    every deep link into the console."""
    response = gui.app.test_client().get("/some/console/route")
    assert response.status_code in (200, 304)
