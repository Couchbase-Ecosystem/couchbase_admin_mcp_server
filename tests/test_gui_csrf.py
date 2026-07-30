"""
Cross-site request forgery against the admin console.

THE FINDING
===========
``POST /api/call`` used ``request.get_json(force=True)``, which parses a JSON body
whatever the Content-Type says, and nothing validated Origin. flask_cors was
configured with a localhost origin allowlist, but CORS governs whether the browser lets
the calling page READ the response — the request is dispatched and its side effects
happen regardless.

So any page the developer happened to visit could run:

    fetch("http://127.0.0.1:5173/api/call", {
      method: "POST", mode: "no-cors",
      headers: {"Content-Type": "text/plain"},
      body: JSON.stringify({tool: "admin_bucket_delete",
                            arguments: {bucket_name: "prod", confirm: true}})})

``text/plain`` makes this a "simple" request by CORS rules, so no preflight is sent and
nothing is asked. In the workstation profile there is no cookie and no token
(CB_GUI_INSECURE_NO_AUTH=1), so SameSite protects nothing; the peer-address check passes
because the browser genuinely is on the developer's machine; and the attacker's own
``confirm: true`` satisfied the confirmation gate.

THE DEFENCES
============
1. ``Content-Type: application/json`` required on /api/ — makes a cross-origin fetch a
   NON-simple request, so the browser must preflight, and the preflight fails.
2. Origin (falling back to Referer) validated on state-changing requests.

Both are tested, independently, because either alone has an edge case.
"""

from __future__ import annotations

import importlib
import json
import sys

import pytest

pytest.importorskip("flask")

PAYLOAD = json.dumps(
    {
        "tool": "admin_bucket_delete",
        "arguments": {"bucket_name": "prod", "confirm": True},
    }
)


@pytest.fixture
def gui(monkeypatch, tmp_path):
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "stdio")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "false")
    monkeypatch.setenv("CB_ADMIN_ALWAYS_CONFIRM", "admin_bucket_delete")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(tmp_path / "audit.log"))
    monkeypatch.delenv("CB_GUI_ALLOWED_ORIGINS", raising=False)

    import audit

    audit.reset_audit_sink()
    for name in ("profile_config", "handlers.shared", "authz", "gui.gui_server"):
        sys.modules.pop(name, None)
    import profile_config

    importlib.reload(profile_config)
    module = importlib.import_module("gui.gui_server")
    module = importlib.reload(module)
    module.app.config.update(TESTING=True)
    yield module
    audit.reset_audit_sink()


# ── The attack itself ────────────────────────────────────────────────────────


def test_the_simple_request_csrf_attack_is_refused(gui):
    """The exact request an attacker page can make with no preflight."""
    with gui.app.test_client() as client:
        resp = client.post(
            "/api/call",
            data=PAYLOAD,
            content_type="text/plain",
            headers={"Origin": "https://evil.example"},
        )
    assert resp.status_code in (403, 415), resp.get_json()


def test_a_hostile_origin_is_refused_even_with_the_right_content_type(gui):
    """Defence 2 alone: a non-browser client, or a browser bug, still fails Origin."""
    with gui.app.test_client() as client:
        resp = client.post(
            "/api/call",
            data=PAYLOAD,
            content_type="application/json",
            headers={"Origin": "https://evil.example"},
        )
    assert resp.status_code == 403
    assert "Origin" in resp.get_json()["error"]


def test_a_wrong_content_type_is_refused_even_with_no_origin(gui):
    """Defence 1 alone: this is what forces the preflight that Origin then fails."""
    with gui.app.test_client() as client:
        resp = client.post("/api/call", data=PAYLOAD, content_type="text/plain")
    assert resp.status_code == 415


def test_form_encoded_bodies_are_refused(gui):
    """The other two CORS-simple content types."""
    with gui.app.test_client() as client:
        for content_type in (
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ):
            resp = client.post("/api/call", data=PAYLOAD, content_type=content_type)
            assert resp.status_code == 415, content_type


def test_a_forged_referer_is_refused_when_origin_is_absent(gui):
    with gui.app.test_client() as client:
        resp = client.post(
            "/api/call",
            data=PAYLOAD,
            content_type="application/json",
            headers={"Referer": "https://evil.example/page"},
        )
    assert resp.status_code == 403


def test_the_hard_ceiling_is_not_satisfied_by_an_attacker_supplied_confirm(gui):
    """Even setting the CSRF layer aside: `confirm: true` in a browser request must not
    be treated as the human approval a ceiling tool requires."""
    with gui.app.test_client() as client:
        resp = client.post(
            "/api/call",
            json={
                "tool": "admin_bucket_delete",
                "arguments": {"bucket_name": "prod", "confirm": True},
            },
            headers={"Origin": "http://127.0.0.1:5173"},
        )
    # Reaches the policy (not a CSRF refusal), and the policy withholds it.
    assert resp.status_code == 403
    body = resp.get_json()
    assert body.get("requires_confirmation") or body.get("hard_ceiling"), body


# ── The legitimate console must keep working ─────────────────────────────────


def test_the_local_ui_can_still_read(gui):
    with gui.app.test_client() as client:
        assert client.get("/api/tools").status_code == 200


def test_the_local_ui_can_still_post(gui):
    with gui.app.test_client() as client:
        resp = client.post(
            "/api/call",
            json={"tool": "admin_bucket_list", "arguments": {}},
            headers={"Origin": "http://localhost:5173"},
        )
    assert resp.status_code not in (403, 415), resp.get_json()


def test_a_json_content_type_with_a_charset_is_accepted(gui):
    """`application/json; charset=utf-8` is what many clients actually send."""
    with gui.app.test_client() as client:
        resp = client.post(
            "/api/call",
            data=json.dumps({"tool": "admin_bucket_list", "arguments": {}}),
            content_type="application/json; charset=utf-8",
            headers={"Origin": "http://127.0.0.1:5173"},
        )
    assert resp.status_code != 415


def test_an_operator_can_allowlist_another_origin(monkeypatch, tmp_path):
    """A reverse-proxied console on a real hostname is a legitimate deployment."""
    monkeypatch.setenv("CB_GUI_ALLOWED_ORIGINS", "https://console.corp.example")
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    for name in ("profile_config", "handlers.shared", "authz", "gui.gui_server"):
        sys.modules.pop(name, None)
    import profile_config

    importlib.reload(profile_config)
    module = importlib.reload(importlib.import_module("gui.gui_server"))
    module.app.config.update(TESTING=True)

    with module.app.test_client() as client:
        resp = client.post(
            "/api/call",
            json={"tool": "admin_bucket_list", "arguments": {}},
            headers={"Origin": "https://console.corp.example"},
        )
    assert resp.status_code != 403


# ── The peer-address check ───────────────────────────────────────────────────


def test_a_forwarding_header_means_the_peer_cannot_be_believed(gui):
    """A same-host reverse proxy makes every remote client look loopback, and the
    startup posture check reads GUI_HOST=127.0.0.1 and raises nothing. The presence of
    a forwarding header is taken as evidence that REMOTE_ADDR is the proxy — not as a
    claim about who the client is, which would be worse."""
    with gui.app.test_client() as client:
        resp = client.post(
            "/api/call",
            json={"tool": "admin_bucket_list", "arguments": {}},
            headers={
                "Origin": "http://127.0.0.1:5173",
                "X-Forwarded-For": "203.0.113.9",
            },
        )
    assert resp.status_code == 403
    assert "non-loopback" in resp.get_json()["error"]


def test_an_ipv4_mapped_loopback_peer_is_accepted(gui):
    """A dual-stack socket reports a v4 client as ::ffff:127.0.0.1, for which
    ipaddress.is_loopback is False — so genuine local clients were refused."""
    with gui.app.test_client() as client:
        resp = client.get(
            "/api/tools", environ_overrides={"REMOTE_ADDR": "::ffff:127.0.0.1"}
        )
    assert resp.status_code == 200


# ── Round-4: the remaining state-changing surface ────────────────────────────


def test_a_cross_site_forced_logout_is_refused(gui):
    """/auth/logout is a GET with a side effect (it clears the session), and the guard
    returns early for GET — so a cross-site GET could force a logout. Cheap to cover."""
    with gui.app.test_client() as client:
        resp = client.get("/auth/logout", headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403


def test_an_ordinary_cross_site_get_is_still_allowed(gui):
    """Read-only GETs must not be broken by the logout special case: the console's own
    static assets and status endpoint are fetched normally."""
    with gui.app.test_client() as client:
        resp = client.get("/auth/status", headers={"Origin": "https://evil.example"})
    assert resp.status_code == 200


def test_a_handler_exception_does_not_echo_credentials(gui, monkeypatch):
    """The GUI's except branch returned str(exc) verbatim while the MCP path redacts
    through err(). Exception text folds in the cluster's raw response body, which is the
    one channel where a submitted credential can come back."""

    class _Exploding:
        def handle(self, name, args):
            raise RuntimeError(
                "connect failed: couchbase://n1?password=hunter2 token=eyJabc123"
            )

    monkeypatch.setitem(gui.HANDLERS, "admin_bucket_list", _Exploding())
    with gui.app.test_client() as client:
        resp = client.post(
            "/api/call",
            json={"tool": "admin_bucket_list", "arguments": {}},
            headers={"Origin": "http://127.0.0.1:5173"},
        )
    body = resp.get_json()
    assert "hunter2" not in json.dumps(body), body
    assert "eyJabc123" not in json.dumps(body), body
    assert "***REDACTED***" in json.dumps(body)
