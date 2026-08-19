"""
Live end-to-end tests of the HTTP transport: a real uvicorn server, real HTTP
requests, a real MCP handshake.

These exist because every unit test of the old design passed while the transport
was completely broken. The authorization bug was a task boundary, and the only way
to be sure it is fixed is to drive the actual server. Each test below would have
failed against the previous implementation:

  * per-client sessions        — one shared transport with mcp_session_id=None
                                 meant no session binding at all
  * automation scope honoured  — claims never crossed the task boundary, so an
                                 authorized service principal was demoted to
                                 needing confirm:true
  * read/write separation      — check_scope always saw None and allowed
  * /mcp without a slash       — answered 307, which MCP clients do not follow

Marked `live` so they can be excluded in a constrained CI:  -m "not live"
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import urllib.error
import urllib.request

import pytest
import pytest_asyncio

pytest.importorskip("uvicorn")
pytest.importorskip("starlette")

pytestmark = [pytest.mark.live, pytest.mark.asyncio]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _fake_validate(token: str) -> dict:
    """Stand in for the IdP. The token string names the scopes it carries."""
    if token == "bad":
        raise ValueError("bad signature")
    roles = {
        "auto": ["couchbase-admin-mcp:write", "couchbase-admin-mcp:automation"],
        "writeonly": ["couchbase-admin-mcp:write"],
        "readonly": ["couchbase-admin-mcp:read"],
    }[token]
    return {
        "sub": f"sp-{token}",
        "iss": "https://idp.example",
        "aud": "api://cb-admin",
        "exp": 9999999999,
        "roles": roles,
    }


class _Client:
    def __init__(self, base: str):
        self.base = base

    def call(self, method, params=None, sid=None, token=None, _id=1):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if sid:
            headers["Mcp-Session-Id"] = sid
        if token:
            headers["Authorization"] = f"Bearer {token}"
        body = {"jsonrpc": "2.0", "id": _id, "method": method}
        if params is not None:
            body["params"] = params
        req = urllib.request.Request(
            self.base, data=json.dumps(body).encode(), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()

    def session(self, token=None):
        status, headers, _ = self.call(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "probe", "version": "1"},
            },
            token=token,
        )
        sid = headers.get("mcp-session-id")
        if sid:
            self.call("notifications/initialized", sid=sid, token=token)
        return status, sid


@pytest_asyncio.fixture
async def live_server(monkeypatch):
    """Boot the real HTTP transport on a free port, authenticated."""
    port = _free_port()
    for key, value in {
        "CB_ADMIN_PROFILE": "enterprise",
        "CB_ADMIN_TRANSPORT": "http",
        "CB_ADMIN_HOST": "127.0.0.1",
        "CB_ADMIN_PORT": str(port),
        "CB_ADMIN_HTTP_REQUIRE_AUTH": "true",
        "OAUTH_ISSUER": "https://idp.example",
        "OAUTH_AUDIENCE": "api://cb-admin",
        "CB_ADMIN_READ_ONLY_MODE": "false",
        "CB_ADMIN_LOG_LEVEL": "ERROR",
    }.items():
        monkeypatch.setenv(key, value)

    from auth import oidc, request_auth

    monkeypatch.setattr(oidc, "validate_token", _fake_validate)
    request_auth.reset_cache()

    # handlers.shared snapshots CB_ADMIN_READ_ONLY_MODE at ITS import time, and
    # server.py builds its tool list from that snapshot at import. An earlier test
    # in the same process may already have imported both with read-only ON, in
    # which case the write tools these tests exercise would not be loaded and the
    # failure would look like a scope bug rather than a stale import. Reload both,
    # shared first, so the tool list matches the env set above.
    import importlib

    import handlers.shared

    importlib.reload(handlers.shared)
    import server

    server = importlib.reload(server)

    task = asyncio.create_task(server._main_http())
    await asyncio.sleep(2.5)
    try:
        yield _Client(f"http://127.0.0.1:{port}/mcp")
    finally:
        task.cancel()
        # BaseException: the cancellation itself, plus whatever uvicorn's lifespan
        # raises on an abrupt shutdown. Teardown must not fail the test.
        with contextlib.suppress(BaseException):
            await task
        request_auth.reset_cache()


async def test_forged_token_is_rejected_at_the_edge(live_server):
    status, sid = await asyncio.to_thread(live_server.session, "bad")
    assert status == 401
    assert sid is None


async def test_automation_scope_skips_the_confirmation_gate(live_server):
    """THE point of fix B. An authorized child agent must not be asked to
    rubber-stamp its own call."""
    _, sid = await asyncio.to_thread(live_server.session, "auto")
    assert sid
    _, _, body = await asyncio.to_thread(
        live_server.call,
        "tools/call",
        {"name": "admin_bucket_flush", "arguments": {"bucket_name": "orders"}},
        sid,
        "auto",
        2,
    )
    assert "Confirmation required" not in body


async def test_write_scope_without_automation_still_needs_confirmation(live_server):
    """The workstation/interactive path is unchanged."""
    _, sid = await asyncio.to_thread(live_server.session, "writeonly")
    _, _, body = await asyncio.to_thread(
        live_server.call,
        "tools/call",
        {"name": "admin_bucket_flush", "arguments": {"bucket_name": "orders"}},
        sid,
        "writeonly",
        3,
    )
    assert "Confirmation required" in body


async def test_read_only_token_cannot_reach_a_write_tool(live_server):
    """Read/write separation was entirely inoperative on HTTP."""
    _, sid = await asyncio.to_thread(live_server.session, "readonly")
    _, _, body = await asyncio.to_thread(
        live_server.call,
        "tools/call",
        {
            "name": "admin_bucket_flush",
            "arguments": {"bucket_name": "orders", "confirm": True},
        },
        sid,
        "readonly",
        4,
    )
    assert "requires scope" in body


async def test_each_client_gets_its_own_session(live_server):
    """One transport with mcp_session_id=None put every client in one session."""
    _, first = await asyncio.to_thread(live_server.session, "auto")
    _, second = await asyncio.to_thread(live_server.session, "auto")
    assert first and second and first != second


async def test_a_call_without_a_session_id_is_refused(live_server):
    status, _, _ = await asyncio.to_thread(
        live_server.call, "tools/list", None, None, "auto", 9
    )
    assert status >= 400


async def test_endpoint_answers_with_and_without_a_trailing_slash(live_server):
    """A 307 here would leave clients configured with the documented URL unable to
    connect, since MCP clients do not follow the redirect."""
    for base in (live_server.base, live_server.base + "/"):
        client = _Client(base)
        status, sid = await asyncio.to_thread(client.session, "auto")
        assert status == 200, base
        assert sid, base
