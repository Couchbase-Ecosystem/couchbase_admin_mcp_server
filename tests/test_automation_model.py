"""Tests for the confirmation / automation trust model.

These lock in the safety-critical dispatch behaviour:
  * writes are gated by default,
  * an automation-scoped principal skips per-call confirmation,
  * the automation scope never substitutes for the write scope,
  * the hard ceiling (CB_ADMIN_ALWAYS_CONFIRM) cannot be bypassed by automation,
  * credentials are redacted from responses.

They run without a cluster: gated calls are rejected *before* any REST call, and
the one case that reaches execution is asserted only to have passed the gate
(the subsequent connection error is expected and ignored).
"""

from __future__ import annotations

import asyncio
import importlib

import pytest


@pytest.fixture
def srv(monkeypatch):
    """Import server.py with writes enabled and a known ceiling, isolated per test.

    server.py reads env at import time (tool filtering, confirmation set), so we
    set env then (re)import it fresh inside each test's fixture.
    """
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "false")
    monkeypatch.setenv("CB_ADMIN_ALWAYS_CONFIRM", "admin_bucket_delete")
    monkeypatch.setenv("CB_ADMIN_SCOPE_WRITE", "couchbase-admin-mcp:write")
    monkeypatch.setenv("CB_ADMIN_SCOPE_AUTOMATION", "couchbase-admin-mcp:automation")

    # handlers.shared reads CB_ADMIN_READ_ONLY_MODE at import time and caches it;
    # server.py reads the cached value plus its own env at import. Reload shared
    # FIRST so the write tools are actually loaded, then server on top of it.
    import handlers.shared

    importlib.reload(handlers.shared)
    import server as server_module

    server_module = importlib.reload(server_module)
    from auth import scope_gate

    scope_gate.clear_token_claims()
    yield server_module
    scope_gate.clear_token_claims()


def _call(srv, name, args):
    return asyncio.new_event_loop().run_until_complete(srv.call_tool(name, args))[0].text


def _set_claims(scopes: str):
    from auth import scope_gate

    scope_gate.set_token_claims({"scope": scopes})


def test_writes_are_gated_by_default(srv):
    """With no token (interactive) a write tool is withheld pending confirmation."""
    from auth import scope_gate

    scope_gate.clear_token_claims()
    out = _call(srv, "admin_bucket_create", {"bucket_name": "b", "ram_quota_mb": 256})
    assert "requires_confirmation" in out


def test_confirm_argument_satisfies_the_gate(srv):
    """confirm:true lets an interactive caller through (reaches execution)."""
    from auth import scope_gate

    scope_gate.clear_token_claims()
    out = _call(
        srv,
        "admin_bucket_create",
        {"bucket_name": "b", "ram_quota_mb": 256, "confirm": True},
    )
    # Passed the gate — no confirmation demand. (A REST/connection error is fine.)
    assert "requires_confirmation" not in out


def test_automation_scope_skips_confirmation(srv):
    """An automation+write principal executes ordinary writes without a prompt."""
    _set_claims("couchbase-admin-mcp:write couchbase-admin-mcp:automation")
    out = _call(srv, "admin_bucket_create", {"bucket_name": "b", "ram_quota_mb": 256})
    assert "requires_confirmation" not in out


def test_automation_scope_does_not_substitute_for_write(srv):
    """Automation scope WITHOUT write scope is still denied by the scope gate."""
    _set_claims("couchbase-admin-mcp:automation")
    out = _call(srv, "admin_bucket_create", {"bucket_name": "b", "ram_quota_mb": 256})
    assert "scope" in out.lower()


def test_hard_ceiling_not_bypassable_by_automation(srv):
    """A tool in CB_ADMIN_ALWAYS_CONFIRM is withheld even for automation."""
    _set_claims("couchbase-admin-mcp:write couchbase-admin-mcp:automation")
    out = _call(srv, "admin_bucket_delete", {"bucket_name": "b"})
    assert "requires_confirmation" in out


def test_read_tool_never_gated(srv):
    """Read-only tools are not gated regardless of principal."""
    from auth import scope_gate

    scope_gate.clear_token_claims()
    out = _call(srv, "admin_bucket_list", {})
    assert "requires_confirmation" not in out


def test_password_redacted_in_confirmation_response(srv):
    """A withheld admin_user_create must not echo the plaintext password."""
    from auth import scope_gate

    scope_gate.clear_token_claims()
    out = _call(
        srv,
        "admin_user_create",
        {"username": "alice", "password": "hunter2", "roles": ["admin"]},
    )
    assert "hunter2" not in out
    assert "***REDACTED***" in out


def test_ceiling_is_empty_by_default(monkeypatch):
    """Without CB_ADMIN_ALWAYS_CONFIRM the ceiling is empty (dev-friendly)."""
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "false")
    monkeypatch.delenv("CB_ADMIN_ALWAYS_CONFIRM", raising=False)
    import handlers.shared

    importlib.reload(handlers.shared)
    import server as server_module

    server_module = importlib.reload(server_module)
    assert set() == server_module._AUTOMATION_HARD_CEILING
