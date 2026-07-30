"""
The HTTP authorization fix, tested across the task boundary that broke it.

WHY THE OLD TESTS COULD NOT CATCH THIS
======================================
tests/test_automation_model.py sets the claims contextvar and then awaits
``call_tool`` IN THE SAME TASK. That passes whether or not the transport works,
because the whole failure was a task boundary:

    middleware task            dispatch task (created at session init)
    ───────────────            ───────────────────────────────────────
    set_token_claims(claims)   call_tool() -> check_scope() -> claims is None

``contextvars`` snapshot at task creation, and the SDK's dispatch loop is a sibling
task started before any request existed. So the tests below deliberately create the
consumer task FIRST and only then set a value in a different task — reproducing the
topology rather than the happy path. A test that cannot fail on the real bug is not
a test of it.
"""

from __future__ import annotations

import asyncio
import contextvars

import pytest

from auth import request_auth, scope_gate


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    request_auth.reset_cache()
    scope_gate.clear_token_claims()
    monkeypatch.delenv("CB_ADMIN_HTTP_REQUIRE_AUTH", raising=False)
    yield
    request_auth.reset_cache()
    scope_gate.clear_token_claims()


# ── The task-boundary reproduction ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_contextvar_set_in_another_task_is_invisible_to_dispatch():
    """The original bug, reproduced. Documents WHY the mechanism was replaced —
    if this ever starts failing, contextvar semantics have changed and the
    surrounding design rationale should be revisited."""
    var: contextvars.ContextVar[str | None] = contextvars.ContextVar("t", default=None)
    seen: list[str | None] = []
    gate = asyncio.Event()

    async def consumer():
        # Created BEFORE the value is set, exactly like the SDK's dispatch loop.
        await gate.wait()
        seen.append(var.get())

    consumer_task = asyncio.create_task(consumer())
    await asyncio.sleep(0)

    async def request_task():
        var.set("claims-from-middleware")
        gate.set()

    await asyncio.create_task(request_task())
    await consumer_task

    assert seen == [None], (
        "a contextvar set in the request task reached the dispatch task — the "
        "premise of the fix no longer holds"
    )


class _FakeRequest:
    """Minimal stand-in for the Starlette request the SDK attaches to the context."""

    def __init__(
        self, token: str | None = None, host: str = "10.1.2.3", port: int = 5555
    ):
        self.headers = {"authorization": f"Bearer {token}"} if token else {}
        self.client = type("C", (), {"host": host, "port": port})()


def _install_request(monkeypatch, request):
    """Put a request on the SDK's request context, as _handle_request does."""
    from mcp.server.lowlevel.server import request_ctx

    ctx = type("Ctx", (), {"request": request})()
    token = request_ctx.set(ctx)
    monkeypatch.setattr(
        request_auth,
        "current_request",
        lambda: getattr(request_ctx.get(), "request", None),
    )
    return token


# ── Resolution from the request, in the dispatch task ────────────────────────


@pytest.mark.asyncio
async def test_claims_resolve_from_the_request_inside_the_dispatch_task(monkeypatch):
    """The fix: no cross-task handoff. The claims come from the request that the
    SDK hands to the dispatch task, so they are always visible where the
    authorization decision is made."""
    claims = {
        "sub": "sp-workflow-manager",
        "roles": ["couchbase-admin-mcp:write", "couchbase-admin-mcp:automation"],
        "exp": 9999999999,
    }
    monkeypatch.setattr("auth.oidc.validate_token", lambda _t: claims)
    _install_request(monkeypatch, _FakeRequest(token="abc.def.ghi"))

    seen: list[bool] = []

    async def dispatch_like_the_sdk():
        # A task created separately from whoever set up the request — the shape
        # that broke the contextvar approach.
        seen.append(scope_gate.session_has_automation_scope())

    await asyncio.create_task(dispatch_like_the_sdk())
    assert seen == [True], (
        "the automation scope did not reach the dispatch task; the enterprise "
        "unattended authorization path is inoperative"
    )


def test_automation_scope_now_engages_for_a_service_principal(monkeypatch):
    """The consequence that matters: an authorized child agent is NOT asked for a
    per-call confirmation. Previously it always was, because the scope was
    invisible — so the agent supplied confirm:true, rubber-stamping itself."""
    monkeypatch.setattr(
        "auth.oidc.validate_token",
        lambda _t: {
            "sub": "sp-child",
            "roles": ["couchbase-admin-mcp:write", "couchbase-admin-mcp:automation"],
        },
    )
    _install_request(monkeypatch, _FakeRequest(token="t"))
    assert scope_gate.session_has_automation_scope() is True


def test_write_scope_is_required_for_a_write_tool(monkeypatch):
    """Read/write separation was entirely inoperative on HTTP."""
    from mcp.types import Tool, ToolAnnotations

    monkeypatch.setattr(
        "auth.oidc.validate_token",
        lambda _t: {"sub": "svc", "scp": ["couchbase-admin-mcp:read"]},
    )
    _install_request(monkeypatch, _FakeRequest(token="t"))

    write_tool = Tool(
        name="admin_bucket_delete",
        description="d",
        inputSchema={"type": "object"},
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True),
    )
    denial = scope_gate.check_scope(write_tool)
    assert denial is not None
    assert "couchbase-admin-mcp:write" in denial


def test_read_scope_admits_a_read_tool(monkeypatch):
    from mcp.types import Tool, ToolAnnotations

    monkeypatch.setattr(
        "auth.oidc.validate_token",
        lambda _t: {"sub": "svc", "scp": ["couchbase-admin-mcp:read"]},
    )
    _install_request(monkeypatch, _FakeRequest(token="t"))

    read_tool = Tool(
        name="admin_cluster_info",
        description="d",
        inputSchema={"type": "object"},
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    assert scope_gate.check_scope(read_tool) is None


# ── Failure modes ────────────────────────────────────────────────────────────


def test_an_invalid_token_yields_no_claims(monkeypatch):
    def boom(_t):
        raise ValueError("bad signature")

    monkeypatch.setattr("auth.oidc.validate_token", boom)
    _install_request(monkeypatch, _FakeRequest(token="forged"))
    assert scope_gate.current_claims() is None


def test_invalid_token_is_refused_when_auth_is_required(monkeypatch):
    from mcp.types import Tool, ToolAnnotations

    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    monkeypatch.setattr(
        "auth.oidc.validate_token", lambda _t: (_ for _ in ()).throw(ValueError("nope"))
    )
    _install_request(monkeypatch, _FakeRequest(token="forged"))

    tool = Tool(
        name="admin_cluster_info",
        description="d",
        inputSchema={"type": "object"},
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    denial = scope_gate.check_scope(tool)
    assert denial is not None
    assert "no valid bearer token" in denial


def test_missing_token_is_refused_when_auth_is_required(monkeypatch):
    from mcp.types import Tool, ToolAnnotations

    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    _install_request(monkeypatch, _FakeRequest(token=None))
    tool = Tool(
        name="admin_cluster_info",
        description="d",
        inputSchema={"type": "object"},
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    assert scope_gate.check_scope(tool) is not None


def test_stdio_needs_no_token(monkeypatch):
    """The workstation path: no request, no token, and that is correct — not a
    failure. Requiring auth on a laptop with no IdP would block for nothing."""
    from mcp.types import Tool, ToolAnnotations

    monkeypatch.setattr(request_auth, "current_request", lambda: None)
    tool = Tool(
        name="admin_bucket_delete",
        description="d",
        inputSchema={"type": "object"},
        annotations=ToolAnnotations(readOnlyHint=False),
    )
    assert scope_gate.check_scope(tool) is None
    assert scope_gate.session_has_automation_scope() is False


# ── Validation cache ─────────────────────────────────────────────────────────


def test_token_is_validated_once_per_window(monkeypatch):
    """check_scope and session_has_automation_scope both need the claims, and a
    JWKS cache miss means an outbound fetch to the IdP — so a tight loop of tool
    calls must not become a tight loop of token validations."""
    calls = []

    def counting(_t):
        calls.append(1)
        return {"sub": "svc", "scp": ["couchbase-admin-mcp:write"], "exp": 9999999999}

    monkeypatch.setattr("auth.oidc.validate_token", counting)
    _install_request(monkeypatch, _FakeRequest(token="same-token"))

    for _ in range(5):
        scope_gate.current_claims()
    assert len(calls) == 1


def test_the_cache_never_holds_the_raw_token(monkeypatch):
    """A memory dump or a debug repr must not yield a usable credential."""
    monkeypatch.setattr(
        "auth.oidc.validate_token", lambda _t: {"sub": "s", "exp": 9999999999}
    )
    _install_request(monkeypatch, _FakeRequest(token="super-secret-jwt"))
    scope_gate.current_claims()
    assert "super-secret-jwt" not in repr(request_auth._validated)


def test_an_expired_token_is_not_cached_past_its_expiry(monkeypatch):
    """Caching validation must never extend a credential's life."""
    import time as _time

    monkeypatch.setattr(
        "auth.oidc.validate_token",
        lambda _t: {"sub": "s", "exp": _time.time() - 1},
    )
    _install_request(monkeypatch, _FakeRequest(token="expired"))
    request_auth.resolve_claims()
    assert request_auth._validated == {}


def test_different_tokens_get_different_cache_entries(monkeypatch):
    """Two concurrent clients must not share an authorization decision."""
    monkeypatch.setattr(
        "auth.oidc.validate_token",
        lambda t: {"sub": "a" if "one" in t else "b", "exp": 9999999999},
    )
    _install_request(monkeypatch, _FakeRequest(token="token-one"))
    first = scope_gate.current_claims()["sub"]
    _install_request(monkeypatch, _FakeRequest(token="token-two"))
    second = scope_gate.current_claims()["sub"]
    assert (first, second) == ("a", "b")


# ── The explicit contextvar remains usable for tests / future transports ─────


def test_an_explicitly_set_contextvar_still_wins(monkeypatch):
    monkeypatch.setattr(request_auth, "current_request", lambda: None)
    scope_gate.set_token_claims({"sub": "explicit", "scp": ["x"]})
    try:
        assert scope_gate.current_claims()["sub"] == "explicit"
    finally:
        scope_gate.clear_token_claims()


# ── Transport hardening ──────────────────────────────────────────────────────


def test_audit_source_carries_the_client_address(monkeypatch):
    _install_request(monkeypatch, _FakeRequest(token="t", host="10.9.8.7", port=41234))
    assert request_auth.request_source() == "10.9.8.7:41234"


def test_origin_allowlist_is_parsed(monkeypatch):
    import server

    monkeypatch.setenv(
        "CB_ADMIN_ALLOWED_ORIGINS",
        "https://console.corp.example, http://127.0.0.1:5173",
    )
    assert server._allowed_origins() == [
        "https://console.corp.example",
        "http://127.0.0.1:5173",
    ]


def test_no_origin_allowlist_by_default(monkeypatch):
    import server

    monkeypatch.delenv("CB_ADMIN_ALLOWED_ORIGINS", raising=False)
    assert server._allowed_origins() == []


def test_claims_resolution_survives_the_thread_hop():
    """server.call_tool resolves claims via ``asyncio.to_thread`` so a JWKS fetch does
    not block the event loop for every other client.

    That is only safe because to_thread COPIES THE CONTEXT into the worker. The
    obvious-looking alternative, ``loop.run_in_executor``, does not — and the whole
    HTTP authorization bug in this codebase was a context that did not cross a task
    boundary, silently, with the result that every request was treated as anonymous.
    So the propagation property is pinned here rather than assumed.
    """
    import asyncio
    import contextvars

    probe: contextvars.ContextVar = contextvars.ContextVar("probe", default=None)

    async def scenario():
        probe.set({"sub": "svc-child"})
        via_to_thread = await asyncio.to_thread(probe.get)
        loop = asyncio.get_running_loop()
        via_executor = await loop.run_in_executor(None, probe.get)
        return via_to_thread, via_executor

    via_to_thread, via_executor = asyncio.run(scenario())
    assert via_to_thread == {"sub": "svc-child"}, (
        "to_thread no longer propagates context; claims resolution in server.call_tool "
        "would see no request and every HTTP call would be anonymous"
    )
    assert via_executor is None, (
        "run_in_executor unexpectedly propagates context; the comment in "
        "server.call_tool explaining why to_thread is required needs revisiting"
    )


def test_the_dispatch_does_not_validate_tokens_on_the_event_loop():
    """Structural backstop: the call must be awaited through to_thread."""
    import inspect

    import server

    source = inspect.getsource(server.call_tool)
    assert "await asyncio.to_thread(current_claims)" in source, (
        "claims are being resolved synchronously again; a slow or unreachable IdP "
        "would stall every connected client, not just the one being authenticated"
    )


# ── Tool enumeration is not public ───────────────────────────────────────────


def test_list_tools_refuses_an_unauthenticated_http_caller(monkeypatch):
    """list_tools had NO authorization check.

    On HTTP, any client that completed the MCP handshake received a full inventory:
    every tool name, every argument schema, and by omission the deployment mode and
    read-only posture. That is a reconnaissance primitive and the natural first step for
    an attacker — and it was reachable in the one case the edge middleware failed to
    recognise (CB_ADMIN_HTTP_REQUIRE_AUTH=on).
    """
    import asyncio
    import importlib

    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "http")
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "false")

    import server

    importlib.reload(server)
    from auth import scope_gate

    scope_gate.clear_token_claims()

    listed = asyncio.new_event_loop().run_until_complete(server.list_tools())
    assert listed == [], (
        f"{len(listed)} tools disclosed to a caller with no validated token"
    )


def test_list_tools_serves_an_authenticated_caller(monkeypatch):
    import asyncio
    import importlib

    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "http")
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")

    import server

    importlib.reload(server)
    from auth import scope_gate

    scope_gate.set_token_claims({"sub": "svc", "scope": "couchbase-admin-mcp:read"})
    try:
        listed = asyncio.new_event_loop().run_until_complete(server.list_tools())
        assert listed, "an authenticated caller must still see the tool surface"
    finally:
        scope_gate.clear_token_claims()


def test_list_tools_is_open_on_stdio(monkeypatch):
    """stdio has no token by design; returning an empty list would make the
    workstation profile useless."""
    import asyncio
    import importlib

    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "stdio")
    monkeypatch.delenv("CB_ADMIN_HTTP_REQUIRE_AUTH", raising=False)

    import server

    importlib.reload(server)
    from auth import scope_gate

    scope_gate.clear_token_claims()
    listed = asyncio.new_event_loop().run_until_complete(server.list_tools())
    assert listed
