"""
The ASGI auth middleware, the startup banner, and the dispatch error path.

WHY THE MIDDLEWARE IS THE INTERESTING PART
==========================================
`_ScopeAuthMiddleware` sits in front of every HTTP request, and it carries three properties
that each fix a real defect:

  1. **A presented token that fails validation is always a 401.** It used to be discarded, and
     the request then proceeded as anonymous — so a forged or expired token DISABLED
     enforcement instead of being rejected. A bad credential must never be a downgrade.

  2. **Validation runs off the event loop.** `validate_token` does a blocking JWKS fetch, and
     PyJWT re-fetches unconditionally for an unknown `kid` — which is attacker-chosen, read
     from the unverified header. Inline, one request per second with a random kid stalled the
     single event loop for up to 30 seconds each and hammered the customer's IdP from a
     trusted source address.

  3. **The token never reaches a log.** Only the exception type is recorded.

The banner is here because two of its warnings are the only notice an operator gets that a
control they think is on is inert.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import types

import pytest

import server

# ── A minimal ASGI harness ───────────────────────────────────────────────────


class _Downstream:
    """The app behind the middleware. Records whether it was reached."""

    def __init__(self):
        self.calls = 0

    async def __call__(self, scope, receive, send):
        self.calls += 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _scope(*, token: str | None = None, kind: str = "http", client=("10.1.2.3", 55555)):
    headers = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    return {"type": kind, "headers": headers, "client": client, "path": "/mcp"}


async def _drive(middleware, scope):
    """Run one request. Returns (status, body_bytes)."""
    sent: list[dict] = []

    async def _receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(message):
        sent.append(message)

    await middleware(scope, _receive, _send)
    status = next(
        (m["status"] for m in sent if m["type"] == "http.response.start"), None
    )
    body = b"".join(
        m.get("body", b"") for m in sent if m["type"] == "http.response.body"
    )
    return status, body


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture
def edge(monkeypatch):
    """The middleware wrapping a recording app, with audit captured.

    Returns (downstream, failures, build). `build(require=...)` constructs the middleware —
    `_require` is read from CB_ADMIN_HTTP_REQUIRE_AUTH at CONSTRUCTION time, not passed in, so
    the variable has to be set before the object exists. That is deliberate in the server:
    reading it per request would let a runtime env change turn enforcement off.
    """
    downstream = _Downstream()
    failures: list[dict] = []
    monkeypatch.setattr(
        server.audit,
        "emit_auth_failure",
        lambda **kw: failures.append(kw),
        raising=False,
    )

    def build(*, require: bool):
        monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true" if require else "false")
        middleware = server._ScopeAuthMiddleware(downstream)
        assert middleware._require is require, (
            "CB_ADMIN_HTTP_REQUIRE_AUTH was not honoured at construction"
        )
        return middleware

    return downstream, failures, build


# ── A valid token passes through ─────────────────────────────────────────────


def _a_dispatchable_tool_name() -> str:
    """A tool that this posture actually LOADS, not merely one that is registered.

    `server._HANDLERS` is the full registry; `server._TOOLS` is what survived the
    deployment, read-only and disabled-tools filters. Three tests here took
    `next(iter(server._HANDLERS))` and got `admin_bucket_list`, which is gated out
    whenever `detect_mode()` resolves to `capella` -- so on any machine with a
    Capella API key and no connection string, dispatch refused before reaching the
    stand-in handler and the test failed with an assertion about an empty list
    that said nothing about the property under test.

    Picking from the FILTERED list makes these tests independent of the machine's
    deployment posture, which is what they were always about: they are testing the
    transport, not the gate.
    """
    loaded = [getattr(t, "name", "") for t in server._TOOLS]
    assert loaded, (
        "no tools survived filtering, so every dispatch test below would be "
        "asserting against a refusal rather than a handler"
    )
    for name in loaded:
        if name in server._HANDLERS:
            return name
    raise AssertionError(
        f"none of the {len(loaded)} loaded tools has a handler in _HANDLERS; "
        "the tool list and the dispatch table disagree"
    )


def test_a_valid_token_reaches_the_application(edge, monkeypatch):
    downstream, failures, build = edge
    monkeypatch.setattr("auth.oidc.validate_token", lambda _t: {"sub": "u"})

    status, _ = _run(_drive(build(require=True), _scope(token="good")))

    assert status == 200
    assert downstream.calls == 1
    assert failures == []


def test_validation_happens_off_the_event_loop(edge, monkeypatch):
    """A blocking JWKS fetch on the loop thread stalls every other request. `to_thread` is
    what keeps one attacker-chosen `kid` from freezing the server for 30 seconds."""
    downstream, _failures, build = edge
    threads: list[str] = []

    def _record(_token):
        import threading

        threads.append(threading.current_thread().name)
        return {"sub": "u"}

    monkeypatch.setattr("auth.oidc.validate_token", _record)
    _run(_drive(build(require=True), _scope(token="good")))

    assert threads, "validate_token was never called"
    assert threads[0] != "MainThread", (
        "token validation ran on the event loop thread; a blocking JWKS fetch there stalls "
        "every concurrent request"
    )


# ── A bad token is a rejection, never a downgrade ────────────────────────────


def test_an_invalid_token_is_rejected_even_when_auth_is_not_required(edge, monkeypatch):
    """THE defect. With CB_ADMIN_HTTP_REQUIRE_AUTH unset — the default — a forged or expired
    token used to be discarded and the request proceeded as anonymous. Presenting a bad
    credential therefore DISABLED enforcement rather than failing."""
    downstream, failures, build = edge

    def _reject(_token):
        raise ValueError("signature mismatch")

    monkeypatch.setattr("auth.oidc.validate_token", _reject)

    status, body = _run(_drive(build(require=False), _scope(token="forged")))

    assert status == 401
    assert downstream.calls == 0, "the request proceeded after a failed validation"
    assert failures and "invalid token" in failures[0]["reason"]
    assert json.loads(body)


def test_the_rejection_never_contains_the_token(edge, monkeypatch):
    """The 401 body and the audit record both go somewhere durable. A rejected token is still
    a credential, and it is frequently a valid one for another system."""
    downstream, failures, build = edge
    secret = "eyJhbGciOiJSUzI1NiJ9.super-secret-token-material.sig"

    def _reject(_token):
        raise ValueError(f"bad token: {secret}")

    monkeypatch.setattr("auth.oidc.validate_token", _reject)

    _status, body = _run(_drive(build(require=True), _scope(token=secret)))

    assert secret not in body.decode()
    assert secret not in json.dumps(failures)


def test_the_401_body_is_valid_json_even_with_hostile_exception_text(edge, monkeypatch):
    """The detail is interpolated from an exception. `json.dumps` rather than an f-string,
    because a quote in that text would produce a malformed body — and a client that cannot
    parse the rejection reports a transport error instead of an auth failure."""
    downstream, _failures, build = edge

    def _reject(_token):
        raise ValueError('quote " backslash \\ newline \n brace }')

    monkeypatch.setattr("auth.oidc.validate_token", _reject)
    _status, body = _run(_drive(build(require=True), _scope(token="x")))
    assert isinstance(json.loads(body), dict)


def test_the_source_address_is_audited(edge, monkeypatch):
    """An unauthenticated caller probing the port is worth being able to find."""
    downstream, failures, build = edge
    monkeypatch.setattr(
        "auth.oidc.validate_token", lambda _t: (_ for _ in ()).throw(ValueError("no"))
    )
    _run(_drive(build(require=True), _scope(token="x")))
    assert "10.1.2.3" in failures[0]["source"]


def test_a_missing_client_address_does_not_break_the_rejection(edge, monkeypatch):
    """Some ASGI servers omit it. Reading `client[0]` unguarded would turn a 401 into a 500."""
    downstream, failures, build = edge
    monkeypatch.setattr(
        "auth.oidc.validate_token", lambda _t: (_ for _ in ()).throw(ValueError("no"))
    )
    status, _ = _run(_drive(build(require=True), _scope(token="x", client=None)))
    assert status == 401
    assert failures[0]["source"] == ""


# ── A missing token ──────────────────────────────────────────────────────────


def test_a_missing_token_is_refused_when_auth_is_required(edge):
    downstream, failures, build = edge
    status, _ = _run(_drive(build(require=True), _scope()))
    assert status == 401
    assert downstream.calls == 0
    assert failures and "missing bearer token" in failures[0]["reason"].lower()


def test_a_missing_token_is_allowed_when_auth_is_not_required(edge):
    """The workstation default. Guards the test above from passing because everything is
    refused — and the scope gate still applies further in."""
    downstream, failures, build = edge
    status, _ = _run(_drive(build(require=False), _scope()))
    assert status == 200
    assert downstream.calls == 1
    assert failures == []


@pytest.mark.parametrize(
    "header", ["bearer lower-case-scheme", "BEARER UPPER", "Bearer   spaced"]
)
def test_the_bearer_scheme_is_matched_case_insensitively(edge, monkeypatch, header):
    """RFC 7235 makes the scheme case-insensitive, and clients vary. Missing a spelling would
    treat a presented token as absent — i.e. anonymous rather than rejected."""
    downstream, _failures, build = edge
    seen: list[str] = []
    monkeypatch.setattr(
        "auth.oidc.validate_token", lambda t: seen.append(t) or {"sub": "u"}
    )

    scope = {
        "type": "http",
        "headers": [(b"authorization", header.encode())],
        "client": ("1.2.3.4", 1),
        "path": "/mcp",
    }
    _run(_drive(build(require=True), scope))
    assert seen, f"{header!r} was not recognised as a bearer token"
    assert not seen[0].startswith(" "), "the token was not stripped"


def test_a_non_bearer_authorization_header_is_treated_as_absent(edge):
    """Basic auth is not a token. Passing it to `validate_token` would produce a confusing
    JWT decode error rather than "missing Bearer token"."""
    downstream, failures, build = edge
    scope = {
        "type": "http",
        "headers": [(b"authorization", b"Basic YWRtaW46cGFzcw==")],
        "client": ("1.2.3.4", 1),
        "path": "/mcp",
    }
    status, _ = _run(_drive(build(require=True), scope))
    assert status == 401
    assert "missing" in failures[0]["reason"].lower()


def test_a_non_http_scope_passes_straight_through(edge):
    """Lifespan and websocket scopes have no headers. Treating them as unauthenticated HTTP
    would refuse the server's own startup event."""
    downstream, _failures, build = edge
    _run(_drive(build(require=True), _scope(kind="lifespan")))
    assert downstream.calls == 1


# ── The startup banner ───────────────────────────────────────────────────────


def test_the_banner_reports_the_profile_and_the_tool_counts(capsys):
    server._startup_banner()
    err = capsys.readouterr().err
    assert "profile:" in err
    assert "tools loaded:" in err
    assert "read_only=" in err


def test_an_issuer_without_enforcement_is_warned_about(monkeypatch, capsys):
    """The footgun: OIDC is configured, so it LOOKS authenticated, but an invalid token is
    ignored on HTTP. The operator has to learn that here rather than from a penetration test."""
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example.com")
    monkeypatch.delenv("CB_ADMIN_HTTP_REQUIRE_AUTH", raising=False)

    server._startup_banner()
    err = capsys.readouterr().err
    assert "OAUTH_ISSUER is set" in err
    assert "CB_ADMIN_HTTP_REQUIRE_AUTH" in err


def test_an_issuer_with_enforcement_is_not_warned_about(monkeypatch, capsys):
    """Guards the warning from firing on the correct configuration, which is how a real
    warning becomes noise and gets ignored."""
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    server._startup_banner()
    assert "OAUTH_ISSUER is set but" not in capsys.readouterr().err


def test_skip_verify_is_announced_loudly(monkeypatch, capsys):
    monkeypatch.setenv("OAUTH_SKIP_VERIFY", "true")
    server._startup_banner()
    err = capsys.readouterr().err
    assert "OAUTH_SKIP_VERIFY IS ENABLED" in err
    assert "NOT verified" in err


def test_a_ceiling_entry_matching_no_tool_is_reported(monkeypatch, capsys):
    """CB_ADMIN_ALWAYS_CONFIRM entries are case-sensitive tool names. One that matches nothing
    protects nothing, while reading as protection in the deployment's configuration."""
    monkeypatch.setattr(
        server, "_CEILING_UNKNOWN", {"admin_bucket_delet"}, raising=False
    )
    server._startup_banner()
    err = capsys.readouterr().err
    assert "admin_bucket_delet" in err
    assert "protect nothing" in err


def test_the_banner_never_raises_even_if_the_guardrail_policy_cannot_be_read(
    monkeypatch, capsys
):
    """A banner that throws stops the server from starting. Reporting configuration is never
    worth that."""
    from handlers.capella import guardrails

    monkeypatch.setattr(
        server, "_DEPLOYMENT_MODE", server.deployment.CAPELLA, raising=False
    )
    monkeypatch.setattr(server, "READ_ONLY_MODE", False, raising=False)
    monkeypatch.setattr(
        guardrails,
        "describe_policy",
        lambda: (_ for _ in ()).throw(RuntimeError("policy unreadable")),
    )

    server._startup_banner()  # must not raise
    assert "could not read Capella guardrail policy" in capsys.readouterr().err


def test_the_capella_guardrail_posture_is_shown_when_writes_are_enabled(
    monkeypatch, capsys
):
    """An operator who enabled writes but set no project allowlist should learn it at boot,
    not on the first refused teardown."""
    monkeypatch.setattr(
        server, "_DEPLOYMENT_MODE", server.deployment.CAPELLA, raising=False
    )
    monkeypatch.setattr(server, "READ_ONLY_MODE", False, raising=False)
    server._startup_banner()
    err = capsys.readouterr().err
    assert "capella guardrails:" in err
    assert "projects=" in err


# ── The dispatch error path ──────────────────────────────────────────────────


def test_a_handler_that_raises_becomes_an_error_response_and_an_audit_record(
    monkeypatch,
):
    """A traceback out of the transport is unrecoverable for the model, and an unaudited
    failure is a gap in the record of what was attempted."""
    records: list[dict] = []
    monkeypatch.setattr(
        server.audit, "emit_tool_call", lambda **kw: records.append(kw), raising=False
    )

    name = _a_dispatchable_tool_name()
    # A module-like stand-in: `_HANDLERS` maps a name to a MODULE and dispatch calls
    # `handler.handle(name, args)`, so a bare callable is an AttributeError rather than the
    # KeyError under test.
    monkeypatch.setitem(
        server._HANDLERS,
        name,
        types.SimpleNamespace(
            handle=lambda _n, _a: (_ for _ in ()).throw(KeyError("boom"))
        ),
    )

    result = _run(server.call_tool(name, {}))
    body = json.loads(result[0].text)

    assert body[server.shared.ERROR_MARKER] is True
    assert "KeyError" in body["error"]
    assert [r for r in records if r["decision"] == "error"]


def test_a_successful_call_is_audited_as_allowed_with_a_duration(monkeypatch):
    """The duration is what makes the audit log useful for anything other than forensics."""
    records: list[dict] = []
    monkeypatch.setattr(
        server.audit, "emit_tool_call", lambda **kw: records.append(kw), raising=False
    )

    name = _a_dispatchable_tool_name()
    from mcp.types import TextContent

    monkeypatch.setitem(
        server._HANDLERS,
        name,
        types.SimpleNamespace(
            handle=lambda _n, _a: [
                TextContent(type="text", text=json.dumps({"ok": True}))
            ]
        ),
    )

    _run(server.call_tool(name, {}))
    allowed = [r for r in records if r["decision"] == "allowed"]
    assert allowed
    assert allowed[0]["duration_ms"] is not None


# ── Correlation id handling ──────────────────────────────────────────────────


def test_the_correlation_id_is_stripped_before_the_handler_sees_it(monkeypatch):
    """It is a transport concern, not a tool argument. Leaving it in would make every handler
    reject it as an undeclared key — `refuse_undeclared` is strict by design."""
    seen: list[dict] = []
    from mcp.types import TextContent

    name = _a_dispatchable_tool_name()
    monkeypatch.setitem(
        server._HANDLERS,
        name,
        types.SimpleNamespace(
            handle=lambda _n, a: seen.append(a) or [TextContent(type="text", text="{}")]
        ),
    )
    monkeypatch.setattr(
        server.audit, "emit_tool_call", lambda **kw: None, raising=False
    )

    _run(server.call_tool(name, {"correlation_id": "run-42"}))
    assert seen
    assert "correlation_id" not in seen[0]


def test_the_correlation_id_reaches_the_audit_record(monkeypatch):
    """It is the only thing tying a child agent's action back to the run that spawned it."""
    records: list[dict] = []
    from mcp.types import TextContent

    monkeypatch.setattr(
        server.audit, "emit_tool_call", lambda **kw: records.append(kw), raising=False
    )
    name = _a_dispatchable_tool_name()
    monkeypatch.setitem(
        server._HANDLERS,
        name,
        types.SimpleNamespace(
            handle=lambda _n, _a: [TextContent(type="text", text="{}")]
        ),
    )

    _run(server.call_tool(name, {"correlation_id": "run-42"}))
    assert records
    assert records[0]["correlation_id"] == "run-42"


# ── Module import surface ────────────────────────────────────────────────────


def test_the_module_exposes_a_main_entry_point():
    """`pyproject.toml` declares `couchbase-admin-mcp-server = "server:main"`. A rename would
    make the installed console script raise AttributeError at startup."""
    assert callable(server.main)


def test_the_transport_selection_reads_the_documented_variable():
    """`CB_ADMIN_TRANSPORT` chooses stdio or http, and the profile validator refuses
    incoherent combinations on the strength of that name."""
    import inspect

    source = inspect.getsource(server)
    assert "CB_ADMIN_TRANSPORT" in source


def test_reimporting_the_server_is_idempotent(monkeypatch):
    """The console and the packaging tests both import it fresh. A module-level side effect
    that cannot run twice makes those unreliable rather than the server wrong."""
    reloaded = importlib.reload(server)
    try:
        assert reloaded._TOOLS
        assert reloaded._HANDLERS
    finally:
        importlib.reload(server)
