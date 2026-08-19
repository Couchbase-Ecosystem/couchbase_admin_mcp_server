"""
auth/request_auth.py — resolve the calling principal INSIDE the dispatch task.

THE BUG THIS REPLACES
=====================
The previous design validated the bearer token in ASGI middleware and stashed the
claims in a ``contextvars.ContextVar``. That cannot work on this transport, and it
failed silently:

    middleware task            dispatch task (created at server startup)
    ───────────────            ────────────────────────────────────────
    set_token_claims(claims)   call_tool() -> check_scope() -> claims is None

``contextvars`` snapshot at task creation. The MCP SDK's dispatch loop
(``Server._handle_request``) is a *sibling* task started when the session was
initialised — before any request existed — so a value set in the request's task is
never visible to it. Consequences, all silent:

  * ``check_scope()`` always saw ``None`` and returned "allowed". Read/write scope
    separation was inoperative on HTTP.
  * ``session_has_automation_scope()`` was permanently ``False``, so the whole
    automation trust model — the thing that authorizes an unattended child agent
    by its token instead of by a per-call confirmation — never engaged. An
    authorized workflow principal was demoted to "must send confirm: true", which
    is the model rubber-stamping itself.
  * ``CB_ADMIN_ALWAYS_CONFIRM`` became dead code, because it is only consulted for
    automation principals.

The existing tests passed because they set the contextvar in the same task that
awaited ``call_tool`` — they exercised the module, not the transport.

THE FIX
=======
Stop moving claims between tasks. The SDK sets ``request_ctx`` — including the
Starlette ``Request`` — inside ``_handle_request``, i.e. inside the dispatch task,
which is exactly where the authorization decision is made. So resolve the
principal from the request at the point of use:

    app.request_context.request  ->  Authorization header  ->  validated claims

There is no cross-task handoff left to get wrong, and it works identically for
every HTTP transport variant because it depends only on the SDK's own request
context rather than on how the ASGI app was assembled.

The ASGI middleware is kept, but only for what middleware is actually good at:
rejecting a bad credential at the edge with a 401 before it reaches the dispatch
loop, and emitting the auth-failure audit record. It is no longer load-bearing for
authorization — belt as well as braces, in that order.

TOKEN VALIDATION CACHE
======================
``check_scope`` and ``session_has_automation_scope`` both need the claims, and a
single tool call touches them more than once. Validating a JWT means a signature
check, and on a JWKS cache miss an outbound fetch to the IdP, so it is cached per
token for a short window (never past the token's own ``exp``). The cache is keyed
by a hash of the token, never the token itself, so a memory dump or a debug repr
cannot yield a usable credential.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

_CACHE_TTL_SECONDS = 60.0
_CACHE_MAX_ENTRIES = 256

#: token-hash -> (claims, expires_at_monotonic)
_validated: dict[str, tuple[dict[str, Any], float]] = {}


def _digest(token: str) -> str:
    """Cache key. A hash, so the cache never holds a usable credential."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _cache_get(token: str) -> dict[str, Any] | None:
    entry = _validated.get(_digest(token))
    if entry is None:
        return None
    claims, expires_at = entry
    if time.monotonic() >= expires_at:
        _validated.pop(_digest(token), None)
        return None
    return claims


def _cache_put(token: str, claims: dict[str, Any]) -> None:
    if len(_validated) >= _CACHE_MAX_ENTRIES:
        # Cheap bound. This is a latency cache, not a correctness mechanism, so
        # dropping the whole thing under pressure is acceptable — the next call
        # simply re-validates.
        _validated.clear()

    ttl = _CACHE_TTL_SECONDS
    # Never cache a token past its own expiry: an expired token must start being
    # rejected the moment it expires, not up to a minute later.
    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        remaining = float(exp) - time.time()
        if remaining <= 0:
            return
        ttl = min(ttl, remaining)
    _validated[_digest(token)] = (claims, time.monotonic() + ttl)


def reset_cache() -> None:
    """Clear the validation cache. For tests, and safe to call at any time."""
    _validated.clear()


def _bearer_from_headers(headers: Any) -> str | None:
    """Extract a bearer token from a Starlette/ASGI headers mapping."""
    if headers is None:
        return None
    try:
        raw = headers.get("authorization")
    except AttributeError:
        return None
    if not raw or not isinstance(raw, str):
        return None
    if not raw.lower().startswith("bearer "):
        return None
    token = raw[7:].strip()
    return token or None


def current_request() -> Any | None:
    """The Starlette request for the tool call being dispatched, if any.

    Returns None on stdio, where there is no HTTP request by design, and None if
    called outside a request context.
    """
    try:
        from mcp.server.lowlevel.server import request_ctx
    except Exception:
        return None
    try:
        ctx = request_ctx.get()
    except LookupError:
        return None
    return getattr(ctx, "request", None)


def resolve_claims() -> dict[str, Any] | None:
    """Validated token claims for the tool call currently being dispatched.

    Returns None when there is no HTTP request (stdio) or no bearer token. Raises
    nothing: a token that fails validation yields None, and the caller decides
    whether that is fatal — which, when CB_ADMIN_HTTP_REQUIRE_AUTH is set, it is.
    """
    request = current_request()
    if request is None:
        return None

    token = _bearer_from_headers(getattr(request, "headers", None))
    if token is None:
        return None

    cached = _cache_get(token)
    if cached is not None:
        return cached

    try:
        from auth import oidc

        claims = oidc.validate_token(token)
    except Exception:
        # Never log the token, and do not distinguish failure modes to the caller:
        # "invalid" is all an unauthenticated party is entitled to learn.
        return None

    if isinstance(claims, dict):
        _cache_put(token, claims)
        return claims
    return None


def request_source() -> str:
    """Client address for the audit record, when one is available."""
    request = current_request()
    client = getattr(request, "client", None) if request is not None else None
    if client is None:
        return ""
    host = getattr(client, "host", None)
    port = getattr(client, "port", None)
    if host is None:
        return ""
    return f"{host}:{port}" if port else str(host)


def transport_is_http() -> bool:
    """Whether this process is serving the HTTP transport.

    Used to decide whether the absence of a token is expected (stdio) or a hard
    failure (HTTP with authentication required).
    """
    return (os.environ.get("CB_ADMIN_TRANSPORT", "stdio") or "").strip().lower() in (
        "http",
        "streamable_http",
        "streamablehttp",
    )
