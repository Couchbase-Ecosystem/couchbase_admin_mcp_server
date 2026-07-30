"""
auth/scope_gate.py — Per-tool OAuth scope enforcement for the MCP call path.

KISS design:
  * When no validated token is in context (stdio transport, or HTTP with OAuth
    not configured), enforcement is a no-op. Same code path serves both modes.
  * When a token IS in context, each tool call is checked against the scopes the
    token carries. Read-side tools need the READ scope; write-side tools need
    the WRITE scope. The two scopes are independent: a read-only token cannot
    reach write tools, and a write-only token cannot reach read tools.

Single source of truth for read-vs-write
─────────────────────────────────────────
The read/write split MUST match the server's own read-only-mode filter, or a
token could be granted a tool that is loaded into its catalog yet denied at
call time (or vice versa). This module therefore classifies a tool as read-side
using the SAME predicate the server uses to decide what loads under
CB_ADMIN_READ_ONLY_MODE:

    read-side  ==  annotations.readOnlyHint is True
               OR  tool name is in the always-loaded-in-read-only set
                   (cb_query / cb_analytics_query — these declare
                   destructiveHint=True but self-block DML internally).

Everything else is write-side. The caller injects the server's actual
always-loaded set via configure(), so the two stay in lockstep even if that set
changes.

Environment
───────────
  CB_ADMIN_SCOPE_READ    scope required for read tools   (default: couchbase-admin-mcp:read)
  CB_ADMIN_SCOPE_WRITE   scope required for write tools  (default: couchbase-admin-mcp:write)

License: MIT — Copyright (c) 2026 Chris Ahrendt
"""

from __future__ import annotations

import contextvars
import os
from typing import Any

# Request-scoped token claims. Set by the HTTP layer after validate_token();
# left as None on stdio or when OAuth is not configured.
_token_claims: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "cb_mcp_token_claims", default=None
)

# Tool names that the server force-loads in read-only mode despite not being
# annotated readOnlyHint=True. Injected by configure() so this module never
# hardcodes a list that could drift from server.py. The admin server has no
# such tools (every write is a real mutation), so the default is empty.
_always_read: frozenset[str] = frozenset()


def configure(always_loaded_in_read_only: set[str] | frozenset[str]) -> None:
    """Align the read-side classification with the server's read-only filter.

    Pass server.py's _ALWAYS_LOADED_IN_READ_ONLY so a token holding only the
    read scope can invoke exactly the tools the server loads in read-only mode.
    """
    global _always_read
    _always_read = frozenset(always_loaded_in_read_only)


def set_token_claims(claims: dict[str, Any] | None) -> None:
    """Store validated JWT claims for the current request context."""
    _token_claims.set(claims)


def current_claims() -> dict[str, Any] | None:
    """Validated claims for the call being dispatched, or None.

    Resolution order matters:

      1. An explicitly-set contextvar. Used by tests, and correct for any caller
         that sets it in the SAME task that will run the tool.
      2. The Starlette request carried on the SDK's request context.

    (2) is what makes HTTP work at all. The contextvar alone could not: the ASGI
    middleware runs in the request's task while tool dispatch runs in a sibling
    task created at session-init time, and contextvars snapshot at task creation —
    so claims set by the middleware were invisible here, every time, silently. See
    auth/request_auth.py for the full account.
    """
    explicit = _token_claims.get()
    if explicit is not None:
        return explicit
    try:
        from auth.request_auth import resolve_claims

        return resolve_claims()
    except Exception:
        # Authorization must never be granted because a lookup blew up.
        return None


def clear_token_claims() -> None:
    """Reset context after a request (defensive; contextvars are per-task)."""
    _token_claims.set(None)


def _scope_read() -> str:
    return os.environ.get("CB_ADMIN_SCOPE_READ", "couchbase-admin-mcp:read").strip()


def _scope_write() -> str:
    return os.environ.get("CB_ADMIN_SCOPE_WRITE", "couchbase-admin-mcp:write").strip()


def _scope_automation() -> str:
    """Scope that grants unattended (automation) mode.

    A token carrying this scope IN ADDITION TO the write scope may execute gated
    write tools without a per-call human confirmation. It never substitutes for
    the write scope — an automation token with no write scope still cannot write.
    Bound to the token (issued by the IdP to a service principal), so a caller
    can never self-promote by placing a value in tool arguments.
    """
    return os.environ.get(
        "CB_ADMIN_SCOPE_AUTOMATION", "couchbase-admin-mcp:automation"
    ).strip()


def session_has_automation_scope() -> bool:
    """True when the calling principal's token carries the automation scope.

    This is the enterprise authorization path: a workflow-manager agent's child
    holds a token carrying write + automation, and the per-call confirmation is
    then skipped entirely. That is the design — the human decision happened once,
    when the IdP issued the credential, not at each tool call.

    Returns False when there is no token (stdio / workstation), so automation mode
    is never reached by default.
    """
    claims = current_claims()
    if claims is None:
        return False
    return _scope_automation() in _claims_scopes(claims)


#: Claims that can carry granted authority, in the order IdPs actually use them.
#:
#: `roles` matters specifically for the unattended workflow. Microsoft Entra issues
#: CLIENT-CREDENTIALS tokens — which is what a workflow-manager service principal
#: receives — with app permissions in `roles`, NOT in `scp`. Reading only
#: scope/scp/scopes meant an Entra service principal's automation grant was
#: invisible, silently downgrading an authorized autonomous caller to
#: "needs per-call confirmation". Okta populates `scp` and Auth0 `scope`, so this
#: gap would pass testing against either and fail against Entra.
#:
#: All present claims are UNIONED rather than first-match-wins: a token may carry
#: delegated scopes in `scp` and application roles in `roles` at the same time, and
#: taking only the first non-empty claim would discard half the grant.
_SCOPE_CLAIMS: tuple[str, ...] = ("scope", "scp", "scopes", "roles", "permissions")


def _claims_scopes(claims: dict[str, Any]) -> set[str]:
    """Extract every granted scope/role from token claims.

    Handles the shapes real IdPs emit:
      * RFC 8693 `scope` as a space-delimited string   (Auth0, Keycloak)
      * `scp` as string or list                        (Entra delegated, Okta)
      * `roles` as a list                              (Entra app permissions —
                                                        client credentials)
      * `permissions` as a list                        (Auth0 RBAC)
    """
    granted: set[str] = set()
    for claim in _SCOPE_CLAIMS:
        raw: Any = claims.get(claim)
        if raw is None:
            continue
        if isinstance(raw, str):
            granted.update(s for s in raw.split() if s)
        elif isinstance(raw, (list, tuple, set)):
            granted.update(str(s) for s in raw if str(s))
    return granted


def principal_of(claims: dict[str, Any] | None) -> dict[str, Any]:
    """Identify the calling principal, for the audit record.

    "Which service principal did this" is the question an audit trail has to
    answer, and for an autonomous workflow it is the ONLY identity available —
    there is no human at the keyboard by design. Pulled from the validated token
    only; never from anything the caller can set alongside the tool arguments.
    """
    if not claims:
        return {"principal": None, "auth": "none"}
    return {
        "principal": claims.get("sub") or claims.get("oid") or claims.get("client_id"),
        "client_id": claims.get("client_id")
        or claims.get("azp")
        or claims.get("appid"),
        "issuer": claims.get("iss"),
        "scopes": sorted(_claims_scopes(claims)),
        "automation": _scope_automation() in _claims_scopes(claims),
        "auth": "oauth",
    }


def _is_read_side(tool: Any) -> bool:
    """Mirror server.py's read-only-mode load predicate exactly.

    A tool is read-side iff it is annotated readOnlyHint=True, OR its name is in
    the server's always-loaded-in-read-only set. Anything else is write-side,
    including tools with no annotations (unknown intent -> stronger scope).
    """
    name = getattr(tool, "name", None)
    if name in _always_read:
        return True
    ann = getattr(tool, "annotations", None)
    return bool(ann and getattr(ann, "readOnlyHint", False))


def _required_scope_for(tool: Any) -> str:
    return _scope_read() if _is_read_side(tool) else _scope_write()


def _auth_required() -> bool:
    """Whether the operator has demanded authenticated access.

    Read from the environment rather than injected, so the gate cannot be left
    un-configured by a caller that forgets to wire it.
    """
    return (os.environ.get("CB_ADMIN_HTTP_REQUIRE_AUTH", "") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def check_scope(tool: Any) -> str | None:
    """
    Authorize the current request to invoke `tool`.

    Returns None when allowed (including the no-token no-op case), or a
    human-readable denial message when the token lacks the required scope.
    """
    claims = current_claims()
    if claims is None:
        # FAIL CLOSED when the operator asked for enforcement.
        #
        # This branch used to return None unconditionally — "no token in context,
        # enforcement disabled, allowed". Correct on stdio, where there is no token
        # by design. On HTTP it was a total authorization bypass, because claims
        # could never reach this function across the task boundary (see
        # auth/request_auth.py). That cause is now fixed: claims are resolved from
        # the request being dispatched.
        #
        # Reaching here on HTTP with authentication required therefore means
        # something real: no bearer token was presented, or it failed validation.
        # Either way it is a refusal, not a downgrade to anonymous.
        if _auth_required():
            return (
                "Access denied: CB_ADMIN_HTTP_REQUIRE_AUTH is enabled but no "
                "validated token reached the tool dispatcher, so authorization "
                "cannot be established: no valid bearer token was presented with "
                "this request. Refusing rather than proceeding unauthenticated."
            )
        return None  # stdio / no OAuth configured -> nothing to enforce

    required = _required_scope_for(tool)
    granted = _claims_scopes(claims)
    if required in granted:
        return None

    return (
        f"Access denied: tool '{getattr(tool, 'name', '?')}' requires scope "
        f"'{required}', which the presented token does not hold."
    )
