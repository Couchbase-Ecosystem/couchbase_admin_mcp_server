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
  CB_ADMIN_SCOPE_READ    scope required for read tools   (default: couchbase-mcp:read)
  CB_ADMIN_SCOPE_WRITE   scope required for write tools  (default: couchbase-mcp:write)

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


def clear_token_claims() -> None:
    """Reset context after a request (defensive; contextvars are per-task)."""
    _token_claims.set(None)


def _scope_read() -> str:
    return os.environ.get("CB_ADMIN_SCOPE_READ", "couchbase-mcp:read").strip()


def _scope_write() -> str:
    return os.environ.get("CB_ADMIN_SCOPE_WRITE", "couchbase-mcp:write").strip()


def _scope_automation() -> str:
    """Scope that grants unattended (automation) mode.

    A token carrying this scope IN ADDITION TO the write scope may execute gated
    write tools without a per-call human confirmation. It never substitutes for
    the write scope — an automation token with no write scope still cannot write.
    Bound to the token (issued by the IdP to a service principal), so a caller
    can never self-promote by placing a value in tool arguments.
    """
    return os.environ.get(
        "CB_ADMIN_SCOPE_AUTOMATION", "couchbase-mcp:automation"
    ).strip()


def session_has_automation_scope() -> bool:
    """True when the current request's token carries the automation scope.

    Returns False when there is no token in context (stdio / unauthenticated),
    so automation mode is only ever reached by an explicitly automation-scoped
    principal on an authenticated transport — never by default.
    """
    claims = _token_claims.get()
    if claims is None:
        return False
    return _scope_automation() in _claims_scopes(claims)


def _claims_scopes(claims: dict[str, Any]) -> set[str]:
    """
    Extract granted scopes from token claims.

    Handles the common shapes:
      * RFC 8693 'scope' as a space-delimited string
      * 'scope'/'scopes' already a list
      * Entra-style 'scp' (string or list)
    """
    raw: Any = claims.get("scope")
    if raw is None:
        raw = claims.get("scp")
    if raw is None:
        raw = claims.get("scopes")

    if raw is None:
        return set()
    if isinstance(raw, str):
        return {s for s in raw.split() if s}
    if isinstance(raw, (list, tuple, set)):
        return {str(s) for s in raw}
    return set()


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


def check_scope(tool: Any) -> str | None:
    """
    Authorize the current request to invoke `tool`.

    Returns None when allowed (including the no-token no-op case), or a
    human-readable denial message when the token lacks the required scope.
    """
    claims = _token_claims.get()
    if claims is None:
        return None  # no token in context -> enforcement disabled, allowed

    required = _required_scope_for(tool)
    granted = _claims_scopes(claims)
    if required in granted:
        return None

    return (
        f"Access denied: tool '{getattr(tool, 'name', '?')}' requires scope "
        f"'{required}', which the presented token does not hold."
    )
