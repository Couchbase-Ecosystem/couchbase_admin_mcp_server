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

Licensed under the Apache License, Version 2.0. Copyright 2026 Couchbase, Inc.
See the LICENSE and NOTICE files at the repository root.
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


def _flatten_grant(raw: Any) -> set[str]:
    """A claim value in any of the shapes an IdP emits, as a set of grants."""
    if isinstance(raw, str):
        return {s for s in raw.split() if s}
    if isinstance(raw, (list, tuple, set)):
        return {str(s) for s in raw if str(s)}
    return set()


def _claims_scopes(claims: dict[str, Any]) -> set[str]:
    """Extract every granted scope/role from token claims.

    Handles the shapes real IdPs emit:
      * RFC 8693 `scope` as a space-delimited string   (Auth0, Keycloak scopes)
      * `scp` as string or list                        (Entra delegated, Okta)
      * `roles` as a list                              (Entra app permissions —
                                                        client credentials)
      * `permissions` as a list                        (Auth0 RBAC)
      * `realm_access.roles`                           (Keycloak REALM roles)
      * `resource_access.<client>.roles`               (Keycloak CLIENT roles)

    THE NESTED KEYCLOAK SHAPES ARE NOT OPTIONAL, and reading only the top level
    was a gap. Keycloak emits SCOPES at the top level in `scope`, but ROLES are
    nested one or two levels down, and an operator who grants the automation
    permission as a role rather than a scope -- which Keycloak's own UI makes the
    more natural choice -- produced a token this function read as carrying
    nothing at all. The failure direction was safe: every unattended write fell
    back to demanding a per-call confirmation, so a pipeline stopped rather than
    over-reaching. But it stopped while reporting "needs confirmation", which
    says nothing about the grant being in a claim nobody read.

    `resource_access` is walked across every client rather than only the
    configured audience, deliberately: the client a role is attached to is the
    IdP administrator's choice, and refusing a grant because it arrived under a
    neighbouring client id would reproduce the same silence one level down.
    """
    granted: set[str] = set()
    for claim in _SCOPE_CLAIMS:
        granted |= _flatten_grant(claims.get(claim))

    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict):
        granted |= _flatten_grant(realm_access.get("roles"))

    resource_access = claims.get("resource_access")
    if isinstance(resource_access, dict):
        for per_client in resource_access.values():
            if isinstance(per_client, dict):
                granted |= _flatten_grant(per_client.get("roles"))

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
    # mcp_compat, not getattr-with-default: the default form silently answers
    # "not read-only" under mcp 2.x naming, so a read-scoped token would be denied
    # every read tool the read-only filter had loaded.
    import mcp_compat

    return bool(ann and mcp_compat.is_read_only(tool))


def is_read_side(tool: Any) -> bool:
    """Public name for the read/write classification.

    Exported because the dry-run policy needs exactly the same answer the scope gate
    uses: a second classifier would eventually disagree with this one, and the
    disagreement would show up as a write that a dry run executed.
    """
    return _is_read_side(tool)


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

    Thin wrapper over denial_for() so that the CALL path and the LISTING path
    reach the same verdict through the same code. See denial_for.
    """
    return denial_for(tool, current_claims())


def denial_for(tool: Any, claims: dict[str, Any] | None) -> str | None:
    """The authorization decision for `tool` under `claims`, as a pure function.

    WHY THIS IS SEPARATE FROM check_scope
    ─────────────────────────────────────
    The tool LISTING needs the same verdict as the tool CALL, and it needs it for
    146 tools against claims it has already resolved. Two things follow.

    First, correctness: server.py's list_tools() must not advertise a tool that
    calling would refuse. A read-only principal was offered the entire surface --
    every write tool, every argument schema -- and only discovered at call time
    that it held none of them. MEASURED 2026-09-15 against a real Keycloak
    reader token: 146 tools listed, admin_scope_create among them, denied on
    invocation. Least privilege says a principal is not handed a catalog it
    cannot use, and the deployment's posture (which tools loaded, whether writes
    are enabled at all) is not something an under-scoped caller should be able to
    read off the listing.

    A separate filter in server.py would have been the obvious fix and the wrong
    one: it would be a SECOND classifier, and the first thing this module's
    docstring promises is that there is only one. Two predicates agree until they
    do not, and the disagreement surfaces as either a tool advertised then
    refused, or -- far worse -- a tool omitted from the listing that a caller can
    still invoke by name. Sharing this function makes the listing and the gate
    the same decision by construction.

    Second, cost: claims are resolved ONCE by the caller and passed in. check_scope
    resolves per call, which is right for a single dispatch and wrong for a loop
    over the catalog -- resolution can reach the IdP on a cache miss, which is
    why list_tools already resolves off the event loop.

    `claims` is None for stdio, for HTTP without OAuth configured, and for a token
    that failed validation. The first two are no-ops; the third is a refusal when
    the operator asked for enforcement. That distinction is made below, not by the
    caller.
    """
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

    if not granted:
        # "I FOUND NO GRANT" AND "THERE IS NO GRANT" ARE DIFFERENT CLAIMS, and a
        # generic denial states the second while only the first was observed.
        # CLAUDE.md section 1.7.
        #
        # A token that validated -- signature, issuer, audience and expiry all
        # checked -- and carries nothing this function recognises is far more
        # likely to be a claim-shape mismatch than a principal that was granted
        # nothing. The operator needs to know WHICH claims were read, because the
        # fix is in their IdP's mapper configuration and nowhere near this server.
        return (
            f"Access denied: tool '{getattr(tool, 'name', '?')}' requires scope "
            f"'{required}'. The presented token VALIDATED but carried no "
            f"recognised grant in any of: {', '.join(_SCOPE_CLAIMS)}, "
            f"realm_access.roles, or resource_access.<client>.roles. That is "
            f"usually an IdP mapper emitting the grant under a claim this server "
            f"does not read, rather than a principal with no permissions."
        )

    return (
        f"Access denied: tool '{getattr(tool, 'name', '?')}' requires scope "
        f"'{required}', which the presented token does not hold. It holds: "
        f"{', '.join(sorted(granted))}."
    )
