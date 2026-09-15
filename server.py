"""
Couchbase MCP Server (Extended, hardened)
=========================================

Exposes the full Couchbase data-plane AND admin REST API as MCP tools, with
defense-in-depth safety primitives modeled after the official Couchbase MCP.

Tool categories (all upstream names preserved)
──────────────────────────────────────────────
  Data       - CRUD, N1QL, FTS search, ping     (cb_*)
  Buckets    - create/update/delete/flush       (admin_bucket_*)
  Collections- scopes and collections           (admin_scope_*, admin_collection_*)
  Security   - users, groups, RBAC, audit       (admin_user_*, admin_group_*, admin_*)
  Cluster    - nodes, rebalance, failover       (admin_cluster_*, admin_node_*, admin_*)
  XDCR       - references and replications      (admin_xdcr_*)
  Indexes    - GSI create/drop/build, settings  (admin_index_*)
  FTS Admin  - FTS index CRUD + stats           (admin_fts_*)
  Stats      - metrics, events, internal        (admin_stats_*, admin_*)
  Diagnostics- schema, advisor, EXPLAIN, perf   (cb_get_schema_for_collection,
                                                  cb_index_advisor, cb_explain_query,
                                                  cb_perf_*)
  8.x-only   - vector indexes, lock, conflicts  (admin_vector_index_create_*,
                                                  admin_user_lock/unlock/create_temporary,
                                                  admin_xdcr_conflict_log_query)
  Backup     - repository, backup, restore       (admin_backup_*)
  Eventing   - function lifecycle, deploy, stats (admin_eventing_*)
  Encryption - DARE + KMIP                       (admin_encryption_*, admin_kmip_*)
  Capella v4 - SaaS control plane (read-only)    (capella_*)

  Note: the data-plane tools (cb_get/upsert/query, cb_transaction_run,
  cb_analytics_query, cb_perf_by_user, cb_fts_synonym_*) live in the separate
  MCP-Couchbase data server, not here.

Environment variables
─────────────────────

CONNECTION
  CB_CONNECTION_STRING         couchbase://localhost (use couchbases:// for TLS)
  CB_USERNAME                  (required unless using mTLS)
  CB_PASSWORD                  (required unless using mTLS)
  CB_BUCKET                    default
  CB_SCOPE                     _default
  CB_COLLECTION                _default
  CB_MGMT_PORT                 8091 (or 18091 for TLS; Capella self-managed admin)

mTLS / TLS  (Phase 3)
  CB_CLIENT_CERT_PATH          path to client cert PEM (presence enables mTLS)
  CB_CLIENT_KEY_PATH           path to client key PEM
  CB_CA_CERT_PATH              path to CA cert for self-signed self-managed clusters
  CB_ADMIN_TLS_INSECURE          false   set true to skip TLS verification (dev only)

SAFETY  (Phase 1)
  CB_ADMIN_READ_ONLY_MODE        true    when true, write tools are NOT loaded
  CB_ADMIN_DISABLED_TOOLS                comma list, or path to file with one name per line
  CB_ADMIN_CONFIRMATION_REQUIRED_TOOLS   additional tools that require confirm:true
  CB_ADMIN_ELICITATION_HINTS     true    include hint text in confirmation errors

NETWORK  (Phase 2)
  CB_ADMIN_HTTP_RETRIES          3       max attempts for admin HTTP calls
  CB_ADMIN_HTTP_TIMEOUT          30      per-request timeout in seconds

TRANSPORT  (Phase 3)
  CB_ADMIN_TRANSPORT             stdio   one of: stdio, http
  CB_ADMIN_HOST                  127.0.0.1  for http transport
  CB_ADMIN_PORT                  8000       for http transport

Compatibility
─────────────
All tool names from the upstream celticht32 server are preserved. New tools
may be added in future; new optional `confirm` arguments are introduced on
destructive tools but do not change existing tool semantics.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolRequest, TextContent, Tool

# NOTE: profile_config applies the deployment profile's env defaults AT IMPORT
# TIME, and handlers.shared snapshots CB_ADMIN_READ_ONLY_MODE at its own import
# time — so profile_config must be imported before the handlers. isort places
# plain `import x` ahead of `from x import y`, which preserves that ordering.
import audit
import authz
import deployment
import dryrun
import mcp_compat
import profile_config
import tls_config
from auth import request_auth
from auth.scope_gate import (
    check_scope,
    current_claims,
    denial_for,
    principal_of,
    session_has_automation_scope,
)
from auth.scope_gate import (
    configure as configure_scope_gate,
)
from auth.scope_gate import (
    is_read_side as scope_gate_is_read_side,
)
from handlers import (
    backup,
    backup_catalog,
    buckets,
    capella,
    cluster,
    collections,
    diagnostics,
    eight_x,
    encryption,
    eventing,
    fixture,
    indexes,
    mcp_status,
    search_admin,
    security,
    shared,
    stats,
    xdcr,
)
from handlers.shared import (
    DISABLED_TOOLS,
    READ_ONLY_MODE,
    env_truthy,
    err,
    get_confirmation_required,
    require_confirmation,
)
from logging_config import configure_from_env, get_logger

# Module logger for the dispatch/server layer. Handlers get their own child
# loggers (couchbase-admin.handlers.<name>) so records are filterable by source.
_log = get_logger("server")

# ── Aggregate tool registry ──────────────────────────────────────────────────

_RAW_TOOLS: list[Tool] = (
    buckets.TOOLS
    + collections.TOOLS
    + security.TOOLS
    + cluster.TOOLS
    + xdcr.TOOLS
    + indexes.TOOLS
    + search_admin.TOOLS
    + stats.TOOLS
    + diagnostics.TOOLS
    + eight_x.TOOLS
    + backup.TOOLS
    + eventing.TOOLS
    + encryption.TOOLS
    + capella.TOOLS
    + mcp_status.TOOLS
    # DELIBERATELY NOT UNDER handlers/capella. The catalogue annotates backups on
    # BOTH planes -- a Capella backup id or an EE repository plus backup name --
    # and registering it as a Capella tool would filter it out of self_managed
    # mode, which is exactly the deployment whose backup naming is worst served
    # by the plane itself.
    + backup_catalog.TOOLS
    # Enterprise Edition fixtures. Under handlers/ rather than handlers/capella/
    # because this is the SELF-MANAGED family -- the Capella one is
    # capella_fixture_*, reached through the Data API, and the two share only
    # handlers/fixture_core.py. See docs/FIXTURE_DESIGN.md.
    + fixture.TOOLS
)

_HANDLERS = {
    **{t.name: buckets for t in buckets.TOOLS},
    **{t.name: collections for t in collections.TOOLS},
    **{t.name: security for t in security.TOOLS},
    **{t.name: cluster for t in cluster.TOOLS},
    **{t.name: xdcr for t in xdcr.TOOLS},
    **{t.name: indexes for t in indexes.TOOLS},
    **{t.name: search_admin for t in search_admin.TOOLS},
    **{t.name: stats for t in stats.TOOLS},
    **{t.name: diagnostics for t in diagnostics.TOOLS},
    **{t.name: eight_x for t in eight_x.TOOLS},
    **{t.name: backup for t in backup.TOOLS},
    **{t.name: eventing for t in eventing.TOOLS},
    **{t.name: encryption for t in encryption.TOOLS},
    **{t.name: capella for t in capella.TOOLS},
    **{t.name: mcp_status for t in mcp_status.TOOLS},
    **{t.name: backup_catalog for t in backup_catalog.TOOLS},
    **{t.name: fixture for t in fixture.TOOLS},
}

# Tools that stay loaded in read-only mode despite destructiveHint=true,
# internally (e.g. a query tool that rejects DML). The admin server has no such
# tools — every write here is a real control-plane mutation — so the set is empty
# and read-only mode filters strictly on the readOnlyHint annotation.
_ALWAYS_LOADED_IN_READ_ONLY: set[str] = set()

# Keep scope-gate read/write classification in lockstep with the read-only
# filter below. A read-scoped token may invoke exactly what loads in read-only.
configure_scope_gate(_ALWAYS_LOADED_IN_READ_ONLY)


# ── Deployment mode ──────────────────────────────────────────────────────────
#
# Resolved once at import. Determines which tools can physically work: the
# self-managed ns_server admin surface, the Capella v4 control plane, or (in
# 'both' mode) everything. See deployment.py for the detection rules.
_DEPLOYMENT_MODE: str = deployment.detect_mode()
_GATING: bool = deployment.gating_enabled()


def _is_read_only(t: Tool) -> bool:
    """A tool is read-only if its annotation says so."""
    return mcp_compat.is_read_only(t)


def _filter_tools(raw_tools: list[Tool]) -> list[Tool]:
    """Apply deployment-capability, read-only mode, and disabled-tools filters.

    The deployment filter comes first and is the coarsest: against Capella, the
    ns_server admin tools cannot work at all, because a Capella database
    credential carries bucket-scoped data roles and never cluster-admin. Loading
    them would hand an agent ~130 tools that each fail with an opaque 401 on
    first use. Absent is better than present-and-broken — an agent cannot
    misroute to a tool it never sees.
    """
    filtered: list[Tool] = []
    for t in raw_tools:
        if t.name in DISABLED_TOOLS:
            continue
        if _GATING and not deployment.tool_is_available(t.name, _DEPLOYMENT_MODE):
            continue
        if READ_ONLY_MODE:
            if not _is_read_only(t) and t.name not in _ALWAYS_LOADED_IN_READ_ONLY:
                continue
        filtered.append(_with_control_fields(t))
    return filtered


def _with_control_fields(tool: Tool) -> Tool:
    """Delegates to mcp_compat so the console advertises the identical surface.

    This lived here only, which is how the console came to serve raw schemas with
    neither dry_run nor correlation_id on them.
    """
    return mcp_compat.with_control_fields(
        tool,
        read_only=_is_read_only(tool),
        always_loaded=_ALWAYS_LOADED_IN_READ_ONLY,
        needs_confirm=tool.name in _CONFIRMATION_REQUIRED,
    )


def _is_write_tool(t: Tool) -> bool:
    """A tool is write-side unless it is explicitly annotated read-only.

    Unannotated tools count as writes (unknown intent -> stronger gate). This is
    the same classification the read-only filter and the scope gate use.
    """
    return not mcp_compat.is_read_only(t)


# Default confirmation set: EVERY write tool (decision: admin operations are
# gated by default, not only the destructive subset). Built from _RAW_TOOLS, not
# the read-only-filtered _TOOLS, so the gate is correct whenever writes are
# enabled (CB_ADMIN_READ_ONLY_MODE=false). An operator loosens this per-tool via
# CB_ADMIN_CONFIRMATION_REQUIRED_TOOLS or, for automation, by issuing an
# automation-scoped token (see the ceiling below).
#
# Defined BEFORE _filter_tools runs, because the schema injector now advertises
# `confirm` on exactly these tools.
_DEFAULT_CONFIRMATION = {t.name for t in _RAW_TOOLS if _is_write_tool(t)}
_CONFIRMATION_REQUIRED: set[str] = get_confirmation_required(_DEFAULT_CONFIRMATION)

# Before filtering, and therefore before any schema is rewritten: this records which tools
# implement dry_run themselves, which is a question the raw schemas can answer and the
# injected ones cannot.
dryrun.register_handler_owned(_RAW_TOOLS)

_TOOLS: list[Tool] = _filter_tools(_RAW_TOOLS)


def _parse_tool_set(env_var: str) -> set[str]:
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return set()
    return {name.strip() for name in raw.split(",") if name.strip()}


# ── Hard automation ceiling ──────────────────────────────────────────────────
#
# Tools in this set ALWAYS require a per-call human confirmation, even for an
# automation-scoped principal. This is the control that makes automation mode
# safe: a workflow/child agent can create buckets and deploy functions
# unattended, but operations listed here (e.g. failover, node removal, dropping
# a production bucket) still stop for a human.
#
# CRITICAL: this set is configured on the SERVER, at deploy time, by a human.
# No token scope, tool argument, or client-supplied value can remove a tool from
# it. The automated caller provably cannot bypass it. Set a strict list on
# production clusters; it ships EMPTY so a developer's own cluster is friction-
# free out of the box. See README "Automation and the hard ceiling".
_AUTOMATION_HARD_CEILING: set[str] = _parse_tool_set("CB_ADMIN_ALWAYS_CONFIRM")

# A ceiling entry that matches no real tool protects nothing while reading in the
# config as though it does. Names are case-sensitive, so a typo silently produced
# an empty-effect ceiling with no complaint at startup.
_CEILING_UNKNOWN: set[str] = _AUTOMATION_HARD_CEILING - {t.name for t in _RAW_TOOLS}


# ── MCP server ───────────────────────────────────────────────────────────────

#: This server's version, mirrored from pyproject.toml. tests/test_packaging.py asserts
#: the two agree, so the mirror cannot drift silently.
#:
#: 1.0.0 rather than 0.x: the tool surface is stable, the security model is
#: documented and measured, and it is published. A 0.x number on a server that
#: administers production infrastructure understates what a reader is being asked to
#: trust, and 0.x also licenses breaking changes that this tool should not be making
#: casually -- every tool name here is a published interface.
__version__ = "1.0.0"


def _server_version() -> str:
    """What `initialize` reports as serverInfo.version.

    Passed EXPLICITLY because the mcp SDK's fallback is `version("mcp")` -- the version of
    the LIBRARY. So every client's connection panel showed this server as "1.27.0" or
    "1.29.0" depending on which mcp happened to be resolved, and a support question that
    starts "which build are you running?" was unanswerable from the protocol. Verified over
    real stdio before the fix: serverInfo said 1.27.0 while pyproject said 0.1.0.

    Prefers the INSTALLED distribution's metadata so a wheel or image reports what was
    actually deployed, and falls back to the mirrored constant when running from a source
    tree with nothing installed.
    """
    try:
        from importlib.metadata import version

        return version("couchbase-admin-mcp-server")
    except Exception:
        return __version__


app = Server("couchbase-admin-mcp", version=_server_version())


@app.list_tools()
async def list_tools() -> list[Tool]:
    """Advertise the tool surface — to an AUTHORIZED caller only.

    This had no authorization check at all. On the HTTP transport with
    CB_ADMIN_HTTP_REQUIRE_AUTH not strictly true (including the `=on` spelling the edge
    middleware failed to recognise), any client that completed the MCP handshake got a
    full inventory: every tool name, every argument schema, and by omission the
    deployment mode and read-only posture. That is a reconnaissance primitive, and it
    is also the natural place for an attacker to start.

    Resolved off the event loop for the same reason the dispatch is: validation can
    reach the IdP.
    """
    if not _auth_required_for_listing():
        return _TOOLS

    claims = await asyncio.to_thread(current_claims)
    if claims is None:
        _log.warning("tool listing refused: no validated token")
        audit.emit_auth_failure(
            reason="list_tools with no validated token",
            source=request_auth.request_source(),
        )
        return []

    # SCOPED TO THE PRINCIPAL, through the same function that decides the call.
    #
    # Authentication was already enforced above; this is authorization, and until
    # now the listing had none. A validated reader token was handed all 146 loaded
    # tools -- every write tool, every argument schema -- and found out only at
    # invocation that it held none of them. MEASURED 2026-09-15 against a real
    # Keycloak reader token.
    #
    # Nothing escalated: the gate refused the call. What leaked was the deployment's
    # posture -- which tools are loaded, that writes are enabled at all, what
    # arguments they take -- to whoever holds the weakest credential in the tenant,
    # which is also the credential most widely handed out. Least privilege says a
    # principal is not given a catalog it cannot use.
    #
    # denial_for() rather than a filter written here: a second classifier would
    # eventually disagree with the gate, and the disagreement has two shapes. A tool
    # advertised then refused is merely confusing. A tool OMITTED from the listing
    # that the gate would still allow by name is a control that looks enforced and
    # is not -- the listing is not a security boundary, the gate is, and the listing
    # must never be mistaken for one. Sharing the function makes them one decision.
    #
    # Claims are resolved once, above, and passed in: resolution can reach the IdP
    # on a cache miss, which is why it happens off the event loop, and doing that
    # per tool across the catalog would be both slow and pointless.
    return [tool for tool in _TOOLS if denial_for(tool, claims) is None]


def _auth_required_for_listing() -> bool:
    """Whether tool enumeration requires a token.

    Only on HTTP: stdio has no token by design, and returning an empty list there
    would make the server useless in the workstation profile.
    """
    return env_truthy("CB_ADMIN_HTTP_REQUIRE_AUTH") and request_auth.transport_is_http()


def _classify_result(result: object) -> tuple[str, str]:
    """Delegates to audit.classify_result so both dispatch paths share one policy.

    This logic lived here only, which is why the console's refusal vocabulary drifted.
    """
    return audit.classify_result(result, shared.ERROR_MARKER)


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    arguments = dict(arguments or {})

    # Capture the caller-supplied correlation id BEFORE any decision path runs.
    # This is the thread that ties "a human pushed a commit" to "a child agent
    # created this bucket forty seconds later": the workflow manager passes its run
    # id down, and every record from the resulting fan-out carries it. It was
    # documented, plumbed through audit.build_record, advertised in the tool schemas
    # — and never actually read here, so every enterprise record was untraceable
    # back to the originating human action. It is provenance only: sanitised, never
    # consulted for authorization, and stripped before the handler sees it.
    _correlation = audit.sanitize_correlation(arguments.get(audit.CORRELATION_ARG))

    # Every tool call is logged here — one central point, so "every tool goes
    # through logging" is a property of the dispatch, not something each handler
    # has to remember. Arguments are redacted so credentials in, e.g.,
    # admin_user_create never reach the logs.
    # One audit record per decision, structured, carrying WHO / WHY / provenance.
    #
    # The previous line recorded the tool and its arguments and nothing else — no
    # principal, no indication whether the call ran unattended, and no way to reach
    # the human whose action set the workflow going. In the enterprise flow the
    # service principal is the only identity that exists, so if it is absent from
    # the record then "who created this bucket" has no answer at all.
    # Resolved in a worker thread, not on the event loop.
    #
    # current_claims() can reach oidc.validate_token(), which on a cache miss makes an
    # OUTBOUND HTTPS call to the IdP's JWKS endpoint. Awaiting nothing while that
    # blocks means one slow or unreachable IdP stalls the entire server for every
    # connected client, not just the caller whose token needed validating.
    #
    # asyncio.to_thread copies the current context into the worker, so request_ctx —
    # the thing that makes HTTP authorization work at all — is still visible there.
    # That is load-bearing and is why this is to_thread rather than run_in_executor.
    _claims = await asyncio.to_thread(current_claims)
    _principal = principal_of(_claims) if _claims else None
    if _principal is None and profile_config.PROFILE_NAME == profile_config.WORKSTATION:
        # No IdP on a laptop, but "who did what" must still resolve. Attribution,
        # not authentication — spoofable by whoever runs the process, recorded on
        # that understanding.
        _principal = {
            "auth": "local",
            "automation": False,
            **profile_config.local_identity(),
        }

    def _audit(
        decision: str, reason: str = "", duration_ms: float | None = None
    ) -> None:
        audit.emit_tool_call(
            tool=name,
            arguments=arguments,
            decision=decision,
            principal=_principal,
            reason=reason,
            duration_ms=duration_ms,
            source=request_auth.request_source(),
            correlation_id=_correlation,
        )

    handler = _HANDLERS.get(name)
    if handler is None:
        _log.warning("unknown tool: %s", name)
        _audit("denied_unknown_tool", reason="no handler registered")
        return err(
            f"Unknown tool: {name}", tool=name, hint="Tool may be disabled or unloaded."
        )

    # Tool must also be in the currently exposed list.
    if name not in {t.name for t in _TOOLS}:
        _log.warning("tool not enabled in current config: %s", name)
        # Deployment gating is the most likely and least obvious reason, so name
        # it specifically and point at the working alternative rather than
        # listing every possible cause.
        if _GATING and not deployment.tool_is_available(name, _DEPLOYMENT_MODE):
            _audit(
                "denied_deployment",
                reason=f"not available in {_DEPLOYMENT_MODE!r} deployment mode",
            )
            return err(
                f"Tool {name} is not available in {_DEPLOYMENT_MODE!r} deployment mode.",
                tool=name,
                hint=deployment.unavailable_reason(name, _DEPLOYMENT_MODE),
                deployment_mode=_DEPLOYMENT_MODE,
            )
        _audit(
            "denied_read_only",
            reason="tool not loaded (read-only mode or CB_ADMIN_DISABLED_TOOLS)",
        )
        return err(
            f"Tool {name} is not enabled in this server configuration.",
            tool=name,
            hint=(
                "It may be unloaded because CB_ADMIN_READ_ONLY_MODE=true or it "
                "appears in CB_ADMIN_DISABLED_TOOLS."
            ),
        )

    # Per-tool OAuth scope enforcement. No-op on stdio / when OAuth is not
    # configured (no token in context). On authenticated HTTP the token's
    # scopes must satisfy the tool's required scope, classified the same way
    # the read-only filter classifies load eligibility.
    tool_obj = next((t for t in _TOOLS if t.name == name), None)
    if tool_obj is not None:
        denial = check_scope(tool_obj)
        if denial:
            _log.warning("scope denied for %s", name)
            _audit("denied_scope", reason=denial)
            return err(denial, tool=name, hint="Token is missing the required scope.")

    # Confirmation gate.
    #
    # A tool needs confirmation if it is in the confirmation set. An automation-
    # scoped principal skips the per-call human confirmation for ordinary gated
    # writes — the human authorization happened once, at credential issuance.
    # BUT the hard ceiling (CB_ADMIN_ALWAYS_CONFIRM) is never skipped: those
    # tools require a human even for automation, and nothing the caller controls
    # can change that.
    in_confirm_set = name in _CONFIRMATION_REQUIRED

    # ── The hard ceiling and the automation path ─────────────────────────────
    #
    # Both now live in authz.evaluate(), which the GUI's POST /api/call also calls.
    # Expressing this policy twice is what let the GUI copy drift: its ceiling check
    # sat inside `if in_confirm_set and automation_mode`, so with automation off a
    # ceiling tool fell through to a caller-supplied `confirm: true`.
    #
    # The ceiling is unconditional and evaluated before anything else. It used to be
    # gated on session_has_automation_scope(), which inverted the privilege model: a
    # principal holding write but NOT automation skipped the ceiling entirely, so
    # dropping a scope from the token GRANTED capability and the most privileged
    # principal was the only one refused.
    # Resolved ONCE and passed explicitly, then re-used below to establish the
    # caller context around the handler. Previously evaluate() derived it internally
    # and nothing downstream could see what had been decided, which is how the
    # composite ceiling guard came to answer the same question differently.
    human_present = authz.human_is_present()
    ceiling, in_confirm_set = authz.evaluate(
        name,
        in_confirm_set=in_confirm_set,
        has_automation_scope=session_has_automation_scope(),
        human_present=human_present,
    )
    if not ceiling.allowed:
        _log.warning("hard ceiling refused %s (no human present)", name)
        _audit(ceiling.decision, reason="hard ceiling; no human present")
        return err(ceiling.reason, tool=name, args=arguments, **ceiling.detail)

    msg = require_confirmation(name, arguments, in_confirm_set)
    if msg:
        _log.info("confirmation required for %s; call withheld", name)
        _audit("denied_confirmation", reason=msg)
        return err(msg, tool=name, args=arguments, requires_confirmation=True)

    # Strip both caller-supplied control fields so neither reaches a REST/SDK call
    # as a stray parameter. correlation_id is provenance for the audit record only
    # — it must never influence a decision, and it has already been captured above.
    arguments.pop("confirm", None)
    arguments.pop(audit.CORRELATION_ARG, None)

    # ── Dry run ──────────────────────────────────────────────────────────────
    #
    # AFTER every gate, deliberately. A dry run is not a way to find out what a tool you
    # are not allowed to call would do, so the scope gate, the ceiling and the
    # confirmation gate all have their say first. And BEFORE execution, obviously.
    #
    # Reads still run: refusing them would remove the information the plan is checked
    # against. Only a write is withheld.
    dry, dry_reason = dryrun.in_effect(arguments, tool_obj)
    read_side = bool(tool_obj is not None and scope_gate_is_read_side(tool_obj))
    # Only strip the flag the DISPATCH owns. This was unconditional, so a tool that
    # implements dry_run itself never received it: in_effect() correctly returns
    # False for a handler-owned tool, and then the argument was removed anyway, so
    # the handler fell back to its own default. capella_env_reap defaults dry_run to
    # TRUE by design, which made every reap a preview and left expired environments
    # billing forever -- the tool could not perform its only job. The strip still
    # matters for every other tool, where the flag must not reach a REST body.
    if not dryrun.handler_owns(tool_obj):
        dryrun.strip(arguments)
    if dry and not read_side:
        _log.info("dry run: %s withheld (%s)", name, dry_reason)
        _audit("dry_run", reason=dry_reason)
        # ok() so it is a SUCCESS payload in the transport's shape, not a dict. The
        # dispatch contract is list[TextContent]; returning a bare dict here type-checked
        # fine and broke every client, which is what the tests caught.
        return shared.ok(
            dryrun.preview(
                name,
                arguments,
                reason=dry_reason,
                deployment_mode=_DEPLOYMENT_MODE,
                read_side=False,
            )
        )

    loop = asyncio.get_event_loop()
    start = time.perf_counter()
    try:
        # Wrapped so anything below the dispatch that asks authz.human_is_present()
        # gets THIS call's evidence rather than re-deriving it from a process-wide
        # variable. Established inside the executor thread, because the context is
        # thread-local and run_in_executor does not propagate it across the hop.
        def _run_handler() -> list[TextContent]:
            with authz.caller_context(human_present=human_present):
                return handler.handle(name, arguments)

        result = await loop.run_in_executor(None, _run_handler)
        elapsed = (time.perf_counter() - start) * 1000

        # A handler that refuses (egress allowlist, Capella guardrail, a validation
        # error) catches its own exception and returns a normal err() payload, so the
        # dispatch used to record decision="allowed" for an operation that never
        # happened — making a refused log-bundle exfiltration indistinguishable from a
        # successful bucket delete, and mislabelling it as the wrong one.
        decision, reason = _classify_result(result)
        _audit(decision, reason=reason, duration_ms=elapsed)
        _log.info("tool %s: %s (%.1f ms)", decision, name, elapsed)
        return result
    except Exception as exc:
        # exc_info=True writes the traceback to the error log — the record
        # Couchbase support asks a customer to send.
        elapsed = (time.perf_counter() - start) * 1000
        _audit("error", reason=f"{type(exc).__name__}", duration_ms=elapsed)
        _log.error("tool error: %s: %s (%.1f ms)", name, exc, elapsed, exc_info=True)
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=arguments)


# ── The protocol-level isError flag ──────────────────────────────────────────
#
# Every refusal this server makes -- unknown tool, scope denial, read-only mode,
# missing confirmation, spend ceiling, egress allowlist -- was reported to the client
# as `isError: false`, i.e. as a SUCCESSFUL tool call whose text happened to describe a
# failure. Verified over real stdio: `tools/call` for a tool that does not exist came
# back `{"content": [...], "isError": false}`.
#
# The cause is structural rather than an oversight in any one handler. The mcp lowlevel
# server sets isError=False on every result whose handler returned content, and reserves
# True for a raised exception. This server's whole design is the opposite: a refusal is a
# normal, structured, audited return value, never an exception -- which is what keeps the
# reason machine-readable and the audit record accurate. So the flag could never become
# True on its own.
#
# It matters for the non-conversational caller. An agent reads the text and understands
# it; a script, a workflow step, or a UI that branches on isError -- the field the
# protocol defines for exactly that -- saw success for a destructive operation that was
# denied. That is the wrong direction for a control to fail in.
#
# Done HERE, at the wire boundary, on purpose:
#   * call_tool above keeps returning list[TextContent], so the operator console, the
#     tests and every internal caller are untouched. Only the JSON-RPC reply changes.
#   * No branch on the mcp version. Wrapping the registered request handler and adjusting
#     the CallToolResult it produced works the same on 1.10 and on 2.x, whereas RETURNING
#     a CallToolResult from the handler is only recognised by newer 1.x -- on the declared
#     floor it would be treated as an iterable of pydantic field pairs and produce
#     nonsense. Same reasoning as mcp_compat.py: ask what the object has, don't decide
#     from a version number.
#   * The marker is the one audit.classify_result already uses, so the flag and the audit
#     record cannot disagree about whether a call was refused.


def _registered_call_tool_handler(registry: dict):
    """The handler the mcp decorator just registered, or a message that says what broke.

    A bare `registry[CallToolRequest]` would raise KeyError at import time on an mcp
    release that reorganises the registry, and "KeyError: CallToolRequest" three frames
    into a module body is a poor way to learn that the server cannot start. Since a
    missing key means this wrapper cannot be installed and the isError flag would go back
    to reporting every refusal as a success, it fails loudly rather than skipping itself.
    """
    handler = registry.get(CallToolRequest)
    if handler is None:
        raise RuntimeError(
            "the installed mcp did not register a CallToolRequest handler, so the "
            "protocol-level isError flag cannot be set. Check the mcp version against "
            "the pin in pyproject.toml (>=1.10,<2.0)."
        )
    return handler


_sdk_call_tool_handler = _registered_call_tool_handler(app.request_handlers)


def _carries_error_marker(content: object) -> bool:
    """True when a result block is an err() payload.

    Reads shared.ERROR_MARKER, the same discriminator the audit classifier uses, and only
    that: several handlers return a SUCCESS payload containing a top-level "error" that
    describes a sub-resource problem, and treating those as failures would mislabel a
    partially-successful batch as a denial.
    """
    for block in content or []:
        text = getattr(block, "text", None)
        if not isinstance(text, str):
            continue
        try:
            payload = json.loads(text)
        except (ValueError, TypeError):
            continue
        if isinstance(payload, dict) and payload.get(shared.ERROR_MARKER) is True:
            return True
    return False


async def _call_tool_with_is_error(req: CallToolRequest):
    """Set isError on the protocol result to match what the handler actually decided."""
    server_result = await _sdk_call_tool_handler(req)
    result = getattr(server_result, "root", None)
    if result is None or getattr(result, "isError", None) is not False:
        # Already an error (input validation, an unexpected exception) or a shape this
        # wrapper does not recognise. Left exactly as the SDK produced it.
        return server_result
    if not _carries_error_marker(getattr(result, "content", None)):
        return server_result
    # model_copy rather than assignment: pydantic models in this position are validated
    # on assignment in some versions, and a copy cannot half-apply.
    return type(server_result)(result.model_copy(update={"isError": True}))


app.request_handlers[CallToolRequest] = _call_tool_with_is_error


# ── Startup banner ───────────────────────────────────────────────────────────


def _enforce_profile() -> None:
    """Refuse to start on a posture that cannot be secure in the stated profile.

    These are the exact pairings that produced real findings, so they are checked
    rather than left in documentation. Failing at startup is the cheap place to
    discover them.
    """
    problems = list(profile_config.PROFILE_ERRORS)

    # An audit sink that was ASKED FOR and cannot be opened is fatal. Deferring this
    # to a log line meant the operator's only signal was a message in the very log
    # they had been told to replace with the audit file.
    sink_problem = audit.audit_sink_error()
    if sink_problem:
        problems.append(sink_problem)

    # One container, one control plane. A deployment that DECLARES its surface
    # must get that surface: `detect_mode()` infers, and the inference that
    # matters resolves to 'both' -- which switches capability gating off -- the
    # moment a Capella key and any non-Capella connection string are both
    # present. That happens by inheriting an env file, not by decision.
    mode_problem = deployment.declared_mode_error(_DEPLOYMENT_MODE)
    if mode_problem:
        problems.append(mode_problem)

    # Transport encryption. A non-loopback HTTP bind with neither a certificate nor an
    # explicit "something in front handles it" is fatal: cleartext bearer tokens are
    # the one exposure that defeats every other control at once, and the two situations
    # are indistinguishable from inside the process.
    problems.extend(
        tls_config.validate(
            os.environ.get("CB_ADMIN_HOST", "127.0.0.1"),
            os.environ.get("CB_ADMIN_TRANSPORT", "stdio").lower(),
        )
    )

    if not problems:
        return
    print(
        "[couchbase-admin-mcp] REFUSING TO START — incoherent security posture for "
        f"CB_ADMIN_PROFILE={profile_config.PROFILE_NAME}:",
        file=sys.stderr,
        flush=True,
    )
    for problem in problems:
        print(f"  * {problem}", file=sys.stderr, flush=True)
    raise SystemExit(2)


def _startup_banner() -> None:
    # Footgun guard: OIDC configured but enforcement not required means invalid
    # tokens are silently ignored on HTTP. Warn so it is a conscious choice.
    if os.environ.get("OAUTH_ISSUER", "").strip() and not env_truthy(
        "CB_ADMIN_HTTP_REQUIRE_AUTH"
    ):
        print(
            "[couchbase-admin-mcp] WARNING: OAUTH_ISSUER is set but "
            "CB_ADMIN_HTTP_REQUIRE_AUTH is not true -- invalid/missing Bearer "
            "tokens on the HTTP transport are ignored (no enforcement). Set "
            "CB_ADMIN_HTTP_REQUIRE_AUTH=true to enforce.",
            file=sys.stderr,
            flush=True,
        )
    if env_truthy("OAUTH_SKIP_VERIFY"):
        print(
            "[couchbase-admin-mcp] *** OAUTH_SKIP_VERIFY IS ENABLED *** JWT "
            "signatures, issuer, audience and expiry are NOT verified. Any token is "
            "accepted. This must never be set outside loopback development.",
            file=sys.stderr,
            flush=True,
        )
    if _CEILING_UNKNOWN:
        print(
            "[couchbase-admin-mcp] WARNING: CB_ADMIN_ALWAYS_CONFIRM names "
            f"{sorted(_CEILING_UNKNOWN)}, which match no loaded tool — those "
            "entries protect nothing. Tool names are case-sensitive.",
            file=sys.stderr,
            flush=True,
        )
    msg = (
        f"[couchbase-admin-mcp] profile: {profile_config.describe(profile_config.PROFILE_NAME)}\n"
        f"[couchbase-admin-mcp] deployment: {deployment.describe(_DEPLOYMENT_MODE)}\n"
        f"[couchbase-admin-mcp] tools loaded: {len(_TOOLS)} of {len(_RAW_TOOLS)} "
        f"(read_only={READ_ONLY_MODE}, disabled={len(DISABLED_TOOLS)}, "
        f"confirmation_required={len(_CONFIRMATION_REQUIRED)})"
    )

    # In Capella mode, surface the guardrail posture at startup. An operator who
    # has enabled writes but not set an allowlist should learn that here, not on
    # the first refused teardown.
    if _DEPLOYMENT_MODE in (deployment.CAPELLA, deployment.BOTH) and not READ_ONLY_MODE:
        try:
            from handlers.capella import guardrails as _guardrails

            posture = _guardrails.describe_policy()
            msg += (
                f"\n[couchbase-admin-mcp] capella guardrails: {posture['posture']}; "
                f"projects={posture['allowed_projects'] or 'NONE'}; "
                f"prefix={posture['name_prefix'] or 'NONE'}; "
                f"ceiling={posture['max_environments']}"
            )
            if not posture["destructive_operations_enabled"]:
                msg += (
                    "\n[couchbase-admin-mcp] NOTE: Capella destructive operations "
                    "are refused because CAPELLA_ALLOWED_PROJECTS is unset "
                    "(fail-closed). Teardown and reap will not run until a "
                    "sandbox project list is configured."
                )
            # A guardrail that is configured but inert is the dangerous case: the
            # config reads as protective while enforcing nothing. Say so at boot.
            for warning in posture.get("warnings", []):
                msg += f"\n[couchbase-admin-mcp] WARNING: {warning}"
        except Exception as exc:  # never let a banner break startup
            print(
                f"[couchbase-admin-mcp] could not read Capella guardrail policy: {exc}",
                file=sys.stderr,
            )
    # Banner goes to stderr so it does not pollute stdio MCP framing.
    print(msg, file=sys.stderr, flush=True)


# ── Transport selection ──────────────────────────────────────────────────────


async def _main_stdio() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


class _ScopeAuthMiddleware:
    """ASGI edge check: reject a bad credential before it reaches the dispatch loop.

    NOT the authorization mechanism. It used to be, by validating the token here
    and stashing the claims in a contextvar — which could never work, because tool
    dispatch runs in a sibling task that snapshotted the contextvar before any
    request existed. Authorization now happens inside the dispatch task, resolving
    the principal from the request itself (auth/request_auth.py).

    What remains here is worth keeping: a malformed or expired token is turned away
    cheaply with a 401 instead of travelling further, and the auth-failure audit
    record is emitted with the client address, which the dispatch layer cannot see
    for a request it never receives.
    """

    def __init__(self, app):
        self.app = app
        # env_truthy, not a local spelling list: this site accepted "1/true/yes" while
        # five others also accepted "on", so CB_ADMIN_HTTP_REQUIRE_AUTH=on disabled the
        # edge 401 while leaving deeper checks on — and list_tools, which has no
        # authorization check of its own, then served the whole admin surface
        # unauthenticated.
        self._require = env_truthy("CB_ADMIN_HTTP_REQUIRE_AUTH")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        token = None
        for k, v in scope.get("headers", []):
            if k == b"authorization":
                val = v.decode("latin-1")
                if val.lower().startswith("bearer "):
                    token = val[7:].strip()
                break

        if token:
            try:
                from auth import oidc as _oidc

                # Result deliberately discarded: this is a validity check at the
                # edge, not the authorization decision. The dispatch task
                # re-resolves the claims from the request (and caches them), which
                # is the only place they are actually visible.
                #
                # OFF THE EVENT LOOP. validate_token performs a blocking JWKS fetch
                # (urllib) on a cache miss, and PyJWT re-fetches unconditionally for
                # an unknown `kid` — which is attacker-controlled, read from the
                # UNVERIFIED header. Calling it inline let one request per second,
                # each with a random kid, stall the single event loop for up to 30s
                # and hammer the customer's IdP from a trusted source IP.
                await asyncio.to_thread(_oidc.validate_token, token)
            except Exception as exc:  # invalid/expired/malformed -- never log token
                # ALWAYS 401 on a token that was presented and failed validation.
                # Previously, with CB_ADMIN_HTTP_REQUIRE_AUTH unset (the default),
                # a forged or expired token was discarded and the request then
                # proceeded as "anonymous" — which meant enforcement disabled. A
                # bad credential must be a rejection, never a downgrade.
                client = scope.get("client")
                source = f"{client[0]}:{client[1]}" if client else ""
                _log.warning("rejected bearer token: %s", type(exc).__name__)
                audit.emit_auth_failure(
                    reason=f"invalid token: {type(exc).__name__}", source=source
                )
                await _send_401(send, f"Invalid token: {type(exc).__name__}")
                return
        elif self._require:
            client = scope.get("client")
            audit.emit_auth_failure(
                reason="missing bearer token",
                source=f"{client[0]}:{client[1]}" if client else "",
            )
            await _send_401(send, "Missing Bearer token")
            return

        # Deliberately NOT set_token_claims(claims): that contextvar is invisible
        # to the dispatch task, and relying on it is the bug this replaces. The
        # dispatch layer re-resolves (and caches) the claims from the request.
        await self.app(scope, receive, send)


async def _send_401(send, detail: str) -> None:
    # json.dumps, not interpolation: `detail` is one careless edit away from
    # carrying exception text that could contain quotes or a token fragment.
    body = json.dumps({"error": "unauthorized", "detail": detail}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"www-authenticate", b"Bearer"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _allowed_origins() -> list[str]:
    """Origins permitted to drive this server from a browser.

    Without an allowlist a page on the operator's machine can drive a
    loopback-bound server (DNS-rebinding / CSRF against 127.0.0.1). The MCP
    Streamable-HTTP spec requires Origin validation for exactly this reason.
    """
    raw = (os.environ.get("CB_ADMIN_ALLOWED_ORIGINS") or "").strip()
    if not raw:
        return []
    return [o.strip() for o in raw.split(",") if o.strip()]


def _allowed_hosts(host: str, port: int) -> list[str]:
    """Host header values this server will answer to.

    DNS-rebinding protection compares the request's Host header against this list, so
    it has to contain the names clients actually use — not just the bind address.

    The derived list alone broke every non-loopback deployment. Behind a Kubernetes
    Service or an ingress the bind is 0.0.0.0 while the Host header is
    `cb-mcp.example.internal`, which matched nothing, so the transport answered 421
    Misdirected Request to every request and the server was unreachable rather than
    insecure. Silently widening the list to fix that would have thrown away the
    protection, so the external names are an explicit operator statement instead.
    """
    derived = [
        f"{host}:{port}",
        host,
        f"localhost:{port}",
        "localhost",
        f"127.0.0.1:{port}",
        "127.0.0.1",
    ]
    raw = (os.environ.get("CB_ADMIN_ALLOWED_HOSTS") or "").strip()
    extra: list[str] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        extra.append(entry)
        # An operator naming a hostname almost never means "only without a port".
        if ":" not in entry:
            extra.append(f"{entry}:{port}")

    # A wildcard bind tells us nothing about the name clients will use, so if the
    # operator has not said, the failure mode is 421 on every request. Say why here
    # rather than leaving them to find it in a proxy log.
    if host in ("0.0.0.0", "::", "") and not extra:
        print(
            "[couchbase-admin-mcp] WARNING: bound to a wildcard address with no "
            "CB_ADMIN_ALLOWED_HOSTS set. DNS-rebinding protection will reject any "
            "request whose Host header is not localhost/127.0.0.1 with HTTP 421. If "
            "clients reach this server by a hostname or a Service name, list it in "
            "CB_ADMIN_ALLOWED_HOSTS (comma-separated).",
            file=sys.stderr,
            flush=True,
        )

    seen: dict[str, None] = {}
    for value in derived + extra:
        if value:
            seen.setdefault(value, None)
    return list(seen)


async def _main_http() -> None:
    """Streamable HTTP transport, with per-client sessions.

    THREE CHANGES FROM THE PREVIOUS IMPLEMENTATION, all load-bearing:

    1. StreamableHTTPSessionManager instead of a single
       StreamableHTTPServerTransport(mcp_session_id=None). One transport with a
       null session id meant ONE MCP session shared by every HTTP client, with no
       session binding at all — any client could POST to /mcp with no
       Mcp-Session-Id and land in the same session as everyone else. There was no
       notion of "this tool call belongs to that authenticated request", which is
       why the authorization bug had no local fix. The manager gives each client
       its own session and its own generated id.

    2. Authorization is resolved from the request inside the dispatch task (see
       auth/request_auth.py), not carried across tasks in a contextvar. That is
       what actually makes the scope model — and therefore the automation trust
       model — work over HTTP.

    3. Origin validation via the SDK's TransportSecuritySettings, plus a
       refusal to bind a non-loopback address without authentication.
    """
    try:
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    except ImportError:
        print(
            "[couchbase-admin-mcp] Streamable HTTP transport requires mcp>=1.10. "
            "Falling back to stdio.",
            file=sys.stderr,
        )
        await _main_stdio()
        return

    host = os.environ.get("CB_ADMIN_HOST", "127.0.0.1")
    port = int(os.environ.get("CB_ADMIN_PORT", "8000"))
    require_auth = os.environ.get(
        "CB_ADMIN_HTTP_REQUIRE_AUTH", "false"
    ).strip().lower() in ("1", "true", "yes", "on")

    # Refuse to expose an unauthenticated admin surface on a network interface.
    # The GUI already had this guard; the MCP HTTP server did not, while both the
    # README and the Dockerfile instruct operators to set CB_ADMIN_HOST=0.0.0.0.
    if host not in ("127.0.0.1", "localhost", "::1") and not require_auth:
        print(
            f"[couchbase-admin-mcp] REFUSING TO START: binding {host}:{port} with "
            "CB_ADMIN_HTTP_REQUIRE_AUTH disabled would expose the full admin tool "
            "surface unauthenticated. Set CB_ADMIN_HTTP_REQUIRE_AUTH=true (with "
            "OAUTH_ISSUER/OAUTH_AUDIENCE), or bind 127.0.0.1.",
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(2)

    try:
        import uvicorn  # type: ignore
        from starlette.applications import Starlette
        from starlette.middleware import Middleware
        from starlette.routing import Mount
    except ImportError as exc:
        print(
            f"[couchbase-admin-mcp] HTTP transport requires uvicorn and starlette: "
            f"{exc}. Install: pip install uvicorn starlette. Falling back to stdio.",
            file=sys.stderr,
        )
        await _main_stdio()
        return

    security_settings = None
    origins = _allowed_origins()
    try:
        from mcp.server.transport_security import TransportSecuritySettings

        # allowed_origins is typed list[str] with default [] — NOT optional. Passing
        # None raised a pydantic ValidationError which the bare `except Exception`
        # swallowed, leaving security_settings None and DNS-rebinding protection OFF
        # on every default deployment, while telling the operator to upgrade mcp.
        security_settings = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_origins=origins,
            allowed_hosts=_allowed_hosts(host, port),
        )
    except ImportError:
        # Older SDKs lack the module. Say so rather than silently serving without
        # Origin validation.
        print(
            "[couchbase-admin-mcp] WARNING: this mcp version has no "
            "TransportSecuritySettings, so Origin/Host validation is unavailable. "
            "A browser page could drive a loopback-bound server. Upgrade mcp.",
            file=sys.stderr,
            flush=True,
        )

    manager = StreamableHTTPSessionManager(
        app=app,
        json_response=False,
        stateless=False,
        security_settings=security_settings,
    )

    _tls = tls_config.from_env()
    print(
        f"[couchbase-admin-mcp] HTTP transport on "
        f"{'https' if _tls.direct else 'http'}://{host}:{port}/mcp "
        f"(auth_required={require_auth}, per-client sessions, "
        f"tls={_tls.describe()}, "
        f"allowed_origins={origins or 'none configured'})",
        file=sys.stderr,
        flush=True,
    )

    # Both "/mcp" and "/mcp/" must work. Starlette's default redirect_slashes
    # answers a POST to "/mcp" with a 307 to "/mcp/", and MCP clients do not
    # follow it — so a client configured with the documented URL got a redirect
    # instead of a session. Verified by driving a real handshake against both.
    async def _mcp_endpoint(scope, receive, send):
        """Serve the MCP endpoint at both /mcp and /mcp/.

        Explicit rather than left to router behaviour, because neither default was
        acceptable and this was verified against a real client handshake:

          * With Starlette's default redirect_slashes, a POST to "/mcp" is answered
            with a 307 to "/mcp/". MCP clients do not follow it, so a client
            configured with the documented URL got a redirect instead of a session.
          * With redirect_slashes disabled, Mount("/mcp") stops matching the bare
            path at all and "/mcp" becomes a 404.

        Normalising here means the documented URL works, with or without the
        trailing slash, and the behaviour does not depend on a Starlette internal.
        """
        path = scope.get("path", "")
        if path.rstrip("/") in ("/mcp", ""):
            await manager.handle_request(scope, receive, send)
            return
        await send(
            {
                "type": "http.response.start",
                "status": 404,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": json.dumps(
                    {"error": "not_found", "detail": "MCP endpoint is at /mcp"}
                ).encode(),
            }
        )

    starlette_app = Starlette(
        routes=[Mount("/", app=_mcp_endpoint)],
        # Edge rejection only. Authorization itself happens in the dispatch task;
        # this exists to turn away a bad credential cheaply and to record the
        # auth-failure audit event.
        middleware=[Middleware(_ScopeAuthMiddleware)],
    )
    # TLS, when this process is the one terminating it. The posture was validated at
    # startup (_enforce_profile), so reaching here means it is coherent: either a
    # certificate pair is present, or the operator has acknowledged that something in
    # front terminates TLS, or the bind is loopback.
    tls = tls_config.from_env()
    config = uvicorn.Config(
        starlette_app,
        host=host,
        port=port,
        log_level="info",
        **tls.uvicorn_kwargs(),
    )
    server = uvicorn.Server(config)

    async with manager.run():
        await server.serve()


async def _async_main() -> None:
    # Wire logging from CB_ADMIN_LOG_* before anything else, so the banner and
    # every subsequent record land in the configured sinks.
    configure_from_env()
    _enforce_profile()
    _startup_banner()
    transport = os.environ.get("CB_ADMIN_TRANSPORT", "stdio").lower()
    if transport in ("http", "streamable_http", "streamablehttp"):
        await _main_http()
    else:
        await _main_stdio()


def main() -> None:
    """Synchronous entry point used by the `couchbase-admin-mcp-server` console script
    (configured in pyproject.toml). Wraps the async runtime so pip-installed
    users get a clean CLI: `couchbase-admin-mcp-server` just works.
    """
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
