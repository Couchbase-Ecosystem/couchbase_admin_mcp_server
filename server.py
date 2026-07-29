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
                                                  admin_xdcr_conflict_log_query,
                                                  cb_perf_by_user)
  Extended   - transactions, Analytics, Backup  (cb_transaction_run,
                                                  cb_analytics_query, admin_backup_*)
  Eventing   - function lifecycle, deploy, stats (admin_eventing_*)
  Synonyms   - FTS synonym set documents (8.x)   (cb_fts_synonym_*)
  Encryption - DARE + KMIP                       (admin_encryption_*, admin_kmip_*)
  Capella v4 - SaaS control plane (read-only)    (capella_*)

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
import os
import sys
import time

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from auth.scope_gate import (
    check_scope,
    clear_token_claims,
    session_has_automation_scope,
    set_token_claims,
)
from auth.scope_gate import (
    configure as configure_scope_gate,
)
from handlers import (
    backup,
    buckets,
    capella,
    cluster,
    collections,
    diagnostics,
    eight_x,
    encryption,
    eventing,
    indexes,
    mcp_status,
    search_admin,
    security,
    stats,
    xdcr,
)
from handlers.shared import (
    DISABLED_TOOLS,
    READ_ONLY_MODE,
    err,
    get_confirmation_required,
    redact,
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
}

# Tools that stay loaded in read-only mode despite destructiveHint=true,
# internally (e.g. a query tool that rejects DML). The admin server has no such
# tools — every write here is a real control-plane mutation — so the set is empty
# and read-only mode filters strictly on the readOnlyHint annotation.
_ALWAYS_LOADED_IN_READ_ONLY: set[str] = set()

# Keep scope-gate read/write classification in lockstep with the read-only
# filter below. A read-scoped token may invoke exactly what loads in read-only.
configure_scope_gate(_ALWAYS_LOADED_IN_READ_ONLY)


def _is_read_only(t: Tool) -> bool:
    """A tool is read-only if its annotation says so."""
    return bool(t.annotations and t.annotations.readOnlyHint)


def _filter_tools(raw_tools: list[Tool]) -> list[Tool]:
    """Apply read-only mode and disabled-tools filters."""
    filtered: list[Tool] = []
    for t in raw_tools:
        if t.name in DISABLED_TOOLS:
            continue
        if READ_ONLY_MODE:
            if not _is_read_only(t) and t.name not in _ALWAYS_LOADED_IN_READ_ONLY:
                continue
        filtered.append(t)
    return filtered


_TOOLS: list[Tool] = _filter_tools(_RAW_TOOLS)


def _is_write_tool(t: Tool) -> bool:
    """A tool is write-side unless it is explicitly annotated read-only.

    Unannotated tools count as writes (unknown intent -> stronger gate). This is
    the same classification the read-only filter and the scope gate use.
    """
    return not (t.annotations and t.annotations.readOnlyHint)


# Default confirmation set: EVERY write tool (decision: admin operations are
# gated by default, not only the destructive subset). Built from _RAW_TOOLS, not
# the read-only-filtered _TOOLS, so the gate is correct whenever writes are
# enabled (CB_ADMIN_READ_ONLY_MODE=false). An operator loosens this per-tool via
# CB_ADMIN_CONFIRMATION_REQUIRED_TOOLS or, for automation, by issuing an
# automation-scoped token (see the ceiling below).
_DEFAULT_CONFIRMATION = {t.name for t in _RAW_TOOLS if _is_write_tool(t)}
_CONFIRMATION_REQUIRED: set[str] = get_confirmation_required(_DEFAULT_CONFIRMATION)


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


# ── MCP server ───────────────────────────────────────────────────────────────

app = Server("couchbase-admin-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return _TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    arguments = dict(arguments or {})

    # Every tool call is logged here — one central point, so "every tool goes
    # through logging" is a property of the dispatch, not something each handler
    # has to remember. Arguments are redacted so credentials in, e.g.,
    # admin_user_create never reach the logs.
    _log.info("tool call: %s args=%s", name, redact(arguments))

    handler = _HANDLERS.get(name)
    if handler is None:
        _log.warning("unknown tool: %s", name)
        return err(
            f"Unknown tool: {name}", tool=name, hint="Tool may be disabled or unloaded."
        )

    # Tool must also be in the currently exposed list.
    if name not in {t.name for t in _TOOLS}:
        _log.warning("tool not enabled in current config: %s", name)
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
            _log.warning("scope denied for %s: %s", name, denial)
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
    if in_confirm_set and session_has_automation_scope():
        if name in _AUTOMATION_HARD_CEILING:
            _log.info(
                "automation principal hit hard ceiling for %s; human confirmation "
                "still required",
                name,
            )
        else:
            _log.info(
                "automation principal authorized for %s; per-call confirmation skipped",
                name,
            )
            in_confirm_set = False

    msg = require_confirmation(name, arguments, in_confirm_set)
    if msg:
        _log.info("confirmation required for %s; call withheld", name)
        return err(msg, tool=name, args=arguments, requires_confirmation=True)

    # Strip the confirm key so it never reaches REST/SDK calls as a stray field.
    arguments.pop("confirm", None)

    loop = asyncio.get_event_loop()
    start = time.perf_counter()
    try:
        result = await loop.run_in_executor(None, handler.handle, name, arguments)
        _log.info("tool ok: %s (%.1f ms)", name, (time.perf_counter() - start) * 1000)
        return result
    except Exception as exc:
        # exc_info=True writes the traceback to the error log — the record
        # Couchbase support asks a customer to send.
        _log.error(
            "tool error: %s: %s (%.1f ms)",
            name,
            exc,
            (time.perf_counter() - start) * 1000,
            exc_info=True,
        )
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=arguments)


# ── Startup banner ───────────────────────────────────────────────────────────


def _startup_banner() -> None:
    # Footgun guard: OIDC configured but enforcement not required means invalid
    # tokens are silently ignored on HTTP. Warn so it is a conscious choice.
    if os.environ.get("OAUTH_ISSUER", "").strip() and os.environ.get(
        "CB_ADMIN_HTTP_REQUIRE_AUTH", "false"
    ).strip().lower() not in ("1", "true", "yes"):
        print(
            "[couchbase-admin-mcp] WARNING: OAUTH_ISSUER is set but "
            "CB_ADMIN_HTTP_REQUIRE_AUTH is not true -- invalid/missing Bearer "
            "tokens on the HTTP transport are ignored (no enforcement). Set "
            "CB_ADMIN_HTTP_REQUIRE_AUTH=true to enforce.",
            file=sys.stderr,
            flush=True,
        )
    msg = (
        f"[couchbase-admin-mcp] tools loaded: {len(_TOOLS)} of {len(_RAW_TOOLS)} "
        f"(read_only={READ_ONLY_MODE}, disabled={len(DISABLED_TOOLS)}, "
        f"confirmation_required={len(_CONFIRMATION_REQUIRED)})"
    )
    # Banner goes to stderr so it does not pollute stdio MCP framing.
    print(msg, file=sys.stderr, flush=True)


# ── Transport selection ──────────────────────────────────────────────────────


async def _main_stdio() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


class _ScopeAuthMiddleware:
    """ASGI middleware: validate Bearer token (if present) and stash claims in
    the scope-gate contextvar for the duration of the request.

    Enforcement is OPTIONAL by default. With OAUTH_ISSUER set and
    CB_ADMIN_HTTP_REQUIRE_AUTH=true, a missing/invalid token is rejected at the
    edge. Otherwise an invalid token is ignored (claims stay None) and per-tool
    scope checks no-op -- preserving today's behavior unless you opt in.
    """

    def __init__(self, app):
        self.app = app
        self._require = os.environ.get(
            "CB_ADMIN_HTTP_REQUIRE_AUTH", "false"
        ).strip().lower() in ("1", "true", "yes")

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

        claims = None
        if token:
            try:
                from auth import oidc as _oidc

                claims = _oidc.validate_token(token)
            except Exception as exc:  # invalid/expired/malformed -- never log token
                if self._require:
                    await _send_401(send, f"Invalid token: {type(exc).__name__}")
                    return
                claims = None
        elif self._require:
            await _send_401(send, "Missing Bearer token")
            return

        set_token_claims(claims)
        try:
            await self.app(scope, receive, send)
        finally:
            clear_token_claims()


async def _send_401(send, detail: str) -> None:
    body = f'{{"error":"unauthorized","detail":"{detail}"}}'.encode()
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


async def _main_http() -> None:
    """Streamable HTTP transport.

    Request authorization is optional: with OAUTH_ISSUER configured and
    CB_ADMIN_HTTP_REQUIRE_AUTH=true, _ScopeAuthMiddleware validates the Bearer
    token and per-tool scope enforcement applies. Otherwise this mode performs
    no request authentication -- deploy behind a reverse proxy or trusted
    network."""
    try:
        from mcp.server.streamable_http import StreamableHTTPServerTransport
    except ImportError:
        print(
            "[couchbase-admin-mcp] Streamable HTTP transport requires a newer mcp library. "
            "Falling back to stdio.",
            file=sys.stderr,
        )
        await _main_stdio()
        return

    host = os.environ.get("CB_ADMIN_HOST", "127.0.0.1")
    port = int(os.environ.get("CB_ADMIN_PORT", "8000"))
    print(
        f"[couchbase-admin-mcp] HTTP transport listening on http://{host}:{port}/mcp",
        file=sys.stderr,
        flush=True,
    )
    # The exact instantiation API for StreamableHTTPServerTransport varies
    # across mcp library versions. We delegate to a thin runner so the user
    # can adapt this in their environment if the API has shifted.
    try:
        import uvicorn  # type: ignore
        from starlette.applications import Starlette
        from starlette.routing import Mount

        transport = StreamableHTTPServerTransport(mcp_session_id=None)
        from starlette.middleware import Middleware

        starlette_app = Starlette(
            routes=[Mount("/mcp", app=transport.handle_request)],
            middleware=[Middleware(_ScopeAuthMiddleware)],
        )
        config = uvicorn.Config(starlette_app, host=host, port=port, log_level="info")
        server = uvicorn.Server(config)

        async def run_server():
            async with transport.connect() as (rs, ws):
                # asyncio.TaskGroup is 3.11+. Use gather for 3.10 compatibility.
                # If one task fails, the other is cancelled (return_exceptions=False)
                # and the first exception propagates — same effective behavior as
                # TaskGroup for our two-task case.
                await asyncio.gather(
                    server.serve(),
                    app.run(rs, ws, app.create_initialization_options()),
                )

        await run_server()
    except ImportError as exc:
        print(
            f"[couchbase-admin-mcp] HTTP transport requires uvicorn and starlette: {exc}. "
            "Install: pip install uvicorn starlette. Falling back to stdio.",
            file=sys.stderr,
        )
        await _main_stdio()


async def _async_main() -> None:
    # Wire logging from CB_ADMIN_LOG_* before anything else, so the banner and
    # every subsequent record land in the configured sinks.
    configure_from_env()
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
