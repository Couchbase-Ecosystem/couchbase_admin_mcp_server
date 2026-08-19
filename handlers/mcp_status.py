"""handlers/mcp_status.py — Server/MCP introspection tools.

These tools report on the MCP server itself (the Python process running
`server.py`), not the Couchbase cluster. They're useful for verifying that
configuration was applied correctly and for diagnosing why a tool is missing
from the discovered tool list (read-only mode, disabled-tools, etc.).

All tools here are READ ONLY and have no cluster dependency — they answer
purely from in-process state.

Tools:
  cb_mcp_status           High-level config summary (transport, safety flags,
                          tool counts, cluster auth method)
  cb_mcp_list_tools       List the tools currently exposed by this server
                          (post read-only / disabled filtering)
  cb_mcp_get_tool_info    Get the schema + annotations for a single tool by name
"""

from __future__ import annotations

import os
import sys

from mcp.types import TextContent, Tool, ToolAnnotations

import mcp_compat

from .shared import (
    DISABLED_TOOLS,
    ELICITATION_HINTS,
    READ_ONLY_MODE,
    env_truthy,
    err,
    get_cluster_version,
    ok,
    redact_uri_credentials,
)

TOOLS: list[Tool] = [
    Tool(
        name="cb_mcp_status",
        description=(
            "Get the current configuration of this MCP server: safety mode, "
            "transport, cluster auth method, tool counts. Does not require a "
            "live cluster connection."
        ),
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="cb_mcp_list_tools",
        description=(
            "List every tool currently exposed by this MCP server (after "
            "read-only and disabled-tools filtering). Returns tool name plus "
            "destructive / read-only annotations for each."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": (
                        "Optional category filter: 'read', 'write', "
                        "'destructive', or 'all' (default)."
                    ),
                    "enum": ["read", "write", "destructive", "all"],
                },
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="cb_mcp_get_tool_info",
        description=(
            "Get the input schema and annotations for a single tool. Useful "
            "for inspecting required parameters before calling a tool."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "tool_name": {"type": "string"},
            },
            "required": ["tool_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
]


def _auth_method() -> str:
    """Determine which auth method is configured."""
    cert = os.environ.get("CB_CLIENT_CERT_PATH")
    key = os.environ.get("CB_CLIENT_KEY_PATH")
    if cert and key:
        return "mTLS (client certificate)"
    if os.environ.get("CB_USERNAME") and os.environ.get("CB_PASSWORD"):
        return "Password (username/password)"
    return "Not configured"


def _tls_state() -> dict:
    """Report TLS configuration without exposing credential paths."""
    conn = os.environ.get("CB_CONNECTION_STRING", "couchbase://localhost")
    is_tls = "couchbases://" in conn
    # env_truthy, not a third hand-rolled set. This one omitted "on", "y" and "t",
    # so cb_mcp_status reported tls_verify_disabled=false while verification was in
    # fact disabled -- the status tool is what an operator checks to confirm the
    # posture, so a wrong answer here is worse than no answer.
    insecure = env_truthy("CB_ADMIN_TLS_INSECURE")
    return {
        "tls_enabled": is_tls,
        "tls_verify_disabled": insecure,
        "ca_cert_configured": bool(os.environ.get("CB_CA_CERT_PATH")),
        "client_cert_configured": bool(
            os.environ.get("CB_CLIENT_CERT_PATH")
            and os.environ.get("CB_CLIENT_KEY_PATH")
        ),
    }


def _status_payload(server_module) -> dict:
    """Build the cb_mcp_status payload from in-process server state."""
    raw_tools = getattr(server_module, "_RAW_TOOLS", [])
    loaded_tools = getattr(server_module, "_TOOLS", [])
    confirmation_required = getattr(server_module, "_CONFIRMATION_REQUIRED", set())

    # Counted through _category_of, the SAME classifier cb_mcp_list_tools filters
    # with. These were computed independently: "write" here meant every non-read
    # tool (destructive included) while the list filter excluded destructive ones, so
    # cb_mcp_status reported write=70 and cb_mcp_list_tools(category="write") returned
    # 32 rows. An operator auditing the write surface saw 38 tools vanish with no
    # explanation. The categories are now mutually exclusive and sum to the total.
    _categories = [_category_of(t) for t in loaded_tools]
    by_category = {
        "read": _categories.count("read"),
        "write": _categories.count("write"),
        "destructive": _categories.count("destructive"),
    }

    return {
        "server": "couchbase-admin-mcp",
        "python_version": sys.version.split()[0],
        "transport": os.environ.get("CB_ADMIN_TRANSPORT", "stdio").lower(),
        "transport_host": os.environ.get("CB_ADMIN_HOST", "127.0.0.1"),
        "transport_port": int(os.environ.get("CB_ADMIN_PORT", "8000")),
        "safety": {
            "read_only_mode": READ_ONLY_MODE,
            "elicitation_hints": ELICITATION_HINTS,
            "disabled_tools_count": len(DISABLED_TOOLS),
            "disabled_tools": sorted(DISABLED_TOOLS) if DISABLED_TOOLS else [],
            "confirmation_required_count": len(confirmation_required),
        },
        "tools": {
            "registered": len(raw_tools),
            "loaded": len(loaded_tools),
            "filtered_out": len(raw_tools) - len(loaded_tools),
            "by_category": by_category,
        },
        "connection": {
            # redact() masks by key name and "connection_string" looks innocent, so a
            # password in the URI's userinfo used to be returned in full by this
            # read-only tool. Masked at the source rather than relying on the generic pass.
            "connection_string": redact_uri_credentials(
                os.environ.get("CB_CONNECTION_STRING", "couchbase://localhost")
            ),
            "default_bucket": os.environ.get("CB_BUCKET", "default"),
            "default_scope": os.environ.get("CB_SCOPE", "_default"),
            "default_collection": os.environ.get("CB_COLLECTION", "_default"),
            "auth_method": _auth_method(),
            "tls": _tls_state(),
        },
        "cluster_version": get_cluster_version() or "unknown (not yet probed)",
        "http_retries": int(os.environ.get("CB_ADMIN_HTTP_RETRIES", "3")),
        "http_timeout_seconds": int(os.environ.get("CB_ADMIN_HTTP_TIMEOUT", "30")),
    }


def _category_of(t: Tool) -> str:
    """Classify a single Tool for the cb_mcp_list_tools filter."""
    if not t.annotations:
        return "write"
    if mcp_compat.is_destructive(t):
        return "destructive"
    if mcp_compat.is_read_only(t):
        return "read"
    return "write"


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        # Import server here (lazily) to avoid a circular import at module load.
        import server as server_module

        if name == "cb_mcp_status":
            return ok(_status_payload(server_module))

        if name == "cb_mcp_list_tools":
            category = args.get("category", "all")
            loaded_tools = getattr(server_module, "_TOOLS", [])
            rows = []
            for t in loaded_tools:
                cat = _category_of(t)
                if category != "all" and cat != category:  # noqa: PLR1714
                    continue
                rows.append(
                    {
                        "name": t.name,
                        "category": cat,
                        "read_only": mcp_compat.is_read_only(t),
                        "destructive": mcp_compat.is_destructive(t),
                        "idempotent": mcp_compat.is_idempotent(t),
                    }
                )
            return ok({"count": len(rows), "filter": category, "tools": rows})

        if name == "cb_mcp_get_tool_info":
            target = args["tool_name"]
            raw_tools = getattr(server_module, "_RAW_TOOLS", [])
            loaded_tools = getattr(server_module, "_TOOLS", [])
            loaded_names = {t.name for t in loaded_tools}
            match = next((t for t in raw_tools if t.name == target), None)
            if match is None:
                return err(
                    f"No tool named {target!r} is registered with this server.",
                    tool=name,
                    hint="Use cb_mcp_list_tools to see available tools.",
                )
            return ok(
                {
                    "name": match.name,
                    "description": match.description,
                    "input_schema": mcp_compat.input_schema(match),
                    "annotations": {
                        "read_only": mcp_compat.is_read_only(match),
                        "destructive": mcp_compat.is_destructive(match),
                        "idempotent": mcp_compat.is_idempotent(match),
                    },
                    "currently_loaded": match.name in loaded_names,
                    "currently_disabled": match.name in DISABLED_TOOLS,
                }
            )

        return err(f"Unknown mcp_status tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
