"""handlers/eventing.py — Phase 6c: Couchbase Eventing service tools.

Couchbase Eventing runs JavaScript functions that react to KV mutations (or
timers). The service exposes a REST API for function lifecycle:

  - List / get / create / update / delete functions
  - Deploy / undeploy (start / stop processing)
  - Pause / resume (temporarily halt without losing checkpoint)
  - Stats and status

REST PATH ASSUMPTION
====================
This module targets the cluster-manager proxy path `/_p/event/api/v1/...`,
which is how the Backup tools (Phase 6b) and many other service REST APIs are
mounted. Some Couchbase deployments instead expose the Eventing service at its
own port (8096 / 18096). If your cluster returns 404 on these tools, the
service is reachable directly — change the path prefix in `_evt_path()` from
`/_p/event/api/v1` to your environment's prefix, or add a `CB_EVENTING_PORT`
env var and route through a service-specific request helper.

I have NOT validated this path against a running cluster — it's based on the
pattern used by other Couchbase service proxies. Treat the first call against
each tool as a verification step.

Tools added (10):
  admin_eventing_list                   read
  admin_eventing_get                    read
  admin_eventing_create_or_update       write
  admin_eventing_delete                 destructive
  admin_eventing_deploy                 write
  admin_eventing_undeploy               destructive (stops event processing)
  admin_eventing_pause                  write
  admin_eventing_resume                 write
  admin_eventing_stats                  read
  admin_eventing_status                 read
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .shared import admin_request, admin_request_json, err, ok, quote_path

# Cluster-manager proxy prefix for the Eventing REST API. See module
# docstring for the path-assumption caveat.
_EVT_BASE = "/_p/event/api/v1"


def _evt_path(suffix: str) -> str:
    """Build an Eventing endpoint URL from a suffix. Centralized so it can be
    swapped in one place if the proxy path differs on your cluster."""
    if not suffix.startswith("/"):
        suffix = "/" + suffix
    return _EVT_BASE + suffix


def _fn_name(args: dict) -> str:
    """Return a URL-encoded function name from args."""
    return quote_path(args["function_name"])


TOOLS: list[Tool] = [
    Tool(
        name="admin_eventing_list",
        description=(
            "List all Eventing functions on the cluster. Returns metadata "
            "(name, deployment status, source bucket, etc.) for each function."
        ),
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_eventing_get",
        description=(
            "Get the full definition of an Eventing function: source code, "
            "settings, bindings, deployment status."
        ),
        inputSchema={
            "type": "object",
            "properties": {"function_name": {"type": "string"}},
            "required": ["function_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_eventing_create_or_update",
        description=(
            "Create or update an Eventing function. The `definition` field "
            "must be the complete function JSON including appname, appcode "
            "(the JavaScript), depcfg (deployment config with source bucket "
            "/scope/collection and bindings), and settings. See Couchbase "
            "Eventing REST docs for the exact shape."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "function_name": {"type": "string"},
                "definition": {
                    "type": "object",
                    "description": (
                        "Full function definition. Minimum required keys: "
                        "appname (string), appcode (string JS source), "
                        "depcfg (object), settings (object)."
                    ),
                },
            },
            "required": ["function_name", "definition"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_eventing_delete",
        description=(
            "Delete an Eventing function. The function must be undeployed first. "
            "IRREVERSIBLE — function source code is removed. Requires confirm:true."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "function_name": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["function_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_eventing_deploy",
        description=(
            "Deploy (start) an Eventing function. The function begins "
            "processing mutations from its configured source. Returns task "
            "ID; monitor with admin_eventing_status."
        ),
        inputSchema={
            "type": "object",
            "properties": {"function_name": {"type": "string"}},
            "required": ["function_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_eventing_undeploy",
        description=(
            "Undeploy (stop) an Eventing function. The function stops "
            "processing mutations; checkpoint is discarded. Function source "
            "remains; can be redeployed later. Requires confirm:true."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "function_name": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["function_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_eventing_pause",
        description=(
            "Pause an Eventing function temporarily. Unlike undeploy, the "
            "checkpoint is preserved — resume picks up where pause left off."
        ),
        inputSchema={
            "type": "object",
            "properties": {"function_name": {"type": "string"}},
            "required": ["function_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_eventing_resume",
        description=(
            "Resume a previously paused Eventing function. Processing "
            "continues from the saved checkpoint."
        ),
        inputSchema={
            "type": "object",
            "properties": {"function_name": {"type": "string"}},
            "required": ["function_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_eventing_stats",
        description=(
            "Get statistics for all Eventing functions: event processing "
            "rates, failure counts, latency percentiles, DCP backlog."
        ),
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_eventing_status",
        description=(
            "Get deployment / running status of all Eventing functions. "
            "Returns each function's composite state (deployed, undeployed, "
            "paused, deploying, undeploying, etc.)."
        ),
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
]


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        if name == "admin_eventing_list":
            return ok(admin_request("GET", _evt_path("/list")))

        if name == "admin_eventing_get":
            fn = _fn_name(args)
            return ok(admin_request("GET", _evt_path(f"/functions/{fn}")))

        if name == "admin_eventing_create_or_update":
            fn = _fn_name(args)
            return ok(
                admin_request_json(
                    "POST",
                    _evt_path(f"/functions/{fn}"),
                    payload=args["definition"],
                )
            )

        if name == "admin_eventing_delete":
            fn = _fn_name(args)
            return ok(admin_request("DELETE", _evt_path(f"/functions/{fn}")))

        if name == "admin_eventing_deploy":
            fn = _fn_name(args)
            return ok(admin_request("POST", _evt_path(f"/functions/{fn}/deploy")))

        if name == "admin_eventing_undeploy":
            fn = _fn_name(args)
            return ok(admin_request("POST", _evt_path(f"/functions/{fn}/undeploy")))

        if name == "admin_eventing_pause":
            fn = _fn_name(args)
            return ok(admin_request("POST", _evt_path(f"/functions/{fn}/pause")))

        if name == "admin_eventing_resume":
            fn = _fn_name(args)
            return ok(admin_request("POST", _evt_path(f"/functions/{fn}/resume")))

        if name == "admin_eventing_stats":
            return ok(admin_request("GET", _evt_path("/stats")))

        if name == "admin_eventing_status":
            return ok(admin_request("GET", _evt_path("/status")))

        return err(f"Unknown eventing tool: {name}", tool=name)

    except Exception as exc:
        # Hint the user at the path-assumption caveat when we get a 404 —
        # most likely cause if the cluster's Eventing proxy is somewhere else.
        msg = str(exc)
        hint = None
        if "404" in msg:
            hint = (
                "404 from the Eventing endpoint may indicate the REST proxy "
                "path is different on this cluster. See handlers/eventing.py "
                "module docstring for adjustments."
            )
        if hint:
            return err(f"{type(exc).__name__}: {exc}", tool=name, args=args, hint=hint)
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
