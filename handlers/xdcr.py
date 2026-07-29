"""handlers/xdcr.py — Cross Datacenter Replication (XDCR) admin tools.

Changes from upstream:
- Phase 1: ToolAnnotations. Replication delete and reference delete marked destructive.
- Phase 2: URL encoding for replication_id moved inside handler (caller no longer
  responsible). Structured err() returns.
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .shared import admin_request, err, ok, quote_path

TOOLS: list[Tool] = [
    Tool(
        name="admin_xdcr_references_list",
        description="List all registered remote cluster references.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_xdcr_reference_create",
        description="Register a remote cluster reference for XDCR.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Friendly name for the remote cluster",
                },
                "hostname": {
                    "type": "string",
                    "description": "IP/hostname of the remote cluster node",
                },
                "username": {"type": "string"},
                "password": {"type": "string"},
                "demandEncryption": {
                    "type": "integer",
                    "enum": [0, 1],
                    "description": "0=none, 1=TLS",
                },
            },
            "required": ["name", "hostname", "username", "password"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
        ),
    ),
    Tool(
        name="admin_xdcr_reference_delete",
        description=(
            "Delete a remote cluster reference by name. Will fail if active "
            "replications exist. Requires confirm:true."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "cluster_name": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["cluster_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_xdcr_replications_list",
        description="List all XDCR replication settings / replications.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_xdcr_replication_create",
        description="Create an XDCR replication from a source bucket to a target bucket.",
        inputSchema={
            "type": "object",
            "properties": {
                "fromBucket": {"type": "string"},
                "toCluster": {
                    "type": "string",
                    "description": "Remote cluster reference name",
                },
                "toBucket": {"type": "string"},
                "replicationType": {
                    "type": "string",
                    "enum": ["continuous"],
                    "description": (
                        "Always 'continuous' on modern Couchbase. Default: continuous."
                    ),
                },
                "type": {
                    "type": "string",
                    "enum": ["xmem", "capi"],
                    "description": (
                        "Replication protocol. xmem (default) uses the memcached "
                        "protocol; capi uses the REST protocol (legacy)."
                    ),
                },
                "compressionType": {
                    "type": "string",
                    "enum": ["None", "Snappy", "Auto"],
                    "description": "Compression for replication payload",
                },
                "filterExpression": {
                    "type": "string",
                    "description": "Optional N1QL-style filter",
                },
                "conflictLogging": {
                    "type": "boolean",
                    "description": (
                        "Couchbase 8.x: enable conflict logging on this "
                        "replication. Pairs with conflictLoggingMapping."
                    ),
                },
                "conflictLoggingMapping": {
                    "type": "object",
                    "description": (
                        "Couchbase 8.x: target bucket/scope/collection for "
                        "the conflict log, e.g. "
                        '{"bucket": "conflicts", "scope": "_default", '
                        '"collection": "_default"}. Sent as a JSON string '
                        "in the form body."
                    ),
                },
            },
            "required": ["fromBucket", "toCluster", "toBucket"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
        ),
    ),
    Tool(
        name="admin_xdcr_replication_pause",
        description="Pause an XDCR replication.",
        inputSchema={
            "type": "object",
            "properties": {
                "replication_id": {
                    "type": "string",
                    "description": "Replication ID (URL-encoding handled by server)",
                },
            },
            "required": ["replication_id"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_xdcr_replication_resume",
        description="Resume a paused XDCR replication.",
        inputSchema={
            "type": "object",
            "properties": {"replication_id": {"type": "string"}},
            "required": ["replication_id"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_xdcr_replication_delete",
        description="Delete an XDCR replication. Requires confirm:true.",
        inputSchema={
            "type": "object",
            "properties": {
                "replication_id": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["replication_id"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_xdcr_settings_get",
        description="Get global XDCR advanced settings.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_xdcr_settings_set",
        description="Update global or per-replication XDCR settings.",
        inputSchema={
            "type": "object",
            "properties": {
                "replication_id": {
                    "type": "string",
                    "description": "Leave empty for global settings",
                },
                "workerBatchSize": {"type": "integer"},
                "docBatchSizeKb": {"type": "integer"},
                "failureRestartInterval": {"type": "integer"},
                "optimisticReplicationThreshold": {"type": "integer"},
                "statsInterval": {"type": "integer"},
                "compressionType": {
                    "type": "string",
                    "enum": ["None", "Snappy", "Auto"],
                },
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
]


def _enc_rep_id(rid: str) -> str:
    """URL-encode a replication ID. Backwards-compatible alias for quote_path."""
    return quote_path(rid)


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        if name == "admin_xdcr_references_list":
            return ok(admin_request("GET", "/pools/default/remoteClusters"))

        if name == "admin_xdcr_reference_create":
            data = {
                "name": args["name"],
                "hostname": args["hostname"],
                "username": args["username"],
                "password": args["password"],
            }
            if args.get("demandEncryption") is not None:
                data["demandEncryption"] = str(args["demandEncryption"])
            return ok(admin_request("POST", "/pools/default/remoteClusters", data=data))

        if name == "admin_xdcr_reference_delete":
            cname = quote_path(args["cluster_name"])
            return ok(admin_request("DELETE", f"/pools/default/remoteClusters/{cname}"))

        if name == "admin_xdcr_replications_list":
            return ok(admin_request("GET", "/settings/replications/"))

        if name == "admin_xdcr_replication_create":
            data = {
                "fromBucket": args["fromBucket"],
                "toCluster": args["toCluster"],
                "toBucket": args["toBucket"],
                "replicationType": args.get("replicationType", "continuous"),
            }
            # 'type' selects the wire protocol (xmem vs capi). Default is xmem.
            if args.get("type"):
                data["type"] = args["type"]
            if args.get("compressionType"):
                data["compressionType"] = args["compressionType"]
            if args.get("filterExpression"):
                data["filterExpression"] = args["filterExpression"]
            if args.get("conflictLogging") is not None:
                data["conflictLogging"] = "true" if args["conflictLogging"] else "false"
            if args.get("conflictLoggingMapping"):
                # Form encoding requires a JSON string for nested objects.
                import json as _json

                data["conflictLoggingMapping"] = _json.dumps(
                    args["conflictLoggingMapping"]
                )
            return ok(admin_request("POST", "/controller/createReplication", data=data))

        if name == "admin_xdcr_replication_pause":
            rid = _enc_rep_id(args["replication_id"])
            return ok(
                admin_request(
                    "POST",
                    f"/settings/replications/{rid}",
                    data={"pauseRequested": "true"},
                )
            )

        if name == "admin_xdcr_replication_resume":
            rid = _enc_rep_id(args["replication_id"])
            return ok(
                admin_request(
                    "POST",
                    f"/settings/replications/{rid}",
                    data={"pauseRequested": "false"},
                )
            )

        if name == "admin_xdcr_replication_delete":
            rid = _enc_rep_id(args["replication_id"])
            return ok(admin_request("DELETE", f"/controller/cancelXDCR/{rid}"))

        if name == "admin_xdcr_settings_get":
            return ok(admin_request("GET", "/settings/replications/"))

        if name == "admin_xdcr_settings_set":
            rid = args.get("replication_id")
            data = {
                k: str(v)
                for k, v in args.items()
                if v is not None and k != "replication_id"
            }
            path = (
                f"/settings/replications/{_enc_rep_id(rid)}"
                if rid
                else "/settings/replications/"
            )
            return ok(admin_request("POST", path, data=data))

        return err(f"Unknown XDCR tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
