"""handlers/buckets.py — Bucket & sample-bucket admin tools.

Changes from upstream:
- Phase 1: ToolAnnotations on every tool. Destructive ops marked.
- Phase 2: admin_sample_buckets_install now routes through admin_request_json
  (was using inline urllib). Structured err() returns on exception.
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .shared import admin_request, admin_request_json, err, ok, quote_path

TOOLS: list[Tool] = [
    Tool(
        name="admin_bucket_list",
        description="List all buckets in the cluster.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_bucket_get",
        description="Get detailed information about a specific bucket.",
        inputSchema={
            "type": "object",
            "properties": {"bucket_name": {"type": "string"}},
            "required": ["bucket_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_bucket_create",
        description=(
            "Create a new bucket. Common params: name, bucketType "
            "(couchbase|ephemeral|memcached), ramQuota (MB), replicaNumber, "
            "flushEnabled (0|1), compressionMode, storageBackend "
            "(couchstore|magma). In Couchbase 8.x, magma defaults to 128 vBuckets "
            "with a 100 MiB minimum memory quota."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "bucketType": {
                    "type": "string",
                    "enum": ["couchbase", "ephemeral", "memcached"],
                },
                "ramQuota": {"type": "integer", "description": "RAM quota in MB"},
                "replicaNumber": {"type": "integer"},
                "flushEnabled": {"type": "integer", "enum": [0, 1]},
                "compressionMode": {
                    "type": "string",
                    "enum": ["off", "passive", "active"],
                },
                "storageBackend": {
                    "type": "string",
                    "enum": ["couchstore", "magma"],
                },
            },
            "required": ["name", "ramQuota"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
        ),
    ),
    Tool(
        name="admin_bucket_update",
        description="Update settings on an existing bucket (ramQuota, replicaNumber, flushEnabled, etc.).",
        inputSchema={
            "type": "object",
            "properties": {
                "bucket_name": {"type": "string"},
                "ramQuota": {"type": "integer"},
                "replicaNumber": {"type": "integer"},
                "flushEnabled": {"type": "integer", "enum": [0, 1]},
                "compressionMode": {"type": "string"},
            },
            "required": ["bucket_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_bucket_delete",
        description="Delete a bucket and all its data. IRREVERSIBLE. Requires confirm:true.",
        inputSchema={
            "type": "object",
            "properties": {
                "bucket_name": {"type": "string"},
                "confirm": {
                    "type": "boolean",
                    "description": "Must be true to execute this destructive operation.",
                },
            },
            "required": ["bucket_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_bucket_flush",
        description=(
            "Flush (delete all documents from) a bucket. Requires flushEnabled=1 "
            "on the bucket. IRREVERSIBLE. Requires confirm:true."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "bucket_name": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["bucket_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
        ),
    ),
    Tool(
        name="admin_bucket_compact",
        description="Trigger compaction on a bucket to reclaim disk space.",
        inputSchema={
            "type": "object",
            "properties": {"bucket_name": {"type": "string"}},
            "required": ["bucket_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_bucket_cancel_compaction",
        description="Cancel an in-progress compaction on a bucket.",
        inputSchema={
            "type": "object",
            "properties": {"bucket_name": {"type": "string"}},
            "required": ["bucket_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_sample_buckets_list",
        description="List available sample buckets (e.g. travel-sample, beer-sample).",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_sample_buckets_install",
        description="Install one or more sample buckets by name.",
        inputSchema={
            "type": "object",
            "properties": {
                "buckets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": 'e.g. ["travel-sample", "beer-sample"]',
                }
            },
            "required": ["buckets"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
        ),
    ),
]


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        if name == "admin_bucket_list":
            return ok(admin_request("GET", "/pools/default/buckets"))

        if name == "admin_bucket_get":
            b = quote_path(args["bucket_name"])
            return ok(admin_request("GET", f"/pools/default/buckets/{b}"))

        if name == "admin_bucket_create":
            data = {k: v for k, v in args.items() if v is not None and k != "confirm"}
            if "ramQuota" in data:
                data["ramQuotaMB"] = data.pop("ramQuota")
            return ok(admin_request("POST", "/pools/default/buckets", data=data))

        if name == "admin_bucket_update":
            b = quote_path(args["bucket_name"])
            data = {
                k: v
                for k, v in args.items()
                if v is not None and k not in ("bucket_name", "confirm")
            }
            if "ramQuota" in data:
                data["ramQuotaMB"] = data.pop("ramQuota")
            return ok(admin_request("POST", f"/pools/default/buckets/{b}", data=data))

        if name == "admin_bucket_delete":
            b = quote_path(args["bucket_name"])
            return ok(admin_request("DELETE", f"/pools/default/buckets/{b}"))

        if name == "admin_bucket_flush":
            b = quote_path(args["bucket_name"])
            return ok(
                admin_request("POST", f"/pools/default/buckets/{b}/controller/doFlush")
            )

        if name == "admin_bucket_compact":
            b = quote_path(args["bucket_name"])
            return ok(
                admin_request(
                    "POST", f"/pools/default/buckets/{b}/controller/compactBucket"
                )
            )

        if name == "admin_bucket_cancel_compaction":
            b = quote_path(args["bucket_name"])
            return ok(
                admin_request(
                    "POST",
                    f"/pools/default/buckets/{b}/controller/cancelBucketCompaction",
                )
            )

        if name == "admin_sample_buckets_list":
            return ok(admin_request("GET", "/sampleBuckets"))

        if name == "admin_sample_buckets_install":
            # Endpoint expects a raw JSON array body. Route through unified client.
            return ok(
                admin_request_json(
                    "POST", "/sampleBuckets/install", payload=args["buckets"]
                )
            )

        return err(f"Unknown bucket tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
