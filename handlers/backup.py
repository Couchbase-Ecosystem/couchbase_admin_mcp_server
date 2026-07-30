"""handlers/backup.py — Backup / Restore service.

Split out of the original monolithic ``extended.py`` for the standalone admin
server: the data-plane tools (``cb_transaction_run``, ``cb_analytics_query``)
stay in the CRUD server; only the ``admin_backup_*`` tools live here.

Wraps the backup service REST endpoints at ``/_p/backup/api/v1/...`` on the
cluster manager. Requires the backup service to be running on at least one node.
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .egress import guard_nested_host_fields
from .shared import admin_request, err, ok, quote_path

# ── Tool definitions ─────────────────────────────────────────────────────────

TOOLS: list[Tool] = [
    Tool(
        name="admin_backup_repository_list",
        description=(
            "List active backup repositories on the backup service. Requires "
            "the backup service to be running on at least one node."
        ),
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_backup_repository_get",
        description="Get details of a specific backup repository.",
        inputSchema={
            "type": "object",
            "properties": {"repository_id": {"type": "string"}},
            "required": ["repository_id"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_backup_list",
        description="List all backups stored in a repository.",
        inputSchema={
            "type": "object",
            "properties": {"repository_id": {"type": "string"}},
            "required": ["repository_id"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_backup_run",
        description=(
            "Trigger a backup operation on the specified repository. Returns "
            "task ID; monitor progress with admin_cluster_tasks."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "repository_id": {"type": "string"},
                "full_backup": {
                    "type": "boolean",
                    "description": "Default false (incremental); true = full backup",
                },
            },
            "required": ["repository_id"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
        ),
    ),
    Tool(
        name="admin_backup_restore_run",
        description=(
            "Trigger a restore operation. This can overwrite data in the "
            "target cluster — review carefully. Requires confirm:true."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "repository_id": {"type": "string"},
                "target": {
                    "type": "object",
                    "description": (
                        "Restore target configuration object. Typical fields: "
                        "filter_keys, filter_values, mappings, include, exclude. "
                        "See Couchbase Backup Service REST docs for the full shape."
                    ),
                },
                "confirm": {"type": "boolean"},
            },
            "required": ["repository_id", "target"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
        ),
    ),
]


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        if name == "admin_backup_repository_list":
            return ok(admin_request("GET", "/_p/backup/api/v1/cluster/self/repository"))

        if name == "admin_backup_repository_get":
            rid = quote_path(args["repository_id"])
            return ok(
                admin_request("GET", f"/_p/backup/api/v1/cluster/self/repository/{rid}")
            )

        if name == "admin_backup_list":
            rid = quote_path(args["repository_id"])
            return ok(
                admin_request(
                    "GET", f"/_p/backup/api/v1/cluster/self/repository/{rid}/backups"
                )
            )

        if name == "admin_backup_run":
            rid = quote_path(args["repository_id"])
            payload: dict = {}
            if args.get("full_backup"):
                payload["full_backup"] = True
            return ok(
                admin_request(
                    "POST",
                    f"/_p/backup/api/v1/cluster/self/repository/{rid}/backup",
                    data=payload if payload else None,
                    json_body=True,
                )
            )

        if name == "admin_backup_restore_run":
            rid = quote_path(args["repository_id"])
            # `target` is a free-form object forwarded verbatim to the Backup Service,
            # and this module had no egress guard of any kind. A restore target can
            # name remote locations and credentials, so the same walk the eventing
            # definitions get applies here: any destination-shaped value at any depth
            # must be in the allowlist.
            guard_nested_host_fields(args["target"], tool=name, path="target")
            return ok(
                admin_request(
                    "POST",
                    f"/_p/backup/api/v1/cluster/self/repository/{rid}/restore",
                    data=args["target"],
                    json_body=True,
                )
            )

        return err(f"Unknown backup tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
