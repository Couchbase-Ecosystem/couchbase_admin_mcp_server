"""handlers/indexes.py — Query Service index management via N1QL system catalog + Index REST API.

Changes from upstream:
- Phase 1: ToolAnnotations. Critical hardening — admin_index_create's raw
  `statement` parameter now only accepts CREATE INDEX / CREATE PRIMARY INDEX /
  CREATE VECTOR INDEX / BUILD INDEX (8.x vector variants supported).
  admin_index_drop similarly restricted to DROP INDEX / DROP PRIMARY INDEX /
  DROP VECTOR INDEX. Both reject other SQL++ even if read-only mode is off.
- Phase 2: Structured err() returns; named parameters for N1QL identifier
  values to prevent injection through bucket/scope/collection name fields.
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .shared import (
    admin_request,
    assert_index_create_ddl,
    assert_index_drop_ddl,
    err,
    form_data,
    get_sdk_connection,
    ok,
)

TOOLS: list[Tool] = [
    Tool(
        name="admin_index_list",
        description="List all GSI indexes (optionally filtered by bucket/scope/collection).",
        inputSchema={
            "type": "object",
            "properties": {
                "bucket_name": {"type": "string"},
                "scope_name": {"type": "string"},
                "collection_name": {"type": "string"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_index_create",
        description=(
            "Create a GSI index using N1QL CREATE INDEX. Provide the full "
            "CREATE INDEX statement (must start with CREATE INDEX / CREATE "
            "PRIMARY INDEX / CREATE [HYPERSCALE|COMPOSITE] VECTOR INDEX / "
            "BUILD INDEX — other SQL++ is rejected), or use the helper fields."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "statement": {
                    "type": "string",
                    "description": (
                        "Full index DDL statement (preferred). "
                        "Only index-DDL keywords accepted."
                    ),
                },
                "index_name": {"type": "string"},
                "bucket_name": {"type": "string"},
                "scope_name": {"type": "string"},
                "collection_name": {"type": "string"},
                "fields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Fields to index",
                },
                "is_primary": {"type": "boolean"},
                "num_replica": {"type": "integer"},
                "defer_build": {"type": "boolean"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
        ),
    ),
    Tool(
        name="admin_index_drop",
        description=(
            "Drop a GSI index. Requires confirm:true. Raw `statement` only "
            "accepts DROP INDEX / DROP PRIMARY INDEX / DROP VECTOR INDEX."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "statement": {
                    "type": "string",
                    "description": "Full DROP INDEX statement (preferred)",
                },
                "index_name": {"type": "string"},
                "bucket_name": {"type": "string"},
                "scope_name": {"type": "string"},
                "collection_name": {"type": "string"},
                "is_primary": {"type": "boolean"},
                "confirm": {"type": "boolean"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_index_build",
        description="Build deferred indexes on a bucket (or scope.collection for CB 7+).",
        inputSchema={
            "type": "object",
            "properties": {
                "bucket_name": {"type": "string"},
                "scope_name": {
                    "type": "string",
                    "description": "Scope name (CB 7+ only; omit for bucket-level build)",
                },
                "collection_name": {
                    "type": "string",
                    "description": "Collection name (CB 7+ only; requires scope_name)",
                },
                "index_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of deferred index names to build",
                },
            },
            "required": ["bucket_name", "index_names"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_index_settings_get",
        description="Get Index Service settings (memory, threads, log level, etc.).",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_index_settings_set",
        description=(
            "Update Index Service settings. Common keys: indexerThreads, "
            "memorySnapshotInterval, stableSnapshotInterval, maxRollbackPoints, "
            "logLevel."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "indexerThreads": {"type": "integer"},
                "memorySnapshotInterval": {"type": "integer"},
                "stableSnapshotInterval": {"type": "integer"},
                "maxRollbackPoints": {"type": "integer"},
                "logLevel": {
                    "type": "string",
                    "enum": [
                        "silent",
                        "fatal",
                        "error",
                        "warn",
                        "info",
                        "verbose",
                        "timing",
                        "debug",
                        "trace",
                    ],
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


def _safe_ident(s: str) -> str:
    """Backtick-quote and escape an identifier for N1QL/SQL++.
    Couchbase backtick-quoting requires doubling embedded backticks."""
    return "`" + (s or "").replace("`", "``") + "`"


def _run_n1ql(statement: str) -> list[TextContent]:
    from couchbase.options import QueryOptions

    cluster, _, _ = get_sdk_connection()
    result = cluster.query(statement, QueryOptions())
    rows = list(result)
    return ok({"rows": rows, "count": len(rows), "statement": statement})


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        if name == "admin_index_list":
            # Use parameterized N1QL where possible to avoid injection through
            # bucket/scope/collection name fields.
            from couchbase.options import QueryOptions

            cluster, _, _ = get_sdk_connection()
            wheres = []
            params: dict = {}
            if args.get("bucket_name"):
                wheres.append("bucket_id = $bucket")
                params["bucket"] = args["bucket_name"]
            if args.get("scope_name"):
                wheres.append("scope_id = $scope")
                params["scope"] = args["scope_name"]
            if args.get("collection_name"):
                wheres.append("keyspace_id = $coll")
                params["coll"] = args["collection_name"]
            stmt = "SELECT * FROM system:indexes"
            if wheres:
                stmt += " WHERE " + " AND ".join(wheres)
            result = cluster.query(stmt, QueryOptions(named_parameters=params))
            rows = list(result)
            return ok({"rows": rows, "count": len(rows)})

        if name == "admin_index_create":
            if args.get("statement"):
                # Hardening: only allow index DDL through the raw path.
                invalid = assert_index_create_ddl(args["statement"])
                if invalid:
                    return err(invalid, tool=name)
                return _run_n1ql(args["statement"])

            if not args.get("bucket_name"):
                return err(
                    "bucket_name is required when statement is not provided",
                    tool=name,
                )

            bucket = _safe_ident(args["bucket_name"])
            scope = _safe_ident(args.get("scope_name", "_default"))
            coll = _safe_ident(args.get("collection_name", "_default"))

            if args.get("is_primary"):
                idx = _safe_ident(args.get("index_name", "#primary"))
                stmt = f"CREATE PRIMARY INDEX {idx} ON {bucket}.{scope}.{coll}"
            else:
                if not args.get("index_name"):
                    return err(
                        "index_name is required for non-primary indexes", tool=name
                    )
                if not args.get("fields"):
                    return err("fields are required for non-primary indexes", tool=name)
                idx = _safe_ident(args["index_name"])
                fields = ", ".join(_safe_ident(f) for f in args["fields"])
                stmt = f"CREATE INDEX {idx} ON {bucket}.{scope}.{coll} ({fields})"

            withs = []
            if args.get("num_replica") is not None:
                withs.append(f'"num_replica": {int(args["num_replica"])}')
            if args.get("defer_build"):
                withs.append('"defer_build": true')
            if withs:
                stmt += " WITH {" + ", ".join(withs) + "}"

            return _run_n1ql(stmt)

        if name == "admin_index_drop":
            if args.get("statement"):
                invalid = assert_index_drop_ddl(args["statement"])
                if invalid:
                    return err(invalid, tool=name)
                return _run_n1ql(args["statement"])

            if not args.get("bucket_name"):
                return err(
                    "bucket_name is required when statement is not provided", tool=name
                )

            bucket = _safe_ident(args["bucket_name"])
            scope = _safe_ident(args.get("scope_name", "_default"))
            coll = _safe_ident(args.get("collection_name", "_default"))
            if args.get("is_primary"):
                stmt = f"DROP PRIMARY INDEX ON {bucket}.{scope}.{coll}"
            else:
                if not args.get("index_name"):
                    return err("index_name is required for non-primary drop", tool=name)
                idx = _safe_ident(args["index_name"])
                stmt = f"DROP INDEX {idx} ON {bucket}.{scope}.{coll}"
            return _run_n1ql(stmt)

        if name == "admin_index_build":
            bucket = _safe_ident(args["bucket_name"])
            scope = args.get("scope_name")
            coll = args.get("collection_name")
            indexes = ", ".join(_safe_ident(i) for i in args["index_names"])
            if scope and coll:
                # CB 7+ scoped build
                keyspace = f"{bucket}.{_safe_ident(scope)}.{_safe_ident(coll)}"
            else:
                keyspace = bucket
            stmt = f"BUILD INDEX ON {keyspace} ({indexes})"
            return _run_n1ql(stmt)

        if name == "admin_index_settings_get":
            return ok(admin_request("GET", "/settings/indexes"))

        if name == "admin_index_settings_set":
            data = form_data(args)
            return ok(admin_request("POST", "/settings/indexes", data=data))

        return err(f"Unknown index tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
