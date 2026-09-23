"""handlers/eight_x.py — Phase 5: Couchbase 8.x-specific first-class tools.

All tools in this module call `_require_8x()` at runtime. If the cluster is
not 8.x (or version detection fails), they return a structured error rather
than constructing SQL++ that the cluster will reject anyway.

Tools added:
  Vector indexes (structured wrappers — no raw SQL++):
    admin_vector_index_create_hyperscale
    admin_vector_index_create_composite
  RBAC additions:
    admin_user_lock                   (destructive — denies access)
    admin_user_unlock
    admin_user_create_temporary       (creates user with temporaryPassword)
  XDCR:
    admin_xdcr_conflict_log_query     (reads from configured conflict collection)

Explicitly deferred (need live-cluster validation):
  - Search synonym source management — the 8.x API for synonym sources is
    cluster-version-dependent. Define synonyms inside FTS index params for now.
  - DARE / KMIP configuration — this is install-time / CLI configuration,
    not a clean runtime REST endpoint surface.
  - NL-to-SQL++ translator — the LLM does this directly; no MCP value-add.

Tool count: 7 new (all 7 loaded in both RO and read-write mode for reads;
writes/destructives gated by the existing read-only-mode and confirmation
infrastructure).
"""

from __future__ import annotations

import re

from mcp.types import TextContent, Tool, ToolAnnotations

from .shared import (
    admin_request,
    arg_truthy,
    err,
    get_sdk_cluster,
    is_8x,
    ok,
    quote_path,
)

# ── Version gate ─────────────────────────────────────────────────────────────


def _require_8x(tool_name: str) -> list[TextContent] | None:
    """Return an error list_content if the cluster is not 8.x, else None.

    Version detection caches at module level (see shared.get_cluster_version),
    so the cost is one /pools call per server lifetime.
    """
    if is_8x():
        return None
    return err(
        "This tool requires Couchbase Server 8.0 or newer. "
        "Run admin_cluster_info and check `implementationVersion` to confirm "
        "your cluster version. For 7.x clusters use the equivalent 7.x tools "
        "or the documented SQL++ workarounds.",
        tool=tool_name,
        hint="Use admin_cluster_info to verify the cluster version.",
    )


# ── Identifier quoting (mirrors handlers/indexes.py) ─────────────────────────


def _safe_ident(s: str) -> str:
    return "`" + (s or "").replace("`", "``") + "`"


def _keyspace(bucket: str, scope: str | None, coll: str | None) -> str:
    return (
        f"{_safe_ident(bucket)}.{_safe_ident(scope or '_default')}"
        f".{_safe_ident(coll or '_default')}"
    )


# Similarity values accepted by Couchbase 8.x vector indexes.
_VALID_SIMILARITY = {"L2_SQUARED", "DOT_PRODUCT", "COSINE"}


def _validate_similarity(sim: str, tool: str) -> list[TextContent] | None:
    """Reject anything not in the documented enum to prevent typo-induced silent
    failures (the cluster's error message is less actionable than this one)."""
    if sim not in _VALID_SIMILARITY:
        return err(
            f"similarity must be one of {sorted(_VALID_SIMILARITY)}; got `{sim}`",
            tool=tool,
        )
    return None


def _with_clause(
    dimension: int,
    similarity: str,
    description: str | None,
    num_replica: int | None,
    defer_build: bool | None,
) -> str:
    """Build the WITH {...} clause for a vector index. JSON-escapes string values."""
    import json

    parts: list[str] = [
        f'"dimension": {int(dimension)}',
        f'"similarity": {json.dumps(similarity)}',
    ]
    if description:
        parts.append(f'"description": {json.dumps(description)}')
    if num_replica is not None:
        parts.append(f'"num_replica": {int(num_replica)}')
    # arg_truthy: defer_build="false" used to DEFER, creating a vector index that is
    # never built, so every ANN query silently returns nothing until someone runs
    # BUILD INDEX by hand -- and the tool reported the index as created.
    if arg_truthy(defer_build):
        parts.append('"defer_build": true')
    return " WITH {" + ", ".join(parts) + "}"


# ── Tool definitions ─────────────────────────────────────────────────────────

TOOLS: list[Tool] = [
    # ── Vector indexes ──────────────────────────────────────────────────
    Tool(
        name="admin_vector_index_create_hyperscale",
        description=(
            "Create a HYPERSCALE VECTOR INDEX (8.x). For billion-scale ANN "
            "search where filtering is rare. Use admin_vector_index_create_composite "
            "instead if queries filter by scalar fields. Requires Couchbase 8.0+."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "bucket_name": {"type": "string"},
                "scope_name": {"type": "string", "description": "default: _default"},
                "collection_name": {
                    "type": "string",
                    "description": "default: _default",
                },
                "index_name": {"type": "string"},
                "field_name": {
                    "type": "string",
                    "description": "The document field holding the embedding array",
                },
                "dimension": {
                    "type": "integer",
                    "description": "Vector length; must match every doc's embedding",
                },
                "similarity": {
                    "type": "string",
                    "enum": ["L2_SQUARED", "DOT_PRODUCT", "COSINE"],
                },
                "description": {"type": "string"},
                "num_replica": {"type": "integer"},
                "defer_build": {"type": "boolean"},
            },
            "required": [
                "bucket_name",
                "index_name",
                "field_name",
                "dimension",
                "similarity",
            ],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
        ),
    ),
    Tool(
        name="admin_vector_index_create_composite",
        description=(
            "Create a COMPOSITE VECTOR INDEX (8.x). Combines a vector field with "
            "scalar prefix keys for filtered ANN search (e.g. tenant_id + status + "
            "embedding). Use this when queries include WHERE on the scalar fields. "
            "Requires Couchbase 8.0+."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "bucket_name": {"type": "string"},
                "scope_name": {"type": "string"},
                "collection_name": {"type": "string"},
                "index_name": {"type": "string"},
                "scalar_fields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Scalar prefix fields; order matters (most selective first)"
                    ),
                },
                "vector_field": {"type": "string"},
                "where_clause": {
                    "type": "string",
                    "description": (
                        "Optional SQL++ WHERE predicate for a partial index, "
                        "without the WHERE keyword (e.g. 'deleted = false')"
                    ),
                },
                "dimension": {"type": "integer"},
                "similarity": {
                    "type": "string",
                    "enum": ["L2_SQUARED", "DOT_PRODUCT", "COSINE"],
                },
                "num_replica": {"type": "integer"},
                "defer_build": {"type": "boolean"},
            },
            "required": [
                "bucket_name",
                "index_name",
                "scalar_fields",
                "vector_field",
                "dimension",
                "similarity",
            ],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
        ),
    ),
    # ── User lock / unlock / temporary password ─────────────────────────
    Tool(
        name="admin_user_lock",
        description=(
            "Lock a local user account (8.x). The user can still be queried "
            "by admins but cannot authenticate until unlocked. Requires "
            "confirm:true. Requires Couchbase 8.0+."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["username"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_user_unlock",
        description=(
            "Unlock a previously locked local user account (8.x). "
            "Requires Couchbase 8.0+."
        ),
        inputSchema={
            "type": "object",
            "properties": {"username": {"type": "string"}},
            "required": ["username"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_user_create_temporary",
        description=(
            "Create a local user with a temporary password (8.x). The user "
            "must rotate the password on first authentication. Equivalent to "
            "admin_user_create but with temporaryPassword=true. Requires "
            "Couchbase 8.0+."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "password": {"type": "string", "description": "Initial temp password"},
                "roles": {
                    "type": "string",
                    "description": "Comma-separated roles, e.g. 'data_reader[bucket:*:*]'",
                },
                "name": {"type": "string", "description": "Display name"},
                "groups": {"type": "string", "description": "Comma-separated groups"},
            },
            "required": ["username", "password", "roles"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    # ── XDCR conflict log readback ──────────────────────────────────────
    Tool(
        name="admin_xdcr_conflict_log_query",
        description=(
            "Query the XDCR conflict log collection (8.x). The conflict log "
            "must already be configured on the replication via "
            "admin_xdcr_replication_create with conflictLogging=true and a "
            "conflictLoggingMapping pointing at the target bucket/scope/collection. "
            "This tool reads from that collection. Requires Couchbase 8.0+."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "bucket_name": {
                    "type": "string",
                    "description": "Bucket where conflicts are logged",
                },
                "scope_name": {"type": "string", "description": "default: _default"},
                "collection_name": {
                    "type": "string",
                    "description": "default: _default",
                },
                "limit": {"type": "integer", "description": "default 50"},
            },
            "required": ["bucket_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    # ── Per-user query stats ────────────────────────────────────────────
]


# ── Handler dispatch ─────────────────────────────────────────────────────────


def handle(name: str, args: dict) -> list[TextContent]:
    gate = _require_8x(name)
    if gate is not None:
        return gate

    try:
        if name == "admin_vector_index_create_hyperscale":
            return _vec_hyperscale(args)

        if name == "admin_vector_index_create_composite":
            return _vec_composite(args)

        if name == "admin_user_lock":
            return _user_lock(args)

        if name == "admin_user_unlock":
            return _user_unlock(args)

        if name == "admin_user_create_temporary":
            return _user_temp(args)

        if name == "admin_xdcr_conflict_log_query":
            return _conflict_query(args)

        return err(f"Unknown 8.x tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)


# ── Tool implementations ─────────────────────────────────────────────────────


def _run_n1ql(statement: str) -> list[TextContent]:
    from couchbase.options import QueryOptions

    cluster = get_sdk_cluster()
    result = cluster.query(statement, QueryOptions())
    rows = list(result)
    return ok({"rows": rows, "count": len(rows), "statement": statement})


def _vec_hyperscale(args: dict) -> list[TextContent]:
    bad_sim = _validate_similarity(
        args["similarity"], "admin_vector_index_create_hyperscale"
    )
    if bad_sim:
        return bad_sim

    keyspace = _keyspace(
        args["bucket_name"], args.get("scope_name"), args.get("collection_name")
    )
    idx = _safe_ident(args["index_name"])
    field = _safe_ident(args["field_name"])
    with_clause = _with_clause(
        dimension=args["dimension"],
        similarity=args["similarity"],
        description=args.get("description"),
        num_replica=args.get("num_replica"),
        defer_build=args.get("defer_build"),
    )
    stmt = f"CREATE HYPERSCALE VECTOR INDEX {idx} ON {keyspace}({field} VECTOR){with_clause}"
    return _run_n1ql(stmt)


# A conservative regex for the optional WHERE predicate — disallows statement
# terminators that could be used to chain DDL. The cluster's SQL++ parser is
# the real defense; this is just an early sanity check.
# A semicolon check alone was the entire guard on this free-text SQL++ fragment.
# It stopped chaining and nothing else: "1=1 --" comments out the trailing WITH
# clause carrying the index's dimension and similarity, so the index built is not
# the one that was reviewed; "META().id IN (SELECT RAW k FROM `other` k)" reads
# across a keyspace boundary the tool never named; "myudf(x)=1" invokes a
# JavaScript UDF during the index build.
_WHERE_FORBID = re.compile(r"[;]|--|/\*|\(\s*SELECT\b", re.IGNORECASE)


def _vec_composite(args: dict) -> list[TextContent]:
    bad_sim = _validate_similarity(
        args["similarity"], "admin_vector_index_create_composite"
    )
    if bad_sim:
        return bad_sim

    scalar_fields = args["scalar_fields"]
    if not isinstance(scalar_fields, list) or not scalar_fields:
        return err(
            "scalar_fields must be a non-empty array",
            tool="admin_vector_index_create_composite",
        )

    where = args.get("where_clause") or ""
    if where and _WHERE_FORBID.search(where):
        return err(
            "where_clause may not contain semicolons or statement terminators",
            tool="admin_vector_index_create_composite",
            where_clause=where,
        )

    keyspace = _keyspace(
        args["bucket_name"], args.get("scope_name"), args.get("collection_name")
    )
    idx = _safe_ident(args["index_name"])
    vec = _safe_ident(args["vector_field"])
    scalar_list = ", ".join(_safe_ident(s) for s in scalar_fields)
    key_list = f"{scalar_list}, {vec} VECTOR"

    where_part = f" WHERE {where}" if where else ""
    with_clause = _with_clause(
        dimension=args["dimension"],
        similarity=args["similarity"],
        description=None,
        num_replica=args.get("num_replica"),
        defer_build=args.get("defer_build"),
    )
    stmt = f"CREATE COMPOSITE VECTOR INDEX {idx} ON {keyspace}({key_list}){where_part}{with_clause}"
    return _run_n1ql(stmt)


def _user_lock(args: dict) -> list[TextContent]:
    u = quote_path(args["username"])
    return ok(admin_request("POST", f"/settings/rbac/users/local/{u}/lock"))


def _user_unlock(args: dict) -> list[TextContent]:
    u = quote_path(args["username"])
    return ok(admin_request("POST", f"/settings/rbac/users/local/{u}/unlock"))


def _user_temp(args: dict) -> list[TextContent]:
    u = quote_path(args["username"])
    data = {
        "password": args["password"],
        "roles": args["roles"],
        "temporaryPassword": "true",
    }
    if args.get("name"):
        data["name"] = args["name"]
    if args.get("groups"):
        data["groups"] = args["groups"]
    return ok(admin_request("PUT", f"/settings/rbac/users/local/{u}", data=data))


def _conflict_query(args: dict) -> list[TextContent]:
    from couchbase.options import QueryOptions

    cluster = get_sdk_cluster()
    limit = int(args.get("limit", 50))
    keyspace = _keyspace(
        args["bucket_name"],
        args.get("scope_name"),
        args.get("collection_name"),
    )
    stmt = f"""
        SELECT META().id AS conflict_id, *
        FROM {keyspace}
        ORDER BY META().id DESC
        LIMIT $lim
    """
    result = cluster.query(stmt, QueryOptions(named_parameters={"lim": limit}))
    rows = list(result)
    return ok(
        {
            "conflicts": rows,
            "count": len(rows),
            "keyspace": keyspace,
            "note": (
                "If this returns empty, verify the replication was created with "
                "conflictLogging=true and conflictLoggingMapping pointing at this "
                "bucket/scope/collection. Conflicts that occurred before logging "
                "was enabled are not retrievable."
            ),
        }
    )
