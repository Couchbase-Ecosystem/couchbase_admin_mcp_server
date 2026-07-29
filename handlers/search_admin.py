"""handlers/search_admin.py — Full-Text Search index administration.

Changes from upstream:
- Phase 1: ToolAnnotations. Delete and ingest pause/resume marked destructive.
- Phase 2: Uses unified admin_request_json for JSON-body endpoints.
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .shared import admin_request, admin_request_json, err, ok, quote_path

TOOLS: list[Tool] = [
    Tool(
        name="admin_fts_index_list",
        description="List all Full-Text Search indexes.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_fts_index_get",
        description="Get the definition of a specific FTS index.",
        inputSchema={
            "type": "object",
            "properties": {"index_name": {"type": "string"}},
            "required": ["index_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_fts_index_create",
        description=(
            "Create or update an FTS index. Pass the full index definition as "
            "a JSON object in 'definition'. Minimum required keys: name, type "
            "(fulltext-index), sourceName (bucket). For Couchbase 8.x vector "
            "search via FTS, use type 'fulltext-index' with a vector mapping."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "index_name": {"type": "string"},
                "definition": {
                    "type": "object",
                    "description": "Full FTS index JSON definition",
                },
            },
            "required": ["index_name", "definition"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_fts_index_delete",
        description="Delete a Full-Text Search index. Requires confirm:true.",
        inputSchema={
            "type": "object",
            "properties": {
                "index_name": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["index_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_fts_index_stats",
        description="Get statistics for a specific FTS index.",
        inputSchema={
            "type": "object",
            "properties": {"index_name": {"type": "string"}},
            "required": ["index_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_fts_index_doc_count",
        description="Get the document count for an FTS index.",
        inputSchema={
            "type": "object",
            "properties": {"index_name": {"type": "string"}},
            "required": ["index_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_fts_index_ingest_pause",
        description="Pause document ingestion for an FTS index.",
        inputSchema={
            "type": "object",
            "properties": {"index_name": {"type": "string"}},
            "required": ["index_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_fts_index_ingest_resume",
        description="Resume document ingestion for an FTS index.",
        inputSchema={
            "type": "object",
            "properties": {"index_name": {"type": "string"}},
            "required": ["index_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_fts_settings_get",
        description="Get global FTS (Search service) settings.",
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
        if name == "admin_fts_index_list":
            return ok(admin_request("GET", "/api/index"))

        if name == "admin_fts_index_get":
            ix = quote_path(args["index_name"])
            return ok(admin_request("GET", f"/api/index/{ix}"))

        if name == "admin_fts_index_create":
            defn = args["definition"]
            defn.setdefault("name", args["index_name"])
            ix = quote_path(args["index_name"])
            return ok(admin_request_json("PUT", f"/api/index/{ix}", payload=defn))

        if name == "admin_fts_index_delete":
            ix = quote_path(args["index_name"])
            return ok(admin_request("DELETE", f"/api/index/{ix}"))

        if name == "admin_fts_index_stats":
            ix = quote_path(args["index_name"])
            return ok(admin_request("GET", f"/api/index/{ix}/stats"))

        if name == "admin_fts_index_doc_count":
            ix = quote_path(args["index_name"])
            return ok(admin_request("GET", f"/api/index/{ix}/count"))

        if name == "admin_fts_index_ingest_pause":
            ix = quote_path(args["index_name"])
            return ok(admin_request("POST", f"/api/index/{ix}/ingestControl/pause"))

        if name == "admin_fts_index_ingest_resume":
            ix = quote_path(args["index_name"])
            return ok(admin_request("POST", f"/api/index/{ix}/ingestControl/resume"))

        if name == "admin_fts_settings_get":
            return ok(admin_request("GET", "/api/cfg"))

        return err(f"Unknown FTS admin tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
