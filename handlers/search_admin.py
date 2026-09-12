"""handlers/search_admin.py — Full-Text Search index administration.

Changes from upstream:
- Phase 1: ToolAnnotations. Delete and ingest pause/resume marked destructive.
- Phase 2: Uses unified admin_request_json for JSON-body endpoints.
- Every path carries the ns_server proxy prefix. See below.

THE PROXY PREFIX, AND WHY EVERY PATH HERE WAS WRONG
===================================================
`admin_request()` talks to the MANAGEMENT port. A service's own REST API is not
served there: it is reached through ns_server's proxy prefix, which is why
eventing.py uses `/_p/event/api/v1` and backup.py uses `/_p/backup/...`.

This module used bare `/api/index` and `/api/cfg`, so every one of its nine tools
answered 404 against any cluster — including one demonstrably running the Search
service. Not an environment problem and not a missing service: the request never
reached Search at all.

Measured on a local Enterprise 8.0.1 cluster with fts on the node, 2026-09-12:

    GET :8091/api/index            404   (as shipped)
    GET :8091/_p/fts/api/index     200   {"status":"ok","indexDefs":{...}}
    GET :8094/api/index            200   (the Search port directly)

The proxy form is used rather than port 8094 because `admin_request()` has one
destination and this module does not get to choose a different one — and because
it is the form the two sibling modules already use, so one rule now covers all
three.

Found by scripts/verify_mcp_surface.py, which called these tools through a real
MCP client for the first time. No unit test could have caught it: they all mock
admin_request and assert on the path string that was passed, which is precisely
the string that was wrong.
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .egress import guard_nested_host_fields
from .shared import admin_request, admin_request_json, err, ok, quote_path

#: ns_server's proxy prefix for the Search service.
#:
#: Named once rather than spelled at nine call sites: the defect this fixes was
#: the prefix being absent from all nine, and a constant makes the next one
#: impossible to forget by omission.
_FTS = "/_p/fts"

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
            destructiveHint=True,
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
            return ok(admin_request("GET", f"{_FTS}/api/index"))

        if name == "admin_fts_index_get":
            ix = quote_path(args["index_name"])
            return ok(admin_request("GET", f"{_FTS}/api/index/{ix}"))

        if name == "admin_fts_index_create":
            defn = args["definition"]
            if not isinstance(defn, dict):
                return err(
                    "`definition` must be a JSON object holding the full FTS index "
                    "definition.",
                    tool=name,
                )
            defn.setdefault("name", args["index_name"])
            # Egress guard on the free-form definition, matching eventing's
            # `definition` and backup's `target`. This was the one free-form JSON sink
            # in the admin surface with no guard, so a definition whose source
            # parameters name an off-cluster host went to the Search service
            # unchecked -- the same shape the other two sinks are guarded against.
            guard_nested_host_fields(defn, tool=name, path="definition")
            ix = quote_path(args["index_name"])
            return ok(admin_request_json("PUT", f"{_FTS}/api/index/{ix}", payload=defn))

        if name == "admin_fts_index_delete":
            ix = quote_path(args["index_name"])
            return ok(admin_request("DELETE", f"{_FTS}/api/index/{ix}"))

        if name == "admin_fts_index_stats":
            ix = quote_path(args["index_name"])
            return ok(admin_request("GET", f"{_FTS}/api/index/{ix}/stats"))

        if name == "admin_fts_index_doc_count":
            ix = quote_path(args["index_name"])
            return ok(admin_request("GET", f"{_FTS}/api/index/{ix}/count"))

        if name == "admin_fts_index_ingest_pause":
            ix = quote_path(args["index_name"])
            return ok(
                admin_request("POST", f"{_FTS}/api/index/{ix}/ingestControl/pause")
            )

        if name == "admin_fts_index_ingest_resume":
            ix = quote_path(args["index_name"])
            return ok(
                admin_request("POST", f"{_FTS}/api/index/{ix}/ingestControl/resume")
            )

        if name == "admin_fts_settings_get":
            return ok(admin_request("GET", f"{_FTS}/api/cfg"))

        return err(f"Unknown FTS admin tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
