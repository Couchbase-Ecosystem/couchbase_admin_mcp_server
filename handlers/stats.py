"""handlers/stats.py — Statistics, diagnostics, events, and system info tools.

Changes from upstream:
- Phase 1: ToolAnnotations. admin_internal_settings_set marked destructive
  (can wedge a cluster if misconfigured). admin_query_settings_set treated as
  routine write.
- Phase 2: Structured err() returns.
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .shared import admin_request, admin_request_json, err, form_data, ok, quote_path

#: queryTmpSpaceDir is a filesystem path the query service writes to, so this
#: endpoint is not a safe mass-assignment target either.
_QUERY_SETTINGS_KEYS: frozenset[str] = frozenset(
    {
        "queryTmpSpaceDir",
        "queryTmpSpaceSize",
        "queryPipelineBatch",
        "queryPipelineCap",
        "queryScanCap",
        "queryTimeout",
        "queryPreparedLimit",
        "queryCompletedLimit",
        "queryCompletedThreshold",
        "queryLogLevel",
        "queryMaxParallelism",
        "queryN1qlFeatCtrl",
        "queryTxTimeout",
        "queryMemoryQuota",
        "queryUseCBO",
        "queryCleanupClientAttempts",
        "queryCleanupLostAttempts",
        "queryCleanupWindow",
        "queryNumAtrs",
    }
)

TOOLS: list[Tool] = [
    Tool(
        name="admin_stats_bucket",
        description="Get statistics for a specific bucket.",
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
        name="admin_stats_single",
        description=(
            "Get a single Prometheus-style metric. metric_name examples: "
            "kv_num_items, index_ram_percent, n1ql_requests."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "metric_name": {"type": "string"},
                "bucket": {
                    "type": "string",
                    "description": "Optional bucket label filter",
                },
                "start": {
                    "type": "integer",
                    "description": "Unix timestamp start (optional)",
                },
                "end": {
                    "type": "integer",
                    "description": "Unix timestamp end (optional)",
                },
                "step": {
                    "type": "integer",
                    "description": "Step/resolution in seconds (optional)",
                },
            },
            "required": ["metric_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_stats_multi",
        description="Get multiple statistics in one call by posting a list of metric requests.",
        inputSchema={
            "type": "object",
            "properties": {
                "metrics": {
                    "type": "array",
                    "description": "List of metric request objects",
                    "items": {
                        "type": "object",
                        "properties": {
                            "metric": {
                                "type": "array",
                                "items": {"type": "object"},
                            },
                            "step": {"type": "integer"},
                            "start": {"type": "integer"},
                            "end": {"type": "integer"},
                        },
                    },
                }
            },
            "required": ["metrics"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_system_events",
        description="Get recent system events from the cluster event log.",
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max events to return (default 50)",
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
        name="admin_node_self_info",
        description="Get detailed information about the current node (storage, services, etc.).",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_internal_settings_get",
        description="Get internal cluster settings (advanced tuning parameters).",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_internal_settings_set",
        description=(
            "Update internal cluster settings. ADVANCED USE ONLY — misconfiguration "
            "can wedge a cluster. Requires confirm:true. Pass every tunable inside "
            'the `settings` object, e.g. {"settings": {"maxParallelIndexers": 4}}.'
        ),
        # `settings` is the ONLY accepted argument, and it is now declared. The schema
        # previously advertised five individual tunables that the handler refuses,
        # while requiring a `settings` object it never declared -- so the tool was
        # uncallable by any model that trusted its own schema.
        inputSchema={
            "type": "object",
            "properties": {
                "settings": {
                    "type": "object",
                    "description": (
                        "Tunables to change, as name/value pairs. Named explicitly "
                        "rather than spread across the argument list so the change is "
                        "reviewable in the audit record. /internalSettings is an "
                        "undocumented surface: only set what you can cite."
                    ),
                },
                "confirm": {"type": "boolean"},
            },
            "required": ["settings"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_query_settings_get",
        description="Get Query Service (N1QL) settings.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_query_settings_set",
        description=(
            "Update Query Service settings. Common keys: queryTmpSpaceDir, "
            "queryTmpSpaceSize, queryPipelineBatch, queryPipelineCap, "
            "queryScanCap, queryTimeout, queryPreparedLimit, queryCompletedLimit, "
            "queryLogLevel, queryMaxParallelism, queryN1qlFeatCtrl."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "queryTmpSpaceDir": {"type": "string"},
                "queryTmpSpaceSize": {"type": "integer"},
                "queryPipelineBatch": {"type": "integer"},
                "queryTimeout": {
                    "type": "integer",
                    "description": "Timeout in nanoseconds",
                },
                "queryLogLevel": {"type": "string"},
                "queryMaxParallelism": {"type": "integer"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_prometheus_targets",
        description="Get Prometheus scrape target discovery config for the cluster.",
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
        if name == "admin_stats_bucket":
            b = quote_path(args["bucket_name"])
            return ok(admin_request("GET", f"/pools/default/buckets/{b}/stats"))

        if name == "admin_stats_single":
            m = quote_path(args["metric_name"])
            params: dict = {}
            # `bucket` (and scope/collection where declared) are documented label
            # filters and were silently dropped, so a caller asking for one bucket's
            # metric got the cluster-wide value and was told it was that bucket's --
            # a wrong answer rather than a missing one.
            for k in ("start", "end", "step", "bucket", "scope", "collection"):
                if args.get(k) is not None:
                    params[k] = args[k]
            return ok(
                admin_request(
                    "GET",
                    f"/pools/default/stats/range/{m}",
                    params=params if params else None,
                )
            )

        if name == "admin_stats_multi":
            return ok(
                admin_request_json(
                    "POST", "/pools/default/stats/range", payload=args["metrics"]
                )
            )

        if name == "admin_system_events":
            # The endpoint takes its own `limit` query parameter and defaults to
            # 250. It was never sent, and the `result[:limit]` slice below was dead
            # code because /events answers with an OBJECT ({"events": [...]}), not an
            # array -- so every call dumped 250 events into the model's context. A
            # non-positive limit is clamped rather than honoured: limit=0 returned
            # nothing and limit=-3 silently dropped the last three.
            try:
                limit = int(args.get("limit", 50))
            except (TypeError, ValueError):
                limit = 50
            limit = max(1, limit)
            return ok(admin_request("GET", "/events", params={"limit": limit}))

        if name == "admin_node_self_info":
            return ok(admin_request("GET", "/nodes/self"))

        if name == "admin_internal_settings_get":
            return ok(admin_request("GET", "/internalSettings"))

        if name == "admin_internal_settings_set":
            # /internalSettings is an unbounded tunable surface that Couchbase does
            # not document as customer-facing, so the caller must name each key
            # deliberately via `settings` rather than having the whole argument
            # dict forwarded.
            # The schema used to declare five individual tunables that this handler
            # refuses, and required a `settings` object it did not declare -- so a
            # model reading the advertised schema could never call the tool
            # successfully and could only discover `settings` from this error text.
            # The schema now declares `settings` and nothing else.
            explicit = args.get("settings")
            if not isinstance(explicit, dict) or not explicit:
                return err(
                    "admin_internal_settings_set requires an explicit `settings` "
                    "object naming each tunable to change.",
                    tool=name,
                    hint=(
                        "Every argument used to be forwarded wholesale to "
                        "/internalSettings. Pass e.g. "
                        '{"settings": {"maxParallelIndexers": 4}} so the change is '
                        "reviewable."
                    ),
                )
            data = form_data(explicit)
            return ok(admin_request("POST", "/internalSettings", data=data))

        if name == "admin_query_settings_get":
            return ok(admin_request("GET", "/settings/querySettings"))

        if name == "admin_query_settings_set":
            unknown = sorted(
                k for k in args if k not in _QUERY_SETTINGS_KEYS and k != "confirm"
            )
            if unknown:
                return err(
                    f"Unrecognised query setting(s): {unknown}.",
                    tool=name,
                    hint=f"Permitted: {sorted(_QUERY_SETTINGS_KEYS)}.",
                )
            data = form_data(
                {k: v for k, v in args.items() if k in _QUERY_SETTINGS_KEYS}
            )
            return ok(admin_request("POST", "/settings/querySettings", data=data))

        if name == "admin_prometheus_targets":
            return ok(admin_request("GET", "/prometheus_sd_config"))

        return err(f"Unknown stats tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
