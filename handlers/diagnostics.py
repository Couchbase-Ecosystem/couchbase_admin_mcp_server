"""handlers/diagnostics.py — Phase 4: schema discovery, query analytics, EXPLAIN.

Adds the tools the official Couchbase MCP exposes that this MCP was missing:
- cb_get_schema_for_collection         (schema sampling via OBJECT_PAIRS)
- cb_index_advisor                      (wraps the ADVISOR() function)
- cb_explain_query                      (EXPLAIN + parsed findings)
- cb_perf_longest_running              (system:completed_requests slow)
- cb_perf_most_frequent                (system:completed_requests grouped)
- cb_perf_largest_responses            (by resultSize)
- cb_perf_large_result_count           (by resultCount)
- cb_perf_using_primary_index          (heuristic: phase operators / EXPLAIN)
- cb_perf_not_using_covering_index     (heuristic: Fetch in plan)
- cb_perf_not_selective                (heuristic: high result count vs scan)

Naming convention: `cb_` prefix matches the existing data-plane style. The
official Couchbase MCP names (without prefix) are noted in each tool description
so users migrating between servers can find the equivalent.

All tools are read-only — they SELECT from system catalogs or wrap EXPLAIN. None
mutate the cluster. They are loaded in both read-only and read-write mode.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

from logging_config import get_logger

from .shared import (
    assert_read_only_statement,
    err,
    get_sdk_connection,
    ok,
)

_log = get_logger("handlers.diagnostics")

# ── Plan-tree walking ────────────────────────────────────────────────────────


def _walk_plan(node: Any) -> Iterable[dict]:
    """Yield every dict in the plan tree that has a `#operator` field."""
    if isinstance(node, dict):
        if "#operator" in node:
            yield node
        for k, v in node.items():
            # Couchbase plan trees use `~child`, `~children`, etc. for nesting.
            if isinstance(v, (dict, list)):
                yield from _walk_plan(v)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_plan(item)


_PRIMARY_SCAN_OPS = {"PrimaryScan", "PrimaryScan2", "PrimaryScan3"}
_INDEX_SCAN_OPS = {"IndexScan", "IndexScan2", "IndexScan3"}


def _summarize_plan(plan_root: Any) -> dict:
    """Walk an EXPLAIN plan tree and return a structured summary."""
    operators: list[str] = []
    indexes_used: list[str] = []
    has_primary_scan = False
    has_fetch = False
    has_filter_after_scan = False
    saw_scan = False

    for node in _walk_plan(plan_root):
        op = node.get("#operator")
        if not isinstance(op, str):
            continue
        operators.append(op)
        if op in _PRIMARY_SCAN_OPS:
            has_primary_scan = True
            saw_scan = True
        if op in _INDEX_SCAN_OPS:
            saw_scan = True
            idx = node.get("index")
            if isinstance(idx, str):
                indexes_used.append(idx)
        if op == "Fetch":
            has_fetch = True
        if op == "Filter" and saw_scan:
            has_filter_after_scan = True

    return {
        "operators": operators,
        "indexes_used": indexes_used,
        "has_primary_scan": has_primary_scan,
        "has_fetch": has_fetch,
        "has_filter_after_scan": has_filter_after_scan,
    }


def _findings_for(summary: dict) -> list[str]:
    """Produce human-readable findings from a plan summary."""
    f: list[str] = []
    if summary["has_primary_scan"]:
        f.append(
            "Primary key scan detected — the query has no usable secondary index. "
            "Add a secondary index on the WHERE-clause fields to avoid scanning every document."
        )
    if summary["indexes_used"]:
        f.append("Indexes used: " + ", ".join(sorted(set(summary["indexes_used"]))))
    if summary["has_fetch"]:
        f.append(
            "Fetch operator present — the index is not covering. Either include "
            "all selected fields in the index for a covering scan, or accept the "
            "extra KV read per row."
        )
    if summary["has_filter_after_scan"]:
        f.append(
            "Filter applied after the scan — at least one predicate was not "
            "pushed down to the index. Consider adding the missing field(s) to "
            "the index."
        )
    if not summary["operators"]:
        f.append("Plan was empty or unparseable; check the EXPLAIN output directly.")
    return f


# ── Identifier quoting (mirrors handlers/indexes.py) ─────────────────────────


def _safe_ident(s: str) -> str:
    return "`" + (s or "").replace("`", "``") + "`"


def _keyspace(bucket: str, scope: str | None, coll: str | None) -> str:
    return f"{_safe_ident(bucket)}.{_safe_ident(scope or '_default')}.{_safe_ident(coll or '_default')}"


# ── Tool definitions ─────────────────────────────────────────────────────────

TOOLS: list[Tool] = [
    Tool(
        name="cb_get_schema_for_collection",
        description=(
            "Sample documents from a collection and infer the schema "
            "(field names + value types + how often each field appears). "
            "Equivalent to the official Couchbase MCP's `get_schema_for_collection`."
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
                "sample_size": {
                    "type": "integer",
                    "description": "How many docs to sample (default 100)",
                },
            },
            "required": ["bucket_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="cb_index_advisor",
        description=(
            "Run the ADVISOR() SQL++ function on one or more statements to get "
            "recommended indexes. Equivalent to the official Couchbase MCP's "
            "`get_index_advisor_recommendations`."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "statements": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of SQL++ statements to analyze",
                },
            },
            "required": ["statements"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="cb_explain_query",
        description=(
            "EXPLAIN a SQL++ query and return both the raw plan and a structured "
            "summary with findings (used indexes, primary scan, non-covering fetch, "
            "filter pushdown). Equivalent to the official Couchbase MCP's "
            "`explain_sql_plus_plus_query`."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "statement": {"type": "string"},
                "params": {
                    "type": "object",
                    "description": "Named parameters for the statement",
                },
            },
            "required": ["statement"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="cb_perf_longest_running",
        description=(
            "Return the longest-running queries from system:completed_requests, "
            "ordered by elapsedTime. Equivalent to the official Couchbase MCP's "
            "`get_longest_running_queries`."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "default 20"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="cb_perf_most_frequent",
        description=(
            "Group completed queries by statement and return the most frequent. "
            "Equivalent to the official Couchbase MCP's `get_most_frequent_queries`."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "default 20"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="cb_perf_largest_responses",
        description=(
            "Return queries with the largest resultSize (bytes returned to client). "
            "Equivalent to the official Couchbase MCP's `get_queries_with_largest_response_sizes`."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "default 20"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="cb_perf_large_result_count",
        description=(
            "Return queries that returned more than `threshold` rows. Equivalent "
            "to the official Couchbase MCP's `get_queries_with_large_result_count`."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "threshold": {"type": "integer", "description": "default 1000"},
                "limit": {"type": "integer", "description": "default 20"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="cb_perf_using_primary_index",
        description=(
            "Return queries that used a primary key scan (PrimaryScan operator). "
            "Detection is heuristic — uses the `phaseOperators` field from "
            "system:completed_requests when available, plus a statement-pattern "
            "fallback. Some primary scans may be missed; verify with cb_explain_query. "
            "Equivalent to the official Couchbase MCP's `get_queries_using_primary_index`."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "default 20"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="cb_perf_not_using_covering_index",
        description=(
            "Return recent queries where Fetch was present in the plan (the index "
            "did not cover all selected fields). Re-runs EXPLAIN on the most recent "
            "N queries to inspect plans; can be slow for large N. Equivalent to "
            "the official Couchbase MCP's `get_queries_not_using_covering_index`."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "How many recent queries to inspect (default 20)",
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
        name="cb_perf_not_selective",
        description=(
            "Return queries where the index scan returned many candidates relative "
            "to the final result count (high `~phaseCounts.indexScan` vs `resultCount`). "
            "Indicates a non-selective predicate. Equivalent to the official "
            "Couchbase MCP's `get_queries_not_selective`."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "min_scan_count": {
                    "type": "integer",
                    "description": "Minimum scan rows to flag (default 1000)",
                },
                "max_ratio": {
                    "type": "number",
                    "description": "Maximum result/scan ratio to flag (default 0.1)",
                },
                "limit": {"type": "integer", "description": "default 20"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
]


# ── Handler dispatch ─────────────────────────────────────────────────────────


def _validate_statement_args(name: str, args: dict) -> list[TextContent] | None:
    """Validate caller-supplied SQL++ BEFORE any connection is made.

    Ordering matters. These checks previously ran after ``get_sdk_connection()``,
    so a mutating or chained statement got as far as the cluster's doorstep before
    being refused, and a refusal required a working cluster to produce. Validation
    that costs nothing belongs before the step that costs a connection.

    The diagnostic tools are read-only PERIOD — they do not consult
    CB_ADMIN_READ_ONLY_MODE, because there is no configuration under which a debug
    tool should modify data. Writes go through the purpose-built admin_* tools,
    which are annotated, gated and audited as writes.
    """
    if name == "cb_explain_query":
        statement = args.get("statement")
        if not isinstance(statement, str) or not statement.strip():
            return err("statement must be a non-empty SQL++ string", tool=name)
        inner = re.sub(r"(?i)^\s*EXPLAIN\s+", "", statement.lstrip())
        blocked = assert_read_only_statement(inner, tool=name)
        if blocked:
            return err(blocked, tool=name)

    if name == "cb_index_advisor":
        statements = args.get("statements")
        if not isinstance(statements, list) or not statements:
            return err(
                "statements must be a non-empty array of SQL++ strings", tool=name
            )
        # Element TYPES were never checked, only that the container was a list.
        # ADVISOR() also accepts a session-control object ({"action": "purge"}), so
        # a dict element reached the function as a control command from a tool
        # annotated read-only.
        non_strings = [type(x).__name__ for x in statements if not isinstance(x, str)]
        if non_strings:
            return err(
                f"statements must contain only SQL++ strings; got {non_strings}.",
                tool=name,
                hint=(
                    "ADVISOR() also accepts a session-control object, so non-string "
                    "elements are refused rather than forwarded."
                ),
            )
        for candidate in statements:
            blocked = assert_read_only_statement(candidate, tool=name)
            if blocked:
                return err(blocked, tool=name)

    return None


def handle(name: str, args: dict) -> list[TextContent]:
    refusal = _validate_statement_args(name, args)
    if refusal is not None:
        return refusal

    try:
        cluster, _, _ = get_sdk_connection()
    except Exception as exc:
        return err(f"Couchbase connection failed: {exc}", tool=name)

    try:
        # Inside the try. This import used to sit above it, so an ImportError escaped
        # handle() uncaught and surfaced as a traceback out of the MCP transport rather than
        # as an error response the model can read. Every other handler in this project
        # returns err() for anything that goes wrong; this was the one exit that did not.
        from couchbase.options import QueryOptions

        if name == "cb_get_schema_for_collection":
            return _schema(cluster, QueryOptions, args)

        if name == "cb_index_advisor":
            return _advisor(cluster, QueryOptions, args)

        if name == "cb_explain_query":
            return _explain(cluster, QueryOptions, args)

        if name == "cb_perf_longest_running":
            return _perf_longest(cluster, QueryOptions, args)

        if name == "cb_perf_most_frequent":
            return _perf_frequent(cluster, QueryOptions, args)

        if name == "cb_perf_largest_responses":
            return _perf_largest_responses(cluster, QueryOptions, args)

        if name == "cb_perf_large_result_count":
            return _perf_large_count(cluster, QueryOptions, args)

        if name == "cb_perf_using_primary_index":
            return _perf_primary(cluster, QueryOptions, args)

        if name == "cb_perf_not_using_covering_index":
            return _perf_not_covering(cluster, QueryOptions, args)

        if name == "cb_perf_not_selective":
            return _perf_not_selective(cluster, QueryOptions, args)

        return err(f"Unknown diagnostics tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)


# ── Tool implementations ─────────────────────────────────────────────────────


def _schema(cluster, QueryOptions, args: dict) -> list[TextContent]:
    bucket = args["bucket_name"]
    scope = args.get("scope_name") or "_default"
    coll = args.get("collection_name") or "_default"
    sample_size = int(args.get("sample_size", 100))

    keyspace = _keyspace(bucket, scope, coll)
    stmt = f"""
        SELECT pair.name AS field,
               type(pair.val) AS field_type,
               COUNT(*) AS occurrences
        FROM (SELECT d.* FROM {keyspace} d LIMIT $sample) AS sample
        UNNEST OBJECT_PAIRS(sample) AS pair
        GROUP BY pair.name, type(pair.val)
        ORDER BY pair.name, occurrences DESC
    """
    result = cluster.query(stmt, QueryOptions(named_parameters={"sample": sample_size}))
    rows = list(result)

    # Group by field name for an easier-to-read shape
    fields: dict[str, dict[str, Any]] = {}
    for r in rows:
        name = r["field"]
        ft = r["field_type"]
        n = r["occurrences"]
        if name not in fields:
            fields[name] = {"types": {}, "total_occurrences": 0}
        fields[name]["types"][ft] = n
        fields[name]["total_occurrences"] += n

    field_list = sorted(
        ({"name": k, **v} for k, v in fields.items()),
        key=lambda f: -f["total_occurrences"],
    )
    return ok(
        {
            "keyspace": f"{bucket}.{scope}.{coll}",
            "sample_size": sample_size,
            "field_count": len(fields),
            "fields": field_list,
        }
    )


def _advisor(cluster, QueryOptions, args: dict) -> list[TextContent]:
    statements = args["statements"]
    if not isinstance(statements, list) or not statements:
        return err(
            "statements must be a non-empty array of SQL++ strings",
            tool="cb_index_advisor",
        )
    # Item TYPES were never validated — only that the container was a list. ADVISOR
    # also accepts a session-control object ({"action": "purge"|"stop"}), so a
    # non-string element reached the function as a control command from a tool
    # annotated read-only.
    non_strings = [type(x).__name__ for x in statements if not isinstance(x, str)]
    if non_strings:
        return err(
            f"statements must contain only SQL++ strings; got {non_strings}.",
            tool="cb_index_advisor",
            hint=(
                "ADVISOR() also accepts a session-control object, so non-string "
                "elements are refused rather than forwarded."
            ),
        )
    for candidate in statements:
        blocked = assert_read_only_statement(candidate, tool="cb_index_advisor")
        if blocked:
            return err(blocked, tool="cb_index_advisor")
    # ADVISOR accepts a single string or an array. Pass the array directly.
    stmt = "SELECT ADVISOR($stmts) AS recommendations"
    result = cluster.query(stmt, QueryOptions(named_parameters={"stmts": statements}))
    rows = list(result)
    return ok({"input_statements": statements, "advisor": rows})


def _explain(cluster, QueryOptions, args: dict) -> list[TextContent]:
    statement = args["statement"]
    params = args.get("params") or {}
    stripped = statement.lstrip()
    # ALWAYS prepend EXPLAIN. The previous branch forwarded the caller's string
    # verbatim whenever it already began with EXPLAIN, so
    # "EXPLAIN SELECT 1; UPDATE `b` SET x=1" reached the query service unchecked,
    # with only its single-statement rule standing in the way.
    inner = re.sub(r"(?i)^\s*EXPLAIN\s+", "", stripped)

    # Unconditional, not read-only-mode dependent: a debug tool has no business
    # executing a mutation under any configuration.
    blocked = assert_read_only_statement(inner, tool="cb_explain_query")
    if blocked:
        return err(blocked, tool="cb_explain_query")

    explain_stmt = "EXPLAIN " + inner
    result = cluster.query(explain_stmt, QueryOptions(named_parameters=params))
    rows = list(result)
    plan_root = rows[0] if rows else {}
    summary = _summarize_plan(plan_root)
    findings = _findings_for(summary)
    return ok(
        {
            "statement": statement,
            "explain_plan": plan_root,
            "summary": summary,
            "findings": findings,
        }
    )


def _perf_longest(cluster, QueryOptions, args: dict) -> list[TextContent]:
    limit = int(args.get("limit", 20))
    stmt = """
        SELECT requestId, statement, users, elapsedTime, executionTime,
               resultCount, resultSize, state, requestTime
        FROM system:completed_requests
        ORDER BY STR_TO_DURATION(elapsedTime) DESC
        LIMIT $lim
    """
    return _safe_query(
        cluster, QueryOptions, stmt, {"lim": limit}, "cb_perf_longest_running"
    )


def _perf_frequent(cluster, QueryOptions, args: dict) -> list[TextContent]:
    limit = int(args.get("limit", 20))
    stmt = """
        SELECT statement,
               COUNT(*) AS execution_count,
               MIN(elapsedTime) AS min_elapsed,
               MAX(elapsedTime) AS max_elapsed,
               AVG(STR_TO_DURATION(elapsedTime)) AS avg_elapsed_ns
        FROM system:completed_requests
        GROUP BY statement
        ORDER BY execution_count DESC
        LIMIT $lim
    """
    return _safe_query(
        cluster, QueryOptions, stmt, {"lim": limit}, "cb_perf_most_frequent"
    )


def _perf_largest_responses(cluster, QueryOptions, args: dict) -> list[TextContent]:
    limit = int(args.get("limit", 20))
    stmt = """
        SELECT requestId, statement, resultSize, resultCount, elapsedTime
        FROM system:completed_requests
        WHERE resultSize IS NOT MISSING
        ORDER BY resultSize DESC
        LIMIT $lim
    """
    return _safe_query(
        cluster, QueryOptions, stmt, {"lim": limit}, "cb_perf_largest_responses"
    )


def _perf_large_count(cluster, QueryOptions, args: dict) -> list[TextContent]:
    limit = int(args.get("limit", 20))
    threshold = int(args.get("threshold", 1000))
    stmt = """
        SELECT requestId, statement, resultCount, elapsedTime
        FROM system:completed_requests
        WHERE resultCount > $thresh
        ORDER BY resultCount DESC
        LIMIT $lim
    """
    return _safe_query(
        cluster,
        QueryOptions,
        stmt,
        {"thresh": threshold, "lim": limit},
        "cb_perf_large_result_count",
    )


def _perf_primary(cluster, QueryOptions, args: dict) -> list[TextContent]:
    """Heuristic: find queries whose plan included a PrimaryScan operator.

    Field shape varies by Couchbase version. We probe ~phaseOperators (which
    is a map of operator->count in 7.0+), and fall back to a statement-pattern
    match against statements that select on fields without obvious predicates.
    """
    limit = int(args.get("limit", 20))
    # Primary attempt: ~phaseOperators map contains a "PrimaryScan*" key.
    stmt = """
        SELECT requestId, statement, elapsedTime, resultCount,
               OBJECT_NAMES(`~phaseOperators`) AS ops_used
        FROM system:completed_requests
        WHERE ANY n IN OBJECT_NAMES(`~phaseOperators`)
              SATISFIES LOWER(n) LIKE "%primaryscan%" END
        ORDER BY requestTime DESC
        LIMIT $lim
    """
    try:
        return _safe_query(
            cluster,
            QueryOptions,
            stmt,
            {"lim": limit},
            "cb_perf_using_primary_index",
        )
    except Exception:
        # `except RuntimeError` here was DEAD: the callee is the Couchbase SDK, whose
        # errors derive from CouchbaseException, and issubclass(CouchbaseException,
        # RuntimeError) is False. So on any cluster lacking ~phaseOperators the raw SDK
        # error propagated instead of taking this version-portable fallback -- and the
        # test that "covered" it fabricated a RuntimeError the SDK never raises.
        return _perf_primary_via_explain(cluster, QueryOptions, limit)


def _perf_primary_via_explain(cluster, QueryOptions, limit: int) -> list[TextContent]:
    """Slower fallback: pull recent queries, EXPLAIN each, filter PrimaryScan."""
    recent_stmt = """
        SELECT requestId, statement, elapsedTime, resultCount
        FROM system:completed_requests
        WHERE statement IS NOT MISSING
        ORDER BY requestTime DESC
        LIMIT $lim
    """
    result = cluster.query(
        recent_stmt, QueryOptions(named_parameters={"lim": limit * 3})
    )
    candidates = list(result)
    flagged = []
    for cand in candidates:
        try:
            ex = cluster.query("EXPLAIN " + cand["statement"], QueryOptions())
            plan = next(iter(ex), {})
            summary = _summarize_plan(plan)
            if summary["has_primary_scan"]:
                cand["plan_summary"] = summary
                flagged.append(cand)
            if len(flagged) >= limit:
                break
        except Exception as e:
            # Skip statements that won't EXPLAIN (DDL, parameter binding issues, etc.)
            _log.debug("skipping un-explainable statement: %s", e)
            continue
    return ok(
        {
            "queries": flagged,
            "method": "explain_fallback",
            "note": "phaseOperators field not available on this cluster; ran EXPLAIN per query.",
        }
    )


def _perf_not_covering(cluster, QueryOptions, args: dict) -> list[TextContent]:
    limit = int(args.get("limit", 20))
    # Pull recent queries and EXPLAIN each, flag those with Fetch in plan.
    recent_stmt = """
        SELECT requestId, statement, elapsedTime, resultCount
        FROM system:completed_requests
        WHERE statement IS NOT MISSING
          AND UPPER(statement) LIKE "SELECT%"
        ORDER BY requestTime DESC
        LIMIT $lim
    """
    result = cluster.query(
        recent_stmt, QueryOptions(named_parameters={"lim": limit * 3})
    )
    candidates = list(result)
    flagged = []
    for cand in candidates:
        try:
            ex = cluster.query("EXPLAIN " + cand["statement"], QueryOptions())
            plan = next(iter(ex), {})
            summary = _summarize_plan(plan)
            if summary["has_fetch"]:
                cand["plan_summary"] = summary
                cand["findings"] = _findings_for(summary)
                flagged.append(cand)
            if len(flagged) >= limit:
                break
        except Exception as e:
            _log.debug("skipping un-explainable statement: %s", e)
            continue
    return ok(
        {
            "queries": flagged,
            "note": (
                "Fetch operator indicates the index is not covering. To remove the "
                "Fetch, ensure all SELECTed fields are in the index keys."
            ),
        }
    )


def _perf_not_selective(cluster, QueryOptions, args: dict) -> list[TextContent]:
    """Find queries where the index scan returned many rows but the final
    result was a small fraction — predicate not selective."""
    min_scan = int(args.get("min_scan_count", 1000))
    max_ratio = float(args.get("max_ratio", 0.1))
    limit = int(args.get("limit", 20))
    # ~phaseCounts.indexScan / IndexScan / primaryScan are typical fields.
    # If unavailable, fall back to comparing resultCount to high-bound estimate.
    stmt = """
        SELECT requestId, statement, elapsedTime, resultCount,
               `~phaseCounts` AS phase_counts
        FROM system:completed_requests
        WHERE `~phaseCounts` IS NOT MISSING
          AND resultCount IS NOT MISSING
        ORDER BY requestTime DESC
        LIMIT $lim
    """
    try:
        result = cluster.query(stmt, QueryOptions(named_parameters={"lim": limit * 5}))
    except Exception as exc:
        return err(
            "~phaseCounts field not available on this Couchbase version; "
            "cannot compute selectivity heuristic.",
            tool="cb_perf_not_selective",
            cause=str(exc),
        )

    flagged = []
    for r in result:
        pc = r.get("phase_counts") or {}
        scan_count = 0
        for k, v in pc.items():
            if "scan" in k.lower() and isinstance(v, (int, float)):
                scan_count = max(scan_count, int(v))
        rc = r.get("resultCount", 0) or 0
        if scan_count >= min_scan and rc <= scan_count * max_ratio:
            r["scan_count"] = scan_count
            r["selectivity_ratio"] = (rc / scan_count) if scan_count else None
            flagged.append(r)
        if len(flagged) >= limit:
            break

    return ok(
        {
            "queries": flagged,
            "threshold": {"min_scan_count": min_scan, "max_ratio": max_ratio},
            "note": (
                "Low selectivity means the index scan returned far more rows than "
                "the final result. Tighten predicates or add a more selective index."
            ),
        }
    )


# ── Shared query helper ──────────────────────────────────────────────────────


def _safe_query(
    cluster, QueryOptions, stmt: str, params: dict, tool_name: str
) -> list[TextContent]:
    result = cluster.query(stmt, QueryOptions(named_parameters=params))
    rows = list(result)
    return ok({"queries": rows, "count": len(rows)})
