"""
Query-plan analysis: what `cb_explain_query` and the performance probes actually tell you.

WHY IT MATTERS
==============
These functions turn a Couchbase EXPLAIN plan into advice an operator acts on — "add a
secondary index", "the index is not covering", "a predicate was not pushed down". Advice
derived from a misread plan is worse than none: it sends someone to add an index that changes
nothing, or leaves a full primary scan in place because the operator was not recognised.

The plan tree is also awkwardly shaped. Couchbase nests children under `~child`, `~children`
and several other tilde-prefixed keys, at arbitrary depth, and the operator names are
versioned (`PrimaryScan`, `PrimaryScan2`, `PrimaryScan3`). A walker that missed a nesting key
or a version suffix would silently under-report.

The plans below are shaped like real EXPLAIN output rather than minimal stubs, because the
shape is the thing most likely to be got wrong.
"""

from __future__ import annotations

import json

import pytest
from mcp.types import TextContent

from handlers import diagnostics

# ── Realistic plan fragments ─────────────────────────────────────────────────

PRIMARY_SCAN_PLAN = {
    "plan": {
        "#operator": "Sequence",
        "~children": [
            {
                "#operator": "PrimaryScan3",
                "index": "#primary",
                "keyspace": "airline",
                "using": "gsi",
            },
            {"#operator": "Fetch", "keyspace": "airline"},
            {
                "#operator": "Parallel",
                "~child": {
                    "#operator": "Sequence",
                    "~children": [
                        {
                            "#operator": "Filter",
                            "condition": '(`airline`.`country` = "US")',
                        },
                        {
                            "#operator": "InitialProject",
                            "result_terms": [{"expr": "self"}],
                        },
                    ],
                },
            },
        ],
    }
}

COVERING_INDEX_PLAN = {
    "plan": {
        "#operator": "Sequence",
        "~children": [
            {
                "#operator": "IndexScan3",
                "index": "def_country",
                "index_id": "abc123",
                "covers": ["cover((`airline`.`country`))"],
                "keyspace": "airline",
            },
            {
                "#operator": "Parallel",
                "~child": {
                    "#operator": "Sequence",
                    "~children": [{"#operator": "InitialProject"}],
                },
            },
        ],
    }
}

NON_COVERING_PLAN = {
    "plan": {
        "#operator": "Sequence",
        "~children": [
            {"#operator": "IndexScan2", "index": "def_type", "keyspace": "airline"},
            {"#operator": "Fetch", "keyspace": "airline"},
            {
                "#operator": "Parallel",
                "~child": {
                    "#operator": "Sequence",
                    "~children": [
                        {"#operator": "Filter", "condition": "(`x` > 3)"},
                        {"#operator": "InitialProject"},
                    ],
                },
            },
        ],
    }
}


# ── Walking the tree ─────────────────────────────────────────────────────────


def test_every_operator_in_a_nested_plan_is_found():
    """`~children` inside `~child` inside `~children` is ordinary EXPLAIN output. A walker
    that only descended one named key would report a plan with no Filter."""
    operators = [n["#operator"] for n in diagnostics._walk_plan(PRIMARY_SCAN_PLAN)]
    assert "PrimaryScan3" in operators
    assert "Fetch" in operators
    assert "Filter" in operators, "a deeply nested operator was missed"
    assert "InitialProject" in operators


def test_only_nodes_with_an_operator_field_are_yielded():
    """The tree is full of dicts that are not operators — `covers`, `index_id`, condition
    expressions. Yielding those would put nonsense in the operator list."""
    for node in diagnostics._walk_plan(COVERING_INDEX_PLAN):
        assert "#operator" in node


def test_a_list_at_the_root_is_walked():
    """`cluster.query("EXPLAIN ...")` yields rows, and callers sometimes pass the row list."""
    operators = [n["#operator"] for n in diagnostics._walk_plan([PRIMARY_SCAN_PLAN])]
    assert "PrimaryScan3" in operators


@pytest.mark.parametrize("plan", [{}, [], None, "text", 42, {"no": "operators"}])
def test_a_degenerate_plan_yields_nothing_rather_than_raising(plan):
    """EXPLAIN output varies by version and by statement type. A TypeError here would surface
    as a tool crash on a query that ran perfectly well."""
    assert list(diagnostics._walk_plan(plan)) == []


def test_deep_nesting_does_not_overflow():
    """A generated query can nest deeply. This is a walker over untrusted structure."""
    node: dict = {"#operator": "Leaf"}
    for _ in range(200):
        node = {"#operator": "Sequence", "~children": [node]}
    found = [n["#operator"] for n in diagnostics._walk_plan(node)]
    assert found.count("Sequence") == 200
    assert "Leaf" in found


# ── Summarising ──────────────────────────────────────────────────────────────


def test_a_primary_scan_is_detected():
    """THE finding that matters most: the query has no usable secondary index and is reading
    every document."""
    summary = diagnostics._summarize_plan(PRIMARY_SCAN_PLAN)
    assert summary["has_primary_scan"] is True


@pytest.mark.parametrize("operator", ["PrimaryScan", "PrimaryScan2", "PrimaryScan3"])
def test_every_version_of_the_primary_scan_operator_is_recognised(operator):
    """Couchbase versions the operator name. Recognising only the newest spelling would miss
    a full scan on a 6.x or 7.0 cluster and report the query as fine."""
    summary = diagnostics._summarize_plan({"#operator": operator})
    assert summary["has_primary_scan"] is True, f"{operator} not recognised"


@pytest.mark.parametrize("operator", ["IndexScan", "IndexScan2", "IndexScan3"])
def test_every_version_of_the_index_scan_operator_is_recognised(operator):
    summary = diagnostics._summarize_plan({"#operator": operator, "index": "ix1"})
    assert summary["indexes_used"] == ["ix1"]
    assert summary["has_primary_scan"] is False


def test_the_index_names_used_are_collected():
    summary = diagnostics._summarize_plan(COVERING_INDEX_PLAN)
    assert summary["indexes_used"] == ["def_country"]


def test_a_non_string_index_name_is_ignored():
    """Defensive: the field comes from the cluster, and a list there would end up
    concatenated into a human-readable finding."""
    summary = diagnostics._summarize_plan(
        {"#operator": "IndexScan3", "index": ["not", "a", "string"]}
    )
    assert summary["indexes_used"] == []


def test_a_fetch_after_an_index_scan_means_the_index_is_not_covering():
    """The second most useful finding: the index was used but every row still costs a KV
    read."""
    summary = diagnostics._summarize_plan(NON_COVERING_PLAN)
    assert summary["has_fetch"] is True
    assert summary["indexes_used"] == ["def_type"]


def test_a_covering_scan_has_no_fetch():
    """Guards the test above from passing because Fetch is always reported."""
    summary = diagnostics._summarize_plan(COVERING_INDEX_PLAN)
    assert summary["has_fetch"] is False


def test_a_filter_after_a_scan_is_noted():
    """It means a predicate was not pushed down to the index — the index is doing less work
    than the operator thinks."""
    summary = diagnostics._summarize_plan(NON_COVERING_PLAN)
    assert summary["has_filter_after_scan"] is True


def test_a_filter_BEFORE_any_scan_is_not_a_pushdown_failure():
    """Ordering is the whole signal. A Filter that precedes the scan is not a missed
    pushdown, and reporting it as one sends the operator to add a field to an index that is
    already doing the work."""
    summary = diagnostics._summarize_plan(
        {
            "#operator": "Sequence",
            "~children": [
                {"#operator": "Filter", "condition": "(1 = 1)"},
                {"#operator": "IndexScan3", "index": "ix"},
            ],
        }
    )
    assert summary["has_filter_after_scan"] is False


def test_a_non_string_operator_is_skipped():
    summary = diagnostics._summarize_plan({"#operator": {"nested": "dict"}})
    assert summary["operators"] == []


def test_an_empty_plan_summarises_to_all_false():
    summary = diagnostics._summarize_plan({})
    assert summary["operators"] == []
    assert summary["has_primary_scan"] is False
    assert summary["has_fetch"] is False
    assert summary["has_filter_after_scan"] is False
    assert summary["indexes_used"] == []


# ── The advice itself ────────────────────────────────────────────────────────


def test_a_primary_scan_produces_advice_that_names_the_fix():
    findings = diagnostics._findings_for(diagnostics._summarize_plan(PRIMARY_SCAN_PLAN))
    joined = " ".join(findings)
    assert "secondary index" in joined
    assert "WHERE" in joined


def test_a_non_covering_index_produces_advice_about_covering():
    findings = diagnostics._findings_for(diagnostics._summarize_plan(NON_COVERING_PLAN))
    joined = " ".join(findings)
    assert "covering" in joined


def test_the_indexes_used_are_reported_and_deduplicated():
    """The same index appears once per scan operator in a UNION or a join. Repeating it three
    times in one line reads as three indexes."""
    findings = diagnostics._findings_for(
        {
            "operators": ["IndexScan3", "IndexScan3"],
            "indexes_used": ["ix1", "ix1", "ix2"],
            "has_primary_scan": False,
            "has_fetch": False,
            "has_filter_after_scan": False,
        }
    )
    line = next(f for f in findings if f.startswith("Indexes used"))
    assert line == "Indexes used: ix1, ix2"


def test_an_unparseable_plan_says_so_rather_than_reporting_no_problems():
    """THE dangerous silence. A plan the walker could not read produces no findings, and "no
    findings" reads as "this query is fine"."""
    findings = diagnostics._findings_for(diagnostics._summarize_plan({}))
    assert findings
    assert any("unparseable" in f or "empty" in f for f in findings)


def test_a_clean_plan_produces_no_alarms():
    """Guards the findings tests from passing because everything is flagged. A covering index
    scan with no fetch and no post-scan filter is the good case."""
    findings = diagnostics._findings_for(
        diagnostics._summarize_plan(COVERING_INDEX_PLAN)
    )
    joined = " ".join(findings)
    assert "Primary key scan" not in joined
    assert "not covering" not in joined
    assert "Filter applied after" not in joined


# ── The EXPLAIN fallback for cb_perf_using_primary_index ─────────────────────


class _FallbackCluster:
    """Answers the recent-queries probe, then an EXPLAIN per candidate."""

    def __init__(
        self, *, plans: dict, recent: list | None = None, raise_on_field=False
    ):
        self.plans = plans
        self.recent = (
            recent
            if recent is not None
            else [{"requestId": name, "statement": name} for name in plans]
        )
        self.raise_on_field = raise_on_field
        self.explained: list[str] = []

    def query(self, statement, options=None, *args, **kwargs):
        if statement.startswith("EXPLAIN "):
            candidate = statement[len("EXPLAIN ") :]
            self.explained.append(candidate)
            plan = self.plans.get(candidate)
            if isinstance(plan, Exception):
                raise plan
            return iter([plan])
        if self.raise_on_field:
            raise RuntimeError(
                "field 'usingPrimaryIndex' does not exist on this version"
            )
        return iter(self.recent)


def _body(result) -> dict:
    assert isinstance(result, list) and result
    assert isinstance(result[0], TextContent)
    return json.loads(result[0].text)


class _Options:
    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs


def test_the_fallback_flags_only_queries_with_a_primary_scan():
    """The direct probe reads a field that does not exist on every version, so the fallback
    EXPLAINs recent queries instead. It has to filter, or it reports every recent query as a
    problem."""
    cluster = _FallbackCluster(
        plans={
            "SELECT full scan": PRIMARY_SCAN_PLAN,
            "SELECT indexed": COVERING_INDEX_PLAN,
        }
    )
    body = _body(diagnostics._perf_primary_via_explain(cluster, _Options, limit=10))

    statements = [q["statement"] for q in body["queries"]]
    assert statements == ["SELECT full scan"]
    assert body["method"] == "explain_fallback"


def test_the_fallback_attaches_the_plan_summary_it_used():
    """So the operator can see WHY it was flagged rather than taking it on trust."""
    cluster = _FallbackCluster(plans={"SELECT full scan": PRIMARY_SCAN_PLAN})
    body = _body(diagnostics._perf_primary_via_explain(cluster, _Options, limit=10))
    assert body["queries"][0]["plan_summary"]["has_primary_scan"] is True


def test_a_statement_that_will_not_explain_is_skipped_not_fatal():
    """DDL and statements with unbound parameters cannot be EXPLAINed. One of those must not
    abort the whole probe — which would make the tool useless on any real cluster, since
    completed_requests contains plenty of both."""
    cluster = _FallbackCluster(
        plans={
            "CREATE INDEX ...": RuntimeError("syntax error near CREATE"),
            "SELECT full scan": PRIMARY_SCAN_PLAN,
        }
    )
    body = _body(diagnostics._perf_primary_via_explain(cluster, _Options, limit=10))
    assert [q["statement"] for q in body["queries"]] == ["SELECT full scan"]


def test_the_fallback_stops_at_the_limit():
    """It EXPLAINs up to three times the limit of candidates, and each EXPLAIN is a round
    trip. Without the early exit a limit of 5 on a busy cluster is 15 needless queries."""
    plans = {f"SELECT scan {i}": PRIMARY_SCAN_PLAN for i in range(20)}
    cluster = _FallbackCluster(plans=plans)
    body = _body(diagnostics._perf_primary_via_explain(cluster, _Options, limit=3))

    assert len(body["queries"]) == 3
    assert len(cluster.explained) == 3, (
        f"kept EXPLAINing after the limit was reached: {len(cluster.explained)}"
    )


def test_the_candidate_pool_is_wider_than_the_limit():
    """Most recent queries are already indexed, so pulling exactly `limit` candidates would
    usually return nothing at all. The pool is deliberately larger — asserted on the bound
    parameter actually sent, because the first version of this test asserted `True`, which is
    the sort of line that makes a suite look bigger without testing anything.
    """
    bound: list[dict] = []

    class _Recording(_FallbackCluster):
        def query(self, statement, options=None, *args, **kwargs):
            if not statement.startswith("EXPLAIN "):
                bound.append(getattr(options, "kwargs", {}).get("named_parameters", {}))
            return super().query(statement, options, *args, **kwargs)

    diagnostics._perf_primary_via_explain(
        _Recording(plans={}, recent=[]), _Options, limit=5
    )
    assert bound and bound[0]["lim"] > 5, f"candidate pool was not widened: {bound}"


def test_the_direct_probe_falls_back_when_the_field_is_missing(monkeypatch):
    """`usingPrimaryIndex` does not exist on older versions, and the RuntimeError it raises
    must become the fallback rather than a tool failure."""
    cluster = _FallbackCluster(
        plans={"SELECT full scan": PRIMARY_SCAN_PLAN}, raise_on_field=True
    )
    # The recent-query probe is the second call, so make it succeed.
    calls = {"n": 0}
    original = cluster.query

    def _query(statement, options=None, *args, **kwargs):
        if statement.startswith("EXPLAIN "):
            return original(statement, options)
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("field 'usingPrimaryIndex' does not exist")
        return iter([{"requestId": "r", "statement": "SELECT full scan"}])

    cluster.query = _query
    body = _body(diagnostics._perf_primary(cluster, _Options, {}))
    assert body["method"] == "explain_fallback", (
        "the version-portable fallback did not run, so this probe fails outright on any "
        "cluster without the newer field"
    )
