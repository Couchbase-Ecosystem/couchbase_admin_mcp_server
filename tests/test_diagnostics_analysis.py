"""The diagnostic tools' analysis, as distinct from the statements they send.

These tools read the query service's own completed-requests log and turn it into
findings. The statements are already guarded elsewhere; what is not covered is
what happens to the ROWS -- the grouping, the thresholds, and the two places a
result is shaped into a verdict:

  * `cb_schema_infer` groups INFER's per-type rows by field name, because a field
    that is a string in 90 percent of documents and an object in the rest is the
    finding, and a flat row list hides it.
  * `cb_perf_not_selective` divides a result count by a scan count. A version of
    Couchbase without ~phaseCounts cannot answer at all, and the refusal has to
    say that rather than reporting "no problems found" -- the two are opposite
    conclusions from the same absence of rows.
  * `cb_perf_not_covering` EXPLAINs each candidate and skips the ones that will
    not explain. A statement that fails to parse is not a finding about the
    cluster, so it is skipped rather than surfaced or allowed to abort the sweep.

The cluster is a stub. These assert the analysis, not the SQL.
"""

from __future__ import annotations

import json

import pytest

from handlers import diagnostics
from handlers.shared import ERROR_MARKER


def payload(result) -> dict:
    return json.loads(result[0].text)


def is_error(result) -> bool:
    return payload(result).get(ERROR_MARKER) is True


class _Cluster:
    """Answers query() from a script keyed on a fragment of the statement."""

    def __init__(self, script=None, error=None):
        self.script = script or []
        self.error = error
        self.statements: list[str] = []

    def query(self, statement, options=None):
        self.statements.append(statement)
        if self.error:
            raise RuntimeError(self.error)
        for fragment, rows in self.script:
            if fragment in statement:
                if isinstance(rows, Exception):
                    raise rows
                return iter(rows)
        return iter([])


def _options(*args, **kwargs):
    return None


# ── cb_schema_infer: the grouping IS the finding ─────────────────────────────


def test_inferred_fields_are_grouped_by_name_with_their_types(monkeypatch):
    """A field that is a string in most documents and an object in the rest is
    the thing worth seeing, and a flat row list hides it."""
    cluster = _Cluster(
        [
            (
                "OBJECT_PAIRS",
                [
                    {"field": "name", "field_type": "string", "occurrences": 90},
                    {"field": "name", "field_type": "object", "occurrences": 10},
                    {"field": "id", "field_type": "number", "occurrences": 200},
                ],
            )
        ]
    )
    body = payload(
        diagnostics._schema(
            cluster,
            _options,
            {"bucket_name": "b", "scope_name": "s", "collection_name": "c"},
        )
    )
    fields = {f["name"]: f for f in body["fields"]}
    assert fields["name"]["types"] == {"string": 90, "object": 10}
    assert fields["name"]["total_occurrences"] == 100
    assert body["keyspace"] == "b.s.c"


def test_fields_are_ordered_by_how_often_they_appear(monkeypatch):
    """The commonest field first, so a reader sees the shape of the collection
    rather than an alphabetical accident."""
    cluster = _Cluster(
        [
            (
                "OBJECT_PAIRS",
                [
                    {"field": "rare", "field_type": "string", "occurrences": 1},
                    {"field": "common", "field_type": "string", "occurrences": 500},
                ],
            )
        ]
    )
    body = payload(
        diagnostics._schema(
            cluster,
            _options,
            {"bucket_name": "b", "scope_name": "s", "collection_name": "c"},
        )
    )
    assert [f["name"] for f in body["fields"]] == ["common", "rare"]


# ── cb_perf_not_selective: an absent capability is not an absent problem ─────


def test_a_version_without_phase_counts_refuses_rather_than_reporting_nothing(
    monkeypatch,
):
    """ "No rows" and "this server cannot answer" are opposite conclusions from
    the same empty result, and only one of them is safe to act on."""
    cluster = _Cluster(error="Unknown field ~phaseCounts")
    result = diagnostics._perf_not_selective(cluster, _options, {})
    assert is_error(result)
    assert "not available on this Couchbase version" in payload(result)["error"]
    assert "Unknown field" in payload(result)["cause"]


def test_a_statement_scanning_far_more_than_it_returns_is_flagged():
    cluster = _Cluster(
        [
            (
                "",
                [
                    {
                        "statement": "SELECT * FROM b WHERE x = 1",
                        "phase_counts": {"indexScan": 100000},
                        "resultCount": 3,
                    }
                ],
            )
        ]
    )
    body = payload(diagnostics._perf_not_selective(cluster, _options, {}))
    flagged = body["queries"]
    assert flagged, body
    assert flagged[0]["scan_count"] == 100000
    assert flagged[0]["selectivity_ratio"] == pytest.approx(3 / 100000)
    assert body["threshold"]["max_ratio"], "the verdict must carry its threshold"


def test_a_statement_that_returns_most_of_what_it_scans_is_not_flagged():
    cluster = _Cluster(
        [
            (
                "",
                [
                    {
                        "statement": "SELECT * FROM b",
                        "phase_counts": {"indexScan": 100000},
                        "resultCount": 99000,
                    }
                ],
            )
        ]
    )
    body = payload(diagnostics._perf_not_selective(cluster, _options, {}))
    assert body["queries"] == []


def test_a_row_with_no_scan_phase_is_not_flagged():
    """Only phases whose name mentions a scan count toward the heuristic; a
    fetch-only row says nothing about selectivity."""
    cluster = _Cluster(
        [("", [{"statement": "SELECT 1", "phase_counts": {"authorize": 5}}])]
    )
    body = payload(diagnostics._perf_not_selective(cluster, _options, {}))
    assert body["queries"] == []


# ── cb_perf_not_covering: an unexplainable statement is not a finding ────────


def test_a_statement_that_will_not_explain_is_skipped_not_surfaced(monkeypatch):
    """A statement that fails to parse says nothing about the cluster, and it
    must not abort the sweep over the ones that do."""
    explained = {"good": False}

    class _Explainer(_Cluster):
        def query(self, statement, options=None):
            self.statements.append(statement)
            if statement.startswith("EXPLAIN"):
                if "broken" in statement:
                    raise RuntimeError("syntax error")
                explained["good"] = True
                return iter([{"plan": {"#operator": "Fetch"}}])
            return iter([{"statement": "SELECT broken"}, {"statement": "SELECT good"}])

    cluster = _Explainer()
    result = diagnostics._perf_not_covering(cluster, _options, {})
    assert not is_error(result)
    assert explained["good"], "the sweep must continue past the unexplainable one"


# ── the plan summary the findings are derived from ───────────────────────────


def test_a_fetch_in_the_plan_is_what_makes_an_index_non_covering():
    summary = diagnostics._summarize_plan({"#operator": "Fetch"})
    assert summary["has_fetch"] is True
    assert diagnostics._findings_for(summary)


def test_a_plan_without_a_fetch_is_covering():
    summary = diagnostics._summarize_plan({"#operator": "IndexScan3"})
    assert summary["has_fetch"] is False


def test_the_walk_reaches_operators_nested_in_lists_and_objects():
    """Query plans nest operators under ~children, and a walk that only looked at
    the top level would call every plan covering."""
    plan = {"#operator": "Sequence", "~children": [{"#operator": "Fetch"}]}
    assert diagnostics._summarize_plan(plan)["has_fetch"] is True


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("plain", "`plain`"),
        ("with space", "`with space`"),
        # A backtick inside an identifier is DOUBLED, which is how SQL++ escapes
        # one. Stripping it instead would silently rename the object; leaving it
        # would end the quoted identifier early, which is the injection.
        ("drop`tick", "`drop``tick`"),
    ],
)
def test_an_identifier_is_quoted_and_its_backticks_doubled(given, expected):
    assert diagnostics._safe_ident(given) == expected


def test_a_keyspace_defaults_its_scope_and_collection():
    assert diagnostics._keyspace("b", None, None) == "`b`.`_default`.`_default`"
    assert diagnostics._keyspace("b", "s", "c") == "`b`.`s`.`c`"
