"""
The SQL++ that `handlers/indexes.py` and `handlers/diagnostics.py` construct by hand.

WHY THIS IS WORTH TESTING RATHER THAN JUST COVERING
===================================================
These two modules build statements by interpolating caller-supplied names into f-strings.
Every one of those names comes from a model, which got it from a user. `_safe_ident` is the
only thing between that and injection, and it works by doubling backticks inside a
backtick-quoted identifier — the SQL++ escaping rule.

A bucket named ``a` OR 1=1 --`` would otherwise close the quote and continue the statement.
`admin_index_create` also accepts a RAW statement, which makes it an execute-anything tool
unless the DDL guard holds; that guard is tested in `test_shared_helpers.py`, and here the
concern is the constructed path.

The statements are captured rather than executed: what matters is the text, and asserting on
the text is stricter than asserting a cluster accepted it.
"""

from __future__ import annotations

import json

import pytest
from mcp.types import TextContent

from handlers import diagnostics, indexes


class _Capture:
    """Records the statements a handler ran, and returns one plausible row."""

    def __init__(self):
        self.statements: list[str] = []
        self.parameters: list[dict] = []

    def query(self, statement, options=None, *args, **kwargs):
        self.statements.append(statement)
        named = (
            getattr(options, "kwargs", {}).get("named_parameters") if options else None
        )
        self.parameters.append(named or {})
        return iter([{"id": "row-1"}])


class _QueryOptions:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


@pytest.fixture
def sql(monkeypatch):
    """Both modules pointed at a capturing cluster, with the SDK's QueryOptions stubbed."""
    import sys
    import types

    capture = _Capture()

    package = types.ModuleType("couchbase")
    options_module = types.ModuleType("couchbase.options")
    options_module.QueryOptions = _QueryOptions
    package.options = options_module
    monkeypatch.setitem(sys.modules, "couchbase", package)
    monkeypatch.setitem(sys.modules, "couchbase.options", options_module)

    for module in (indexes, diagnostics):
        # NOT raising=False. These modules call `get_sdk_cluster`, and patching a name
        # they do not have used to succeed silently: on 2026-09-23 the seam was renamed
        # and every test here kept "passing" against an empty capture until the
        # assertions on captured statements failed with IndexError. A patch that cannot
        # bind is a broken test, so let it raise.
        monkeypatch.setattr(module, "get_sdk_cluster", lambda: capture)
        if hasattr(module, "admin_request"):
            monkeypatch.setattr(
                module,
                "admin_request",
                lambda *a, **k: {"stubbed": True},
                raising=False,
            )
    return capture


def _body(result) -> dict:
    assert isinstance(result, list) and result
    assert isinstance(result[0], TextContent)
    return json.loads(result[0].text)


# ── Identifier quoting: the injection boundary ───────────────────────────────


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("travel", "`travel`"),
        # A backtick is DOUBLED, which is the SQL++ escape. Anything else and the
        # identifier closes early and the rest of the value becomes statement text.
        ("a`b", "`a``b`"),
        ("a` OR 1=1 --", "`a`` OR 1=1 --`"),
        ("`", "````"),
        ("", "``"),
        (None, "``"),
        ("has space", "`has space`"),
        # A FULLWIDTH SEMICOLON (U+FF1B), not an ASCII one. Kept deliberately: a filter
        # that blocklists dangerous characters would miss it, while quoting handles it
        # like any other character. noqa because ruff flags the lookalike.
        ("；drop", "`；drop`"),  # noqa: RUF001
    ],
)
def test_identifier_quoting(given, expected):
    assert indexes._safe_ident(given) == expected


def test_a_hostile_bucket_name_cannot_escape_its_identifier(sql):
    """The concrete attack. If the backtick were not doubled, the statement would become
    `CREATE INDEX ix ON `a` OR 1=1 --`...` and the tail would be interpreted."""
    indexes.handle(
        "admin_index_create",
        {
            "bucket_name": "a` OR 1=1 --",
            "index_name": "ix",
            "fields": ["x"],
        },
    )
    (statement,) = sql.statements
    # Every backtick from the input survives as a doubled pair, so no identifier closes.
    assert statement.count("`") % 2 == 0
    assert "`a`` OR 1=1 --`" in statement


def test_a_hostile_field_name_cannot_escape_either(sql):
    """Fields are joined into the parenthesised list, which is a second interpolation
    point."""
    indexes.handle(
        "admin_index_create",
        {"bucket_name": "b", "index_name": "ix", "fields": ["x`) ; DROP INDEX y --"]},
    )
    (statement,) = sql.statements
    assert "`x``) ; DROP INDEX y --`" in statement


# ── admin_index_create ───────────────────────────────────────────────────────


def test_a_structured_secondary_index(sql):
    indexes.handle(
        "admin_index_create",
        {
            "bucket_name": "travel",
            "scope_name": "inventory",
            "collection_name": "airline",
            "index_name": "ix_name",
            "fields": ["name", "country"],
        },
    )
    assert sql.statements == [
        "CREATE INDEX `ix_name` ON `travel`.`inventory`.`airline` (`name`, `country`)"
    ]


def test_the_default_scope_and_collection_are_used_when_omitted(sql):
    indexes.handle(
        "admin_index_create",
        {"bucket_name": "b", "index_name": "ix", "fields": ["x"]},
    )
    assert "`b`.`_default`.`_default`" in sql.statements[0]


def test_a_primary_index_needs_no_fields(sql):
    indexes.handle("admin_index_create", {"bucket_name": "b", "is_primary": True})
    assert sql.statements[0].startswith("CREATE PRIMARY INDEX")


def test_a_named_primary_index(sql):
    indexes.handle(
        "admin_index_create",
        {"bucket_name": "b", "is_primary": True, "index_name": "pk"},
    )
    assert "CREATE PRIMARY INDEX `pk` ON" in sql.statements[0]


def test_replica_count_is_coerced_to_an_integer(sql):
    """It lands in a WITH clause unquoted, so a string would be a second injection point:
    `"num_replica": 2} ; DROP ...` would otherwise close the object."""
    indexes.handle(
        "admin_index_create",
        {"bucket_name": "b", "index_name": "ix", "fields": ["x"], "num_replica": "2"},
    )
    assert '"num_replica": 2' in sql.statements[0]


def test_a_non_numeric_replica_count_is_refused_rather_than_interpolated(sql):
    body = _body(
        indexes.handle(
            "admin_index_create",
            {
                "bucket_name": "b",
                "index_name": "ix",
                "fields": ["x"],
                "num_replica": "1} ; DROP INDEX y --",
            },
        )
    )
    from handlers.shared import ERROR_MARKER

    assert body[ERROR_MARKER] is True
    assert sql.statements == [], "a hostile replica count reached the cluster"


def test_deferred_build_is_requested(sql):
    indexes.handle(
        "admin_index_create",
        {"bucket_name": "b", "index_name": "ix", "fields": ["x"], "defer_build": True},
    )
    assert '"defer_build": true' in sql.statements[0]


def test_both_with_options_combine(sql):
    indexes.handle(
        "admin_index_create",
        {
            "bucket_name": "b",
            "index_name": "ix",
            "fields": ["x"],
            "num_replica": 1,
            "defer_build": True,
        },
    )
    statement = sql.statements[0]
    assert statement.count("WITH") == 1
    assert '"num_replica": 1' in statement
    assert '"defer_build": true' in statement


@pytest.mark.parametrize(
    ("args", "missing"),
    [
        ({}, "bucket_name"),
        ({"bucket_name": "b", "fields": ["x"]}, "index_name"),
        ({"bucket_name": "b", "index_name": "ix"}, "fields"),
    ],
)
def test_missing_arguments_are_named_rather_than_producing_broken_sql(
    sql, args, missing
):
    """Interpolating a missing name would send `CREATE INDEX `` ON ...` to the cluster and
    surface a parse error that says nothing about which argument was absent."""
    body = _body(indexes.handle("admin_index_create", args))
    assert missing in body["error"]
    assert sql.statements == []


# ── admin_index_drop ─────────────────────────────────────────────────────────


def test_a_structured_drop(sql):
    indexes.handle(
        "admin_index_drop",
        {
            "bucket_name": "b",
            "scope_name": "s",
            "collection_name": "c",
            "index_name": "ix",
        },
    )
    assert sql.statements == ["DROP INDEX `ix` ON `b`.`s`.`c`"]


def test_a_primary_index_drop(sql):
    indexes.handle("admin_index_drop", {"bucket_name": "b", "is_primary": True})
    assert sql.statements == ["DROP PRIMARY INDEX ON `b`.`_default`.`_default`"]


def test_a_drop_without_an_index_name_is_refused(sql):
    body = _body(indexes.handle("admin_index_drop", {"bucket_name": "b"}))
    assert "index_name" in body["error"]
    assert sql.statements == []


def test_a_raw_drop_statement_must_be_index_ddl(sql):
    """`statement` is a raw passthrough, so without the guard this tool executes anything."""
    body = _body(
        indexes.handle("admin_index_drop", {"statement": "DELETE FROM `b` WHERE 1=1"})
    )
    assert body["error"]
    assert sql.statements == []


def test_a_raw_drop_is_blocked_in_read_only_mode(sql, monkeypatch):
    """Index DDL is a schema change, and read-only mode means it does not happen.

    The guard is patched rather than the environment, in BOTH this test and its inverse.
    READ_ONLY_MODE is captured at import, so relying on the ambient default made this fail
    only in a full-suite run — another test reloads `handlers.shared` and flips it. Deciding a
    security assertion from module-import state is the thing to avoid, not to work around.
    """
    from handlers.shared import ERROR_MARKER

    monkeypatch.setattr(
        indexes, "block_dml_if_readonly", lambda _s: "read-only mode: refusing DDL"
    )
    body = _body(
        indexes.handle("admin_index_drop", {"statement": "DROP INDEX `b`.`ix`"})
    )
    assert body[ERROR_MARKER] is True
    assert sql.statements == []


def test_a_valid_raw_drop_statement_is_executed_when_writes_are_allowed(
    sql, monkeypatch
):
    """Guards the guard tests from passing because raw statements are refused outright.

    `block_dml_if_readonly` is patched rather than the environment, because READ_ONLY_MODE is
    captured at import — setting the variable here would change nothing and the test would
    pass for the wrong reason.
    """
    monkeypatch.setattr(indexes, "block_dml_if_readonly", lambda _s: None)
    indexes.handle("admin_index_drop", {"statement": "DROP INDEX `b`.`ix`"})
    assert sql.statements == ["DROP INDEX `b`.`ix`"]


# ── admin_index_build ────────────────────────────────────────────────────────


def test_a_scoped_build(sql):
    indexes.handle(
        "admin_index_build",
        {
            "bucket_name": "b",
            "scope_name": "s",
            "collection_name": "c",
            "index_names": ["ix1", "ix2"],
        },
    )
    assert sql.statements == ["BUILD INDEX ON `b`.`s`.`c` (`ix1`, `ix2`)"]


def test_a_bucket_level_build_when_no_scope_is_given(sql):
    """Pre-7.0 clusters and default-collection indexes. Naming a scope that was not supplied
    would target a keyspace that does not exist."""
    indexes.handle("admin_index_build", {"bucket_name": "b", "index_names": ["ix1"]})
    assert sql.statements == ["BUILD INDEX ON `b` (`ix1`)"]


def test_build_index_names_are_quoted(sql):
    indexes.handle(
        "admin_index_build", {"bucket_name": "b", "index_names": ["a`b", "c"]}
    )
    assert "(`a``b`, `c`)" in sql.statements[0]


# ── admin_index_list: parameterised, not interpolated ────────────────────────


def test_the_index_list_uses_named_parameters(sql):
    """The one place these modules use real parameter binding, and it should stay that way:
    a filter value never becomes statement text at all."""
    indexes.handle(
        "admin_index_list",
        {"bucket_name": "b", "scope_name": "s", "collection_name": "c"},
    )
    statement = sql.statements[0]
    assert "$bucket" in statement
    assert "$scope" in statement
    assert "$coll" in statement
    assert sql.parameters[0] == {"bucket": "b", "scope": "s", "coll": "c"}


def test_a_hostile_filter_value_stays_a_parameter(sql):
    """It is bound, so it cannot be interpreted however hostile it looks."""
    indexes.handle("admin_index_list", {"bucket_name": "x' OR 1=1 --"})
    assert "OR 1=1" not in sql.statements[0]
    assert sql.parameters[0]["bucket"] == "x' OR 1=1 --"


def test_an_unfiltered_index_list_has_no_where_clause(sql):
    indexes.handle("admin_index_list", {})
    assert sql.statements == ["SELECT * FROM system:indexes"]
    assert sql.parameters[0] == {}


# ── diagnostics: the read-only query tools ───────────────────────────────────


def test_the_schema_probe_targets_the_requested_collection(sql):
    diagnostics.handle(
        "cb_get_schema_for_collection",
        {
            "bucket_name": "travel",
            "scope_name": "inventory",
            "collection_name": "airline",
        },
    )
    assert sql.statements, "no statement was run"
    statement = sql.statements[0]
    assert "airline" in statement


@pytest.mark.parametrize(
    "tool",
    [
        "cb_perf_longest_running",
        "cb_perf_most_frequent",
        "cb_perf_largest_responses",
        "cb_perf_large_result_count",
        "cb_perf_using_primary_index",
        "cb_perf_not_using_covering_index",
        "cb_perf_not_selective",
    ],
)
def test_every_performance_probe_reads_the_completed_requests_catalog(sql, tool):
    """These read `system:completed_requests`, which is diagnostic state rather than data.
    A probe that read a data keyspace instead would be scanning the customer's documents."""
    diagnostics.handle(tool, {})
    assert sql.statements, f"{tool} ran no statement"
    assert "system:" in sql.statements[0], sql.statements[0]


@pytest.mark.parametrize(
    "tool",
    [
        "cb_get_schema_for_collection",
        "cb_index_advisor",
        "cb_explain_query",
        "cb_perf_longest_running",
        "cb_perf_most_frequent",
        "cb_perf_largest_responses",
        "cb_perf_large_result_count",
        "cb_perf_using_primary_index",
        "cb_perf_not_using_covering_index",
        "cb_perf_not_selective",
    ],
)
def test_no_diagnostic_tool_ever_mutates(sql, tool):
    """The standing constraint: these exist for read-only debugging. A diagnostic that wrote
    would be a write path with no confirmation gate and a read-only annotation."""
    args = {
        "bucket_name": "b",
        "scope_name": "s",
        "collection_name": "c",
        "statement": "SELECT 1",
        "statements": ["SELECT 1"],
        "query": "SELECT 1",
    }
    diagnostics.handle(tool, args)
    for statement in sql.statements:
        upper = statement.upper()
        for verb in ("INSERT INTO", "UPSERT INTO", "DELETE FROM", "MERGE INTO", "SET "):
            assert verb not in upper, (
                f"{tool} produced a mutating statement: {statement}"
            )


def test_the_index_advisor_wraps_the_callers_statement(sql):
    diagnostics.handle(
        "cb_index_advisor", {"statements": ["SELECT name FROM `travel`"]}
    )
    assert sql.statements
    # `SELECT ADVISOR($stmts)`, with the statements BOUND rather than interpolated —
    # which is stronger than wrapping them in text.
    assert "ADVISOR(" in sql.statements[0].upper()
    assert "$STMTS" in sql.statements[0].upper()
    assert sql.parameters[0] == {"stmts": ["SELECT name FROM `travel`"]}


def test_explain_wraps_the_callers_statement(sql):
    diagnostics.handle("cb_explain_query", {"statement": "SELECT name FROM `travel`"})
    assert sql.statements
    assert "EXPLAIN" in sql.statements[0].upper()


def test_a_diagnostic_refuses_a_mutating_statement_from_the_caller(sql):
    """`cb_explain_query` and `cb_index_advisor` take a statement and wrap it. EXPLAIN does
    not execute, but ADVISE on a DML statement is still a statement this server should not
    be forwarding — and the read-only guard is what stops it."""
    from handlers.shared import ERROR_MARKER

    body = _body(
        diagnostics.handle(
            "cb_index_advisor", {"statements": ["DELETE FROM `b` WHERE 1=1"]}
        )
    )
    assert body.get(ERROR_MARKER) is True
    assert not any("DELETE" in s.upper() for s in sql.statements)


def test_a_diagnostic_refuses_a_chained_statement(sql):
    from handlers.shared import ERROR_MARKER

    body = _body(
        diagnostics.handle(
            "cb_explain_query", {"statement": "SELECT 1; DELETE FROM `b`"}
        )
    )
    assert body.get(ERROR_MARKER) is True
    assert sql.statements == []


def test_an_unknown_diagnostic_tool_is_refused(sql):
    from handlers.shared import ERROR_MARKER

    body = _body(diagnostics.handle("cb_not_a_real_probe", {}))
    assert body[ERROR_MARKER] is True
