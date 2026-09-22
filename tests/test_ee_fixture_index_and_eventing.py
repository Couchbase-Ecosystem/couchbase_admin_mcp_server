"""What the self-managed exporter records about indexes and eventing, and what it
refuses to render.

`system:indexes` is not a GSI-only view. It carries Full-Text Search indexes too,
with `using` of `fts` and NO index_key, and the exporter used to assemble one
into

    CREATE INDEX `mcptest-fts` ON `travel-sample`.`_default`.`_default`()

which the query service rejects with `syntax error ... near '(', at: )`. That
fails at IMPORT time, on somebody else's cluster, after the documents have already
landed -- the worst place for it. Rows are now filtered to gsi, and a row with no
keys that is not primary is skipped WITH A REASON rather than dropped.

This is the one defect from the 2026-09-14 round trip that is still unexercised
against the shape that produced it, because the only cluster in the project with a
Search service group is powered off. These tests cover the fix in isolation --
which is what the module's own docs say is the current state, and saying so is
better than implying more.

Eventing has its own shape: a cluster with no Eventing service answers 404, which
is "not present", not "broken". Reporting it as a warning would make every export
against a Data-and-Query cluster look like a failure.
"""

from __future__ import annotations

import pytest

from handlers import fixture


def _with_query(rows, call):
    """Run `call` with fixture._query replaced.

    A plain monkeypatch works here too, but the module reads the name at call
    time through its own globals, so this keeps the swap explicit and restores it
    even when the call raises.
    """
    original = fixture._query
    fixture._query = lambda statement, parameters=None: rows
    try:
        return call()
    finally:
        fixture._query = original


def _row(**fields):
    base = {
        "name": "ix",
        "using": "gsi",
        "keyspace": "b.s.c",
        "bucket_id": "b",
        "scope_id": "s",
        "keyspace_id": "c",
        "index_key": ["`f`"],
        "state": "online",
    }
    base.update(fields)
    return base


def _definitions(rows, keyspaces=frozenset({"b.s.c"})):
    return _with_query(rows, lambda: fixture._index_definitions(set(keyspaces)))


# ── a Search index is not a GSI index ────────────────────────────────────────


def test_a_search_index_is_skipped_with_a_reason(monkeypatch):
    """The exporter assembled one into a CREATE INDEX with empty parentheses,
    which the query service rejects -- at IMPORT time, on somebody else's
    cluster, after the documents had landed."""
    definitions, warnings = _definitions([_row(using="fts", index_key=[])])
    assert definitions == []
    assert any("not GSI" in w for w in warnings)


def test_an_index_with_no_keys_that_is_not_primary_is_skipped_with_a_reason():
    """Rendering it produces `ON keyspace()` -- a statement that cannot parse."""
    definitions, warnings = _definitions([_row(index_key=[])])
    assert definitions == []
    assert any("declares no index keys" in w for w in warnings)
    assert any("no CREATE INDEX can be rendered" in w for w in warnings)


def test_a_primary_index_with_no_keys_is_rendered_as_a_primary_index():
    """The legitimate no-keys case, and the reason the skip above has to test
    `is_primary` rather than just the key list."""
    definitions, _warnings = _definitions([_row(index_key=[], is_primary=True)])
    assert definitions[0]["definition"].startswith("CREATE PRIMARY INDEX `ix` ON")


# ── what a rendered definition carries ───────────────────────────────────────


def test_an_ordinary_secondary_index_renders_its_keys():
    definitions, _warnings = _definitions([_row(index_key=["`a`", "`b`"])])
    statement = definitions[0]["definition"]
    assert statement.startswith("CREATE INDEX `ix` ON")
    assert "(`a`, `b`)" in statement


def test_a_partial_index_keeps_its_condition():
    """A partial index rebuilt without its WHERE clause indexes the whole
    collection -- a different index with the same name."""
    definitions, _warnings = _definitions([_row(condition="`type` = 'airline'")])
    assert "WHERE `type` = 'airline'" in definitions[0]["definition"]


def test_a_replicated_index_keeps_its_replica_count():
    """num_replica changes failover behaviour and read throughput, so an index
    rebuilt without it is not the index the fixture recorded."""
    definitions, _warnings = _definitions([_row(num_replica=2)])
    statement = definitions[0]["definition"]
    assert "WITH " in statement
    assert '"num_replica": 2' in statement


def test_a_replica_count_of_zero_adds_no_with_clause():
    """`WITH {"num_replica": 0}` is noise, and an empty WITH is a syntax error."""
    definitions, _warnings = _definitions([_row(num_replica=0)])
    assert "WITH" not in definitions[0]["definition"]


def test_definitions_are_scoped_to_the_keyspaces_actually_exported():
    """A fixture carrying ONE collection recorded 23 definitions and the import
    attempted all 23. On a fresh target that builds indexes for collections the
    fixture carries no data for."""
    rows = [_row(name="wanted"), _row(name="elsewhere", keyspace_id="other")]
    definitions, _warnings = _definitions(rows, keyspaces={"b.s.c"})
    assert [d["indexName"] for d in definitions] == ["wanted"]


# ── eventing: absent is not broken ───────────────────────────────────────────


@pytest.fixture
def eventing(monkeypatch):
    state = {"response": [], "error": None}

    def request(method, path, **kwargs):
        if state["error"]:
            raise RuntimeError(state["error"])
        return state["response"]

    monkeypatch.setattr(fixture, "admin_request", request)
    return state


def test_a_cluster_with_no_eventing_service_is_not_a_warning(eventing):
    """A 404 is "not present". Reporting it would make every export against a
    Data-and-Query cluster look broken."""
    eventing["error"] = "404 Not Found"
    functions, warnings = fixture._eventing_functions()
    assert functions == []
    assert warnings == []


def test_any_other_eventing_failure_is_reported(eventing):
    eventing["error"] = "403 Forbidden"
    functions, warnings = fixture._eventing_functions()
    assert functions == []
    assert any("could not be read" in w for w in warnings)


def test_eventing_functions_are_returned_when_present(eventing):
    eventing["response"] = [{"appname": "fn1"}]
    functions, warnings = fixture._eventing_functions()
    assert functions == [{"appname": "fn1"}]
    assert warnings == []


def test_an_eventing_response_of_the_wrong_shape_is_reported(eventing):
    """A dict where a list was expected means the endpoint changed, and silently
    recording nothing would produce a fixture missing its functions."""
    eventing["response"] = {"unexpected": "shape"}
    functions, warnings = fixture._eventing_functions()
    assert functions == []
    assert any("not a list" in w for w in warnings)
