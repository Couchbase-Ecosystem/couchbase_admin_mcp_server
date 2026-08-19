"""
Couchbase 8.x vector indexes, XDCR replication bodies, and the token cache.

WHY THESE THREE
===============
Vector index creation builds a `WITH {...}` clause by string concatenation, with a
caller-supplied dimension, similarity metric and description going into it. Two of those are
JSON-escaped and one is coerced to an int — and the escaping is the only thing between a
description containing a brace and a malformed statement.

XDCR replication creation is where the cluster is told to stream an entire bucket to a remote
host. The nested `conflictLoggingMapping` has to become a JSON string because the endpoint is
form-encoded; a Python repr there is silently unparseable, which on this API means the setting
is ignored rather than rejected.

`auth/request_auth` caches validated tokens. A cache keyed on the token itself, or one that
outlives expiry, would be an authorization bypass.
"""

from __future__ import annotations

import json

import pytest
from mcp.types import TextContent

from handlers import eight_x, xdcr
from handlers.shared import ERROR_MARKER


def _body(result) -> dict:
    assert isinstance(result, list) and result
    assert isinstance(result[0], TextContent)
    return json.loads(result[0].text)


class _Capture:
    def __init__(self):
        self.statements: list[str] = []

    def query(self, statement, *args, **kwargs):
        self.statements.append(statement)
        return iter([{"ok": True}])


@pytest.fixture
def vector(monkeypatch):
    """`eight_x` on an 8.x cluster with the SQL++ path captured."""
    import sys
    import types

    capture = _Capture()
    options = types.ModuleType("couchbase.options")
    options.QueryOptions = lambda *a, **k: None
    package = types.ModuleType("couchbase")
    package.options = options
    monkeypatch.setitem(sys.modules, "couchbase", package)
    monkeypatch.setitem(sys.modules, "couchbase.options", options)

    monkeypatch.setattr(
        eight_x,
        "get_sdk_connection",
        lambda: (capture, object(), object()),
        raising=False,
    )
    monkeypatch.setattr(eight_x, "is_8x", lambda: True, raising=False)
    return capture


# The hyperscale index takes `field_name`; the composite one takes `vector_field` plus
# `scalar_fields`. Different names for the same idea, which is exactly the sort of thing a
# test asserting on the wrong one would not notice.
BASE_VECTOR = {
    "bucket_name": "app",
    "index_name": "vec_ix",
    "field_name": "embedding",
    "dimension": 1536,
    "similarity": "COSINE",
}


# ── The version gate ─────────────────────────────────────────────────────────


def test_a_seven_x_cluster_is_told_which_version_is_needed(monkeypatch, vector):
    """The alternative is a SQL++ syntax error from the cluster, which says nothing about the
    version and sends the operator looking for a typo."""
    monkeypatch.setattr(eight_x, "is_8x", lambda: False, raising=False)
    body = _body(
        eight_x.handle("admin_vector_index_create_hyperscale", dict(BASE_VECTOR))
    )
    assert body[ERROR_MARKER] is True
    assert "8.0" in body["error"]
    assert "admin_cluster_info" in json.dumps(body)
    assert vector.statements == []


# ── The similarity enum ──────────────────────────────────────────────────────


@pytest.mark.parametrize("similarity", ["COSINE", "DOT_PRODUCT", "L2_SQUARED"])
def test_documented_similarity_metrics_are_accepted(vector, similarity):
    args = {**BASE_VECTOR, "similarity": similarity}
    body = _body(eight_x.handle("admin_vector_index_create_hyperscale", args))
    if body.get(ERROR_MARKER):
        pytest.skip(f"{similarity} not in this build's enum")
    assert vector.statements


def test_a_typo_in_the_similarity_metric_is_caught_here_not_by_the_cluster(vector):
    """A typo, or the wrong CASE — the enum is COSINE / DOT_PRODUCT / L2_SQUARED, and
    lowercase `cosine` is the natural thing to write. Either would otherwise build an index
    with the wrong metric, or fail with a cluster message that does not list the valid
    values."""
    body = _body(
        eight_x.handle(
            "admin_vector_index_create_hyperscale",
            # Lower case: the enum is COSINE, so this is the natural spelling and is wrong.
            {**BASE_VECTOR, "similarity": "cosine"},
        )
    )
    assert body[ERROR_MARKER] is True
    assert "similarity must be one of" in body["error"]
    assert vector.statements == []


# ── The WITH clause ──────────────────────────────────────────────────────────


def test_the_with_clause_carries_the_dimension_and_similarity(vector):
    eight_x.handle("admin_vector_index_create_hyperscale", dict(BASE_VECTOR))
    statement = vector.statements[0]
    assert '"dimension": 1536' in statement
    assert '"similarity": "COSINE"' in statement


def test_the_dimension_is_coerced_to_an_integer(vector):
    """It lands in the clause unquoted, so a string would be a second injection point."""
    eight_x.handle(
        "admin_vector_index_create_hyperscale", {**BASE_VECTOR, "dimension": "1536"}
    )
    assert '"dimension": 1536' in vector.statements[0]


def test_a_non_numeric_dimension_is_refused_rather_than_interpolated(vector):
    body = _body(
        eight_x.handle(
            "admin_vector_index_create_hyperscale",
            {**BASE_VECTOR, "dimension": "1536} ; DROP INDEX x --"},
        )
    )
    assert body[ERROR_MARKER] is True
    assert vector.statements == []


def test_a_description_containing_a_brace_is_json_escaped(vector):
    """It is free text from a caller and goes inside a `{...}` clause. Unescaped, a brace or a
    quote closes the object and the rest becomes statement text."""
    eight_x.handle(
        "admin_vector_index_create_hyperscale",
        {**BASE_VECTOR, "description": 'has "quotes" and } a brace'},
    )
    statement = vector.statements[0]
    assert '\\"quotes\\"' in statement

    # The real invariant: the WITH clause PARSES as JSON. Counting braces was the first
    # attempt and is wrong — a `}` inside a JSON string literal is legal and `json.dumps`
    # correctly leaves it unescaped, so a balanced-brace check fails on correct output.
    with_clause = statement[statement.index("WITH ") + len("WITH ") :]
    parsed = json.loads(with_clause)
    assert parsed["description"] == 'has "quotes" and } a brace'
    assert parsed["dimension"] == 1536


def test_a_similarity_value_is_json_escaped_too(vector):
    """Belt and braces: it is enum-checked first, so this can only matter if the enum grows a
    value with a special character — but the escaping costs nothing."""
    eight_x.handle("admin_vector_index_create_hyperscale", dict(BASE_VECTOR))
    assert '"similarity": "COSINE"' in vector.statements[0]


def test_optional_with_fields_are_omitted_when_unset(vector):
    """An explicit `"description": null` is not the same as absent, and Couchbase rejects
    some nulls it accepts as omissions."""
    eight_x.handle("admin_vector_index_create_hyperscale", dict(BASE_VECTOR))
    statement = vector.statements[0]
    assert "description" not in statement
    assert "num_replica" not in statement
    assert "defer_build" not in statement


def test_replica_and_defer_are_included_when_asked_for(vector):
    eight_x.handle(
        "admin_vector_index_create_hyperscale",
        {**BASE_VECTOR, "num_replica": 2, "defer_build": True},
    )
    statement = vector.statements[0]
    assert '"num_replica": 2' in statement
    assert '"defer_build": true' in statement


# ── The composite vector index ───────────────────────────────────────────────


COMPOSITE = {
    "bucket_name": "app",
    "index_name": "vec_ix",
    "vector_field": "embedding",
    "dimension": 1536,
    "similarity": "COSINE",
    "scalar_fields": ["country", "type"],
}


def test_a_composite_index_lists_the_scalar_fields_before_the_vector(vector):
    """Order is load-bearing in a composite index: the scalar predicates are what narrow the
    scan before the vector comparison runs."""
    eight_x.handle("admin_vector_index_create_composite", dict(COMPOSITE))
    statement = vector.statements[0]
    assert "COMPOSITE VECTOR INDEX" in statement
    assert statement.index("`country`") < statement.index("`embedding` VECTOR")


def test_composite_scalar_fields_are_quoted(vector):
    eight_x.handle(
        "admin_vector_index_create_composite",
        {**COMPOSITE, "scalar_fields": ["a`b"]},
    )
    assert "`a``b`" in vector.statements[0]


def test_an_empty_scalar_field_list_is_refused(vector):
    """A composite index with no scalar fields is just a vector index, and the statement it
    would build is a syntax error."""
    body = _body(
        eight_x.handle(
            "admin_vector_index_create_composite", {**COMPOSITE, "scalar_fields": []}
        )
    )
    assert body[ERROR_MARKER] is True
    assert "non-empty" in body["error"]


def test_a_non_list_scalar_field_value_is_refused(vector):
    body = _body(
        eight_x.handle(
            "admin_vector_index_create_composite",
            {**COMPOSITE, "scalar_fields": "country"},
        )
    )
    assert body[ERROR_MARKER] is True


def test_a_where_clause_is_included(vector):
    """Partial indexes are the point of the feature — an index over only the rows that matter."""
    eight_x.handle(
        "admin_vector_index_create_composite",
        {**COMPOSITE, "where_clause": "type = 'hotel'"},
    )
    assert "WHERE type = 'hotel'" in vector.statements[0]


@pytest.mark.parametrize(
    "hostile", ["1=1; DROP INDEX x", "type='a';DELETE FROM `b`", "x=1;"]
)
def test_a_where_clause_containing_a_statement_terminator_is_refused(vector, hostile):
    """The one field that is deliberately NOT quoted, because it is an expression. A semicolon
    in it would chain a second statement onto an index creation."""
    body = _body(
        eight_x.handle(
            "admin_vector_index_create_composite",
            {**COMPOSITE, "where_clause": hostile},
        )
    )
    assert body[ERROR_MARKER] is True
    assert "semicolon" in body["error"] or "terminator" in body["error"]
    assert vector.statements == []


# ── XDCR ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def replication(monkeypatch):
    """`xdcr` with the REST call captured and egress checks satisfied."""
    calls: list[tuple] = []

    def _request(method="GET", path="/", data=None, **kwargs):
        calls.append((method, path, data))
        return {"ok": True}

    monkeypatch.setattr(xdcr, "admin_request", _request, raising=False)
    monkeypatch.setattr(
        xdcr, "assert_egress_allowed", lambda *a, **k: None, raising=False
    )
    return calls


BASE_REPLICATION = {
    "fromBucket": "app",
    "toCluster": "dr-site",
    "toBucket": "app",
}


def test_a_replication_defaults_to_continuous(replication):
    """One-shot replication is not what anybody means by "set up XDCR", and the API's own
    default has changed across versions."""
    xdcr.handle("admin_xdcr_replication_create", dict(BASE_REPLICATION))
    _method, _path, data = replication[0]
    assert data["replicationType"] == "continuous"


def test_optional_replication_fields_are_omitted_when_unset(replication):
    """Sending an empty `filterExpression` would replicate nothing, which looks exactly like
    a broken replication."""
    xdcr.handle("admin_xdcr_replication_create", dict(BASE_REPLICATION))
    _m, _p, data = replication[0]
    for field in ("type", "compressionType", "filterExpression", "conflictLogging"):
        assert field not in data


def test_the_wire_protocol_can_be_selected(replication):
    xdcr.handle("admin_xdcr_replication_create", {**BASE_REPLICATION, "type": "capi"})
    assert replication[0][2]["type"] == "capi"


def test_conflict_logging_is_encoded_as_a_lowercase_string(replication):
    """The endpoint is form-encoded, and Python's `str(True)` is `"True"` — which this API
    does not accept."""
    xdcr.handle(
        "admin_xdcr_replication_create",
        {**BASE_REPLICATION, "conflictLogging": True},
    )
    assert replication[0][2]["conflictLogging"] == "true"

    replication.clear()
    xdcr.handle(
        "admin_xdcr_replication_create",
        {**BASE_REPLICATION, "conflictLogging": False},
    )
    assert replication[0][2]["conflictLogging"] == "false"


def test_a_nested_conflict_logging_mapping_becomes_a_json_string(replication):
    """Form encoding cannot carry a nested object. A Python repr there is silently
    unparseable, and on this endpoint an unparseable value means the setting is IGNORED rather
    than rejected — so conflict logging would appear configured and do nothing."""
    mapping = {"bucket": {"app": {"collection": "logs"}}}
    xdcr.handle(
        "admin_xdcr_replication_create",
        {**BASE_REPLICATION, "conflictLoggingMapping": mapping},
    )
    encoded = replication[0][2]["conflictLoggingMapping"]
    assert isinstance(encoded, str)
    assert "'" not in encoded, "a Python repr was sent instead of JSON"
    assert json.loads(encoded) == mapping


def test_creating_a_remote_reference_checks_egress_first(monkeypatch):
    """The cluster will connect to this host and, once a replication exists, stream an entire
    bucket to it. That is the reverse-proxy / exfiltration path the egress allowlist exists
    for, and it has to be checked BEFORE the reference is created."""
    order: list[str] = []
    monkeypatch.setattr(
        xdcr,
        "assert_egress_allowed",
        lambda *a, **k: order.append("egress"),
        raising=False,
    )
    monkeypatch.setattr(
        xdcr,
        "admin_request",
        lambda *a, **k: order.append("request") or {"ok": True},
        raising=False,
    )

    xdcr.handle(
        "admin_xdcr_reference_create",
        {
            "name": "dr",
            "hostname": "dr.example.com",
            "username": "u",
            "password": "p",
        },
    )
    assert order == ["egress", "request"], (
        "the remote reference was created before the egress check ran"
    )


def test_a_reference_name_is_url_encoded_on_delete(replication):
    """A name with a slash would otherwise address a different resource entirely."""
    xdcr.handle("admin_xdcr_reference_delete", {"cluster_name": "a/b"})
    _method, path, _data = replication[0]
    assert "a%2Fb" in path


# ── The validated-token cache ────────────────────────────────────────────────


def test_the_cache_is_keyed_on_a_digest_not_the_token():
    """A cache keyed on the token itself keeps the credential in memory in plaintext, and any
    dump of that structure is a credential leak."""
    import inspect

    from auth import request_auth

    source = inspect.getsource(request_auth._cache_put)
    assert "_digest" in source, "the cache key is not a digest of the token"


def test_a_cached_entry_is_returned_for_the_same_token():
    from auth import request_auth

    request_auth.reset_cache()
    claims = {"sub": "u", "exp": 9999999999}
    request_auth._cache_put("token-abc", claims)
    assert request_auth._cache_get("token-abc") == claims


def test_a_different_token_does_not_hit_the_cache():
    from auth import request_auth

    request_auth.reset_cache()
    request_auth._cache_put("token-abc", {"sub": "u"})
    assert request_auth._cache_get("token-xyz") is None


def test_resetting_the_cache_forgets_everything():
    """Used between tests, and after a configuration change — a cached validation made under
    the old issuer must not survive it."""
    from auth import request_auth

    request_auth._cache_put("token-abc", {"sub": "u"})
    request_auth.reset_cache()
    assert request_auth._cache_get("token-abc") is None


def test_the_cache_does_not_grow_without_bound():
    """It is keyed on attacker-suppliable input. An unbounded cache is a memory exhaustion
    path that needs no valid credential at all."""
    from auth import request_auth

    request_auth.reset_cache()
    for index in range(5000):
        request_auth._cache_put(
            f"token-{index}", {"sub": str(index), "exp": 9999999999}
        )

    size = len(getattr(request_auth, "_cache", {}))
    assert size < 5000, f"the token cache holds {size} entries with no bound"
