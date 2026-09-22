"""The self-managed importer, which is the half that writes to somebody's cluster.

tests/test_ee_fixture.py covers the refusals -- the cases where the importer must
stop BEFORE touching anything. This file covers what happens once it has decided
to proceed: the structure it creates, the documents it writes over KV, the
indexes it recreates, and the count it compares afterwards.

Those four functions shipped at 57 percent coverage, and the reason is visible in
the module's own history. The EE round trip on 2026-09-14 passed first attempt --
187 documents out and back, keys, bodies and expiries identical -- and STILL found
four defects, every one of them in the index step, because the document
comparison does not reach it. A clean result on the thing you measured says
nothing about the thing beside it.

So the cases here are weighted towards the steps a round trip does not compare:
the expiry arithmetic, the failure cap, the keyspace rewrite, the deferred build,
and the difference between "this file could not be read" and "this file held
nothing".

No cluster is contacted. The SDK handle and the admin REST call are both stubbed,
which is what lets the error branches -- an unopenable collection, an upsert that
raises, an index that already exists -- be provoked at all.
"""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from handlers import fixture

# ── A stand-in for the SDK, small enough to reason about ─────────────────────


class _FakeCollection:
    def __init__(self, fail_on=None, fail_with="upsert refused"):
        self.upserts: list[tuple] = []
        self.fail_on = fail_on  # None | "all" | set of keys
        self.fail_with = fail_with

    def upsert(self, key, value, options=None):
        if self.fail_on == "all" or (
            isinstance(self.fail_on, set) and key in self.fail_on
        ):
            raise RuntimeError(self.fail_with)
        self.upserts.append((key, value, options))


class _FakeCluster:
    def __init__(self, collection=None, open_error=None):
        self.collection_obj = collection or _FakeCollection()
        self.open_error = open_error
        self.opened: list[str] = []

    def bucket(self, name):
        if self.open_error:
            raise RuntimeError(self.open_error)
        self.opened.append(name)
        return self

    def scope(self, name):
        self.opened.append(name)
        return self

    def collection(self, name):
        self.opened.append(name)
        return self.collection_obj


@pytest.fixture
def sdk(monkeypatch):
    collection = _FakeCollection()
    cluster = _FakeCluster(collection)
    monkeypatch.setattr(fixture, "get_sdk_connection", lambda: (cluster, None, None))
    return cluster, collection


def _manifest(keyspace="b.s.c", path="data/b.s.c.jsonl", count=1, **extra):
    manifest = {
        "files": [
            {"keyspace": keyspace, "path": path, "document_count": count},
        ],
    }
    manifest.update(extra)
    return manifest


def _data(tmp_path: pathlib.Path, lines: list[str], name="data/b.s.c.jsonl"):
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return tmp_path


# ═══ _import_structure ═══════════════════════════════════════════════════════


def test_structure_creates_only_what_the_data_needs(monkeypatch):
    """A fixture may describe forty collections and carry documents for two.
    Creating the other thirty-eight is the tool inventing work on someone's
    cluster."""
    calls: list[tuple] = []

    def admin(method, path, data=None):
        calls.append((method, path, data))
        if method == "GET":
            return {"scopes": [{"name": "s", "collections": []}]}
        return {}

    monkeypatch.setattr(fixture, "admin_request", admin)
    manifest = _manifest(
        structure=[
            {
                "name": "b",
                "scopes": [
                    {"name": "s", "collections": [{"name": "c"}, {"name": "unused"}]}
                ],
            }
        ]
    )
    result = fixture._import_structure(manifest, {})
    assert result["ok"] is True
    assert result["collections_created"] == ["b.s.c"]
    created = [c for c in calls if c[0] == "POST"]
    assert len(created) == 1, "only the collection the data needs"


def test_structure_creates_a_missing_scope_then_its_collection(monkeypatch):
    calls: list[tuple] = []

    def admin(method, path, data=None):
        calls.append((method, path, data))
        if method == "GET":
            return {"scopes": []}
        return {}

    monkeypatch.setattr(fixture, "admin_request", admin)
    result = fixture._import_structure(_manifest(), {})
    assert result["scopes_created"] == ["b.s"]
    assert result["collections_created"] == ["b.s.c"]
    assert result["ok"] is True


def test_structure_reports_an_existing_collection_without_recreating_it(monkeypatch):
    def admin(method, path, data=None):
        if method == "GET":
            return {"scopes": [{"name": "s", "collections": [{"name": "c"}]}]}
        raise AssertionError("nothing should be created")

    monkeypatch.setattr(fixture, "admin_request", admin)
    result = fixture._import_structure(_manifest(), {})
    assert result["already_present"] == ["b.s.c"]
    assert result["ok"] is True


def test_structure_says_it_does_not_create_buckets(monkeypatch):
    """The failure a caller hits first, and the one where a vague message costs
    the most time."""

    def admin(method, path, data=None):
        raise RuntimeError("404 not found")

    monkeypatch.setattr(fixture, "admin_request", admin)
    result = fixture._import_structure(_manifest(), {})
    assert result["ok"] is False
    assert "does not create buckets" in result["failures"][0]
    assert "admin_bucket_create" in result["failures"][0]


def test_structure_reports_a_scope_that_could_not_be_created(monkeypatch):
    def admin(method, path, data=None):
        if method == "GET":
            return {"scopes": []}
        raise RuntimeError("insufficient permissions")

    monkeypatch.setattr(fixture, "admin_request", admin)
    result = fixture._import_structure(_manifest(), {})
    assert result["ok"] is False
    assert "scope 's' could not be created" in result["failures"][0]


def test_structure_reports_a_collection_that_could_not_be_created(monkeypatch):
    def admin(method, path, data=None):
        if method == "GET":
            return {"scopes": [{"name": "s", "collections": []}]}
        raise RuntimeError("quota exceeded")

    monkeypatch.setattr(fixture, "admin_request", admin)
    result = fixture._import_structure(_manifest(), {})
    assert result["ok"] is False
    assert "collection 'c' could not be created" in result["failures"][0]


def test_structure_refuses_a_keyspace_that_is_not_three_parts(monkeypatch):
    monkeypatch.setattr(fixture, "admin_request", lambda *a, **kw: {"scopes": []})
    result = fixture._import_structure(_manifest(keyspace="justabucket"), {})
    assert result["ok"] is False
    assert "not bucket.scope.collection" in result["failures"][0]


def test_structure_follows_the_keyspace_map(monkeypatch):
    seen: list[str] = []

    def admin(method, path, data=None):
        seen.append(path)
        if method == "GET":
            return {"scopes": [{"name": "other", "collections": []}]}
        return {}

    monkeypatch.setattr(fixture, "admin_request", admin)
    result = fixture._import_structure(_manifest(), {"b.s.c": "target.other.c"})
    assert result["collections_created"] == ["target.other.c"]
    assert any("buckets/target/" in p for p in seen)


# ── the recorded TTL travels with the collection ─────────────────────────────


def test_a_recorded_max_ttl_is_applied_to_the_created_collection(monkeypatch):
    """A dataset whose documents expire after an hour behaves differently from
    one whose documents do not. A fixture that drops it reproduces the wrong
    thing."""
    bodies: list[dict] = []

    def admin(method, path, data=None):
        if method == "GET":
            return {"scopes": [{"name": "s", "collections": []}]}
        bodies.append(data)
        return {}

    monkeypatch.setattr(fixture, "admin_request", admin)
    manifest = _manifest(
        structure=[
            {
                "name": "b",
                "scopes": [
                    {"name": "s", "collections": [{"name": "c", "maxTTL": 3600}]}
                ],
            }
        ]
    )
    fixture._import_structure(manifest, {})
    assert bodies[-1] == {"name": "c", "maxTTL": 3600}


@pytest.mark.parametrize(
    ("manifest", "keyspace", "expected"),
    [
        ({}, "b.s.c", None),
        ({"structure": []}, "b.s.c", None),
        ({"structure": [{"name": "other", "scopes": []}]}, "b.s.c", None),
        (
            {"structure": [{"name": "b", "scopes": [{"name": "nope"}]}]},
            "b.s.c",
            None,
        ),
        (
            {
                "structure": [
                    {
                        "name": "b",
                        "scopes": [
                            {"name": "s", "collections": [{"name": "elsewhere"}]}
                        ],
                    }
                ]
            },
            "b.s.c",
            None,
        ),
        (
            {
                "structure": [
                    {
                        "name": "b",
                        "scopes": [
                            {
                                "name": "s",
                                "collections": [{"name": "c", "maxTTL": "not-int"}],
                            }
                        ],
                    }
                ]
            },
            "b.s.c",
            None,
        ),
        ({}, "not-a-keyspace", None),
    ],
)
def test_recorded_max_ttl_returns_none_rather_than_guessing(
    manifest, keyspace, expected
):
    assert fixture._recorded_max_ttl(manifest, keyspace) is expected


# ═══ _import_documents ═══════════════════════════════════════════════════════


def test_documents_are_written_over_kv(tmp_path, sdk):
    """KV, not SQL++. A mutating SQL++ statement in a handler is refused by
    tests/test_no_handler_embeds_a_mutating_sql_statement, and UPSERT through the
    query service cannot set a per-document expiry without more statement text."""
    _cluster, collection = sdk
    _data(tmp_path, [json.dumps({"id": "k1", "doc": {"a": 1}})])
    result = fixture._import_documents(tmp_path, _manifest(), {})
    assert result["documents_written"] == 1
    assert result["ok"] is True
    assert collection.upserts[0][0] == "k1"
    assert collection.upserts[0][1] == {"a": 1}
    assert collection.upserts[0][2] is None, "no expiry means no options"


def test_blank_lines_are_skipped_without_being_counted_as_failures(tmp_path, sdk):
    _cluster, collection = sdk
    _data(tmp_path, [json.dumps({"id": "k1", "doc": {}}), "", "   "])
    result = fixture._import_documents(tmp_path, _manifest(), {})
    assert result["documents_written"] == 1
    assert result["keyspaces"][0]["failures"] == []
    assert len(collection.upserts) == 1


def test_a_line_that_is_not_json_is_reported_with_its_number(tmp_path, sdk):
    _data(tmp_path, [json.dumps({"id": "k1", "doc": {}}), "{ not json"])
    result = fixture._import_documents(tmp_path, _manifest(count=2), {})
    assert result["ok"] is False
    assert "line 2 is not JSON" in result["keyspaces"][0]["failures"][0]


@pytest.mark.parametrize("row", [{"doc": {}}, {"id": "", "doc": {}}, {"id": 7}])
def test_a_document_with_no_usable_key_points_at_the_export_not_the_import(
    tmp_path, sdk, row
):
    """This is the Capella key bug's signature. The message has to send the
    reader back to the export rather than into the importer."""
    _data(tmp_path, [json.dumps(row)])
    result = fixture._import_documents(tmp_path, _manifest(), {})
    failure = result["keyspaces"][0]["failures"][0]
    assert "no usable document key" in failure
    assert "re-export rather than loading this" in failure


def test_a_future_expiry_is_converted_to_a_remaining_duration(tmp_path, sdk):
    """An exported expiry is an absolute Unix time; the SDK takes a duration."""
    _cluster, collection = sdk
    future = int((datetime.now(timezone.utc) + timedelta(hours=2)).timestamp())
    _data(tmp_path, [json.dumps({"id": "k1", "doc": {}, "exp": future})])
    result = fixture._import_documents(tmp_path, _manifest(), {})
    assert result["documents_written"] == 1
    assert collection.upserts[0][2] is not None, "an expiry should carry options"


def test_a_past_expiry_is_dropped_and_reported_rather_than_written_dead(tmp_path, sdk):
    """A fixture loaded after its documents' recorded expiry would otherwise be
    written already expired -- an empty collection that reports a successful
    import."""
    _cluster, collection = sdk
    past = int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp())
    _data(tmp_path, [json.dumps({"id": "k1", "doc": {}, "exp": past})])
    result = fixture._import_documents(tmp_path, _manifest(), {})
    assert result["documents_written"] == 1
    assert collection.upserts[0][2] is None, "written WITHOUT an expiry"
    failure = result["keyspaces"][0]["failures"][0]
    assert "is in the past" in failure
    assert "rather than written already expired" in failure


def test_an_upsert_that_raises_is_recorded_against_its_key(tmp_path, monkeypatch):
    collection = _FakeCollection(fail_on={"k2"}, fail_with="durability failure")
    cluster = _FakeCluster(collection)
    monkeypatch.setattr(fixture, "get_sdk_connection", lambda: (cluster, None, None))
    _data(
        tmp_path,
        [
            json.dumps({"id": "k1", "doc": {}}),
            json.dumps({"id": "k2", "doc": {}}),
        ],
    )
    result = fixture._import_documents(tmp_path, _manifest(count=2), {})
    assert result["documents_written"] == 1
    assert result["ok"] is False
    assert "k2: durability failure" in result["keyspaces"][0]["failures"]


def test_it_stops_after_twenty_failures_rather_than_hammering_the_cluster(
    tmp_path, monkeypatch
):
    collection = _FakeCollection(fail_on="all")
    cluster = _FakeCluster(collection)
    monkeypatch.setattr(fixture, "get_sdk_connection", lambda: (cluster, None, None))
    _data(tmp_path, [json.dumps({"id": f"k{n}", "doc": {}}) for n in range(50)])
    result = fixture._import_documents(tmp_path, _manifest(count=50), {})
    assert result["documents_written"] == 0
    failures = result["keyspaces"][0]["failures"]
    assert len(failures) <= 20
    assert len(collection.upserts) == 0


def test_a_collection_that_cannot_be_opened_is_reported_not_raised(
    tmp_path, monkeypatch
):
    cluster = _FakeCluster(open_error="bucket not ready")
    monkeypatch.setattr(fixture, "get_sdk_connection", lambda: (cluster, None, None))
    _data(tmp_path, [json.dumps({"id": "k1", "doc": {}})])
    result = fixture._import_documents(tmp_path, _manifest(), {})
    assert result["ok"] is False
    assert "collection could not be opened" in result["keyspaces"][0]["error"]


def test_a_data_file_that_is_missing_is_reported_against_its_keyspace(tmp_path, sdk):
    result = fixture._import_documents(tmp_path, _manifest(), {})
    assert result["ok"] is False
    assert "could not be read" in result["keyspaces"][0]["error"]


def test_a_keyspace_that_is_not_three_parts_is_refused(tmp_path, sdk):
    result = fixture._import_documents(tmp_path, _manifest(keyspace="b"), {})
    assert result["ok"] is False
    assert "not bucket.scope.collection" in result["keyspaces"][0]["error"]


def test_writing_fewer_documents_than_recorded_is_not_ok(tmp_path, sdk):
    """The expected count is in the manifest. Writing 1 of 10 and reporting
    success is the failure this comparison exists for."""
    _data(tmp_path, [json.dumps({"id": "k1", "doc": {}})])
    result = fixture._import_documents(tmp_path, _manifest(count=10), {})
    assert result["keyspaces"][0]["written"] == 1
    assert result["keyspaces"][0]["expected"] == 10
    assert result["ok"] is False


def test_a_manifest_with_no_files_is_vacuously_ok(tmp_path, sdk):
    result = fixture._import_documents(tmp_path, {"files": []}, {})
    assert result == {"documents_written": 0, "keyspaces": [], "ok": True}


def test_documents_follow_the_keyspace_map(tmp_path, monkeypatch):
    collection = _FakeCollection()
    cluster = _FakeCluster(collection)
    monkeypatch.setattr(fixture, "get_sdk_connection", lambda: (cluster, None, None))
    _data(tmp_path, [json.dumps({"id": "k1", "doc": {}})])
    result = fixture._import_documents(
        tmp_path, _manifest(), {"b.s.c": "other.scope2.coll2"}
    )
    assert result["keyspaces"][0]["target"] == "other.scope2.coll2"
    assert cluster.opened == ["other", "scope2", "coll2"]


# ═══ _import_indexes ═════════════════════════════════════════════════════════


def _gsi(name="ix", definition=None, keyspace="b.s.c"):
    return {
        "indexName": name,
        "definition": definition or f"CREATE INDEX `{name}` ON `b`.`s`.`c`(`f`)",
        "keyspace": keyspace,
    }


def test_indexes_are_created_deferred_then_built_in_one_pass(monkeypatch):
    """Building one at a time scans the collection once per index; a single
    BUILD INDEX naming all of them scans it once. On a collection of any size
    that is the difference between minutes and an hour."""
    statements: list[str] = []
    monkeypatch.setattr(fixture, "_query", lambda s, p=None: statements.append(s) or [])
    manifest = {"gsi_definitions": [_gsi("ix1"), _gsi("ix2")]}
    result = fixture._import_indexes(manifest, {})

    assert result["created"] == ["ix1", "ix2"]
    assert result["build_issued_for"] == ["b.s.c"]
    assert sum("defer_build" in s.lower() for s in statements) == 2
    builds = [s for s in statements if s.startswith("BUILD INDEX")]
    assert len(builds) == 1
    assert "`ix1`, `ix2`" in builds[0]


def test_the_build_note_says_acceptance_is_not_completion(monkeypatch):
    """An index that exists but is not online makes the cluster look slow in a
    way that reads as a Couchbase problem."""
    monkeypatch.setattr(fixture, "_query", lambda s, p=None: [])
    result = fixture._import_indexes({"gsi_definitions": [_gsi()]}, {})
    assert "as soon as the build is ACCEPTED" in result["note"]
    assert "state='online'" in result["note"]


def test_a_definition_with_no_name_or_no_statement_is_skipped(monkeypatch):
    monkeypatch.setattr(fixture, "_query", lambda s, p=None: [])
    manifest = {
        "gsi_definitions": [
            {"indexName": "", "definition": "CREATE INDEX x ON y"},
            {"indexName": "ix", "definition": ""},
        ]
    }
    result = fixture._import_indexes(manifest, {})
    assert len(result["skipped"]) == 2
    assert result["created"] == []


def test_an_index_that_already_exists_is_skipped_not_failed(monkeypatch):
    """Re-importing a fixture onto a cluster that already carries its indexes is
    an ordinary case, not an error."""

    def query(statement, parameters=None):
        if statement.startswith("CREATE INDEX"):
            raise RuntimeError("index already exists")
        return []

    monkeypatch.setattr(fixture, "_query", query)
    result = fixture._import_indexes({"gsi_definitions": [_gsi()]}, {})
    assert result["skipped"] == ["ix: already exists"]
    assert result["ok"] is True


def test_couchbase_error_4300_is_also_read_as_already_exists(monkeypatch):
    def query(statement, parameters=None):
        if statement.startswith("CREATE INDEX"):
            raise RuntimeError("error 4300 duplicate index")
        return []

    monkeypatch.setattr(fixture, "_query", query)
    result = fixture._import_indexes({"gsi_definitions": [_gsi()]}, {})
    assert result["skipped"] == ["ix: already exists"]


def test_any_other_create_failure_is_a_failure(monkeypatch):
    def query(statement, parameters=None):
        raise RuntimeError("syntax error near '('")

    monkeypatch.setattr(fixture, "_query", query)
    result = fixture._import_indexes({"gsi_definitions": [_gsi()]}, {})
    assert result["ok"] is False
    assert "syntax error" in result["failures"][0]


def test_a_build_that_fails_names_the_keyspace(monkeypatch):
    def query(statement, parameters=None):
        if statement.startswith("BUILD INDEX"):
            raise RuntimeError("build refused")
        return []

    monkeypatch.setattr(fixture, "_query", query)
    result = fixture._import_indexes({"gsi_definitions": [_gsi()]}, {})
    assert result["ok"] is False
    assert "BUILD INDEX on b.s.c: build refused" in result["failures"][0]


def test_a_keyspace_map_that_rewrites_to_a_bad_target_is_refused(monkeypatch):
    """The worst of the four defects the round trip found was a keyspace_map that
    rewrote only the BUCKET: mapping travel-sample.inventory.airline to
    travel-sample.roundtrip.airline substituted travel-sample for travel-sample,
    a no-op, so every statement still named the source scope. On a fresh target
    it would have built the fixture's indexes on the SOURCE collection and left
    the imported one with none, reporting ok either way.

    The rewrite is now conservative and REFUSES what it cannot do unambiguously.
    A map whose target is not three parts is one of those refusals.
    """
    monkeypatch.setattr(fixture, "_query", lambda s, p=None: [])
    result = fixture._import_indexes(
        {"gsi_definitions": [_gsi()]}, {"b.s.c": "onlyabucket"}
    )
    assert result["ok"] is False
    assert "not bucket.scope.collection" in result["failures"][0]
    assert result["created"] == [], "nothing may be created once the map is bad"


def test_a_keyspace_map_rewrites_the_whole_three_part_target(monkeypatch):
    """The positive half of the same defect: scope and collection must move too,
    not just the bucket."""
    statements: list[str] = []
    monkeypatch.setattr(fixture, "_query", lambda s, p=None: statements.append(s) or [])
    result = fixture._import_indexes(
        {"gsi_definitions": [_gsi()]}, {"b.s.c": "b.roundtrip.c"}
    )
    assert result["ok"] is True
    created = next(s for s in statements if s.startswith("CREATE INDEX"))
    assert "`b`.`roundtrip`.`c`" in created
    assert "`s`" not in created, "the SOURCE scope must not survive the rewrite"


def test_a_statement_whose_target_cannot_be_read_is_left_alone(monkeypatch):
    """Conservative by design: rewriting SQL with regular expressions is how an
    index quietly gets built against the wrong keyspace. A statement this cannot
    parse is passed through unchanged rather than guessed at."""
    monkeypatch.setattr(fixture, "_query", lambda s, p=None: [])
    result = fixture._import_indexes(
        {"gsi_definitions": [_gsi(definition="CREATE INDEX `ix` ON something")]},
        {"b.s.c": "other.scope.coll"},
    )
    assert result["ok"] is True
    assert result["created"] == ["ix"]


def test_an_index_with_no_recorded_keyspace_is_created_but_not_built(monkeypatch):
    """Without a keyspace there is nothing to name in a BUILD INDEX. Creating it
    deferred and saying nothing was built is better than guessing."""
    statements: list[str] = []
    monkeypatch.setattr(fixture, "_query", lambda s, p=None: statements.append(s) or [])
    result = fixture._import_indexes({"gsi_definitions": [_gsi(keyspace="")]}, {})
    assert result["created"] == ["ix"]
    assert result["build_issued_for"] == []
    assert not any(s.startswith("BUILD INDEX") for s in statements)


# ═══ _cluster_counts ═════════════════════════════════════════════════════════


def test_a_matching_count_is_reported_as_necessary_not_sufficient(monkeypatch):
    """COUNT(*) agreed exactly while 187 of 188 document KEYS were wrong. The
    note is the part that stops a reader over-reading the result."""
    monkeypatch.setattr(fixture, "_query", lambda s, p=None: [{"total": 1}])
    result = fixture._cluster_counts(_manifest(), {})
    assert result["ok"] is True
    assert result["keyspaces"][0]["actual"] == 1
    assert "NECESSARY condition, not a sufficient one" in result["note"]
    assert "187" in result["note"]


def test_a_count_mismatch_names_both_numbers(monkeypatch):
    """The check that catches a half-finished import."""
    monkeypatch.setattr(fixture, "_query", lambda s, p=None: [{"total": 3}])
    result = fixture._cluster_counts(_manifest(count=10), {})
    assert result["ok"] is False
    assert "holds 3 documents, the fixture records 10" in result["problems"][0]


def test_a_count_query_that_fails_is_a_problem_not_a_zero(monkeypatch):
    """Reading a failed count as zero would report a missing keyspace as an
    empty one."""

    def query(statement, parameters=None):
        raise RuntimeError("keyspace not found")

    monkeypatch.setattr(fixture, "_query", query)
    result = fixture._cluster_counts(_manifest(), {})
    assert result["ok"] is False
    assert result["keyspaces"][0]["ok"] is False
    assert "keyspace not found" in result["problems"][0]


def test_an_empty_result_set_counts_as_zero(monkeypatch):
    monkeypatch.setattr(fixture, "_query", lambda s, p=None: [])
    result = fixture._cluster_counts(_manifest(count=0), {})
    assert result["keyspaces"][0]["actual"] == 0
    assert result["ok"] is True


def test_counts_refuse_a_keyspace_that_is_not_three_parts(monkeypatch):
    monkeypatch.setattr(fixture, "_query", lambda s, p=None: [{"total": 1}])
    result = fixture._cluster_counts(_manifest(keyspace="bucketonly"), {})
    assert result["ok"] is False
    assert "not bucket.scope.collection" in result["problems"][0]


def test_counts_follow_the_keyspace_map(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(
        fixture,
        "_query",
        lambda s, p=None: seen.append(s) or [{"total": 1}],
    )
    fixture._cluster_counts(_manifest(), {"b.s.c": "t.s2.c2"})
    assert "`t`.`s2`.`c2`" in seen[0]
