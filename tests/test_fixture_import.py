"""Guards for capella_fixture_import and the integrity check it shares with verify.

The importer writes to somebody's cluster, so the interesting cases are the ones
where it must REFUSE before doing so. Each test here pins a refusal that costs
nothing to get wrong in code and a great deal to get wrong in production.

None of these contact a cluster. Every refusal asserted below happens strictly
before the first outbound call, which is itself the property under test: an
importer that validated after creating three buckets would pass a test that only
checked the final verdict.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from handlers.capella import fixture


def _payload(*hashes: str) -> str:
    return hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest()


def _write_fixture(root: pathlib.Path, *, documents: str = '{"id": "a"}\n',
                   mode: str = "server", schema: str | None = None) -> pathlib.Path:
    """A minimal fixture on disk whose manifest is internally consistent."""
    directory = root / "fx"
    (directory / "data").mkdir(parents=True, exist_ok=True)
    data_file = directory / "data" / "b.s.c.jsonl"
    data_file.write_text(documents, encoding="utf-8")
    digest = hashlib.sha256(data_file.read_bytes()).hexdigest()
    manifest = {
        "schema": schema or fixture.MANIFEST_SCHEMA,
        "fixture_id": "fx",
        "name": "fx",
        "mode": mode,
        "created_at": "2026-09-14T00:00:00Z",
        "structure": [],
        "gsi_definitions": [],
        "eventing_functions": [],
        "files": [{"path": "data/b.s.c.jsonl", "keyspace": "b.s.c",
                   "sha256": digest,
                   "document_count": documents.count("\n")}],
        "document_count": documents.count("\n"),
        "payload_sha256": _payload(digest),
        "fidelity": {"documents": True},
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory


def _text(result) -> str:
    return "".join(block.text for block in result)


# ── the integrity check both tools share ─────────────────────────────────────


def test_integrity_accepts_a_fixture_that_matches_its_manifest(tmp_path):
    directory = _write_fixture(tmp_path)
    manifest = json.loads((directory / "manifest.json").read_text())
    _checks, problems, payload = fixture._fixture_integrity(directory, manifest)
    assert problems == []
    assert payload == manifest["payload_sha256"]


def test_integrity_catches_a_file_edited_after_the_fixture_was_written(tmp_path):
    """The whole reason the manifest records hashes."""
    directory = _write_fixture(tmp_path)
    manifest = json.loads((directory / "manifest.json").read_text())
    (directory / "data" / "b.s.c.jsonl").write_text('{"id": "TAMPERED"}\n',
                                                    encoding="utf-8")
    _checks, problems, _payload_sha = fixture._fixture_integrity(directory, manifest)
    assert any("has changed since the fixture was written" in p for p in problems)


def test_integrity_catches_a_missing_data_file(tmp_path):
    directory = _write_fixture(tmp_path)
    manifest = json.loads((directory / "manifest.json").read_text())
    (directory / "data" / "b.s.c.jsonl").unlink()
    _checks, problems, _payload_sha = fixture._fixture_integrity(directory, manifest)
    assert any("does not exist" in p for p in problems)


# ── refusals that must happen before the cluster is touched ──────────────────


def test_import_refuses_a_fixture_that_does_not_verify(tmp_path):
    directory = _write_fixture(tmp_path)
    (directory / "data" / "b.s.c.jsonl").write_text("{}\n{}\n", encoding="utf-8")
    result = fixture._import({"fixture_path": str(directory),
                              "cluster_id": "c", "organization_id": "o",
                              "project_id": "p"})
    body = _text(result)
    assert "NOTHING was imported" in body


def test_import_refuses_a_mobile_fixture(tmp_path):
    """A mobile fixture loaded over the server path loses _sync silently."""
    directory = _write_fixture(tmp_path, mode="mobile")
    result = fixture._import({"fixture_path": str(directory),
                              "cluster_id": "c", "organization_id": "o",
                              "project_id": "p"})
    body = _text(result)
    assert "mobile" in body and "cannot serve a single mobile client" in body


def test_import_refuses_a_manifest_from_another_schema_version(tmp_path):
    directory = _write_fixture(tmp_path, schema="couchbase.capella.fixture/v99")
    result = fixture._import({"fixture_path": str(directory),
                              "cluster_id": "c", "organization_id": "o",
                              "project_id": "p"})
    assert "not importable by this one" in _text(result)


def test_import_requires_a_cluster_id(tmp_path):
    directory = _write_fixture(tmp_path)
    result = fixture._import({"fixture_path": str(directory),
                              "organization_id": "o", "project_id": "p"})
    assert "cluster_id is required" in _text(result)


# ── index definition handling ────────────────────────────────────────────────


def test_source_cluster_node_placement_is_stripped_from_an_index_definition():
    """Replaying the source cluster's hostnames onto another cluster cannot work."""
    statement = (
        'CREATE INDEX `sg_users_x1` ON `travel-sample`((meta().`id`)) '
        'WITH {  "defer_build":true, "nodes":[ "svc-qi-node-004.example:18091",'
        '"svc-qi-node-005.example:18091" ], "num_replica":1 }'
    )
    rewritten, stripped = fixture._strip_index_nodes(statement)
    assert stripped is True
    assert "nodes" not in rewritten
    assert "svc-qi-node-004" not in rewritten
    # num_replica is a property of the index, not of the machine it came from.
    assert '"num_replica":1' in rewritten
    assert '"defer_build":true' in rewritten
    # The WITH clause must still be valid -- no dangling or doubled commas.
    assert ",  }" not in rewritten and ", ," not in rewritten and "{," not in rewritten


def test_a_definition_without_placement_is_left_alone():
    statement = 'CREATE INDEX `i` ON `b`(`x`) WITH { "defer_build":true }'
    rewritten, stripped = fixture._strip_index_nodes(statement)
    assert stripped is False
    assert rewritten == statement


def test_an_ambiguous_keyspace_map_refuses_rather_than_guessing_the_bucket():
    """Two targets for one source bucket means the index's home is undecidable."""
    statement = "CREATE INDEX `i` ON `src`(`x`)"
    _rewritten, why_not = fixture._rewrite_index_keyspace(
        statement, {"src.s.c1": "one.s.c1", "src.s.c2": "two.s.c2"},
    )
    assert "more than one target" in why_not


def test_a_single_target_keyspace_map_rewrites_the_bucket():
    statement = "CREATE INDEX `i` ON `src`(`x`)"
    rewritten, why_not = fixture._rewrite_index_keyspace(
        statement, {"src.s.c1": "dst.s.c1", "src.s.c2": "dst.s.c2"},
    )
    assert why_not == ""
    assert "`dst`" in rewritten and "`src`" not in rewritten


# ── keyspace splitting ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "keyspace,expected",
    [
        ("b.s.c", ("b", "s", "c")),
        # A BUCKET NAME MAY CONTAIN DOTS; a scope or collection name may not. The
        # manifest stores the keyspace as one joined string, so splitting from the
        # left would query a keyspace that does not exist.
        ("my.bucket.s.c", ("my.bucket", "s", "c")),
    ],
)
def test_a_keyspace_splits_from_the_right(keyspace, expected):
    assert fixture._split_keyspace(keyspace) == expected


@pytest.mark.parametrize("keyspace", ["b.s", "b", "", "b..c"])
def test_a_malformed_keyspace_is_rejected_rather_than_padded(keyspace):
    assert fixture._split_keyspace(keyspace) is None


# ── a replica is not a second index ──────────────────────────────────────────


def test_a_replica_suffix_collapses_to_the_base_index_name():
    assert fixture._base_index_name("sg_users_x1 (replica 1)") == "sg_users_x1"
    assert fixture._base_index_name("sg_users_x1 (replica 12)") == "sg_users_x1"
    assert fixture._base_index_name("sg_users_x1") == "sg_users_x1"
    # Not every parenthesis is a replica marker.
    assert fixture._base_index_name("weird(replica)") == "weird(replica)"


# ── the measured KV document endpoint ────────────────────────────────────────


def test_the_document_path_is_the_spelling_that_was_measured():
    """Three candidates were probed against a live cluster; this is the one that
    routed. Pinning it means a later 'tidy-up' cannot quietly reintroduce a guess."""
    assert fixture._DOCUMENT_PATH == (
        "/v1/buckets/{bucket}/scopes/{scope}/collections/{collection}/documents/{key}"
    )


@pytest.mark.parametrize(
    "key,expected",
    [
        # A COUCHBASE KEY IS NOT A PATH SEGMENT UNTIL IT IS ESCAPED. These are not
        # hypothetical shapes: "_sync:user:alice" is what Sync Gateway writes, and
        # an unescaped slash would address a different URL entirely -- which is to
        # say, write to a different document, silently.
        ("_sync:user:alice", "_sync%3Auser%3Aalice"),
        ("order/2026/01", "order%2F2026%2F01"),
        ("a b", "a%20b"),
        ("frag#ment", "frag%23ment"),
        ("q?uery", "q%3Fuery"),
        ("plain", "plain"),
    ],
)
def test_a_document_key_is_escaped_into_the_path(monkeypatch, key, expected):
    seen: dict = {}

    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _fake_urlopen(request, timeout=None):
        seen["url"] = request.full_url
        return _Response()

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    reason = fixture._put_document(
        "https://example.invalid", ("u", "p"), "b", "s", "c", key, {"x": 1},
    )
    assert reason == ""
    assert seen["url"].endswith(f"/documents/{expected}")


def test_a_keyspace_component_is_escaped_too(monkeypatch):
    """A bucket name may contain characters that are not URL-safe."""
    seen: dict = {}

    class _Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda request, timeout=None: (
                            seen.update(url=request.full_url) or _Response()))

    fixture._put_document("https://example.invalid", ("u", "p"),
                          "my bucket", "s", "c", "k", {})
    assert "/buckets/my%20bucket/" in seen["url"]


def test_a_document_write_reports_its_failure_rather_than_raising(monkeypatch):
    """_put_document runs inside a thread pool; a raise there loses the batch."""
    import urllib.request

    def _boom(request, timeout=None):
        raise OSError("connection reset")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    reason = fixture._put_document("https://example.invalid", ("u", "p"),
                                   "b", "s", "c", "k", {})
    assert "OSError" in reason and "connection reset" in reason


# ── the loader ───────────────────────────────────────────────────────────────


def _payload_file(tmp_path: pathlib.Path, rows: list[dict]) -> pathlib.Path:
    target = tmp_path / "p.jsonl"
    target.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return target


def test_the_loader_streams_every_row_and_counts_them(tmp_path, monkeypatch):
    rows = [{"id": f"k{n}", "doc": {"n": n}, "exp": 0} for n in range(25)]
    written: list[str] = []

    def _record(base, credential, bucket, scope, collection, key, body,
                timeout=30):
        written.append(key)
        return ""

    monkeypatch.setattr(fixture, "_put_document", _record)
    loaded, failures, dropped, fatal = fixture._load_documents(
        _payload_file(tmp_path, rows), "https://x", ("u", "p"), ("b", "s", "c"),
    )
    assert (loaded, failures, dropped, fatal) == (25, [], 0, "")
    assert len(written) == 25


def test_an_expiry_that_cannot_be_sent_is_counted_not_ignored(tmp_path, monkeypatch):
    """A document that carried a TTL and arrives without one never expires."""
    rows = [{"id": "a", "doc": {}, "exp": 1789000000},
            {"id": "b", "doc": {}, "exp": 0}]
    monkeypatch.setattr(fixture, "_put_document", lambda *a, **k: "")
    loaded, _failures, dropped, fatal = fixture._load_documents(
        _payload_file(tmp_path, rows), "https://x", ("u", "p"), ("b", "s", "c"),
    )
    assert (loaded, dropped, fatal) == (2, 1, "")


def test_malformed_json_stops_the_keyspace_and_names_the_line(tmp_path, monkeypatch):
    target = tmp_path / "p.jsonl"
    target.write_text('{"id": "a", "doc": {}}\nNOT JSON\n', encoding="utf-8")
    monkeypatch.setattr(fixture, "_put_document", lambda *a, **k: "")
    _loaded, _failures, _dropped, fatal = fixture._load_documents(
        target, "https://x", ("u", "p"), ("b", "s", "c"),
    )
    assert "line 2" in fatal


def test_the_loader_gives_up_rather_than_repeating_one_error_forever(
        tmp_path, monkeypatch):
    """A wrong credential should be diagnosable after twenty rows, not a million."""
    rows = [{"id": f"k{n}", "doc": {}} for n in range(500)]
    monkeypatch.setattr(fixture, "_put_document",
                        lambda *a, **k: "401: wrong credential")
    loaded, failures, _dropped, fatal = fixture._load_documents(
        _payload_file(tmp_path, rows), "https://x", ("u", "p"), ("b", "s", "c"),
    )
    assert loaded == 0
    assert len(failures) < 500
    assert "stopped after" in fatal and "401" in fatal


def test_a_row_without_an_id_is_a_failure_not_a_silent_skip(tmp_path, monkeypatch):
    monkeypatch.setattr(fixture, "_put_document", lambda *a, **k: "")
    loaded, failures, _dropped, _fatal = fixture._load_documents(
        _payload_file(tmp_path, [{"doc": {}}]), "https://x", ("u", "p"),
        ("b", "s", "c"),
    )
    assert loaded == 0
    assert failures and "no id" in failures[0]


# ── cluster verification reports WHERE an index lives ────────────────────────


def _cluster_report(monkeypatch, manifest: dict, index_rows: list[dict],
                    count_rows: list[dict] | None = None) -> dict:
    """Drive _cluster_checks with canned Data API answers."""
    monkeypatch.setattr(fixture, "_data_api_base", lambda ids: ("https://x", ""))
    monkeypatch.setattr(fixture, "_data_api_credential", lambda: (("u", "p"), ""))

    from handlers.capella import environment as env
    monkeypatch.setattr(env, "_resolve_context", lambda args: ("o", "p", None))

    def _query(base, credential, statement, parameters=None, timeout=None):
        if "system:indexes" in statement:
            return {"results": index_rows}
        return {"results": count_rows if count_rows is not None else [{"n": 0}]}

    monkeypatch.setattr(fixture, "_sql_query", _query)
    return fixture._cluster_checks(manifest, {"cluster_id": "c"})


def test_a_deferred_index_is_reported_with_its_keyspace_and_a_build_statement(
        monkeypatch):
    """'mcptest_idx_meta is deferred' is not actionable without a keyspace: the
    operator's next move is BUILD INDEX, which names one."""
    report = _cluster_report(
        monkeypatch,
        {"files": [], "gsi_definitions": []},
        [{"name": "mcptest_idx_meta", "state": "deferred",
          "bucket_id": "travel-sample", "scope_id": "mcptest",
          "keyspace_id": "meta"}],
    )
    entry = report["indexes"]["not_online"][0]
    assert entry["keyspace"] == "travel-sample.mcptest.meta"
    assert entry["build_with"] == (
        "BUILD INDEX ON `travel-sample`.`mcptest`.`meta` (`mcptest_idx_meta`)"
    )


def test_a_pre_collections_index_row_is_read_correctly(monkeypatch):
    """Older rows put the BUCKET in keyspace_id and carry no bucket_id, so the
    same two fields mean different things depending on which shape arrived."""
    report = _cluster_report(
        monkeypatch,
        {"files": [], "gsi_definitions": []},
        [{"name": "old_idx", "state": "deferred", "keyspace_id": "travel-sample"}],
    )
    entry = report["indexes"]["not_online"][0]
    assert entry["keyspace"] == "travel-sample._default._default"


def test_an_online_index_is_not_reported_as_a_problem(monkeypatch):
    report = _cluster_report(
        monkeypatch,
        {"files": [], "gsi_definitions": [{"indexName": "i"}]},
        [{"name": "i", "state": "online", "bucket_id": "b",
          "scope_id": "s", "keyspace_id": "c"}],
    )
    assert report["problems"] == []
    assert report["indexes"]["not_online"] == []


def test_a_recorded_index_that_is_deferred_names_its_keyspace_in_the_problem(
        monkeypatch):
    report = _cluster_report(
        monkeypatch,
        {"files": [], "gsi_definitions": [{"indexName": "i"}]},
        [{"name": "i", "state": "deferred", "bucket_id": "b",
          "scope_id": "s", "keyspace_id": "c"}],
    )
    assert any("on b.s.c is deferred" in problem for problem in report["problems"])
