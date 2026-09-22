"""capella_fixture_verify, and the cluster comparison behind it.

The question this tool exists to answer is "is the cluster the thing the fixture
says it is", and the failure it exists to prevent is a FALSE GREEN -- a verdict of
verified:true over a cluster nobody actually checked. So the cases below are
weighted towards the paths where the check could not be performed, rather than the
ones where it passes.

Three properties are load-bearing and each has a test here:

  * A cluster question that was ASKED and not ANSWERED must fail the verdict.
    Silence would read as agreement, and a caller that passed cluster_id and reads
    verified:true has been told the cluster matches.

  * Replica counts are reported only if the server actually names them. Whether
    system:indexes carries a replica column varies by version, so the code looks
    for one rather than assuming. An unchecked property described as checked is
    the same false green one level down.

  * An index that exists but is not online is a PROBLEM, not a warning. A cluster
    in that state looks slow in a way that reads as a Couchbase performance
    problem, and the report has to name the keyspace because the operator's next
    move is BUILD INDEX, which needs one.

No cluster is contacted: the Data API calls are stubbed. That is what makes the
blocked-and-unreachable branches reachable, and those branches are the ones
carrying the reasoning above.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from handlers.capella import fixture
from handlers.shared import ERROR_MARKER


def payload(result) -> dict:
    return json.loads(result[0].text)


def is_error(result) -> bool:
    return payload(result).get(ERROR_MARKER) is True


def _write(
    root: pathlib.Path,
    *,
    documents: str = '{"id": "a", "doc": {}}\n',
    keyspace: str = "b.s.c",
    gsi: list | None = None,
    schema: str | None = None,
    with_files: bool = True,
) -> pathlib.Path:
    """A fixture on disk whose manifest is internally consistent."""
    directory = root / "fx"
    (directory / "data").mkdir(parents=True, exist_ok=True)
    files = []
    hashes = []
    if with_files:
        data_file = directory / "data" / f"{keyspace}.jsonl"
        data_file.write_text(documents, encoding="utf-8")
        digest = hashlib.sha256(data_file.read_bytes()).hexdigest()
        hashes.append(digest)
        files.append(
            {
                "path": f"data/{keyspace}.jsonl",
                "keyspace": keyspace,
                "sha256": digest,
                "document_count": documents.count("\n"),
            }
        )
    manifest = {
        "schema": schema or fixture.MANIFEST_SCHEMA,
        "fixture_id": "fx",
        "name": "fx",
        "mode": "server",
        "created_at": "2026-09-14T00:00:00Z",
        "source": {"plane": "capella"},
        "structure": [],
        "gsi_definitions": gsi if gsi is not None else [],
        "eventing_functions": [],
        "files": files,
        "document_count": documents.count("\n") if with_files else 0,
        "payload_sha256": hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest(),
        "fidelity": {"documents": True},
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory


def verify(directory, **args):
    return fixture.handle(
        "capella_fixture_verify", {"fixture_path": str(directory), **args}
    )


# ═══ fixture-alone: nothing but the filesystem ═══════════════════════════════


def test_a_consistent_fixture_verifies(tmp_path):
    body = payload(verify(_write(tmp_path)))
    assert body["verified"] is True
    assert body["problems"] == []
    assert body["fixture_id"] == "fx"
    assert body["files_checked"]


def test_the_manifest_file_itself_may_be_named_instead_of_its_directory(tmp_path):
    directory = _write(tmp_path)
    body = payload(verify(directory / "manifest.json"))
    assert body["verified"] is True
    assert body["fixture_path"] == str(directory)


def test_a_directory_with_no_manifest_is_reported(tmp_path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    result = verify(empty)
    assert is_error(result)


def test_a_manifest_that_will_not_parse_is_reported(tmp_path):
    directory = tmp_path / "fx"
    directory.mkdir()
    (directory / "manifest.json").write_text("{ not json", encoding="utf-8")
    result = verify(directory)
    assert is_error(result)
    assert "not valid JSON" in payload(result)["error"]


def test_a_tampered_data_file_fails_its_hash(tmp_path):
    directory = _write(tmp_path)
    (directory / "data" / "b.s.c.jsonl").write_text(
        '{"id": "different", "doc": {}}\n', encoding="utf-8"
    )
    body = payload(verify(directory))
    assert body["verified"] is False
    assert body["problems"]


def test_an_unknown_schema_is_a_problem(tmp_path):
    body = payload(verify(_write(tmp_path, schema="couchbase.fixture/v99")))
    assert body["verified"] is False
    assert body["problems"]


def test_a_structure_only_fixture_says_it_carries_no_data(tmp_path):
    """A legitimate thing to have, but it cannot be verified as carrying data and
    must not be presented as a dataset."""
    body = payload(verify(_write(tmp_path, with_files=False)))
    assert body["verified"] is True
    assert "must not be presented as a dataset" in body["note"]


# ═══ the cluster half ════════════════════════════════════════════════════════


@pytest.fixture
def cluster(monkeypatch):
    """Stub the whole Data API path and the org/project resolution.

    Returns a dict the test mutates to drive the stubs, so each case says only
    what it changes.
    """
    from handlers.capella import environment as env

    state = {
        "context": ("org-1", "proj-1", None),
        "base": ("https://data.invalid", ""),
        "credential": (("u", "p"), ""),
        "counts": {},
        "index_rows": [],
        "count_error": None,
        "index_error": None,
    }

    def resolve(args):
        if isinstance(state["context"], Exception):
            raise state["context"]
        return state["context"]

    def sql(base, credential, statement, parameters=None, timeout=None):
        if "system:indexes" in statement:
            if state["index_error"]:
                raise RuntimeError(state["index_error"])
            return {"results": state["index_rows"]}
        if state["count_error"]:
            raise RuntimeError(state["count_error"])
        for keyspace, n in state["counts"].items():
            bucket, scope, collection = keyspace.split(".")
            if f"`{bucket}`.`{scope}`.`{collection}`" in statement:
                return {"results": [{"n": n}]}
        return {"results": []}

    monkeypatch.setattr(env, "_resolve_context", resolve)
    monkeypatch.setattr(fixture, "_data_api_base", lambda ids: state["base"])
    monkeypatch.setattr(fixture, "_data_api_credential", lambda: state["credential"])
    monkeypatch.setattr(fixture, "_sql_query", sql)
    return state


def test_a_cluster_that_matches_verifies(tmp_path, cluster):
    cluster["counts"] = {"b.s.c": 1}
    body = payload(verify(_write(tmp_path), cluster_id="c1"))
    assert body["verified"] is True
    assert body["cluster_verification"]["performed"] is True
    assert body["cluster_verification"]["keyspaces"][0]["ok"] is True


def test_a_document_count_mismatch_fails_the_top_level_verdict(tmp_path, cluster):
    """The check that catches an import that ran, reported success, and loaded a
    subset."""
    cluster["counts"] = {"b.s.c": 0}
    body = payload(verify(_write(tmp_path), cluster_id="c1"))
    assert body["verified"] is False
    assert "holds 0 documents on the cluster, the fixture holds 1" in " ".join(
        body["problems"]
    )


def test_a_cluster_that_could_not_be_checked_is_not_a_pass(tmp_path, cluster):
    """A caller that passed cluster_id and reads verified:true has been told the
    cluster matches. Leaving the flag green while the check never ran is the
    exact false green this tool exists to prevent."""
    cluster["base"] = ("", "the Data API is not usable on this cluster")
    body = payload(verify(_write(tmp_path), cluster_id="c1"))
    assert body["verified"] is False
    assert body["cluster_verification"]["performed"] is False
    assert "not usable" in body["cluster_verification"]["blocked"]
    assert "was NOT checked" in " ".join(body["problems"])


def test_a_missing_credential_blocks_rather_than_fails_silently(tmp_path, cluster):
    cluster["credential"] = (("", ""), "no Data API credential")
    body = payload(verify(_write(tmp_path), cluster_id="c1"))
    assert body["verified"] is False
    assert "no Data API credential" in body["cluster_verification"]["blocked"]


def test_an_unresolvable_org_context_blocks_the_cluster_check(tmp_path, cluster):
    cluster["context"] = RuntimeError("no organization id configured")
    body = payload(verify(_write(tmp_path), cluster_id="c1"))
    assert body["verified"] is False
    blocked = body["cluster_verification"]["blocked"]
    assert "context could not be resolved" in blocked


def test_a_count_query_failure_is_a_problem_not_a_zero(tmp_path, cluster):
    cluster["count_error"] = "Keyspace not found in CB datastore"
    body = payload(verify(_write(tmp_path), cluster_id="c1"))
    assert body["verified"] is False
    assert "could not be counted" in " ".join(body["problems"])


def test_a_file_record_with_no_keyspace_cannot_be_checked(tmp_path, cluster):
    directory = _write(tmp_path)
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["keyspace"] = ""
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    checks = fixture._cluster_checks(manifest, {"cluster_id": "c1"})
    assert "records no keyspace" in " ".join(checks["problems"])


def test_a_keyspace_that_is_not_three_parts_is_refused(tmp_path, cluster):
    manifest = {"files": [{"path": "d.jsonl", "keyspace": "bucketonly"}]}
    checks = fixture._cluster_checks(manifest, {"cluster_id": "c1"})
    assert "not a bucket.scope.collection" in " ".join(checks["problems"])


def test_a_file_record_that_is_not_an_object_is_ignored(cluster):
    checks = fixture._cluster_checks({"files": ["nonsense"]}, {"cluster_id": "c1"})
    assert checks["keyspaces"] == []


# ── index state ──────────────────────────────────────────────────────────────


def _index_row(name, state="online", bucket="b", scope="s", collection="c", **extra):
    row = {
        "name": name,
        "state": state,
        "bucket_id": bucket,
        "scope_id": scope,
        "keyspace_id": collection,
    }
    row.update(extra)
    return row


def test_an_index_recorded_and_absent_is_a_problem(cluster):
    manifest = {"files": [], "gsi_definitions": [{"indexName": "ix1"}]}
    checks = fixture._cluster_checks(manifest, {"cluster_id": "c1"})
    assert checks["verified"] is False
    assert "does not exist on the cluster" in " ".join(checks["problems"])
    assert checks["indexes"]["missing_on_cluster"] == ["ix1"]


def test_an_index_that_is_not_online_names_the_keyspace_and_the_next_command(
    cluster,
):
    """Reporting "mcptest_idx_meta is deferred" without saying where it lives is
    not actionable: the operator's next move is BUILD INDEX, which names a
    keyspace."""
    cluster["index_rows"] = [_index_row("ix1", state="deferred")]
    manifest = {"files": [], "gsi_definitions": [{"indexName": "ix1"}]}
    checks = fixture._cluster_checks(manifest, {"cluster_id": "c1"})
    assert checks["verified"] is False
    assert "is deferred, not online" in " ".join(checks["problems"])
    entry = checks["indexes"]["not_online"][0]
    assert entry["keyspace"] == "b.s.c"
    assert entry["build_with"] == "BUILD INDEX ON `b`.`s`.`c` (`ix1`)"


def test_a_pre_collections_index_row_is_read_with_its_fields_swapped(cluster):
    """Pre-collections rows put the bucket in keyspace_id and carry no bucket_id
    at all, so the fields mean different things depending on the shape."""
    cluster["index_rows"] = [
        {"name": "ix1", "state": "online", "keyspace_id": "legacy-bucket"}
    ]
    manifest = {"files": [], "gsi_definitions": [{"indexName": "ix1"}]}
    checks = fixture._cluster_checks(manifest, {"cluster_id": "c1"})
    assert checks["verified"] is True


def test_index_state_that_cannot_be_read_is_a_problem(cluster):
    """A cluster whose index states are unknown must not be reported ready for
    measurement."""
    cluster["index_error"] = "User does not have credentials"
    checks = fixture._cluster_checks({"files": []}, {"cluster_id": "c1"})
    assert checks["verified"] is False
    assert checks["indexes"]["read"] is False
    assert "must not be reported" in " ".join(checks["problems"])


def test_replica_counts_are_only_reported_when_the_server_names_them(cluster):
    """Whether system:indexes carries a replica column varies by version. An
    unchecked property described as checked is a false green."""
    cluster["index_rows"] = [_index_row("ix1")]
    manifest = {"files": [], "gsi_definitions": [{"indexName": "ix1"}]}
    checks = fixture._cluster_checks(manifest, {"cluster_id": "c1"})
    assert checks["indexes"]["replicas_checked"] is False
    assert "carries no replica column" in checks["indexes"]["replicas_note"]


def test_a_replica_shortfall_is_reported_when_the_column_exists(cluster):
    """A fixture whose source carried replicas can otherwise be satisfied by a
    cluster with fewer, which changes failover behaviour and read throughput."""
    cluster["index_rows"] = [_index_row("ix1", replica_id=0)]
    manifest = {
        "files": [],
        "gsi_definitions": [{"indexName": "ix1"}, {"indexName": "ix1 (replica 1)"}],
    }
    checks = fixture._cluster_checks(manifest, {"cluster_id": "c1"})
    assert checks["indexes"]["replica_field"] == "replica_id"
    assert checks["verified"] is False
    assert "cop(ies) on the cluster" in " ".join(checks["problems"])


def test_a_definition_with_no_recognisable_name_is_reported_not_skipped(cluster):
    """A coverage gap reported as a pass is the failure this module exists to
    avoid."""
    manifest = {"files": [], "gsi_definitions": [{"no": "name"}, "not-a-dict"]}
    checks = fixture._cluster_checks(manifest, {"cluster_id": "c1"})
    assert checks["indexes"]["unnamed_definitions"] == 2
    assert "NOT checked" in " ".join(checks["problems"])


def test_offline_indexes_are_reported_even_when_the_fixture_recorded_none(cluster):
    cluster["index_rows"] = [_index_row("stray", state="building")]
    checks = fixture._cluster_checks(
        {"files": [], "gsi_definitions": []}, {"cluster_id": "c1"}
    )
    assert checks["verified"] is False
    assert "are not online" in " ".join(checks["problems"])


def test_definitions_that_are_not_a_list_are_treated_as_none(cluster):
    checks = fixture._cluster_checks(
        {"files": [], "gsi_definitions": "nonsense"}, {"cluster_id": "c1"}
    )
    assert checks["indexes"]["recorded_in_fixture"] == 0
