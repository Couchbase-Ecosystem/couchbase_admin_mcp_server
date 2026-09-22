"""The self-managed exporter's cluster walk, and the listing beside it.

The walk is the half that decides what a fixture CLAIMS to describe, and its
failure mode is quiet: a bucket whose scopes cannot be read, dropped rather than
recorded, produces a fixture that says it describes a cluster and does not. So
every branch here is about recording a gap instead of losing it -- the module
carries warnings rather than exceptions for exactly that reason.

The listing is filesystem-only and its one rule is the same one: a manifest that
will not parse is REPORTED, never skipped, because a listing that omits an
unreadable fixture answers "what do I have" with a confident lie.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from handlers import fixture
from handlers.shared import ERROR_MARKER


def payload(result) -> dict:
    return json.loads(result[0].text)


def is_error(result) -> bool:
    return payload(result).get(ERROR_MARKER) is True


@pytest.fixture
def admin(monkeypatch):
    """Replace the cluster's admin REST surface with a scripted one."""
    state = {"responses": {}, "errors": {}}

    def request(method, path, data=None, **kwargs):
        if path in state["errors"]:
            raise RuntimeError(state["errors"][path])
        if path in state["responses"]:
            return state["responses"][path]
        return {}

    monkeypatch.setattr(fixture, "admin_request", request)
    return state


# ═══ the cluster identity a manifest records ═════════════════════════════════


def test_the_identity_records_the_cluster_uuid_and_its_nodes(admin):
    """A fixture is meaningless six months later if nobody can say which cluster
    it came from, and on a self-managed cluster there is no organization or
    project id to name one."""
    admin["responses"]["/pools"] = {"uuid": "abc", "implementationVersion": "7.6.0"}
    admin["responses"]["/pools/default"] = {
        "clusterName": "prod",
        "nodes": [{"hostname": "n1:8091"}, {"hostname": "n2:8091"}, "not-an-object"],
    }
    identity = fixture._cluster_identity()
    assert identity["cluster_uuid"] == "abc"
    assert identity["implementation_version"] == "7.6.0"
    assert identity["cluster_name"] == "prod"
    assert identity["nodes"] == ["n1:8091", "n2:8091"]


def test_an_unreadable_identity_is_recorded_as_an_error_not_dropped(admin):
    """Half an identity is still worth having, and the half that failed has to
    say so rather than being absent."""
    admin["errors"]["/pools"] = "401 unauthorized"
    admin["errors"]["/pools/default"] = "connection refused"
    identity = fixture._cluster_identity()
    assert "401 unauthorized" in identity["cluster_uuid_error"]
    assert "connection refused" in identity["cluster_name_error"]
    assert "cluster_uuid" not in identity


def test_an_identity_response_of_the_wrong_shape_is_ignored_quietly(admin):
    admin["responses"]["/pools"] = ["not", "a", "dict"]
    admin["responses"]["/pools/default"] = "neither"
    identity = fixture._cluster_identity()
    assert identity["plane"]
    assert "cluster_uuid" not in identity


# ═══ the structure walk ══════════════════════════════════════════════════════


def test_a_bucket_listing_that_fails_stops_the_walk(admin):
    admin["errors"]["/pools/default/buckets"] = "403 forbidden"
    with pytest.raises(RuntimeError) as caught:
        fixture._structure(set())
    assert "could not list buckets" in str(caught.value)


def test_a_bucket_listing_of_the_wrong_shape_is_refused_with_its_type(admin):
    """This is the shape the rest of the walk depends on, so guessing at it would
    produce a structure built from nothing."""
    admin["responses"]["/pools/default/buckets"] = {"not": "a list"}
    with pytest.raises(RuntimeError) as caught:
        fixture._structure(set())
    assert "returned dict, not a" in str(caught.value)


def test_a_bucket_entry_that_is_not_an_object_is_warned_about_not_dropped(admin):
    admin["responses"]["/pools/default/buckets"] = ["a string", {"name": "b"}]
    structure, warnings = fixture._structure(set())
    assert any("is not an object" in w for w in warnings)
    assert [b["name"] for b in structure] == ["b"]


def test_only_the_wanted_buckets_are_walked(admin):
    admin["responses"]["/pools/default/buckets"] = [{"name": "a"}, {"name": "b"}]
    structure, _warnings = fixture._structure({"b"})
    assert [b["name"] for b in structure] == ["b"]


def test_a_bucket_whose_scopes_cannot_be_read_is_recorded_with_the_reason(admin):
    """A structure that silently omits a bucket produces a fixture that claims to
    describe a cluster and does not."""
    admin["responses"]["/pools/default/buckets"] = [{"name": "b"}]
    admin["errors"]["/pools/default/buckets/b/scopes"] = "timed out"
    structure, warnings = fixture._structure(set())
    assert [b["name"] for b in structure] == ["b"], "the bucket is still recorded"
    assert any("timed out" in w for w in warnings)


# ═══ the listing ═════════════════════════════════════════════════════════════


def _fixture_dir(root: pathlib.Path, name: str, **manifest) -> pathlib.Path:
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    body = {
        "schema": fixture.MANIFEST_SCHEMA,
        "fixture_id": name,
        "name": name,
        "mode": "server",
        "created_at": "2026-09-14T00:00:00Z",
        "tags": {},
        "document_count": 0,
    }
    body.update(manifest)
    (directory / "manifest.json").write_text(json.dumps(body), encoding="utf-8")
    return directory


def _list(root, **args):
    return fixture.handle("admin_fixture_list", {"root_path": str(root), **args})


def test_listing_a_path_that_is_not_a_directory_is_refused(tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("x", encoding="utf-8")
    assert is_error(_list(target))


def test_tags_must_be_an_object(tmp_path):
    _fixture_dir(tmp_path, "fx")
    result = _list(tmp_path, tags="tier=gold")
    assert is_error(result)
    assert "tags must be an object" in payload(result)["error"]


def test_a_directory_without_a_manifest_is_not_a_fixture(tmp_path):
    _fixture_dir(tmp_path, "fx")
    (tmp_path / "not-a-fixture").mkdir()
    (tmp_path / "loose-file.txt").write_text("x", encoding="utf-8")
    body = payload(_list(tmp_path))
    assert [f["fixture_id"] for f in body["fixtures"]] == ["fx"]


def test_an_unreadable_manifest_is_reported_not_skipped(tmp_path):
    """A listing that omits an unreadable fixture answers "what do I have" with a
    confident lie."""
    _fixture_dir(tmp_path, "good")
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "manifest.json").write_text("{ not json", encoding="utf-8")

    body = payload(_list(tmp_path))
    assert [f["fixture_id"] for f in body["fixtures"]] == ["good"]
    assert len(body["unreadable"]) == 1


def test_tags_filter_by_exact_match(tmp_path):
    _fixture_dir(tmp_path, "gold", tags={"tier": "gold"})
    _fixture_dir(tmp_path, "scratch", tags={"tier": "scratch"})
    body = payload(_list(tmp_path, tags={"tier": "gold"}))
    assert [f["fixture_id"] for f in body["fixtures"]] == ["gold"]


def test_a_fixture_missing_one_of_several_wanted_tags_does_not_match(tmp_path):
    _fixture_dir(tmp_path, "partial", tags={"tier": "gold"})
    body = payload(_list(tmp_path, tags={"tier": "gold", "region": "eu"}))
    assert body["fixtures"] == []
