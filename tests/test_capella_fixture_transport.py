"""The Capella fixture family's transport layer and its listing.

Three groups, chosen because each one has a measured failure behind it:

  * The Data API base URL is NOT derived from the cluster id. The module's own
    docstring once claimed it was `https://{clusterId}.data.cloud.couchbase.com`
    -- the pattern the public docs show -- but a Capella cluster has TWO
    identifiers and the docs do not say which one that is. It reads
    `connectionString` from the control plane instead, and an EMPTY one is the
    answer "not enabled yet" rather than a lookup failure.

  * A document key is not a path segment until it is escaped. Couchbase keys
    routinely carry '/' and ':' -- `_sync:user:alice`, `order/2026/01` -- and an
    unescaped one addresses a different URL, or a different document.

  * `_list` walks rather than glances. The first version looked only at
    root_path's immediate children, so a caller who pointed it at a repository
    root got "no fixtures" while fixtures/<id>/manifest.json sat two levels down.
    Answering "you have none" when the answer is "you have one" is the worst
    failure available to a listing tool.

Nothing here contacts Capella. urlopen is stubbed, which is what makes the error
branches -- a 401, a CIDR timeout, a non-2xx status -- reachable at all. Those
branches carry the diagnostic text a caller needs when a Data API call fails, and
untested diagnostic text is how a message comes to describe a different problem
than the one it fires on.
"""

from __future__ import annotations

import io
import json
import pathlib
import urllib.error

import pytest

from handlers.capella import fixture
from handlers.shared import ERROR_MARKER


def payload(result) -> dict:
    return json.loads(result[0].text)


def is_error(result) -> bool:
    return payload(result).get(ERROR_MARKER) is True


class _Response:
    def __init__(self, status=200, body=b"{}"):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _http_error(code, body=b"nope"):
    return urllib.error.HTTPError(
        "https://example.invalid", code, "err", {}, io.BytesIO(body)
    )


# ═══ _data_api_base ══════════════════════════════════════════════════════════


def _with_status(monkeypatch, value):
    """Stand in for the control-plane GET .../dataAPI call."""
    from handlers.capella import client

    def fake(method, path, *a, **kw):
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(client, "capella_request", fake)


IDS = {
    "organization_id": "org-1",
    "project_id": "proj-1",
    "cluster_id": "clus-1",
}


def test_the_base_url_comes_from_the_control_plane_not_the_cluster_id(monkeypatch):
    _with_status(monkeypatch, {"connectionString": "abc.data.cloud.couchbase.com"})
    base, why = fixture._data_api_base(IDS)
    assert why == ""
    assert base == "https://abc.data.cloud.couchbase.com"


def test_a_connection_string_that_already_has_a_scheme_is_left_alone(monkeypatch):
    _with_status(monkeypatch, {"connectionString": "https://abc.example.com/"})
    base, why = fixture._data_api_base(IDS)
    assert (base, why) == ("https://abc.example.com", "")


def test_an_empty_connection_string_is_not_yet_rather_than_a_failure(monkeypatch):
    """The control plane saying 'not yet'. Handing back a URL that will time out
    instead would send the caller to the CIDR list for an entitlement problem."""
    _with_status(
        monkeypatch, {"connectionString": "", "enabled": True, "state": "deploying"}
    )
    base, why = fixture._data_api_base(IDS)
    assert base == ""
    assert "not yet" in why
    assert "capella_data_api_set" in why
    assert "state='deploying'" in why


def test_a_status_call_that_raises_is_reported_not_propagated(monkeypatch):
    _with_status(monkeypatch, RuntimeError("403 forbidden"))
    base, why = fixture._data_api_base(IDS)
    assert base == ""
    assert "could not be read" in why and "403 forbidden" in why


def test_a_status_response_that_is_not_an_object_is_refused(monkeypatch):
    _with_status(monkeypatch, ["unexpected"])
    base, why = fixture._data_api_base(IDS)
    assert base == ""
    assert "was not an object" in why


# ═══ _data_api_credential ════════════════════════════════════════════════════


def test_the_credential_is_read_from_the_cluster_access_variables(monkeypatch):
    monkeypatch.setenv(fixture._DATA_USER_ENV, "fixture-user")
    monkeypatch.setenv(fixture._DATA_PASSWORD_ENV, "s3cret")
    credential, why = fixture._data_api_credential()
    assert credential == ("fixture-user", "s3cret")
    assert why == ""


@pytest.mark.parametrize("present", ["neither", "user", "password"])
def test_a_missing_credential_says_which_kind_of_secret_is_wanted(monkeypatch, present):
    """The Data API answers 401 to a Bearer token without saying which secret was
    wrong, so the message has to say it instead."""
    monkeypatch.delenv(fixture._DATA_USER_ENV, raising=False)
    monkeypatch.delenv(fixture._DATA_PASSWORD_ENV, raising=False)
    if present == "user":
        monkeypatch.setenv(fixture._DATA_USER_ENV, "u")
    if present == "password":
        monkeypatch.setenv(fixture._DATA_PASSWORD_ENV, "p")

    credential, why = fixture._data_api_credential()
    assert credential == ("", "")
    assert "CLUSTER ACCESS credential" in why
    assert "not the organization" in why
    assert "data_reader" in why and "data_writer" in why


# ═══ _put_document ═══════════════════════════════════════════════════════════


def test_a_document_key_is_escaped_before_it_becomes_a_path_segment(monkeypatch):
    """`_sync:user:alice` and `order/2026/01` are ordinary Couchbase keys. An
    unescaped one addresses a different URL, or a different document."""
    seen: list[str] = []

    def fake_urlopen(request, timeout=None):
        seen.append(request.full_url)
        return _Response(200)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    why = fixture._put_document(
        "https://base", ("u", "p"), "b", "s", "c", "order/2026/01", {"a": 1}
    )
    assert why == ""
    assert "order%2F2026%2F01" in seen[0]
    assert "/documents/order/2026/01" not in seen[0]


def test_a_put_sends_basic_auth_and_json(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["auth"] = request.get_header("Authorization")
        captured["type"] = request.get_header("Content-type")
        captured["method"] = request.get_method()
        captured["body"] = request.data
        return _Response(201)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert (
        fixture._put_document("https://base", ("u", "p"), "b", "s", "c", "k", {"a": 1})
        == ""
    )
    assert captured["auth"].startswith("Basic ")
    assert captured["type"] == "application/json"
    assert captured["method"] == "PUT", "PUT upserts; POST answers conflict"
    assert json.loads(captured["body"]) == {"a": 1}


def test_a_non_2xx_status_is_returned_as_the_reason(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda r, timeout=None: _Response(302)
    )
    assert (
        fixture._put_document("https://b", ("u", "p"), "b", "s", "c", "k", {}) == "302"
    )


def test_an_http_error_carries_its_body_back_to_the_caller(monkeypatch):
    def fake(request, timeout=None):
        raise _http_error(403, b"forbidden by CIDR")

    monkeypatch.setattr("urllib.request.urlopen", fake)
    why = fixture._put_document("https://b", ("u", "p"), "b", "s", "c", "k", {})
    assert why.startswith("403: ")
    assert "forbidden by CIDR" in why


def test_any_other_failure_is_returned_rather_than_raised(monkeypatch):
    """It runs inside a thread pool: a per-document failure is data the caller
    aggregates, not an exception that should unwind the batch."""

    def fake(request, timeout=None):
        raise TimeoutError("timed out")

    monkeypatch.setattr("urllib.request.urlopen", fake)
    why = fixture._put_document("https://b", ("u", "p"), "b", "s", "c", "k", {})
    assert why == "TimeoutError: timed out"


# ═══ _sql_query ══════════════════════════════════════════════════════════════


def test_a_query_returns_the_parsed_body(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda r, timeout=None: _Response(200, json.dumps({"results": [1]}).encode()),
    )
    assert fixture._sql_query("https://b", ("u", "p"), "SELECT 1") == {"results": [1]}


def test_named_parameters_are_merged_into_the_request_body(monkeypatch):
    captured = {}

    def fake(request, timeout=None):
        captured["body"] = json.loads(request.data)
        return _Response(200, b"{}")

    monkeypatch.setattr("urllib.request.urlopen", fake)
    fixture._sql_query("https://b", ("u", "p"), "SELECT 1", {"$k": "v"})
    assert captured["body"] == {"statement": "SELECT 1", "$k": "v"}


def test_a_401_names_the_kind_of_credential_rather_than_the_value(monkeypatch):
    """401 from the Data API almost always means the wrong KIND of credential."""

    def fake(request, timeout=None):
        raise _http_error(401, b"unauthorized")

    monkeypatch.setattr("urllib.request.urlopen", fake)
    with pytest.raises(RuntimeError) as caught:
        fixture._sql_query("https://b", ("u", "p"), "SELECT 1")
    assert "Data API 401" in str(caught.value)
    assert "wrong KIND" in str(caught.value)
    assert fixture._DATA_USER_ENV in str(caught.value)


def test_a_403_points_at_the_allowed_cidr_list(monkeypatch):
    """A fixture cluster allowlisted to 192.0.2.1/32 grants nothing to anybody,
    and the refusal does not say so by itself."""

    def fake(request, timeout=None):
        raise _http_error(403, b"forbidden")

    monkeypatch.setattr("urllib.request.urlopen", fake)
    with pytest.raises(RuntimeError) as caught:
        fixture._sql_query("https://b", ("u", "p"), "SELECT 1")
    assert "allowed CIDR list" in str(caught.value)


def test_an_error_body_is_returned_at_length_rather_than_truncated_to_nothing(
    monkeypatch,
):
    """A query service refusal names the keyspace and the reason. Truncating that
    turns a fixable problem into a mystery."""

    def fake(request, timeout=None):
        raise _http_error(400, b"Keyspace not found in CB datastore: default:missing")

    monkeypatch.setattr("urllib.request.urlopen", fake)
    with pytest.raises(RuntimeError) as caught:
        fixture._sql_query("https://b", ("u", "p"), "SELECT 1")
    assert "Keyspace not found" in str(caught.value)


def test_an_unreachable_data_api_explains_that_a_timeout_looks_like_a_hang(
    monkeypatch,
):
    """A data-plane client that is not allowlisted is DROPPED rather than
    refused, so it looks like a hang and not a rejection."""

    def fake(request, timeout=None):
        raise TimeoutError("timed out")

    monkeypatch.setattr("urllib.request.urlopen", fake)
    with pytest.raises(RuntimeError) as caught:
        fixture._sql_query("https://b", ("u", "p"), "SELECT 1")
    text = str(caught.value)
    assert "unreachable" in text
    assert "allowed-CIDR list" in text
    assert "TLS interception" in text


# ═══ keyspace remapping: the defect that loaded 0 of 188 documents ═══════════


def test_remap_bucket_falls_through_to_the_source_when_unmapped():
    assert fixture._remap_bucket("b", {}) == "b"
    assert fixture._remap_bucket("b", {"other.s.c": "target.s.c"}) == "b"
    assert fixture._remap_bucket("b", {"b.s.c": "target.s.c"}) == "target"


def test_remap_triple_moves_the_scope_as_well_as_the_bucket():
    """MEASURED 2026-09-14 on a live Capella round trip. The structure step
    remapped only the bucket, so travel-sample.inventory.airline ->
    travel-sample.roundtrip.airline created NOTHING: the bucket rewrote to
    itself, `inventory` already existed, and `roundtrip` was never made. The
    document step, which always used the full remap, then wrote into a scope that
    did not exist -- 24 consecutive 404 ScopeNotFound, 0 of 188 documents loaded.

    It only shows when source and target share a bucket, which is why a round
    trip into a DIFFERENT bucket passed.
    """
    mapped = fixture._remap_triple(
        "travel-sample",
        "inventory",
        "airline",
        {"travel-sample.inventory.airline": "travel-sample.roundtrip.airline"},
    )
    assert mapped == ("travel-sample", "roundtrip", "airline")


def test_remap_triple_leaves_an_unmapped_keyspace_alone():
    """The common case: most recorded collections are not being retargeted.

    The map is keyed on the WHOLE keyspace, so an entry for a different
    collection in the same bucket does not drag this one along with it. That is
    the conservative reading, and the one that stops a rewrite reaching a
    keyspace nobody named.
    """
    assert fixture._remap_triple("b", "s", "c", {}) == ("b", "s", "c")
    assert fixture._remap_triple("b", "s", "c", {"b.x.y": "t.x.y"}) == ("b", "s", "c")


def test_remap_bucket_is_the_fallback_only_when_the_mapped_value_is_unusable():
    """_remap_triple falls back to the bucket-only remap when the mapped value
    is not a three-part keyspace. Reached through _remap_bucket directly, since
    a well-formed map never gets there."""
    assert fixture._remap_bucket("b", {"b.s.c": "t.s.c"}) == "t"


# ═══ _list ═══════════════════════════════════════════════════════════════════


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
    return fixture.handle("capella_fixture_list", {"root_path": str(root), **args})


def test_listing_a_path_that_is_not_a_directory_says_what_it_wanted(tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("x", encoding="utf-8")
    result = _list(target)
    assert is_error(result)
    assert "is the directory that CONTAINS fixtures" in payload(result)["error"]


def test_it_walks_instead_of_glancing_at_the_immediate_children(tmp_path):
    """Pointing it at a repository root is the obvious thing to do, and the first
    version answered "no fixtures" while fixtures/<id>/manifest.json sat two
    levels down."""
    _fixture_dir(tmp_path / "fixtures", "fx1")
    body = payload(_list(tmp_path))
    assert body["matched"] == 1
    assert body["fixtures"][0]["fixture_id"] == "fx1"


def test_a_manifest_at_the_root_itself_is_found(tmp_path):
    _fixture_dir(tmp_path, ".")
    body = payload(_list(tmp_path))
    assert body["matched"] == 1


def test_the_walk_stops_before_it_becomes_a_disk_crawl(tmp_path):
    """Bounded at four levels, and a fixture is not inside .git or a virtualenv."""
    _fixture_dir(tmp_path / "a/b/c/d/e", "deep")
    _fixture_dir(tmp_path / ".git", "ingit")
    _fixture_dir(tmp_path / "node_modules", "invendor")
    _fixture_dir(tmp_path, "shallow")
    body = payload(_list(tmp_path))
    found = {f["fixture_id"] for f in body["fixtures"]}
    assert "shallow" in found
    assert "ingit" not in found and "invendor" not in found
    assert "deep" not in found


def test_a_manifest_that_will_not_parse_is_reported_not_skipped(tmp_path):
    """A listing that omits it answers "what fixtures do I have" with a confident
    lie."""
    _fixture_dir(tmp_path, "good")
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "manifest.json").write_text("{ not json", encoding="utf-8")
    notobject = tmp_path / "notobject"
    notobject.mkdir()
    (notobject / "manifest.json").write_text("[1,2]", encoding="utf-8")

    body = payload(_list(tmp_path))
    assert body["matched"] == 1
    assert body["scanned"] == 3
    assert len(body["unreadable"]) == 2
    assert "could not be read or parsed" in body["note"]


def test_tags_filter_by_exact_match_and_exclusion(tmp_path):
    _fixture_dir(tmp_path, "gold", tags={"tier": "gold", "version": "1.6"})
    _fixture_dir(tmp_path, "scratch", tags={"tier": "scratch"})

    body = payload(_list(tmp_path, match_tags={"tier": "gold"}))
    assert [f["fixture_id"] for f in body["fixtures"]] == ["gold"]

    body = payload(_list(tmp_path, exclude_tags={"tier": "scratch"}))
    assert [f["fixture_id"] for f in body["fixtures"]] == ["gold"]

    body = payload(_list(tmp_path, match_tags={"tier": "platinum"}))
    assert body["matched"] == 0


def test_the_original_requirement_latest_where_a_tag_matches(tmp_path):
    """ "Latest where content-publisher-version = 1.6" has nothing to match
    against in a Capella backup; it matches here."""
    _fixture_dir(
        tmp_path,
        "old",
        created_at="2026-01-01T00:00:00Z",
        tags={"content-publisher-version": "1.6"},
    )
    _fixture_dir(
        tmp_path,
        "new",
        created_at="2026-06-01T00:00:00Z",
        tags={"content-publisher-version": "1.6"},
    )
    _fixture_dir(
        tmp_path,
        "other",
        created_at="2026-09-01T00:00:00Z",
        tags={"content-publisher-version": "1.7"},
    )
    body = payload(
        _list(
            tmp_path,
            match_tags={"content-publisher-version": "1.6"},
            latest_only=True,
        )
    )
    assert [f["fixture_id"] for f in body["fixtures"]] == ["new"]


def test_fixtures_are_returned_newest_first(tmp_path):
    _fixture_dir(tmp_path, "old", created_at="2026-01-01T00:00:00Z")
    _fixture_dir(tmp_path, "new", created_at="2026-06-01T00:00:00Z")
    body = payload(_list(tmp_path))
    assert [f["fixture_id"] for f in body["fixtures"]] == ["new", "old"]


def test_an_unparseable_date_filter_is_refused_rather_than_ignored(tmp_path):
    _fixture_dir(tmp_path, "fx")
    result = _list(tmp_path, created_after="last tuesday")
    assert is_error(result)
    assert "not an ISO-8601 timestamp" in payload(result)["error"]


def test_a_fixture_with_no_parseable_date_cannot_satisfy_a_date_filter(tmp_path):
    """Treating it as a match would answer "what did we take last month" with
    something of unknown age."""
    _fixture_dir(tmp_path, "undated", created_at="whenever")
    body = payload(_list(tmp_path, created_after="2020-01-01T00:00:00Z"))
    assert body["matched"] == 0


def test_date_filters_bound_on_both_sides(tmp_path):
    _fixture_dir(tmp_path, "early", created_at="2026-01-01T00:00:00Z")
    _fixture_dir(tmp_path, "middle", created_at="2026-06-01T00:00:00Z")
    _fixture_dir(tmp_path, "late", created_at="2026-12-01T00:00:00Z")
    body = payload(
        _list(
            tmp_path,
            created_after="2026-03-01T00:00:00Z",
            created_before="2026-09-01T00:00:00Z",
        )
    )
    assert [f["fixture_id"] for f in body["fixtures"]] == ["middle"]


def test_a_fixture_whose_tags_are_not_an_object_never_matches(tmp_path):
    _fixture_dir(tmp_path, "bent", tags=["not", "an", "object"])
    body = payload(_list(tmp_path, match_tags={"a": "b"}))
    assert body["matched"] == 0


def test_the_whole_manifest_is_not_echoed_back_in_the_listing(tmp_path):
    """The listing is an index. Returning every manifest in full makes the
    response size scale with the fixtures' contents rather than their count."""
    _fixture_dir(tmp_path, "fx")
    body = payload(_list(tmp_path))
    assert "manifest" not in body["fixtures"][0]
    assert body["fixtures"][0]["fixture_path"].endswith("fx")
