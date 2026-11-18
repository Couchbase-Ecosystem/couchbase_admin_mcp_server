"""Regression tests for the fixture, 8.x and user-password hardening fixes.

Component: regression suite; see tests/README.md.
Spec: docs/spec.md S8, S9.
Main items: tests for manifest index DDL, manifest file paths, identifier quoting,
xattr names, the conflict-log limit, temporary-user roles and password change.
Callers: none; collected by pytest
Callees: `handlers.capella.fixture`, `handlers.eight_x`, `handlers.fixture`,
    `handlers.fixture_core`, `handlers.security`, `handlers.shared`

Each test fails on the code before the fix: a manifest is data from outside the
server and must not steer SQL++ or file reads.
"""

import hashlib
import json

import pytest

from handlers import eight_x, fixture, security
from handlers import fixture_core as core
from handlers.capella import fixture as capella_fixture


class _Cluster:
    """A cluster that records every statement sent to it."""

    def __init__(self):
        self.statements = []

    def query(self, statement, *a, **k):
        self.statements.append(statement)
        return []


def _manifest_dir(tmp_path, manifest):
    """Write `manifest` as manifest.json in `tmp_path` and return the directory."""
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    return tmp_path


def test_import_refuses_non_index_definition_and_names_the_index(tmp_path, monkeypatch):
    """A DELETE in gsi_definitions is refused before anything runs."""
    directory = _manifest_dir(
        tmp_path,
        {
            "schema": "couchbase.fixture/v1",
            "files": [],
            "gsi_definitions": [
                {
                    "indexName": "evil",
                    "keyspace": "b.s.c",
                    "definition": "DELETE FROM `b`.`s`.`c`",
                }
            ],
        },
    )
    cluster = _Cluster()
    monkeypatch.setattr(fixture, "get_sdk_cluster", lambda: cluster)
    monkeypatch.setattr(fixture, "admin_request", lambda *a, **k: {})
    monkeypatch.delenv("CB_ADMIN_FIXTURE_ROOT", raising=False)
    res = fixture.handle(
        "admin_fixture_import", {"fixture_path": str(directory), "confirm": True}
    )
    assert cluster.statements == []
    assert "'evil'" in res[0].text


def test_import_refuses_chained_index_definition(tmp_path, monkeypatch):
    """A CREATE INDEX followed by a second statement is refused."""
    directory = _manifest_dir(
        tmp_path,
        {
            "schema": "couchbase.fixture/v1",
            "files": [],
            "gsi_definitions": [
                {
                    "indexName": "x",
                    "keyspace": "b.s.c",
                    "definition": "CREATE INDEX x ON `b`.`s`.`c`(a); DROP SCOPE `b`.`s`",
                }
            ],
        },
    )
    cluster = _Cluster()
    monkeypatch.setattr(fixture, "get_sdk_cluster", lambda: cluster)
    monkeypatch.setattr(fixture, "admin_request", lambda *a, **k: {})
    monkeypatch.delenv("CB_ADMIN_FIXTURE_ROOT", raising=False)
    fixture.handle(
        "admin_fixture_import", {"fixture_path": str(directory), "confirm": True}
    )
    assert cluster.statements == []


def test_index_definition_problems_accepts_plain_ddl():
    """A normal CREATE INDEX passes the guards unchanged."""
    from handlers.shared import assert_index_create_ddl, assert_single_statement

    manifest = {
        "gsi_definitions": [
            {"indexName": "ok", "definition": "CREATE INDEX ok ON `b`.`s`.`c`(a)"}
        ]
    }
    assert (
        core.index_definition_problems(
            manifest, (assert_single_statement, assert_index_create_ddl)
        )
        == []
    )


def test_capella_import_refuses_non_index_definition(tmp_path, monkeypatch):
    """The Capella plane runs the same index guard before any step."""
    directory = _manifest_dir(
        tmp_path,
        {
            "schema": "couchbase.fixture/v1",
            "files": [],
            "gsi_definitions": [{"indexName": "evil", "definition": "DELETE FROM `b`"}],
        },
    )
    monkeypatch.delenv("CB_ADMIN_FIXTURE_ROOT", raising=False)
    res = capella_fixture.handle(
        "capella_fixture_import",
        {"fixture_path": str(directory), "cluster_id": "c", "confirm": True},
    )
    assert "'evil'" in res[0].text
    assert "NOTHING was imported" in res[0].text


@pytest.mark.parametrize("kind", ["absolute", "dotdot", "symlink"])
def test_verify_reports_escaping_file_path_without_hashing(tmp_path, monkeypatch, kind):
    """files[].path outside the fixture is reported, and its bytes are never hashed."""
    root = tmp_path / "root"
    fx = root / "fx"
    fx.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("top secret\n")
    secret_hash = hashlib.sha256(outside.read_bytes()).hexdigest()
    if kind == "absolute":
        rel = str(outside)
    elif kind == "dotdot":
        rel = "../../outside.txt"
    else:
        (fx / "link.jsonl").symlink_to(outside)
        rel = "link.jsonl"
    (fx / "manifest.json").write_text(
        json.dumps(
            {
                "schema": "couchbase.fixture/v1",
                "files": [{"keyspace": "b.s.c", "path": rel, "document_count": 1}],
            }
        )
    )
    monkeypatch.setenv("CB_ADMIN_FIXTURE_ROOT", str(root))
    res = fixture.handle("admin_fixture_verify", {"fixture_path": str(fx)})
    assert secret_hash not in res[0].text
    assert '"verified": false' in res[0].text


def test_import_documents_refuses_escaping_path(tmp_path, monkeypatch):
    """_import_documents never opens a path outside the fixture directory."""
    outside = tmp_path / "outside.jsonl"
    outside.write_text('{"id": "k", "doc": {}}\n')
    fx = tmp_path / "fx"
    fx.mkdir()
    monkeypatch.setattr(fixture, "get_sdk_cluster", lambda: object())
    out = fixture._import_documents(
        fx, {"files": [{"keyspace": "b.s.c", "path": str(outside)}]}, {}
    )
    assert "absolute" in json.dumps(out)


def test_safe_fixture_file_cases(tmp_path):
    """Relative in-tree paths pass; absolute, dot-dot and NUL paths do not."""
    (tmp_path / "data").mkdir()
    good, why = core.safe_fixture_file(tmp_path, "data/a.jsonl")
    assert good is not None and why == ""
    for bad in (
        "/etc/passwd",
        "../x",
        "data/../../x",
        "a\\..\\b",
        "C:\\x",
        "a\x00b",
        "",
    ):
        path, reason = core.safe_fixture_file(tmp_path, bad)
        assert path is None and reason


def test_quote_identifier_doubles_backticks_and_rejects_control_chars():
    """Backticks double; newline and NUL are refused."""
    assert core.quote_identifier("a`b") == "`a``b`"
    assert core.quote_keyspace_parts(("b", "s", "c`")) == "`b`.`s`.`c```"
    for bad in ("a\nb", "a\x00b", ""):
        with pytest.raises(ValueError):
            core.quote_identifier(bad)


def test_cluster_counts_escapes_keyspace_target(monkeypatch):
    """admin_fixture_verify's count query doubles a backtick in a keyspace_map target."""
    seen = []
    monkeypatch.setattr(
        fixture, "_query", lambda stmt, *a, **k: seen.append(stmt) or [{"total": 0}]
    )
    manifest = {"files": [{"keyspace": "b.s.c", "document_count": 0}]}
    fixture._cluster_counts(manifest, {"b.s.c": "b.s.c`; DROP SCOPE `x"})
    assert seen and "`c``; DROP SCOPE ``x`" in seen[0]


def test_cluster_counts_refuses_control_character_target(monkeypatch):
    """A newline in a target keyspace is a problem, not a query."""
    seen = []
    monkeypatch.setattr(
        fixture, "_query", lambda stmt, *a, **k: seen.append(stmt) or []
    )
    out = fixture._cluster_counts(
        {"files": [{"keyspace": "b.s.c", "document_count": 0}]}, {"b.s.c": "b.s.c\nx"}
    )
    assert seen == [] and out["problems"]


def test_build_index_escapes_backtick_in_names(monkeypatch):
    """BUILD INDEX doubles backticks in the keyspace and the index names."""
    seen = []
    monkeypatch.setattr(
        fixture, "_query", lambda stmt, *a, **k: seen.append(stmt) or []
    )
    manifest = {
        "gsi_definitions": [
            {
                "indexName": "i`x",
                "keyspace": "b.s.c`d",
                "definition": "CREATE INDEX `i``x` ON `b`.`s`.`c``d`(a)",
            }
        ]
    }
    fixture._import_indexes(manifest, {})
    build = [s for s in seen if s.startswith("BUILD INDEX")]
    assert build == ["BUILD INDEX ON `b`.`s`.`c``d`(`i``x`)"]


def test_capella_build_with_escapes():
    """The Capella verify hint doubles backticks and refuses control characters."""
    assert capella_fixture._build_with(
        "b.s.c`", "n`"
    ) == "BUILD INDEX ON `b`.`s`.`c```(`n```)".replace("(", " (")
    assert capella_fixture._build_with("b.s.c\n", "n") == ""


def test_xattr_names_are_validated_in_export_statement():
    """A user xattr name carrying a backtick is refused, a plain one is kept."""
    with pytest.raises(ValueError):
        core.export_statement(
            "b", "s", "c", page_size=10, user_xattrs=["a` AS x, 1 AS `y"]
        )
    assert "`__fixture_xattr_ok`" in core.export_statement(
        "b", "s", "c", page_size=10, user_xattrs=["ok"]
    )


def test_export_refuses_bad_xattr_name(tmp_path, monkeypatch):
    """admin_fixture_export returns an error for a bad xattr name, before any query."""
    monkeypatch.setenv("CB_ADMIN_FIXTURE_ROOT", str(tmp_path))
    cluster = _Cluster()
    monkeypatch.setattr(fixture, "get_sdk_cluster", lambda: cluster)
    res = fixture.handle(
        "admin_fixture_export",
        {
            "fixture_id": "x",
            "fixture_path": str(tmp_path / "x"),
            "user_xattrs": ["a`b"],
        },
    )
    assert "plain identifier" in res[0].text
    assert cluster.statements == []


def test_structure_step_encodes_rest_path_pieces(monkeypatch):
    """Bucket, scope and collection are percent-encoded in the REST path."""
    paths = []

    def fake(method, path, **kw):
        paths.append(path)
        return {"scopes": []}

    monkeypatch.setattr(fixture, "admin_request", fake)
    fixture._import_structure(
        {"files": [{"keyspace": "b/x.s y.c", "document_count": 0}]}, {}
    )
    assert paths and all("b%2Fx" in p for p in paths)
    assert any("s%20y" in p for p in paths)


def _conflict_cluster(monkeypatch):
    seen = {}

    class FakeCluster:
        def query(self, stmt, opts=None):
            seen["opts"] = opts
            return []

    monkeypatch.setattr(eight_x, "_require_8x", lambda n: None)
    monkeypatch.setattr(eight_x, "get_sdk_cluster", lambda: FakeCluster())
    return seen


def test_conflict_log_limit_is_capped(monkeypatch):
    """A huge limit is clamped to the documented maximum."""
    seen = _conflict_cluster(monkeypatch)
    eight_x.handle(
        "admin_xdcr_conflict_log_query", {"bucket_name": "b", "limit": 10**9}
    )
    assert str(eight_x._CONFLICT_LIMIT_MAX) in str(seen["opts"])
    assert "1000000000" not in str(seen["opts"])


def test_conflict_log_limit_default_minimum_and_type(monkeypatch):
    """Default applies, zero rises to one, non-integers are refused."""
    seen = _conflict_cluster(monkeypatch)
    eight_x.handle("admin_xdcr_conflict_log_query", {"bucket_name": "b"})
    assert str(eight_x._CONFLICT_LIMIT_DEFAULT) in str(seen["opts"])
    eight_x.handle("admin_xdcr_conflict_log_query", {"bucket_name": "b", "limit": 0})
    assert "'lim': 1}" in str(seen["opts"]).replace('"', "'")
    res = eight_x.handle(
        "admin_xdcr_conflict_log_query", {"bucket_name": "b", "limit": "lots"}
    )
    assert "integer" in res[0].text


@pytest.mark.parametrize(
    "roles", ["admin; DROP", "admin,", "data_reader[b:s:c:d]", "a b", "role[b`]", ""]
)
def test_temp_user_rejects_malformed_roles(monkeypatch, roles):
    """A roles string outside the role-entry shape is refused before any request."""
    monkeypatch.setattr(eight_x, "_require_8x", lambda n: None)
    calls = []
    monkeypatch.setattr(eight_x, "admin_request", lambda *a, **k: calls.append(a) or {})
    res = eight_x.handle(
        "admin_user_create_temporary",
        {"username": "t", "password": "P@ssw0rd!!", "roles": roles},
    )
    assert calls == []
    assert "role" in res[0].text


def test_temp_user_accepts_scoped_roles(monkeypatch):
    """Legitimate role lists still go through."""
    monkeypatch.setattr(eight_x, "_require_8x", lambda n: None)
    calls = []
    monkeypatch.setattr(
        eight_x, "admin_request", lambda m, p, **kw: calls.append(kw) or {}
    )
    eight_x.handle(
        "admin_user_create_temporary",
        {
            "username": "t",
            "password": "P@ssw0rd!!",
            "roles": "data_reader[travel-sample:inventory:*], query_select[*]",
        },
    )
    assert (
        calls[0]["data"]["roles"]
        == "data_reader[travel-sample:inventory:*],query_select[*]"
    )


def test_change_password_does_not_flatten_group_roles(monkeypatch):
    """Group-derived roles are not re-submitted as direct roles; groups pass through."""
    calls = []

    def fake(method, path, **kw):
        calls.append((method, path, kw))
        if method == "GET":
            return {
                "id": "bob",
                "groups": ["g1"],
                "roles": [
                    {"role": "admin", "origins": [{"type": "group", "name": "g1"}]},
                    {
                        "role": "bucket_admin",
                        "bucket_name": "b",
                        "origins": [{"type": "user"}],
                    },
                    {"role": "ro_admin"},
                ],
            }
        return {"status": "ok"}

    monkeypatch.setattr(security, "admin_request", fake)
    security.handle(
        "admin_user_change_password",
        {"username": "bob", "password": "NewPw123!", "confirm": True},
    )
    data = next(c for c in calls if c[0] == "PUT")[2]["data"]
    assert data["roles"].split(",") == ["bucket_admin[b]", "ro_admin"]
    assert data["groups"] == "g1"
