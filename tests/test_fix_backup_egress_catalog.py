"""Regression tests for the backup egress, strict host shape and catalogue confinement fixes.

Component: regression suite; see tests/README.md.
Spec: docs/spec.md S10 (egress allowlist) and S9 (backup catalogue).
Main items: restore and repository-create egress tests, strict host shape tests, added denied
    ranges, catalogue root confinement, schema marker and non-UTF-8 tests.
Callers: none; collected by pytest
Callees: `handlers.backup`, `handlers.egress`, `handlers.backup_catalog`

Each test failed on the code before the fix: a restore target or repository archive under a
key that is not host-like reached the Backup service unchecked, `split_host` extracted a host
from values with a path or query, several internal ranges were not denied, and any caller could
aim the catalogue tools at any directory.
"""

from __future__ import annotations

import json

import pytest

from handlers import backup, egress
from handlers import backup_catalog as bc


@pytest.fixture
def sent(monkeypatch):
    """Capture backup service requests and fix the egress environment."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "allowed.example.com,10.9.0.5")
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOW_ANY", raising=False)
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")
    calls = []

    def fake(method, path, **kw):
        calls.append((method, path, kw))
        return {"ok": True}

    monkeypatch.setattr(backup, "admin_request", fake)
    return calls


def _restore(target):
    return backup.handle(
        "admin_backup_restore_run",
        {"repository_id": "r", "target": target, "confirm": True},
    )


def _create(archive):
    return backup.handle(
        "admin_backup_repository_create",
        {
            "repository_id": "r",
            "plan": "_daily_backups",
            "archive": archive,
            "confirm": True,
        },
    )


@pytest.mark.parametrize(
    "dest",
    [
        "http://169.254.169.254/",
        "http://127.0.0.1:8091",
        "http://evil.example.net:8091",
        "http://10.1.2.3:8091",
        "http://168.63.129.16",
    ],
)
def test_restore_target_destination_is_checked(sent, dest):
    out = _restore({"target": dest, "user": "u", "password": "p"})
    assert sent == [], out[0].text
    assert "error" in json.loads(out[0].text)


def test_restore_target_allowlisted_host_still_works(sent):
    _restore(
        {"target": "https://allowed.example.com:18091", "user": "u", "password": "p"}
    )
    assert len(sent) == 1


@pytest.mark.parametrize(
    "archive",
    [
        "s3://attacker-bucket/x",
        "az://attacker/c",
        "gs://attacker-bucket/p",
        "https://169.254.169.254/latest",
        "https://evil.example.net/b",
        "s3://169.254.169.254/x",
        "s3://10.1.2.3/x",
    ],
)
def test_repository_archive_is_checked(sent, archive):
    out = _create(archive)
    assert sent == [], out[0].text
    assert "error" in json.loads(out[0].text)


@pytest.mark.parametrize(
    "archive",
    [
        "/data/backups",
        "./rel/dir",
        "s3://allowed.example.com/p",
        "https://allowed.example.com/b",
    ],
)
def test_repository_archive_legitimate_forms_pass(sent, archive):
    out = _create(archive)
    assert len(sent) == 1, out[0].text


def test_allow_any_admits_a_public_bucket_but_never_metadata(sent, monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    _create("s3://some-public-bucket/x")
    assert len(sent) == 1
    sent.clear()
    out = _create("s3://169.254.169.254/x")
    assert sent == [] and "error" in json.loads(out[0].text)


@pytest.mark.parametrize("key", ["target", "archive", "remote", "destination"])
def test_explicit_destination_keys_are_guarded_in_nested_payloads(monkeypatch, key):
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOW_ANY", raising=False)
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "allowed.example.com")
    with pytest.raises(egress.EgressDeniedError):
        egress.guard_nested_host_fields(
            {"x": {key: "http://169.254.169.254/"}}, tool="t"
        )
    with pytest.raises(egress.EgressDeniedError):
        egress.guard_host_like_fields({key: "http://169.254.169.254/"}, tool="t")
    # A non-destination value under the same key is not refused.
    egress.guard_nested_host_fields({key: "/var/data"}, tool="t")


@pytest.mark.parametrize(
    "value",
    [
        "allowed.example.com/evil",
        "https://allowed.example.com/x",
        "allowed.example.com?x=1",
        "allowed.example.com#x",
        "allowed.example.com\\evil",
        "allowed.example.com evil",
        "https://allowed.example.com://169.254.169.254",
        "http://allowed.example.com/http://x",
    ],
)
def test_strict_shape_refuses_urls_with_more_than_a_host(monkeypatch, value):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "allowed.example.com")
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed(value, field="hostname", tool="t")


@pytest.mark.parametrize(
    "value",
    [
        "allowed.example.com",
        "allowed.example.com:8091",
        "https://allowed.example.com:18091",
    ],
)
def test_strict_shape_keeps_plain_forms(monkeypatch, value):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "allowed.example.com")
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")
    assert egress.assert_egress_allowed(value, field="hostname", tool="t")


def test_strict_shape_keeps_bracketed_ipv6(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "2001:db8::1")
    assert egress.assert_egress_allowed("[2001:db8::1]:8091", field="h", tool="t")


@pytest.mark.parametrize(
    "host",
    [
        "168.63.129.16",
        "64:ff9b::a9fe:a9fe",
        "2002:a9fe:a9fe::1",
        "192.0.0.8",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "fec0::1",
    ],
)
def test_added_ranges_are_always_denied(monkeypatch, host):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", host)
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed(host, field="h", tool="t")


# ── Catalogue confinement ────────────────────────────────────────────────────


def _pl(res):
    return json.loads(res[0].text)


def _entry(root, cid="e1", **extra):
    root.mkdir(parents=True, exist_ok=True)
    body = {
        "schema": bc.CATALOG_SCHEMA,
        "catalog_id": cid,
        "backup_id": "b",
        "plane": "capella",
    }
    body.update(extra)
    (root / f"{cid}.json").write_text(json.dumps(body), encoding="utf-8")


@pytest.mark.parametrize(
    "tool,extra",
    [
        ("cb_backup_catalog_list", {}),
        ("cb_backup_catalog_get", {"catalog_id": "secret"}),
        (
            "cb_backup_catalog_update",
            {"catalog_id": "secret", "notes": "x", "confirm": True},
        ),
        ("cb_backup_catalog_delete", {"catalog_id": "secret", "confirm": True}),
        ("cb_backup_catalog_sync", {"backup_ids": []}),
    ],
)
def test_catalog_root_outside_configured_root_is_refused(
    tmp_path, monkeypatch, tool, extra
):
    a = tmp_path / "a"
    a.mkdir()
    other = tmp_path / "other"
    _entry(other, "secret")
    monkeypatch.setenv("CB_ADMIN_CATALOG_ROOT", str(a))
    out = _pl(bc.handle(tool, {"catalog_root": str(other), **extra}))
    assert out.get("_is_error") is True, out
    assert (other / "secret.json").exists()
    assert json.loads((other / "secret.json").read_text()).get("notes") is None


def test_symlink_inside_root_cannot_escape(tmp_path, monkeypatch):
    a = tmp_path / "a"
    a.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    (a / "link").symlink_to(other)
    monkeypatch.setenv("CB_ADMIN_CATALOG_ROOT", str(a))
    out = _pl(bc.handle("cb_backup_catalog_list", {"catalog_root": str(a / "link")}))
    assert out.get("_is_error") is True


def test_unset_root_confines_to_the_default_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CB_ADMIN_CATALOG_ROOT", raising=False)
    monkeypatch.delenv("CB_ADMIN_CATALOG_ALLOW_ANY_ROOT", raising=False)
    outside = tmp_path / "outside"
    outside.mkdir()
    out = _pl(bc.handle("cb_backup_catalog_list", {"catalog_root": str(outside)}))
    assert out.get("_is_error") is True
    inside = tmp_path / ".backup-catalog" / "sub"
    assert "_is_error" not in _pl(
        bc.handle("cb_backup_catalog_list", {"catalog_root": str(inside)})
    )


def test_allow_any_root_switch_lifts_the_default_confinement(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CB_ADMIN_CATALOG_ROOT", raising=False)
    monkeypatch.setenv("CB_ADMIN_CATALOG_ALLOW_ANY_ROOT", "true")
    outside = tmp_path / "outside"
    outside.mkdir()
    assert "_is_error" not in _pl(
        bc.handle("cb_backup_catalog_list", {"catalog_root": str(outside)})
    )


def test_foreign_json_without_schema_marker_is_never_touched(tmp_path, monkeypatch):
    root = tmp_path / "c"
    root.mkdir()
    monkeypatch.setenv("CB_ADMIN_CATALOG_ROOT", str(root))
    foreign = root / "foreign.json"
    foreign.write_text(json.dumps({"x": 1}))
    for tool, extra in (
        ("cb_backup_catalog_update", {"notes": "pwned"}),
        ("cb_backup_catalog_delete", {}),
        ("cb_backup_catalog_get", {}),
    ):
        out = _pl(bc.handle(tool, {"catalog_id": "foreign", "confirm": True, **extra}))
        assert out.get("_is_error") is True, (tool, out)
    sync = _pl(bc.handle("cb_backup_catalog_sync", {"backup_ids": []}))
    assert json.loads(foreign.read_text()) == {"x": 1}
    assert any("foreign.json" in u["file"] for u in sync["unreadable"])


def test_non_utf8_file_is_unreadable_not_fatal(tmp_path, monkeypatch):
    root = tmp_path / "c"
    _entry(root, "good")
    (root / "bad.json").write_bytes(b"\xff\xfe\x00bad")
    monkeypatch.setenv("CB_ADMIN_CATALOG_ROOT", str(root))
    listed = _pl(bc.handle("cb_backup_catalog_list", {}))
    assert [e["catalog_id"] for e in listed["entries"]] == ["good"]
    assert any("bad.json" in u["file"] for u in listed["unreadable"])
    synced = _pl(bc.handle("cb_backup_catalog_sync", {"backup_ids": ["b"]}))
    assert synced["present"] == ["good"]
    assert any("bad.json" in u["file"] for u in synced["unreadable"])
