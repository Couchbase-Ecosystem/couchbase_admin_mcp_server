"""The backup catalogue: the only record that a backup existed.

This module is a pointer store. Nothing it holds can be re-derived -- an
expired backup and a wrongly-deleted one look identical from here, and the
catalogue entry is the only surviving evidence the backup was ever taken. That
makes silent wrongness the failure worth testing for, rather than crashes.

It was also absent from the operator console for its entire life, which is the
defect that prompted tests/test_gui_authorization.py's membership check. A
module nobody could reach through half the surface is a module nobody exercised,
and it shipped at 37 percent coverage.

The cases below are organised by the way this module can lie: writing a
catalogue somewhere that disappears, storing a tag the caller cannot then filter
for, matching a date filter against an entry whose age is unknown, reporting a
file it could not read as absent rather than broken, and marking every entry
missing because the list it was handed came back empty.
"""

from __future__ import annotations

import json

import pytest

from handlers import backup_catalog as bc
from handlers.shared import ERROR_MARKER

ENV = "CB_ADMIN_CATALOG_ROOT"


def payload(result) -> dict:
    return json.loads(result[0].text)


def is_error(result) -> bool:
    return payload(result).get(ERROR_MARKER) is True


@pytest.fixture
def root(tmp_path, monkeypatch):
    """A catalogue location that is stated, as every write requires."""
    path = tmp_path / "catalog"
    monkeypatch.setenv(ENV, str(path))
    return path


def record(**args):
    return bc.handle("cb_backup_catalog_record", args)


def _recorded(**args) -> dict:
    """Record an entry and return it, failing the test if it was refused."""
    args.setdefault("plane", "capella")
    args.setdefault("backup_id", "bk-1")
    result = record(**args)
    assert not is_error(result), payload(result)
    return payload(result)


# ── Where the catalogue lives ────────────────────────────────────────────────


def test_a_write_is_refused_when_no_location_is_configured(tmp_path, monkeypatch):
    """The default is RELATIVE, so it resolves against the working directory.

    In a container that is the image layer, and the catalogue vanishes on the
    next restart having reported success every time. During a pytest run it is
    the repository -- which is how two generated entries with backup_id "sample"
    came to be committed-adjacent on 2026-09-14, written by the handler-contract
    harness calling every tool in every group.
    """
    monkeypatch.delenv(ENV, raising=False)
    result = record(plane="capella", backup_id="bk-1")
    assert is_error(result)
    assert "refusing to write" in payload(result)["error"]
    assert ENV in payload(result)["error"]


def test_a_read_still_falls_back_to_the_default(tmp_path, monkeypatch):
    """Reads may fall back; writes may not. An existing catalogue stays listable
    even where a write would be refused."""
    monkeypatch.delenv(ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    result = bc.handle("cb_backup_catalog_list", {})
    assert not is_error(result)
    assert payload(result)["matched"] == 0


def test_a_traversing_catalog_root_is_refused_rather_than_normalised(root):
    result = record(plane="capella", backup_id="bk-1", catalog_root="../escape")
    assert is_error(result)
    assert "traversal is refused" in payload(result)["error"]


def test_an_explicit_catalog_root_overrides_the_environment(root, tmp_path):
    other = tmp_path / "elsewhere"
    entry = _recorded(catalog_root=str(other))
    assert str(other) in entry["_file"]
    assert not root.exists()


# ── Tags: what is stored must be what a filter can ask for ───────────────────


@pytest.mark.parametrize(
    ("given", "stored"),
    [
        ({"keep": True}, {"keep": "true"}),
        ({"keep": False}, {"keep": "false"}),
        ({"retain": 2.0}, {"retain": "2"}),
        ({"version": 1.6}, {"version": "1.6"}),
        ({"count": 3}, {"count": "3"}),
        ("not-a-dict", {}),
    ],
)
def test_tag_values_are_stored_as_the_strings_a_filter_will_compare(given, stored):
    """2.0 from a shell means "2", not "2.0".

    json.loads produces the float; storing its repr would make an exact-match
    filter for "2" miss the entry it was written for -- invisible until someone
    filtered on a whole number.
    """
    assert bc._string_tags(given) == stored


def test_a_whole_number_tag_is_found_by_the_query_that_wrote_it(root):
    _recorded(catalog_id="e1", tags={"retain": 2.0})
    result = bc.handle("cb_backup_catalog_list", {"match_tags": {"retain": 2}})
    assert payload(result)["matched"] == 1


def test_exclude_tags_removes_a_matching_entry(root):
    _recorded(catalog_id="keepme", tags={"tier": "gold"})
    _recorded(catalog_id="dropme", tags={"tier": "scratch"})
    result = bc.handle("cb_backup_catalog_list", {"exclude_tags": {"tier": "scratch"}})
    body = payload(result)
    assert body["matched"] == 1
    assert body["entries"][0]["catalog_id"] == "keepme"


# ── Identity ─────────────────────────────────────────────────────────────────


def test_a_catalog_id_that_could_contain_a_separator_is_refused(root):
    """The id becomes a filename. One that can hold a path separator is one that
    can write outside the catalogue."""
    result = record(plane="capella", backup_id="bk-1", catalog_id="../../etc/passwd")
    assert is_error(result)
    assert "may contain only letters" in payload(result)["error"]


def test_an_id_is_generated_when_none_is_given(root):
    entry = _recorded(bucket="travel-sample")
    assert entry["catalog_id"].startswith("capella-travel-sample-")
    assert entry["tags"] == {}


def test_recording_over_an_existing_id_is_refused(root):
    _recorded(catalog_id="e1")
    result = record(plane="capella", backup_id="bk-2", catalog_id="e1")
    assert is_error(result)
    assert "already exists" in payload(result)["error"]
    assert "starts lying" in payload(result)["error"]


def test_backup_id_is_required(root):
    result = record(plane="capella", backup_id="   ")
    assert is_error(result)
    assert "backup_id is required" in payload(result)["error"]


def test_an_enterprise_entry_without_a_repository_is_refused(root):
    """An EE backup name is unique only within its repository, so a pointer
    without one cannot be resolved back to a backup."""
    result = record(plane="enterprise", backup_id="bk-1")
    assert is_error(result)
    assert "repository_id is required" in payload(result)["error"]


def test_an_enterprise_entry_with_a_repository_is_accepted(root):
    entry = _recorded(plane="enterprise", repository_id="repo-1")
    assert entry["repository_id"] == "repo-1"
    assert entry["sync"] == {"status": "unchecked", "checked_at": None}


# ── Timestamps and date filters ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("given", "expected_none"),
    [
        ("2026-09-14T03:26:29Z", False),
        ("2026-09-14T03:26:29", False),
        ("not a date", True),
        ("", True),
        (None, True),
        (17, True),
    ],
)
def test_timestamp_parsing(given, expected_none):
    assert (bc._parse_timestamp(given) is None) is expected_none


def test_a_naive_timestamp_is_read_as_utc():
    parsed = bc._parse_timestamp("2026-09-14T03:26:29")
    assert parsed is not None and parsed.tzinfo is not None


def test_an_unparseable_date_filter_is_refused_rather_than_ignored(root):
    """A filter that cannot be parsed must not silently match everything."""
    result = bc.handle("cb_backup_catalog_list", {"created_after": "last tuesday"})
    assert is_error(result)
    assert "not an ISO-8601 timestamp" in payload(result)["error"]


def test_an_entry_with_no_readable_timestamp_cannot_satisfy_a_date_filter(root):
    """Matching it would answer "what did we take last month" with something of
    unknown age."""
    _recorded(catalog_id="undated", backup_created_at="whenever")
    path = root / "undated.json"
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry["recorded_at"] = "also whenever"
    path.write_text(json.dumps(entry), encoding="utf-8")

    result = bc.handle(
        "cb_backup_catalog_list", {"created_after": "2020-01-01T00:00:00Z"}
    )
    assert payload(result)["matched"] == 0


def test_date_filters_bound_on_both_sides(root):
    _recorded(catalog_id="old", backup_created_at="2026-01-01T00:00:00Z")
    _recorded(catalog_id="mid", backup_created_at="2026-06-01T00:00:00Z")
    _recorded(catalog_id="new", backup_created_at="2026-12-01T00:00:00Z")

    body = payload(
        bc.handle(
            "cb_backup_catalog_list",
            {
                "created_after": "2026-03-01T00:00:00Z",
                "created_before": "2026-09-01T00:00:00Z",
            },
        )
    )
    assert [e["catalog_id"] for e in body["entries"]] == ["mid"]


def test_entries_are_returned_newest_first_and_latest_only_takes_one(root):
    _recorded(catalog_id="old", backup_created_at="2026-01-01T00:00:00Z")
    _recorded(catalog_id="new", backup_created_at="2026-12-01T00:00:00Z")

    body = payload(bc.handle("cb_backup_catalog_list", {}))
    assert [e["catalog_id"] for e in body["entries"]] == ["new", "old"]

    body = payload(bc.handle("cb_backup_catalog_list", {"latest_only": True}))
    assert [e["catalog_id"] for e in body["entries"]] == ["new"]


# ── Scalar field filters ─────────────────────────────────────────────────────


@pytest.mark.parametrize("field", ["plane", "cluster_id", "bucket"])
def test_a_scalar_filter_selects_only_its_own_entry(root, field):
    _recorded(catalog_id="wanted", **{field: "yes"} if field != "plane" else {})
    if field == "plane":
        # plane is already set by _recorded's default; record a second plane.
        _recorded(catalog_id="other", plane="enterprise", repository_id="r")
        body = payload(bc.handle("cb_backup_catalog_list", {"plane": "capella"}))
        assert [e["catalog_id"] for e in body["entries"]] == ["wanted"]
        return
    _recorded(catalog_id="other", **{field: "no"})
    body = payload(bc.handle("cb_backup_catalog_list", {field: "yes"}))
    assert [e["catalog_id"] for e in body["entries"]] == ["wanted"]


def test_an_entry_whose_tags_are_not_an_object_never_matches(root):
    _recorded(catalog_id="bent")
    path = root / "bent.json"
    entry = json.loads(path.read_text(encoding="utf-8"))
    entry["tags"] = ["not", "an", "object"]
    path.write_text(json.dumps(entry), encoding="utf-8")
    body = payload(bc.handle("cb_backup_catalog_list", {"match_tags": {"a": "b"}}))
    assert body["matched"] == 0


# ── Unreadable files are reported, never skipped ─────────────────────────────


def test_a_file_that_will_not_parse_is_reported_rather_than_skipped(root):
    """A pointer you can no longer read is exactly the thing you need to be told
    about. Skipping it makes a broken catalogue look like a small one."""
    _recorded(catalog_id="good")
    (root / "broken.json").write_text("{ not json", encoding="utf-8")
    (root / "notanobject.json").write_text("[1, 2, 3]", encoding="utf-8")

    body = payload(bc.handle("cb_backup_catalog_list", {}))
    assert body["matched"] == 1
    assert body["scanned"] == 3
    assert len(body["unreadable"]) == 2
    assert "could not be read" in body["note"]
    assert any("not a JSON object" in u["error"] for u in body["unreadable"])


def test_a_missing_catalogue_is_distinguished_from_an_empty_one(root):
    """An empty catalogue and a missing one look the same in the entry list."""
    body = payload(bc.handle("cb_backup_catalog_list", {}))
    assert body["matched"] == 0
    assert "does not exist yet" in body["note"]


# ── get ──────────────────────────────────────────────────────────────────────


def test_get_returns_the_entry_and_its_file(root):
    _recorded(catalog_id="e1", notes="nightly")
    body = payload(bc.handle("cb_backup_catalog_get", {"catalog_id": "e1"}))
    assert body["catalog_id"] == "e1"
    assert body["notes"] == "nightly"
    assert body["_file"].endswith("e1.json")


def test_get_names_the_root_it_looked_under(root):
    result = bc.handle("cb_backup_catalog_get", {"catalog_id": "absent"})
    assert is_error(result)
    assert str(root) in payload(result)["error"]


def test_get_reports_an_entry_it_cannot_parse(root):
    (root).mkdir(parents=True, exist_ok=True)
    (root / "bent.json").write_text("{ not json", encoding="utf-8")
    result = bc.handle("cb_backup_catalog_get", {"catalog_id": "bent"})
    assert is_error(result)
    assert "could not be read" in payload(result)["error"]


# ── update ───────────────────────────────────────────────────────────────────


def test_update_merges_tags_by_default(root):
    _recorded(catalog_id="e1", tags={"tier": "gold", "keep": "yes"})
    body = payload(
        bc.handle(
            "cb_backup_catalog_update",
            {"catalog_id": "e1", "tags": {"tier": "silver"}},
        )
    )
    assert body["tags"] == {"tier": "silver", "keep": "yes"}
    assert "updated_at" in body


def test_update_replaces_tags_when_asked(root):
    _recorded(catalog_id="e1", tags={"tier": "gold", "keep": "yes"})
    body = payload(
        bc.handle(
            "cb_backup_catalog_update",
            {"catalog_id": "e1", "tags": {"tier": "silver"}, "replace_tags": True},
        )
    )
    assert body["tags"] == {"tier": "silver"}


def test_update_sets_notes_and_persists_to_disk(root):
    _recorded(catalog_id="e1")
    bc.handle("cb_backup_catalog_update", {"catalog_id": "e1", "notes": "restored"})
    on_disk = json.loads((root / "e1.json").read_text(encoding="utf-8"))
    assert on_disk["notes"] == "restored"


def test_update_refuses_an_entry_that_is_not_there(root):
    result = bc.handle("cb_backup_catalog_update", {"catalog_id": "absent"})
    assert is_error(result)


def test_update_reports_an_entry_it_cannot_parse(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "bent.json").write_text("{ not json", encoding="utf-8")
    result = bc.handle("cb_backup_catalog_update", {"catalog_id": "bent"})
    assert is_error(result)
    assert "could not be read" in payload(result)["error"]


# ── delete ───────────────────────────────────────────────────────────────────


def test_deleting_an_absent_entry_succeeds_and_says_it_did_nothing(root):
    """Idempotent on purpose: the desired end state, not an error worth failing a
    cleanup script over."""
    body = payload(bc.handle("cb_backup_catalog_delete", {"catalog_id": "absent"}))
    assert body["deleted"] is False
    assert "nothing to delete" in body["note"]


def test_delete_removes_the_entry_and_returns_what_was_removed(root):
    _recorded(catalog_id="e1", notes="keep a copy of this")
    body = payload(bc.handle("cb_backup_catalog_delete", {"catalog_id": "e1"}))
    assert body["deleted"] is True
    assert body["removed_entry"]["notes"] == "keep a copy of this"
    assert not (root / "e1.json").exists()


def test_delete_says_the_backup_itself_is_untouched(root):
    """The distinction the note draws is the whole safety property: this server
    cannot delete backup bytes, deliberately."""
    _recorded(catalog_id="e1")
    body = payload(bc.handle("cb_backup_catalog_delete", {"catalog_id": "e1"}))
    assert "BACKUP is untouched" in body["note"]


def test_delete_still_removes_an_entry_it_could_not_parse(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "bent.json").write_text("{ not json", encoding="utf-8")
    body = payload(bc.handle("cb_backup_catalog_delete", {"catalog_id": "bent"}))
    assert body["deleted"] is True
    assert body["removed_entry"] == {}


# ── sync ─────────────────────────────────────────────────────────────────────


def test_sync_marks_present_and_missing_without_deleting_anything(root):
    """An expired backup and a wrongly-deleted one look identical from here, and
    the entry is the only surviving record that the backup existed."""
    _recorded(catalog_id="here", backup_id="bk-1")
    _recorded(catalog_id="gone", backup_id="bk-2")

    body = payload(bc.handle("cb_backup_catalog_sync", {"backup_ids": ["bk-1"]}))
    assert body["present"] == ["here"]
    assert body["missing"] == ["gone"]
    assert body["present_count"] == 1 and body["missing_count"] == 1
    assert "MARKED, not deleted" in body["note"]
    assert (root / "gone.json").exists()

    on_disk = json.loads((root / "gone.json").read_text(encoding="utf-8"))
    assert on_disk["sync"]["status"] == "missing"
    assert on_disk["sync"]["checked_at"]
    assert "_file" not in on_disk, "the internal field must not be persisted"


def test_sync_with_an_empty_list_warns_that_it_marked_everything_missing(root):
    """If the list call failed and returned nothing, sync would otherwise report
    a total loss as fact."""
    _recorded(catalog_id="e1")
    body = payload(bc.handle("cb_backup_catalog_sync", {"backup_ids": []}))
    assert body["missing"] == ["e1"]
    assert "was EMPTY" in body["warning"]


def test_sync_leaves_out_of_scope_entries_alone(root):
    _recorded(catalog_id="capella-one", plane="capella", cluster_id="c1")
    _recorded(
        catalog_id="ee-one", plane="enterprise", repository_id="r", cluster_id="c2"
    )
    body = payload(
        bc.handle("cb_backup_catalog_sync", {"backup_ids": [], "plane": "enterprise"})
    )
    assert body["out_of_scope"] == ["capella-one"]
    assert body["missing"] == ["ee-one"]

    untouched = json.loads((root / "capella-one.json").read_text(encoding="utf-8"))
    assert untouched["sync"]["status"] == "unchecked"


def test_sync_scopes_by_cluster_id_as_well(root):
    _recorded(catalog_id="c1-entry", cluster_id="c1")
    _recorded(catalog_id="c2-entry", cluster_id="c2")
    body = payload(
        bc.handle("cb_backup_catalog_sync", {"backup_ids": [], "cluster_id": "c1"})
    )
    assert body["out_of_scope"] == ["c2-entry"]


def test_sync_reports_files_it_could_not_read(root):
    _recorded(catalog_id="e1")
    (root / "bent.json").write_text("{ not json", encoding="utf-8")
    body = payload(bc.handle("cb_backup_catalog_sync", {"backup_ids": ["bk-1"]}))
    assert len(body["unreadable"]) == 1


def test_sync_refuses_without_a_configured_location(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    result = bc.handle("cb_backup_catalog_sync", {"backup_ids": []})
    assert is_error(result)


# ── dispatch ─────────────────────────────────────────────────────────────────


def test_an_unknown_tool_name_is_refused(root):
    result = bc.handle("cb_backup_catalog_teleport", {})
    assert is_error(result)
    assert "Unknown backup catalog tool" in payload(result)["error"]


def test_every_advertised_tool_has_a_handler():
    assert {t.name for t in bc.TOOLS} == set(bc.HANDLERS)


# ── Error branches: what happens when the filesystem says no ─────────────────
#
# These are the paths a reviewer most wants covered and a test suite most often
# leaves out, because provoking them needs a fault rather than an input. Each
# one is a place where the catalogue could otherwise report success over a write
# that did not happen -- the module's whole failure mode.


def test_a_non_matching_tag_filter_excludes_the_entry(root):
    _recorded(catalog_id="gold", tags={"tier": "gold"})
    body = payload(bc.handle("cb_backup_catalog_list", {"match_tags": {"tier": "tin"}}))
    assert body["matched"] == 0


def test_a_root_that_cannot_be_resolved_is_reported_as_such(root, monkeypatch):
    def explode(self, strict=False):
        raise OSError("name too long")

    monkeypatch.setattr("pathlib.Path.resolve", explode)
    result = record(plane="capella", backup_id="bk-1")
    assert is_error(result)
    assert "could not be resolved" in payload(result)["error"]


@pytest.mark.parametrize(
    "tool",
    [
        "cb_backup_catalog_list",
        "cb_backup_catalog_get",
        "cb_backup_catalog_update",
        "cb_backup_catalog_delete",
    ],
)
def test_every_read_and_write_tool_refuses_a_traversing_root(root, tool):
    """The traversal guard has to hold on every entry point, not just the one it
    was written for."""
    result = bc.handle(tool, {"catalog_id": "e1", "catalog_root": "../escape"})
    assert is_error(result)


def test_a_failed_write_is_reported_rather_than_reported_as_success(root, monkeypatch):
    """The catalogue's worst failure is looking like success. An OSError on the
    write must reach the caller."""

    def refuse(self, *a, **kw):
        raise OSError("read-only file system")

    monkeypatch.setattr("pathlib.Path.write_text", refuse)
    result = record(plane="capella", backup_id="bk-1", catalog_id="e1")
    assert is_error(result)
    assert "could not write the entry" in payload(result)["error"]
    assert payload(result)["catalog_root"] == str(root)


def test_a_failed_update_write_is_reported(root, monkeypatch):
    _recorded(catalog_id="e1")

    def refuse(self, *a, **kw):
        raise OSError("read-only file system")

    monkeypatch.setattr("pathlib.Path.write_text", refuse)
    result = bc.handle("cb_backup_catalog_update", {"catalog_id": "e1", "notes": "x"})
    assert is_error(result)
    assert "could not write the entry" in payload(result)["error"]


def test_a_failed_delete_is_reported(root, monkeypatch):
    _recorded(catalog_id="e1")

    def refuse(self, *a, **kw):
        raise OSError("permission denied")

    monkeypatch.setattr("pathlib.Path.unlink", refuse)
    result = bc.handle("cb_backup_catalog_delete", {"catalog_id": "e1"})
    assert is_error(result)
    assert "could not delete the entry" in payload(result)["error"]


def test_sync_logs_an_entry_it_could_not_rewrite_and_carries_on(root, monkeypatch):
    """One unwritable entry must not abandon the rest of the sweep: the result is
    still the operator's picture of what the plane reports."""
    _recorded(catalog_id="e1", backup_id="bk-1")
    _recorded(catalog_id="e2", backup_id="bk-2")

    def refuse(self, *a, **kw):
        raise OSError("read-only file system")

    monkeypatch.setattr("pathlib.Path.write_text", refuse)
    body = payload(bc.handle("cb_backup_catalog_sync", {"backup_ids": ["bk-1"]}))
    assert body["present"] == ["e1"]
    assert body["missing"] == ["e2"]
