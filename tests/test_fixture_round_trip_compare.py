"""The comparison at the heart of the round trip.

This is the only check in the project that compares a fixture against something
OTHER THAN ITSELF, and it exists because everything that did compare a fixture
against itself passed while the data was wrong: per-file sha256 matched the hash
recorded for that same wrong file, 188 wrong documents were still 188 lines, and
a cluster-side COUNT(*) counted the wrong documents correctly. All three agreed
while the Capella exporter was recording the wrong key for 187 of 188 documents.

So the comparison's own correctness is load-bearing in a way most test code is
not -- a bug here restores the blind spot the script was written to remove. Two
properties in particular:

  * KEYS AND BODIES ARE REPORTED SEPARATELY, because that separation IS the
    diagnosis. 187 differing keys with zero differing bodies says the content
    survived and the key did not, which is a completely different repair from the
    other way round.

  * A DUPLICATE KEY IS A FINDING, not something to overwrite. Two rows with the
    same key in one export means the exporter's pagination repeated a page, and
    collapsing them silently would hide exactly that.

The refusals matter too. An empty source proves nothing, and a round trip that
reports "identical" over two empty directories is worse than one that fails.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "_round_trip_under_test",
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fixture_round_trip.py",
)
round_trip = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = round_trip
_SPEC.loader.exec_module(round_trip)


def _fixture(root: pathlib.Path, name: str, rows: list[dict] | None) -> pathlib.Path:
    """A fixture directory holding one payload file, or none at all."""
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    if rows is None:
        return directory
    data = directory / "data"
    data.mkdir(exist_ok=True)
    (data / "b.s.c.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    return directory


def _row(key, doc=None, exp=None):
    row = {"id": key, "doc": doc if doc is not None else {"v": 1}}
    if exp is not None:
        row["exp"] = exp
    return row


# ── the clean case ───────────────────────────────────────────────────────────


def test_two_identical_exports_compare_identical(tmp_path):
    rows = [_row("k1"), _row("k2")]
    report = round_trip.compare(
        _fixture(tmp_path, "first", rows), _fixture(tmp_path, "second", rows)
    )
    assert report["identical"] is True
    assert report["signature"] is None
    assert report["keys_matching"] == 2
    assert report["first_documents"] == report["second_documents"] == 2
    assert report["bodies_differing_total"] == 0
    assert report["expiries_differing_total"] == 0


def test_blank_lines_are_not_documents(tmp_path):
    first = _fixture(tmp_path, "first", [_row("k1")])
    (first / "data" / "b.s.c.jsonl").write_text(
        json.dumps(_row("k1")) + "\n\n   \n", encoding="utf-8"
    )
    report = round_trip.compare(first, _fixture(tmp_path, "second", [_row("k1")]))
    assert report["first_documents"] == 1
    assert report["identical"] is True


def test_every_payload_file_in_a_fixture_is_read(tmp_path):
    first = _fixture(tmp_path, "first", [_row("k1")])
    (first / "data" / "other.jsonl").write_text(
        json.dumps(_row("k2")) + "\n", encoding="utf-8"
    )
    second = _fixture(tmp_path, "second", [_row("k1"), _row("k2")])
    report = round_trip.compare(first, second)
    assert report["first_documents"] == 2
    assert report["identical"] is True


# ── the signature the script was written to name ─────────────────────────────


def test_keys_differing_while_bodies_do_not_is_named_as_the_alias_bug(tmp_path):
    """The exact shape of the Capella defect: the content survived the trip and
    the key did not. Naming it here means the next person does not re-derive the
    diagnosis from two lists of uuids."""
    body = {"airline": "AA"}
    first = _fixture(tmp_path, "first", [_row("airline_1234", body), _row("k", body)])
    second = _fixture(tmp_path, "second", [_row("AA", body), _row("k", body)])

    report = round_trip.compare(first, second)
    assert report["identical"] is False
    assert report["bodies_differing_total"] == 0
    assert report["keys_only_in_first_total"] == 1
    assert "KEYS DIFFER AND BODIES DO NOT" in report["signature"]
    assert "META_ID_ALIAS" in report["signature"]


def test_the_signature_does_not_fire_when_the_bodies_also_differ(tmp_path):
    """A different failure needs a different diagnosis, and offering the alias
    explanation for it would send the reader to the wrong file."""
    first = _fixture(tmp_path, "first", [_row("k1", {"a": 1}), _row("k2", {"a": 1})])
    second = _fixture(tmp_path, "second", [_row("k9", {"a": 1}), _row("k2", {"a": 2})])
    report = round_trip.compare(first, second)
    assert report["bodies_differing_total"] == 1
    assert report["signature"] is None


def test_the_signature_does_not_fire_when_every_key_survived(tmp_path):
    """Keys only in the SECOND export are extra documents, not lost ones."""
    first = _fixture(tmp_path, "first", [_row("k1")])
    second = _fixture(tmp_path, "second", [_row("k1"), _row("k2")])
    report = round_trip.compare(first, second)
    assert report["identical"] is False
    assert report["keys_only_in_second_total"] == 1
    assert report["signature"] is None


# ── what each half of the report is for ──────────────────────────────────────


def test_bodies_are_compared_independently_of_keys(tmp_path):
    first = _fixture(tmp_path, "first", [_row("k1", {"a": 1})])
    second = _fixture(tmp_path, "second", [_row("k1", {"a": 2})])
    report = round_trip.compare(first, second)
    assert report["keys_matching"] == 1
    assert report["bodies_differing"] == ["k1"]
    assert report["identical"] is False


def test_expiries_are_compared_and_reported_separately(tmp_path):
    """An expiry that does not survive the trip is a fixture that behaves
    differently from the dataset it claims to reproduce -- and it changes nothing
    about keys or bodies, so it needs its own count."""
    first = _fixture(tmp_path, "first", [_row("k1", exp=1800000000)])
    second = _fixture(tmp_path, "second", [_row("k1", exp=0)])
    report = round_trip.compare(first, second)
    assert report["expiries_differing_total"] == 1
    assert report["bodies_differing_total"] == 0
    assert report["identical"] is True, (
        "identical covers keys and bodies; the expiry count is reported beside it"
    )


def test_the_key_lists_are_capped_but_the_totals_are_not(tmp_path):
    """A report that prints two thousand uuids is a report nobody reads; one that
    hides how many there were is a report that misleads."""
    first = _fixture(tmp_path, "first", [_row(f"k{n}") for n in range(30)])
    second = _fixture(tmp_path, "second", [])
    report = round_trip.compare(first, second)
    assert len(report["keys_only_in_first"]) == 20
    assert report["keys_only_in_first_total"] == 30


# ── refusals ─────────────────────────────────────────────────────────────────


def test_a_source_with_no_payload_files_is_refused(tmp_path):
    """Either the source keyspace was empty -- in which case the round trip
    proves nothing -- or the export failed. Reporting "identical" over two empty
    directories is worse than failing."""
    with pytest.raises(SystemExit) as caught:
        round_trip.compare(
            _fixture(tmp_path, "first", None), _fixture(tmp_path, "second", [_row("k")])
        )
    assert "proves nothing" in str(caught.value)


def test_a_source_directory_with_an_empty_data_folder_is_refused(tmp_path):
    first = _fixture(tmp_path, "first", [])
    (first / "data" / "b.s.c.jsonl").unlink()
    with pytest.raises(SystemExit):
        round_trip.compare(first, _fixture(tmp_path, "second", [_row("k")]))


def test_a_duplicate_key_is_a_finding_not_something_to_overwrite(tmp_path):
    """Two rows with the same key in one export means the exporter's pagination
    repeated a page. Collapsing them here would hide exactly that."""
    first = _fixture(tmp_path, "first", [_row("k1"), _row("k1", {"v": 2})])
    with pytest.raises(SystemExit) as caught:
        round_trip.compare(first, _fixture(tmp_path, "second", [_row("k1")]))
    message = str(caught.value)
    assert "duplicate document keys" in message
    assert "paged over the same rows twice" in message
    assert "'k1' appears twice (line 2)" in message


def test_an_empty_second_export_is_compared_rather_than_refused(tmp_path):
    """The SECOND export being empty is a real result -- the import wrote
    nothing -- and must be reported, not treated as a broken run."""
    report = round_trip.compare(
        _fixture(tmp_path, "first", [_row("k1")]),
        _fixture(tmp_path, "second", None),
    )
    assert report["second_documents"] == 0
    assert report["keys_only_in_first_total"] == 1
    assert report["identical"] is False


# ── the client environment the run uses ──────────────────────────────────────


def test_the_dry_run_is_lowered_only_when_performing():
    """This lowers the DRY RUN, not the confirmation gate. The import still needs
    its own confirm:true in the arguments -- which is the distinction that cost a
    wasted run when --perform alone was expected to be enough."""
    assert round_trip._client_env(perform=True)["CB_ADMIN_DRY_RUN"] == "false"
    assert round_trip._client_env(perform=False)["CB_ADMIN_DRY_RUN"] == "true"
    for perform in (True, False):
        env = round_trip._client_env(perform=perform)
        assert env["CB_ADMIN_READ_ONLY_MODE"] == "false", "writes advertised"
        assert env["CB_ADMIN_TRANSPORT"] == "stdio"


def test_the_capella_ids_are_read_from_the_environment(monkeypatch):
    """Typing a uuid three times is how the wrong uuid gets typed."""
    for variable in round_trip._CAPELLA_IDS.values():
        monkeypatch.setenv(variable, f"value-of-{variable}")
    ids = round_trip._capella_ids()
    assert set(ids) == set(round_trip._CAPELLA_IDS)
    assert ids["cluster_id"] == "value-of-CAPELLA_CLUSTER_ID"


def test_a_missing_capella_id_names_every_variable_that_is_missing(monkeypatch):
    for variable in round_trip._CAPELLA_IDS.values():
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("CAPELLA_ORG_ID", "org")
    with pytest.raises(SystemExit) as caught:
        round_trip._capella_ids()
    message = str(caught.value)
    assert "CAPELLA_PROJECT_ID" in message and "CAPELLA_CLUSTER_ID" in message
    assert "CAPELLA_ORG_ID" not in message


# ── unwrapping a tool response ───────────────────────────────────────────────


class _Block:
    def __init__(self, text):
        self.text = text


class _Response:
    def __init__(self, content):
        self.content = content


def test_a_json_tool_response_is_parsed():
    assert round_trip._payload(_Response([_Block('{"a": 1}')])) == {"a": 1}


def test_a_non_json_tool_response_is_returned_as_text():
    assert round_trip._payload(_Response([_Block("not json")])) == "not json"


def test_a_response_with_no_usable_content_is_none():
    assert round_trip._payload(_Response([])) is None
    assert round_trip._payload(_Response(None)) is None
    assert round_trip._payload(object()) is None
