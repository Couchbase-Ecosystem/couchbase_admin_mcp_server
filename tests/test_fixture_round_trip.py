"""The round-trip comparison must catch the bug that nothing else caught.

WHY THIS FILE EXISTS
====================
`scripts/fixture_round_trip.py` is the only check in this repository that
compares a fixture against something other than itself. Per-file hashes, line
counts and a cluster-side COUNT(*) all agreed on 2026-09-14 while the Capella
exporter was writing the wrong document key for 187 of 188 documents, because
each of those compares a wrong file against the record of that same wrong file.

A harness whose whole job is catching that class of defect had better be shown
catching it. So the historical failure is reconstructed here from what was
actually measured -- travel-sample airline documents, `{"id": 10, ...}` keyed
`airline_10`, bodies intact and keys wrong -- and the comparison is asserted to
report it, AND to name the diagnosis rather than leaving two lists of ids for
the reader to interpret.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

_SCRIPTS = pathlib.Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))

import fixture_round_trip as rt  # noqa: E402


def _fixture(root: pathlib.Path, name: str, rows: list[dict]) -> pathlib.Path:
    directory = root / name
    (directory / "data").mkdir(parents=True, exist_ok=True)
    payload = directory / "data" / "b.s.c.jsonl"
    payload.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    return directory


def _airline(key: str, identifier: int, name: str) -> dict:
    """One travel-sample airline row in the fixture's JSON Lines shape."""
    return {
        "id": key,
        "exp": 0,
        "doc": {"id": identifier, "name": name, "type": "airline"},
        "xattrs": {},
    }


def test_a_clean_round_trip_is_reported_as_identical(tmp_path):
    rows = [
        _airline("airline_10", 10, "40-Mile Air"),
        _airline("airline_11", 11, "Texas Wings"),
    ]
    first = _fixture(tmp_path, "first", rows)
    second = _fixture(tmp_path, "second", rows)

    report = rt.compare(first, second)
    assert report["identical"] is True
    assert report["keys_matching"] == 2
    assert report["bodies_differing_total"] == 0
    assert report["signature"] is None


def test_the_key_corruption_bug_is_caught_and_diagnosed(tmp_path):
    """THE REGRESSION THIS SCRIPT EXISTS FOR, reconstructed from what was
    measured on 2026-09-14.

    The exporter wrote the document's own `id` FIELD as the key, because `d.*`
    came after `META().id AS id` in the SELECT and overwrote the alias. So the
    second export carries keys `10` and `11` where the first carries
    `airline_10` and `airline_11` -- while every body is byte-identical.

    Hashes matched. Line counts matched. COUNT(*) matched. Only this comparison
    sees it.
    """
    first = _fixture(
        tmp_path,
        "first",
        [
            _airline("airline_10", 10, "40-Mile Air"),
            _airline("airline_11", 11, "Texas Wings"),
        ],
    )
    second = _fixture(
        tmp_path,
        "second",
        [
            _airline("10", 10, "40-Mile Air"),
            _airline("11", 11, "Texas Wings"),
        ],
    )

    report = rt.compare(first, second)
    assert report["identical"] is False
    assert report["keys_only_in_first_total"] == 2
    assert report["keys_only_in_second_total"] == 2
    assert report["keys_matching"] == 0
    # The bodies survived the trip. That asymmetry IS the diagnosis.
    assert report["bodies_differing_total"] == 0
    assert report["signature"], (
        "the comparison found differing keys with identical bodies and did not "
        "name the cause. Two lists of ids leave the next person to re-derive a "
        "diagnosis that is already known."
    )
    assert "META_ID_ALIAS" in report["signature"]


def test_a_document_lost_in_the_round_trip_is_reported(tmp_path):
    """The other failure an import can produce: it wrote some and not all."""
    first = _fixture(
        tmp_path,
        "first",
        [
            _airline("airline_10", 10, "40-Mile Air"),
            _airline("airline_11", 11, "Texas Wings"),
        ],
    )
    second = _fixture(tmp_path, "second", [_airline("airline_10", 10, "40-Mile Air")])

    report = rt.compare(first, second)
    assert report["identical"] is False
    assert report["keys_only_in_first"] == ["airline_11"]
    assert report["first_documents"] == 2
    assert report["second_documents"] == 1


def test_a_changed_body_is_reported_separately_from_a_changed_key(tmp_path):
    """Keys and bodies are reported apart because the repairs are different."""
    first = _fixture(tmp_path, "first", [_airline("airline_10", 10, "40-Mile Air")])
    second = _fixture(tmp_path, "second", [_airline("airline_10", 10, "Renamed Air")])

    report = rt.compare(first, second)
    assert report["identical"] is False
    assert report["keys_matching"] == 1
    assert report["keys_only_in_first_total"] == 0
    assert report["bodies_differing"] == ["airline_10"]
    assert report["signature"] is None, (
        "bodies differing is not the alias signature, and saying it is would "
        "send the reader to the wrong place"
    )


def test_a_changed_expiry_is_reported(tmp_path):
    """Expiry travels with the document and a fixture that silently drops it
    reproduces the wrong scenario -- a dataset whose documents expire behaves
    differently from one whose documents do not."""
    first = _fixture(tmp_path, "first", [_airline("airline_10", 10, "40-Mile Air")])
    row = _airline("airline_10", 10, "40-Mile Air")
    row["exp"] = 1789500000
    second = _fixture(tmp_path, "second", [row])

    report = rt.compare(first, second)
    assert report["expiries_differing_total"] == 1


def test_a_duplicate_key_in_one_export_is_a_finding_not_an_overwrite(tmp_path):
    """Two rows with the same key means the exporter paged over the same rows
    twice. Collapsing them silently would hide exactly that."""
    first = _fixture(
        tmp_path,
        "first",
        [
            _airline("airline_10", 10, "40-Mile Air"),
            _airline("airline_10", 10, "40-Mile Air"),
        ],
    )
    second = _fixture(tmp_path, "second", [_airline("airline_10", 10, "40-Mile Air")])

    with pytest.raises(SystemExit, match="duplicate document keys"):
        rt.compare(first, second)


def test_an_empty_source_export_refuses_rather_than_reporting_success(tmp_path):
    """A round trip over zero documents compares nothing with nothing and would
    otherwise report `identical: true` -- a green result that establishes
    nothing at all, which is the worst kind."""
    first = _fixture(tmp_path, "first", [])
    (first / "data" / "b.s.c.jsonl").unlink()
    second = _fixture(tmp_path, "second", [])

    with pytest.raises(SystemExit, match="no payload files"):
        rt.compare(first, second)


def test_the_script_refuses_to_import_back_over_its_own_source():
    """Overwriting the source with the fixture being verified, and then
    comparing against what it just wrote, proves nothing."""
    import subprocess

    result = subprocess.run(
        [
            sys.executable,
            str(_SCRIPTS / "fixture_round_trip.py"),
            "--plane",
            "ee",
            "--keyspace",
            "b.s.c",
            "--scratch",
            "b.s.c",
            "--work",
            "/tmp/x",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "must differ from" in (result.stdout + result.stderr)


def test_both_planes_are_covered_by_the_harness():
    """A round-trip script that only knows one plane would leave the other
    verified by nothing -- which is the state the EE family is in until this is
    run against it."""
    assert set(rt._TOOLS) == {"capella", "ee"}
    for plane, tools in rt._TOOLS.items():
        assert set(tools) == {"export", "import", "verify"}, plane
