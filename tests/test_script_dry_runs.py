"""Scripts that change things preview first; scripts with no parser now have one.

Component: regression suite for `scripts/load_test_data.py` and the five `scripts/mutation_*.py`.
Spec: docs/plans/script-dry-run-spec.md (decisions 1 and 3, Chris Ahrendt, 2026-11-06);
    docs/questions.md Q-004.
Main items: `test_load_test_data_previews_and_connects_to_nothing_without_perform`,
    `test_load_test_data_writes_only_with_perform`, `test_mutation_list_runs_nothing`.
Callers: none; collected by pytest
Callees: none

WHY THIS FILE EXISTS
====================
`load_test_data.py` once wrote about 2,200 documents the moment it started. The first test
makes the connection function fail if it is called, so a preview that quietly connects fails.
The second proves `--perform` still writes, so the preview cannot pass by never writing at all.
The mutation scripts once started a five-minute round on `--help`; the last tests make the
round's runner fail if it is called under `--list`, and check `--help` exits at once.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

_SCRIPTS = pathlib.Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))

import load_test_data as ltd  # noqa: E402
import mutation_round_4  # noqa: E402
import mutation_round_5  # noqa: E402
import mutation_round_6  # noqa: E402
import mutation_round_7  # noqa: E402
import mutation_rounds_1_3  # noqa: E402


class _Collection:
    def __init__(self) -> None:
        self.keys: list[str] = []

    def upsert(self, key: str, _doc: dict) -> None:
        self.keys.append(key)


class _Scope:
    def __init__(self, bucket: _Bucket) -> None:
        self._bucket = bucket

    def collection(self, name: str) -> _Collection:
        return self._bucket.collections.setdefault(name, _Collection())


class _Bucket:
    def __init__(self) -> None:
        self.collections: dict[str, _Collection] = {}

    def scope(self, _name: str) -> _Scope:
        return _Scope(self)

    def default_collection(self) -> _Collection:
        return self.collections.setdefault("_default", _Collection())


class _Cluster:
    def __init__(self) -> None:
        self.the_bucket = _Bucket()

    def bucket(self, _name: str) -> _Bucket:
        return self.the_bucket

    def query(self, _statement: str) -> list[dict]:
        return [{"n": 3}]


def _run(monkeypatch, argv: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["load_test_data.py", *argv])
    return ltd.main()


def test_load_test_data_previews_and_connects_to_nothing_without_perform(
    monkeypatch, capsys
):
    def _refuse(_args):
        raise AssertionError("a preview must not open a connection")

    monkeypatch.setattr(ltd, "_connect", _refuse)
    assert _run(monkeypatch, ["--events", "3", "--assets", "2"]) == 0
    out = capsys.readouterr().out
    assert "PREVIEW" in out and "Nothing is changed" in out
    assert "would upsert 3 documents" in out and "Add --perform" in out


def test_load_test_data_writes_only_with_perform(monkeypatch):
    cluster = _Cluster()
    monkeypatch.setattr(ltd, "_connect", lambda _args: cluster)
    monkeypatch.setattr(ltd, "_ensure_keyspaces", lambda *_a: None)
    monkeypatch.setattr(ltd, "_index", lambda *_a: None)
    argv = ["--events", "3", "--assets", "2", "--perform"]
    assert _run(monkeypatch, argv) == 0
    written = cluster.the_bucket.collections
    assert len(written[ltd.EVENTS].keys) == 3
    assert len(written[ltd.ASSETS].keys) == 2
    assert len(written["_default"].keys) == 5


MUTATION_SCRIPTS = [
    mutation_rounds_1_3,
    mutation_round_4,
    mutation_round_5,
    mutation_round_6,
    mutation_round_7,
]
assert len(MUTATION_SCRIPTS) == 5, (
    "a parametrised list that came back empty would skip, not fail"
)


@pytest.mark.parametrize("module", MUTATION_SCRIPTS, ids=lambda m: m.__name__)
def test_mutation_list_runs_nothing(module, monkeypatch, capsys):
    def _refuse(*_a, **_k):
        raise AssertionError("--list must not run a mutation")

    monkeypatch.setattr(module, "run", _refuse)
    assert module.main(["--list"]) == 0
    out = capsys.readouterr().out
    assert f"{len(module.MUTATIONS)} mutations. Nothing was run." in out
    assert module.MUTATIONS[0][0] in out


@pytest.mark.parametrize("module", MUTATION_SCRIPTS, ids=lambda m: m.__name__)
def test_mutation_help_exits_without_starting_a_round(module, monkeypatch, capsys):
    def _refuse(*_a, **_k):
        raise AssertionError("--help must not run a mutation")

    monkeypatch.setattr(module, "run", _refuse)
    with pytest.raises(SystemExit) as stop:
        module.main(["--help"])
    assert stop.value.code == 0
    assert "--list" in capsys.readouterr().out
