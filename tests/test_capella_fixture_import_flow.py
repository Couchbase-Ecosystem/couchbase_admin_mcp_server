"""Driving capella_fixture_import end to end against a cluster held in memory.

This tool refused for the whole life of the module, and the refusal was correct
while the Data API layer did not exist: "a fixture that reports success with no
documents in it is the worst outcome available here". Now that it writes, the
same sentence describes the thing the tests have to rule out.

The ORDER is the design, and most of these cases assert it rather than the
result:

  1. Integrity FIRST, before a single call to the cluster. Finding out that a
     fixture's files changed after creating three buckets is finding out too
     late.
  2. Guardrails -- project allowlist, and the name prefix on every bucket this
     call would CREATE. Existing buckets are not prefix-checked, because the rule
     governs what this server brings into existence.
  3. Structure, then documents, then indexes. Documents before indexes is
     deliberate: building an index over a populated collection is one pass, while
     loading into an already-built index pays the maintenance cost every batch.

And the refusals that were measured rather than imagined: a keyspace_map arriving
as a NESTED OBJECT because scripts/dump_tool.py reads every dot as a level of
nesting, and a map that sends a keyspace to a bucket this structure entry never
resolved.
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
    rows: list[dict] | None = None,
    structure: list | None = None,
    gsi: list | None = None,
    mode: str = "server",
    keyspace: str = "b.s.c",
) -> pathlib.Path:
    directory = root / "fx"
    (directory / "data").mkdir(parents=True, exist_ok=True)
    rows = [{"id": "k1", "doc": {"v": 1}}] if rows is None else rows
    files = []
    hashes = []
    if rows:
        data_file = directory / "data" / f"{keyspace}.jsonl"
        data_file.write_text(
            "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
        )
        digest = hashlib.sha256(data_file.read_bytes()).hexdigest()
        hashes.append(digest)
        files.append(
            {
                "path": f"data/{keyspace}.jsonl",
                "keyspace": keyspace,
                "sha256": digest,
                "document_count": len(rows),
            }
        )
    manifest = {
        "schema": fixture.MANIFEST_SCHEMA,
        "fixture_id": "fx",
        "name": "fx",
        "mode": mode,
        "created_at": "2026-09-14T00:00:00Z",
        "source": {"plane": "capella"},
        "structure": structure
        if structure is not None
        else [{"name": "b", "scopes": [{"name": "s", "collections": [{"name": "c"}]}]}],
        "gsi_definitions": gsi or [],
        "eventing_functions": [],
        "files": files,
        "document_count": len(rows),
        "payload_sha256": hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest(),
        "fidelity": {"documents": True},
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory


@pytest.fixture
def target(monkeypatch):
    """A Capella cluster in memory, plus every seam the importer goes through."""
    from handlers.capella import environment as env
    from handlers.capella import guardrails as g

    state = {
        "buckets": [{"name": "b", "id": "Yg=="}],
        "invocations": [],
        "invoke_errors": {},
        "documents": [],
        "put_error": "",
        "base": ("https://data.invalid", ""),
        "credential": (("u", "p"), ""),
        "queries": [],
        "index_rows": [{"name": "ix1", "state": "online"}],
        "name_refusal": None,
        "project_refusal": None,
        "buckets_list_error": None,
    }

    def invoke(op_name, args, body=None, composite=""):
        state["invocations"].append((op_name, body))
        if op_name == "capella_buckets_list":
            if state["buckets_list_error"]:
                raise RuntimeError(state["buckets_list_error"])
            return {"data": list(state["buckets"])}
        if op_name in state["invoke_errors"]:
            raise RuntimeError(state["invoke_errors"][op_name])
        if op_name == "capella_bucket_create":
            state["buckets"].append({"name": body["name"], "id": "bmV3"})
            return {"id": "bmV3"}
        return {"data": []}

    def put(base, credential, bucket, scope, collection, key, doc, timeout=30):
        state["documents"].append((bucket, scope, collection, key))
        return state["put_error"]

    def sql(base, credential, statement, parameters=None, timeout=None):
        state["queries"].append(statement)
        if "system:indexes" in statement:
            return {"results": state["index_rows"]}
        return {"results": [{"n": 1}]}

    def assert_name(name, policy):
        if state["name_refusal"]:
            raise RuntimeError(state["name_refusal"])

    def assert_project(project, policy):
        if state["project_refusal"]:
            raise RuntimeError(state["project_refusal"])

    monkeypatch.setattr(env, "_resolve_context", lambda args: ("o", "p", None))
    monkeypatch.setattr(env, "_invoke", invoke)
    monkeypatch.setattr(g, "assert_name_allowed", assert_name)
    monkeypatch.setattr(g, "assert_project_allowed", assert_project)
    monkeypatch.setattr(fixture, "_data_api_base", lambda ids: state["base"])
    monkeypatch.setattr(fixture, "_data_api_credential", lambda: state["credential"])
    monkeypatch.setattr(fixture, "_put_document", put)
    monkeypatch.setattr(fixture, "_sql_query", sql)
    return state


def run(directory, **args):
    return fixture.handle(
        "capella_fixture_import",
        {
            "fixture_path": str(directory),
            "cluster_id": "c1",
            "confirm": True,
            **args,
        },
    )


# ═══ refusals before anything is touched ═════════════════════════════════════


def test_a_keyspace_map_that_is_not_an_object_is_refused(tmp_path, target):
    result = run(_write(tmp_path), keyspace_map="b.s.c=x.y.z")
    assert is_error(result)
    assert target["invocations"] == [], "nothing may be called before this refusal"


def test_a_nested_keyspace_map_names_the_dotted_argument_that_produced_it(
    tmp_path, target
):
    """MEASURED 2026-09-14: scripts/dump_tool.py's dotted -a syntax turns
    keyspace_map.travel-sample.inventory.airline=... into
    {"travel-sample": {"inventory": {"airline": "..."}}}, because it reads every
    dot as nesting. The KEY here is a whole keyspace, dots included, so that
    spelling cannot express it at all.

    str(v) on that produces a plausible-looking target keyspace out of a Python
    repr, and this operation writes to somebody's cluster."""
    result = run(
        _write(tmp_path), keyspace_map={"travel-sample": {"inventory": {"a": "x"}}}
    )
    assert is_error(result)
    error = payload(result)["error"]
    assert "--args-json" in error
    assert "Nothing was imported" in error
    assert target["invocations"] == []


def test_a_tampered_fixture_is_refused_before_the_cluster_is_touched(tmp_path, target):
    """Integrity FIRST. Finding out after creating three buckets is too late."""
    directory = _write(tmp_path)
    (directory / "data" / "b.s.c.jsonl").write_text(
        '{"id": "different", "doc": {}}\n', encoding="utf-8"
    )
    result = run(directory)
    assert is_error(result)
    assert target["invocations"] == []


def test_a_refused_project_stops_the_import(tmp_path, target):
    target["project_refusal"] = "project p is not in the allowlist"
    result = run(_write(tmp_path))
    assert is_error(result)
    assert "allowlist" in payload(result)["error"]


def test_a_bucket_that_would_be_created_is_prefix_checked(tmp_path, target):
    """A bucket created without the configured prefix could never be torn down by
    this server."""
    target["buckets"] = []
    target["name_refusal"] = "name 'b' lacks the required prefix"
    result = run(_write(tmp_path))
    assert is_error(result)
    error = payload(result)["error"]
    assert "Nothing was imported" in error
    assert "could never be torn down" in error


def test_an_existing_bucket_is_not_prefix_checked(tmp_path, target):
    """The rule governs what this server brings into existence, not what it
    finds. A fixture imported into a bucket somebody else made is not this
    server's naming decision."""
    target["name_refusal"] = "would refuse if asked"
    result = run(_write(tmp_path))
    assert not is_error(result), payload(result)


def test_a_bucket_listing_that_fails_stops_the_import(tmp_path, target):
    target["buckets_list_error"] = "403 forbidden"
    result = run(_write(tmp_path))
    assert is_error(result)
    assert "could not list buckets" in payload(result)["error"]


# ═══ structure ═══════════════════════════════════════════════════════════════


def test_a_missing_bucket_scope_and_collection_are_created(tmp_path, target):
    target["buckets"] = []
    result = run(_write(tmp_path))
    body = payload(result)
    ops = [name for name, _ in target["invocations"]]
    assert "capella_bucket_create" in ops
    assert "capella_scope_create" in ops
    assert "capella_collection_create" in ops
    structure = next(s for s in body["steps"] if s["step"] == "structure")
    assert structure["buckets_created"] == ["b"]
    assert "re-runnable by design" in structure["note"]


def test_an_existing_scope_is_reused_rather_than_failing_the_import(tmp_path, target):
    """This tool is explicitly re-runnable, so an already-existing scope is the
    expected case on a second run."""
    target["invoke_errors"]["capella_scope_create"] = "scope already exists"
    result = run(_write(tmp_path))
    assert not is_error(result), payload(result)


def test_any_other_scope_failure_is_reported(tmp_path, target):
    target["invoke_errors"]["capella_scope_create"] = "insufficient permissions"
    body = payload(run(_write(tmp_path)))
    assert body["imported"] is False
    assert any("could not" in p for p in body["problems"])


def test_an_existing_collection_is_reused(tmp_path, target):
    target["invoke_errors"]["capella_collection_create"] = "collection already exists"
    assert not is_error(run(_write(tmp_path)))


def test_a_collection_failure_is_reported(tmp_path, target):
    target["invoke_errors"]["capella_collection_create"] = "quota exceeded"
    body = payload(run(_write(tmp_path)))
    assert body["imported"] is False


def test_capella_owned_system_scopes_are_skipped_and_explained(tmp_path, target):
    """Capella creates and owns these and refuses any attempt to make one
    (422 code 11006). The exporter records them because it records what it
    finds."""
    structure = [
        {
            "name": "b",
            "scopes": [
                {"name": "s", "collections": [{"name": "c"}]},
                {"name": "_system", "collections": [{"name": "_mobile"}]},
            ],
        }
    ]
    body = payload(run(_write(tmp_path, structure=structure)))
    step = next(s for s in body["steps"] if s["step"] == "structure")
    assert step["system_scopes_skipped"]
    assert "NOT a problem" in step["system_scopes_note"]
    assert body["imported"] is True


def test_a_keyspace_map_pointing_at_another_bucket_is_refused_not_guessed(
    tmp_path, target
):
    """This bucket's id was resolved above; another bucket's has not been, and
    inventing one addresses the wrong cluster object.

    The map below is INTERNALLY INCONSISTENT, which is the case worth refusing:
    the bucket-level remap resolves `b` to `keep` (the first entry naming that
    bucket), while the full-keyspace remap sends `b.s.c` to a different bucket
    entirely. A consistent map -- every keyspace in a bucket going to the same
    target bucket -- is rewritten normally and is not what this guard is for.
    """
    body = payload(
        run(
            _write(tmp_path),
            keyspace_map={"b.other.thing": "keep.other.thing", "b.s.c": "far.s.c"},
        )
    )
    assert body["imported"] is False
    assert any("Map the bucket itself instead" in p for p in body["problems"])


def test_a_consistent_keyspace_map_is_rewritten_rather_than_refused(tmp_path, target):
    """The positive half: when every keyspace in a bucket goes to the same target
    bucket, the rewrite is unambiguous and proceeds."""
    target["buckets"] = [{"name": "target", "id": "dA=="}]
    body = payload(run(_write(tmp_path), keyspace_map={"b.s.c": "target.s2.c2"}))
    assert body["imported"] is True, body.get("problems")
    assert target["documents"] == [("target", "s2", "c2", "k1")]


def test_a_scope_with_no_collections_is_still_created(tmp_path, target):
    structure = [{"name": "b", "scopes": [{"name": "empty", "collections": []}]}]
    run(_write(tmp_path, structure=structure))
    ops = [(name, body) for name, body in target["invocations"]]
    assert ("capella_scope_create", {"name": "empty"}) in ops


# ═══ documents ═══════════════════════════════════════════════════════════════


def test_documents_are_written_over_the_data_api(tmp_path, target):
    body = payload(run(_write(tmp_path, rows=[{"id": "k1", "doc": {"v": 1}}])))
    assert target["documents"] == [("b", "s", "c", "k1")]
    assert body["imported"] is True


def test_an_unusable_data_api_fails_the_import_rather_than_half_finishing(
    tmp_path, target
):
    """The structure was created and the documents CANNOT be loaded, so the
    target must not be treated as a populated environment."""
    target["base"] = ("", "the Data API is not usable on this cluster")
    result = run(_write(tmp_path))
    assert is_error(result)
    error = payload(result)["error"]
    assert "CANNOT be loaded" in error
    assert "must not be treated as a populated environment" in error


def test_a_missing_data_api_credential_fails_the_same_way(tmp_path, target):
    target["credential"] = (("", ""), "no Data API credential")
    result = run(_write(tmp_path))
    assert is_error(result)
    assert "no Data API credential" in payload(result)["error"]


def test_a_document_that_will_not_write_is_reported(tmp_path, target):
    target["put_error"] = "403: forbidden"
    body = payload(run(_write(tmp_path)))
    assert body["imported"] is False


def test_a_structure_only_fixture_needs_no_data_api_at_all(tmp_path, target):
    """No files means no document phase, so a cluster with the Data API disabled
    can still receive a structure-only fixture."""
    target["base"] = ("", "the Data API is not usable on this cluster")
    result = run(_write(tmp_path, rows=[]))
    assert not is_error(result), payload(result)


# ═══ indexes ═════════════════════════════════════════════════════════════════
#
# Documents BEFORE indexes is deliberate: building an index over a populated
# collection is one pass, while loading into an already-built index pays the
# maintenance cost on every batch. The index step therefore runs last, and its
# failures have to be visible without unwinding the documents already written.


def _gsi(name="ix1", definition=None):
    return {
        "indexName": name,
        "definition": definition or f"CREATE INDEX `{name}` ON `b`.`s`.`c`(`f`)",
        "keyspace": "b.s.c",
    }


def test_recorded_indexes_are_created(tmp_path, target):
    body = payload(run(_write(tmp_path, gsi=[_gsi()])))
    assert body["imported"] is True
    assert any("CREATE INDEX" in q for q in target["queries"])


def test_a_replica_entry_is_not_created_a_second_time(tmp_path, target):
    """A replica entry is the SAME index. Creating it twice is an error, not a
    second index."""
    gsi = [_gsi("ix1"), _gsi("ix1 (replica 1)")]
    run(_write(tmp_path, gsi=gsi))
    creates = [q for q in target["queries"] if q.startswith("CREATE INDEX")]
    assert len(creates) == 1


def test_two_definitions_that_render_the_same_statement_are_issued_once(
    tmp_path, target
):
    """The control plane enumerates copies; the statement is what the query
    service acts on, so deduplicating on the statement is what stops a second
    identical CREATE."""
    same = "CREATE INDEX `ix1` ON `b`.`s`.`c`(`f`)"
    run(_write(tmp_path, gsi=[_gsi("ix1", same), _gsi("ix1_other", same)]))
    creates = [q for q in target["queries"] if q.startswith("CREATE INDEX")]
    assert len(creates) == 1


def test_a_definition_with_no_statement_is_reported(tmp_path, target):
    body = payload(run(_write(tmp_path, gsi=[{"indexName": "ix1"}])))
    assert body["imported"] is False
    assert any("no recorded definition" in p for p in body["problems"])


def test_an_index_that_already_exists_is_not_a_failure(tmp_path, target, monkeypatch):
    """This tool is re-runnable, so the second import onto the same cluster finds
    its indexes already there."""

    def sql(base, credential, statement, parameters=None, timeout=None):
        target["queries"].append(statement)
        if statement.startswith("CREATE INDEX"):
            raise RuntimeError("index already exists")
        if "system:indexes" in statement:
            return {"results": target["index_rows"]}
        return {"results": [{"n": 1}]}

    monkeypatch.setattr(fixture, "_sql_query", sql)
    body = payload(run(_write(tmp_path, gsi=[_gsi()])))
    assert body["imported"] is True


def test_an_index_that_cannot_be_created_is_reported(tmp_path, target, monkeypatch):
    def sql(base, credential, statement, parameters=None, timeout=None):
        if statement.startswith("CREATE INDEX"):
            raise RuntimeError("syntax error near '('")
        if "system:indexes" in statement:
            return {"results": target["index_rows"]}
        return {"results": [{"n": 1}]}

    monkeypatch.setattr(fixture, "_sql_query", sql)
    body = payload(run(_write(tmp_path, gsi=[_gsi()])))
    assert body["imported"] is False
    assert any("could not be created" in p for p in body["problems"])


def test_indexes_are_not_applied_when_the_data_api_is_unavailable(tmp_path, target):
    """A structure-only fixture carrying index definitions still needs the Data
    API to create them, and saying so beats reporting an import that quietly
    created none."""
    target["base"] = ("", "the Data API is not usable on this cluster")
    body = payload(run(_write(tmp_path, rows=[], gsi=[_gsi()])))
    assert any("could not be applied" in p for p in body["problems"])
