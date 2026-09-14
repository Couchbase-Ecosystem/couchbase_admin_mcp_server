"""Guards for the Enterprise Edition fixture family (`admin_fixture_*`).

WHAT THESE COVER, AND WHAT THEY CANNOT
======================================
Every test here is decidable without a cluster: refusals, ordering, the shapes
written to disk, and the transport a write actually uses. None of them contact a
Couchbase server, and the module is explicit that it has **not yet been run
against a live Enterprise Edition cluster**.

That distinction is load-bearing rather than modest. The Capella side had
per-file hashes, line counts and a cluster-side `COUNT(*)` all agreeing while
187 of 188 document KEYS were wrong, because each of those compares a fixture
against itself. Only a round trip -- export, import elsewhere, export back,
compare -- found it. So these tests establish that the code does what it says;
they do not establish that what it says is what the cluster does.

THE REFUSALS ARE THE POINT
==========================
The importer writes to somebody's cluster, so the interesting cases are the ones
where it must refuse BEFORE doing so. An importer that validated after creating
three collections would pass a test that only checked the final verdict.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from handlers import fixture


def _payload(*hashes: str) -> str:
    return hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest()


def _write_fixture(root: pathlib.Path, *, documents: str = '{"id": "a", "doc": {}}\n',
                   mode: str = "server", schema: str | None = None,
                   keyspace: str = "b.s.c") -> pathlib.Path:
    """A minimal fixture on disk whose manifest is internally consistent."""
    directory = root / "fx"
    (directory / "data").mkdir(parents=True, exist_ok=True)
    data_file = directory / "data" / f"{keyspace}.jsonl"
    data_file.write_text(documents, encoding="utf-8")
    digest = hashlib.sha256(data_file.read_bytes()).hexdigest()
    manifest = {
        "schema": schema or fixture.MANIFEST_SCHEMA,
        "fixture_id": "fx",
        "name": "fx",
        "mode": mode,
        "created_at": "2026-09-14T00:00:00Z",
        "source": {"plane": "enterprise"},
        "structure": [],
        "gsi_definitions": [],
        "eventing_functions": [],
        "files": [{"path": f"data/{keyspace}.jsonl", "keyspace": keyspace,
                   "sha256": digest,
                   "document_count": documents.count("\n")}],
        "document_count": documents.count("\n"),
        "payload_sha256": _payload(digest),
        "fidelity": {"documents": True},
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory


def _text(result) -> str:
    return "".join(block.text for block in result)


# ── the family is registered and gated ───────────────────────────────────────


def test_the_family_declares_four_tools():
    """Premise for everything below."""
    names = {t.name for t in fixture.TOOLS}
    assert names == {
        "admin_fixture_export",
        "admin_fixture_import",
        "admin_fixture_list",
        "admin_fixture_verify",
    }, names


def test_every_tool_is_dispatchable():
    """A tool declared and not wired is a tool that 404s at call time."""
    for tool in fixture.TOOLS:
        assert tool.name in fixture.TOOL_NAMES
    assert "Unknown fixture tool" in _text(fixture.handle("admin_fixture_nope", {}))


def test_the_export_tool_says_it_writes_to_the_filesystem():
    """It is annotated readOnlyHint=True, which is true of the CLUSTER and not of
    the disk. A caller reading only the annotation would otherwise be misled, so
    the description has to carry it."""
    export = next(t for t in fixture.TOOLS if t.name == "admin_fixture_export")
    assert export.annotations.readOnlyHint is True
    assert "WRITES TO THE LOCAL FILESYSTEM" in export.description


def test_the_import_tool_requires_confirmation():
    """It writes to a cluster."""
    imp = next(t for t in fixture.TOOLS if t.name == "admin_fixture_import")
    assert "confirm" in imp.inputSchema["required"]
    assert imp.annotations.destructiveHint is True


def test_the_export_tool_refuses_to_create_indexes_and_says_so():
    """Building an index on somebody's cluster is a capacity decision, not a
    side effect of reading -- and an unindexed collection is the FIRST thing a
    real export hits, so the remedy has to be in the description."""
    export = next(t for t in fixture.TOOLS if t.name == "admin_fixture_export")
    assert "will NOT create one" in export.description


def test_the_import_tool_refuses_to_create_buckets_and_says_so():
    """A bucket is a memory-quota decision on a cluster somebody else sized."""
    imp = next(t for t in fixture.TOOLS if t.name == "admin_fixture_import")
    assert "Does NOT create buckets" in imp.description


# ── refusals that happen before any cluster call ──────────────────────────────


def test_export_requires_a_fixture_id():
    result = fixture.handle("admin_fixture_export", {"fixture_path": "/tmp/x"})
    assert "fixture_id is required" in _text(result)


def test_export_refuses_a_path_outside_the_fixture_root(tmp_path, monkeypatch):
    """CB_ADMIN_FIXTURE_ROOT is the only bound on where this writes, and a
    container is exactly the deployment where the caller is not the operator."""
    monkeypatch.setenv("CB_ADMIN_FIXTURE_ROOT", str(tmp_path / "allowed"))
    result = fixture.handle("admin_fixture_export", {
        "fixture_id": "x", "fixture_path": str(tmp_path / "elsewhere"),
    })
    assert "outside CB_ADMIN_FIXTURE_ROOT" in _text(result)


def test_import_refuses_a_fixture_whose_bytes_have_changed(tmp_path):
    """The check runs BEFORE the first cluster call. A fixture whose files have
    changed since it was written is not a fixture, and finding that out after
    creating three collections is finding out too late."""
    directory = _write_fixture(tmp_path)
    (directory / "data" / "b.s.c.jsonl").write_text(
        '{"id": "tampered", "doc": {}}\n', encoding="utf-8"
    )
    result = fixture.handle("admin_fixture_import", {
        "fixture_path": str(directory), "confirm": True,
    })
    text = _text(result)
    assert "does not verify" in text
    assert "NOTHING was imported" in text


def test_import_refuses_a_mobile_fixture(tmp_path):
    """Its sync metadata cannot be restored, and documents that look synced and
    are not are worse than documents that were never loaded."""
    directory = _write_fixture(tmp_path, mode="mobile")
    result = fixture.handle("admin_fixture_import", {
        "fixture_path": str(directory), "confirm": True,
    })
    assert "MOBILE fixture" in _text(result)


def test_import_refuses_an_unknown_manifest_schema(tmp_path):
    directory = _write_fixture(tmp_path, schema="couchbase.fixture/v99")
    result = fixture.handle("admin_fixture_import", {
        "fixture_path": str(directory), "confirm": True,
    })
    assert "schema is" in _text(result)


def test_import_accepts_a_fixture_written_before_the_schema_was_renamed(tmp_path):
    """The legacy Capella schema id is READABLE. Fixtures on somebody's disk do
    not stop being fixtures because the name of the format changed."""
    from handlers import fixture_core

    legacy = sorted(fixture_core.LEGACY_MANIFEST_SCHEMAS)[0]
    directory = _write_fixture(tmp_path, schema=legacy)
    result = fixture.handle("admin_fixture_import", {
        "fixture_path": str(directory), "confirm": True,
    })
    # It gets PAST the schema gate. What it does next needs a cluster, which is
    # not the property under test here.
    assert "schema is" not in _text(result)


def test_import_refuses_a_nested_keyspace_map(tmp_path):
    """A dotted argument name produces a nested object by accident, and a map
    whose values are objects would silently rewrite nothing."""
    directory = _write_fixture(tmp_path)
    result = fixture.handle("admin_fixture_import", {
        "fixture_path": str(directory), "confirm": True,
        "keyspace_map": {"b": {"s": "x"}},
    })
    assert "must be strings" in _text(result)


# ── what the export writes ───────────────────────────────────────────────────


class _Stub:
    """Stands in for the cluster: REST reads and SQL++ rows, by statement."""

    def __init__(self, rows_by_keyspace=None, buckets=None):
        self.rows_by_keyspace = rows_by_keyspace or {}
        self.buckets = buckets or [{"name": "b", "bucketType": "membase",
                                    "quota": {"rawRAM": 104857600}}]
        self.statements: list[str] = []

    def admin_request(self, method, path, *args, **kwargs):
        if path == "/pools/default/buckets":
            return self.buckets
        if path.endswith("/scopes"):
            return {"scopes": [
                {"name": "s", "collections": [{"name": "c"}]},
                {"name": "_system", "collections": [{"name": "internal"}]},
            ]}
        if path == "/pools":
            return {"uuid": "abc", "implementationVersion": "7.6.0"}
        if path == "/pools/default":
            return {"clusterName": "test", "nodes": [{"hostname": "n1:8091"}]}
        if "functions" in path:
            return []
        return {}

    def query(self, statement, parameters=None):
        self.statements.append(statement)
        if "system:indexes" in statement:
            return []
        if "COUNT(*)" in statement:
            return [{"total": 1}]
        # A key-range page: serve everything once, then nothing.
        last = (parameters or {}).get("last_key", "")
        for keyspace, rows in self.rows_by_keyspace.items():
            if f"`{keyspace.split('.')[2]}`" in statement:
                return [] if last else list(rows)
        return []


@pytest.fixture
def stub(monkeypatch):
    instance = _Stub()
    monkeypatch.setattr(fixture, "admin_request", instance.admin_request)
    monkeypatch.setattr(fixture, "_query", instance.query)
    return instance


def test_export_writes_a_manifest_and_one_file_per_non_empty_keyspace(
    tmp_path, stub, monkeypatch
):
    stub.rows_by_keyspace = {"b.s.c": [
        {fixture.META_ID_ALIAS: "k1", fixture.META_EXP_ALIAS: 0, "field": 1},
    ]}
    result = fixture.handle("admin_fixture_export", {
        "fixture_id": "fx", "fixture_path": str(tmp_path / "out"),
        "tags": {"scenario": "one"},
    })
    text = _text(result)
    assert "error" not in text.lower() or "errors" in text.lower()

    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["schema"] == fixture.MANIFEST_SCHEMA
    assert manifest["source"]["plane"] == "enterprise"
    assert manifest["tags"] == {"scenario": "one"}
    assert manifest["document_count"] == 1
    assert [f["keyspace"] for f in manifest["files"]] == ["b.s.c"]

    rows = (tmp_path / "out" / "data" / "b.s.c.jsonl").read_text().strip().splitlines()
    assert json.loads(rows[0]) == {"id": "k1", "exp": 0, "doc": {"field": 1},
                                   "xattrs": {}}


def test_export_skips_reserved_scopes(tmp_path, stub):
    """`_system` is Couchbase's own, it is not the customer data a fixture is
    for, and the query service refuses some of it outright."""
    stub.rows_by_keyspace = {"b.s.c": [
        {fixture.META_ID_ALIAS: "k1", fixture.META_EXP_ALIAS: 0},
    ]}
    fixture.handle("admin_fixture_export", {
        "fixture_id": "fx", "fixture_path": str(tmp_path / "out"),
    })
    assert not any("_system" in s for s in stub.statements), stub.statements


def test_export_refuses_a_keyspace_filter_that_matches_nothing(tmp_path, stub):
    """A single typo would otherwise produce a SILENT SUCCESS: no collection
    matches, nothing is written, and the manifest reports a clean export of zero
    documents. The caller asked for a keyspace and got a fixture without it."""
    result = fixture.handle("admin_fixture_export", {
        "fixture_id": "fx", "fixture_path": str(tmp_path / "out"),
        "keyspaces": ["b.s.typo"],
    })
    text = _text(result)
    assert "do not exist on this cluster" in text
    assert not (tmp_path / "out" / "manifest.json").exists(), (
        "a manifest was written for an export that matched nothing"
    )


def test_export_refuses_a_row_whose_key_alias_was_overwritten(tmp_path, stub):
    """THE CAPELLA BUG, guarded here before it can happen on this plane.

    A document carrying a field named like the metadata alias would overwrite it
    and the real key could not be recovered. Recording the wrong key silently is
    what shipped on the other plane; here it refuses.
    """
    stub.rows_by_keyspace = {"b.s.c": [{"field": 1}]}  # no META_ID_ALIAS at all
    result = fixture.handle("admin_fixture_export", {
        "fixture_id": "fx", "fixture_path": str(tmp_path / "out"),
    })
    text = _text(result)
    assert fixture.META_ID_ALIAS in text
    assert "real key cannot be recovered" in text
    assert not (tmp_path / "out" / "manifest.json").exists()


def test_an_export_of_only_empty_collections_does_not_claim_to_hold_documents(
    tmp_path, stub
):
    """fidelity.documents means "this fixture contains documents", not "the
    document phase ran". An export of empty collections satisfies the second and
    a consumer reads the first."""
    stub.rows_by_keyspace = {}
    fixture.handle("admin_fixture_export", {
        "fixture_id": "fx", "fixture_path": str(tmp_path / "out"),
    })
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["fidelity"]["documents"] is False
    assert "no documents" in manifest["fidelity"]["note"]


def test_a_structure_only_export_says_it_is_not_a_dataset(tmp_path, stub):
    fixture.handle("admin_fixture_export", {
        "fixture_id": "fx", "fixture_path": str(tmp_path / "out"),
        "include_data": False,
    })
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["fidelity"]["documents"] is False
    assert "SHAPE, not a dataset" in manifest["fidelity"]["note"]


def test_the_manifest_never_claims_cas_or_system_xattrs(tmp_path, stub):
    """Neither is preserved by any write path available here, and a fixture that
    silently drops something is worse than one that refuses."""
    fixture.handle("admin_fixture_export", {
        "fixture_id": "fx", "fixture_path": str(tmp_path / "out"),
    })
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["fidelity"]["cas"] is False
    assert manifest["fidelity"]["system_xattrs"] is False


# ── the write path ───────────────────────────────────────────────────────────


def test_the_importer_writes_over_kv_rather_than_sql(tmp_path):
    """Parsed from the source, not asserted by convention.

    Two reasons this matters. A mutating SQL++ statement in a handler is refused
    by tests/test_no_handler_embeds_a_mutating_sql_statement -- this server's
    SQL++ surface is read-guarded. And UPSERT through the query service cannot
    set a per-document expiry without more statement text, which is exactly the
    kind of generated SQL that guard exists to keep out.
    """
    import ast
    import inspect
    import textwrap

    source = inspect.getsource(fixture._import_documents)
    assert ".upsert(" in source, "the importer no longer writes over KV"

    # Asserted on the CALL GRAPH, not on the text. The function's own docstring
    # explains why it does not use UPSERT, and a text scan reads that
    # explanation as the offence.
    tree = ast.parse(textwrap.dedent(source))
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "_query" not in called, (
        "the document importer calls the SQL++ path. Documents are written over "
        "KV: a mutating SQL++ statement in a handler is refused by "
        "tests/test_no_handler_embeds_a_mutating_sql_statement, and UPSERT "
        "through the query service cannot set a per-document expiry without "
        "more generated statement text."
    )


def test_the_module_states_that_it_has_not_been_run_against_a_cluster():
    """CLAUDE.md rule 1.7 applied to a module: code that reads as verified when
    it is not is the claim this repository most wants to avoid making.

    Delete this test when the round trip has been run -- and change the
    docstring in the same commit, with the date and what was measured.
    """
    assert "NOT YET RUN AGAINST A LIVE ENTERPRISE EDITION CLUSTER" in fixture.__doc__


def test_a_cluster_count_is_reported_as_necessary_not_sufficient():
    """COUNT(*) agreed exactly while 187 of 188 keys were wrong. A verify that
    presented a matching count as proof would have reported that fixture clean.
    """
    import inspect

    source = inspect.getsource(fixture._cluster_counts)
    assert "NECESSARY condition, not a sufficient one" in source


# ── listing ──────────────────────────────────────────────────────────────────


def test_listing_reports_an_unreadable_fixture_rather_than_skipping_it(tmp_path):
    """A listing that omits an unreadable fixture answers "what do I have" with
    a confident lie."""
    good = _write_fixture(tmp_path)
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "manifest.json").write_text("{not json", encoding="utf-8")

    result = fixture.handle("admin_fixture_list", {"root_path": str(tmp_path)})
    payload = json.loads(_text(result))
    assert payload["count"] == 1
    assert payload["fixtures"][0]["fixture_path"] == str(good)
    assert len(payload["unreadable"]) == 1
    assert "not valid JSON" in payload["unreadable"][0]["error"]


def test_listing_filters_on_every_named_tag(tmp_path):
    directory = _write_fixture(tmp_path)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["tags"] = {"scenario": "hurricane", "version": "1.1"}
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    matching = json.loads(_text(fixture.handle("admin_fixture_list", {
        "root_path": str(tmp_path), "tags": {"scenario": "hurricane"},
    })))
    assert matching["count"] == 1

    partial = json.loads(_text(fixture.handle("admin_fixture_list", {
        "root_path": str(tmp_path),
        "tags": {"scenario": "hurricane", "version": "9.9"},
    })))
    assert partial["count"] == 0, "a tag filter matched with one value wrong"


def test_verify_reports_a_structure_only_fixture_as_carrying_no_data(tmp_path):
    directory = _write_fixture(tmp_path)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"] = []
    manifest["payload_sha256"] = None
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    payload = json.loads(_text(fixture.handle("admin_fixture_verify", {
        "fixture_path": str(directory),
    })))
    assert payload["verified"] is True
    assert "must not be presented as a dataset" in payload["note"]
