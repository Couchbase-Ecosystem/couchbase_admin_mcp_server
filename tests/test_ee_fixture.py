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


def _write_fixture(
    root: pathlib.Path,
    *,
    documents: str = '{"id": "a", "doc": {}}\n',
    mode: str = "server",
    schema: str | None = None,
    keyspace: str = "b.s.c",
) -> pathlib.Path:
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
        "files": [
            {
                "path": f"data/{keyspace}.jsonl",
                "keyspace": keyspace,
                "sha256": digest,
                "document_count": documents.count("\n"),
            }
        ],
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
    result = fixture.handle(
        "admin_fixture_export",
        {
            "fixture_id": "x",
            "fixture_path": str(tmp_path / "elsewhere"),
        },
    )
    assert "outside CB_ADMIN_FIXTURE_ROOT" in _text(result)


def test_import_refuses_a_fixture_whose_bytes_have_changed(tmp_path):
    """The check runs BEFORE the first cluster call. A fixture whose files have
    changed since it was written is not a fixture, and finding that out after
    creating three collections is finding out too late."""
    directory = _write_fixture(tmp_path)
    (directory / "data" / "b.s.c.jsonl").write_text(
        '{"id": "tampered", "doc": {}}\n', encoding="utf-8"
    )
    result = fixture.handle(
        "admin_fixture_import",
        {
            "fixture_path": str(directory),
            "confirm": True,
        },
    )
    text = _text(result)
    assert "does not verify" in text
    assert "NOTHING was imported" in text


def test_import_refuses_a_mobile_fixture(tmp_path):
    """Its sync metadata cannot be restored, and documents that look synced and
    are not are worse than documents that were never loaded."""
    directory = _write_fixture(tmp_path, mode="mobile")
    result = fixture.handle(
        "admin_fixture_import",
        {
            "fixture_path": str(directory),
            "confirm": True,
        },
    )
    assert "MOBILE fixture" in _text(result)


def test_import_refuses_an_unknown_manifest_schema(tmp_path):
    directory = _write_fixture(tmp_path, schema="couchbase.fixture/v99")
    result = fixture.handle(
        "admin_fixture_import",
        {
            "fixture_path": str(directory),
            "confirm": True,
        },
    )
    assert "schema is" in _text(result)


def test_import_accepts_a_fixture_written_before_the_schema_was_renamed(tmp_path):
    """The legacy Capella schema id is READABLE. Fixtures on somebody's disk do
    not stop being fixtures because the name of the format changed."""
    from handlers import fixture_core

    legacy = sorted(fixture_core.LEGACY_MANIFEST_SCHEMAS)[0]
    directory = _write_fixture(tmp_path, schema=legacy)
    result = fixture.handle(
        "admin_fixture_import",
        {
            "fixture_path": str(directory),
            "confirm": True,
        },
    )
    # It gets PAST the schema gate. What it does next needs a cluster, which is
    # not the property under test here.
    assert "schema is" not in _text(result)


def test_import_refuses_a_nested_keyspace_map(tmp_path):
    """A dotted argument name produces a nested object by accident, and a map
    whose values are objects would silently rewrite nothing."""
    directory = _write_fixture(tmp_path)
    result = fixture.handle(
        "admin_fixture_import",
        {
            "fixture_path": str(directory),
            "confirm": True,
            "keyspace_map": {"b": {"s": "x"}},
        },
    )
    assert "must be strings" in _text(result)


# ── what the export writes ───────────────────────────────────────────────────


class _Stub:
    """Stands in for the cluster: REST reads and SQL++ rows, by statement."""

    def __init__(self, rows_by_keyspace=None, buckets=None):
        self.rows_by_keyspace = rows_by_keyspace or {}
        self.buckets = buckets or [
            {"name": "b", "bucketType": "membase", "quota": {"rawRAM": 104857600}}
        ]
        self.statements: list[str] = []

    def admin_request(self, method, path, *args, **kwargs):
        if path == "/pools/default/buckets":
            return self.buckets
        if path.endswith("/scopes"):
            return {
                "scopes": [
                    {"name": "s", "collections": [{"name": "c"}]},
                    {"name": "_system", "collections": [{"name": "internal"}]},
                ]
            }
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
    stub.rows_by_keyspace = {
        "b.s.c": [
            {fixture.META_ID_ALIAS: "k1", fixture.META_EXP_ALIAS: 0, "field": 1},
        ]
    }
    result = fixture.handle(
        "admin_fixture_export",
        {
            "fixture_id": "fx",
            "fixture_path": str(tmp_path / "out"),
            "tags": {"scenario": "one"},
        },
    )
    text = _text(result)
    assert "error" not in text.lower() or "errors" in text.lower()

    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["schema"] == fixture.MANIFEST_SCHEMA
    assert manifest["source"]["plane"] == "enterprise"
    assert manifest["tags"] == {"scenario": "one"}
    assert manifest["document_count"] == 1
    assert [f["keyspace"] for f in manifest["files"]] == ["b.s.c"]

    rows = (tmp_path / "out" / "data" / "b.s.c.jsonl").read_text().strip().splitlines()
    assert json.loads(rows[0]) == {
        "id": "k1",
        "exp": 0,
        "doc": {"field": 1},
        "xattrs": {},
    }


def test_export_skips_reserved_scopes(tmp_path, stub):
    """`_system` is Couchbase's own, it is not the customer data a fixture is
    for, and the query service refuses some of it outright."""
    stub.rows_by_keyspace = {
        "b.s.c": [
            {fixture.META_ID_ALIAS: "k1", fixture.META_EXP_ALIAS: 0},
        ]
    }
    fixture.handle(
        "admin_fixture_export",
        {
            "fixture_id": "fx",
            "fixture_path": str(tmp_path / "out"),
        },
    )
    assert not any("_system" in s for s in stub.statements), stub.statements


def test_export_refuses_a_keyspace_filter_that_matches_nothing(tmp_path, stub):
    """A single typo would otherwise produce a SILENT SUCCESS: no collection
    matches, nothing is written, and the manifest reports a clean export of zero
    documents. The caller asked for a keyspace and got a fixture without it."""
    result = fixture.handle(
        "admin_fixture_export",
        {
            "fixture_id": "fx",
            "fixture_path": str(tmp_path / "out"),
            "keyspaces": ["b.s.typo"],
        },
    )
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
    result = fixture.handle(
        "admin_fixture_export",
        {
            "fixture_id": "fx",
            "fixture_path": str(tmp_path / "out"),
        },
    )
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
    fixture.handle(
        "admin_fixture_export",
        {
            "fixture_id": "fx",
            "fixture_path": str(tmp_path / "out"),
        },
    )
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["fidelity"]["documents"] is False
    assert "no documents" in manifest["fidelity"]["note"]


def test_a_structure_only_export_says_it_is_not_a_dataset(tmp_path, stub):
    fixture.handle(
        "admin_fixture_export",
        {
            "fixture_id": "fx",
            "fixture_path": str(tmp_path / "out"),
            "include_data": False,
        },
    )
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["fidelity"]["documents"] is False
    assert "SHAPE, not a dataset" in manifest["fidelity"]["note"]


def test_the_manifest_never_claims_cas_or_system_xattrs(tmp_path, stub):
    """Neither is preserved by any write path available here, and a fixture that
    silently drops something is worse than one that refuses."""
    fixture.handle(
        "admin_fixture_export",
        {
            "fixture_id": "fx",
            "fixture_path": str(tmp_path / "out"),
        },
    )
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


def test_the_module_records_what_was_measured_and_what_was_not():
    """CLAUDE.md rule 1.7 applied to a module: code that reads as verified when
    it is not is the claim this repository most wants to avoid making.

    This test used to assert the module said it had NOT been run. It has now
    been run -- 187 documents out and back, clean -- so the assertion moved with
    the fact rather than being deleted: the docstring must carry the date, and
    it must still name the part that is NOT verified.

    That second half is the one that will rot. The document path is proven; the
    index step was exercised against a target where every index already existed,
    so nothing was actually created. Saying so is the difference between a
    status and a claim.
    """
    doc = fixture.__doc__
    assert "2026-09-14" in doc, "the round-trip claim carries no date"
    assert "ROUND-TRIPPED CLEAN" in doc
    assert "still unverified" in doc, (
        "the module no longer names what the round trip did NOT establish. If "
        "the index step has since been exercised against a fresh target, say so "
        "with the date -- do not simply delete the admission."
    )


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

    matching = json.loads(
        _text(
            fixture.handle(
                "admin_fixture_list",
                {
                    "root_path": str(tmp_path),
                    "tags": {"scenario": "hurricane"},
                },
            )
        )
    )
    assert matching["count"] == 1

    partial = json.loads(
        _text(
            fixture.handle(
                "admin_fixture_list",
                {
                    "root_path": str(tmp_path),
                    "tags": {"scenario": "hurricane", "version": "9.9"},
                },
            )
        )
    )
    assert partial["count"] == 0, "a tag filter matched with one value wrong"


def test_verify_reports_a_structure_only_fixture_as_carrying_no_data(tmp_path):
    directory = _write_fixture(tmp_path)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"] = []
    manifest["payload_sha256"] = None
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    payload = json.loads(
        _text(
            fixture.handle(
                "admin_fixture_verify",
                {
                    "fixture_path": str(directory),
                },
            )
        )
    )
    assert payload["verified"] is True
    assert "must not be presented as a dataset" in payload["note"]


# ── what the first live round trip corrected, 2026-09-14 ─────────────────────
#
# The EE round trip PASSED on its first run: 187 documents out, 187 back, keys,
# bodies and expiries identical. Everything below is a defect it found ANYWAY,
# in the index step, which the document comparison does not cover.
#
# That is the argument for running it rather than reasoning about it, stated
# with evidence: four bugs in code that had been read carefully twice.


def test_a_full_text_index_is_not_rendered_as_a_create_index(stub, tmp_path):
    """FOUND BY THE FIRST EE ROUND TRIP.

    system:indexes carries Search indexes too, with `using` of fts and NO
    index_key, and the exporter assembled one into

        CREATE INDEX `mcptest-fts` ON `travel-sample`.`_default`.`_default`()

    which the query service rejected: syntax error near '(', at: ). The tool
    generated invalid SQL from a row it had no business reading.
    """

    def rows(statement, parameters=None):
        if "system:indexes" in statement:
            return [
                {
                    "name": "mcptest-fts",
                    "bucket_id": "b",
                    "scope_id": "s",
                    "keyspace_id": "c",
                    "index_key": [],
                    "using": "fts",
                    "is_primary": False,
                }
            ]
        return stub.query(statement, parameters)

    definitions, warnings = _with_query(rows, lambda: fixture._index_definitions(set()))
    assert definitions == [], (
        "a full-text index was rendered as a CREATE INDEX statement"
    )
    assert any("not GSI" in w for w in warnings), warnings


def test_an_index_with_no_keys_that_is_not_primary_is_skipped_with_a_reason(stub):
    """The general form of the same defect: no keys means no renderable
    statement, and `()` is not a statement, it is a syntax error."""

    def rows(statement, parameters=None):
        if "system:indexes" in statement:
            return [
                {
                    "name": "weird",
                    "bucket_id": "b",
                    "scope_id": "s",
                    "keyspace_id": "c",
                    "index_key": [],
                    "using": "gsi",
                    "is_primary": False,
                }
            ]
        return stub.query(statement, parameters)

    definitions, warnings = _with_query(rows, lambda: fixture._index_definitions(set()))
    assert definitions == []
    assert any("no index keys" in w for w in warnings), warnings


def test_index_definitions_are_scoped_to_the_keyspaces_the_fixture_carries(stub):
    """FOUND BY THE FIRST EE ROUND TRIP.

    A fixture covering ONE collection recorded 23 index definitions across the
    whole bucket, and the import then attempted all 23. On that cluster they
    existed already; against a fresh target it would have built indexes for
    collections the fixture carries no data for.
    """

    def rows(statement, parameters=None):
        if "system:indexes" in statement:
            return [
                {
                    "name": "wanted",
                    "bucket_id": "b",
                    "scope_id": "s",
                    "keyspace_id": "c",
                    "index_key": ["`x`"],
                    "using": "gsi",
                },
                {
                    "name": "elsewhere",
                    "bucket_id": "b",
                    "scope_id": "other",
                    "keyspace_id": "c",
                    "index_key": ["`x`"],
                    "using": "gsi",
                },
            ]
        return stub.query(statement, parameters)

    definitions, _warnings = _with_query(
        rows, lambda: fixture._index_definitions({"b.s.c"})
    )
    assert [d["indexName"] for d in definitions] == ["wanted"]


def _with_query(replacement, call):
    """Run `call` with fixture._query replaced. A plain monkeypatch fixture would
    not reach these, which take the stub's query as a fallback."""
    original = fixture._query
    fixture._query = replacement
    try:
        return call()
    finally:
        fixture._query = original


def test_defer_build_is_merged_into_an_existing_with_clause():
    """FOUND BY THE FIRST EE ROUND TRIP, by inspection of the statement it sent.

    The check was `if " WITH " not in statement`, so an index that already
    carried a WITH clause -- exactly the ones with num_replica, the expensive
    ones -- got nothing appended and was built EAGERLY, while the importer went
    on to issue a BUILD INDEX for it.
    """
    from handlers import fixture_core

    statement, why = fixture_core.with_defer_build(
        'CREATE INDEX `i` ON `b`.`s`.`c`(a) WITH {"num_replica": 1}'
    )
    assert not why
    assert '"num_replica": 1' in statement, "the original options were dropped"
    assert '"defer_build": true' in statement


def test_an_unparseable_with_clause_is_refused_rather_than_rewritten():
    """Guessing at the shape of somebody's index options is how an index
    acquires a setting nobody asked for."""
    from handlers import fixture_core

    statement, why = fixture_core.with_defer_build(
        "CREATE INDEX `i` ON `b`.`s`.`c`(a) WITH {nodes: broken}"
    )
    assert why and "cannot parse" in why
    assert statement == "CREATE INDEX `i` ON `b`.`s`.`c`(a) WITH {nodes: broken}"


def test_a_keyspace_map_that_changes_only_the_scope_rewrites_the_index():
    """FOUND BY THE FIRST EE ROUND TRIP, and the worst of the four.

    The import mapped travel-sample.inventory.airline to
    travel-sample.roundtrip.airline -- same bucket, different scope. The rewrite
    substituted the BUCKET only, replacing travel-sample with travel-sample, so
    every statement still named inventory.airline. On that cluster the indexes
    already existed there and it reported "already exists"; against a FRESH
    target it would have built the fixture's indexes on the SOURCE collection
    and left the imported one with none, reporting ok either way.
    """
    from handlers import fixture_core

    statement, why = fixture_core.rewrite_index_keyspace(
        "CREATE INDEX `i` ON `travel-sample`.`inventory`.`airline`(a)",
        {"travel-sample.inventory.airline": "travel-sample.roundtrip.airline"},
    )
    assert not why
    assert "`travel-sample`.`roundtrip`.`airline`" in statement
    assert "inventory" not in statement


def test_an_index_on_a_keyspace_the_map_says_nothing_about_is_left_alone():
    """Rewriting it would be inventing an instruction. It is not this call's
    business, and it must not be refused either -- a refusal would report a
    problem where there is none."""
    from handlers import fixture_core

    statement, why = fixture_core.rewrite_index_keyspace(
        "CREATE INDEX `i` ON `travel-sample`.`inventory`.`route`(a)",
        {"travel-sample.inventory.airline": "travel-sample.roundtrip.airline"},
    )
    assert not why
    assert statement == "CREATE INDEX `i` ON `travel-sample`.`inventory`.`route`(a)"


def test_a_bucket_only_index_follows_an_unambiguous_bucket_rename():
    """The index is on the bucket's default collection and stays there.

    Nothing is guessed: every mapping under the bucket agrees on the target, and
    the collection does not change. Refusing this would report a problem where
    there is none -- which is its own kind of wrong answer.
    """
    from handlers import fixture_core

    statement, why = fixture_core.rewrite_index_keyspace(
        "CREATE PRIMARY INDEX `p` ON `travel-sample`",
        {"travel-sample.inventory.airline": "scratch.inventory.airline"},
    )
    assert not why
    assert statement == "CREATE PRIMARY INDEX `p` ON `scratch`"


def test_a_bucket_only_index_is_refused_when_the_bucket_has_two_targets():
    """THE case that is genuinely undecidable: the map sends one source bucket
    to two different targets, so which one this index belongs to cannot be read
    off the statement."""
    from handlers import fixture_core

    statement, why = fixture_core.rewrite_index_keyspace(
        "CREATE PRIMARY INDEX `p` ON `src`",
        {"src.s.c1": "one.s.c1", "src.s.c2": "two.s.c2"},
    )
    assert why and "more than one target" in why
    assert statement == "CREATE PRIMARY INDEX `p` ON `src`"


def test_only_the_on_target_is_rewritten_not_every_mention_of_the_bucket():
    """A bucket name can appear in a WHERE clause or an index key expression,
    and rewriting every occurrence rewrites those too."""
    from handlers import fixture_core

    statement, why = fixture_core.rewrite_index_keyspace(
        "CREATE INDEX `i` ON `b`.`s`.`c`(`name`) WHERE `name` = 'b'",
        {"b.s.c": "target.s.c"},
    )
    assert not why
    assert statement.startswith("CREATE INDEX `i` ON `target`.`s`.`c`")
    assert "= 'b'" in statement, "a literal that happened to match was rewritten"
