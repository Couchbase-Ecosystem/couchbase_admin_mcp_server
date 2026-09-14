"""handlers/fixture.py — fixtures on Enterprise Edition (`admin_fixture_*`).

WHAT A FIXTURE IS, AND WHY EE WANTS ONE
=======================================
A fixture is a named, tagged, hash-verified capture of a dataset: a manifest
plus one JSON Lines file per keyspace, carrying structure, index definitions,
eventing functions and document bodies with their expiry.

The Capella argument for fixtures is that Capella backups cannot be named, carry
no metadata and cannot be moved between clusters on demand. **That argument does
not apply here** — `cbbackupmgr` is a real backup tool with real restore
semantics, on every EE node. The EE argument is a different one:

    cbbackupmgr answers RECOVERY. A fixture answers REPRODUCIBILITY.

"The exact dataset scenario 1.6 was measured against, tagged as such, diffable,
and loadable into a cluster that is not the one it came from" is not a backup
question, and a binary backup is a poor artifact for it. That is the need this
family serves, and `docs/FIXTURE_DESIGN.md` records the decision and the
argument against it.

THIS IS A SECOND IMPLEMENTATION, NOT A PORT
===========================================
The design note is explicit about this and it is the thing most likely to be
underestimated. Capella reaches documents through the Data API: a control-plane
call to discover a connection string, an HTTP Basic cluster access credential,
and an IP allowlist governing it. Enterprise Edition has none of those three.
Here the query service is simply present, reached with the cluster credentials
this server already holds, and documents are written over KV through the SDK.

So the transport is different, the credential is different, and the structure
walk goes through ns_server's REST API rather than v4 operations.

WHAT IS *NOT* DIFFERENT lives in `handlers/fixture_core.py`: the manifest schema,
the integrity check, fixture-root containment, keyspace splitting, the export
statement and the metadata aliases. Those are shared deliberately and the
sharing is asserted by `tests/test_fixture_core_is_plane_neutral.py`, because a
fixture captured here and imported into Capella — capture on a laptop, import
into the cloud, compare like for like — only works if both sides agree byte for
byte on what the manifest means.

THE HONEST STATUS
=================
**Written 2026-09-14. NOT YET RUN AGAINST A LIVE ENTERPRISE EDITION CLUSTER.**

That matters more than usual here, because of what the Capella round trip found.
Export, import into a scratch keyspace, export back, compare: 187 of 188 keys
differed while zero document bodies did, and nothing else had caught it — not
per-file hashes, not line counts, not a `COUNT(*)` on the cluster. Every one of
those compares a fixture against itself.

So until an EE round trip has been run, this module is carefully written code
and not a verified capability, and anything it reports about a cluster should be
confirmed with `admin_fixture_verify` rather than believed.

WHAT THIS DOES NOT PRESERVE
===========================
Stated up front, because a fixture that silently drops something is worse than
one that refuses:

  * **CAS.** Not settable through any supported write path. A document restored
    from a fixture is a new mutation with a new CAS.
  * **System xattrs**, including `_sync`. `META().xattrs` is not enumerable —
    only NAMED attributes are selectable — so anything the caller does not list
    in `user_xattrs` is dropped, and the manifest records which were asked for.
    A mobile-synced dataset is not faithfully captured by this module.
  * **Point-in-time consistency.** Export pages through a collection by key
    range; it does not snapshot. Run it against a quiesced cluster or accept
    that a concurrent mutation may land on either side of the cursor.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from datetime import datetime, timedelta, timezone
from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

from handlers.fixture_core import (
    MANIFEST_SCHEMA,
    META_EXP_ALIAS,
    META_ID_ALIAS,
    export_statement,
    fixture_integrity,
    read_manifest,
    resolve_under_root,
    rewrite_index_keyspace,
    schema_problem,
    sha256_file,
    split_keyspace,
    strip_index_nodes,
)
from handlers.shared import admin_request, err, get_sdk_connection, ok
from logging_config import get_logger

_log = get_logger("handlers.fixture")

#: The plane recorded in every manifest this module writes. A reader that needs
#: to know where a fixture came from reads this; nothing GATES on it, which is
#: the point of a neutral schema.
_PLANE = "enterprise"

#: Eventing lives behind the cluster manager's proxy prefix, like Search and
#: Backup. See CLAUDE.md section 2.3: nine Search tools once shipped with bare
#: paths and 404'd against every cluster.
_EVENTING_BASE = "/_p/event/api/v1"

#: READ-ONLY WITH RESPECT TO THE CLUSTER, and that is what the hint governs.
#:
#: admin_fixture_export carries readOnlyHint=True and WRITES FILES. The same
#: decision was taken and recorded on the Capella side: in this server
#: readOnlyHint is not documentation, server.py uses it to decide which tools
#: LOAD in read-only mode, and read-only mode exists to protect the CLUSTER.
#: Flipping it would remove fixture export from exactly the deployment that most
#: wants it — a read-only forensic posture where capturing what a cluster looks
#: like is the whole job. The filesystem write is stated in the tool's own
#: description instead, and CB_ADMIN_FIXTURE_ROOT bounds it.
_READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)
_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False
)

_TAGS_SCHEMA = {
    "type": "object",
    "description": (
        "Free-form scenario metadata, recorded verbatim in the manifest and the "
        "basis for all fixture filtering. This is what makes a fixture findable "
        'six months later. Example: {"scenario": "Notification Center '
        'Hurricane", "version": "1.1"}'
    ),
    "additionalProperties": {"type": "string"},
}


TOOLS: list[Tool] = [
    Tool(
        name="admin_fixture_export",
        description=(
            "Export a named, tagged fixture from a self-managed Couchbase cluster: "
            "structure, GSI definitions, eventing functions, and document bodies "
            "with their expiry. Writes a manifest plus JSON Lines payload to "
            "fixture_path.\n\n"
            "NOT A BACKUP, and not a replacement for cbbackupmgr. Export iterates "
            "rather than snapshotting, so it is not point-in-time consistent — run "
            "it against a quiesced cluster. CAS is not preserved. System xattrs "
            "(including _sync) are not readable, so a mobile-synced dataset is not "
            "faithfully captured.\n\n"
            "A fixture answers REPRODUCIBILITY — the exact dataset a scenario was "
            "measured against, tagged, diffable, and loadable into a different "
            "cluster. Use cbbackupmgr for recovery.\n\n"
            "Every collection exported needs an index that can serve "
            "`WHERE META().id > $k ORDER BY META().id`. A collection with no index "
            "at all cannot be read by SQL++ and the export refuses, naming it. "
            "This tool will NOT create one: building an index on somebody's "
            "cluster is a capacity decision, not a side effect of reading.\n\n"
            "WRITES TO THE LOCAL FILESYSTEM. Annotated read-only, which is true of "
            "the CLUSTER and not of the disk. Set CB_ADMIN_FIXTURE_ROOT to confine "
            "where it can write."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "fixture_id": {
                    "type": "string",
                    "description": "Stable identifier for this fixture, recorded "
                                   "in the manifest.",
                },
                "fixture_path": {
                    "type": "string",
                    "description": "Directory to write the fixture into. Created "
                                   "if absent. Must sit under "
                                   "CB_ADMIN_FIXTURE_ROOT when that is set.",
                },
                "name": {"type": "string", "description": "Human-readable name."},
                "tags": _TAGS_SCHEMA,
                "include_data": {
                    "type": "boolean",
                    "default": True,
                    "description": "False writes a STRUCTURE-ONLY fixture: "
                                   "buckets, scopes, collections, index "
                                   "definitions and eventing functions, with no "
                                   "documents. A complete artifact in its own "
                                   "right — it just is not a dataset, and the "
                                   "manifest's fidelity block says so.",
                },
                "keyspaces": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Restrict to these bucket.scope.collection "
                                   "keyspaces. A name that matches nothing is an "
                                   "ERROR, not a silent empty export.",
                },
                "user_xattrs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "User xattrs to carry, BY NAME. META().xattrs "
                                   "is not enumerable, so anything not listed "
                                   "here is dropped silently by the server — the "
                                   "manifest records what was asked for.",
                },
                "page_size": {
                    "type": "integer",
                    "default": 1000,
                    "description": "Documents per key-range page.",
                },
            },
            "required": ["fixture_id", "fixture_path"],
        },
        annotations=_READ,
    ),
    Tool(
        name="admin_fixture_import",
        description=(
            "Load a fixture into a self-managed cluster: scopes and collections, "
            "then documents, then GSI indexes built and polled to online.\n\n"
            "REFUSES BEFORE IT TOUCHES THE CLUSTER if the fixture does not verify "
            "— every recorded hash is recomputed from the bytes on disk first. A "
            "fixture whose files have changed since it was written is not a "
            "fixture, and finding that out after creating three collections is "
            "finding out too late.\n\n"
            "Does NOT create buckets. A bucket is a memory-quota decision on a "
            "cluster somebody else sized, and creating one as a side effect of an "
            "import is how a node starts swapping. Create the bucket with "
            "admin_bucket_create first, or pass keyspace_map to load into one "
            "that exists.\n\n"
            "Documents are written over KV, which means an existing document with "
            "the same key is REPLACED. Partial success is a normal outcome and is "
            "reported per step and per keyspace rather than collapsed into one "
            "status."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "fixture_path": {
                    "type": "string",
                    "description": "The fixture directory, or its manifest.json.",
                },
                "keyspace_map": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Rewrite source keyspaces to targets, e.g. "
                                   '{"travel-sample.inventory.airline": '
                                   '"scratch.inventory.airline"}. Values must be '
                                   "strings; a nested object is refused.",
                },
                "create_indexes": {
                    "type": "boolean",
                    "default": True,
                    "description": "Recreate the fixture's GSI definitions. Built "
                                   "deferred, then BUILD INDEX per keyspace, then "
                                   "polled to online — an index that exists but is "
                                   "not online makes the cluster look slow in a "
                                   "way that reads as a Couchbase problem.",
                },
                "confirm": {
                    "type": "boolean",
                    "description": "Required. This writes to a cluster.",
                },
            },
            "required": ["fixture_path", "confirm"],
        },
        annotations=_DESTRUCTIVE,
    ),
    Tool(
        name="admin_fixture_list",
        description=(
            "List fixtures under a directory, with their tags, and optionally "
            "filter by tag. Pure filesystem work — it talks to no cluster.\n\n"
            "A fixture whose manifest will not parse is REPORTED, never skipped. "
            "A listing that quietly omits an unreadable fixture answers 'what do I "
            "have' with a confident lie."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "root_path": {
                    "type": "string",
                    "description": "Directory to scan. Each immediate "
                                   "subdirectory holding a manifest.json is one "
                                   "fixture.",
                },
                "tags": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Return only fixtures whose tags match ALL of "
                                   "these exactly.",
                },
            },
            "required": ["root_path"],
        },
        annotations=_READ,
    ),
    Tool(
        name="admin_fixture_verify",
        description=(
            "Verify a fixture: every file named in the manifest exists, every "
            "recorded hash recomputes, every line count agrees, and the payload "
            "hash recomputes over the per-file hashes.\n\n"
            "With check_cluster=true it additionally counts the documents present "
            "on the CLUSTER for each keyspace and compares. That second check is "
            "the one that catches a half-finished import; the first only proves "
            "the fixture on disk is intact.\n\n"
            "A MISMATCH IS NOT A WARNING. A fixture whose bytes have changed since "
            "it was written is not a fixture, it is an unlabelled dataset."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "fixture_path": {"type": "string"},
                "check_cluster": {
                    "type": "boolean",
                    "default": False,
                    "description": "Also count documents on the cluster per "
                                   "keyspace and compare with the manifest.",
                },
                "keyspace_map": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Apply the same rewrite an import used, so the "
                                   "cluster check looks where the data actually "
                                   "went.",
                },
            },
            "required": ["fixture_path"],
        },
        annotations=_READ,
    ),
]

TOOL_NAMES = frozenset(t.name for t in TOOLS)


# ── cluster reads ────────────────────────────────────────────────────────────


def _query(statement: str, parameters: dict | None = None) -> list[dict]:
    """Run a SQL++ statement through the SDK and return its rows.

    THE SDK, NOT THE REST ENDPOINT. The query service is reachable over HTTP at
    :18093 and through the cluster manager's proxy, but the SDK is what every
    other SQL++ tool in this server already uses, it carries the same credential
    and TLS configuration, and it handles node selection. A second transport for
    the same statements would be a second place for the connection semantics to
    differ.
    """
    from couchbase.options import QueryOptions

    cluster, _bucket, _collection = get_sdk_connection()
    options = QueryOptions(named_parameters=parameters) if parameters else QueryOptions()
    return list(cluster.query(statement, options))


def _cluster_identity() -> dict:
    """What a manifest records about WHERE a fixture came from.

    Not decoration. A fixture is meaningless six months later if nobody can say
    which cluster it was taken from, and on a self-managed cluster there is no
    organization or project id to name one — so the cluster's own UUID and the
    node list are what identify it.
    """
    identity: dict[str, Any] = {"plane": _PLANE}
    try:
        pools = admin_request("GET", "/pools")
        if isinstance(pools, dict):
            identity["cluster_uuid"] = pools.get("uuid")
            identity["implementation_version"] = pools.get("implementationVersion")
    except Exception as exc:
        identity["cluster_uuid_error"] = str(exc)
    try:
        default = admin_request("GET", "/pools/default")
        if isinstance(default, dict):
            identity["cluster_name"] = default.get("clusterName")
            identity["nodes"] = [
                node.get("hostname")
                for node in (default.get("nodes") or [])
                if isinstance(node, dict)
            ]
    except Exception as exc:
        identity["cluster_name_error"] = str(exc)
    return identity


def _structure(wanted_buckets: set[str]) -> tuple[list[dict], list[str]]:
    """(structure, warnings) — buckets, their settings, scopes and collections.

    A bucket whose scopes cannot be read is recorded WITH the reason rather than
    dropped. A structure that silently omits a bucket produces a fixture that
    claims to describe a cluster and does not.
    """
    warnings: list[str] = []
    structure: list[dict] = []

    try:
        buckets = admin_request("GET", "/pools/default/buckets")
    except Exception as exc:
        raise RuntimeError(f"could not list buckets: {exc}") from exc
    if not isinstance(buckets, list):
        raise RuntimeError(
            f"/pools/default/buckets returned {type(buckets).__name__}, not a "
            f"list. This is the shape the rest of the walk depends on."
        )

    for bucket in buckets:
        if not isinstance(bucket, dict):
            warnings.append(f"a bucket entry is not an object: {bucket!r}")
            continue
        name = bucket.get("name")
        if wanted_buckets and name not in wanted_buckets:
            continue
        quota = (bucket.get("quota") or {}).get("rawRAM")
        record: dict[str, Any] = {
            "name": name,
            "settings": {
                "bucketType": bucket.get("bucketType"),
                "storageBackend": bucket.get("storageBackend"),
                "ramQuotaMB": int(quota / (1024 * 1024)) if quota else None,
                "replicaNumber": bucket.get("replicaNumber"),
                "conflictResolutionType": bucket.get("conflictResolutionType"),
                "evictionPolicy": bucket.get("evictionPolicy"),
                "maxTTL": bucket.get("maxTTL"),
                "durabilityMinLevel": bucket.get("durabilityMinLevel"),
            },
            "scopes": [],
        }
        record["settings"] = {
            k: v for k, v in record["settings"].items() if v is not None
        }
        try:
            payload = admin_request("GET", f"/pools/default/buckets/{name}/scopes")
        except Exception as exc:
            warnings.append(f"scopes for bucket {name} could not be read: {exc}")
            payload = {}
        for scope in (payload or {}).get("scopes") or []:
            record["scopes"].append({
                "name": scope.get("name"),
                "collections": [
                    {"name": c.get("name"), "maxTTL": c.get("maxTTL")}
                    for c in (scope.get("collections") or [])
                ],
            })
        structure.append(record)
    return structure, warnings


def _index_definitions(buckets: list[str]) -> tuple[list[dict], list[str]]:
    """GSI definitions from `system:indexes`, in the manifest's shape.

    The Capella side reads these from a v4 endpoint that returns a rendered
    `definition` string per index. `system:indexes` does not: it returns the
    index's parts. So the CREATE INDEX statement is assembled here, and the two
    planes produce the same manifest field from different sources — which is the
    whole reason the manifest is plane-neutral and the transports are not.
    """
    warnings: list[str] = []
    rows: list[dict] = []
    try:
        rows = _query(
            "SELECT name, keyspace_id, bucket_id, scope_id, index_key, `condition`, "
            "`using`, is_primary, state, num_replica "
            "FROM system:indexes"
        )
    except Exception as exc:
        warnings.append(f"index definitions could not be read: {exc}")
        return [], warnings

    definitions: list[dict] = []
    for row in rows:
        # system:indexes names the keyspace in one of two shapes depending on
        # whether the index is on a collection or on a bucket's default
        # collection: bucket_id/scope_id/keyspace_id for the former, and
        # keyspace_id alone naming the BUCKET for the latter. Reading only one
        # of them silently loses every index of the other kind.
        bucket = row.get("bucket_id") or row.get("keyspace_id")
        scope = row.get("scope_id") or "_default"
        collection = row.get("keyspace_id") if row.get("bucket_id") else "_default"
        if buckets and bucket not in buckets:
            continue

        keyspace = f"{bucket}.{scope}.{collection}"
        quoted = f"`{bucket}`.`{scope}`.`{collection}`"
        name = row.get("name")
        if row.get("is_primary"):
            statement = f"CREATE PRIMARY INDEX `{name}` ON {quoted}"
        else:
            keys = ", ".join(str(k) for k in (row.get("index_key") or []))
            statement = f"CREATE INDEX `{name}` ON {quoted}({keys})"
            if row.get("condition"):
                statement += f" WHERE {row['condition']}"
        with_clause = {}
        if row.get("num_replica"):
            with_clause["num_replica"] = row["num_replica"]
        if with_clause:
            statement += " WITH " + json.dumps(with_clause)

        definitions.append({
            "indexName": name,
            "keyspace": keyspace,
            "definition": statement,
            "state": row.get("state"),
            "using": row.get("using"),
        })
    return definitions, warnings


def _eventing_functions() -> tuple[list[dict], list[str]]:
    """Eventing functions, or a warning saying why not.

    A cluster with no Eventing service answers 404 here, and that is NOT an
    error: it is a cluster without the service. Reporting it as a failure would
    make every export against a Data-and-Query cluster look broken.
    """
    try:
        payload = admin_request("GET", f"{_EVENTING_BASE}/functions")
    except Exception as exc:
        text = str(exc)
        if "404" in text:
            return [], []
        return [], [f"eventing functions could not be read: {exc}"]
    if isinstance(payload, list):
        return payload, []
    return [], [f"eventing functions returned {type(payload).__name__}, not a list"]


# ── export ───────────────────────────────────────────────────────────────────


def _export(args: dict) -> list[TextContent]:
    """Export a fixture from a self-managed cluster.

    ORDER, and why: structure first because it is cheap and it bounds everything
    after it; indexes and eventing next because they are metadata; documents
    last because they are the expensive part and the part that can fail halfway.

    The manifest is written ONLY at the end. A partial payload file is left on
    disk deliberately, so the failure can be inspected — but with no manifest
    beside it, nothing downstream can mistake the directory for a fixture.
    """
    tool = "admin_fixture_export"
    fixture_id = str(args.get("fixture_id") or "").strip()
    if not fixture_id:
        return err("fixture_id is required", tool=tool)

    try:
        root = resolve_under_root(
            args.get("fixture_path"), field="fixture_path", tool=tool
        )
    except ValueError as exc:
        return err(str(exc), tool=tool)

    include_data = bool(args.get("include_data", True))
    page_size = int(args.get("page_size") or 1000)
    xattrs = [str(x) for x in (args.get("user_xattrs") or [])]
    wanted_keyspaces = {str(k) for k in (args.get("keyspaces") or []) if k}
    wanted_buckets = {k.split(".")[0] for k in wanted_keyspaces}

    started = datetime.now(timezone.utc)
    try:
        structure, warnings = _structure(wanted_buckets)
    except RuntimeError as exc:
        return err(str(exc), tool=tool)

    index_defs, index_warnings = _index_definitions(sorted(wanted_buckets))
    warnings.extend(index_warnings)
    eventing, eventing_warnings = _eventing_functions()
    warnings.extend(eventing_warnings)

    data_files: list[dict] = []
    document_total = 0
    documents_ok = False
    matched: set[str] = set()

    if include_data:
        data_dir = root / "data"
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return err(f"could not create {data_dir}: {exc}", tool=tool)

        for bucket in structure:
            for scope in bucket["scopes"]:
                scope_name = scope["name"]
                # Reserved scopes are Couchbase's own (`_system`, `%` prefixed).
                # They are not the customer data a fixture is for, and the query
                # service refuses some of them outright.
                if str(scope_name).startswith(("_", "%")) and scope_name != "_default":
                    continue
                for collection in scope["collections"]:
                    keyspace = f"{bucket['name']}.{scope_name}.{collection['name']}"
                    if wanted_keyspaces:
                        if keyspace not in wanted_keyspaces:
                            continue
                        matched.add(keyspace)

                    statement = export_statement(
                        bucket["name"], scope_name, collection["name"],
                        page_size=page_size, user_xattrs=xattrs,
                    )
                    target = data_dir / f"{keyspace}.jsonl"
                    written, failure = _export_keyspace(
                        statement, target, keyspace, page_size
                    )
                    if failure:
                        return err(
                            f"export failed on {keyspace} after {written} "
                            f"document(s): {failure}\n"
                            f"The partial file was left at {target} so it can be "
                            f"inspected; the manifest was NOT written, so nothing "
                            f"downstream will mistake this for a complete fixture.",
                            tool=tool,
                        )
                    if written == 0:
                        # An empty collection is legitimate. The file goes, so the
                        # manifest does not name a data file holding nothing --
                        # which reads as a failed export.
                        target.unlink(missing_ok=True)
                        continue
                    data_files.append({
                        "path": f"data/{target.name}",
                        "keyspace": keyspace,
                        "sha256": sha256_file(target),
                        "document_count": written,
                    })
                    document_total += written

        unmatched = sorted(wanted_keyspaces - matched)
        if unmatched:
            return err(
                f"these keyspaces were requested and do not exist on this "
                f"cluster: {unmatched}\n"
                f"Nothing was written. A keyspace filter that matches nothing "
                f"would otherwise produce a clean-looking export of zero "
                f"documents -- the caller names a keyspace, gets a fixture "
                f"without it, and nothing says so.\n"
                f"The filter takes bucket.scope.collection, not a bare "
                f"collection name.",
                tool=tool,
                requested=sorted(wanted_keyspaces),
                matched=sorted(matched),
            )
        documents_ok = True

    finished = datetime.now(timezone.utc)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "fixture_id": fixture_id,
        "name": args.get("name") or fixture_id,
        "mode": "server",
        "created_at": finished.isoformat().replace("+00:00", "Z"),
        "export_started_at": started.isoformat().replace("+00:00", "Z"),
        "export_finished_at": finished.isoformat().replace("+00:00", "Z"),
        "source": _cluster_identity(),
        "tags": args.get("tags") or {},
        "structure": structure,
        "gsi_definitions": index_defs,
        "eventing_functions": eventing,
        "files": data_files,
        "document_count": document_total,
        "payload_sha256": hashlib.sha256(
            "".join(sorted(f["sha256"] for f in data_files)).encode()
        ).hexdigest() if data_files else None,
        "user_xattrs": xattrs,
        # FIDELITY IS WHAT ACTUALLY HAPPENED, not what was asked for. This is the
        # single most important field in the manifest: it is what stops a
        # consumer mistaking a shape fixture for a dataset.
        "fidelity": {
            # NOT documents_ok. That means "the document phase ran without
            # failing", which an export of only-empty collections also satisfies
            # while a consumer reads it as "this fixture contains documents".
            "documents": documents_ok and document_total > 0,
            "structure": True,
            "gsi_definitions": not index_warnings,
            "eventing_functions": not eventing_warnings,
            "search_definitions": False,
            "xattrs": bool(xattrs) and documents_ok,
            "cas": False,
            "system_xattrs": False,
            "note": _fidelity_note(documents_ok, document_total, include_data),
        },
        "warnings": warnings,
    }
    try:
        root.mkdir(parents=True, exist_ok=True)
        (root / "manifest.json").write_text(
            json.dumps(manifest, indent=1), encoding="utf-8"
        )
    except OSError as exc:
        return err(f"could not write the manifest: {exc}", tool=tool)

    return ok({
        "fixture_path": str(root),
        "fixture_id": fixture_id,
        "documents": document_total,
        "keyspaces": [f["keyspace"] for f in data_files],
        "gsi_definitions": len(index_defs),
        "eventing_functions": len(eventing),
        "fidelity": manifest["fidelity"],
        "warnings": warnings,
    })


def _fidelity_note(documents_ok: bool, total: int, include_data: bool) -> str:
    if not include_data:
        return (
            "Structure-only export. This fixture describes a SHAPE, not a "
            "dataset: buckets, scopes, collections, index definitions and "
            "eventing functions, with no documents."
        )
    if documents_ok and total == 0:
        return (
            "include_data was requested and every keyspace exported was EMPTY, "
            "so this fixture contains no documents. It is a faithful export of "
            "an empty dataset, which is a legitimate thing to have and is NOT a "
            "dataset: fidelity.documents is false for that reason, not because "
            "anything failed."
        )
    return (
        "Documents exported over the query service. CAS is NOT preserved -- a "
        "document loaded from this fixture is a new mutation. System xattrs, "
        "including _sync, are NOT captured, so a mobile-synced dataset is not "
        "faithfully represented here. Search index definitions are not present."
    )


def _export_keyspace(statement: str, target: pathlib.Path, keyspace: str,
                     page_size: int) -> tuple[int, str]:
    """(documents written, failure). Pages one collection into a JSON Lines file.

    An unindexed collection is a PRECONDITION FAILURE, not a bug, and it is the
    first thing a real export hits: the key-range page is a SELECT with a WHERE,
    and SQL++ needs an index to serve one.
    """
    last_key = ""
    written = 0
    try:
        with target.open("w", encoding="utf-8") as handle:
            while True:
                rows = _query(statement, {"last_key": last_key})
                if not rows:
                    break
                for row in rows:
                    doc_id = row.pop(META_ID_ALIAS, None)
                    expiry = row.pop(META_EXP_ALIAS, 0)
                    prefix = "__fixture_xattr_"
                    carried = {
                        key[len(prefix):]: row.pop(key)
                        for key in list(row)
                        if key.startswith(prefix)
                    }
                    if doc_id is None:
                        # The alias did not survive, which can only mean a
                        # document field of the same name overwrote it. Refuse
                        # rather than record a key that is not the key -- the
                        # exact failure these aliases exist to prevent, and the
                        # one that shipped undetected on the Capella side.
                        return written, (
                            f"a document in {keyspace} has no {META_ID_ALIAS}: a "
                            f"field of that name in the document overwrote the "
                            f"metadata alias, so its real key cannot be "
                            f"recovered. Nothing further was written."
                        )
                    handle.write(json.dumps({
                        "id": doc_id,
                        "exp": expiry,
                        "doc": row,
                        "xattrs": carried,
                    }) + "\n")
                    written += 1
                    last_key = doc_id or last_key
                if len(rows) < page_size:
                    break
    except Exception as exc:
        text = str(exc)
        remedy = ""
        if "No index available" in text or "4000" in text:
            remedy = (
                f"\nTHE COLLECTION HAS NO INDEX. Create one and re-run:\n"
                f"  CREATE PRIMARY INDEX ON `{keyspace}`\n"
                f"A primary index is the general answer and it is not free -- it "
                f"indexes every key in the collection. On a large collection "
                f"prefer an existing secondary index that covers META().id, or "
                f"create the primary index, export, and drop it again. This tool "
                f"will NOT create one for you: building an index on somebody's "
                f"cluster is a capacity decision, not a side effect of reading."
            )
        return written, text + remedy
    return written, ""


# ── import ───────────────────────────────────────────────────────────────────


def _import(args: dict) -> list[TextContent]:
    """Load a fixture into a self-managed cluster.

    ORDER OF OPERATIONS, and why this order:

      1. Integrity FIRST, before a single call to the cluster. Every recorded
         hash is recomputed from the bytes on disk.
      2. Structure: scopes and collections. NOT buckets -- see the tool
         description; a bucket is a memory-quota decision on a cluster somebody
         else sized.
      3. Documents, then indexes. Documents first is deliberate: building an
         index over a populated collection is one pass, while loading into an
         already-built index pays the maintenance cost on every batch.
      4. Indexes deferred, then one BUILD INDEX per keyspace, then polled.

    PARTIAL SUCCESS IS A NORMAL OUTCOME and is reported per step and per
    keyspace. It is never collapsed into a single status: "it failed" tells an
    operator nothing about whether the documents landed.

    NOT YET RUN AGAINST A LIVE CLUSTER. Confirm what it reports with
    admin_fixture_verify --check_cluster, which recounts independently rather
    than believing this tool's own report.
    """
    tool = "admin_fixture_import"
    try:
        directory = resolve_under_root(
            args.get("fixture_path"), field="fixture_path", tool=tool
        )
    except ValueError as exc:
        return err(str(exc), tool=tool)
    if directory.name == "manifest.json":
        directory = directory.parent

    entry = read_manifest(directory)
    if not entry.get("readable"):
        return err(entry.get("error", "manifest could not be read"),
                   tool=tool, fixture_path=str(directory))
    manifest = entry["manifest"]

    why = schema_problem(manifest.get("schema"))
    if why:
        return err(why.replace("verifiable", "importable"),
                   tool=tool, fixture_path=str(directory))

    if manifest.get("mode") == "mobile":
        return err(
            "this is a MOBILE fixture and its sync metadata cannot be restored "
            "by this tool. Loading it would produce documents that look synced "
            "and are not, which is worse than not loading them.",
            tool=tool, fixture_path=str(directory),
        )

    checks, problems, _payload = fixture_integrity(directory, manifest)
    if problems:
        return err(
            "the fixture does not verify, so NOTHING was imported:\n  - "
            + "\n  - ".join(problems)
            + "\nRun admin_fixture_verify for the full report. A fixture whose "
              "bytes have changed since it was written is not a fixture, and "
              "importing one would put unlabelled data on a cluster.",
            tool=tool, fixture_path=str(directory), files_checked=checks,
        )

    keyspace_map = args.get("keyspace_map") or {}
    if not isinstance(keyspace_map, dict):
        return err("keyspace_map must be an object", tool=tool)
    nested = sorted(k for k, v in keyspace_map.items() if not isinstance(v, str))
    if nested:
        return err(
            f"keyspace_map values must be strings naming a target keyspace; "
            f"{nested} are not. A dotted argument name can produce a nested "
            f"object by accident -- pass the map as JSON.",
            tool=tool,
        )

    steps: dict[str, Any] = {}
    steps["structure"] = _import_structure(manifest, keyspace_map)
    steps["documents"] = _import_documents(directory, manifest, keyspace_map)
    if args.get("create_indexes", True):
        steps["indexes"] = _import_indexes(manifest, keyspace_map)
    else:
        steps["indexes"] = {"skipped": "create_indexes was false"}

    return ok({
        "fixture_path": str(directory),
        "fixture_id": manifest.get("fixture_id"),
        "steps": steps,
        "note": (
            "Counts here are what THIS TOOL believes it wrote. Confirm them "
            "with admin_fixture_verify check_cluster=true, which recounts on "
            "the cluster rather than trusting this report."
        ),
    })


def _import_structure(manifest: dict, keyspace_map: dict) -> dict:
    """Create the scopes and collections the fixture's data files need.

    Only what the DATA needs, not the whole recorded structure. A fixture may
    describe a cluster with forty collections and carry documents for two;
    creating the other thirty-eight would be this tool inventing work nobody
    asked for on somebody's cluster.
    """
    created_scopes: list[str] = []
    created_collections: list[str] = []
    existing: list[str] = []
    failures: list[str] = []

    for record in manifest.get("files") or []:
        source = str(record.get("keyspace") or "")
        target = str(keyspace_map.get(source) or source)
        parts = split_keyspace(target)
        if not parts:
            failures.append(f"{target!r} is not bucket.scope.collection")
            continue
        bucket, scope, collection = parts

        try:
            payload = admin_request("GET", f"/pools/default/buckets/{bucket}/scopes")
        except Exception as exc:
            failures.append(
                f"{target}: bucket {bucket!r} could not be read ({exc}). This "
                f"tool does not create buckets -- create it with "
                f"admin_bucket_create, or point keyspace_map at one that exists."
            )
            continue

        scopes = {s.get("name"): s for s in (payload or {}).get("scopes") or []}
        if scope not in scopes:
            try:
                admin_request(
                    "POST", f"/pools/default/buckets/{bucket}/scopes",
                    data={"name": scope},
                )
                created_scopes.append(f"{bucket}.{scope}")
            except Exception as exc:
                failures.append(f"{target}: scope {scope!r} could not be created: {exc}")
                continue
            collections_present: set[str] = set()
        else:
            collections_present = {
                c.get("name") for c in (scopes[scope].get("collections") or [])
            }

        if collection in collections_present:
            existing.append(target)
            continue
        body: dict[str, Any] = {"name": collection}
        max_ttl = _recorded_max_ttl(manifest, source)
        if max_ttl is not None:
            body["maxTTL"] = int(max_ttl)
        try:
            admin_request(
                "POST",
                f"/pools/default/buckets/{bucket}/scopes/{scope}/collections",
                data=body,
            )
            created_collections.append(target)
        except Exception as exc:
            failures.append(
                f"{target}: collection {collection!r} could not be created: {exc}"
            )

    return {
        "scopes_created": created_scopes,
        "collections_created": created_collections,
        "already_present": existing,
        "failures": failures,
        "ok": not failures,
    }


def _recorded_max_ttl(manifest: dict, keyspace: str) -> int | None:
    """The maxTTL the fixture recorded for a keyspace, if it recorded one.

    Carried because a collection's TTL is part of the scenario: a dataset whose
    documents expire after an hour behaves differently from one whose documents
    do not, and a fixture that silently drops it reproduces the wrong thing.
    """
    parts = split_keyspace(keyspace)
    if not parts:
        return None
    bucket, scope, collection = parts
    for record in manifest.get("structure") or []:
        if record.get("name") != bucket:
            continue
        for recorded_scope in record.get("scopes") or []:
            if recorded_scope.get("name") != scope:
                continue
            for recorded in recorded_scope.get("collections") or []:
                if recorded.get("name") == collection:
                    value = recorded.get("maxTTL")
                    return int(value) if isinstance(value, int) else None
    return None


def _import_documents(directory: pathlib.Path, manifest: dict,
                      keyspace_map: dict) -> dict:
    """Write every document over KV.

    KV, NOT SQL++. Two reasons, and the second is the load-bearing one:

      1. A mutating SQL++ statement embedded in a handler is refused by
         tests/test_no_handler_embeds_a_mutating_sql_statement, and rightly --
         this server's SQL++ surface is read-guarded.
      2. UPSERT through the query service goes key by key through a second
         service for something KV does natively, and it cannot set an expiry
         per document without more statement text. `collection.upsert` takes the
         expiry as an option.

    A DOCUMENT WITH THE SAME KEY IS REPLACED. That is what loading a fixture
    means, and the tool description says so.
    """
    from couchbase.options import UpsertOptions

    cluster, _bucket, _collection = get_sdk_connection()
    per_keyspace: list[dict] = []
    total = 0

    for record in manifest.get("files") or []:
        source = str(record.get("keyspace") or "")
        target = str(keyspace_map.get(source) or source)
        parts = split_keyspace(target)
        path = directory / str(record.get("path") or "")
        entry: dict[str, Any] = {"source": source, "target": target}
        if not parts:
            entry.update(ok=False, error=f"{target!r} is not bucket.scope.collection")
            per_keyspace.append(entry)
            continue
        bucket_name, scope_name, collection_name = parts

        try:
            handle = cluster.bucket(bucket_name).scope(scope_name).collection(
                collection_name
            )
        except Exception as exc:
            entry.update(ok=False, error=f"collection could not be opened: {exc}")
            per_keyspace.append(entry)
            continue

        written = 0
        failures: list[str] = []
        try:
            with path.open("r", encoding="utf-8") as lines:
                for number, line in enumerate(lines, start=1):
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError as exc:
                        failures.append(f"line {number} is not JSON: {exc}")
                        continue
                    key = row.get("id")
                    if not isinstance(key, str) or not key:
                        failures.append(
                            f"line {number} has no usable document key. The "
                            f"fixture's key column is missing or is not a "
                            f"string, which is what the export aliases exist to "
                            f"prevent -- re-export rather than loading this."
                        )
                        continue
                    expiry = row.get("exp") or 0
                    options = None
                    if isinstance(expiry, int) and expiry > 0:
                        # An EXPORTED expiry is an absolute Unix time; the SDK
                        # takes a duration. A fixture loaded after its documents'
                        # recorded expiry would otherwise be written already
                        # dead -- so a past expiry is dropped and reported.
                        remaining = expiry - int(datetime.now(timezone.utc).timestamp())
                        if remaining > 0:
                            options = UpsertOptions(
                                expiry=timedelta(seconds=remaining)
                            )
                        else:
                            failures.append(
                                f"{key}: recorded expiry {expiry} is in the past, "
                                f"so the document was written WITHOUT one rather "
                                f"than written already expired"
                            )
                    try:
                        if options is not None:
                            handle.upsert(key, row.get("doc") or {}, options)
                        else:
                            handle.upsert(key, row.get("doc") or {})
                        written += 1
                    except Exception as exc:
                        failures.append(f"{key}: {exc}")
                        if len(failures) >= 20:
                            failures.append(
                                "stopped after 20 failures in this keyspace -- "
                                "the remainder were not attempted"
                            )
                            break
        except OSError as exc:
            entry.update(ok=False, error=f"{path} could not be read: {exc}")
            per_keyspace.append(entry)
            continue

        expected = record.get("document_count")
        entry.update(
            written=written,
            expected=expected,
            ok=not failures and (expected is None or written == expected),
            failures=failures[:20],
        )
        total += written
        per_keyspace.append(entry)

    return {
        "documents_written": total,
        "keyspaces": per_keyspace,
        "ok": all(k.get("ok") for k in per_keyspace) if per_keyspace else True,
    }


def _import_indexes(manifest: dict, keyspace_map: dict) -> dict:
    """Recreate the recorded GSI definitions, deferred, then build them.

    DEFERRED THEN BUILD, not one build per index. Building indexes one at a time
    scans the collection once per index; a single BUILD INDEX naming all of them
    scans it once. On a collection of any size that is the difference between
    minutes and an hour.
    """
    created: list[str] = []
    skipped: list[str] = []
    failures: list[str] = []
    by_keyspace: dict[str, list[str]] = {}

    for definition in manifest.get("gsi_definitions") or []:
        name = str(definition.get("indexName") or "")
        statement = str(definition.get("definition") or "")
        if not name or not statement:
            skipped.append(f"{definition!r} has no name or no definition")
            continue

        statement, _stripped = strip_index_nodes(statement)
        statement, why = rewrite_index_keyspace(statement, keyspace_map)
        if why:
            failures.append(f"{name}: {why}")
            continue

        # Deferred, so every index in a keyspace can be built in one pass.
        if "defer_build" not in statement:
            statement += (
                ' WITH {"defer_build": true}' if " WITH " not in statement
                else ""
            )
        try:
            _query(statement)
            created.append(name)
            keyspace = str(
                keyspace_map.get(definition.get("keyspace"))
                or definition.get("keyspace")
                or ""
            )
            if keyspace:
                by_keyspace.setdefault(keyspace, []).append(name)
        except Exception as exc:
            text = str(exc)
            if "already exists" in text or "4300" in text:
                skipped.append(f"{name}: already exists")
                continue
            failures.append(f"{name}: {exc}")

    built: list[str] = []
    for keyspace, names in sorted(by_keyspace.items()):
        parts = split_keyspace(keyspace)
        if not parts:
            failures.append(f"{keyspace!r} is not bucket.scope.collection")
            continue
        quoted_keyspace = "`" + "`.`".join(parts) + "`"
        index_list = ", ".join(f"`{n}`" for n in names)
        try:
            _query(f"BUILD INDEX ON {quoted_keyspace}({index_list})")
            built.append(keyspace)
        except Exception as exc:
            failures.append(f"BUILD INDEX on {keyspace}: {exc}")

    return {
        "created": created,
        "skipped": skipped,
        "build_issued_for": built,
        "failures": failures,
        "ok": not failures,
        "note": (
            "BUILD INDEX returns as soon as the build is ACCEPTED, not when it "
            "finishes. Poll system:indexes for state='online' before treating "
            "the environment as ready -- an index that exists but is not online "
            "makes the cluster look slow in a way that reads as a Couchbase "
            "problem."
        ),
    }


# ── list and verify ──────────────────────────────────────────────────────────


def _list(args: dict) -> list[TextContent]:
    """List fixtures under a directory. Filesystem only; no cluster call."""
    tool = "admin_fixture_list"
    try:
        root = resolve_under_root(args.get("root_path"), field="root_path", tool=tool)
    except ValueError as exc:
        return err(str(exc), tool=tool)
    if not root.is_dir():
        return err(f"{root} is not a directory", tool=tool)

    wanted_tags = args.get("tags") or {}
    if not isinstance(wanted_tags, dict):
        return err("tags must be an object", tool=tool)

    fixtures: list[dict] = []
    unreadable: list[dict] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir() or not (child / "manifest.json").exists():
            continue
        entry = read_manifest(child)
        if not entry.get("readable"):
            # REPORTED, never skipped. A listing that omits an unreadable
            # fixture answers "what do I have" with a confident lie.
            unreadable.append(entry)
            continue
        if wanted_tags:
            tags = entry.get("tags") or {}
            if any(tags.get(k) != v for k, v in wanted_tags.items()):
                continue
        entry.pop("manifest", None)
        fixtures.append(entry)

    return ok({
        "root_path": str(root),
        "fixtures": fixtures,
        "count": len(fixtures),
        "unreadable": unreadable,
        "filtered_by": wanted_tags or None,
    })


def _verify(args: dict) -> list[TextContent]:
    """Verify a fixture on disk, and optionally against the cluster."""
    tool = "admin_fixture_verify"
    try:
        directory = resolve_under_root(
            args.get("fixture_path"), field="fixture_path", tool=tool
        )
    except ValueError as exc:
        return err(str(exc), tool=tool)
    if directory.name == "manifest.json":
        directory = directory.parent

    entry = read_manifest(directory)
    if not entry.get("readable"):
        return err(entry.get("error", "manifest could not be read"),
                   tool=tool, fixture_path=str(directory))
    manifest = entry["manifest"]

    problems: list[str] = []
    why = schema_problem(manifest.get("schema"))
    if why:
        problems.append(why)

    checks, file_problems, payload_sha = fixture_integrity(directory, manifest)
    problems.extend(file_problems)

    result: dict[str, Any] = {
        "fixture_path": str(directory),
        "schema": manifest.get("schema"),
        "fixture_id": manifest.get("fixture_id"),
        "tags": manifest.get("tags") or {},
        "source": manifest.get("source") or {},
        "files_checked": checks,
        "payload_sha256": payload_sha,
        "verified": not problems,
        "problems": problems,
    }
    if not manifest.get("files"):
        result["note"] = (
            "The manifest names no data files. A structure-only fixture is a "
            "legitimate thing to have, but it cannot be verified as carrying "
            "data, and it must not be presented as a dataset."
        )

    if args.get("check_cluster"):
        result["cluster"] = _cluster_counts(manifest, args.get("keyspace_map") or {})
        if not result["cluster"].get("ok"):
            result["verified"] = False

    return ok(result)


def _cluster_counts(manifest: dict, keyspace_map: dict) -> dict:
    """Count documents on the cluster per keyspace and compare.

    THE CHECK THAT CATCHES A HALF-FINISHED IMPORT. The on-disk check only proves
    the fixture is intact; it says nothing about whether the data reached the
    cluster, and an import that wrote 9 of 10 files reports plausibly either way
    without this.

    It is NOT a proof of equality. A count matching does not mean the documents
    match -- that is exactly the trap the Capella key bug hid in, where COUNT(*)
    agreed while 187 of 188 keys were wrong. A count is a cheap necessary
    condition, and this says so rather than implying more.
    """
    per_keyspace: list[dict] = []
    problems: list[str] = []
    for record in manifest.get("files") or []:
        source = str(record.get("keyspace") or "")
        target = str(keyspace_map.get(source) or source)
        parts = split_keyspace(target)
        entry: dict[str, Any] = {
            "source": source,
            "target": target,
            "expected": record.get("document_count"),
        }
        if not parts:
            entry.update(ok=False, error=f"{target!r} is not bucket.scope.collection")
            problems.append(entry["error"])
            per_keyspace.append(entry)
            continue
        quoted = "`" + "`.`".join(parts) + "`"
        try:
            rows = _query(f"SELECT COUNT(*) AS total FROM {quoted}")
            actual = (rows[0] or {}).get("total") if rows else 0
        except Exception as exc:
            entry.update(ok=False, error=str(exc))
            problems.append(f"{target}: {exc}")
            per_keyspace.append(entry)
            continue
        entry["actual"] = actual
        entry["ok"] = actual == record.get("document_count")
        if not entry["ok"]:
            problems.append(
                f"{target} holds {actual} documents, the fixture records "
                f"{record.get('document_count')}"
            )
        per_keyspace.append(entry)

    return {
        "keyspaces": per_keyspace,
        "problems": problems,
        "ok": not problems,
        "note": (
            "A matching COUNT(*) is a NECESSARY condition, not a sufficient one. "
            "It does not establish that the documents match -- a Capella export "
            "bug once produced a fixture whose counts agreed exactly while 187 "
            "of 188 document KEYS were wrong. Only a round trip settles that."
        ),
    }


def handle(name: str, args: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "admin_fixture_export":
            return _export(args)
        if name == "admin_fixture_import":
            return _import(args)
        if name == "admin_fixture_list":
            return _list(args)
        if name == "admin_fixture_verify":
            return _verify(args)
        return err(f"Unknown fixture tool: {name}", tool=name)
    except Exception as exc:
        _log.exception("fixture tool %s failed", name)
        return err(str(exc), tool=name)


__all__ = ["TOOLS", "TOOL_NAMES", "handle"]
