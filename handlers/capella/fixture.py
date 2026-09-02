"""
handlers/capella/fixture.py — portable, taggable Capella fixtures.

WHAT A FIXTURE IS, AND IS NOT
=============================
A fixture is a named, versioned, tagged dataset: a manifest plus a JSON Lines
payload, committed to a repository, restorable into any Capella cluster in any
organization on any cloud provider.

It is NOT a backup. Export iterates rather than snapshotting, so it is not
point-in-time consistent. CAS is not preserved, because no documented Capella API
sets it. In server mode system xattrs are not preserved, so Sync Gateway state is
lost. Anything resembling recovery uses the capella_backup_* primitives instead.
Nothing in this module is named "backup", deliberately.

WHY THIS EXISTS
===============
The requirement that produced it asked for backups carrying tags, filtered by
queries like "latest where content-publisher-version = 1.6" and "where scenario =
'Notification Center Hurricane' and version = 1.1". Capella backups carry no
user-defined metadata and cannot be user-named, so those queries have nothing to
match against, and the bytes cannot be retrieved over any API — download is
console-only, with an emailed URL and a one-hour window. The requirement is a
fixture catalogue wearing backup vocabulary. The manifest is the answer to it.

THREE APIS, TWO CREDENTIALS
===========================
There is no single export endpoint on Capella, no bulk export, no bulk-get and no
DCP over HTTP. A fixture is assembled from:

  Data API        POST /_p/query/query/service            SQL++ passthrough; the export engine
                  GET  /_p/fts/api/bucket/{b}/scope/{s}/index[/{i}]   Search definitions out
                  PUT  /_p/fts/api/bucket/{b}/scope/{s}/index/{i}     Search definitions in
                  base https://{clusterId}.data.cloud.couchbase.com
                  auth HTTP Basic, CLUSTER ACCESS credential

  v4 Management   queryIndexes/definitions, queryIndexes/buildStatus,
                  eventing/functions, buckets/scopes/collections
                  auth organization API key

The two credentials are different and both are required. The Data API is off by
default and is enabled by setting enableDataApi on the cluster resource. Its
absence is the most likely first failure and must be reported as "the Data API is
not enabled on cluster X", never as a connection error.

CONSISTENCY, STATED PLAINLY
===========================
Export from a quiesced cluster. Documents that mutate mid-export produce a payload
that is internally inconsistent and nothing here detects that. The manifest records
the export window so a consumer can see how much drift was possible.

TWO MODES
=========
  server   SQL++ over the Data API. Correct for anything not mobile-synced.
           Loses system xattrs, therefore loses _sync.
  mobile   App Services Public REST _bulk_get / _bulk_docs. The only documented
           path that handles _sync correctly, because App Services owns that xattr
           and regenerates it on write. Sees only mobile-synced keyspaces and
           rewrites revision metadata.

A server-mode fixture presented as suitable for a mobile scenario is the failure
this design most wants to prevent. That is why mode is a required manifest field
and why import refuses a mismatch rather than warning about it.

STATUS
======
Tool definitions are complete. The four handlers return a refusal rather than a
result, because they depend on response shapes the rendered v4 reference truncates
(the queryIndexes/definitions payload) and on a disputed restore path. A fixture
that ships with a silently empty index list, or with no documents, is worse than
one that does not ship. See docs/FIXTURE_DESIGN.md for the probe that unblocks
them.
"""

from __future__ import annotations

from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

from handlers.shared import err
from logging_config import get_logger

_log = get_logger("handlers.capella.fixture")

#: Manifest schema identifier. Bump the version segment on any breaking change to
#: the manifest shape; import validates against it and refuses a mismatch.
MANIFEST_SCHEMA = "couchbase.capella.fixture/v1"

_READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)
_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False
)

#: Key-range pagination, deliberately not LIMIT/OFFSET. OFFSET re-scans on every
#: page, degrades quadratically across a large collection, and is unstable if
#: anything mutates mid-export. The last key is the only cursor state to persist,
#: which also makes a failed export resumable.
EXPORT_QUERY = """
SELECT META().id AS id, META().expiration AS exp, d.*
FROM `{bucket}`.`{scope}`.`{collection}` AS d
WHERE META().id > $last_key
ORDER BY META().id
LIMIT $page_size
"""

#: SELECT META().xattrs returns empty BY DESIGN — the whole object is not
#: selectable, only named attributes are. Every user xattr a fixture should carry
#: must therefore be declared by the caller and recorded in the manifest. Get the
#: list wrong and xattrs are dropped in silence. Fifteen per query maximum; the
#: full surface requires Couchbase Server 8.0.
XATTR_SELECT = "META().xattrs.`{name}` AS `xattr_{name}`"

_TAGS_SCHEMA = {
    "type": "object",
    "description": (
        "Free-form scenario metadata, recorded verbatim in the manifest and the "
        "basis for all fixture filtering. Capella backups cannot carry this, which "
        'is the whole reason fixtures exist. Example: {"scenario": "Notification '
        'Center Hurricane", "version": "1.1", "content-publisher-version": "1.6"}'
    ),
    "additionalProperties": {"type": "string"},
}


TOOLS: list[Tool] = [
    Tool(
        name="capella_fixture_export",
        description=(
            "Export a named, tagged fixture from a Capella cluster: structure, GSI "
            "and Search index definitions, eventing functions, and document bodies "
            "with their expiry. Writes a manifest plus JSON Lines payload to "
            "fixture_path.\n\n"
            "NOT A BACKUP. Export iterates rather than snapshotting, so it is not "
            "point-in-time consistent — run it against a quiesced cluster. CAS is "
            "not preserved by any documented Capella API. In server mode system "
            "xattrs are not preserved, so Sync Gateway state is lost; use "
            "mode=mobile if the dataset is mobile-synced.\n\n"
            "Requires the Data API to be enabled on the cluster (enableDataApi via "
            "capella_cluster_update) and a cluster access credential in addition to "
            "the organization API key."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "fixture_id": {
                    "type": "string",
                    "description": (
                        "Stable identifier, also the directory name. Convention: "
                        "slug of scenario plus version, e.g. "
                        "'notification-center-hurricane-1.1'."
                    ),
                },
                "fixture_path": {
                    "type": "string",
                    "description": (
                        "Directory to write into. Subject to the same egress walk "
                        "as every other path argument on this server."
                    ),
                },
                "cluster_id": {"type": "string"},
                "project_id": {"type": "string"},
                "organization_id": {"type": "string"},
                "mode": {
                    "type": "string",
                    "enum": ["server", "mobile"],
                    "description": (
                        "server: SQL++ over the Data API; loses _sync. mobile: App "
                        "Services bulk API; preserves _sync, sees only mobile-synced "
                        "keyspaces, rewrites revision metadata. Defaults to server."
                    ),
                },
                "tags": _TAGS_SCHEMA,
                "keyspaces": {
                    "type": "array",
                    "description": (
                        "Keyspaces to export as bucket.scope.collection. Omit to "
                        "export every collection the credential can read."
                    ),
                    "items": {"type": "string"},
                },
                "user_xattrs": {
                    "type": "array",
                    "description": (
                        "User xattr names to carry. Unlisted attributes are dropped "
                        "silently, because the xattr object is not enumerable. "
                        "System xattrs such as _sync cannot be read here at all."
                    ),
                    "items": {"type": "string"},
                },
                "page_size": {
                    "type": "integer",
                    "description": (
                        "Documents per SQL++ page. Keep the response under the Data "
                        "API's 100 MB payload cap and 120 second timeout. Defaults "
                        "to 1000."
                    ),
                },
                "include_data": {
                    "type": "boolean",
                    "description": (
                        "False exports structure, indexes and eventing only — a "
                        "shape fixture with no documents, for targets that generate "
                        "their own data. Defaults to true."
                    ),
                },
            },
            "required": ["fixture_id", "fixture_path", "cluster_id"],
        },
        annotations=_READ,
    ),
    Tool(
        name="capella_fixture_import",
        description=(
            "Import a fixture into a Capella cluster: create buckets, scopes and "
            "collections, load documents with their expiry, apply Search index "
            "definitions, create eventing functions, then create the GSI indexes AND "
            "BUILD THEM, polling until every index is online before reporting "
            "ready.\n\n"
            "The build gate is not optional. A cluster whose index definitions exist "
            "but are not online is not performance-comparable to the fixture's "
            "source, and a load test started against it produces numbers that look "
            "like a Couchbase performance problem.\n\n"
            "DESTRUCTIVE: overwrites documents in existing collections. Refused "
            "unless the target is in an allowlisted project and any bucket it "
            "creates carries the configured prefix. Refused outright if the "
            "manifest's mode does not match what the target needs."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "fixture_path": {"type": "string"},
                "cluster_id": {"type": "string"},
                "project_id": {"type": "string"},
                "organization_id": {"type": "string"},
                "keyspace_map": {
                    "type": "object",
                    "description": (
                        "Optional bucket.scope.collection rewrites, applied to "
                        "keyspaces, index statements and eventing bindings alike. "
                        "Without this a fixture can only be imported into the "
                        "structure it was exported from."
                    ),
                    "additionalProperties": {"type": "string"},
                },
                "build_indexes": {
                    "type": "boolean",
                    "description": (
                        "Defaults to true. False leaves indexes deferred and the "
                        "resulting cluster must NOT be used for measurement."
                    ),
                },
                "confirm": {"type": "boolean"},
            },
            "required": ["fixture_path", "cluster_id"],
        },
        annotations=_DESTRUCTIVE,
    ),
    Tool(
        name="capella_fixture_list",
        description=(
            "List fixtures under a root path with their tags, and filter on them. "
            "This is the tool that answers what Capella backups cannot: 'latest "
            "where content-publisher-version = 1.6', 'where scenario = Notification "
            "Center Hurricane and version = 1.1', 'last month where trips not in "
            "projectName'. Local filesystem only — no cluster contact and no "
            "credentials required."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "root_path": {"type": "string"},
                "match_tags": {
                    "type": "object",
                    "description": "Exact tag matches, ANDed together.",
                    "additionalProperties": {"type": "string"},
                },
                "exclude_tags": {
                    "type": "object",
                    "description": "Tag values to exclude, ANDed together.",
                    "additionalProperties": {"type": "string"},
                },
                "created_after": {"type": "string"},
                "created_before": {"type": "string"},
                "latest_only": {
                    "type": "boolean",
                    "description": "Return only the newest match. Defaults to false.",
                },
            },
            "required": ["root_path"],
        },
        annotations=_READ,
    ),
    Tool(
        name="capella_fixture_verify",
        description=(
            "Verify a fixture, or a cluster imported from one. Against a fixture: "
            "validate the manifest, recompute the payload hash, confirm declared "
            "document counts. Against a cluster: confirm structure exists, document "
            "counts match, and every GSI index named in the manifest is ONLINE "
            "rather than merely defined. Use as the readiness gate after "
            "capella_fixture_import."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "fixture_path": {"type": "string"},
                "cluster_id": {
                    "type": "string",
                    "description": (
                        "Supply to verify an imported cluster against the fixture. "
                        "Omit to verify the fixture artifact alone."
                    ),
                },
                "project_id": {"type": "string"},
                "organization_id": {"type": "string"},
            },
            "required": ["fixture_path"],
        },
        annotations=_READ,
    ),
]

TOOL_NAMES = frozenset(t.name for t in TOOLS)

#: Returned by every handler until the probe run lands. Deliberately an error
#: response rather than a raised exception: the handler contract requires that no
#: handler raises on empty arguments, and deliberately not a plausible empty
#: success, because a fixture that reports success with no documents in it is the
#: worst outcome available here.
_BLOCKED = (
    "capella_fixture_* is defined but not yet implemented. This is now IMPLEMENTATION "
    "WORK, not an unknown: both v4 questions it was waiting on were settled against a "
    "live control plane on 2026-09-01.\n"
    "\n"
    "  * The index-definition payload is at GET .../clusters/{id}/queryService/indexes "
    "    (NOT /queryIndexes/definitions, which does not exist), takes a required "
    "    `bucket` NAME plus optional scope and collection, and answers 200 with a "
    "    `definitions` key. Shipped as capella_query_index_definitions_list.\n"
    "  * The restore path dispute is settled in favour of "
    "    POST .../clusters/{cluster_id}/backups/{backup_id}/restore, and more strongly "
    "    than the path alone showed: the body requires BOTH sourceClusterID and "
    "    targetClusterID, so cross-cluster restore is a single call with both ends "
    "    named. Shipped as capella_backup_restore.\n"
    "\n"
    "What remains is writing the export/import/verify logic against those two, plus the "
    "eventing and search definitions -- see the per-handler docstrings below and "
    "docs/FIXTURE_DESIGN.md. Still refusing rather than half-implementing: a fixture "
    "that reports success with no documents in it is the worst outcome available here."
)


def _export(args: dict) -> list[TextContent]:
    """Export a fixture.

    Sequence, each step recorded in the manifest as it completes:

      1. Resolve org and project and apply the org pin. Export is a read, but a
         fixture taken from a project outside the sandbox is an exfiltration path
         with a friendly name, so the pin still applies.
      2. capella_cluster_get; confirm the Data API endpoint is enabled. If not,
         fail with "the Data API is not enabled on cluster X — set enableDataApi
         via capella_cluster_update" and stop.
      3. Run fixture_path through the egress walk in handlers/egress.py. Do not
         write a bespoke path check here.
      4. Structure: buckets with settings, scopes, collections, via the existing
         v4 ops.
      5. GSI: capella_query_index_definitions_list.
      6. Search: GET /_p/fts/api/bucket/{b}/scope/{s}/index per scope, storing each
         definition verbatim. Scope-level paths only — bucket-wide and alias
         indexes are unconfirmed on Capella.
      7. Eventing: list, then per function fetch the object and /code separately.
      8. Documents, if include_data: EXPORT_QUERY per keyspace, key-range
         paginated, plus one XATTR_SELECT clause per declared user xattr. Stream to
         data/{keyspace}.jsonl as {"id":…,"exp":…,"doc":{…},"xattrs":{…}}, one
         document per line so a large fixture streams and diffs sanely.
      9. Hash each data file, hash the payload, write manifest.json with the
         fidelity block populated from what actually happened rather than intent.

    Record export start and end timestamps. Export is not a snapshot, and the
    window is the only signal a consumer has about how much drift to expect.
    """
    return err(_BLOCKED, tool="capella_fixture_export")


def _import(args: dict) -> list[TextContent]:
    """Import a fixture.

    Sequence:

      1. Read and validate the manifest. Refuse on schema mismatch, payload hash
         mismatch, or a mode the target cannot honour.
      2. Guardrails: project allowlist, name prefix on every bucket to be created,
         confirm. Automation principals are NOT exempt from confirm here. Teardown
         is exempt so CI can clean up after itself; there is no equivalent argument
         for overwriting data in an existing bucket.
      3. Create structure via v4, applying keyspace_map.
      4. Load documents with INSERT INTO … (KEY, VALUE, OPTIONS) carrying
         {"expiration": …} and {"xattrs": …}. Manifest expiry is an absolute Unix
         timestamp, so use the absolute form. Batch inside single statements —
         there is no bulk write on the KV side and batching is the only source of
         throughput.
      5. PUT each Search index definition.
      6. POST each eventing function, PUT its /code, then PUT its /state.
      7. CREATE INDEX for every GSI entry, BUILD INDEX, then poll
         capella_query_index_build_status until all are online. If build_indexes is
         false, say so loudly in the result and mark the target unsuitable for
         measurement.
      8. Return a per-step, per-keyspace result. Partial success is a normal
         outcome and must not be collapsed into a single status.
    """
    return err(_BLOCKED, tool="capella_fixture_import")


def _list(args: dict) -> list[TextContent]:
    """List and filter fixtures by manifest tags.

    Walk root_path for */manifest.json, read tags and created_at from each, apply
    match_tags, exclude_tags and the date range, sort newest first, honour
    latest_only. Pure local filesystem work.

    A manifest that fails to parse is reported as a warning entry rather than
    skipped. A fixture directory that has silently stopped being readable is
    exactly what someone needs to be told about.
    """
    return err(_BLOCKED, tool="capella_fixture_list")


def _verify(args: dict) -> list[TextContent]:
    """Verify a fixture, and optionally a cluster imported from it.

    Fixture alone: manifest validates against MANIFEST_SCHEMA, payload_sha256
    recomputes, per-file sha256 recomputes, document_count matches the actual line
    count of each data file.

    With cluster_id: every bucket, scope and collection exists; document counts
    match per keyspace; every GSI index named in the manifest is ONLINE, not merely
    defined. Report index states individually — "4 of 7 online" is actionable,
    "not ready" is not.
    """
    return err(_BLOCKED, tool="capella_fixture_verify")


HANDLERS = {
    "capella_fixture_export": _export,
    "capella_fixture_import": _import,
    "capella_fixture_list": _list,
    "capella_fixture_verify": _verify,
}


def handle(name: str, args: dict[str, Any]) -> list[TextContent]:
    """Dispatch a fixture tool call."""
    handler = HANDLERS.get(name)
    if handler is None:
        return err(f"Unknown fixture tool: {name}", tool=name)
    return handler(args or {})


__all__ = ["TOOLS", "TOOL_NAMES", "handle", "MANIFEST_SCHEMA"]
