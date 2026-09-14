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
                  EVERY EXPORTED COLLECTION NEEDS AN INDEX. SQL++ cannot serve a
                  WHERE against an unindexed collection -- error 4000, "No index
                  available on keyspace". travel-sample ships without one on a
                  fresh Capella cluster, so this bites on the first real export.
                  Create a primary index (and consider dropping it afterwards).
                  GET  /_p/fts/api/bucket/{b}/scope/{s}/index[/{i}]   Search definitions out
                  PUT  /_p/fts/api/bucket/{b}/scope/{s}/index/{i}     Search definitions in
                  base FROM capella_data_api_get's `connectionString`, e.g.
                       https://vn1kiibitcyvwrw.data.cloud.couchbase.com
                       -- the SHORT connection-string id (the cluster's SDK
                       string is cb.vn1kiibitcyvwrw.cloud.couchbase.com), NOT
                       the v4 UUID. Read it; the same call also says whether
                       the Data API is enabled.
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

import hashlib
import json
import os
import pathlib
from datetime import datetime, timezone
from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

from handlers.fixture_core import (
    MANIFEST_SCHEMA as _MANIFEST_SCHEMA,
)
from handlers.fixture_core import (
    META_EXP_ALIAS,
    META_ID_ALIAS,
    export_statement,
)

# The plane-neutral half. Imported under the names this module has always used,
# so every call site below is unchanged -- the code MOVED, it was not rewritten.
#
# An Enterprise Edition fixture family imports exactly the same functions, which
# is the point: a fixture captured on one plane and verified on the other must
# agree byte for byte on what the manifest means, and two implementations that
# agree today would drift silently. See docs/FIXTURE_DESIGN.md.
from handlers.fixture_core import (
    REPLICA_SUFFIX as _REPLICA_SUFFIX,
)
from handlers.fixture_core import (
    base_index_name as _base_index_name,
)
from handlers.fixture_core import (
    fixture_integrity as _fixture_integrity,
)
from handlers.fixture_core import (
    parse_timestamp as _parse_timestamp,
)
from handlers.fixture_core import (
    read_manifest as _read_manifest,
)
from handlers.fixture_core import (
    remap_keyspace as _remap_keyspace,
)
from handlers.fixture_core import (
    resolve_under_root as _resolve_under_root,
)
from handlers.fixture_core import (
    rewrite_index_keyspace as _rewrite_index_keyspace,
)
from handlers.fixture_core import (
    schema_problem as _schema_problem,
)
from handlers.fixture_core import (
    sha256_file as _sha256_file,
)
from handlers.fixture_core import (
    split_keyspace as _split_keyspace,
)
from handlers.fixture_core import (
    strip_index_nodes as _strip_index_nodes,
)
from handlers.shared import err, ok
from logging_config import get_logger

from .client import build_path, capella_request
from .spec import OPS_BY_NAME

_log = get_logger("handlers.capella.fixture")

#: Manifest schema identifier. Bump the version segment on any breaking change to
#: the manifest shape; import validates against it and refuses a mismatch.
#: Re-exported from the shared core so existing importers of
#: `fixture.MANIFEST_SCHEMA` keep working. The value itself is neutral now --
#: see handlers/fixture_core.py for why the plane name came out of it.
MANIFEST_SCHEMA = _MANIFEST_SCHEMA

#: READ-ONLY WITH RESPECT TO THE CLUSTER. That is what the hint governs here, and
#: the distinction is deliberate rather than accidental.
#:
#: capella_fixture_export carries readOnlyHint=True and WRITES FILES -- a manifest
#: and a JSON Lines payload under fixture_path. Judged against the MCP annotation's
#: plain wording ("does not modify its environment") that is a contradiction, and
#: the honest-looking fix is to flip the hint to False.
#:
#: It was NOT flipped, because in this server readOnlyHint is not documentation:
#: server.py uses it to decide which tools LOAD in read-only mode, and read-only
#: mode exists to protect the CLUSTER. Flipping it would remove fixture export from
#: exactly the deployment that most wants it -- a read-only, forensic posture where
#: capturing what a cluster currently looks like is the whole job -- in exchange for
#: preventing a bounded write to a directory the operator named, under
#: CB_ADMIN_FIXTURE_ROOT when one is set.
#:
#: So the hint stays True and the filesystem write is stated in the tool's own
#: description, where a caller reading the annotation alone will still see it.
#: Decided 2026-09-14; recorded here so the next reader finds a decision rather
#: than an oversight.
_READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)
_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False
)

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
            "the organization API key.\n\n"
            "WRITES TO THE LOCAL FILESYSTEM. This tool is annotated read-only, which "
            "is true of the CLUSTER and not of the disk: it creates fixture_path and "
            "writes a manifest plus one JSON Lines file per keyspace there. Set "
            "CB_ADMIN_FIXTURE_ROOT to confine where that can be."
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

#: Cluster access credential for the DATA API. Not the organization API key.
#:
#: TWO CREDENTIALS, AND THEY ARE NOT INTERCHANGEABLE. Everything in v4 --
#: buckets, scopes, indexes, eventing -- authenticates with the organization API
#: key as a Bearer token. The Data API authenticates with a CLUSTER ACCESS
#: credential over HTTP Basic: the thing capella_database_credential_create
#: makes. An operator who sets only the API key gets a 401 from the Data API and
#: no hint about which of their two secrets is missing, so this names them.
_DATA_USER_ENV = "CB_CAPELLA_CLUSTER_USER"
_DATA_PASSWORD_ENV = "CB_CAPELLA_CLUSTER_PASSWORD"

#: Data API query service path, relative to the connection string.
_QUERY_PATH = "/_p/query/query/service"


def _data_api_base(ids: dict) -> tuple[str, str]:
    """(base_url, why_not). Reads the connection string from the control plane.

    NOT DERIVED FROM THE CLUSTER ID. This module's docstring claimed the base was
    https://{clusterId}.data.cloud.couchbase.com, which is the pattern the public
    docs show -- but a Capella cluster has TWO identifiers, the v4 UUID and the
    short connection-string id, and the docs do not say which one this is. The
    provider does not guess either: it reads `connectionString` from
    GET .../dataAPI, which is empty until the API is enabled and settled.

    So this asks. An empty string is not an error here -- it is the answer
    "not enabled yet", and the caller is told that rather than being handed a
    URL that will time out.
    """
    from .client import build_path, capella_request
    from .spec import OPS_BY_NAME

    op = OPS_BY_NAME["capella_data_api_get"]
    try:
        status = capella_request(op.method, build_path(op.path, ids))
    except Exception as exc:
        return "", f"the Data API status could not be read: {exc}"
    if not isinstance(status, dict):
        return "", "the Data API status response was not an object"
    connection = str(status.get("connectionString") or "")
    if not connection:
        state = status.get("state")
        return "", (
            f"the Data API is not usable on this cluster: enabled="
            f"{status.get('enabled')}, state={state!r}, and connectionString is "
            f"empty. Enable it with capella_data_api_set and wait for the state "
            f"to settle -- it is asynchronous and takes minutes. An empty "
            f"connection string is the control plane saying 'not yet', not a "
            f"lookup failure."
        )
    if not connection.startswith("http"):
        connection = "https://" + connection
    return connection.rstrip("/"), ""


def _data_api_credential() -> tuple[tuple[str, str], str]:
    """((user, password), why_not) for HTTP Basic against the Data API."""
    user = (os.environ.get(_DATA_USER_ENV) or "").strip()
    password = (os.environ.get(_DATA_PASSWORD_ENV) or "").strip()
    if not user or not password:
        return ("", ""), (
            f"no Data API credential. Set {_DATA_USER_ENV} and "
            f"{_DATA_PASSWORD_ENV} to a CLUSTER ACCESS credential -- the kind "
            f"capella_database_credential_create issues -- not the organization "
            f"API key. The Data API uses HTTP Basic and will answer 401 to a "
            f"Bearer token without saying which secret was wrong.\n"
            f"The credential also needs the right privileges: data_reader is "
            f"enough to EXPORT, and an import additionally needs data_writer on "
            f"the target keyspaces."
        )
    return (user, password), ""


#: Seconds for one Data API query. DELIBERATELY SHORTER THAN THE MCP CLIENT'S.
#:
#: This was 120, and scripts/dump_tool.py allows an MCP call 60 seconds by
#: default. The client therefore gave up FIRST, every time, and the caller saw
#: an asyncio TimeoutError traceback from deep inside anyio instead of this
#: module's own message -- which would have named the allowed-CIDR list, the
#: credential kind, or whatever the query service actually said.
#:
#: The layer that knows WHY must be the layer that fails. 45 leaves room for the
#: handler to catch its own timeout, write a useful error and return it through
#: the transport before the client's clock runs out. Raise both together if a
#: fixture ever needs longer pages -- never this one alone.
_QUERY_TIMEOUT_SECONDS = 45


#: One document on the Data API's KV surface. MEASURED, NOT INFERRED.
#:
#: probe_data_api_kv.py tried three candidate spellings against a live cluster on
#: 2026-09-14 and this is the one that routed. Every step was measured:
#:
#:     GET    -> 404 {"code":"DocumentNotFound", "message":"Document '...' not
#:                    found in 'travel-sample/inventory/airline'."}
#:     POST   -> 200   (create)
#:     GET    -> 200   body returned byte for byte
#:     PUT    -> 200   (upsert over the existing document)
#:     GET    -> 200   upserted body
#:     DELETE -> 200
#:
#: The two rejected spellings are recorded in that script rather than here, so
#: the next person can see what was tried instead of re-trying it.
#:
#: THIS IS WHY DOCUMENT IMPORT IS NOT SQL++. A literal UPSERT in handler source
#: bypasses is_dml_statement -- that guard only inspects statements arriving as
#: ARGUMENTS -- so "nothing writes data through SQL++" would have become advisory.
#: The importer WAS written that way first and
#: test_no_handler_embeds_a_mutating_sql_statement caught it. This endpoint is the
#: honest route: same host, same credential, same allowlist, no SQL++, and no
#: dependency on the data plane's port 11210 that a container may not have.
_DOCUMENT_PATH = (
    "/v1/buckets/{bucket}/scopes/{scope}/collections/{collection}/documents/{key}"
)

#: Concurrent document writes. The Data API's KV surface is one request per
#: document -- there is no documented bulk endpoint -- so a fixture of any size is
#: latency-bound rather than throughput-bound, and sequential writes over HTTPS
#: would put a 100k-document fixture into the hours.
#:
#: Kept deliberately modest. This is somebody's cluster and an importer is not
#: entitled to saturate it; 8 in flight is enough to hide round-trip latency
#: without behaving like a load generator.
_IMPORT_CONCURRENCY = 8

#: Stop after this many document failures. A fixture whose every write is failing
#: -- wrong credential, revoked privilege, collection dropped mid-run -- should
#: say so after twenty attempts, not after a hundred thousand.
_IMPORT_FAILURE_LIMIT = 20


def _put_document(base: str, credential: tuple[str, str], bucket: str, scope: str,
                  collection: str, key: str, body: Any,
                  timeout: int = 30) -> str:
    """PUT one document. Returns "" on success, else the reason.

    PUT rather than POST, because the importer is explicitly re-runnable: POST is
    create and answers a conflict on a key that already exists, while PUT upserts.
    Both were measured at 200.

    Returns a string instead of raising because it runs inside a thread pool and a
    per-document failure is data the caller aggregates, not an exception that
    should unwind the batch.
    """
    import base64
    import urllib.error
    import urllib.parse
    import urllib.request

    path = _DOCUMENT_PATH.format(
        bucket=urllib.parse.quote(bucket, safe=""),
        scope=urllib.parse.quote(scope, safe=""),
        collection=urllib.parse.quote(collection, safe=""),
        # A DOCUMENT KEY IS NOT A PATH SEGMENT UNTIL IT IS ESCAPED. Couchbase keys
        # routinely carry '/', ':' and '#' -- "_sync:user:alice", "order/2026/01" --
        # and an unescaped one would silently address a different URL, or a
        # different document.
        key=urllib.parse.quote(str(key), safe=""),
    )
    payload = json.dumps(body).encode()
    request = urllib.request.Request(base + path, data=payload, method="PUT")
    token = base64.b64encode(f"{credential[0]}:{credential[1]}".encode()).decode()
    request.add_header("Authorization", f"Basic {token}")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if 200 <= response.status < 300:
                return ""
            return f"{response.status}"
    except urllib.error.HTTPError as exc:
        return f"{exc.code}: {exc.read().decode(errors='replace')[:200]}"
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def _sql_query(base: str, credential: tuple[str, str], statement: str,
               parameters: dict | None = None,
               timeout: int = _QUERY_TIMEOUT_SECONDS) -> dict:
    """One SQL++ statement over the Data API. Raises RuntimeError with the body.

    Errors are returned with their FULL text. A query service refusal names the
    keyspace and the reason -- "Keyspace not found", "User does not have
    credentials" -- and truncating that turns a fixable problem into a mystery.
    """
    import base64
    import urllib.error
    import urllib.request

    payload = {"statement": statement}
    if parameters:
        payload.update(parameters)
    data = json.dumps(payload).encode()
    request = urllib.request.Request(base + _QUERY_PATH, data=data, method="POST")
    token = base64.b64encode(f"{credential[0]}:{credential[1]}".encode()).decode()
    request.add_header("Authorization", f"Basic {token}")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        hint = ""
        if exc.code == 401:
            hint = (
                f" -- 401 from the Data API almost always means the wrong KIND "
                f"of credential. It wants a cluster access credential over HTTP "
                f"Basic ({_DATA_USER_ENV}/{_DATA_PASSWORD_ENV}), not the "
                f"organization API key."
            )
        elif exc.code in (403, 0) or "timed out" in body.lower():
            hint = (
                " -- check the cluster's allowed CIDR list. A Data API client "
                "is subject to it exactly like any other data-plane client, and "
                "a fixture cluster allowlisted to 192.0.2.1/32 (RFC 5737 "
                "documentation space) grants nothing to anybody."
            )
        raise RuntimeError(f"Data API {exc.code}: {body[:900]}{hint}") from exc
    except Exception as exc:
        raise RuntimeError(
            f"Data API unreachable at {base} after {timeout}s: {exc}\n"
            f"A TIMEOUT here is almost always the allowed-CIDR list: a data-plane "
            f"client that is not allowlisted is dropped rather than refused, so "
            f"it looks like a hang and not a rejection. Check "
            f"capella_allowed_cidrs_list includes THIS machine's egress address "
            f"-- and note a new entry can take a minute to take effect, so an "
            f"immediate retry after adding one can still time out.\n"
            f"A CONNECTION RESET instead usually means TLS interception; a "
            f"corporate proxy cannot sit in front of a Data API call."
        ) from exc


def _export(args: dict) -> list[TextContent]:
    """Export a fixture.

    IMPLEMENTED 2026-09-14 FOR include_data=false ONLY -- structure, GSI
    definitions and eventing functions. That is not a stopgap, it is where the
    credential boundary falls: everything in this path is a v4 management read
    with the organization API key, and every one of those ops is already shipped
    and live-verified. Documents need the DATA API, a second credential, and the
    cluster to have enableDataApi set; Search definitions need the same. Those
    are the next piece of work, and an export that quietly produced no documents
    while reporting success is the exact outcome this module's docstring calls
    the worst one available.

    So: include_data=true REFUSES, by name, with what is missing. A shape fixture
    is a real artifact -- it is what a target that generates its own data needs --
    and the manifest records fidelity so nothing downstream can mistake one for a
    dataset.

    Sequence, all v4 reads:
      1. Resolve org and project, applying the org pin and the project allowlist.
         Export is a read, but a fixture taken from a project outside the sandbox
         is an exfiltration path with a friendly name.
      2. Resolve fixture_path under CB_ADMIN_FIXTURE_ROOT and refuse traversal.
      3. Buckets, then scopes and collections per bucket.
      4. GSI definitions via capella_query_index_definitions_list.
      5. Eventing functions via capella_eventing_functions_list.
      6. Write manifest.json with the fidelity block populated from what actually
         happened, not from what was intended.
    """
    from . import environment as _env  # local import: avoids a package cycle

    fixture_id = str(args.get("fixture_id") or "").strip()
    if not fixture_id:
        return err("fixture_id is required", tool="capella_fixture_export")

    include_data = bool(args.get("include_data", True))

    # NO BLANKET REFUSAL HERE ANY MORE. This used to stop every include_data=true
    # call with "NOT YET IMPLEMENTED"; the documents are implemented below.
    #
    # THE BASE URL, MEASURED ON TWO CLUSTERS 2026-09-14:
    #     https://cpvbgft3fwgwy3eu.data.cloud.couchbase.com
    #     https://vn1kiibitcyvwrw.data.cloud.couchbase.com
    # The second cluster's SDK connection string is
    # cb.vn1kiibitcyvwrw.cloud.couchbase.com, so the id in the Data API host is
    # the SHORT connection-string id -- which is what the public docs mean by
    # "{clusterId}" -- and NOT the v4 UUID (3c5e8191-...) that this module used
    # to interpolate. That old base could never have resolved.
    #
    # It is still read from capella_data_api_get rather than assembled from the
    # cluster document, for two reasons: the same call reports whether the API
    # is enabled at all, and a string the control plane hands you cannot drift
    # from a rule inferred off two examples.
    #
    # The refusal now happens where the fact is known: if the Data API is off,
    # or no cluster credential is configured, the document phase says which of
    # the two it is and writes nothing.

    try:
        org, project, _policy = _env._resolve_context(args)
    except Exception as exc:  # GuardrailError and friends carry their own hints
        return err(str(exc), tool="capella_fixture_export")

    cluster_id = str(args.get("cluster_id") or "").strip()
    if not cluster_id:
        return err("cluster_id is required", tool="capella_fixture_export")

    try:
        root = _resolve_under_root(
            args.get("fixture_path"), field="fixture_path",
            tool="capella_fixture_export",
        )
    except ValueError as exc:
        return err(str(exc), tool="capella_fixture_export")

    ids = {"organization_id": org, "project_id": project, "cluster_id": cluster_id}
    started = datetime.now(timezone.utc)
    structure: list[dict] = []
    warnings: list[str] = []

    try:
        buckets = _env._items(
            _env._invoke("capella_buckets_list", ids, composite="capella_fixture_export")
        )
    except Exception as exc:
        return err(f"could not list buckets: {exc}", tool="capella_fixture_export")

    wanted = {k.split(".")[0] for k in (args.get("keyspaces") or []) if k}
    for bucket in buckets:
        name = bucket.get("name")
        if wanted and name not in wanted:
            continue
        record: dict[str, Any] = {
            "name": name,
            "bucket_id": bucket.get("id"),
            "settings": {
                key: bucket.get(key)
                for key in (
                    "type", "storageBackend", "memoryAllocationInMb", "replicas",
                    "bucketConflictResolution", "durabilityLevel", "flush",
                    "timeToLiveInSeconds", "evictionPolicy",
                )
                if bucket.get(key) is not None
            },
            "scopes": [],
        }
        try:
            scope_args = dict(ids, bucket_id=bucket.get("id"))
            scopes = _env._items(
                _env._invoke("capella_scopes_list", scope_args,
                             composite="capella_fixture_export")
            )
        except Exception as exc:
            warnings.append(f"scopes for bucket {name} could not be read: {exc}")
            scopes = []
        for scope in scopes:
            record["scopes"].append({
                "name": scope.get("name"),
                "collections": [
                    {"name": c.get("name"), "maxTTL": c.get("maxTTL")}
                    for c in (scope.get("collections") or [])
                ],
            })
        structure.append(record)

    indexes: list[dict] = []
    for bucket in structure:
        try:
            # NOT _invoke: `bucket` IS A QUERY PARAMETER, NOT A PATH SEGMENT.
            #
            # environment._invoke builds the path and calls capella_request with
            # no params, so passing bucket in its args dict dropped it silently
            # and the API answered
            #   400 code 1000 "Check if you have provided a valid URL and all the
            #   required params are present in the request body."
            # -- a generic message that names neither the parameter nor the fact
            # that it never arrived. Measured 2026-09-14 on the first real export.
            #
            # The op declares bucket/scope/collection as query parameters and the
            # API treats bucket as mandatory, which is the same trap recorded in
            # _HARVEST_ONLY in scripts/verify_mcp_surface.py: optional in the
            # schema, required in practice.
            op = OPS_BY_NAME["capella_query_index_definitions_list"]
            payload = capella_request(
                op.method,
                build_path(op.path, ids),
                params={"bucket": bucket["name"]},
            )
        except Exception as exc:
            warnings.append(
                f"GSI definitions for {bucket['name']} could not be read: {exc}"
            )
            continue
        found = payload.get("definitions") if isinstance(payload, dict) else None
        indexes.extend(found or [])

    try:
        eventing = _env._items(
            _env._invoke("capella_eventing_functions_list", ids,
                         composite="capella_fixture_export")
        )
    except Exception as exc:
        warnings.append(f"eventing functions could not be read: {exc}")
        eventing = []

    # ── documents ────────────────────────────────────────────────────────
    data_files: list[dict] = []
    document_total = 0
    documents_ok = False
    if include_data:
        base, why = _data_api_base(ids)
        credential, cred_why = _data_api_credential()
        blocker = why or cred_why
        if blocker:
            # REFUSE, DO NOT DEGRADE. Falling back to a structure-only export
            # here would produce a fixture that looks like a dataset and holds
            # nothing -- which this module's docstring calls the worst outcome
            # available. The caller asked for documents; if they cannot be had,
            # say so and write nothing.
            return err(
                f"include_data=true was requested and the documents cannot be "
                f"read.\n{blocker}\n"
                f"Pass include_data=false for a structure-only fixture, which is "
                f"a complete artifact in its own right -- it just is not a "
                f"dataset, and its manifest says so.",
                tool="capella_fixture_export",
            )

        page_size = int(args.get("page_size") or 1000)
        xattrs = [str(x) for x in (args.get("user_xattrs") or [])]
        wanted_keyspaces = {k for k in (args.get("keyspaces") or []) if k}
        # MATCHED, so an unmatched request can be refused rather than ignored.
        # Without this a single typo in `keyspaces` produced a SILENT SUCCESS: no
        # collection matched the filter, the loop wrote nothing, and the manifest
        # reported a clean export of zero documents. The caller asked for a named
        # keyspace and got a fixture that does not contain it, with no indication
        # that anything was wrong.
        matched_keyspaces: set[str] = set()
        data_dir = root / "data"
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return err(f"could not create {data_dir}: {exc}",
                       tool="capella_fixture_export")

        for bucket in structure:
            for scope in bucket.get("scopes") or []:
                for collection in scope.get("collections") or []:
                    keyspace = (f"{bucket['name']}.{scope['name']}."
                                f"{collection['name']}")
                    if wanted_keyspaces and keyspace in wanted_keyspaces:
                        matched_keyspaces.add(keyspace)
                    if wanted_keyspaces and keyspace not in wanted_keyspaces:
                        continue
                    # The statement is built by the SHARED builder, not here.
                    # Both planes must issue the same query or the row format
                    # they write is not the same row format, and a fixture stops
                    # being portable between them.
                    statement = export_statement(
                        bucket["name"], scope["name"], collection["name"],
                        page_size=page_size, user_xattrs=xattrs,
                    )
                    target = data_dir / f"{keyspace}.jsonl"
                    last_key = ""
                    written = 0
                    try:
                        with target.open("w", encoding="utf-8") as handle:
                            while True:
                                result = _sql_query(
                                    base, credential, statement,
                                    {"$last_key": last_key},
                                )
                                rows = result.get("results") or []
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
                                        # The alias did not survive, which can
                                        # only mean a document field of the same
                                        # name overwrote it. Refuse rather than
                                        # record a key that is not the key --
                                        # the exact failure these aliases exist
                                        # to prevent.
                                        raise RuntimeError(
                                            f"a document in {keyspace} has no "
                                            f"{META_ID_ALIAS}: a field of that "
                                            f"name in the document overwrote "
                                            f"the metadata alias, so its real "
                                            f"key cannot be recovered. Nothing "
                                            f"was written for this keyspace."
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
                    except RuntimeError as exc:
                        # AN UNINDEXED COLLECTION IS A PRECONDITION FAILURE, NOT
                        # A BUG, and it is the first thing a real export hits.
                        # SQL++ cannot read a collection with no index at all:
                        # the key-range page is a SELECT with a WHERE, and N1QL
                        # needs an index to serve one. travel-sample's own
                        # collections have none on a fresh Capella cluster, so
                        # the very first document export fails here.
                        remedy = ""
                        if "No index available" in str(exc) or "4000" in str(exc):
                            remedy = (
                                f"\nTHE COLLECTION HAS NO INDEX. Create one and "
                                f"re-run:\n"
                                f"  capella_query_index_manage with\n"
                                f"  CREATE PRIMARY INDEX ON `{keyspace}`\n"
                                f"A primary index is the general answer and it is "
                                f"not free -- it indexes every key in the "
                                f"collection. On a large collection prefer an "
                                f"existing secondary index that covers META().id, "
                                f"or create the primary index, export, and drop "
                                f"it again. This tool will NOT create one for "
                                f"you: building an index on somebody's cluster "
                                f"is a capacity decision, not a side effect of "
                                f"reading."
                            )
                        return err(
                            f"export failed on {keyspace} after {written} "
                            f"document(s): {exc}{remedy}\n"
                            f"The partial file was left at {target} so the "
                            f"failure can be inspected; the manifest was NOT "
                            f"written, so nothing downstream will mistake this "
                            f"for a complete fixture.",
                            tool="capella_fixture_export",
                        )
                    if written == 0:
                        # An empty collection is legitimate. The file is removed
                        # so the manifest does not name a data file holding
                        # nothing, which reads as a failed export.
                        target.unlink(missing_ok=True)
                        continue
                    data_files.append({
                        "path": f"data/{target.name}",
                        "keyspace": keyspace,
                        "sha256": _sha256_file(target),
                        "document_count": written,
                    })
                    document_total += written
        unmatched = sorted(wanted_keyspaces - matched_keyspaces)
        if unmatched:
            return err(
                f"these keyspaces were requested and do not exist on this "
                f"cluster: {unmatched}\n"
                f"Nothing was written. A keyspace filter that matches nothing "
                f"would otherwise produce a clean-looking export of zero "
                f"documents -- the caller names a keyspace, gets a fixture "
                f"without it, and nothing says so.\n"
                f"Check the spelling against capella_scopes_list, and note the "
                f"filter takes bucket.scope.collection, not a bare collection "
                f"name.",
                tool="capella_fixture_export",
                requested=sorted(wanted_keyspaces),
                matched=sorted(matched_keyspaces),
            )
        documents_ok = True

    finished = datetime.now(timezone.utc)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "fixture_id": fixture_id,
        "name": args.get("name") or fixture_id,
        "mode": args.get("mode") or "server",
        "created_at": finished.isoformat().replace("+00:00", "Z"),
        "export_started_at": started.isoformat().replace("+00:00", "Z"),
        "export_finished_at": finished.isoformat().replace("+00:00", "Z"),
        "source": {"organization_id": org, "project_id": project,
                   "cluster_id": cluster_id},
        "tags": args.get("tags") or {},
        "structure": structure,
        "gsi_definitions": indexes,
        "eventing_functions": eventing,
        "files": data_files,
        "document_count": document_total,
        "payload_sha256": hashlib.sha256(
            "".join(sorted(f["sha256"] for f in data_files)).encode()
        ).hexdigest() if data_files else None,
        "user_xattrs": [str(x) for x in (args.get("user_xattrs") or [])],
        # FIDELITY IS WHAT ACTUALLY HAPPENED, not what was asked for. A consumer
        # reading this cannot mistake a shape fixture for a dataset, and that is
        # the single most important field in the manifest.
        "fidelity": {
            # NOT `documents_ok`. That flag means "the document phase ran without
            # failing", which is not the same claim as "this fixture contains
            # documents" -- and an export of only-empty collections satisfied the
            # first while a consumer reads the second.
            #
            # Measured 2026-09-14: exporting travel-sample.mcptest.meta, an
            # existing but EMPTY collection, produced documents:0, data_files:0
            # and fidelity.documents:true, with a note reading "Documents
            # exported over the Data API". That is the false green this module's
            # own docstring calls the worst outcome available here, produced by
            # this module.
            "documents": documents_ok and document_total > 0,
            "search_definitions": False,
            # Only the xattrs the caller NAMED. META().xattrs is not enumerable,
            # so anything unlisted was dropped and the manifest must not imply
            # otherwise.
            "xattrs": bool(args.get("user_xattrs")) and documents_ok,
            "structure": True,
            "gsi_definitions": bool(indexes) or not warnings,
            "eventing_functions": True,
            "note": (
                (
                    "include_data was requested and every keyspace exported was "
                    "EMPTY, so this fixture contains no documents. It is a "
                    "faithful export of an empty dataset, which is a legitimate "
                    "thing to have and is NOT a dataset: fidelity.documents is "
                    "false for that reason, not because anything failed."
                )
                if documents_ok and document_total == 0 else
                (
                    "Documents exported over the Data API. Search index "
                    "definitions are still NOT present. CAS is not preserved by "
                    "any documented Capella API, and in server mode system "
                    "xattrs (including _sync) are not readable, so a "
                    "mobile-synced dataset needs mode=mobile."
                )
                if documents_ok else
                "Structure-only export. Documents, Search index definitions and "
                "xattrs are NOT present: they require the Data API and a cluster "
                "access credential. This fixture describes a shape, not a dataset."
            ),
        },
    }
    if warnings:
        manifest["warnings"] = warnings

    try:
        root.mkdir(parents=True, exist_ok=True)
        (root / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
    except OSError as exc:
        return err(f"could not write the fixture: {exc}",
                   tool="capella_fixture_export", fixture_path=str(root))

    result = {
        "fixture_path": str(root),
        "fixture_id": fixture_id,
        "manifest": str(root / "manifest.json"),
        "buckets": len(structure),
        "collections": sum(len(sc.get("collections") or [])
                           for b in structure for sc in b.get("scopes") or []),
        "gsi_definitions": len(indexes),
        "eventing_functions": len(eventing),
        "documents": document_total,
        "data_files": len(data_files),
        "fidelity": manifest["fidelity"],
    }
    if warnings:
        result["warnings"] = warnings
    return ok(result)


#: The only manifest mode this importer can honour.
#:
#: A 'mobile' fixture carries _sync metadata that only the App Services bulk API
#: can replay. Loading one over SQL++ would write the documents and silently drop
#: the sync metadata, producing a cluster that looks populated and cannot serve a
#: single mobile client. Refusing is the only honest option until the mobile path
#: exists.
_IMPORT_MODE_SUPPORTED = "server"

#: Rows per UPSERT statement. Chosen for the Data API's payload cap rather than
#: for throughput: each row carries a whole document, so a large batch can exceed
#: the request limit on a fixture of fat documents long before it exceeds the
#: statement limit on a fixture of thin ones.
_IMPORT_BATCH_ROWS = 100

def _load_documents(source: pathlib.Path, base: str, credential: tuple[str, str],
                    parts: tuple[str, str, str]) -> tuple[int, list[str], int, str]:
    """Load one JSON Lines payload into one keyspace.

    Returns (loaded, per-document failures, expiries dropped, fatal reason).

    STREAMS. The payload is read a line at a time and handed to a bounded pool
    rather than loaded into memory: a fixture is allowed to be larger than the
    process, and an importer that reads a 4 GB file into a list to write it one
    document at a time has chosen the worst of both.

    A FATAL REASON STOPS THE KEYSPACE. Twenty consecutive-ish failures means the
    credential, the privilege or the collection is wrong, and continuing would
    turn one diagnosable error into a hundred thousand identical ones.
    """
    from concurrent.futures import ThreadPoolExecutor

    bucket, scope, collection = parts
    loaded = 0
    failures: list[str] = []
    expiries_dropped = 0

    def write(row: dict) -> tuple[str, int]:
        key = row.get("id")
        if not key:
            return "a row carries no id", 0
        # EXPIRY IS NOT SENT. The fixture records META().expiration as an absolute
        # Unix timestamp, and how this endpoint accepts one -- query parameter,
        # header, or not at all -- was NOT among the things probe_data_api_kv.py
        # measured. Sending a guessed parameter would either be ignored silently
        # or set the wrong expiry, and a document that expires at the wrong time
        # is worse than one that does not expire. The caller is told the count.
        dropped = 1 if isinstance(row.get("exp"), int) and row["exp"] > 0 else 0
        reason = _put_document(base, credential, bucket, scope, collection,
                               key, row.get("doc"))
        return reason, dropped

    try:
        with source.open("r", encoding="utf-8") as handle:
            with ThreadPoolExecutor(max_workers=_IMPORT_CONCURRENCY) as pool:
                batch: list[dict] = []
                for number, line in enumerate(handle, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        batch.append(json.loads(line))
                    except ValueError as exc:
                        return loaded, failures, expiries_dropped, (
                            f"line {number} of {source.name} is not JSON: {exc}"
                        )
                    if len(batch) >= _IMPORT_CONCURRENCY:
                        for reason, dropped in pool.map(write, batch):
                            expiries_dropped += dropped
                            if reason:
                                failures.append(reason)
                            else:
                                loaded += 1
                        batch = []
                        if len(failures) >= _IMPORT_FAILURE_LIMIT:
                            return loaded, failures, expiries_dropped, (
                                f"stopped after {len(failures)} failures -- the "
                                f"first was: {failures[0]}"
                            )
                if batch:
                    for reason, dropped in pool.map(write, batch):
                        expiries_dropped += dropped
                        if reason:
                            failures.append(reason)
                        else:
                            loaded += 1
    except OSError as exc:
        return loaded, failures, expiries_dropped, f"{source.name}: {exc}"

    return loaded, failures, expiries_dropped, ""


def _remap_bucket(source_bucket: str, keyspace_map: dict) -> str:
    """The bucket a recorded bucket maps onto under ``keyspace_map``.

    Factored out because this loop was written twice, three lines apart, and a
    fix applied to one copy would not have reached the other.
    """
    for source_keyspace, target_keyspace in keyspace_map.items():
        if source_keyspace.split(".", 1)[0] == source_bucket:
            return target_keyspace.split(".", 1)[0]
    return source_bucket


def _remap_triple(bucket: str, scope: str, collection: str,
                  keyspace_map: dict) -> tuple[str, str, str]:
    """Map a recorded (bucket, scope, collection) onto its import target.

    THE WHOLE KEYSPACE, NOT JUST THE BUCKET. The structure step used to take
    the scope and collection verbatim out of the manifest and remap only the
    bucket, so a keyspace_map of

        travel-sample.inventory.airline -> travel-sample.roundtrip.airline

    created NOTHING: the bucket rewrote to itself, `inventory` already existed,
    and the `roundtrip` scope was never made. The document step, which has
    always used the full remap, then wrote into a scope that did not exist.

    MEASURED 2026-09-14 on a live Capella round trip: 24 consecutive
    404 ScopeNotFound, `imported: false`, 0 of 188 documents loaded. The
    Enterprise Edition importer carried the same defect and it is already fixed
    there; this is its twin, and it only shows when source and target share a
    bucket -- which is why a round trip into a different bucket passed.

    Falls back to the bucket-only remap when the map has no entry for this
    keyspace, which is the common case: most recorded collections are not being
    retargeted at all.
    """
    mapped = _remap_keyspace(f"{bucket}.{scope}.{collection}", keyspace_map)
    parts = _split_keyspace(mapped)
    if parts:
        return parts
    return (_remap_bucket(bucket, keyspace_map), scope, collection)


def _import(args: dict) -> list[TextContent]:
    """Import a fixture into a Capella cluster.

    IMPLEMENTED 2026-09-14. This refused for the whole life of the module, and
    the refusal was correct while the Data API layer did not exist: "a fixture
    that reports success with no documents in it is the worst outcome available
    here". The read path is now proven end to end -- export wrote 188 documents
    and capella_fixture_verify counted 188 on the cluster -- so the write path
    has something to be checked against.

    ORDER OF OPERATIONS, and why this order:

      1. Integrity FIRST, before a single call to the cluster. Every recorded
         hash is recomputed from the bytes on disk. A fixture whose files have
         changed since it was written is not a fixture, and finding that out
         after creating three buckets is finding out too late.
      2. Mode. A 'mobile' manifest is refused outright rather than loaded
         without its sync metadata.
      3. Guardrails, through the same functions every other destructive Capella
         tool uses -- project allowlist, and the name prefix on every bucket
         this call would CREATE. Buckets that already exist are not prefix
         checked, because the prefix rule governs what this server creates.
      4. Structure, then documents, then indexes. Documents before indexes is
         deliberate: building an index over a populated collection is one pass,
         while loading into an already-built index pays the maintenance cost on
         every batch.
      5. Indexes are created deferred and built in one BUILD INDEX per keyspace,
         then polled until online. An index that exists but is not online makes
         the cluster look slow in a way that reads as a Couchbase performance
         problem, which is why this tool's own description calls the build gate
         not optional.

    PARTIAL SUCCESS IS A NORMAL OUTCOME and is reported per step and per
    keyspace. It is never collapsed into a single status: "it failed" tells an
    operator nothing about whether the documents landed.

    NOT VERIFIED AGAINST A LIVE CLUSTER AT THE TIME OF WRITING. The read path
    was; this write path was implemented against the same API surface but has
    not yet been run end to end. Anything it reports about a live cluster should
    be confirmed with capella_fixture_verify --cluster_id, which recomputes the
    counts independently rather than believing this tool's own report.
    """
    from . import environment as _env  # local imports: avoid a package cycle
    from . import guardrails as g

    try:
        directory = _resolve_under_root(
            args.get("fixture_path"), field="fixture_path",
            tool="capella_fixture_import",
        )
    except ValueError as exc:
        return err(str(exc), tool="capella_fixture_import")
    if directory.name == "manifest.json":
        directory = directory.parent

    entry = _read_manifest(directory)
    if not entry.get("readable"):
        return err(entry.get("error", "manifest could not be read"),
                   tool="capella_fixture_import", fixture_path=str(directory))
    manifest = entry["manifest"]

    _schema_why = _schema_problem(manifest.get("schema"))
    if _schema_why:
        return err(
            _schema_why.replace("verifiable", "importable"),
            tool="capella_fixture_import", fixture_path=str(directory),
        )

    # ── 1. integrity, before touching the cluster ────────────────────────
    checks, problems, _payload = _fixture_integrity(directory, manifest)
    if problems:
        return err(
            "the fixture does not verify, so NOTHING was imported:\n  - "
            + "\n  - ".join(problems)
            + "\nRun capella_fixture_verify for the full report. A fixture whose "
              "bytes have changed since it was written is not a fixture, and "
              "importing one would put unlabelled data on a cluster.",
            tool="capella_fixture_import", fixture_path=str(directory),
            files_checked=checks,
        )

    # ── 2. mode ──────────────────────────────────────────────────────────
    mode = str(manifest.get("mode") or "server")
    if mode != _IMPORT_MODE_SUPPORTED:
        return err(
            f"this fixture's mode is {mode!r} and only {_IMPORT_MODE_SUPPORTED!r} "
            f"can be imported. A mobile fixture carries _sync metadata that only "
            f"the App Services bulk API can replay; loading it over SQL++ would "
            f"write the documents and drop the sync metadata, producing a cluster "
            f"that looks populated and cannot serve a single mobile client.",
            tool="capella_fixture_import", fixture_path=str(directory),
        )

    # ── 3. context and guardrails ────────────────────────────────────────
    try:
        org, project, policy = _env._resolve_context(args)
    except Exception as exc:
        return err(str(exc), tool="capella_fixture_import")

    cluster_id = str(args.get("cluster_id") or "").strip()
    if not cluster_id:
        return err("cluster_id is required", tool="capella_fixture_import")

    keyspace_map = args.get("keyspace_map") or {}
    if not isinstance(keyspace_map, dict):
        return err("keyspace_map must be an object of "
                   "bucket.scope.collection -> bucket.scope.collection",
                   tool="capella_fixture_import")
    # VALUES MUST ALREADY BE STRINGS. str(v) on anything else produces a
    # plausible-looking target keyspace out of a Python repr -- "{'inventory':
    # {...}}" -- and this operation writes to somebody's cluster, so a garbage
    # mapping is worse than a refusal.
    #
    # MEASURED 2026-09-14: scripts/dump_tool.py's dotted -a syntax turns
    #   -a "keyspace_map.travel-sample.inventory.airline=..."
    # into {"travel-sample": {"inventory": {"airline": "..."}}}, because it
    # reads every dot as nesting. The KEY here is a whole keyspace, dots
    # included, so that spelling cannot express it at all. Use --args-json.
    nested = sorted(k for k, v in keyspace_map.items() if not isinstance(v, str))
    if nested:
        return err(
            f"keyspace_map values must be keyspace STRINGS, and these are not: "
            f"{nested}.\n"
            f"A keyspace_map key is a WHOLE keyspace including its dots -- "
            f"{{'bucket.scope.collection': 'bucket.scope.collection'}} -- so a "
            f"nested object here almost certainly came from a dotted "
            f"command-line argument, which reads every dot as a level of "
            f"nesting and cannot express a key that contains one.\n"
            f"Pass the mapping with scripts/dump_tool.py --args-json instead. "
            f"Nothing was imported.",
            tool="capella_fixture_import",
        )
    keyspace_map = {str(k): str(v) for k, v in keyspace_map.items()}

    try:
        g.assert_project_allowed(project, policy)
    except Exception as exc:
        return err(str(exc), tool="capella_fixture_import")

    ids = {"organization_id": org, "project_id": project, "cluster_id": cluster_id}

    structure = manifest.get("structure")
    if not isinstance(structure, list):
        structure = []

    # Which buckets would this call CREATE? Only those get the prefix check: the
    # rule governs what this server brings into existence, not what it finds.
    try:
        existing_buckets = _env._items(
            _env._invoke("capella_buckets_list", ids,
                         composite="capella_fixture_import")
        )
    except Exception as exc:
        return err(f"could not list buckets on the target: {exc}",
                   tool="capella_fixture_import")
    existing_by_name = {str(b.get("name") or ""): b for b in existing_buckets}

    planned_buckets: list[str] = []
    for bucket in structure:
        source_name = str(bucket.get("name") or "")
        if not source_name:
            continue
        target_name = _remap_bucket(source_name, keyspace_map)
        if target_name not in planned_buckets:
            planned_buckets.append(target_name)

    for name in planned_buckets:
        if name in existing_by_name:
            continue
        try:
            g.assert_name_allowed(name, policy)
        except Exception as exc:
            return err(
                f"{exc}\nNothing was imported. This bucket does not exist on the "
                f"target, so importing would CREATE it, and a bucket created "
                f"without the configured prefix could never be torn down by this "
                f"server.",
                tool="capella_fixture_import",
            )

    steps: list[dict] = []
    skipped_system_scopes: list[str] = []
    created_buckets: list[str] = []
    created_scopes: list[str] = []
    created_collections: list[str] = []
    step_problems: list[str] = []

    # ── 4. structure ─────────────────────────────────────────────────────
    bucket_ids: dict[str, str] = {}
    for bucket in structure:
        source_name = str(bucket.get("name") or "")
        if not source_name:
            continue
        target_name = _remap_bucket(source_name, keyspace_map)

        found = existing_by_name.get(target_name)
        if found is None:
            body = {"name": target_name,
                    "type": bucket.get("type") or "couchbase",
                    "storageBackend": bucket.get("storageBackend") or "couchstore",
                    "memoryAllocationInMb": bucket.get("memoryAllocationInMb") or 100}
            try:
                created = _env._invoke("capella_bucket_create", ids, body=body,
                                       composite="capella_fixture_import")
            except Exception as exc:
                step_problems.append(f"bucket {target_name} could not be created: {exc}")
                continue
            created_buckets.append(target_name)
            bucket_ids[target_name] = str(
                (created or {}).get("id") if isinstance(created, dict) else ""
            ) or target_name
        else:
            bucket_ids[target_name] = str(found.get("id") or target_name)

        bucket_ref = dict(ids, bucket_id=bucket_ids[target_name])

        for scope in bucket.get("scopes") or []:
            scope_name = str(scope.get("name") or "")
            if not scope_name:
                continue
            # A SYSTEM SCOPE IS NOT THE FIXTURE'S TO CREATE. Capella makes
            # `_system` itself and refuses any attempt to add one:
            #
            #   422 code 11006 "A scope name can not start with an underscore
            #                   or percentage."
            #
            # MEASURED 2026-09-14. The exporter records every scope it sees,
            # `_system` included, so the importer dutifully tried to create it
            # and collected a problem on every single run -- enough to set
            # imported:false on an import that had otherwise loaded all 188
            # documents correctly. A tool that always reports a failure it
            # cannot avoid trains its reader to ignore the failures.
            #
            # The underscore rule is Capella's, not a guess: `_default` was
            # already skipped for the same reason, one case at a time. This
            # covers the family.
            if scope_name.startswith(("_", "%")):
                skipped_system_scopes.append(f"{target_name}.{scope_name}")
                scope_ref = dict(bucket_ref, scope_name=scope_name)
                for collection in scope.get("collections") or []:
                    collection_name = str(collection.get("name") or "")
                    if collection_name:
                        skipped_system_scopes.append(
                            f"{target_name}.{scope_name}.{collection_name}"
                        )
                continue
            # THE TARGET IS THE REMAPPED KEYSPACE, not the recorded one with a
            # rewritten bucket. See _remap_triple for the failure this fixes.
            plan: list[dict[str, Any]] = []
            recorded = [
                c for c in (scope.get("collections") or [])
                if str(c.get("name") or "")
            ]
            if not recorded:
                # A scope with no collections still has to exist.
                plan.append({
                    "source": f"{source_name}.{scope_name}",
                    "bucket": target_name,
                    "scope": scope_name,
                    "collection": None,
                    "record": {},
                })
            for collection in recorded:
                collection_name = str(collection.get("name") or "")
                mapped_bucket, mapped_scope, mapped_collection = _remap_triple(
                    source_name, scope_name, collection_name, keyspace_map
                )
                plan.append({
                    "source": f"{source_name}.{scope_name}.{collection_name}",
                    "bucket": mapped_bucket,
                    "scope": mapped_scope,
                    "collection": mapped_collection,
                    "record": collection,
                })

            scopes_attempted: set[str] = set()
            for entry in plan:
                if entry["bucket"] != target_name:
                    # REFUSE rather than guess. This bucket's id was resolved
                    # above; another bucket's has not been, and inventing one
                    # addresses the wrong cluster object.
                    step_problems.append(
                        f"keyspace_map sends {entry['source']} to bucket "
                        f"{entry['bucket']!r}, which is not the bucket this "
                        f"structure entry resolved to ({target_name!r}). Map "
                        f"the bucket itself instead."
                    )
                    continue

                target_scope = str(entry["scope"])
                if target_scope != "_default" and target_scope not in scopes_attempted:
                    scopes_attempted.add(target_scope)
                    try:
                        _env._invoke("capella_scope_create", bucket_ref,
                                     body={"name": target_scope},
                                     composite="capella_fixture_import")
                        created_scopes.append(f"{target_name}.{target_scope}")
                    except Exception as exc:
                        # An existing scope is not a failure -- this tool is
                        # explicitly re-runnable. Anything else is.
                        if "already exists" not in str(exc).lower():
                            step_problems.append(
                                f"scope {target_name}.{target_scope} could not "
                                f"be created: {exc}"
                            )
                            continue

                target_collection = entry["collection"]
                if not target_collection or target_collection == "_default":
                    continue
                scope_ref = dict(bucket_ref, scope_name=target_scope)
                body = {"name": target_collection}
                if entry["record"].get("maxTTL"):
                    body["maxTTL"] = entry["record"]["maxTTL"]
                try:
                    _env._invoke("capella_collection_create", scope_ref, body=body,
                                 composite="capella_fixture_import")
                    created_collections.append(
                        f"{target_name}.{target_scope}.{target_collection}"
                    )
                except Exception as exc:
                    if "already exists" not in str(exc).lower():
                        step_problems.append(
                            f"collection {target_name}.{target_scope}."
                            f"{target_collection} could not be created: {exc}"
                        )

    structure_step: dict[str, Any] = {
        "step": "structure",
        "buckets_created": created_buckets,
        "scopes_created": created_scopes,
        "collections_created": created_collections,
        "note": (
            "Existing buckets, scopes and collections are REUSED, not "
            "recreated. This tool is re-runnable by design."
        ),
    }
    if skipped_system_scopes:
        structure_step["system_scopes_skipped"] = skipped_system_scopes
        structure_step["system_scopes_note"] = (
            "Capella creates and owns these, and refuses any attempt to make "
            "one (422 code 11006). They are recorded by the exporter because it "
            "records what it finds, and skipped here because they are not the "
            "fixture's to create. This is NOT a problem and does not affect "
            "`imported`."
        )
    steps.append(structure_step)

    # ── 5. documents ─────────────────────────────────────────────────────
    #
    # Over the Data API's KV document endpoint, NOT SQL++. See _DOCUMENT_PATH for
    # the measurement that established it and for why the SQL++ route was removed.
    files = manifest.get("files")
    if not isinstance(files, list):
        files = []

    documents_loaded = 0
    document_report: list[dict] = []
    base = ""
    credential: tuple[str, str] = ("", "")
    if files:
        base, why = _data_api_base(ids)
        credential, cred_why = _data_api_credential()
        blocker = why or cred_why
        if blocker:
            return err(
                f"the structure was created and the documents CANNOT be loaded, so "
                f"this import is incomplete and the target must not be treated as a "
                f"populated environment.\n{blocker}\n"
                f"An import that creates empty collections and reports success is "
                f"the failure this family exists to prevent. Fix the Data API "
                f"access and re-run -- every step of this tool is re-runnable.",
                tool="capella_fixture_import",
                steps=steps,
                structure_created=True,
                documents_loaded=0,
            )

        for record in files:
            if not isinstance(record, dict):
                continue
            relative = str(record.get("path") or "")
            source_keyspace = str(record.get("keyspace") or "")
            target_keyspace = _remap_keyspace(source_keyspace, keyspace_map)
            report: dict[str, Any] = {
                "keyspace": target_keyspace,
                "source_keyspace": source_keyspace,
                "expected": record.get("document_count"),
                "loaded": 0,
            }
            parts = _split_keyspace(target_keyspace)
            if parts is None:
                report["error"] = (
                    f"{target_keyspace!r} is not a bucket.scope.collection keyspace"
                )
                step_problems.append(report["error"])
                document_report.append(report)
                continue

            loaded, failures, expiries_dropped, fatal = _load_documents(
                directory / relative, base, credential, parts
            )
            report["loaded"] = loaded
            documents_loaded += loaded
            if expiries_dropped:
                # NOT A FOOTNOTE. A document that carried a TTL and arrives without
                # one never expires, so the target diverges from the fixture's
                # source over time rather than at import.
                report["expiries_not_restored"] = expiries_dropped
            if fatal:
                report["error"] = fatal
                step_problems.append(f"{target_keyspace}: {fatal}")
            elif failures:
                report["failures"] = failures[:10]
                report["failure_count"] = len(failures)
                step_problems.append(
                    f"{target_keyspace}: {len(failures)} document(s) failed to load"
                )
            elif isinstance(record.get("document_count"), int) and \
                    loaded != record["document_count"]:
                report["error"] = (
                    f"loaded {loaded} of {record['document_count']} documents"
                )
                step_problems.append(f"{target_keyspace}: {report['error']}")
            document_report.append(report)

    dropped_total = sum(
        r.get("expiries_not_restored") or 0 for r in document_report
    )
    document_step: dict[str, Any] = {
        "step": "documents",
        "keyspaces": document_report,
        "documents_loaded": documents_loaded,
    }
    if dropped_total:
        document_step["WARNING"] = (
            f"{dropped_total} document(s) carried an expiry in the fixture and were "
            f"written WITHOUT one, because how this endpoint accepts an expiry has "
            f"not been measured and this module does not ship unmeasured "
            f"parameters. Those documents will not expire on the target. If the "
            f"scenario depends on expiry, this target is wrong for it."
        )
    steps.append(document_step)

    # ── 6. indexes ───────────────────────────────────────────────────────
    build_indexes = bool(args.get("build_indexes", True))
    definitions = manifest.get("gsi_definitions")
    if not isinstance(definitions, list):
        definitions = []

    index_report: list[dict] = []
    seen_statements: set[str] = set()
    if definitions and not base:
        base, why = _data_api_base(ids)
        credential, cred_why = _data_api_credential()
        if why or cred_why:
            step_problems.append(
                f"index definitions could not be applied: {why or cred_why}"
            )
            definitions = []

    for definition in definitions:
        if not isinstance(definition, dict):
            continue
        raw_name = str(definition.get("indexName") or definition.get("name") or "")
        # A replica entry is the SAME index. Creating it twice is an error, not
        # a second index -- see _REPLICA_SUFFIX.
        if _REPLICA_SUFFIX.search(raw_name):
            continue
        statement = str(definition.get("definition") or "")
        if not statement:
            index_report.append({"name": raw_name, "created": False,
                                 "error": "no definition statement recorded"})
            step_problems.append(f"index {raw_name} has no recorded definition")
            continue

        statement, stripped = _strip_index_nodes(statement)
        statement, why_not = _rewrite_index_keyspace(statement, keyspace_map)
        if why_not:
            index_report.append({"name": raw_name, "created": False,
                                 "error": why_not})
            step_problems.append(f"index {raw_name}: {why_not}")
            continue
        if statement in seen_statements:
            continue
        seen_statements.add(statement)

        record: dict[str, Any] = {"name": _base_index_name(raw_name),
                                  "placement_stripped": stripped}
        try:
            _sql_query(base, credential, statement)
            record["created"] = True
        except RuntimeError as exc:
            message = str(exc)
            if "already exist" in message.lower():
                record.update(created=False, existing=True)
            else:
                record.update(created=False, error=message)
                step_problems.append(f"index {raw_name} could not be created: {exc}")
        index_report.append(record)

    built: list[str] = []
    created_names = [r["name"] for r in index_report if r.get("created")]
    if build_indexes and created_names:
        # BUILD INDEX names a bucket, and the recorded definitions can span
        # several, so the buckets are derived from the data files rather than
        # assumed to be one. A fixture with no data files falls back to the
        # buckets the structure step planned.
        build_buckets: list[str] = []
        for record in files:
            if not isinstance(record, dict):
                continue
            parts = _split_keyspace(
                _remap_keyspace(str(record.get("keyspace") or ""), keyspace_map)
            )
            if parts and parts[0] not in build_buckets:
                build_buckets.append(parts[0])
        if not build_buckets:
            build_buckets = list(planned_buckets)

        names = ", ".join(f"`{n}`" for n in created_names)
        for bucket_name in build_buckets:
            try:
                _sql_query(base, credential,
                           f"BUILD INDEX ON `{bucket_name}` ({names})")
                built.append(bucket_name)
            except RuntimeError as exc:
                # An index that belongs to a different bucket is not an error
                # for THIS bucket's build; a real failure is.
                if "not found" in str(exc).lower():
                    continue
                step_problems.append(
                    f"BUILD INDEX on {bucket_name} failed: {exc}"
                )

    index_step: dict[str, Any] = {
        "step": "indexes",
        "indexes": index_report,
        "built_on": built,
        "build_requested": build_indexes,
    }
    if not build_indexes:
        index_step["WARNING"] = (
            "build_indexes=false. The indexes exist as definitions and are NOT "
            "online. THIS TARGET MUST NOT BE USED FOR MEASUREMENT: a load test "
            "against a cluster whose indexes are still deferred produces numbers "
            "that read as a Couchbase performance problem and are an artifact of "
            "this flag."
        )
    steps.append(index_step)

    # ── 7. what this importer does NOT do ────────────────────────────────
    fidelity = manifest.get("fidelity") or {}
    not_applied: list[str] = []
    if manifest.get("eventing_functions"):
        not_applied.append(
            f"{len(manifest['eventing_functions'])} eventing function(s) recorded "
            f"in the fixture were NOT created. Eventing deployment is a three-call "
            f"sequence (create, set code, set state) whose failure modes are not "
            f"yet measured, and a half-deployed function is worse than none."
        )
    if not fidelity.get("search_definitions", False):
        not_applied.append(
            "Search index definitions are not present in the fixture at all -- the "
            "exporter does not capture them yet -- so none were applied."
        )
    if not fidelity.get("xattrs", False):
        not_applied.append(
            "No user xattrs were carried by this fixture, so none were restored."
        )
    not_applied.append(
        "Document EXPIRY is not restored. The fixture records it, and how this "
        "endpoint accepts an expiry was not measured, so it is not sent rather "
        "than guessed -- see _load_documents. Any document that carried a TTL is "
        "on the target without one."
    )

    result: dict[str, Any] = {
        "fixture_path": str(directory),
        "fixture_id": manifest.get("fixture_id"),
        "cluster_id": cluster_id,
        "mode": mode,
        "steps": steps,
        "documents_loaded": documents_loaded,
        "not_applied": not_applied,
        "imported": not step_problems,
        "problems": step_problems,
        "verify_with": (
            "capella_fixture_verify with this fixture_path AND cluster_id. It "
            "recomputes the counts from the cluster rather than believing this "
            "tool's own report, which is the only check that can catch an import "
            "that thought it succeeded."
        ),
    }
    return ok(result)


def _list(args: dict) -> list[TextContent]:
    """List and filter fixtures by manifest tags.

    IMPLEMENTED 2026-09-14. Pure local filesystem work: no cluster contact, no
    credentials, nothing that can fail because of an entitlement or a network.
    That is why it is the first of the four to land — it is the one whose
    correctness can be established completely, and it is the one the original
    requirement actually asked for. "Latest where content-publisher-version =
    1.6" has nothing to match against in a Capella backup; it matches here.

    A manifest that fails to parse is reported as an unreadable entry rather than
    skipped. See _read_manifest.
    """
    try:
        root = _resolve_under_root(
            args.get("root_path"), field="root_path", tool="capella_fixture_list"
        )
    except ValueError as exc:
        return err(str(exc), tool="capella_fixture_list")

    if not root.is_dir():
        return err(
            f"root_path {root} is not a directory. It is the directory that "
            f"CONTAINS fixtures, each of which is its own directory holding a "
            f"manifest.json.",
            tool="capella_fixture_list",
        )

    match_tags = args.get("match_tags") or {}
    exclude_tags = args.get("exclude_tags") or {}
    created_after = _parse_timestamp(args.get("created_after"))
    created_before = _parse_timestamp(args.get("created_before"))

    for label, raw in (("created_after", args.get("created_after")),
                       ("created_before", args.get("created_before"))):
        if raw and _parse_timestamp(raw) is None:
            return err(
                f"{label}={raw!r} is not an ISO-8601 timestamp. A filter that "
                f"cannot be parsed must not silently match everything.",
                tool="capella_fixture_list",
            )

    # WALK, DO NOT GLANCE. The first version looked only at root_path's immediate
    # children, so a caller who pointed it at a repository root -- the obvious
    # thing to do -- got "no fixtures" while fixtures/<id>/manifest.json sat two
    # levels down. Answering "you have none" when the answer is "you have one" is
    # the worst failure available to a listing tool.
    #
    # Bounded at four levels and skipping the directories that make a recursive
    # walk expensive and pointless: a fixture is not inside .git or a virtualenv,
    # and scanning them turns a listing into a disk crawl.
    _SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox",
             ".mypy_cache", ".pytest_cache", ".idea", ".vscode"}
    candidates: list[pathlib.Path] = []
    if (root / "manifest.json").is_file():
        candidates.append(root)
    for current, dirnames, filenames in os.walk(root):
        depth = len(pathlib.Path(current).relative_to(root).parts)
        if depth >= 4:
            dirnames[:] = []
            continue
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP
                             and not d.startswith("."))
        if "manifest.json" in filenames and pathlib.Path(current) != root:
            candidates.append(pathlib.Path(current))

    entries: list[dict] = []
    unreadable: list[dict] = []
    for child in sorted(set(candidates)):
        entry = _read_manifest(child)
        if not entry.get("readable"):
            unreadable.append(entry)
            continue
        entries.append(entry)

    def _keep(entry: dict) -> bool:
        tags = entry.get("tags") or {}
        if not isinstance(tags, dict):
            return False
        for key, value in match_tags.items():
            if str(tags.get(key)) != str(value):
                return False
        for key, value in exclude_tags.items():
            if str(tags.get(key)) == str(value):
                return False
        created = _parse_timestamp(entry.get("created_at"))
        if created_after or created_before:
            # A fixture with no parseable created_at CANNOT satisfy a date
            # filter. Treating it as a match would answer "what did we take last
            # month" with something of unknown age.
            if created is None:
                return False
            if created_after and created < created_after:
                return False
            if created_before and created > created_before:
                return False
        return True

    matched = [e for e in entries if _keep(e)]
    matched.sort(
        key=lambda e: (_parse_timestamp(e.get("created_at"))
                       or datetime.min.replace(tzinfo=timezone.utc)),
        reverse=True,
    )
    if args.get("latest_only") and matched:
        matched = matched[:1]

    for entry in matched:
        entry.pop("manifest", None)

    result: dict[str, Any] = {
        "root_path": str(root),
        "fixtures": matched,
        "matched": len(matched),
        "scanned": len(entries) + len(unreadable),
    }
    if unreadable:
        # NOT an error, and NOT silence. The call succeeded; some directories
        # could not be read, and the caller is told which and why.
        result["unreadable"] = unreadable
        result["note"] = (
            f"{len(unreadable)} fixture director(ies) have a manifest.json that "
            f"could not be read or parsed. They are listed under 'unreadable' "
            f"and are excluded from 'fixtures'."
        )
    return ok(result)


def _cluster_checks(manifest: dict, args: dict) -> dict:
    """Compare a live cluster against the fixture that claims to describe it.

    IMPLEMENTED 2026-09-14. This used to refuse, and the refusal was honest at
    the time: it needed the Data API, which did not exist in this module yet.
    It does now, so the refusal became the only thing standing between a fixture
    and the question that actually matters -- is the cluster the thing the
    fixture says it is?

    TWO CHECKS, both decidable, neither of them a heuristic:

      * DOCUMENT COUNTS. For every data file the manifest names, COUNT(*) on the
        live keyspace must equal the file's recorded document_count. This is the
        check that catches the failure mode the whole fixture design exists to
        prevent: an import that ran, reported success, and loaded a subset.

      * INDEX STATE. Every index the fixture recorded must exist on the cluster
        AND be online. An index whose definition exists but is still building
        makes the cluster look slow in a way that reads as a Couchbase
        performance problem -- this module's own import docstring calls that
        gate not optional, so verify has to be able to check it.

    Index state is read with ONE `system:indexes` query rather than a
    capella_query_index_build_status call per index. That is deliberate: the
    per-index control-plane call needs the index's bucket as a required query
    parameter, which means knowing the shape of the definition objects the
    manifest stored -- and those come straight from a control-plane payload this
    module does not own. system:indexes reports name, keyspace and state
    together, from the data plane the counts already came from, and costs one
    round trip regardless of index count.

    A MISMATCH IS A PROBLEM, NOT A WARNING, consistent with the fixture-side
    checks: the caller gets `verified: false` and the specific numbers.
    """
    from . import environment as _env  # local import: avoids a package cycle

    report: dict[str, Any] = {"performed": False, "problems": []}
    problems: list[str] = report["problems"]

    cluster_id = str(args.get("cluster_id") or "").strip()
    try:
        org, project, _policy = _env._resolve_context(args)
    except Exception as exc:
        report["blocked"] = (
            f"the organization/project context could not be resolved: {exc}"
        )
        return report

    ids = {"organization_id": org, "project_id": project, "cluster_id": cluster_id}
    base, why = _data_api_base(ids)
    credential, cred_why = _data_api_credential()
    blocker = why or cred_why
    if blocker:
        # NOT A PARTIAL PASS. The fixture-side result stands on its own, but the
        # cluster question was asked and was not answered, and saying so is the
        # whole point. Silence here would read as agreement.
        report["blocked"] = (
            f"the cluster could not be checked.\n{blocker}\n"
            f"The fixture-side result is unaffected and complete; it simply does "
            f"not speak about this cluster."
        )
        return report

    report["cluster_id"] = cluster_id
    report["performed"] = True

    # ── document counts ──────────────────────────────────────────────────
    keyspace_checks: list[dict] = []
    files = manifest.get("files")
    if not isinstance(files, list):
        files = []
    for record in files:
        if not isinstance(record, dict):
            continue
        keyspace = str(record.get("keyspace") or "")
        expected = record.get("document_count")
        if not keyspace:
            problems.append(
                f"{record.get('path')!r} records no keyspace, so the cluster "
                f"cannot be checked against it"
            )
            continue
        parts = _split_keyspace(keyspace)
        if parts is None:
            problems.append(
                f"{keyspace!r} is not a bucket.scope.collection keyspace"
            )
            continue
        bucket, scope, collection = parts
        check: dict[str, Any] = {"keyspace": keyspace, "expected": expected}
        try:
            result = _sql_query(
                base, credential,
                f"SELECT COUNT(*) AS n FROM `{bucket}`.`{scope}`.`{collection}`",
            )
        except RuntimeError as exc:
            check.update(ok=False, error=str(exc))
            problems.append(f"{keyspace} could not be counted: {exc}")
            keyspace_checks.append(check)
            continue
        rows = result.get("results") or []
        actual = rows[0].get("n") if rows and isinstance(rows[0], dict) else None
        check["actual"] = actual
        if isinstance(expected, int) and actual != expected:
            check["ok"] = False
            problems.append(
                f"{keyspace} holds {actual} documents on the cluster, the "
                f"fixture holds {expected}"
            )
        else:
            check["ok"] = True
        keyspace_checks.append(check)
    report["keyspaces"] = keyspace_checks

    # ── index state ────────────────────────────────────────────
    definitions = manifest.get("gsi_definitions")
    if not isinstance(definitions, list):
        definitions = []

    # Recorded indexes, COLLAPSED BY BASE NAME. The number of entries sharing a
    # base name is how many copies the control plane enumerated: the index
    # itself plus one per replica.
    recorded: dict[str, int] = {}
    unnamed = 0
    for definition in definitions:
        if not isinstance(definition, dict):
            unnamed += 1
            continue
        raw = str(definition.get("indexName") or definition.get("name") or "")
        name = _base_index_name(raw)
        if not name:
            unnamed += 1
            continue
        recorded[name] = recorded.get(name, 0) + 1

    # `idx.*` rather than a named column list: it returns whatever fields this
    # server version actually carries, so the replica handling below can DETECT
    # a replica column instead of assuming one exists. A SELECT naming a column
    # the server does not have fails the entire query.
    try:
        index_rows = (_sql_query(
            base, credential, "SELECT idx.* FROM system:indexes AS idx",
        ).get("results") or [])
    except RuntimeError as exc:
        report["indexes"] = {"read": False, "error": str(exc)}
        problems.append(
            f"index state could not be read from system:indexes: {exc}\n"
            f"A cluster whose index states are unknown must not be reported "
            f"ready for measurement."
        )
        index_rows = None

    if index_rows is not None:
        on_cluster: dict[str, list[str]] = {}
        keyspace_of: dict[str, str] = {}
        replica_field = ""
        for row in index_rows:
            if not isinstance(row, dict):
                continue
            name = _base_index_name(str(row.get("name") or ""))
            if not name:
                continue
            # KEYSPACE, NOT JUST STATE. Reporting "mcptest_idx_meta is deferred"
            # without saying where it lives is not actionable: the operator's next
            # move is BUILD INDEX, which names a keyspace. Finding that keyspace
            # then costs a round of guessing -- and guessing it from an index
            # DEFINITIONS listing is worse than useless, because that endpoint
            # silently defaults scope and collection to _default and will happily
            # report an empty list for a bucket whose indexes all live elsewhere.
            # system:indexes already carries the answer; this keeps it.
            scope = str(row.get("scope_id") or "_default")
            collection = str(row.get("keyspace_id") or "")
            bucket = str(row.get("bucket_id") or "")
            if not bucket:
                # Pre-collections rows put the bucket in keyspace_id and carry no
                # bucket_id at all, so the fields mean different things depending
                # on which shape arrived.
                bucket, collection = collection, "_default"
            on_cluster.setdefault(name, []).append(str(row.get("state") or ""))
            keyspace_of.setdefault(
                name, f"{bucket}.{scope}.{collection or '_default'}")
            if not replica_field:
                for candidate in ("replica_id", "replicaId"):
                    if candidate in row:
                        replica_field = candidate
                        break

        not_online = [
            {"name": name, "state": state,
             "keyspace": keyspace_of.get(name, "unknown"),
             "build_with": (
                 f"BUILD INDEX ON `{keyspace_of[name].split('.', 2)[0]}`"
                 f".`{keyspace_of[name].split('.', 2)[1]}`"
                 f".`{keyspace_of[name].split('.', 2)[2]}` (`{name}`)"
                 if keyspace_of.get(name, "").count(".") == 2 else ""
             )}
            for name, states in sorted(on_cluster.items())
            for state in states
            if state.lower() != "online"
        ]

        missing: list[str] = []
        for name, copies in sorted(recorded.items()):
            states = on_cluster.get(name)
            if not states:
                missing.append(name)
                problems.append(
                    f"index {name} is recorded in the fixture and does not "
                    f"exist on the cluster"
                )
                continue
            offline = [s for s in states if s.lower() != "online"]
            if offline:
                where = keyspace_of.get(name, "an unknown keyspace")
                problems.append(
                    f"index {name} on {where} is {', '.join(offline)}, not "
                    f"online -- the cluster is not yet performance-comparable "
                    f"to the fixture's source"
                )

        details: dict[str, Any] = {
            "read": True,
            "rows_on_cluster": len(index_rows),
            "distinct_on_cluster": len(on_cluster),
            "recorded_in_fixture": len(recorded),
            "recorded_definition_entries": len(definitions),
            "missing_on_cluster": missing,
            "not_online": not_online,
        }

        # REPLICA COUNTS ARE REPORTED ONLY IF THE SERVER ACTUALLY NAMES THEM.
        # Whether system:indexes carries a replica column varies by version, so
        # this looks for one rather than assuming. When there is none, the gap
        # is stated: an unchecked property described as checked is exactly the
        # false green this tool exists to prevent.
        if replica_field:
            mismatched = [
                {"name": name, "expected_copies": copies,
                 "copies_on_cluster": len(on_cluster.get(name) or [])}
                for name, copies in sorted(recorded.items())
                if on_cluster.get(name) and len(on_cluster[name]) != copies
            ]
            details["replica_field"] = replica_field
            details["replica_mismatches"] = mismatched
            for entry in mismatched:
                problems.append(
                    f"index {entry['name']} has {entry['copies_on_cluster']} "
                    f"cop(ies) on the cluster, the fixture recorded "
                    f"{entry['expected_copies']} (the index plus its replicas)"
                )
        else:
            details["replicas_checked"] = False
            details["replicas_note"] = (
                "system:indexes on this cluster carries no replica column, so "
                "replica COUNT was not verified -- only that each recorded "
                "index exists and is online. A fixture whose source carried "
                "replicas can therefore be satisfied by a cluster with fewer, "
                "which changes failover behaviour and read throughput."
            )

        if unnamed:
            # NOT SILENTLY SKIPPED. An unnameable definition is a gap in what
            # this check covers, and a coverage gap reported as a pass is the
            # failure this module exists to avoid.
            details["unnamed_definitions"] = unnamed
            problems.append(
                f"{unnamed} recorded index definition(s) carry no recognisable "
                f"name, so their state on the cluster was NOT checked"
            )
        if not_online and not recorded:
            problems.append(
                f"{len(not_online)} index(es) on the cluster are not online"
            )
        report["indexes"] = details

    report["verified"] = not problems
    return report


def _verify(args: dict) -> list[TextContent]:
    """Verify a fixture, and optionally a cluster imported from it.

    IMPLEMENTED 2026-09-14, both cases. Fixture-alone needs nothing but the
    filesystem. The cluster case additionally needs the Data API and a cluster
    access credential, and is implemented in _cluster_checks below; when those
    are not configured it reports blocked rather than quietly passing.

    Fixture alone, all of it local and all of it decidable:
      * the manifest parses and declares the schema this module writes
      * every data file named in the manifest exists
      * each file's sha256 recomputes to the recorded value
      * each file's line count matches the recorded document_count
      * the payload hash recomputes over the per-file hashes

    A MISMATCH IS NOT A WARNING. A fixture whose bytes have changed since it was
    written is not a fixture, it is an unlabelled dataset, and the whole point of
    the manifest is that it can say so.
    """
    try:
        fixture_path = _resolve_under_root(
            args.get("fixture_path"), field="fixture_path",
            tool="capella_fixture_verify",
        )
    except ValueError as exc:
        return err(str(exc), tool="capella_fixture_verify")

    directory = fixture_path.parent if fixture_path.name == "manifest.json" else fixture_path
    entry = _read_manifest(directory)
    if not entry.get("readable"):
        return err(entry.get("error", "manifest could not be read"),
                   tool="capella_fixture_verify", fixture_path=str(directory))

    manifest = entry["manifest"]
    problems: list[str] = []

    schema = manifest.get("schema")
    schema_why = _schema_problem(schema)
    if schema_why:
        problems.append(schema_why)

    checks, file_problems, payload_sha = _fixture_integrity(directory, manifest)
    problems.extend(file_problems)
    files = manifest.get("files") or []

    result: dict[str, Any] = {
        "fixture_path": str(directory),
        "schema": schema,
        "fixture_id": manifest.get("fixture_id"),
        "tags": manifest.get("tags") or {},
        "mode": manifest.get("mode"),
        "created_at": manifest.get("created_at"),
        "files_checked": checks,
        "payload_sha256": payload_sha,
        "verified": not problems,
        "problems": problems,
    }
    if not files:
        result["note"] = (
            "The manifest names no data files. A structure-only fixture is a "
            "legitimate thing to have, but it cannot be verified as carrying "
            "data, and it must not be presented as a dataset."
        )

    if args.get("cluster_id"):
        cluster = _cluster_checks(manifest, args)
        result["cluster_verification"] = cluster
        # THE TOP-LEVEL VERDICT COVERS BOTH QUESTIONS WHEN BOTH WERE ASKED.
        # A caller that passed cluster_id and reads verified:true has been told
        # the cluster matches; leaving the flag green while the cluster check
        # failed would be the exact false green this tool exists to prevent.
        if cluster.get("problems"):
            result["verified"] = False
            problems.extend(cluster["problems"])
        elif not cluster.get("performed"):
            result["verified"] = False
            problems.append(
                "cluster_id was supplied and the cluster was NOT checked: "
                + str(cluster.get("blocked") or "reason unrecorded")
            )
    return ok(result)


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
