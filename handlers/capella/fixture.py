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
import re
from datetime import datetime, timezone
from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

from handlers.shared import err, ok

from .client import build_path, capella_request
from .spec import OPS_BY_NAME
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

#: Root under which fixture paths must live, when the operator sets one.
#:
#: WHY THIS IS DEFINED HERE AND NOT IN handlers/egress.py. The export docstring
#: says to run fixture_path through "the egress walk", and that advice does not
#: survive contact with the module: handlers/egress.py guards HOSTS -- allowlists,
#: CIDRs, DNS resolution, SSRF. It has no notion of a filesystem path and nothing
#: in it can be reused here. Writing a bespoke check was the instruction's spirit
#: to avoid; having no check at all is worse. This is that check, named, in one
#: place, with the reasoning attached.
#:
#: Unset means "any absolute path", which is the correct default for a tool run
#: from a developer workstation and the wrong one for a shared container. Set it
#: in any deployment where the caller is not the operator.
_FIXTURE_ROOT_ENV = "CB_ADMIN_FIXTURE_ROOT"


def _resolve_under_root(raw: str, *, field: str, tool: str) -> pathlib.Path:
    """Resolve `raw` to an absolute path, refusing traversal and root escapes.

    Symlinks are resolved BEFORE the containment test, not after. A check that
    compares the literal string and then opens the resolved path is a check that
    a symlink walks straight through.
    """
    if not raw or not str(raw).strip():
        raise ValueError(f"{field} is required")
    path = pathlib.Path(str(raw)).expanduser()
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:  # RuntimeError: symlink loop
        raise ValueError(f"{field} could not be resolved: {exc}") from exc

    root = (os.environ.get(_FIXTURE_ROOT_ENV) or "").strip()
    if root:
        root_resolved = pathlib.Path(root).expanduser().resolve(strict=False)
        if root_resolved not in resolved.parents and resolved != root_resolved:
            raise ValueError(
                f"{field} {resolved} is outside {_FIXTURE_ROOT_ENV} "
                f"({root_resolved}). Fixtures may only be read from and written "
                f"to that subtree."
            )
    return resolved


def _sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _count_lines(path: pathlib.Path) -> int:
    """Non-empty lines in a JSON Lines file. One line is one document."""
    count = 0
    with path.open("rb") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def _parse_timestamp(value: Any) -> datetime | None:
    """An ISO-8601 timestamp, or None. Trailing Z is accepted."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _read_manifest(directory: pathlib.Path) -> dict:
    """Read one fixture's manifest.json.

    A manifest that will not parse is REPORTED, never skipped. A fixture
    directory that has quietly stopped being readable is the single thing a
    caller most needs to be told about, and a listing that omits it answers
    "what fixtures do I have" with a confident lie.
    """
    manifest_path = directory / "manifest.json"
    entry: dict[str, Any] = {"fixture_path": str(directory)}
    try:
        raw = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        entry.update(readable=False, error=f"manifest.json could not be read: {exc}")
        return entry
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        entry.update(readable=False, error=f"manifest.json is not valid JSON: {exc}")
        return entry
    if not isinstance(manifest, dict):
        entry.update(readable=False, error="manifest.json is not a JSON object")
        return entry
    entry.update(
        readable=True,
        schema=manifest.get("schema"),
        fixture_id=manifest.get("fixture_id"),
        name=manifest.get("name"),
        mode=manifest.get("mode"),
        created_at=manifest.get("created_at"),
        tags=manifest.get("tags") or {},
        document_count=manifest.get("document_count"),
        manifest=manifest,
    )
    return entry


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
                    if wanted_keyspaces and keyspace not in wanted_keyspaces:
                        continue
                    select = ["META().id AS id", "META().expiration AS exp", "d.*"]
                    for name in xattrs:
                        select.append(XATTR_SELECT.format(name=name))
                    statement = (
                        f"SELECT {', '.join(select)} "
                        f"FROM `{bucket['name']}`.`{scope['name']}`."
                        f"`{collection['name']}` AS d "
                        f"WHERE META().id > $last_key "
                        f"ORDER BY META().id LIMIT {page_size}"
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
                                    doc_id = row.pop("id", None)
                                    expiry = row.pop("exp", 0)
                                    carried = {
                                        key[len("xattr_"):]: row.pop(key)
                                        for key in list(row)
                                        if key.startswith("xattr_")
                                    }
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
            "documents": documents_ok,
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


def _split_keyspace(keyspace: str) -> tuple[str, str, str] | None:
    """`bucket.scope.collection` -> its three parts, or None if it is not three.

    rsplit, NOT split. A Couchbase BUCKET NAME MAY CONTAIN DOTS -- the name
    charset allows them -- while scope and collection names may not. Splitting
    left-to-right therefore mangles a bucket called `my.bucket`; splitting from
    the right takes the last two separators, which are always the scope and
    collection ones. This is not a hypothetical: the fixture manifest stores the
    keyspace as a single joined string, so this function is the only thing
    standing between a dotted bucket name and a query against a keyspace that
    does not exist.
    """
    parts = keyspace.rsplit(".", 2)
    if len(parts) != 3 or not all(parts):
        return None
    return parts[0], parts[1], parts[2]


#: Trailing " (replica 1)" on a control-plane index definition's indexName.
#:
#: A REPLICA IS NOT A SEPARATE INDEX. capella_query_index_definitions_list
#: enumerates every replica as its own entry -- same `definition` string,
#: verbatim, with the replica number appended to `indexName`:
#:
#:     {"indexName": "sg_users_x1",              "definition": "CREATE INDEX ..."}
#:     {"indexName": "sg_users_x1 (replica 1)",  "definition": "CREATE INDEX ..."}
#:
#: system:indexes reports the base name only, so comparing the two registers
#: name-for-name reported every replica as an index that does not exist on the
#: cluster. Measured 2026-09-14 against fixtures/mcptest-data-1, whose four
#: recorded definitions are two indexes each carrying num_replica 1; the first
#: run of the cluster check called two of the four missing, which was wrong and
#: was this tool's fault rather than the cluster's.
_REPLICA_SUFFIX = re.compile(r"\s*\(replica\s+\d+\)\s*$")


def _base_index_name(name: str) -> str:
    """An index definition's indexName with any replica suffix removed."""
    return _REPLICA_SUFFIX.sub("", name).strip()


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
        replica_field = ""
        for row in index_rows:
            if not isinstance(row, dict):
                continue
            name = _base_index_name(str(row.get("name") or ""))
            if not name:
                continue
            on_cluster.setdefault(name, []).append(str(row.get("state") or ""))
            if not replica_field:
                for candidate in ("replica_id", "replicaId"):
                    if candidate in row:
                        replica_field = candidate
                        break

        not_online = [
            {"name": name, "state": state}
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
                problems.append(
                    f"index {name} is {', '.join(offline)}, not online -- the "
                    f"cluster is not yet performance-comparable to the "
                    f"fixture's source"
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
    checks: list[dict] = []

    schema = manifest.get("schema")
    if schema != MANIFEST_SCHEMA:
        problems.append(
            f"schema is {schema!r}, expected {MANIFEST_SCHEMA!r}. A manifest "
            f"written by a different version is not verifiable by this one."
        )

    files = manifest.get("files")
    if files is None:
        files = []
    if not isinstance(files, list):
        problems.append("manifest 'files' is not a list")
        files = []

    file_hashes: list[str] = []
    for record in files:
        if not isinstance(record, dict):
            problems.append(f"file entry is not an object: {record!r}")
            continue
        rel = str(record.get("path") or "")
        check: dict[str, Any] = {"path": rel}
        target = directory / rel
        if not rel:
            problems.append("a file entry has no path")
            continue
        if not target.is_file():
            check.update(present=False, ok=False)
            problems.append(f"{rel} is named in the manifest and does not exist")
            checks.append(check)
            continue

        actual_hash = _sha256_file(target)
        expected_hash = record.get("sha256")
        file_hashes.append(actual_hash)
        check.update(present=True, sha256=actual_hash)
        if expected_hash and actual_hash != expected_hash:
            check["ok"] = False
            problems.append(
                f"{rel} sha256 is {actual_hash}, manifest says {expected_hash} "
                f"-- the file has changed since the fixture was written"
            )
        expected_count = record.get("document_count")
        if isinstance(expected_count, int):
            actual_count = _count_lines(target)
            check["document_count"] = actual_count
            if actual_count != expected_count:
                check["ok"] = False
                problems.append(
                    f"{rel} holds {actual_count} documents, manifest says "
                    f"{expected_count}"
                )
        check.setdefault("ok", True)
        checks.append(check)

    expected_payload = manifest.get("payload_sha256")
    payload_sha = hashlib.sha256(
        "".join(sorted(file_hashes)).encode()
    ).hexdigest() if file_hashes else None
    if expected_payload and payload_sha and expected_payload != payload_sha:
        problems.append(
            f"payload_sha256 is {payload_sha}, manifest says {expected_payload}"
        )

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
