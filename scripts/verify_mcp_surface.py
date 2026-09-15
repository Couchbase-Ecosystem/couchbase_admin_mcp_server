"""
scripts/verify_mcp_surface.py — drive this server the way a client does.

WHAT THIS PROVES THAT verify_capella_paths.py DOES NOT
=====================================================
``verify_capella_paths.py`` speaks HTTP to the Capella control plane directly.
It answers one question — does this path exist, and does this method reach it —
and it answers it well. But it never starts the server, never loads a tool, and
never passes through a single line of dispatch. Ninety-seven live-verified paths
therefore say nothing at all about whether a client can call them.

Everything between the registry and the wire is outside that script's reach:

  * startup under a deployment profile, and the posture guard that can refuse it
  * the advertised tool list — names, input schemas, annotations
  * deployment gating, the read-only filter, ``CB_ADMIN_DISABLED_TOOLS``
  * the scope gate, the hard ceiling, the confirmation gate
  * dry-run interception
  * argument marshalling, and the redaction applied to every response
  * the audit record each call emits

This script exercises all of it over stdio with the official ``mcp`` client —
the same library Claude Desktop and Claude Code use. A tool that answers here has
been proven callable *by a client*, not merely routable by curl.

It is the admin server's counterpart to ``mcp-crud-couchbase/manual-check.py``,
which did this job for the four KV pull requests against the official data-plane
server. Same idea, wider surface: that one exercised four capabilities by name,
this one walks whatever the server advertises.

THREE PHASES
============
  protocol   Start the server, initialise, list tools. Check the advertised
             surface against the shipped registry, and check every schema is
             well formed. No cluster needed.

  read       Discover the object graph — organization, project, cluster, bucket,
             scope, collection — by calling the list tools, then call every
             advertised read tool whose arguments that discovery satisfies.
             Reads only. Nothing is created and nothing is modified.

  write      Opt-in (``--write-preview``). Restart the server with writes loaded
             and ``CB_ADMIN_DRY_RUN=true``, then call every write tool twice:
             once without ``confirm`` — which must be refused — and once with it,
             which must come back as a preview rather than a result.

WHY THE WRITE PHASE IS SAFE, STATED PRECISELY
=============================================
Not because this script is careful. Because the dispatch order in ``server.py``
puts the dry-run interception *before* the handler and *after* every gate, and
because ``CB_ADMIN_DRY_RUN`` is an operator control a caller cannot override —
``dryrun.in_effect`` consults the environment before it consults the arguments.
So a write cannot reach a handler in this phase no matter what this script sends.

There is exactly one exception, and it is the reason this phase refuses to run
against a server that cannot describe itself: a tool that implements ``dry_run``
in its own handler is deliberately NOT intercepted by the dispatch. Calling one
with ``confirm: true`` would perform it. ``capella_env_reap`` is such a tool, and
it reaps clusters. This script therefore does not infer that set from the schema —
``mcp_compat.with_control_fields`` advertises ``dry_run`` on nearly every write
tool, so the schema cannot distinguish them — it reads the set from
``cb_mcp_status``, and if the server does not report it, the phase does not run.

Every write-phase response is checked for ``executed: false``. A response without
it means a write was performed, and that is a hard failure, reported first.

WHAT COUNTS AS A PASS
=====================
An outcome is never a pass by default. A tool whose arguments could not be
resolved is SKIPPED, and a skipped tool is reported as skipped in the totals and
in the exit code's reasoning — it is not silently folded into the successes. The
whole value of this run is that the number at the end means something, and the
failure mode these harnesses share is looking more conclusive than they are.

RUNNING IT
==========
From the repository root, with the Capella credentials in the environment
(``cbenv.bat`` sets them) and the machine on a network the cluster allowlists —
see ``CAPELLA-CONNECTIVITY.md``, which is where a day went the first time:

    uv run python scripts\\verify_mcp_surface.py --out evidence-mcp-read.txt

and, when you want the write surface exercised too:

    uv run python scripts\\verify_mcp_surface.py --write-preview --out evidence-mcp-full.txt

``scripts\\run-mcp-evidence.ps1`` wraps both in a transcript.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Outcomes ─────────────────────────────────────────────────────────────────
#
# Spelled out rather than reduced to pass/fail, because the interesting cases are
# in between. A guardrail refusal and an upstream 404 are both "not a result",
# and conflating them is how a run that proved the guardrails work gets reported
# as a run with sixteen failures.

OK = "OK"  # handler ran, returned a payload
EMPTY = "EMPTY"  # handler ran, returned an empty collection — a real answer
PREVIEW = "PREVIEW"  # write withheld by the dry run, as intended
GATED = "GATED"  # refused for want of confirm: true — the gate works
GUARDED = "GUARDED"  # refused by Capella guardrail policy
UPSTREAM = "UPSTREAM"  # handler ran, the API refused it
SKIPPED = "SKIPPED"  # arguments could not be resolved; nothing was sent
NOT_REACHED = "NOT_REACHED"  # the phase stopped before this tool's turn
PROTOCOL = "PROTOCOL"  # the MCP layer itself failed — always a defect here
TIMEOUT = "TIMEOUT"  # the call never came back; says nothing about the surface
PERFORMED = "PERFORMED"  # a write ran when it should have been withheld

#: Outcomes that mean the dispatch worked. Note what is absent: SKIPPED.
_SUCCESSFUL = frozenset({OK, EMPTY, PREVIEW, GATED, GUARDED})

#: Outcomes that fail the run regardless of flags.
#:
#: TIMEOUT is deliberately NOT here, and it used to be — folded into PROTOCOL,
#: which made every VPN-up run exit 1 the moment cb_get_schema_for_collection hung
#: on port 11207. That is the data plane being unreachable, not a defect in the
#: MCP surface, and an exit code that cannot tell those apart stops meaning
#: anything. It is reported, counted, and fails a --strict run alongside UPSTREAM.
_HARD_FAILURES = frozenset({PROTOCOL, PERFORMED})


@dataclass
class Result:
    """One tool call and what became of it."""

    tool: str
    outcome: str
    detail: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    shape: str = ""
    phase: str = "read"

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "outcome": self.outcome,
            "detail": self.detail,
            "arguments": sorted(self.arguments),
            "shape": self.shape,
            "phase": self.phase,
        }


# ── Discovery ────────────────────────────────────────────────────────────────
#
# Which list tool fills which schema property, and from which field of each item.
#
# Explicit rather than inferred. A generic "take anything called id" walk looked
# tempting and is wrong in a way that is hard to see afterwards: several v4 list
# payloads nest a second `id` for a sub-resource, and a context filled from the
# wrong one produces a run where every dependent tool answers 404 and the report
# says the paths are broken. Naming the pairs costs twenty lines and means a
# mis-fill is a visible edit rather than an emergent property.

#: Which side of a `both`-mode run a tool addresses.
#:
#: `capella_*` reaches the v4 control plane. Everything else reaches A CLUSTER --
#: a different one, with different objects in it. One shared context sent the
#: Capella bucket name to the local cluster (`admin_bucket_get` asked for
#: travel-sample on a laptop) and the Capella eventing function name too
#: (`admin_eventing_get` asked for `test`). Both produced 404s that read as broken
#: tools. They are not two spellings of one namespace; they are two namespaces.
CAPELLA_SIDE = "capella"
CLUSTER_SIDE = "cluster"


def side_of(tool_name: str) -> str:
    """Which context a tool's arguments come from."""
    return CAPELLA_SIDE if tool_name.startswith("capella_") else CLUSTER_SIDE


#: (tool, context key, field or fields to read the id from)
#:
#: The third element is a tuple where v4 does not name the id predictably --
#: audit-log exports return `exportId` in some shapes and `id` in others, and
#: guessing wrong is a silent empty discovery rather than an error.
_DISCOVERY: tuple[tuple[str, str, str | tuple[str, ...]], ...] = (
    # (tool, context key it fills, field on each returned item)
    ("capella_organizations_list", "organization_id", "id"),
    ("capella_projects_list", "project_id", "id"),
    ("capella_clusters_list", "cluster_id", "id"),
    ("capella_buckets_list", "bucket_id", "id"),
    ("capella_database_credentials_list", "user_id", "id"),
    ("capella_app_services_list", "app_service_id", "id"),
    # Both of these hang off app_service_id, so they must come AFTER it: the
    # loop resolves in table order and a tool whose arguments are not yet in the
    # context is reported "not yet resolvable" and never retried.
    #
    # Their absence was worth 14 SKIPPED results reading "no value for
    # app_service_id, app_endpoint_name" -- which named the right cause for the
    # first id and the wrong one for the second. app_endpoint_name was never
    # discovered by anything, so it would have stayed missing even once an App
    # Service existed.
    ("capella_app_endpoints_list", "app_endpoint_name", ("name", "id")),
    ("capella_app_service_admin_users_list", "admin_user_id", "id"),
    ("capella_allowed_cidrs_list", "allowed_cidr_id", "id"),
    ("capella_backups_list", "backup_id", "id"),
    ("capella_events_list", "event_id", "id"),
    ("capella_alert_integrations_list", "alert_integration_id", "id"),
    ("capella_replications_list", "replication_id", "id"),
    ("capella_eventing_functions_list", "function_name", "name"),
    # Both of these were sitting in a response the run already had. Three tools
    # reported "no value for" while the ids were on screen two lines earlier --
    # including capella_cluster_audit_log_export_get, the ONE shipped-but-
    # unverified operation left in the registry.
    ("capella_query_index_definitions_list", "index_name", ("indexName", "name")),
    (
        "capella_cluster_audit_log_exports_list",
        "export_id",
        # auditLogExportId, confirmed against the live response on 2026-09-12.
        # `exportId` and `id` were both guessed and both wrong; the create response
        # uses one spelling and the list response another, which is exactly why the
        # field is a tuple and why a failed selection now prints the row's keys.
        ("auditLogExportId", "exportId", "id"),
    ),
    # FIXTURES AND ENVIRONMENTS: OUR OWN TOOLS, DISCOVERED THE SAME WAY.
    #
    # Four SKIPPED results read "no value for fixture_path / fixture_id / env_name"
    # and every one was this table not looking, not a missing capability.
    # capella_fixture_list walks root_path (already seeded to the repo root) and
    # returns a row per fixture; capella_env_list returns a row per managed
    # environment. Both are reads, both are free, and both were being ignored.
    #
    # These stay SKIPPED when the lists are genuinely empty -- no fixture on disk,
    # no managed environment -- and that is the correct result rather than a gap:
    # a fixture_path invented by this checker points at nothing, and a call aimed
    # at nothing tests nothing. Run capella_fixture_export --include-data false to
    # put one on disk.
    # The backup catalogue is LOCAL and works on both planes, so it is discovered
    # here rather than in either plane's section. catalog_root is seeded as a
    # literal for the same reason root_path is.
    ("cb_backup_catalog_list", "catalog_id", ("catalog_id", "id")),
    ("capella_fixture_list", "fixture_path", ("fixture_path", "path")),
    ("capella_fixture_list", "fixture_id", ("fixture_id", "id")),
    # The row key is `environment`, not `env_name` -- capella_env_list reports the
    # marker's own vocabulary (mcp-env:{"env": ...}) rather than the argument name
    # the env tools take. Both spellings are listed because a reader checking this
    # table against the tool schema will look for the argument name first.
    ("capella_env_list", "env_name", ("environment", "env", "env_name", "name")),
    # Self-managed. Same mechanism, different vocabulary: ns_server addresses
    # buckets by NAME where v4 uses an opaque id.
    ("admin_bucket_list", "bucket_name", "name"),
    ("admin_scope_list", "scope_name", "name"),
    ("admin_user_list", "username", "id"),
    ("admin_group_list", "group_name", "id"),
    ("admin_backup_repository_list", "repository_id", "id"),
    ("admin_eventing_list", "function_name", "appname"),
    # DISCOVERABLE ALL ALONG, AND NOTHING WAS LOOKING.
    #
    # Eight write tools skipped for want of `otpNode` or a server-group `uuid`,
    # reported as "no otpNode exists on this cluster" -- which is false. Every
    # cluster has nodes, and admin_node_list was already being CALLED in the
    # read phase and its rows thrown away. Same for admin_server_groups_get.
    #
    # This is the third kind of SKIPPED, distinct from the two the write phase
    # already separates: not a missing object, and not an unsynthesisable body,
    # but an id sitting in a response the run had already received. The skip
    # message named the environment when the gap was in this table.
    #
    # NOTE what this makes testable: admin_node_remove, admin_failover_hard,
    # admin_failover_graceful and admin_recovery_type_set all take an otpNode.
    # They are DESTRUCTIVE and the write phase runs under CB_ADMIN_DRY_RUN with
    # the confirmation gate in front, so they are previewed and never performed
    # -- but it is worth saying out loud that this line is what lets a failover
    # tool be aimed at a real node id.
    # The FTS index and the eventing function BOTH EXIST on a populated
    # cluster; nothing was looking for either. See _ROWS_READER for why their
    # responses needed a reader rather than a field name.
    # Self-managed XDCR. Newly discoverable on 2026-09-14: until that day
    # admin_xdcr_replications_list returned the global tuning document rather
    # than any replication, so there was no id to find and three tools --
    # pause, resume, delete -- skipped for want of it. Fixing the handler is
    # what made this line possible; see handlers/xdcr.py.
    ("admin_xdcr_replications_list", "replication_id", "id"),
    ("admin_fts_index_list", "index_name", "name"),
    ("admin_node_list", "otpNode", "otpNode"),
    ("admin_server_groups_get", "uuid", "uuid"),
)

#: Every field name the discovery table can fill: the OBJECT IDENTITIES of this
#: surface. A required argument in this set names a thing that must already
#: exist; a required argument outside it is payload the caller supplies.
#:
#: WHY THIS SET EXISTS, AND WHY IT IS NOT A NAME PATTERN
#: -----------------------------------------------------
#: The write phase briefly synthesised EVERY missing argument, on the reasoning
#: that CB_ADMIN_DRY_RUN is forced on and the confirmation gate sits in front,
#: so nothing can be performed. tests/test_verify_mcp_surface.py rejected it,
#: and the test was right:
#:
#:     "Bodies are payload and are never routed. Path ids are targets and
#:      always are. Inventing a cluster_id would preview a call against a
#:      cluster that does not exist, and WITHOUT THE DRY RUN it would be a real
#:      request to a fabricated path."
#:
#: The point is the last clause. "Dry run is on" was the single assumption the
#: looser rule rested on, and that is precisely the assumption the safety
#: property must not rest on. Depth, not one gate.
#:
#: A name pattern (`*_id`, `*_name`) cannot make the distinction: admin_bucket_create
#: takes `name` as PAYLOAD while admin_scope_create takes `bucket_name` as a
#: TARGET. The discovery table already enumerates what an identity is on this
#: surface, so it is the authority rather than a second guess about spelling.
#:
#: The principled version of this needs the server to expose each Op's route so
#: the harness can read the {placeholders} directly -- cb_mcp_get_tool_info
#: returns schema and annotations but not the path. Until it does, this is the
#: honest approximation, and it errs toward skipping.
_IDENTITY_FIELDS: frozenset[str] = frozenset(
    field_name for _tool_name, field_name, *_rest in _DISCOVERY
)

#: Discovery entries that must NOT be called during the discovery loop, only
#: harvested from their result if the read phase happens to call them.
#:
#: capella_query_index_definitions_list takes `bucket`, `scope` and `collection`
#: as OPTIONAL query parameters, so nothing looks missing and the resolver calls
#: it happily -- but the keyspace is resolved at the END of discovery, so during
#: the loop it goes out without a bucket and answers 400. In the read phase it has
#: the keyspace and returns rows. Adding it to the discovery loop moved a working
#: tool to the one place it could not work.
#:
#: "Its required arguments resolve" is not the same claim as "it will succeed
#: here", and the resolver cannot tell the difference for an optional parameter
#: the API treats as mandatory.
_HARVEST_ONLY = frozenset(
    {
        "capella_query_index_definitions_list",
        "capella_cluster_audit_log_exports_list",
    }
)

#: Optional properties worth filling when the context has them.
#:
#: Deliberately tiny. Filling an optional argument changes what the call MEANS,
#: so the default is to leave it out — with one exception that has already cost a
#: false verdict once. The /queryService/ reads declare `bucket`, `scope` and
#: `collection` as optional query parameters, but a keyspace read without a
#: bucket answers 400, and 400 was being recorded as proof the route existed.
#: Filling them here is the difference between exercising the tool and exercising
#: its argument validation.
_OPTIONAL_FILL = frozenset({"bucket", "scope", "collection"})

#: Never sent from the resolver. These are the dispatch's own control fields;
#: the phases set them deliberately or not at all.
_CONTROL_FIELDS = frozenset({"confirm", "dry_run", "correlation_id"})

#: Buckets to reach for FIRST, in this order.
#:
#: The first run of this script discovered `harvester` and pointed every keyspace
#: read at it. Nothing was at risk -- the read phase only reads, and the server
#: redacts on the way out -- but a tool that is checking whether a surface
#: dispatches has no business selecting the bucket with the customer data in it
#: when a sample bucket is sitting on the same cluster. Least sensitive thing that
#: exercises the same code path.
_PREFERRED_BUCKETS: tuple[str, ...] = ("travel-sample", "beer-sample", "gamesim-sample")

#: Buckets that would make the run vacuous: system keyspaces with no user scopes,
#: so every keyspace read answers about nothing.
_INTERNAL_BUCKETS = frozenset({"N1QL_SYSTEM_BUCKET", "_system"})

#: The tools whose selection the bucket preference applies to.
_BUCKET_TOOLS = frozenset({"capella_buckets_list", "admin_bucket_list"})


def _is_data_plane(name: str) -> bool:
    """Whether a tool reaches a cluster rather than a control plane.

    Defined by exclusion, because the first version enumerated prefixes and the
    enumeration was wrong: it named cb_get_/cb_perf_/cb_index_/cb_explain_ and
    missed admin_index_list and admin_xdcr_conflict_log_query, both of which go
    through the SDK and both of which hung for thirty seconds each.

    `capella_*` is HTTPS to the control plane and cb_mcp_* answers from process
    state. Everything else can touch a cluster, and the ones that do are the ones
    that can hang, so they go last -- a hanging cluster then truncates the tail
    rather than the middle.
    """
    return not name.startswith(("capella_", "cb_mcp_"))


def _read_order(tools: list) -> list:
    """Control-plane tools first, cluster-touching ones last. Stable within each."""
    return sorted(tools, key=lambda t: _is_data_plane(getattr(t, "name", "")))


def _client_env(*, read_only: bool, dry_run: bool) -> dict[str, str]:
    """The child server's environment.

    Inherited rather than constructed, because the whole point is to start the
    server the way the operator's client starts it — a curated environment would
    verify a configuration nobody runs.
    """
    env = dict(os.environ)
    env["CB_ADMIN_TRANSPORT"] = "stdio"
    env["CB_ADMIN_READ_ONLY_MODE"] = "true" if read_only else "false"
    if dry_run:
        env["CB_ADMIN_DRY_RUN"] = "true"
    else:
        # Not merely "don't set it": an inherited CB_ADMIN_DRY_RUN=true from the
        # operator's shell would make every read phase look normal and every write
        # phase look safe for the wrong reason. The phases assert the posture they
        # asked for, and this is where the asking happens.
        env.pop("CB_ADMIN_DRY_RUN", None)
    env.setdefault("CB_ADMIN_PROFILE", "workstation")
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env


# ── Payload reading ──────────────────────────────────────────────────────────


def _text_blocks(response: Any) -> list[str]:
    out: list[str] = []
    for block in getattr(response, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            out.append(text)
    return out


def _payload(response: Any) -> Any:
    """The first JSON object in a tool response, or None."""
    return _text_and_payload(response)[1]


def _text_and_payload(response: Any) -> tuple[str, Any]:
    """Both halves of a response: the raw text, and the JSON if it parsed.

    The text is kept because "no JSON payload" turned out to be a diagnosis
    rather than an observation, and a wrong one. The write phase reported 86
    PROTOCOL failures reading exactly that, with nothing to say what had come
    back -- and the pattern (every *_create failing while every *_update and
    *_delete passed) pointed at argument validation rejecting the call before
    dispatch, which would be the schema working rather than the server failing.

    Whatever it is, the answer was in the response the whole time. Discarding it
    and printing a category is how three field-name guesses happened earlier in
    the same session.
    """
    texts = _text_blocks(response)
    for text in texts:
        try:
            return text, json.loads(text)
        except (ValueError, TypeError):
            continue
    return "\n".join(texts), None


def _is_error(payload: Any) -> bool:
    """Whether this is an err() payload.

    Reads the same discriminator ``server.py`` and the audit classifier read, and
    only that. Several handlers return a SUCCESS payload carrying a top-level
    "error" that describes a sub-resource problem; treating those as failures
    would mislabel a partially successful call as a denial.
    """
    return isinstance(payload, dict) and payload.get("_is_error") is True


#: Responses whose rows cannot be found by "the one list in the envelope".
#:
#: `_items` picks the single list in a dict and returns nothing when there is
#: more than one -- deliberately, because guessing between two lists is how a
#: harness silently reports the wrong object. /pools/nodes carries BOTH `nodes`
#: and `alerts`, so it needs the key naming rather than inferring. That is why
#: admin_node_list reported "no rows" on a cluster that plainly has a node.
_ENVELOPE_KEY: dict[str, str] = {
    "admin_node_list": "nodes",
    "admin_server_groups_get": "groups",
}

#: Responses that are not a list of objects at all.
#:
#: Two endpoints answer in shapes nothing generic can read:
#:
#:   /_p/fts/api/index   -> {"indexDefs": {"indexDefs": {"<name>": {...}}}}
#:                          a MAP KEYED BY NAME, twice nested, no list anywhere
#:   /_p/event/.../list/functions
#:                       -> {"functions": ["<name>", ...]}
#:                          a list of STRINGS, which is why discovery reported
#:                          "1 row(s), none of them an object" on a cluster that
#:                          demonstrably had a function
#:
#: Both were read as "no such object" when the object existed. A reader turns
#: each into the {field: value} rows the rest of this file expects, so the
#: special case is one line of shape-handling rather than a special case in
#: every consumer.
_ROWS_READER: dict[str, Any] = {
    "admin_fts_index_list": lambda payload: [
        {"name": name}
        for name in (((payload or {}).get("indexDefs") or {}).get("indexDefs") or {})
    ],
    "admin_eventing_list": lambda payload: [
        {"appname": item} if isinstance(item, str) else item
        for item in ((payload or {}).get("functions") or [])
    ],
}

#: Ids that are not a field but a SUBSTRING of one.
#:
#: A server group carries no `uuid`; its id is the last segment of its `uri`
#: (/pools/default/serverGroups/<uuid>), which admin_server_group_delete and
#: admin_server_group_rename both require. Reading it out is not a guess -- the
#: uri is the object's canonical address -- but it is not a field lookup either,
#: so it is stated here rather than hidden behind a field name.
_FIELD_FROM_URI: frozenset[str] = frozenset({"admin_server_groups_get"})


def _items(payload: Any) -> list:
    """The rows of a list response, across the shapes v4 actually uses.

    There is no single envelope. Most list endpoints answer
    ``{"data": [...], "cursor": {...}}``; ``GET .../scopes`` answers
    ``{"scopes": [...]}``; a scope answers ``{"collections": [...]}``; and some
    items arrive nested a second time as ``{"data": {"data": {...}}}``. Assuming
    uniformity here silently produced empty discovery for two of the three.
    """
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return data["items"]
    # OUR OWN COMPOSITE TOOLS ANSWER WITH TWO LISTS, AND THE FALLBACK BELOW
    # REFUSES TO GUESS BETWEEN THEM -- correctly, but the result was silent
    # empty discovery for both.
    #
    #   capella_env_list         -> {"managed": [...], "unmanaged": [...]}
    #   capella_fixture_list     -> {"fixtures": [...], "unreadable": [...]}
    #   cb_backup_catalog_list   -> {"entries": [...], "unreadable": [...]}
    #
    # In each pair the first is the answer and the second is a caveat: an
    # unmanaged cluster is one this server did not create, an unreadable fixture
    # is a directory whose manifest will not parse. Neither can supply an
    # identity, so naming the row key is not a preference, it is the difference
    # between discovering nothing and discovering the right thing.
    for key in ("managed", "fixtures", "entries"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return rows
    lists = [value for value in payload.values() if isinstance(value, list)]
    return lists[0] if len(lists) == 1 else []


def _unwrap(item: Any) -> Any:
    """Peel the second ``data`` layer some v4 items arrive inside."""
    while isinstance(item, dict) and set(item) == {"data"}:
        item = item["data"]
    return item


def _shape(payload: Any) -> str:
    """A description of a response that is safe to put in an evidence file.

    Keys and counts, never values. Responses here carry allowlists, credential
    ids, eventing source and alert-integration configuration; the server redacts
    what it knows to be secret, but an evidence file is a document that gets
    attached to tickets and this is the cheap way not to have to think about it
    each time. ``--print-bodies`` overrides it deliberately.
    """
    if payload is None:
        return "no JSON payload"
    if isinstance(payload, list):
        return f"list[{len(payload)}]"
    if not isinstance(payload, dict):
        return type(payload).__name__
    rows = _items(payload)
    keys = ", ".join(sorted(payload)[:8])
    if rows:
        return f"{len(rows)} row(s); keys: {keys}"
    return f"keys: {keys}"


# ── Argument resolution ──────────────────────────────────────────────────────


def _app_endpoint_keyspace(name: Any, row: Any) -> str:
    """`<endpoint>.<scope>.<collection>` from an App Endpoint document.

    Returns "" when the endpoint has no scope/collection to name, because a
    two-part or one-part keyspace is not a keyspace and a 404 earned by sending
    one teaches nothing. See the retraction in _seed_derived_context.
    """
    if not name or not isinstance(row, dict):
        return ""
    scopes = row.get("scopes")
    if not isinstance(scopes, dict):
        return ""
    for scope_name, scope in scopes.items():
        collections = (scope or {}).get("collections")
        if isinstance(collections, dict) and collections:
            return f"{name}.{scope_name}.{next(iter(collections))}"
    return ""


def resolve_arguments(
    schema: dict[str, Any], context: dict[str, str]
) -> tuple[dict[str, Any], list[str]]:
    """Build a call's arguments from discovered context.

    Returns ``(arguments, missing)``. ``missing`` is every REQUIRED property the
    context cannot fill; a non-empty list means the tool is skipped rather than
    called with a hole in it.

    Optional properties are left out unless they are in ``_OPTIONAL_FILL`` — see
    the note there for why that set is small and why it is not empty.
    """
    properties = (schema or {}).get("properties") or {}
    required = list((schema or {}).get("required") or [])

    arguments: dict[str, Any] = {}
    missing: list[str] = []

    for name in required:
        if name in _CONTROL_FIELDS:
            # A schema that requires `confirm` would make every call a write; no
            # tool does this today and if one ever does, skipping is the safe read.
            missing.append(name)
            continue
        value = context.get(name)
        if value is None:
            missing.append(name)
        else:
            arguments[name] = value

    for name in properties:
        if name in arguments or name in _CONTROL_FIELDS:
            continue
        if name in _OPTIONAL_FILL and context.get(name) is not None:
            arguments[name] = context[name]

    return arguments, missing


def classify(payload: Any, *, phase: str, text: str = "") -> tuple[str, str]:
    """Turn a response payload into an outcome and a one-line reason.

    The ordering matters. A dry-run preview is a success payload that happens to
    mention a write, and an err() carrying ``requires_confirmation`` is a refusal
    that happens to be the thing the write phase is trying to prove. Reading the
    discriminators in the wrong order reports the working case as broken.
    """
    if payload is None:
        # Still a failure, deliberately, until the text says otherwise. Naming a
        # cause before reading the evidence is the error this session kept making;
        # showing the evidence and keeping the severity is the honest middle.
        body = text.strip()
        if not body:
            return PROTOCOL, "response carried no content at all"
        return PROTOCOL, f"response was not JSON: {body[:200]!r}"

    if _is_error(payload):
        message = str(payload.get("error", ""))[:220]
        if payload.get("requires_confirmation") is True:
            return GATED, "refused: confirmation required"
        if payload.get("guardrail") is True:
            return GUARDED, f"refused by guardrail policy: {message}"
        status = payload.get("status")
        if status is not None:
            return UPSTREAM, f"HTTP {status}: {message}"
        # No status and no guard: the handler itself failed, or the tool was not
        # dispatchable. Both are defects in the surface this script exists to check.
        lowered = message.lower()
        if "unknown tool" in lowered or "not enabled" in lowered:
            return PROTOCOL, message
        return UPSTREAM, message

    if isinstance(payload, dict) and "executed" in payload:
        if payload.get("executed") is False:
            return PREVIEW, "withheld by dry run"
        return PERFORMED, "the call reports it EXECUTED — a write was performed"

    if phase == "write":
        # A write-phase call that came back as an ordinary success is the case
        # this whole phase is built to catch: the dry run did not intercept it.
        return PERFORMED, "write phase returned a result rather than a preview"

    rows = _items(payload)
    if isinstance(payload, dict) and not rows and _looks_like_a_listing(payload):
        return EMPTY, "no rows"
    return OK, ""


def _looks_like_a_listing(payload: dict) -> bool:
    """Whether an empty response is an empty LIST rather than a scalar answer.

    ``{"data": []}`` is a list with nothing in it. ``{"state": "healthy"}`` is a
    complete answer that happens to have no rows, and calling it EMPTY would read
    as a gap where there is none.
    """
    for key in ("data", "items", "cursor"):
        if key in payload:
            return True
    return any(isinstance(value, list) for value in payload.values())


# ── Body synthesis ───────────────────────────────────────────────────────────
#
# WHAT IS SYNTHESISED, AND WHAT IS NEVER
#
# Bodies are PAYLOAD. They are never routed, so a synthetic one cannot reach an
# object that exists -- and under the dry run it is not sent at all. Path ids are
# TARGETS. Inventing a cluster_id would produce a preview of a call against a
# cluster that does not exist, which is worse than no preview, and without the dry
# run it would be a real request to a fabricated path. So: bodies are generated,
# ids are discovered or the tool is skipped. That line is the whole safety
# argument and it is why the two are handled separately.
#
# WHY GENERATE RATHER THAN HAND-WRITE
#
# Every write op in spec.py already declares `body` as a map of JSON-schema
# properties plus `body_required`. Eighty-odd hand-written fixtures would restate
# what the registry already says, and would drift from it silently. Generating
# from the declared schema also turns the schemas into the thing under test: a
# body built from the schema and REFUSED by Capella means the schema is wrong,
# and roughly forty of them were transcribed from the Terraform provider and have
# never been exercised.

#: Names that look like an identifier rather than a label, so a generated value
#: would be meaningless. Left out of a synthesised body; the API's own rejection
#: is more informative than an invented UUID.
_ID_LIKE = ("id", "Id", "ID", "uuid", "Uuid", "UUID")


def _looks_like_an_id(name: str) -> bool:
    return name.endswith(_ID_LIKE)


def synthesise_body(
    schema: dict[str, Any], context: dict[str, str], prefix: str, _depth: int = 0
) -> tuple[dict[str, Any], list[str]]:
    """Build a minimal object satisfying `schema`'s required properties.

    Returns ``(body, guessed)``. ``guessed`` names every field filled with a value
    invented rather than derived -- and the transcript says so, because a preview
    obtained with an invented body proves the gate and NOT that the body is one
    Capella would accept. Reporting the first as though it were the second is the
    error this script exists to avoid.
    """
    if _depth > 4:
        # Recursion guard. A self-referential schema is a defect worth surfacing
        # rather than a stack overflow worth debugging.
        return {}, ["<schema nests deeper than 4 levels>"]

    properties = (schema or {}).get("properties") or {}
    required = list((schema or {}).get("required") or [])
    body: dict[str, Any] = {}
    guessed: list[str] = []

    for name in required:
        spec = properties.get(name)
        if not isinstance(spec, dict):
            guessed.append(name)
            body[name] = f"{prefix}-{name}"
            continue

        # A value already discovered beats an invented one, every time.
        if name in context:
            body[name] = context[name]
            continue

        value, invented = _value_for(name, spec, context, prefix, _depth)
        if invented:
            guessed.append(name)
        body[name] = value

    return body, guessed


def _value_for(
    name: str, spec: dict[str, Any], context: dict[str, str], prefix: str, depth: int
) -> tuple[Any, bool]:
    """One value for one declared property. Second element: was it invented?"""
    if "default" in spec:
        return spec["default"], False
    enum = spec.get("enum")
    if isinstance(enum, list) and enum:
        # The first enum member is a real choice from a closed set, not a guess.
        return enum[0], False

    declared = spec.get("type")
    if isinstance(declared, list):
        declared = next((t for t in declared if t != "null"), "string")

    if declared == "boolean":
        # False, never True. Several booleans in this registry turn a preview into
        # a wider operation -- forceUpdates on a restore overwrites newer documents
        # in the target. The safe value is also the honest default.
        return False, False
    if declared in ("integer", "number"):
        for key in ("minimum", "exclusiveMinimum"):
            if isinstance(spec.get(key), (int, float)):
                return spec[key], False
        return 1, True
    if declared == "array":
        item = spec.get("items")
        if spec.get("minItems") and isinstance(item, dict):
            # ONE ELEMENT IS NOT ENOUGH WHEN THE SCHEMA ASKS FOR SEVEN.
            #
            # This built a single-element list for any minItems at all, which the
            # MCP SDK then rejected before dispatch:
            #
            #   Input validation error: [{'day': 'monday', 'state': 'on'}] is
            #   too short
            #
            # reported as PROTOCOL FAILURE — a result about this checker, dressed
            # as a result about the server. capella_cluster_onoff_schedule_set
            # requires exactly seven days, and it is the first operation in the
            # registry whose minItems is not 1.
            count = int(spec.get("minItems") or 1)
            values = []
            invented = False
            for _ in range(count):
                value, was_invented = _value_for(name, item, context, prefix, depth + 1)
                values.append(value)
                invented = invented or was_invented
            return values, invented
        return [], False
    if declared == "object":
        nested, nested_guessed = synthesise_body(spec, context, prefix, depth + 1)
        return nested, bool(nested_guessed)

    if _looks_like_an_id(name):
        # Deliberately obvious. A fabricated UUID reads as a real one in a
        # transcript six weeks later; this does not.
        return f"{prefix}-NOT-A-REAL-{name}", True
    return f"{prefix}-{name}", True


# ── The run ──────────────────────────────────────────────────────────────────


class Run:
    """State for one invocation: the context, the results, and the reporting."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        #: Two namespaces, addressed separately. See `side_of`.
        self.contexts: dict[str, dict[str, str]] = {
            CAPELLA_SIDE: {},
            CLUSTER_SIDE: {},
        }
        self.results: list[Result] = []
        self.notes: list[str] = []
        self.correlation = f"verify-mcp-surface-{uuid.uuid4().hex[:12]}"
        self.started = datetime.now(timezone.utc)
        self.status: dict[str, Any] = {}
        self.advertised: list[Any] = []
        self._out = sys.stdout
        self._line_open = False
        self._consecutive_timeouts = 0
        self._mirror = None

    # -- output -----------------------------------------------------------

    def say(self, line: str = "") -> None:
        print(line, file=self.out)
        # Mirrored to stderr whenever the transcript is going to a file.
        #
        # `--out` sent every line to the file and left the terminal empty, so a
        # run that was working looked like one that had returned instantly -- and
        # a run that was genuinely slow looked the same. stderr rather than stdout
        # because stdout carries the --json payload.
        if self._mirror is not None:
            print(line, file=self._mirror, flush=True)

    @property
    def out(self):
        return self._out

    def open_output(self):
        self._out = sys.stdout
        self._mirror = sys.stderr if self.args.out else None
        if self.args.out:
            # Held open for the length of the run rather than wrapped in a
            # context manager: the transcript is written across every phase, and
            # close_output() in main()'s finally is what closes it. SIM115 is
            # right about the usual case and wrong about this one.
            self._out = open(  # noqa: SIM115
                self.args.out, "w", encoding="utf-8"
            )
        return self._out

    def close_output(self) -> None:
        if self.args.out and self._out is not sys.stdout:
            self._out.close()

    @property
    def context(self) -> dict[str, str]:
        """The Capella-side context.

        Named plainly because it is the one almost everything uses; the cluster
        side is reached through `context_for`. A single merged dict was the
        original design and it is what sent Capella object names to a laptop.
        """
        return self.contexts[CAPELLA_SIDE]

    #: Tools whose PATH cluster is not the cluster this run is pointed at.
    #:
    #: An XDCR replication is a property of a PAIR, and Capella lists it on the
    #: SOURCE. A replication into the throwaway cluster is therefore invisible
    #: from the throwaway cluster, and capella_replication_get skipped for want
    #: of an id that the run could see the whole time -- on the other cluster.
    #:
    #: Feeding it that id WITHOUT also switching the cluster would manufacture a
    #: 404: correct id, wrong path. That is the same mistake as sending an App
    #: Endpoint name where a keyspace belongs, and it is why the id and the
    #: cluster travel together here rather than the id alone being seeded.
    _CLUSTER_FROM: ClassVar[dict[str, str]] = {
        "capella_replication_get": "_replication_cluster_id",
        "capella_replication_delete": "_replication_cluster_id",
    }

    def context_for(self, tool_name: str) -> dict[str, str]:
        context = self.contexts[side_of(tool_name)]
        key = self._CLUSTER_FROM.get(tool_name)
        if key and context.get(key):
            # A COPY. Mutating the shared side context would repoint every
            # later tool at the other cluster, which is a much larger mistake
            # than the one this fixes.
            return {**context, "cluster_id": context[key]}
        return context

    def note(self, text: str) -> None:
        """Record a finding that is not a tool call.

        Deduplicated, because ``--write-preview`` runs the protocol phase twice —
        once per server — and a note repeated verbatim reads as two findings when
        it is one.
        """
        if text not in self.notes:
            self.notes.append(text)

    def begin_line(self, tool: str) -> None:
        """Print a call's name BEFORE it is made, and leave the line open.

        The run looked hung on admin_prometheus_targets. It was not: the next tool
        was an SDK read on port 11207, which with the corporate tunnel up does not
        fail, it hangs -- Capella drops packets from unlisted sources rather than
        refusing them -- and at the old 90-second timeout a handful of those is
        several silent minutes.

        Nothing about the logic was wrong. The output was: a name printed only on
        completion cannot distinguish "working" from "stopped", and the name a
        reader is staring at is the last one that SUCCEEDED, which points at the
        wrong tool. This is the same lesson the keyspace sweep taught -- print what
        is being asked, not only what answered.
        """
        print(f"  {tool:<46} ", end="", flush=True, file=self.out)
        if self._mirror is not None:
            print(f"  {tool:<46} ", end="", flush=True, file=self._mirror)
        self._line_open = True

    def record(self, result: Result) -> Result:
        self.results.append(result)
        marker = {
            OK: "ok",
            EMPTY: "ok (empty)",
            PREVIEW: "preview",
            GATED: "gated",
            GUARDED: "guarded",
            UPSTREAM: "UPSTREAM",
            SKIPPED: "skipped",
            NOT_REACHED: "not reached",
            TIMEOUT: "TIMEOUT",
            PROTOCOL: "PROTOCOL FAILURE",
            PERFORMED: "*** PERFORMED ***",
        }[result.outcome]
        if self._line_open:
            # Completing a line begin_line() opened, so the name is not repeated.
            line = marker
            self._line_open = False
        else:
            line = f"  {result.tool:<46} {marker}"
        if result.detail:
            line += f"  — {result.detail}"
        self.say(line)
        if result.shape and self.args.verbose:
            self.say(f"  {'':<46} {result.shape}")
        return result

    # -- calling ----------------------------------------------------------

    async def call(
        self,
        session,
        name: str,
        arguments: dict[str, Any],
        *,
        phase: str,
        confirm: bool = False,
    ) -> tuple[Any, Result]:
        """One tool call, classified and recorded.

        Every call carries ``correlation_id``. That is not decoration: it is the
        field the audit record uses to tie a fan-out back to the action that
        started it, it was advertised and plumbed for a while before anything
        actually sent it, and a run of this script is exactly the kind of fan-out
        it exists for. Afterwards the whole run is one grep of the audit log.
        """
        self.begin_line(name)
        sent = dict(arguments)
        sent["correlation_id"] = self.correlation
        if confirm:
            sent["confirm"] = True

        try:
            response = await asyncio.wait_for(
                session.call_tool(name, arguments=sent),
                timeout=self.args.timeout,
            )
        except asyncio.TimeoutError:
            self._consecutive_timeouts += 1
            return None, self.record(
                Result(
                    name,
                    TIMEOUT,
                    f"no response within {self.args.timeout:g}s{self._target_hint()}",
                    arguments,
                    phase=phase,
                )
            )
        # A bare `except Exception` on purpose: the client raising IS the finding,
        # and one unroutable tool must not abandon every tool after it.
        except Exception as exc:
            return None, self.record(
                Result(
                    name,
                    PROTOCOL,
                    f"{type(exc).__name__}: {exc}",
                    arguments,
                    phase=phase,
                )
            )

        self._consecutive_timeouts = 0
        text, payload = _text_and_payload(response)
        outcome, detail = classify(payload, phase=phase, text=text)
        shape = (
            json.dumps(payload, indent=2, default=str)[:4000]
            if self.args.print_bodies
            else _shape(payload)
        )
        return payload, self.record(
            Result(name, outcome, detail, arguments, shape, phase=phase)
        )

    def _target_hint(self) -> str:
        """Name the cluster the server is pointed at, on every timeout.

        A hang was read twice as evidence about the corporate tunnel. It was not:
        the SDK tools default to ``couchbase://localhost`` when
        CB_CONNECTION_STRING is unset, and a connection to a cluster that is not
        there blocks exactly the same way a firewalled one does.

        cb_mcp_status already reports the connection string, redacted, and this
        run already has it. Printing it turns "hung" into "hung trying to reach
        X", which answers the question instead of inviting a theory about it —
        the same reason the keyspace sweep prints what it asked for.
        """
        connection = (self.status.get("connection") or {}).get("connection_string")
        if not connection:
            return " — the call never came back, which says nothing about the tool"
        return (
            f" — the server is pointed at {connection}. A data-plane tool blocks "
            "the same way on an unreachable cluster and on one that does not "
            "exist, so check that this is the cluster you meant. If it is, check "
            "what the cluster ADVERTISES: GET /pools/nodes returning a private "
            "address such as 172.18.0.2 means a containerised cluster handing the "
            "SDK a node address the host cannot route to. REST answers on a "
            "published port while every SDK call hangs, which looks like a network "
            "problem and is a cluster-map problem. Alternate addresses are the fix."
        )

    # -- phases -----------------------------------------------------------

    async def phase_protocol(self, session) -> None:
        self.say("== protocol ==")
        listing = await session.list_tools()
        self.advertised = list(listing.tools)
        names = sorted(t.name for t in self.advertised)
        self.say(f"  advertised tools: {len(names)}")

        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            self.record(
                Result(
                    "list_tools",
                    PROTOCOL,
                    f"duplicate tool names: {duplicates}",
                    phase="protocol",
                )
            )

        malformed = [
            t.name
            for t in self.advertised
            if not isinstance(_input_schema(t), dict)
            or not isinstance(_input_schema(t).get("properties", {}), dict)
        ]
        if malformed:
            self.record(
                Result(
                    "list_tools",
                    PROTOCOL,
                    f"tools with an unreadable input schema: {malformed[:6]}",
                    phase="protocol",
                )
            )

        # cb_mcp_status is the first call deliberately. It touches no cluster, so
        # if it answers, the transport, the dispatch, the audit path and the
        # response encoding are all working, and every later failure is about
        # Capella rather than about this server.
        payload, _ = await self.call(session, "cb_mcp_status", {}, phase="protocol")
        if isinstance(payload, dict) and not _is_error(payload):
            self.status = payload
            tools = payload.get("tools", {})
            safety = payload.get("safety", {})
            self.say(
                f"  registry: {tools.get('registered')} registered, "
                f"{tools.get('loaded')} loaded, "
                f"{tools.get('filtered_out')} filtered out"
            )
            self.say(
                f"  posture : read_only={safety.get('read_only_mode')} "
                f"disabled={safety.get('disabled_tools_count')} "
                f"confirm_required={safety.get('confirmation_required_count')}"
            )

        self._warn_about_the_data_plane()
        self._crosscheck_registry(names)
        self.say()

    def _warn_about_the_data_plane(self) -> None:
        """Say up front where the SDK tools will dial, when it is nowhere.

        CB_CONNECTION_STRING defaults to couchbase://localhost. With it unset —
        the normal state for a server configured for Capella, since the control
        plane needs no connection string at all — every cb_* diagnostic dials a
        default rather than a configured target.

        The note says that and stops there, deliberately. It does NOT say the
        cluster is absent: on the machine this was written for, something was in
        fact listening on 11210, and the likelier cause was an unset CB_BUCKET
        leaving the SDK retrying a bucket open. Every wrong reading in this
        investigation came from a note like this one asserting a cause instead of
        naming the configuration and stopping.

        The information was already in the cb_mcp_status payload this phase just
        fetched. Nothing was missing except the sentence.
        """
        connection = (self.status.get("connection") or {}).get("connection_string", "")
        if not connection or "localhost" not in connection:
            return
        data_plane = sorted(
            t.name for t in self.advertised if _is_data_plane(getattr(t, "name", ""))
        )
        if not data_plane:
            return
        self.note(
            f"The server reports {connection}. That is also the default when "
            "CB_CONNECTION_STRING is unset, and from here the two are "
            f"indistinguishable. The {len(data_plane)} cluster-touching tool(s) "
            "will dial it. If they time out, that is this "
            "configuration and NOT the network and NOT Capella: the control-plane "
            "tools need no connection string at all. Check CB_BUCKET too (it "
            "defaults to 'default', and a bucket that does not exist makes the SDK "
            "retry the open until it times out, which looks identical to an "
            "unreachable cluster). Run with --only capella_ to skip them, or set "
            "both variables to exercise them properly."
        )
        self.say(
            f"  NOTE: the server is pointed at {connection}; {len(data_plane)} "
            "cluster-touching tool(s) will dial it. --only capella_ skips them."
        )

    def _crosscheck_registry(self, advertised: list[str]) -> None:
        """Compare the advertised surface against what the server registers.

        Two different questions, and the first version conflated them.

        `handlers.capella.TOOLS` is what the server actually registers. It is the
        primitive registry PLUS the environment tools and the fixture tools, which
        are handled by their own modules and have no `Op` record at all. Comparing
        against `spec.OPS_BY_NAME` alone reported capella_env_*, capella_fixture_*
        and capella_guardrails_status as tools advertised by nobody — seven false
        strays, on the first live run.

        The second question is which registered operations this POSTURE leaves
        out, which read-only mode and deployment gating both do legitimately. An
        unexplained count there reads as drift; a count with the reason attached
        reads as the filter working.
        """
        try:
            sys.path.insert(0, REPO_ROOT)
            os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
            from handlers.capella import TOOLS as CAPELLA_TOOLS
            from handlers.capella.spec import SHIPPED_UNVERIFIED
        except Exception as exc:
            # Reported, never swallowed. A cross-check that quietly does not run
            # is worse than one that fails, because the report still looks complete.
            self.note(
                f"registry cross-check UNAVAILABLE ({type(exc).__name__}: {exc}) — "
                "the advertised list was not compared against the shipped registry"
            )
            return

        registered = {getattr(t, "name", "") for t in CAPELLA_TOOLS}
        advertised_set = set(advertised)

        strays = sorted(
            name for name in advertised_set - registered if name.startswith("capella_")
        )
        if strays:
            self.note("advertised but registered by no handler: " + ", ".join(strays))

        absent = sorted(registered - advertised_set)
        if absent:
            # Split by what the filter would explain. A write tool missing under
            # read-only mode is the filter working; a READ tool missing is not,
            # and that is the one worth surfacing on its own line.
            # Read the annotation off the REGISTERED tool, not the Op.
            #
            # capella_env_* and capella_fixture_import are handled by their own
            # modules and have no Op record, so `name in OPS_BY_NAME and not
            # read_only` could not classify them and they fell through to
            # "unexplained" -- six write tools reported as read tools that should
            # have loaded. The annotation is on the Tool, it is what the read-only
            # filter itself reads, and it exists for every registered tool.
            by_name = {getattr(t, "name", ""): t for t in CAPELLA_TOOLS}
            writes = [
                name
                for name in absent
                if name in by_name and not _is_read_only(by_name[name])
            ]
            unexplained = sorted(set(absent) - set(writes))
            self.note(
                f"{len(absent)} registered Capella tool(s) are not advertised in "
                f"this posture; {len(writes)} of them are write tools, which is "
                "read-only mode doing its job"
            )
            if unexplained:
                self.note(
                    "NOT explained by read-only mode — these are read tools and "
                    "should have loaded: "
                    + ", ".join(unexplained[:10])
                    + (" …" if len(unexplained) > 10 else "")
                )

        if SHIPPED_UNVERIFIED:
            self.note(
                "shipped-but-unverified operations in this build: "
                + ", ".join(sorted(SHIPPED_UNVERIFIED))
            )

    async def phase_discovery(self, session) -> None:
        """Fill the context by calling the list tools, in dependency order."""
        self.say("== discovery ==")
        advertised = {t.name for t in self.advertised}

        # SEED THE LITERALS FIRST, NOT ONLY LAST.
        #
        # _seed_derived_context ran at the END of this phase, so every literal it
        # supplies was missing while the discovery loop needed it. That cost
        # nothing until a discovery tool took one: capella_fixture_list needs
        # root_path, which is a literal, and the loop reported
        #
        #   capella_fixture_list   not yet resolvable (needs ['root_path'])
        #
        # then the value was seeded four lines later. Three fixture tools stayed
        # SKIPPED for want of an argument this script had all along -- the same
        # class of mistake as the missing _DISCOVERY entries, one layer up.
        #
        # Calling it twice is safe by construction: every assignment in it is a
        # setdefault, so the second call cannot overwrite anything discovery
        # found. It runs again at the end because a few literals are only useful
        # once discovery has supplied what they sit beside.
        self._seed_derived_context()

        # Seed every id the environment pins, not just the organization.
        #
        # CAPELLA_ORG_ID was honoured and the other two were not, which was
        # harmless while the organization held ONE cluster and became the whole
        # run the moment it held two: `_choose` takes the first row for anything
        # that is not a bucket, so a second cluster silently moved the target.
        # A run against a cluster with no buckets, no backups and no app services
        # reports 134 SKIPPED and looks like a collapse in coverage when nothing
        # about the server changed.
        for env_name, key in (
            ("CAPELLA_ORG_ID", "organization_id"),
            ("CAPELLA_PROJECT_ID", "project_id"),
            ("CAPELLA_CLUSTER_ID", "cluster_id"),
        ):
            pinned = os.environ.get(env_name, "").strip()
            if pinned:
                self.context[key] = pinned
                self.say(f"  {key} from {env_name}: {pinned}")

        for tool, key, item_field in _DISCOVERY:
            if tool not in advertised or key in self.context_for(tool):
                continue
            if tool in _HARVEST_ONLY:
                continue
            if self.args.only and not tool.startswith(self.args.only):
                # --only restricted the read phase but not this loop, so a run
                # asked for `capella_` still called the self-managed list tools and
                # counted their 404s. An evidence file for one deployment must not
                # carry results from the other.
                continue
            schema = _input_schema(next(t for t in self.advertised if t.name == tool))
            arguments, missing = resolve_arguments(schema, self.context_for(tool))
            if missing:
                self.say(f"  {tool:<46} not yet resolvable (needs {missing})")
                continue
            payload, result = await self.call(
                session, tool, arguments, phase="discovery"
            )
            if result.outcome not in _SUCCESSFUL:
                continue
            reader = _ROWS_READER.get(tool)
            envelope = _ENVELOPE_KEY.get(tool)
            if reader is not None and isinstance(payload, dict):
                raw_rows = reader(payload)
            elif (
                envelope
                and isinstance(payload, dict)
                and isinstance(payload.get(envelope), list)
            ):
                raw_rows = payload[envelope]
            else:
                raw_rows = _items(payload)
            rows = [_unwrap(row) for row in raw_rows]
            if tool in _FIELD_FROM_URI:
                for row in rows:
                    if isinstance(row, dict) and row.get("uri") and not row.get(key):
                        row[key] = str(row["uri"]).rstrip("/").rsplit("/", 1)[-1]
            chosen = self._choose(tool, rows, item_field)
            if chosen is None:
                self.say(f"  {tool:<46} {self._nothing_to_select(rows, item_field)}")
                continue
            self.context_for(tool)[key] = chosen
            self._report_choice(key, chosen, rows, item_field, side_of(tool))

            # KEEP THE ROW, not only the id, for the one case where a later
            # argument has to be BUILT from the object rather than copied out of
            # it. app_endpoint_keyspace is `<endpoint>.<scope>.<collection>`,
            # and the scope and collection live nowhere but this row. Stored
            # under a leading underscore so it is never mistaken for a resolved
            # argument and never sent to a tool.
            if tool == "capella_clusters_list":
                # Kept for the cross-cluster replication lookup below: a
                # replication is listed on its SOURCE, which may not be the
                # cluster this run selected.
                self.context_for(tool)["_cluster_rows"] = [
                    r for r in rows if isinstance(r, dict)
                ]

            if tool == "capella_app_endpoints_list":
                # item_field is a str OR a tuple of candidate spellings -- see
                # _DISCOVERY, where this entry is ("name", "id"). row.get(tuple)
                # looks up a TUPLE KEY, finds nothing, and matches no row, so
                # the first version of this silently stored nothing and the
                # keyspace it exists to build stayed missing. A dict lookup with
                # the wrong key type fails quietly, which is the whole problem.
                fields = (item_field,) if isinstance(item_field, str) else item_field
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    if any(str(row.get(f)) == chosen for f in fields):
                        self.context_for(tool)["_app_endpoint_row"] = row
                        break

        # REPLICATIONS LIVE ON THE SOURCE. If none is visible here, look at the
        # other clusters in this project before concluding there are none --
        # and keep the cluster alongside the id, because the pair is what makes
        # the id usable. See _CLUSTER_FROM.
        capella_ctx = self.contexts[CAPELLA_SIDE]
        if (
            "capella_replications_list" in advertised
            and not capella_ctx.get("replication_id")
            and capella_ctx.get("organization_id")
            and capella_ctx.get("project_id")
        ):
            others = [
                str(row.get("id"))
                for row in (capella_ctx.get("_cluster_rows") or [])
                if isinstance(row, dict)
                and str(row.get("id")) != capella_ctx.get("cluster_id")
            ]
            for other in others:
                payload, result = await self.call(
                    session,
                    "capella_replications_list",
                    {
                        "organization_id": capella_ctx["organization_id"],
                        "project_id": capella_ctx["project_id"],
                        "cluster_id": other,
                    },
                    phase="discovery",
                )
                if result.outcome not in _SUCCESSFUL:
                    continue
                rows = [_unwrap(r) for r in _items(payload)]
                found = next(
                    (
                        str(r.get("id"))
                        for r in rows
                        if isinstance(r, dict) and r.get("id")
                    ),
                    "",
                )
                if found:
                    capella_ctx["replication_id"] = found
                    capella_ctx["_replication_cluster_id"] = other
                    self.say(f"  {'replication_id (on another cluster)':<46} {found}")
                    self.say(f"  {'  its source cluster':<46} {other}")
                    break

        mode_note = (self.status.get("connection") or {}).get("connection_string", "")
        if mode_note and "cloud.couchbase.com" not in mode_note:
            capella_side = any(n.startswith("capella_") for n in advertised)
            if capella_side:
                self.note(
                    "This run spans BOTH deployments: a self-managed cluster at "
                    f"{mode_note} and the Capella control plane. `scope_name` and "
                    "`collection_name` are plain names in both vocabularies and "
                    "discovery can only hold one value for each, so some "
                    "cross-side reads will answer 404. Those are UPSTREAM results "
                    "about a name that does not exist on that side, not tools "
                    "that failed to dispatch."
                )

        # A bucket's scope list is the only place collections come from, and it
        # is also where the bucket-id-versus-bucket-name distinction bites: a
        # keyspace is three NAMES, while everything else in v4 addresses a bucket
        # by an opaque id.
        await self._discover_keyspace(session, advertised)
        self._seed_derived_context()
        self.say()

    def _seed_derived_context(self) -> None:
        """Fill the arguments that are LITERALS, not discovered objects.

        These were the other kind of SKIPPED. "no value for statement" does not
        mean the cluster is missing something — there is no object called a
        statement. It means this script never invented one, and every run
        reported a dozen tools as untested for want of values that cost nothing
        to produce. That is a gap in the CHECKER reported as a gap in the
        ENVIRONMENT, which is the distinction the write phase is careful about
        and discovery was not.

        Each value below is chosen to exercise the tool without depending on
        anything: `SELECT 1` is valid SQL++ that names no keyspace, so it works
        on a cluster with no buckets and cannot be broken by whatever the sample
        data happens to look like. Nothing here is discovered, so nothing here
        can be stale.
        """
        cluster = self.contexts[CLUSTER_SIDE]
        capella = self.contexts[CAPELLA_SIDE]

        # A statement that names no keyspace. cb_explain_query and
        # cb_index_advisor both parse before they plan, so this reaches the
        # planner without needing a bucket to exist.
        #
        # TYPES MATTER HERE. `statement` is a string and `statements` is an
        # ARRAY of strings; seeding both as strings would have replaced "no value
        # for statements" with a schema-validation failure upstream of the
        # handler -- a skip turned into a false defect, which is worse than the
        # skip. The shapes below were read off the shipped inputSchemas, not
        # assumed from the names.
        cluster.setdefault("statement", "SELECT 1")
        cluster.setdefault("statements", ["SELECT 1"])

        # admin_stats_single takes a metric NAME. admin_stats_multi takes a list
        # of ns_server range-query objects, each carrying Prometheus label
        # matchers -- a different shape entirely despite the similar argument
        # name. kv_curr_items is exported by every Data node.
        cluster.setdefault("metric_name", "kv_curr_items")
        cluster.setdefault(
            "metrics",
            [{"metric": [{"label": "name", "value": "kv_curr_items"}], "step": 60}],
        )

        # cb_mcp_get_tool_info describes a tool, and this script is holding the
        # list of every advertised tool. Prefer one that is always present.
        known = sorted(t.name for t in self.advertised)
        if known:
            preferred = "cb_mcp_status" if "cb_mcp_status" in known else known[0]
            cluster.setdefault("tool_name", preferred)
            capella.setdefault("tool_name", preferred)

        # capella_fixture_list walks a directory on THIS machine, so the only
        # sensible root is the repository the server was started from.
        # THE REPOSITORY ROOT IS NOT WHERE FIXTURES LIVE. capella_fixture_list
        # answers "how many fixtures are under this path", and pointed at the
        # repository root it correctly answered zero -- the fixture is in
        # <repo>/fixtures/<id>/manifest.json. Prefer that directory when it
        # exists, so the tool is asked the question it can answer.
        # The catalogue's own default, so a run with no configuration looks where
        # the tools would have written.
        capella.setdefault(
            "catalog_root",
            os.environ.get("CB_ADMIN_CATALOG_ROOT")
            or os.path.join(REPO_ROOT, ".backup-catalog"),
        )
        fixtures_dir = os.path.join(REPO_ROOT, "fixtures")
        capella.setdefault(
            "root_path",
            fixtures_dir if os.path.isdir(fixtures_dir) else REPO_ROOT,
        )

        # ONE URL SLOT, TWO PLACEHOLDER NAMES -- AND THEY ARE NOT THE SAME VALUE.
        #
        #   .../appEndpoints/{app_endpoint_name}/cors
        #   .../appEndpoints/{app_endpoint_keyspace}/accessControlFunction
        #
        # RETRACTED 2026-09-14. This block used to say "same position, same
        # value, different spelling" and seeded the keyspace FROM the endpoint
        # name. That was wrong, and it manufactured a 404 that was then read as
        # "no access control function is configured":
        #
        #   PUT .../appEndpoints/test/accessControlFunction
        #   404 {"message": "App Endpoint keyspace test not found"}
        #
        # An access control function is per COLLECTION, not per endpoint. The
        # endpoint document says so plainly once you look at it:
        #
        #   {"name": "test",
        #    "scopes": {"inventory": {"collections": {
        #        "airline": {"accessControlFunction": "function (doc, oldDoc…"}}}}}
        #
        # So the keyspace is `<endpoint>.<scope>.<collection>` -- three parts --
        # and the endpoint name alone is one of them. Building it from the
        # endpoint's own scopes map is the only honest source; inventing the
        # scope and collection would reproduce the same false 404 with more
        # steps.
        endpoint_row = capella.get("_app_endpoint_row")
        endpoint = capella.get("app_endpoint_name")
        keyspace = _app_endpoint_keyspace(endpoint, endpoint_row)
        if keyspace:
            capella.setdefault("app_endpoint_keyspace", keyspace)

        seeded = {
            "statement",
            "statements",
            "metric_name",
            "metrics",
            "tool_name",
            "root_path",
        }
        if capella.get("app_endpoint_keyspace"):
            seeded.add("app_endpoint_keyspace")
        self.say(
            f"  seeded (literals, not discovered)             "
            f"{', '.join(sorted(seeded))}"
        )

    def _choose(self, tool: str, rows: list, item_field: str) -> str | None:
        """Pick one row.

        For buckets the order is deliberate: an explicitly named bucket, then a
        sample bucket, then anything that is not a system keyspace. For everything
        else it is the first usable row, which is arbitrary and reported as such.
        """
        fields = (item_field,) if isinstance(item_field, str) else tuple(item_field)

        def value_of(row: dict) -> str | None:
            for field_name in fields:
                if row.get(field_name):
                    return str(row[field_name])
            return None

        candidates = [
            row for row in rows if isinstance(row, dict) and value_of(row) is not None
        ]
        if not candidates:
            return None

        if tool == "capella_clusters_list":
            # The operator knows this cluster as a name off the console or as a
            # hostname in a connection string; v4 knows it as a uuid. Accept any
            # of the three rather than making someone look it up, and REFUSE on
            # an unmatched name instead of falling through to row zero -- falling
            # through is how a run ends up pointed at the wrong cluster while
            # printing a cluster id that looks deliberate.
            wanted = (getattr(self.args, "capella_cluster", "") or "").strip()
            if wanted:
                needle = wanted.lower()
                named = [
                    r
                    for r in candidates
                    if any(
                        needle in str(r.get(f, "")).lower()
                        for f in ("id", "name", "connectionString")
                    )
                ]
                if len(named) == 1:
                    return value_of(named[0])
                self.note(
                    f"--capella-cluster {wanted!r} matched {len(named)} of "
                    f"{len(candidates)} cluster(s); discovery did NOT select one. "
                    "Every Capella read below is unresolved rather than pointed "
                    "at an arbitrary cluster."
                )
                return None

        if tool in _BUCKET_TOOLS:
            wanted = getattr(self.args, "bucket", "") or ""
            if not wanted and side_of(tool) == CLUSTER_SIDE:
                # CB_BUCKET is what the SERVER was configured with, so it is what
                # the cluster-side tools will actually be asked about. Discovery
                # picking a different bucket meant a run where CB_BUCKET=mcptest
                # was set and every admin_* read went to `harvester` instead --
                # the first non-system row, which is arbitrary and was not what
                # anyone asked for.
                wanted = (os.environ.get("CB_BUCKET") or "").strip()
            if wanted:
                named = [r for r in candidates if str(r.get("name", "")) == wanted]
                if named:
                    return value_of(named[0])
                self.note(
                    f"--bucket {wanted!r} is not on this cluster; "
                    "discovery fell back to its usual order"
                )
            for preference in _PREFERRED_BUCKETS:
                for row in candidates:
                    if str(row.get("name", "")) == preference:
                        return value_of(row)

        usable = [
            row
            for row in candidates
            if str(row.get("name", "")) not in _INTERNAL_BUCKETS
        ]
        return value_of((usable or candidates)[0])

    def _nothing_to_select(self, rows: list, item_field) -> str:
        """Why a selection failed, with the evidence needed to fix it.

        "returned nothing to select" is true of two different situations and only
        one of them is normal. An empty list is normal. A list of rows none of
        which carries the field this table names is a wrong field name, and the
        answer is sitting in the row that was just parsed -- but the old message
        threw it away, so the next step was another guess at the spelling.
        """
        if not rows:
            return "returned no rows"
        fields = (item_field,) if isinstance(item_field, str) else tuple(item_field)
        first = next((r for r in rows if isinstance(r, dict)), None)
        if first is None:
            return f"{len(rows)} row(s), none of them an object"
        return (
            f"{len(rows)} row(s) but none carries {'/'.join(fields)} — "
            f"available keys: {', '.join(sorted(first)[:12])}"
        )

    def _report_choice(
        self,
        key: str,
        chosen: str,
        rows: list,
        item_field: str,
        side: str = CAPELLA_SIDE,
    ) -> None:
        """Say what was picked AND what it was picked out of.

        Added because guessing wrong about which cluster a run had selected cost
        several hours once, and the fix was not better logic — it was printing the
        alternatives. A report that names one id looks the same whether there was
        one candidate or forty.
        """
        labels = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = row.get("name") or row.get(item_field)
            labels.append(str(name))
        label = key if side == CAPELLA_SIDE else f"{key} ({side})"
        detail = f"  {label:<46} {chosen}"
        if len(labels) > 1:
            others = ", ".join(labels[:6]) + (" …" if len(labels) > 6 else "")
            detail += f"   (1 of {len(labels)}: {others})"
        self.say(detail)

    async def _discover_keyspace(self, session, advertised: set[str]) -> None:
        """Resolve bucket NAME, scope and collection for the keyspace reads."""
        if "capella_scopes_list" not in advertised:
            return
        if not all(k in self.context for k in ("cluster_id", "bucket_id")):
            self.say("  keyspace: no bucket resolved, keyspace reads will be skipped")
            return

        # The bucket NAME, which v4 returns base64-encoded as the id. Decoding is
        # the documented relationship and it is worth doing rather than calling
        # the get endpoint: it keeps discovery to one request.
        name = _decode_bucket_id(self.context["bucket_id"])
        if name:
            # `bucket` ONLY, never `bucket_name`.
            #
            # They are two vocabularies, not two spellings. v4 keyspace query
            # parameters are `bucket`/`scope`/`collection`; ns_server addresses a
            # bucket as `bucket_name`. Writing the Capella bucket into
            # `bucket_name` sent every self-managed tool in a `both`-mode run
            # looking for travel-sample on the local cluster, which produced a
            # screenful of 404s that looked like broken tools.
            self.context["bucket"] = name
            self.say(f"  bucket name (decoded){'':<25} {name}")

        schema = _input_schema(
            next(t for t in self.advertised if t.name == "capella_scopes_list")
        )
        arguments, missing = resolve_arguments(schema, self.context)
        if missing:
            return
        payload, result = await self.call(
            session, "capella_scopes_list", arguments, phase="discovery"
        )
        if result.outcome not in _SUCCESSFUL:
            return
        scopes = [_unwrap(row) for row in _items(payload)]
        for scope in scopes:
            if not isinstance(scope, dict):
                continue
            collections = scope.get("collections") or []
            if collections:
                self.context["scope"] = str(scope.get("name"))
                self.context.setdefault("scope_name", self.context["scope"])
                first = _unwrap(collections[0])
                collection_name = (
                    first.get("name") if isinstance(first, dict) else str(first)
                )
                self.context["collection"] = str(collection_name)
                self.context.setdefault("collection_name", self.context["collection"])
                self.say(
                    f"  keyspace{'':<38} "
                    f"{self.context['bucket']}.{self.context['scope']}"
                    f".{self.context['collection']}"
                )
                return
        self.say("  keyspace: no scope with a collection; keyspace reads will be thin")

    async def phase_reads(self, session) -> None:
        """Call every advertised read tool the context can satisfy.

        A fixpoint rather than one pass: a get-by-id tool becomes callable only
        once the corresponding list tool has run, and the dependency order is a
        property of the registry rather than something worth hard-coding. Loop
        until a pass adds nothing.
        """
        self.say("== reads ==")
        called: set[str] = {r.tool for r in self.results}
        for round_number in range(1, self.args.max_rounds + 1):
            progressed = False
            for tool in _read_order(self.advertised):
                if tool.name in called or not _is_read_only(tool):
                    continue
                if self.args.only and not tool.name.startswith(self.args.only):
                    continue
                schema = _input_schema(tool)
                arguments, missing = resolve_arguments(
                    schema, self.context_for(tool.name)
                )
                if missing:
                    continue
                if self._consecutive_timeouts >= self.args.max_timeouts:
                    # Checked INSIDE the loop, not between rounds. Between rounds
                    # is too late: on the first pass every tool is callable, so the
                    # breaker would fire only after all of them had timed out --
                    # which is the wait it exists to prevent.
                    break
                called.add(tool.name)
                progressed = True
                payload, result = await self.call(
                    session, tool.name, arguments, phase="read"
                )
                if result.outcome in _SUCCESSFUL:
                    self._harvest(tool.name, payload)
            if self._consecutive_timeouts >= self.args.max_timeouts:
                break
            if not progressed:
                break
            if round_number == self.args.max_rounds:
                self.note(
                    f"read phase stopped at the {self.args.max_rounds}-round cap; "
                    "some tools may not have been reached"
                )

        if self._consecutive_timeouts >= self.args.max_timeouts:
            self.note(
                f"READ PHASE STOPPED after {self._consecutive_timeouts} calls in a row "
                f"timed out at {self.args.timeout:g}s. Every remaining tool would cost "
                "the same wait for the same answer.\n"
                "    These tools reach a cluster over the SDK rather than the "
                "control plane. Two configuration causes account for every "
                "instance of this seen so far, and neither is a network one:\n"
                "      1. CB_CONNECTION_STRING unset, so it defaults to "
                "couchbase://localhost -- a connection to a cluster that is not "
                "there blocks exactly as a firewalled one does.\n"
                "      2. The cluster advertising an address the client cannot "
                "route to. GET /pools/nodes on a containerised cluster returns "
                "something like 172.18.0.2:8091; the SDK follows the cluster map "
                "and dials that, while REST keeps working on a published port. "
                "Alternate addresses are the fix.\n"
                "    Rule both out before reading this as evidence about the "
                "network.\n"
                f"    This server reports: "
                f"{(self.status.get('connection') or {}).get('connection_string', 'unknown')}"
            )

        # Everything still uncalled, named, AND WITH THE RIGHT REASON.
        #
        # These were one outcome and that was wrong in the direction that matters.
        # When the breaker fired, forty-eight tools whose arguments resolved
        # perfectly well were reported as "skipped -- no value for" with an empty
        # list after it, because this loop recomputes `missing` and finds nothing
        # missing. They were not unresolvable; their turn never came. Reporting a
        # truncated run as an unresolvable one understates coverage and points the
        # reader at the registry instead of at the timeout.
        stopped_early = self._consecutive_timeouts >= self.args.max_timeouts
        for tool in _read_order(self.advertised):
            if tool.name in called or not _is_read_only(tool):
                continue
            if self.args.only and not tool.name.startswith(self.args.only):
                continue
            _, missing = resolve_arguments(
                _input_schema(tool), self.context_for(tool.name)
            )
            if missing:
                self.record(
                    Result(
                        tool.name,
                        SKIPPED,
                        f"no value for {', '.join(missing)}",
                        phase="read",
                    )
                )
            else:
                self.record(
                    Result(
                        tool.name,
                        NOT_REACHED,
                        (
                            "the read phase stopped before its turn"
                            if stopped_early
                            else "callable, but the phase ended before its turn"
                        ),
                        phase="read",
                    )
                )
        self.say()

    def _harvest(self, tool: str, payload: Any) -> None:
        """Fill context from a response, for the tools named in _DISCOVERY."""
        for name, key, item_field in _DISCOVERY:
            if name != tool or key in self.context_for(tool):
                continue
            rows = [_unwrap(row) for row in _items(payload)]
            chosen = self._choose(tool, rows, item_field)
            if chosen is not None:
                self.context_for(tool)[key] = chosen
            elif rows:
                # Reported here too, not only in the discovery loop.
                #
                # Moving a tool to _HARVEST_ONLY moved it out of the loop that
                # reports a failed selection, so a wrong field name became silent
                # again -- the tool answered `ok`, the context stayed empty, and
                # the dependent tool said "no value for" with no clue why. Every
                # place that selects must be able to say why it could not.
                self.say(f"  {tool:<46} {self._nothing_to_select(rows, item_field)}")

    async def phase_writes(self, session) -> None:
        """Prove the write surface dispatches, without performing a write.

        Two calls per tool. The first has no ``confirm`` and must be refused —
        that is the confirmation gate, end to end, which no unit test can prove
        for the transport. The second has ``confirm: true`` and must come back as
        a preview, which is the dry run, also end to end.
        """
        self.say("== writes (previewed) ==")

        safety = self.status.get("safety", {})
        posture = safety.get("dry_run")
        if not isinstance(posture, dict):
            self.note(
                "WRITE PHASE NOT RUN: cb_mcp_status does not report its dry-run "
                "posture, so the set of tools that implement dry_run in their own "
                "handler is unknown. Those tools are NOT intercepted by the "
                "dispatch, and capella_env_reap is one of them — calling it with "
                "confirm:true would reap clusters. Refusing rather than guessing."
            )
            self.say("  refused: server does not report its dry-run posture")
            self.say()
            return

        if posture.get("server_wide") is not True:
            self.note(
                "WRITE PHASE NOT RUN: the server reports CB_ADMIN_DRY_RUN is not in "
                "effect. Without server-wide preview mode a write reaches its handler."
            )
            self.say("  refused: server-wide dry run is not in effect")
            self.say()
            return

        if safety.get("read_only_mode") is not False:
            self.say("  no write tools loaded (read-only mode is still on)")
            self.say()
            return

        handler_owned = set(posture.get("handler_owned") or [])
        if handler_owned:
            self.say(
                f"  excluded — these implement dry_run themselves and are not "
                f"intercepted: {', '.join(sorted(handler_owned))}"
            )

        for tool in self.advertised:
            if _is_read_only(tool) or tool.name in handler_owned:
                continue
            if self.args.only and not tool.name.startswith(self.args.only):
                continue
            schema = _input_schema(tool)
            arguments, missing = resolve_arguments(schema, self.context_for(tool.name))

            # The body first, because its schema carries structure the scalar
            # path cannot. Anything still missing afterwards is synthesised too
            # -- see the note below on why that is safe HERE and would not be
            # anywhere else.
            guessed: list[str] = []
            if missing == ["body"] or ("body" in missing and len(missing) == 1):
                body_schema = (schema.get("properties") or {}).get("body") or {}
                if body_schema.get("type") == "object":
                    arguments["body"], guessed = synthesise_body(
                        body_schema, self.context_for(tool.name), self.args.name_prefix
                    )
                    missing = []
                elif body_schema:
                    # A scalar body -- two ops take JavaScript source as a bare
                    # JSON string: capella_eventing_function_code_set and
                    # capella_app_endpoint_access_control_function_set (the
                    # latter corrected from an object body 2026-09-14, after
                    # three valid inputs all earned the same "does not evaluate
                    # to a function" 400). Generated the same way, flagged the
                    # same way.
                    value, invented = _value_for(
                        "body",
                        body_schema,
                        self.context_for(tool.name),
                        self.args.name_prefix,
                        0,
                    )
                    arguments["body"] = value
                    guessed = ["body"] if invented else []
                    missing = []

            if missing:
                # SYNTHESISE PAYLOAD. NEVER SYNTHESISE AN IDENTITY.
                #
                # A missing identity is a fact about the environment: the object
                # does not exist, and a call aimed at an invented one is aimed at
                # nothing. A missing payload field is a limit of this checker,
                # and a value invented for it is routed nowhere -- it rides in
                # the body or the form, and the worst it can do is earn a 422
                # that names the field, which is information.
                #
                # This block once invented BOTH, justified by the dry run being
                # forced on. See _IDENTITY_FIELDS for why that justification was
                # wrong and which test caught it.
                identities = [n for n in missing if n in _IDENTITY_FIELDS]
                if identities:
                    self.record(
                        Result(
                            tool.name,
                            SKIPPED,
                            "no " + ", ".join(identities) + " exists on this cluster",
                            phase="write",
                        )
                    )
                    continue
                if "body" in missing:
                    # Reached only when the body schema carried no structure to
                    # build from -- an empty schema is not a licence to invent a
                    # shape, because the MCP SDK validates against the schema
                    # before the gate is reached and a made-up body tests the
                    # SDK, not the server.
                    #
                    # NAME THE REMEDY, not just the refusal. A skip that says
                    # only "cannot synthesise" leaves the reader to work out
                    # whether this is a defect, an environment gap, or a limit
                    # of the checker. It is the third, and the thing that
                    # settles it is a LEVEL 3 run -- a real body performed
                    # against a live cluster through a real client, which is
                    # what scripts/backup_cycle_test.py does for the backup
                    # family. Saying so is the difference between a result and
                    # a next step.
                    self.record(
                        Result(
                            tool.name,
                            SKIPPED,
                            "cannot synthesise a body from the shipped schema — "
                            "provable only at Level 3, with a real body performed "
                            "against a live cluster",
                            phase="write",
                        )
                    )
                    continue
                for name in list(missing):
                    spec = (schema.get("properties") or {}).get(name) or {}
                    value, invented = _value_for(
                        name,
                        spec,
                        self.context_for(tool.name),
                        self.args.name_prefix,
                        0,
                    )
                    arguments[name] = value
                    if invented:
                        guessed.append(name)
                missing = []

            # Unconfirmed first, for the tools whose arguments do resolve.
            _, gate = await self.call(session, tool.name, arguments, phase="write")
            if gate.outcome == GATED:
                _, preview = await self.call(
                    session, tool.name, arguments, phase="write", confirm=True
                )
                if guessed and preview.outcome == PREVIEW:
                    # Said plainly, every time. A preview reached with an invented
                    # body proves the GATE and the DISPATCH. It does not prove the
                    # body is one Capella would accept -- that needs a real write,
                    # and claiming otherwise would be exactly the conflation this
                    # script keeps finding in its own output.
                    self.say(
                        f"  {'':<46} synthesised from the shipped schema; "
                        f"invented: {', '.join(guessed)} — gate proven, schema "
                        "validity NOT proven"
                    )
            elif gate.outcome == PREVIEW:
                self.note(
                    f"{tool.name} is NOT confirmation-gated — it went straight to "
                    "the dry run without asking for confirm:true"
                )
        self.say()

    # -- reporting --------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for result in self.results:
            counts[result.outcome] = counts.get(result.outcome, 0) + 1
        failures = [r for r in self.results if r.outcome in _HARD_FAILURES]
        upstream = [r for r in self.results if r.outcome in (UPSTREAM, TIMEOUT)]
        return {
            "started": self.started.isoformat(),
            "correlation_id": self.correlation,
            "counts": counts,
            "hard_failures": [r.as_dict() for r in failures],
            "upstream_errors": [r.as_dict() for r in upstream],
            "notes": self.notes,
            "context": {
                side: dict(sorted(values.items()))
                for side, values in self.contexts.items()
            },
            "results": [r.as_dict() for r in self.results],
        }

    def report(self) -> int:
        summary = self.summary()
        counts = summary["counts"]
        self.say("== summary ==")
        for outcome in (
            OK,
            EMPTY,
            PREVIEW,
            GATED,
            GUARDED,
            UPSTREAM,
            SKIPPED,
            NOT_REACHED,
            TIMEOUT,
            PROTOCOL,
            PERFORMED,
        ):
            if counts.get(outcome):
                self.say(f"  {outcome:<10} {counts[outcome]}")

        if any(self.contexts.values()):
            self.say()
            self.say("  resolved context (what this run was pointed at):")
            for side in (CAPELLA_SIDE, CLUSTER_SIDE):
                values = self.contexts[side]
                if not values:
                    continue
                self.say(f"    [{side}]")
                for key, value in sorted(values.items()):
                    # Underscore keys are working material kept for building
                    # other arguments -- a whole App Endpoint document, for
                    # instance. They are not what the run was "pointed at", and
                    # printing one would bury the summary in JSON.
                    if key.startswith("_"):
                        continue
                    self.say(f"      {key:<24} {value}")
            self.say()

        for note in self.notes:
            self.say(f"  note: {note}")

        performed = [r for r in self.results if r.outcome == PERFORMED]
        if performed:
            self.say()
            self.say("  *** A WRITE WAS PERFORMED IN A PREVIEW PHASE ***")
            for r in performed:
                self.say(f"      {r.tool}: {r.detail}")

        exit_code = 0
        if summary["hard_failures"]:
            exit_code = 1
        elif self.args.strict and (counts.get(UPSTREAM) or counts.get(TIMEOUT)):
            exit_code = 2
        elif self.args.strict and (counts.get(SKIPPED) or counts.get(NOT_REACHED)):
            exit_code = 3

        self.say()
        self.say(f"  exit {exit_code}")
        if self.args.json:
            json.dump(summary, self._out, indent=2)
        return exit_code


def _input_schema(tool: Any) -> dict:
    """A tool's schema under either mcp field spelling.

    The same two-spelling problem ``mcp_compat`` solves server-side, restated in
    six lines rather than imported: this script must run against a checkout whose
    dependencies are not installed, which is the configuration it is most often
    reached from.
    """
    schema = getattr(tool, "inputSchema", None)
    if schema is None:
        schema = getattr(tool, "input_schema", None)
    return schema or {}


def _is_read_only(tool: Any) -> bool:
    annotations = getattr(tool, "annotations", None)
    if annotations is None:
        return False
    value = getattr(annotations, "readOnlyHint", None)
    if value is None:
        value = getattr(annotations, "read_only_hint", None)
    return bool(value)


def _decode_bucket_id(bucket_id: str) -> str:
    """v4 bucket ids are the base64 of the bucket name. Decode, or give up quietly."""
    import base64
    import binascii

    try:
        padded = bucket_id + "=" * (-len(bucket_id) % 4)
        name = base64.b64decode(padded).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""
    return name if name.isprintable() else ""


# ── Entry point ──────────────────────────────────────────────────────────────


async def _drive(run: Run, *, read_only: bool, dry_run: bool, phases) -> None:
    from mcp import ClientSession, StdioServerParameters, stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(REPO_ROOT, "server.py")],
        env=_client_env(read_only=read_only, dry_run=dry_run),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=run.args.timeout)
            for phase in phases:
                await phase(session)


async def run_all(run: Run) -> int:
    run.say(f"verify_mcp_surface — {run.started.isoformat()}")
    run.say(f"repository     : {REPO_ROOT}")
    run.say(f"python         : {sys.version.split()[0]}")
    run.say(f"correlation id : {run.correlation}")
    run.say()

    await _drive(
        run,
        read_only=True,
        dry_run=False,
        phases=[run.phase_protocol, run.phase_discovery, run.phase_reads],
    )

    if run.args.write_preview:
        # A SECOND server, deliberately. Read-only mode and the dry-run flag are
        # both read at import time or from the environment, and flipping them in
        # a running process is not something the server supports — asking it to
        # would test a configuration that cannot occur in production.
        await _drive(
            run,
            read_only=False,
            dry_run=True,
            phases=[run.phase_protocol, run.phase_writes],
        )

    return run.report()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Drive the Couchbase Admin MCP server over stdio and report which "
            "tools a client can actually call."
        )
    )
    parser.add_argument(
        "--write-preview",
        action="store_true",
        help=(
            "Also exercise the write surface. Writes are never performed: the "
            "server is started with CB_ADMIN_DRY_RUN=true, which a caller cannot "
            "override, and the phase refuses to run if the server cannot confirm "
            "that posture."
        ),
    )
    parser.add_argument(
        "--only",
        default="",
        metavar="PREFIX",
        help="Restrict the read and write phases to tools with this name prefix.",
    )
    parser.add_argument(
        "--print-bodies",
        action="store_true",
        help=(
            "Print full response bodies rather than key shapes. Responses carry "
            "allowlists, credential ids and eventing source; the server redacts "
            "what it knows to be secret, but evidence files get attached to "
            "tickets. Off by default for that reason."
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on upstream errors or skipped tools, not just defects.",
    )
    parser.add_argument("--json", action="store_true", help="Append a JSON summary.")
    parser.add_argument("--out", default="", help="Write the transcript to this file.")
    parser.add_argument("--verbose", action="store_true", help="Show response shapes.")
    parser.add_argument(
        "--bucket",
        default="",
        metavar="NAME",
        help=(
            "Bucket to point the keyspace reads at. Defaults to a sample bucket "
            "when one is present, so the check does not select the bucket holding "
            "real data."
        ),
    )
    # 30 rather than 90. A control-plane call answers in well under a second; the
    # only thing the long timeout bought was nine unbroken minutes of silence when
    # six data-plane tools hung in a row.
    parser.add_argument(
        "--name-prefix",
        default="mcptest",
        help=(
            "Prefix for every value this script invents for a request body. "
            "Nothing generated can collide with a real object, and a prefixed "
            "name in a transcript is obviously synthetic six weeks later."
        ),
    )
    parser.add_argument(
        "--capella-cluster",
        default="",
        metavar="ID|NAME|HOST",
        help=(
            "Which Capella cluster to point the run at, by id, name, or a "
            "fragment of its connection string. Required in substance once an "
            "organization holds more than one cluster: without it discovery "
            "takes the first row, which is arbitrary. CAPELLA_CLUSTER_ID pins "
            "the same thing from the environment."
        ),
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--max-timeouts",
        type=int,
        default=3,
        help=(
            "Stop the read phase after this many consecutive timeouts. Three in a "
            "row means the data plane is unreachable, not that three tools are "
            "broken, and the rest of the run would only confirm it slowly."
        ),
    )
    parser.add_argument("--max-rounds", type=int, default=6)
    return parser


def _require_mcp_client() -> None:
    """Fail before the run starts if the client library is missing, and say how.

    The import lives inside `_drive`, so without this check the failure arrives as
    a ModuleNotFoundError traceback several screens below a header that has
    already announced the repository, the interpreter and a correlation id. That
    reads like the SERVER failed to start, which is the one thing it does not
    mean.

    It happens on the obvious command. This repository's dependencies live in a
    uv-managed environment, so `python scripts\\verify_mcp_surface.py` runs under
    whichever interpreter is on PATH and that one has neither `mcp` nor
    `couchbase`. The child server is launched with sys.executable, so an
    interpreter that cannot import the client could not have run the server
    either -- one check covers both.
    """
    import importlib.util

    if importlib.util.find_spec("mcp") is not None:
        return
    raise SystemExit(
        "verify_mcp_surface: the 'mcp' client library is not importable by "
        f"{sys.executable}.\n"
        "\n"
        "This repository's dependencies are uv-managed. Run it through uv:\n"
        "\n"
        "    uv run python scripts/verify_mcp_surface.py\n"
        "\n"
        "That also fixes the server this script starts, which is launched with "
        "the same interpreter.\n"
        "\n"
        "If uv then fails with 'invalid peer certificate: UnknownIssuer', that is "
        "corporate TLS interception, not a broken index -- uv bundles its own CA "
        "store. Set UV_SYSTEM_CERTS=1 first:\n"
        "\n"
        "    $env:UV_SYSTEM_CERTS = '1'\n"
        "\n"
        "Outside uv: pip install 'mcp>=1.10,<2.0'\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # BEFORE the Run is built and before a line of the header is printed. A
    # diagnostic that arrives after the banner gets read as a failure of the thing
    # the banner described.
    _require_mcp_client()
    run = Run(args)
    run.open_output()
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        return asyncio.run(run_all(run))
    finally:
        run.close_output()


if __name__ == "__main__":
    raise SystemExit(main())
