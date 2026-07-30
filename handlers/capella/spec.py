"""
handlers/capella/spec.py — declarative registry of the Capella v4 operations used
by the ephemeral-environment workflow.

WHY DECLARATIVE
===============
Each operation is one ``Op`` record: name, verb, path template, request-body
shape, and safety classification. Tool definitions and dispatch are both
generated from the same records, so a path can never drift from its schema and
a new operation cannot be added with a mismatched annotation. The alternative —
a hand-written function per operation — is where the two Capella bugs in the
previous implementation came from.

PATH PROVENANCE
===============
Every path below is transcribed from a primary source, because a wrong path
fails as an opaque 404 that looks like a missing resource. Sources:

  [TF]   The official Terraform provider, which builds these URLs as Go string
         literals — the most reliable public source of exact v4 paths.
         github.com/couchbasecloud/terraform-provider-couchbase-capella
         internal/resources/{bucket,scope,appservice,cluster_onoff,
         database_credential}.go
  [DOC]  docs.couchbase.com/cloud/management-api-reference — verbatim paths as
         rendered in the API reference.
  [PAT]  Not individually verified; follows the confirmed sibling pattern
         exactly. NONE REMAIN — every path now cites a primary source. The tag is
         kept because it is how a newly-added path should be marked until it has
         one, and scripts/verify_capella_paths.py --only-pat selects on it.
  [LIVE] Path confirmed against a real Capella organization with
         scripts/verify_capella_paths.py — the control plane matched the route
         and answered 405 to an OPTIONS probe, which it can only do after
         routing. Verified 2026-07-30 against a Couchbase-internal test
         organization (v4, cloudapi.cloud.couchbase.com).

         [LIVE] alone asserts the PATH. It does not assert the METHOD, because
         an OPTIONS probe deliberately mutates nothing and a route accepting
         only GET would answer 405 as well.

  [LIVE+METHOD]
         Path AND method confirmed. Sending the real method with an EMPTY body
         returned 422: the route matched, the method was accepted, and the
         request was refused on its contents — so nothing was created. That is
         a stronger result than an OPTIONS probe and, for any operation with
         required body fields, it costs nothing. `--method-probe` does this
         across the surface.

TWO CORRECTIONS TO THE PREVIOUS IMPLEMENTATION
==============================================
  1. App Services are ``/projects/{p}/clusters/{c}/appservices``, NOT
     ``/projects/{p}/appservices``. [TF appservice.go] The old path could never
     have worked.
  2. List endpoints return a ``{"data": [...], "cursor": {...}}`` envelope and
     must be paginated; the old code read page 1 and stopped, silently
     truncating at 100 items. Handled centrally in client.capella_list.

REQUEST BODIES
==============
Write operations take a single ``body`` object argument rather than flattened
per-field arguments. This is deliberate:

  * it maps 1:1 onto the v4 request body, so there is no translation layer to
    get wrong;
  * v4 adds fields faster than this registry can track, and
    ``additionalProperties: true`` lets a caller pass a new field the day it
    ships rather than waiting for a release here;
  * declared ``properties`` still give the model the shape and the enums it
    needs to construct a valid body.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp.types import Tool, ToolAnnotations

# ── Op record ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Op:
    """One Capella v4 operation, and everything needed to expose it as a tool."""

    name: str
    method: str
    path: str
    summary: str
    group: str

    read_only: bool = False
    destructive: bool = False
    idempotent: bool = False

    #: GET list endpoint — auto-paginate the v4 cursor envelope.
    paginated: bool = False
    #: Extra query parameters to expose as tool arguments.
    query: tuple[str, ...] = ()
    #: JSON-schema properties for the request body.
    body: dict[str, Any] = field(default_factory=dict)
    body_required: tuple[str, ...] = ()
    #: Response carries credential material and must be redacted before it
    #: reaches an LLM context window or the server log.
    sensitive_response: bool = False
    #: Enforce the project allowlist / name-prefix guardrails before calling.
    guarded: bool = False

    @property
    def annotations(self) -> ToolAnnotations:
        return ToolAnnotations(
            readOnlyHint=self.read_only,
            destructiveHint=self.destructive,
            idempotentHint=self.idempotent,
        )


# ── Shared schema fragments ──────────────────────────────────────────────────

_ID_DESCRIPTIONS: dict[str, str] = {
    "organization_id": (
        "Capella organization UUID. Omit when CAPELLA_ORG_ID is configured — the "
        "server supplies it and refuses a conflicting override."
    ),
    "project_id": "Capella project UUID. See capella_projects_list.",
    "cluster_id": "Capella cluster UUID. See capella_clusters_list.",
    "bucket_id": (
        "Bucket id as returned by capella_buckets_list — NOT the bucket name. v4 "
        "uses an opaque id for buckets; look it up rather than constructing it."
    ),
    "scope_name": "Scope name (a name, not a UUID).",
    "collection_name": "Collection name (a name, not a UUID).",
    "user_id": "Database credential UUID. See capella_database_credentials_list.",
    "app_service_id": "App Service UUID. See capella_app_services_list.",
    "app_endpoint_name": "App Endpoint name.",
    "app_endpoint_keyspace": (
        "A COLLECTION, written as endpoint.scope.collection — for example "
        "'endpoint1.scope1.collection1'. Supplying a bare App Endpoint name is "
        "accepted but v4 interprets it as 'endpoint1._default._default', so on a "
        "cluster with named scopes it silently targets the wrong collection. Spell "
        "the keyspace out unless you mean the default scope and collection."
    ),
    "allowed_cidr_id": "Allowlist entry UUID.",
    "admin_user_id": "App Service admin user UUID.",
}

_PAGE_QUERY: tuple[str, ...] = ("sortBy", "sortDirection")

# Cluster states used for readiness polling, mirroring the Terraform provider's
# final-state handling. A state in neither set is treated as in-flight by the
# reconciler, which is the safe default: it waits and re-checks rather than
# declaring an environment ready.
TERMINAL_CLUSTER_STATES: frozenset[str] = frozenset(
    {"healthy", "turnedOff", "degraded", "deploymentFailed", "destroyFailed"}
)
IN_FLIGHT_CLUSTER_STATES: frozenset[str] = frozenset(
    {
        "deploying",
        "destroying",
        "scaling",
        "turningOn",
        "turningOff",
        "rebalancing",
        "upgrading",
        "peering",
        "pending",
    }
)

# App Service states observed in the provider's IsFinalState handling.
TERMINAL_APP_SERVICE_STATES: frozenset[str] = frozenset(
    {"healthy", "turnedOff", "degraded", "deploymentFailed"}
)


# ── Body fragments ───────────────────────────────────────────────────────────

_CLUSTER_CREATE_BODY: dict[str, Any] = {
    "name": {
        "type": "string",
        "description": (
            "Cluster name. Must satisfy CAPELLA_ENV_NAME_PREFIX when configured "
            "— the prefix is what makes the cluster reapable later."
        ),
    },
    "description": {
        "type": "string",
        "description": (
            "Free text. The environment orchestrator stores its ownership marker "
            "here (mcp-env:{...}); preserve that line if you edit it by hand, or "
            "capella_env_list and capella_env_reap will stop recognizing this "
            "cluster as theirs."
        ),
    },
    "cloudProvider": {
        "type": "object",
        "description": "Where to deploy. For a throwaway test cluster the region should match the CI runners to keep latency and egress cost down.",
        "properties": {
            "type": {"type": "string", "enum": ["aws", "gcp", "azure"]},
            "region": {"type": "string", "description": "e.g. us-east-1"},
            "cidr": {
                "type": "string",
                "description": (
                    "VPC CIDR for the cluster, e.g. 10.0.0.0/23. Must not overlap "
                    "another cluster you intend to peer with."
                ),
            },
        },
    },
    "couchbaseServer": {
        "type": "object",
        "properties": {"version": {"type": "string", "description": "e.g. 7.6"}},
    },
    "serviceGroups": {
        "type": "array",
        "description": (
            "Node groups. A single group running data+query+index at the smallest "
            "supported compute is the cheapest viable target for app testing."
        ),
        "items": {"type": "object"},
    },
    "availability": {
        "type": "object",
        "description": "{'type': 'single'} for a single-node test cluster; 'multi' for HA.",
        "properties": {"type": {"type": "string", "enum": ["single", "multi"]}},
    },
    "support": {
        "type": "object",
        "description": "{'plan': 'basic'|'developer pro'|'enterprise', 'timezone': 'ET'}. 'basic' is the cheapest and is appropriate for ephemeral test clusters.",
        "properties": {"plan": {"type": "string"}, "timezone": {"type": "string"}},
    },
}

_BUCKET_CREATE_BODY: dict[str, Any] = {
    "name": {"type": "string"},
    "type": {"type": "string", "enum": ["couchbase", "ephemeral"]},
    "storageBackend": {"type": "string", "enum": ["couchstore", "magma"]},
    "memoryAllocationInMb": {
        "type": "integer",
        "description": (
            "Per-node RAM quota. Must fit the cluster's free quota or v4 answers "
            "422. 100 is the practical minimum for couchstore."
        ),
    },
    "bucketConflictResolution": {"type": "string", "enum": ["seqno", "lww"]},
    "durabilityLevel": {
        "type": "string",
        "enum": ["none", "majority", "majorityAndPersistActive", "persistToMajority"],
    },
    "replicas": {
        "type": "integer",
        "description": "0 is valid and correct on a single-node test cluster.",
    },
    "flush": {
        "type": "boolean",
        "description": (
            "Enable flush. Worth true on a test bucket: flushing between test "
            "runs is far cheaper than reprovisioning the cluster."
        ),
    },
    "timeToLiveInSeconds": {"type": "integer"},
}

_DB_CREDENTIAL_BODY: dict[str, Any] = {
    "name": {"type": "string", "description": "Credential username."},
    "password": {
        "type": "string",
        "description": (
            "Omit to have Capella generate one. Generated is preferred: it is "
            "returned once in the create response and never has to appear in a "
            "prompt, a pipeline definition, or this server's log."
        ),
    },
    "access": {
        "type": "array",
        "description": (
            "Privilege grants. Shape: [{'privileges': ['data_reader',"
            "'data_writer'], 'resources': {'buckets': [{'name': 'travel-sample', "
            "'scopes': [{'name': '_default', 'collections': ['_default']}]}]}}]. "
            "Omit 'resources' for access to all buckets. Note that these are "
            "bucket-scoped data roles — Capella never grants cluster-admin here, "
            "which is why the self-managed admin_* tools cannot work."
        ),
        "items": {"type": "object"},
    },
}

#: The node range Capella accepts for an App Service. Named, because the wrong value was
#: hard-coded in three places and a live 422 was the only thing that found it.
MIN_APP_SERVICE_NODES = 2
MAX_APP_SERVICE_NODES = 12

_APP_SERVICE_CREATE_BODY: dict[str, Any] = {
    "name": {"type": "string"},
    "description": {
        "type": "string",
        "description": "Free text; carries the mcp-env marker.",
    },
    # LIVE-CORRECTED. This said "2 is the documented minimum for HA; 1 suffices for
    # testing", which is wrong — Capella rejects 1 outright:
    #
    #   POST .../appservices  {"nodes": 1, ...}
    #   422 {"code":422,"message":"The instance desired capacity must be between 2 and 12."}
    #
    # The claim came from reading the docs, where 2 is described as the HA minimum, and
    # nothing contradicted it because no test ever created an App Service. It made
    # capella_env_create fail at its App Service phase every time.
    "nodes": {
        "type": "integer",
        "description": (
            f"Node count. Capella requires {MIN_APP_SERVICE_NODES}-"
            f"{MAX_APP_SERVICE_NODES} and rejects anything outside that with a 422; "
            f"{MIN_APP_SERVICE_NODES} is both the minimum and the cheapest."
        ),
    },
    "compute": {
        "type": "object",
        "description": "{'cpu': 2, 'ram': 4} — must be a combination the provider offers.",
        "properties": {"cpu": {"type": "integer"}, "ram": {"type": "integer"}},
    },
    "version": {
        "type": "string",
        "description": (
            "App Services version. Immutable after creation — changing it "
            "requires destroying and recreating the App Service."
        ),
    },
    "loadBalancerCidr": {"type": "string"},
}


# ── The registry ─────────────────────────────────────────────────────────────

OPS: tuple[Op, ...] = (
    # ── Organizations ────────────────────────────────────────────────────────
    Op(
        name="capella_organizations_list",
        method="GET",
        path="/v4/organizations",
        summary=(
            "List organizations this API key can see (usually one). Use as the "
            "connectivity and credential check after configuring "
            "CAPELLA_API_KEY_SECRET — it is the cheapest call that proves the "
            "Bearer token is valid."
        ),
        group="organizations",
        read_only=True,
        idempotent=True,
        paginated=True,
    ),
    # ── Projects ─────────────────────────────────────────────────────────────
    Op(
        name="capella_projects_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects",
        summary="List projects in the organization. [DOC]",
        group="projects",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=_PAGE_QUERY,
    ),
    Op(
        name="capella_project_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}",
        summary="Get one project. [DOC]",
        group="projects",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_project_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects",
        summary=(
            "Create a project. A project is the natural boundary for a test "
            "environment: it is also the unit the guardrail allowlist works on, "
            "so a dedicated test project is what keeps teardown away from "
            "production. [DOC]"
        ),
        group="projects",
        body={"name": {"type": "string"}, "description": {"type": "string"}},
        body_required=("name",),
        guarded=True,
    ),
    Op(
        name="capella_project_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}",
        summary=(
            "Delete a project. Fails while it still contains clusters — delete "
            "those first. [DOC]"
        ),
        group="projects",
        destructive=True,
        guarded=True,
    ),
    # ── Clusters ─────────────────────────────────────────────────────────────
    Op(
        name="capella_clusters_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters",
        summary="List clusters in a project. [TF]",
        group="clusters",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=_PAGE_QUERY,
    ),
    Op(
        name="capella_cluster_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}",
        summary=(
            "Get a cluster: cloud provider, region, service groups, support plan, "
            "connection string, and currentState. currentState is the field to "
            "poll for readiness — 'healthy' means usable, 'deploying' / "
            "'turningOn' / 'scaling' mean keep waiting. [TF cluster_onoff.go]"
        ),
        group="clusters",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_cluster_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters",
        summary=(
            "Create a cluster. Returns immediately with an id while deployment "
            "continues asynchronously — expect roughly 5-15 minutes before "
            "currentState reaches 'healthy'. Do not block on this call; poll "
            "capella_cluster_get, or use capella_env_create which handles the "
            "whole sequence. [TF]"
        ),
        group="clusters",
        body=_CLUSTER_CREATE_BODY,
        body_required=(
            "name",
            "cloudProvider",
            "serviceGroups",
            "availability",
            "support",
        ),
        guarded=True,
    ),
    Op(
        name="capella_cluster_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}",
        summary="Update a cluster (scale service groups, change support plan, edit description). [TF]",
        group="clusters",
        body={
            "name": {"type": "string"},
            "description": {"type": "string"},
            "serviceGroups": {"type": "array", "items": {"type": "object"}},
            "support": {"type": "object"},
        },
        guarded=True,
    ),
    Op(
        name="capella_cluster_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}",
        summary=(
            "Delete a cluster and everything in it. Irreversible. Refused unless "
            "the cluster is in an allowlisted project, its name carries the "
            "configured prefix, and Capella deletion protection is off. Delete "
            "any attached App Service first. [TF]"
        ),
        group="clusters",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_cluster_turn_on",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/activationState",
        summary=(
            "Turn a parked cluster back on. Answers 202 and completes "
            "asynchronously. Set turnOnLinkedAppService to bring the attached "
            "App Service up in the same operation — otherwise a mobile client "
            "will reach a live cluster through a dead sync endpoint. Capella "
            "error 7010 means it was already on; the orchestrator treats that as "
            "success. [TF cluster_onoff.go]"
        ),
        group="clusters",
        idempotent=True,
        body={
            "turnOnLinkedAppService": {
                "type": "boolean",
                "description": "Also turn on the linked App Service. Almost always true for mobile testing.",
            }
        },
        guarded=True,
    ),
    Op(
        name="capella_cluster_turn_off",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/activationState",
        summary=(
            "Park a cluster (turn it off) without destroying it — the cheap "
            "middle ground between paying for an idle cluster and paying 5-15 "
            "minutes of provisioning latency on the next test run. Data and "
            "configuration survive. Capella error 7011 means it was already off. "
            "[TF cluster_onoff.go]"
        ),
        group="clusters",
        idempotent=True,
        guarded=True,
    ),
    Op(
        name="capella_cluster_onoff_schedule_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/onOffSchedule",
        summary="Get the cluster's recurring on/off schedule. [PAT — pattern-derived, verify if 404]",
        group="clusters",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_cluster_onoff_schedule_set",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/onOffSchedule",
        summary=(
            "Create a recurring on/off schedule — the set-and-forget way to stop "
            "paying for test clusters overnight and at weekends. Body: "
            "{'timezone': 'ET', 'days': [{'day': 'monday', 'state': 'on', "
            "'from': {...}, 'to': {...}}]}. [PAT — verify if 404]"
        ),
        group="clusters",
        body={
            "timezone": {"type": "string"},
            "days": {"type": "array", "items": {"type": "object"}},
        },
        guarded=True,
    ),
    Op(
        name="capella_cluster_onoff_schedule_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/onOffSchedule",
        summary="Remove the on/off schedule. [PAT — verify if 404]",
        group="clusters",
        destructive=True,
        guarded=True,
    ),
    # ── Buckets, scopes, collections ─────────────────────────────────────────
    Op(
        name="capella_buckets_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets",
        summary="List buckets, with per-bucket item counts and memory/disk usage. [TF]",
        group="buckets",
        read_only=True,
        idempotent=True,
        paginated=True,
    ),
    Op(
        name="capella_bucket_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}",
        summary="Get one bucket, including stats. [TF bucket.go]",
        group="buckets",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_bucket_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets",
        summary="Create a bucket. Fast (seconds), unlike cluster creation. [TF bucket.go]",
        group="buckets",
        body=_BUCKET_CREATE_BODY,
        body_required=("name",),
        guarded=True,
    ),
    Op(
        name="capella_bucket_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}",
        summary="Delete a bucket and its data. Irreversible. [TF bucket.go]",
        group="buckets",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_bucket_flush",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/flush",
        summary=(
            "Delete all documents in a bucket, keeping the bucket and its "
            "indexes. The right reset between test runs — seconds instead of the "
            "minutes a reprovision costs. Requires flush enabled on the bucket. "
            "[PAT — verify if 404; some revisions use PUT]"
        ),
        group="buckets",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_scopes_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/scopes",
        summary="List scopes in a bucket, each with its collections. [TF scope.go]",
        group="buckets",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_scope_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/scopes",
        summary="Create a scope. v4 has no update for scopes — create and delete only. [TF scope.go]",
        group="buckets",
        body={"name": {"type": "string"}},
        body_required=("name",),
        guarded=True,
    ),
    Op(
        name="capella_scope_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/scopes/{scope_name}",
        summary="Delete a scope and every collection in it. [TF scope.go]",
        group="buckets",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_collections_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/scopes/{scope_name}/collections",
        summary="List collections in a scope. [PAT — sibling of the confirmed scopes path]",
        group="buckets",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_collection_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/scopes/{scope_name}/collections",
        summary=(
            "Create a collection. For mobile testing the collection layout must "
            "match what the App Endpoint syncs and what Couchbase Lite expects. "
            "[LIVE+METHOD]"
        ),
        group="buckets",
        body={"name": {"type": "string"}, "maxTTL": {"type": "integer"}},
        body_required=("name",),
        guarded=True,
    ),
    Op(
        name="capella_collection_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/scopes/{scope_name}/collections/{collection_name}",
        summary="Delete a collection and its documents. [LIVE]",
        group="buckets",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_sample_bucket_load",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/sampleBuckets",
        summary=(
            "Load a Couchbase sample dataset (e.g. travel-sample). Useful as "
            "deterministic seed data for app tests without shipping a fixture "
            "loader. Body: {'name': 'travel-sample'}. [PAT — verify if 404]"
        ),
        group="buckets",
        body={
            "name": {
                "type": "string",
                "description": "e.g. travel-sample, beer-sample, gamesim-sample",
            }
        },
        body_required=("name",),
        guarded=True,
    ),
    # ── Database credentials ─────────────────────────────────────────────────
    Op(
        name="capella_database_credentials_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/users",
        summary=(
            "List database credentials on a cluster. Note the path segment is "
            "/users even though the API reference calls these Database "
            "Credentials. Distinct from organization users. [TF database_credential.go]"
        ),
        group="credentials",
        read_only=True,
        idempotent=True,
        paginated=True,
    ),
    Op(
        name="capella_database_credential_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/users/{user_id}",
        summary="Get one database credential. The password is never returned. [TF]",
        group="credentials",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_database_credential_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/users",
        summary=(
            "Create a database credential for the app under test. If password is "
            "omitted Capella generates one and returns it in this response ONLY "
            "— it cannot be retrieved later. This server redacts it from logs and "
            "from the tool result; use capella_env_connection_info, which returns "
            "it once, deliberately, at the point of use. [TF database_credential.go]"
        ),
        group="credentials",
        body=_DB_CREDENTIAL_BODY,
        body_required=("name",),
        sensitive_response=True,
        guarded=True,
    ),
    Op(
        name="capella_database_credential_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/users/{user_id}",
        summary="Delete a database credential. [TF]",
        group="credentials",
        destructive=True,
        guarded=True,
    ),
    # ── Allowed CIDRs ────────────────────────────────────────────────────────
    Op(
        name="capella_allowed_cidrs_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/allowedcidrs",
        summary=(
            "List the cluster's IP allowlist. Capella refuses client connections "
            "from anywhere not on this list, so an empty allowlist is the most "
            "common reason a correctly-provisioned test cluster appears "
            "unreachable. [DOC]"
        ),
        group="networking",
        read_only=True,
        idempotent=True,
        paginated=True,
    ),
    Op(
        name="capella_allowed_cidr_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/allowedcidrs",
        summary=(
            "Add a CIDR to the allowlist. Body: {'cidr': '203.0.113.4/32', "
            "'comment': 'ci-runner', 'expiresAt': '2026-08-01T00:00:00Z'}. Prefer "
            "a /32 for a CI runner and set expiresAt so a temporary rule cannot "
            "outlive the test run. Avoid 0.0.0.0/0 — it exposes the cluster to "
            "the whole internet, and on a test cluster holding a copy of "
            "production-shaped data that is a real exposure, not a theoretical "
            "one. [DOC]"
        ),
        group="networking",
        body={
            "cidr": {"type": "string"},
            "comment": {"type": "string"},
            "expiresAt": {
                "type": "string",
                "description": "RFC3339. Omit for a permanent rule.",
            },
        },
        body_required=("cidr",),
        guarded=True,
    ),
    Op(
        name="capella_allowed_cidr_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/allowedcidrs/{allowed_cidr_id}",
        summary="Remove an allowlist entry. [DOC]",
        group="networking",
        destructive=True,
        guarded=True,
    ),
    # ── App Services (mobile sync) ───────────────────────────────────────────
    Op(
        name="capella_app_services_list",
        method="GET",
        path="/v4/organizations/{organization_id}/appservices",
        summary=(
            "List App Services visible to this API key, ORGANIZATION-WIDE. Narrow with "
            "the projectId query parameter; there is NO clusterId parameter, so for a "
            "single cluster filter the returned items on their `clusterId` field. "
            "Each item carries id, name, clusterId, currentState, version and the "
            "public hostname. [LIVE]"
        ),
        group="app_services",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=("projectId", *_PAGE_QUERY),
    ),
    Op(
        name="capella_app_service_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}",
        summary=(
            "Get an App Service, including currentState and the public hostname "
            "Couchbase Lite connects to. Poll currentState for readiness. [TF]"
        ),
        group="app_services",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_app_service_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices",
        summary=(
            "Create an App Service (managed Sync Gateway) on a cluster — the "
            "endpoint a Couchbase Lite mobile app replicates against. The cluster "
            "must already be healthy. Asynchronous; the provider allows up to 60 "
            "minutes, with ~4-5 minutes typical. Version is immutable after "
            "creation. [TF appservice.go]"
        ),
        group="app_services",
        body=_APP_SERVICE_CREATE_BODY,
        body_required=("name", "compute"),
        guarded=True,
    ),
    Op(
        name="capella_app_service_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}",
        summary=(
            "Delete an App Service. Must happen before the cluster is deleted. "
            "[TF appservice.go]"
        ),
        group="app_services",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_app_service_turn_on",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/activationState",
        summary="Turn on a parked App Service. [PAT — mirrors the confirmed cluster activationState]",
        group="app_services",
        idempotent=True,
        guarded=True,
    ),
    Op(
        name="capella_app_service_turn_off",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/activationState",
        summary=(
            "Park an App Service. Turning the cluster off with "
            "turnOnLinkedAppService handling is usually simpler than managing "
            "both independently. [DOC openapi: DELETE .../activationState]"
        ),
        group="app_services",
        idempotent=True,
        guarded=True,
    ),
    Op(
        name="capella_app_service_certificate_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/certificates",
        summary=(
            "Get the App Service public certificate — what a mobile client pins "
            "or trusts when replicating. [PAT — verify if 404]"
        ),
        group="app_services",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_app_service_allowed_cidrs_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/allowedcidrs",
        summary=(
            "List the App Service allowlist. Separate from the cluster "
            "allowlist: a phone or device farm reaching the sync endpoint needs "
            "an entry HERE, not on the cluster. This trips people up constantly. "
            "[DOC]"
        ),
        group="app_services",
        read_only=True,
        idempotent=True,
        paginated=True,
    ),
    Op(
        name="capella_app_service_allowed_cidr_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/allowedcidrs",
        summary=(
            "Add a CIDR to the App Service allowlist. Mobile devices on carrier "
            "networks have unpredictable addresses — for a device farm, allowlist "
            "the farm's documented egress ranges rather than reaching for "
            "0.0.0.0/0. [DOC]"
        ),
        group="app_services",
        body={
            "cidr": {"type": "string"},
            "comment": {"type": "string"},
            "expiresAt": {"type": "string"},
        },
        body_required=("cidr",),
        guarded=True,
    ),
    Op(
        name="capella_app_service_allowed_cidr_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/allowedcidrs/{allowed_cidr_id}",
        summary="Remove an App Service allowlist entry. [DOC]",
        group="app_services",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_app_service_admin_users_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/adminUsers",
        summary="List App Service admin users. [PAT — verify if 404]",
        group="app_services",
        read_only=True,
        idempotent=True,
        paginated=True,
    ),
    Op(
        name="capella_app_service_admin_user_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/adminUsers",
        summary=(
            "Create an App Service admin user — the credential a test harness "
            "uses against the Sync Gateway admin surface to seed users, channels "
            "or documents. [PAT — verify if 404]"
        ),
        group="app_services",
        body={"name": {"type": "string"}, "password": {"type": "string"}},
        body_required=("name",),
        sensitive_response=True,
        guarded=True,
    ),
    Op(
        name="capella_app_service_admin_user_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/adminUsers/{admin_user_id}",
        summary=(
            "Delete an App Service admin user. "
            "[DOC openapi: DELETE .../adminUsers/{userId}]"
        ),
        group="app_services",
        destructive=True,
        guarded=True,
    ),
    # ── App Endpoints ────────────────────────────────────────────────────────
    Op(
        name="capella_app_endpoints_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints",
        summary="List App Endpoints (the per-keyspace sync databases). [DOC]",
        group="app_endpoints",
        read_only=True,
        idempotent=True,
        paginated=True,
    ),
    Op(
        name="capella_app_endpoint_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_name}",
        summary="Get one App Endpoint. [DOC]",
        group="app_endpoints",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_app_endpoint_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints",
        summary=(
            "Create an App Endpoint — binds a bucket/scope/collection set to a "
            "sync database and defines how documents route to channels. This, not "
            "the App Service itself, is what a Couchbase Lite replicator targets. "
            "A newly created endpoint is offline until brought online. [DOC]"
        ),
        group="app_endpoints",
        body={
            "name": {"type": "string"},
            "bucket": {
                "type": "string",
                "description": "Bucket NAME (not the v4 bucket id).",
            },
            "scopes": {
                "type": "object",
                "description": "Scope/collection mapping to sync.",
            },
            "deltaSync": {"type": "boolean"},
            "userXattrKey": {"type": "string"},
        },
        body_required=("name", "bucket"),
        guarded=True,
    ),
    Op(
        name="capella_app_endpoint_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_name}",
        summary="Delete an App Endpoint. [DOC]",
        group="app_endpoints",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_app_endpoint_online",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_name}/activationStatus",
        summary=(
            "Bring an App Endpoint online (resume). Required after creation — an "
            "offline endpoint accepts no replication, which presents to a mobile "
            "client as an authentication or connectivity failure rather than as "
            "'not started yet'. [DOC]"
        ),
        group="app_endpoints",
        idempotent=True,
        guarded=True,
    ),
    Op(
        name="capella_app_endpoint_offline",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_name}/activationStatus",
        summary="Take an App Endpoint offline (pause). [DOC]",
        group="app_endpoints",
        idempotent=True,
        guarded=True,
    ),
    Op(
        name="capella_app_endpoint_access_control_function_set",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_keyspace}/accessControlFunction",
        summary=(
            "Upsert the access control and validation function — the JavaScript "
            "that assigns documents to channels and authorizes writes. For a test "
            "environment this is the main lever for reproducing the production "
            "sync topology. Body is the function source as a string. [DOC]"
        ),
        group="app_endpoints",
        body={
            "function": {
                "type": "string",
                "description": "JavaScript source of the access control / validation function.",
            }
        },
        guarded=True,
    ),
    Op(
        name="capella_app_endpoint_access_control_function_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_keyspace}/accessControlFunction",
        summary=(
            "Get the current access control and validation function for a COLLECTION. "
            "The path segment is a keyspace (endpoint.scope.collection), not a bare "
            "App Endpoint name — see app_endpoint_keyspace. [DOC]"
        ),
        group="app_endpoints",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_app_endpoint_cors_set",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_name}/cors",
        summary=(
            "Upsert CORS configuration. Needed when the test client is a browser "
            "or a hybrid/webview app rather than native. [DOC]"
        ),
        group="app_endpoints",
        body={
            "origin": {"type": "array", "items": {"type": "string"}},
            "loginOrigin": {"type": "array", "items": {"type": "string"}},
            "headers": {"type": "array", "items": {"type": "string"}},
            "maxAge": {"type": "integer"},
            "disabled": {"type": "boolean"},
        },
        guarded=True,
    ),
    Op(
        name="capella_app_endpoint_resync_start",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_name}/resync",
        summary=(
            "Start a resync — reprocesses existing documents through the access "
            "control function. Required after changing that function, or after "
            "loading seed data directly into the bucket rather than through sync, "
            "otherwise those documents carry no channel assignments and are "
            "invisible to mobile clients. [DOC]"
        ),
        group="app_endpoints",
        guarded=True,
    ),
    Op(
        name="capella_app_endpoint_resync_status",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_name}/resync",
        summary="Get resync progress. [DOC]",
        group="app_endpoints",
        read_only=True,
        idempotent=True,
    ),
    # ── Diagnostics ──────────────────────────────────────────────────────────
    Op(
        name="capella_events_list",
        method="GET",
        path="/v4/organizations/{organization_id}/events",
        summary=(
            "List organization activity events. The first place to look when a "
            "provisioning call succeeded but the cluster never became healthy — "
            "the failure reason lands here, not in the create response. [DOC]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=("sortBy", "sortDirection", "from", "to"),
    ),
    Op(
        name="capella_project_events_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/events",
        summary="List events scoped to one project. [DOC]",
        group="diagnostics",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=("sortBy", "sortDirection", "from", "to"),
    ),
    Op(
        name="capella_cluster_certificate_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/certificates",
        summary=(
            "Get the cluster's TLS certificate. Needed by SDK clients that pin or "
            "explicitly trust it; most Capella SDK connections do not, since the "
            "chain is publicly trusted. [DOC]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
    ),
)


# ── Tool generation ──────────────────────────────────────────────────────────


def _path_arg_schema(name: str) -> dict:
    return {
        "type": "string",
        "description": _ID_DESCRIPTIONS.get(name, f"{name} path parameter."),
    }


def _query_arg_schema(name: str) -> dict:
    descriptions = {
        "sortBy": "Field to sort by.",
        "sortDirection": "asc or desc.",
        "from": "RFC3339 start of the time window.",
        "to": "RFC3339 end of the time window.",
    }
    return {
        "type": "string",
        "description": descriptions.get(name, f"{name} query parameter."),
    }


def build_input_schema(op: Op) -> dict:
    """Build the JSON schema for an Op's tool.

    Path placeholders become required top-level string arguments, except
    organization_id which is optional whenever the server pins CAPELLA_ORG_ID —
    it is declared optional here and resolved at call time, so the same tool
    definition works pinned or unpinned.
    """
    from .client import extract_placeholders

    properties: dict[str, Any] = {}
    required: list[str] = []

    for placeholder in extract_placeholders(op.path):
        properties[placeholder] = _path_arg_schema(placeholder)
        if placeholder != "organization_id":
            required.append(placeholder)

    for q in op.query:
        properties[q] = _query_arg_schema(q)

    if op.paginated:
        properties["max_items"] = {
            "type": "integer",
            "description": (
                "Cap on items collected across pages. Defaults to "
                "CAPELLA_MAX_ITEMS. Results are auto-paginated; a truncated "
                "result says so explicitly."
            ),
        }

    if op.body:
        properties["body"] = {
            "type": "object",
            "description": (
                "Request body, passed to the Capella v4 API as-is. Undeclared "
                "fields are forwarded, so newer v4 fields work without a change "
                "here."
            ),
            "properties": op.body,
            "additionalProperties": True,
        }
        if op.body_required:
            properties["body"]["required"] = list(op.body_required)
            required.append("body")

    if not op.read_only:
        properties["confirm"] = {
            "type": "boolean",
            "description": (
                "Set true to execute a gated write. Required unless the caller is "
                "an automation-scoped principal. Never satisfies the "
                "CB_ADMIN_ALWAYS_CONFIRM ceiling."
            ),
        }

    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def build_tools() -> list[Tool]:
    return [
        Tool(
            name=op.name,
            description=op.summary,
            inputSchema=build_input_schema(op),
            annotations=op.annotations,
        )
        for op in OPS
    ]


OPS_BY_NAME: dict[str, Op] = {op.name: op for op in OPS}

#: Operations a production deployment should put behind the hard ceiling even
#: for automation principals. Referenced by the README rather than applied
#: automatically — the ceiling is the deployer's call, not this file's.
RECOMMENDED_HARD_CEILING: tuple[str, ...] = (
    "capella_project_delete",
    "capella_bucket_delete",
    "capella_bucket_flush",
    "capella_scope_delete",
    "capella_collection_delete",
)
