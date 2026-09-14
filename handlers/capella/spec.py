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

         WRITE IT EXACTLY AS `[PAT` PLUS ANY TRAILING NOTE. The selector matches
         the prefix, not the closed literal `[PAT]`, and that is a correction:
         it used to test `"[PAT]" in summary`, which missed all ten paths that
         were tagged `[PAT — verify if 404]`. --only-pat therefore selected
         nothing and printed "No [PAT] paths remain: every operation now cites a
         primary source" while ten still did not. A check that reports an
         all-clear it has not earned is worse than no check, because it closes
         the question. Those ten have since been verified live and promoted.

  [LIVE] Path confirmed against a real Capella organization with
         scripts/verify_capella_paths.py — the control plane matched the route
         and answered 405 to an OPTIONS probe, which it can only do after
         routing. Verified 2026-07-30 against a Couchbase-internal test
         organization (v4, cloudapi.cloud.couchbase.com).

         [LIVE] alone asserts the PATH. It does not assert the METHOD, because
         an OPTIONS probe deliberately mutates nothing and a route accepting
         only GET would answer 405 as well.

  [LIVE+METHOD]
         Path AND method confirmed, by one of three observations, each of which
         requires the route to have matched AND the method to have been accepted:

           200  the real GET was performed and answered
           404 + a Capella domain code (e.g. 11040) — the handler ran and
                reported the OBJECT absent, which it cannot do before routing
           422  the real method was sent with a deliberately EMPTY body, so the
                request was refused on its contents and nothing was created
                (`--method-probe` does this across the surface)

         The tag carries the observed status so the evidence is legible rather
         than asserted.

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

# ── Live verification record ─────────────────────────────────────────────────

#: Date of the last full sweep against a live Capella organization.
# 2026-07-30 for the original 61; 2026-09-01 for the seventeen promoted from
# spec_pending.py on that date, when the whole registry was re-probed. The later date is
# recorded because it is the one a reader should judge staleness against — but note that
# the App Services subtree SKIPPED in both runs for want of an App Service, so those paths
# rest on the July evidence.
LIVE_VERIFIED_ON = "2026-09-01"

#: Entries observed OUTSIDE the 2026-09-01 sweep, with what produced them.
#:
#: Provenance matters as much as the status. This file's own rule is that a
#: verification claim nobody made is worse than an admitted gap, so an entry
#: recorded by a different tool on a different day says so rather than sitting
#: silently under the LIVE_VERIFIED_ON banner and inheriting a provenance it
#: does not have.
LIVE_VERIFIED_OUT_OF_BAND: dict[str, str] = {
    # LIVE_VERIFIED still says 405 for this operation, and that is correct: 405
    # is what the non-mutating sweep observed. The 422 below came from a real
    # POST by a different tool on a different day, and recording it there would
    # give it a provenance it does not have.
    #
    # It is the strongest evidence this registry holds about the operation, and
    # it is evidence of a DEFECT IN THIS FILE rather than in the server: the
    # summary said the path names the target, Capella says the path names the
    # source, and Capella has a dedicated error code for people who get it that
    # way round.
    # SAME SHAPE, SECOND TOOL. An XDCR replication is defined ON the cluster it
    # replicates FROM, so the path names the SOURCE and body.target.cluster names
    # the cluster that is WRITTEN — continuously, not once. The ownership
    # guardrail had the same blind spot here as on restore and it is now handled
    # generically; see _WRITES_ELSEWHERE in handlers/capella/__init__.py.
    "capella_replication_create": (
        "2026-09-13, scripts/capella_xdcr_setup.py --perform. PERFORMED: the "
        "body {sourceBucket, target:{bucket, cluster, type}, direction:'oneWay', "
        "priority:'low'} was ACCEPTED and answered {\"jobId\": "
        "\"46b2431d-9821-4a2b-8d10-7a1c891c728e\"} — note the response names a "
        "JOB, not the replication, so the id a caller needs for "
        "capella_replication_get comes from capella_replications_list and not "
        "from this create.\n"
        "Both ends are addressed by BUCKET ID, and those ids differ per cluster "
        "even when the bucket name is identical, so neither can be reused across "
        "the two sides of the call.\n"
        "The FIRST attempt was refused by the guardrail because the SOURCE "
        "cluster was in CAPELLA_PROTECTED_CLUSTERS — which is how the "
        "wrong-end-guarded defect was found in this tool. After the fix (see "
        "_WRITES_ELSEWHERE in handlers/capella/__init__.py) the same call was "
        "accepted with the source still protected, and the guard now evaluates "
        "body.target.cluster instead. Both halves of that are load-bearing: the "
        "refusal proved the guard was on the read end, the acceptance proved the "
        "replacement guards the write end without blocking the safe direction."
    ),
    "capella_backup_restore": (
        "2026-09-13, scripts/capella_cross_cluster_restore.py --perform. A real "
        "POST through an MCP client, source Bride-of-Frankenstein -> target a "
        "freshly provisioned cluster, answered 422 code 5026: 'The source "
        "cluster ID is invalid. Please ensure the source cluster id matches the "
        "id in the path.' [LIVE+METHOD] — the method and body were SENT and "
        "REFUSED, so nothing was restored. The four required fields are "
        "confirmed present and correctly named; what was wrong was which cluster "
        "belongs in the path. Corrected in the Op below. A second run with the "
        "path corrected answered 422 code 5022 — target cluster in `peering` — "
        "which is the other documented precondition and is also recorded below. "
        "A THIRD run, path corrected and both clusters healthy, answered "
        "202 ACCEPTED: a real cross-cluster restore, Bride-of-Frankenstein -> "
        "ashmahadevsatyanarayanan, bucket travel-sample, backup "
        "bfacf78e-bd29-4bcb-a72a-9e174768c6b1 (full, 63,349 items). The body "
        "below is now OBSERVED rather than transcribed, and cross-cluster "
        "restore is no longer a documented capability this server had never "
        "exercised."
    ),
    "capella_cloud_snapshot_backups_list": (
        "2026-09-12, scripts/capella_backup_readiness.py. Real GET, 200, cursor "
        "envelope, one snapshot present."
    ),
    "capella_cloud_snapshot_regions_list": (
        "2026-09-12, scripts/capella_backup_readiness.py. Real GET, 200, returns "
        "a bare JSON array of provider regions rather than a cursor envelope."
    ),
    # NOT IN LIVE_VERIFIED, DELIBERATELY. That register holds what the
    # NON-MUTATING probe observed, and a 2xx there would mean the verification
    # run performed a write -- which is the one thing
    # test_no_write_is_recorded_with_a_success_status exists to catch. It caught
    # this entry when the 202 was put there by hand, correctly: "either the probe
    # performed them, or someone recorded a status by hand", and it was the
    # second.
    #
    # The distinction the tag vocabulary draws is worth keeping. [LIVE+METHOD] is
    # earned by a 422 -- the method was SENT and REFUSED, so the method is
    # accepted and nothing was created. A 202 is stronger evidence about the body
    # and weaker evidence about safety: something happened. Those do not belong
    # under one label.
    "capella_backup_create": (
        "2026-09-12, scripts/capella_backup_cycle.py --perform. A real POST "
        "through an MCP client against bucket travel-sample answered 202 "
        "Accepted with an EMPTY body, and the backup subsequently appeared in "
        "capella_backups_list (3 -> 4). This SETTLES body={} as an observation "
        "rather than an omission. LIVE_VERIFIED keeps 405, which is what the "
        "non-mutating path probe saw and all it is entitled to claim."
    ),
    "capella_cloud_snapshot_restores_list": (
        "2026-09-12, scripts/capella_backup_readiness.py. Real GET, 200, cursor "
        "envelope, empty."
    ),
}

#: Every operation, and the HTTP status the control plane answered when its path was last
#: exercised for real by scripts/verify_capella_paths.py.
#:
#: EVERY OPERATION IS PRESENT, and a test asserts that — so "every path is verified" is a
#: checkable property of this file rather than a claim in a commit message. The count used
#: to be written here as a number and went stale every time an operation was added, which
#: teaches the next reader to edit the number rather than ask why it moved. The test counts;
#: this comment does not. Closing the last of them
#: needed an App Service, an App Endpoint, a database credential, two allowlist entries and
#: an App Services admin user to exist, which the script now creates and removes per run.
#:
#: HOW TO READ A STATUS
#:   200  the real GET was performed and answered — path AND method confirmed
#:   404  a Capella DOMAIN code came back (11040), so the handler ran and reported the
#:        object absent, which it cannot do before routing — path and method confirmed
#:   405  an OPTIONS probe matched the route and was refused for the method. Confirms the
#:        PATH ONLY: OPTIONS deliberately mutates nothing, and a GET-only route answers 405
#:        just the same. Every write operation is in this category, by design.
#:
#: So a 405 here is weaker evidence than a 200, and the distinction is worth keeping: it
#: says the URL is right and says nothing about the request body. Three bodies in this
#: registry were wrong while their paths were 405-verified — `access` missing from both
#: credential creates, and `deltaSync` for `deltaSyncEnabled`. A path probe cannot catch
#: that, because it never sends a body.
#: Operations SHIPPED WITHOUT LIVE VERIFICATION, and why.
#:
#: This register exists because the alternative was worse. The ask was "mark XDCR active
#: so Disney can test it and we fix whatever breaks" — a reasonable product call — and the
#: two ways to grant it were to fake a LIVE_VERIFIED entry or to say plainly that these
#: ship on weaker evidence. A faked entry is the exact failure
#: test_every_operation_has_been_verified_against_a_live_organization was written for: a
#: claim of verification that nobody made.
#:
#: What these DO have: a path read from the Terraform provider's generated OpenAPI client,
#: and a sibling on the same route confirmed live. capella_replications_list answered 200
#: and capella_replication_create answered 405 to an OPTIONS probe on 2026-09-01, so
#: /replications exists. What is missing is one call against a real replication id, and
#: the test organization has no replication to make one with.
#:
#: Every entry costs something: build_tools() appends the caveat to the tool description,
#: so a model calling one is told the path is unconfirmed. Clear entries as evidence
#: arrives; a name here for long is a question nobody went back to.
SHIPPED_UNVERIFIED: dict[str, str] = {
    "capella_cluster_audit_log_export_get": (
        "RETRACTION AND RE-MEASUREMENT, 2026-09-13. The note here said an export job "
        "'WAS created successfully and did not persist to the list'. The second half "
        "is FALSE and was never checked: exports persist fine. Two of them were listed "
        "on 2026-09-13, and the earlier conclusion came from reading a list that had "
        "been queried before the create settled.\n\n"
        "What is actually true, all of it measured the same day:\n"
        "  capella_cluster_audit_log_export_create -> 202 {\"exportId\": \"f198d096-...\"}\n"
        "  capella_cluster_audit_log_exports_list  -> 200, rows keyed auditLogExportId,\n"
        "        each carrying status 'no audit log files exist within the requested\n"
        "        time frame'\n"
        "  capella_cluster_audit_log_export_get    -> 404 {\"message\": \"No audit log\n"
        "        files exist within the requested time frame.\"}\n"
        "  capella_cluster_audit_log_config_set    -> 422 'your support package does\n"
        "        not include audit logging'\n\n"
        "So the PATH, the METHOD and the ID FIELD are all confirmed -- the getter was "
        "handed a correct auditLogExportId for an export that exists, under the right "
        "project and cluster. Capella returns 404 for an export that COMPLETED WITH NO "
        "CONTENT, not only for one that does not exist; that is a real behaviour worth "
        "knowing, because it is indistinguishable from a wrong id unless you read the "
        "message. handlers/capella/client.py now stops the generic 'check your ids' "
        "hint from firing over it.\n\n"
        "This stays UNVERIFIED for one reason only: the 200 body has never been seen, "
        "and it cannot be from this organization. Producing content needs audit logging "
        "enabled, and enabling it is refused by ENTITLEMENT -- not by a defect, not by "
        "a missing object, and not by anything this server does. An Enterprise-plan "
        "organization would close it in one run. Response stays redacted either way: it "
        "carries a signed download URL."
    ),
}


LIVE_VERIFIED: dict[str, str] = {
    "capella_alert_integration_create": "422",
    "capella_alert_integration_delete": "405",
    "capella_alert_integration_get": "200",
    "capella_alert_integration_test": "422",
    "capella_alert_integration_update": "405",
    "capella_alert_integrations_list": "200",
    "capella_allowed_cidr_create": "405",
    "capella_allowed_cidr_delete": "405",
    "capella_allowed_cidrs_list": "200",
    "capella_app_endpoint_access_control_function_get": "200",
    "capella_app_endpoint_access_control_function_set": "405",
    "capella_app_endpoint_cors_set": "405",
    "capella_app_endpoint_create": "405",
    "capella_app_endpoint_delete": "405",
    "capella_app_endpoint_get": "200",
    "capella_app_endpoint_offline": "405",
    "capella_app_endpoint_online": "405",
    "capella_app_endpoint_resync_start": "405",
    "capella_app_endpoint_resync_status": "200",
    "capella_app_endpoints_list": "200",
    "capella_app_service_admin_user_create": "405",
    "capella_app_service_admin_user_delete": "405",
    "capella_app_service_admin_users_list": "200",
    "capella_app_service_allowed_cidr_create": "405",
    "capella_app_service_allowed_cidr_delete": "405",
    "capella_app_service_allowed_cidrs_list": "200",
    "capella_app_service_certificate_get": "200",
    "capella_app_service_create": "405",
    "capella_app_service_delete": "405",
    "capella_app_service_get": "200",
    "capella_app_service_turn_off": "405",
    "capella_app_service_turn_on": "405",
    "capella_app_services_list": "200",
    "capella_backup_create": "405",
    "capella_backup_cycle_delete": "405",
    "capella_backup_get": "200",
    "capella_backup_restore": "405",
    "capella_backups_list": "200",
    "capella_cloud_snapshot_backups_list": "200",
    "capella_cloud_snapshot_regions_list": "200",
    "capella_cloud_snapshot_restores_list": "200",
    "capella_bucket_create": "405",
    "capella_bucket_delete": "405",
    "capella_bucket_flush": "405",
    "capella_bucket_get": "200",
    "capella_buckets_list": "200",
    "capella_cluster_audit_log_config_get": "200",
    "capella_cluster_audit_log_config_set": "422",
    "capella_cluster_audit_log_events_list": "200",
    "capella_cluster_audit_log_export_create": "405",
    "capella_cluster_audit_log_exports_list": "200",
    "capella_cluster_certificate_get": "200",
    "capella_cluster_create": "405",
    "capella_cluster_delete": "405",
    "capella_cluster_get": "200",
    "capella_cluster_onoff_schedule_delete": "405",
    "capella_cluster_onoff_schedule_get": "404",
    "capella_cluster_onoff_schedule_set": "405",
    "capella_cluster_stats_get": "200",
    "capella_cluster_turn_off": "405",
    "capella_cluster_turn_on": "405",
    "capella_cluster_update": "405",
    "capella_clusters_list": "200",
    "capella_collection_create": "405",
    "capella_collection_delete": "405",
    "capella_collections_list": "200",
    "capella_database_credential_create": "405",
    "capella_database_credential_delete": "405",
    "capella_database_credential_get": "200",
    "capella_database_credentials_list": "200",
    "capella_event_get": "200",
    "capella_eventing_function_code_get": "200",
    "capella_eventing_function_code_set": "405",
    "capella_eventing_function_create": "405",
    "capella_eventing_function_delete": "405",
    "capella_eventing_function_get": "200",
    "capella_eventing_function_logs_get": "200",
    "capella_eventing_function_state_set": "405",
    "capella_eventing_function_update": "405",
    "capella_eventing_functions_list": "200",
    "capella_events_list": "200",
    "capella_organizations_list": "200",
    "capella_project_create": "405",
    "capella_project_delete": "405",
    "capella_project_events_list": "200",
    "capella_project_get": "200",
    "capella_projects_list": "200",
    "capella_query_index_build_status": "200",
    "capella_query_index_definitions_list": "200",
    "capella_query_index_manage": "405",
    "capella_query_index_properties_get": "200",
    "capella_replication_create": "422",
    "capella_replication_delete": "405",
    "capella_replication_get": "200",
    "capella_replications_list": "200",
    "capella_sample_bucket_load": "405",
    "capella_scope_create": "405",
    "capella_scope_delete": "405",
    "capella_scopes_list": "200",
}


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
    #: The API ACCEPTS an empty body here, observed live. Blocks the empty-body probe.
    #:
    #: `body_required` was doing two jobs and they are not the same claim:
    #:
    #:   1. "a caller must send these fields for the request to make sense" -- a schema
    #:      statement, and what body_required is for;
    #:   2. "the API is guaranteed to REJECT an empty body" -- a statement about the
    #:      server, which --method-probe relies on to send a real write safely.
    #:
    #: capella_alert_integration_update declares config as required, because the
    #: provider's UpdateAlertRequest has it as a non-pointer field. The live API does not
    #: agree: PUT with {} answered 200 on 2026-09-01, and the probe -- reading
    #: body_required as claim (2) -- had already sent it. The operation was performed.
    #:
    #: Conflating a type definition with a server guarantee is how a verification tool
    #: comes to modify the thing it is verifying. This field separates them: the schema
    #: keeps saying config is required, and the probe stops assuming that protects it.
    empty_body_accepted: bool = False

    #: A COMPLETE JSON schema for a request body that is not an object.
    #:
    #: Almost every v4 endpoint takes a JSON object, so `body` above is a map of property
    #: schemas and build_input_schema wraps it in {"type": "object"}. One does not:
    #: PUT .../eventingFunctions/{name}/code takes the JavaScript source as a bare JSON
    #: STRING. Its getter returns one, which is how this was found.
    #:
    #: Kept as a separate field rather than by making `body` polymorphic, so that every
    #: existing reader of `body` — the guards, the probe, the input-schema builder —
    #: keeps its simple contract, and the exception is visible as an exception.
    body_scalar: dict[str, Any] = field(default_factory=dict)
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
    "backup_id": "Managed backup UUID. See capella_backups_list.",
    "event_id": "Event UUID. See capella_events_list or capella_project_events_list.",
    "export_id": "Audit-log export job UUID. Returned by the export-create call.",
    "alert_integration_id": (
        "Alert integration UUID. See capella_alert_integrations_list."
    ),
    "function_name": "Eventing function name (a name, not a UUID).",
    "replication_id": (
        "XDCR replication UUID. See capella_replications_list. NOTE these are "
        "DELETED when a cluster is turned off — capture before park, replay on "
        "resume."
    ),
}

_PAGE_QUERY: tuple[str, ...] = ("sortBy", "sortDirection")

#: The keyspace selectors every /queryService/ read takes. Lived in spec_pending.py while
#: nothing shipped used it; moved here on 2026-09-01 with the query-index promotion, which
#: is what the note there said to do.
#:
#: `bucket` is REQUIRED and is a NAME, not the base64 bucket id -- a keyspace is
#: `bucket`.`scope`.`collection`, three names. Sending the id produces "Index not found in
#: key space", which is true and unhelpful.
_KEYSPACE_QUERY: tuple[str, ...] = ("bucket", "scope", "collection")

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


# ── Request bodies for the operations promoted on 2026-09-01 ─────────────────
#
# Every field below is transcribed from the Terraform provider's generated OpenAPI
# client — the same primary source that corrected the paths — and NOT from a live call.
# The paths are [LIVE]; these shapes are [TF]. That distinction is the point: an OPTIONS
# probe confirms a route and says nothing about what the route wants, which is how these
# operations came to ship with body={} and tools that exposed no way to send anything.

#: CreateClusterAuditSettingsRequest. All three fields are non-pointer in the provider,
#: so all three are required — including the lists, which must be sent empty rather than
#: omitted.
_AUDIT_SETTINGS_BODY: dict[str, Any] = {
    "auditEnabled": {
        "type": "boolean",
        "description": "Whether audit logging is enabled on the cluster.",
    },
    "disabledUsers": {
        "type": "array",
        "description": (
            "Users whose filterable events will NOT be logged. Send [] to filter nobody."
        ),
        "items": {"type": "object"},
    },
    "enabledEventIDs": {
        "type": "array",
        "description": (
            "Filterable audit event ids to record. Read the available ids from "
            "capella_cluster_audit_log_events_list; an id absent here is an event that "
            "will not appear in the audit trail."
        ),
        "items": {"type": "integer"},
    },
}

#: CreateClusterAuditLogExportRequest.
_AUDIT_EXPORT_BODY: dict[str, Any] = {
    "start": {
        "type": "string",
        "description": "Start of the export window, RFC 3339 (e.g. 2026-09-01T00:00:00Z).",
    },
    "end": {
        "type": "string",
        "description": "End of the export window, RFC 3339.",
    },
}

#: IndexDDLRequest. One statement, not a script.
_INDEX_DDL_BODY: dict[str, Any] = {
    "definition": {
        "type": "string",
        "description": (
            "A single CREATE / DROP / ALTER / BUILD index statement. Multiple delimited "
            "queries are rejected. Prefer deferred builds for large indexes, and create "
            "in batches of 100 or fewer."
        ),
    },
}

#: CreateReplicationRequest. Only sourceBucket and target are non-pointer.
_REPLICATION_CREATE_BODY: dict[str, Any] = {
    "sourceBucket": {"type": "string", "description": "Id of the source bucket."},
    "target": {
        "type": "object",
        "description": (
            "The replication target. `bucket` and `cluster` are ids for Capella targets "
            "and names for external ones; `type` is 'capella' or 'external'."
        ),
        "properties": {
            "bucket": {"type": "string"},
            "cluster": {"type": "string"},
            "type": {"type": "string"},
        },
        "required": ["bucket", "cluster"],
    },
    "direction": {
        "type": "string",
        "description": "'oneWay' (source to target) or 'twoWay'.",
    },
    "mode": {"type": "string", "description": "Replication creation mode."},
    "priority": {
        "type": "string",
        "description": (
            "'low', 'medium' or 'high'. Resource allocation relative to other "
            "replications; high is the default and applies no constraints."
        ),
    },
    "networkUsageLimit": {
        "type": "integer",
        "description": "MiB per second. 0 means unlimited.",
    },
    "filter": {"type": "object", "description": "Server-side replication filter."},
    "mappings": {
        "type": "object",
        "description": (
            "Source-to-target scope and collection mappings. Only needed when "
            "replicating specific scopes; an empty or omitted collections array means "
            "every collection under that scope."
        ),
    },
}

#: RequestWebhook. This shipped as a bare {"type": "object"} — technically a schema and
#: practically useless, since it told a caller nothing about url, method or auth. A live
#: 422 named the gap: "The webhook config provided does not provide a valid
#: authentication method. Please provide either basic auth credentials or a token."
#:
#: An opaque object is the body={} defect wearing a different hat. The guard added on
#: 2026-09-01 checks that a body EXISTS, not that it says anything — which is why this
#: got through it.
_ALERT_WEBHOOK: dict[str, Any] = {
    "type": "object",
    "description": (
        "Where the alert is delivered. EXACTLY ONE authentication method is required — "
        "`basicAuth` or `token` — and a config carrying neither is rejected with 422. "
        "CREATING an integration makes Capella send a REAL request to this URL "
        "immediately; a destination that does not answer 2xx fails the create. "
        "Three constraints, all established from live 422s rather than from any "
        "document: an auth method is required, the scheme must be https, and the "
        "endpoint must answer 2xx to a POST."
    ),
    "properties": {
        "url": {
            "type": "string",
            "description": (
                "Base URL of the webhook. MUST be https -- Capella rejects any other "
                "scheme with 422 before it attempts the call."
            ),
        },
        "method": {
            "type": "string",
            "description": "HTTP method used to deliver the alert.",
            "enum": ["POST", "PUT"],
        },
        "basicAuth": {
            "type": "object",
            "description": (
                "Basic credentials for the receiving endpoint. SECRET-BEARING: "
                "handlers.shared.redact masks this whole object before it reaches a log, "
                "an audit record or a model context — verified, not assumed."
            ),
            "properties": {
                "user": {"type": "string"},
                "password": {"type": "string"},
            },
            "required": ["user", "password"],
        },
        "token": {
            "type": "string",
            "description": (
                "Bearer token for the receiving endpoint, as an alternative to "
                "basicAuth. Masked by handlers.shared.redact."
            ),
        },
        "headers": {
            "type": "object",
            "description": "Additional headers to send with the alert.",
        },
        "exclude": {"type": "object", "description": "Alert kinds to suppress."},
    },
    "required": ["url", "method"],
}

#: CreateAlertRequest. `config` carries a webhook object; this is the EGRESS field, and
#: it is why the alert-integration writes are guarded.
_ALERT_INTEGRATION_BODY: dict[str, Any] = {
    "name": {"type": "string", "description": "Up to 1024 characters."},
    "kind": {
        "type": "string",
        "description": "Integration type. Only 'webhook' is currently supported.",
    },
    "config": {
        "type": "object",
        "description": (
            "Destination configuration. This names an OUTBOUND host, so it must clear "
            "the egress allowlist before it is sent."
        ),
        "properties": {"webhook": _ALERT_WEBHOOK},
        "required": ["webhook"],
    },
}

#: UpdateAlertRequest. `config` is required and `name` is not -- an update REPLACES the
#: destination, so omitting config is not "leave it alone", it is an invalid request.
_ALERT_INTEGRATION_UPDATE_BODY: dict[str, Any] = {
    "config": _ALERT_INTEGRATION_BODY["config"],
    "name": _ALERT_INTEGRATION_BODY["name"],
}

#: PostTestAlertIntegrationJSONBody — the same shape minus the name, because a test
#: sends to a destination without creating anything.
_ALERT_INTEGRATION_TEST_BODY: dict[str, Any] = {
    "kind": _ALERT_INTEGRATION_BODY["kind"],
    "config": _ALERT_INTEGRATION_BODY["config"],
}

#: eventingfunction.CreateEventingFunctionRequest, from the provider's hand-written
#: client rather than the generated one — the generated client has no eventing surface.
_EVENTING_KEYSPACE = {
    "type": "object",
    "description": (
        "A keyspace. `bucket` is required; `scope` and `collection` default to _default "
        "server-side."
    ),
    "properties": {
        "bucket": {"type": "string"},
        "scope": {"type": "string"},
        "collection": {"type": "string"},
    },
    "required": ["bucket"],
}

_EVENTING_FUNCTION_BODY: dict[str, Any] = {
    "name": {"type": "string", "description": "Function name."},
    "eventSource": _EVENTING_KEYSPACE,
    "eventMetadataStorage": {
        **_EVENTING_KEYSPACE,
        "description": (
            "Keyspace for function metadata. MUST differ from eventSource — pointing "
            "both at the same collection is rejected."
        ),
    },
    "code": {"type": "string", "description": "The JavaScript handler source."},
    "description": {"type": "string"},
    "settings": {"type": "object", "description": "Runtime settings."},
    "bindings": {"type": "array", "items": {"type": "object"}},
}


#: eventingfunction.UpdateEventingFunctionRequest. EVERY field is a pointer, so every
#: field is optional and body_required is empty — a legitimately partial update, not a
#: gap in what we know.
_EVENTING_FUNCTION_UPDATE_BODY: dict[str, Any] = {
    "code": {"type": "string", "description": "Replacement JavaScript handler source."},
    "description": {"type": "string"},
    "eventSource": _EVENTING_KEYSPACE,
    "eventMetadataStorage": {
        **_EVENTING_KEYSPACE,
        "description": "Metadata keyspace. Must differ from eventSource.",
    },
    "settings": {"type": "object", "description": "Runtime settings."},
    "bindings": {"type": "array", "items": {"type": "object"}},
}

#: eventingfunction.SetFunctionStateRequest. One field, and the enum is the whole
#: lifecycle — this is the operation that actually starts and stops a function.
_EVENTING_FUNCTION_STATE_BODY: dict[str, Any] = {
    "state": {
        "type": "string",
        "description": (
            "The action to take: 'deploy', 'undeploy', 'pause' or 'resume'. Undeploy "
            "discards the function's processing checkpoint; pause keeps it."
        ),
        "enum": ["deploy", "undeploy", "pause", "resume"],
    },
}


#: CreateOnDemandRestoreRequest. THE RECORD THAT SETTLES CROSS-CLUSTER RESTORE.
#:
#: The parked record carried a dispute: whether managed restore is
#: .../clusters/{id}/backup/restore with the source in the body, or
#: .../clusters/{id}/backups/{backup_id}/restore with the target in the path. The second
#: was chosen on the argument that a backup id in the path ALONGSIDE a cluster id is what
#: makes cross-cluster restore a primitive rather than an orchestration problem.
#:
#: This body proves it, and more strongly than the path did: it carries BOTH
#: sourceClusterID AND targetClusterID as required fields. Restoring a backup taken from
#: one cluster into a different one is a single call, and both ends are named explicitly.
#: That is the capability behind CBSE-23536.
_BACKUP_RESTORE_BODY: dict[str, Any] = {
    "backupID": {
        "type": "string",
        "description": "The backup record to restore FROM. From capella_backups_list.",
    },
    "sourceClusterID": {
        "type": "string",
        "description": "The cluster the backup was taken from.",
    },
    "targetClusterID": {
        "type": "string",
        "description": (
            "The cluster to restore INTO. May differ from sourceClusterID -- that is the "
            "cross-cluster case, and it is a single call rather than an export/import "
            "dance. Both clusters must be on the same cloud provider."
        ),
    },
    "services": {
        "type": "array",
        "description": "Services to restore, e.g. ['data', 'query', 'index'].",
        "items": {"type": "string"},
    },
    "autoRemoveCollections": {
        "type": "boolean",
        "description": (
            "Delete scopes and collections that the backup records as deleted. Off by "
            "default, so a restore does not silently remove things the target has."
        ),
    },
    "forceUpdates": {
        "type": "boolean",
        "description": (
            "Overwrite documents in the target even where the target's copy is NEWER. "
            "This is the flag that turns a restore into data loss on a live cluster."
        ),
    },
    "includeData": {"type": "string", "description": "Restore only this data."},
    "excludeData": {"type": "string", "description": "Skip this data."},
    "filterKeys": {
        "type": "string",
        "description": "Restore only keys matching this regular expression.",
    },
    "filterValues": {
        "type": "string",
        "description": "Restore only values matching this regular expression.",
    },
    "mapData": {
        "type": "string",
        "description": "Restore source data into a different location.",
    },
    "replaceTTL": {"type": "string", "description": "How to reset expiry on restore."},
    "replaceTTLWith": {"type": "string", "description": "The new expiry value."},
}


#: PUT .../eventingFunctions/{name}/code — a bare JSON STRING, not an object.
#:
#: There is no source for this anywhere: the Terraform provider carries no /code endpoint,
#: and the reference does not give the shape. It was settled by CALLING THE GETTER, which
#: answers 200 with the source as a JSON string:
#:
#:     "function OnUpdate(doc, meta, xattrs) {\n   log(\"Doc created/updated\", meta.id);\n}"
#:
#: A setter round-trips what its getter returns, so the request body is the same shape.
#: This is the only operation in the registry whose body is not an object, and it is why
#: Op grew a `body_scalar` field.
_EVENTING_CODE_BODY: dict[str, Any] = {
    "type": "string",
    "description": (
        "The complete JavaScript source for the function, as a bare JSON string -- NOT "
        "wrapped in an object. Replaces the existing source outright; there is no partial "
        "update. Read the current source with capella_eventing_function_code_get first if "
        "you intend to amend rather than replace it."
    ),
}


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
        # CBSE-23617: an empty-body POST here answers HTTP 500 rather than the 422 every
        # sibling create returns, so --method-probe records this operation as ERROR and
        # the run cannot report a clean pass. That is the probe being honest -- a 5xx
        # could come from a gateway before routing, so it proves nothing about the
        # endpoint -- and NOT a defect in this record. The path is confirmed by the
        # OPTIONS probe recorded in LIVE_VERIFIED.
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
            "serviceGroups": {
                "type": "array",
                "description": (
                    "Service groups to scale. Same element shape as the create body's "
                    "serviceGroups; see _CLUSTER_CREATE_BODY."
                ),
                "items": {"type": "object"},
            },
            # Was a bare {"type": "object"}. The CREATE body has always described this
            # field properly; the UPDATE body — the one whose summary says "change
            # support plan" — offered no hint that `plan` was the field to send, or what
            # values it takes. Found by test_an_opaque_object_is_not_accepted_as_a_body
            # _schema, which was written for an unrelated defect in the alert webhook.
            "support": _CLUSTER_CREATE_BODY["support"],
            "enableDataApi": {
                "type": "boolean",
                "description": (
                    "Enable the per-cluster Data API endpoint at "
                    "https://{clusterId}.data.cloud.couchbase.com. Off by "
                    "default. Required before capella_fixture_export or "
                    "_import, which reach the query and FTS services through "
                    "its passthrough routes. Uses a CLUSTER ACCESS credential "
                    "and HTTP Basic, not the organization API key."
                ),
            },
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
        summary="Get the cluster's recurring on/off schedule. [LIVE+METHOD 404/11040]",
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
            "'from': {...}, 'to': {...}}]}. [LIVE 405]"
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
        summary="Remove the on/off schedule. [LIVE 405]",
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
        # PUT, not POST. This shipped as POST behind a [LIVE 405] tag, and the tag was
        # honest about the wrong thing: the OPTIONS probe confirmed the ROUTE and, as
        # test_write_operations_are_path_verified_only_and_that_is_deliberate says in so
        # many words, says nothing about the method. The Terraform provider's generated
        # client — generated from Couchbase's own API document — issues PUT here.
        #
        # The consequence of the old value was not a loud failure. A caller asking to
        # flush a bucket got a 405 that reads like a permissions or entitlement problem,
        # on the one operation whose whole purpose is "reset this quickly between test
        # runs" — so it would have been retried, not investigated.
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/flush",
        summary=(
            "Delete all documents in a bucket, keeping the bucket and its "
            "indexes. The right reset between test runs — seconds instead of the "
            "minutes a reprovision costs. Requires flush enabled on the bucket. "
            "[LIVE 405 path; method PUT from the Terraform provider, not yet observed]"
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
        summary="List collections in a scope. [LIVE+METHOD 200]",
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
            "loader. Body: {'name': 'travel-sample'}. [LIVE 405]"
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
            "from the tool result; use capella_env_ensure, which returns "
            "it once, deliberately, at the point of use. [TF database_credential.go]"
        ),
        group="credentials",
        body=_DB_CREDENTIAL_BODY,
        # `access` too, not just `name`. LIVE-CORRECTED — Capella refuses a credential with
        # no grant:
        #
        #   422 "Can not create new dataplane user without at least (1) valid permission
        #        being specified"
        #
        # Declaring it optional told the model it could omit the field, so the natural
        # minimal call was the one that always fails. `password` stays optional: omitting it
        # genuinely works and is preferred, since Capella then returns a generated one.
        body_required=("name", "access"),
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
        # CBSE-23617: an empty-body POST here answers HTTP 500 rather than the 422 every
        # sibling create returns, so --method-probe records this operation as ERROR and
        # the run cannot report a clean pass. That is the probe being honest -- a 5xx
        # could come from a gateway before routing, so it proves nothing about the
        # endpoint -- and NOT a defect in this record. The path is confirmed by the
        # OPTIONS probe recorded in LIVE_VERIFIED.
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
        summary="Turn on a parked App Service. [LIVE 405]",
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
            "or trusts when replicating. [LIVE+METHOD 200]"
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
        summary="List App Service admin users. [LIVE+METHOD 200]",
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
            "or documents. [LIVE 405]"
        ),
        group="app_services",
        # LIVE-CORRECTED against Capella's OpenAPI document
        # (CreateAppServiceAdminUserRequest). `access` was missing entirely and is REQUIRED:
        #
        #   422 "Payload for creating or modifying app service admin user contains or lacks
        #        both ..."
        #
        # That message is about the `oneOf`: `access` must carry EXACTLY ONE of
        # `accessAllEndpoints` or `endpoints`. Supplying neither, or both, is the error.
        body={
            "name": {"type": "string"},
            "password": {"type": "string"},
            "access": {
                "type": "object",
                "description": (
                    "REQUIRED. Exactly one of two shapes, never both and never neither: "
                    "{'accessAllEndpoints': true} for every App Endpoint, or "
                    "{'endpoints': ['endpoint1', 'endpoint2']} to name them. Supplying "
                    "both or neither is a 422. Note that "
                    "{'accessAllEndpoints': false} is NEITHER — it grants nothing, and "
                    "Capella rejects it with the same error as omitting the field. To "
                    "restrict a user, list the endpoints; there is no 'no access' form."
                ),
            },
            "enableBucketLevelAccess": {
                "type": "boolean",
                "description": (
                    "Optional, defaults true. Couchbase's document notes that true is "
                    "currently the only supported value."
                ),
            },
        },
        body_required=("name", "password", "access"),
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
                "description": (
                    "Optional. Keys are SCOPE names, and ONLY ONE scope is allowed per App "
                    "Endpoint. Each scope requires a 'collections' object keyed by "
                    "collection name; a collection's value may be empty, or carry "
                    "'accessControlFunction' and 'importFilter' as JavaScript strings. "
                    "Shape: {'scope1': {'collections': {'coll1': {}}}}. Omit the whole "
                    "field to sync the default scope and collection."
                ),
            },
            # `deltaSyncEnabled`, NOT `deltaSync`. Corrected against Capella's OpenAPI
            # document (CreateAppEndpointRequest); the short name is silently ignored,
            # which is worse than a rejection — delta sync would simply never be on.
            "deltaSyncEnabled": {
                "type": "boolean",
                "description": "Optional, defaults false.",
            },
            "userXattrKey": {"type": "string"},
            "disablePublicAllDocs": {
                "type": "boolean",
                "description": "Optional, defaults false.",
            },
            "oidc": {
                "type": "array",
                "description": "OIDC providers for this endpoint.",
                "items": {"type": "object"},
            },
            "cors": {"type": "object", "description": "CORS configuration."},
        },
        # Only these two. `scopes` is optional — omitting it uses the default scope and
        # collection. Creation answers 201 with an EMPTY body: the endpoint is addressed by
        # the `name` supplied here, which is why every path in this subtree takes
        # {app_endpoint_name} rather than an id.
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
    # ── Promoted 2026-09-01 from spec_pending.py ────────────────────────────
    #
    # Seventeen operations, verified against a live organization on that date. Their
    # paths did NOT survive the probe unchanged: /eventing/functions, /auditLogExport
    # and /queryIndexes/* were all wrong, and were corrected against the Terraform
    # provider's generated OpenAPI client before any of this answered.
    #
    # The tags mean what they have always meant here. [LIVE+METHOD 200] is a GET that
    # was performed and returned data. [LIVE 405] is a write whose PATH was confirmed by
    # an OPTIONS probe and whose METHOD was not — deliberately, because the alternative
    # is performing it.
    # ── Backups and restore ──────────────────────────────────────────────────
    # Managed backup is the right primitive for RECOVERY and the wrong one for
    # tagged, portable test datasets: Capella backups carry no user-defined
    # metadata, cannot be user-named, and their bytes are retrievable only through
    # a console download with an emailed URL and a one-hour window. For a
    # portable, taggable artifact use capella_fixture_export.
    Op(
        name="capella_backup_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/backups",
        summary=(
            "Take an on-demand managed backup of one bucket. ASYNCHRONOUS — returns "
            "once the backup is scheduled, not once it completes; poll "
            "capella_backups_list. The resulting bytes cannot be retrieved over any "
            "API. [LIVE 405] — and the BODY is separately confirmed: a real "
            "create performed on 2026-09-12 sent an empty body and answered 202 "
            "Accepted. See LIVE_VERIFIED_OUT_OF_BAND."
        ),
        group="backup",
        idempotent=False,
        # EMPTY BY OBSERVATION, not by omission. Until 2026-09-12 this `{}` meant
        # "nobody has checked" -- the operation's 405 came from an OPTIONS probe,
        # and OPTIONS never sends a body. Three bodies in this registry were
        # wrong while their paths were 405-verified, so the distinction is not
        # academic.
        #
        # A real POST with no body answered 202 Accepted. The bucket is named by
        # the PATH, so there is nothing left for a body to carry.
        body={},
    ),
    Op(
        name="capella_backups_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/backups",
        summary=(
            "List managed backups for a cluster. Returns timestamps and the owning "
            "bucket, which is enough for date-based and project-based filtering "
            "client-side. Capella backups carry NO user-defined metadata, so "
            "filtering by scenario or version is impossible here — that is what the "
            "fixture manifest exists for. [LIVE+METHOD 200]"
        ),
        group="backup",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=_PAGE_QUERY,
    ),
    Op(
        name="capella_query_index_manage",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/queryService/indexes",
        summary=(
            "Manage query indexes. Verb coverage UNCONFIRMED — whether this covers "
            "create, drop, build or alter is not documented in the rendered "
            "reference. Prefer plain CREATE INDEX / BUILD INDEX / DROP INDEX over "
            "the Data API query passthrough, which is predictable. [LIVE 405]"
        ),
        group="query_index",
        guarded=True,
        body=_INDEX_DDL_BODY,
        body_required=("definition",),
    ),
    # ── Eventing functions ───────────────────────────────────────────────────
    # Settings and source are separate resources; a fixture must capture both.
    Op(
        name="capella_eventing_functions_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventingFunctions",
        summary="List eventing functions on a cluster. [LIVE+METHOD 200]",
        group="eventing",
        read_only=True,
        idempotent=True,
        paginated=True,
    ),
    Op(
        name="capella_eventing_function_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventingFunctions",
        summary="Create an eventing function from a settings object. [LIVE 405]",
        group="eventing",
        guarded=True,
        body=_EVENTING_FUNCTION_BODY,
        body_required=("name", "eventSource", "eventMetadataStorage"),
    ),
    # ── Replications (XDCR) ──────────────────────────────────────────────────
    # Needed for correctness of park and resume independently of fixtures: turning
    # a cluster off DELETES its replications on both sides, while
    # capella_env_park's description currently promises configuration is kept.
    # Capture before park, replay on resume, storing the captured config in the
    # existing mcp-env: marker rather than inventing a new home for it.
    Op(
        name="capella_replications_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/replications",
        summary=(
            "List XDCR replications on a cluster. Call this BEFORE "
            "capella_cluster_turn_off or capella_env_park — turning a cluster off "
            "deletes its replications on both the source and target side, and they "
            "must be recreated afterwards unless captured first. [LIVE+METHOD 200]"
        ),
        group="replication",
        read_only=True,
        idempotent=True,
        paginated=True,
    ),
    Op(
        name="capella_replication_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/replications",
        summary="Create an XDCR replication. [LIVE+METHOD 422 -- a real POST with an empty body, refused on its contents. Upgraded from [LIVE 405] once the body schema existed: --method-probe can only send the real method for an operation that declares required fields, so filling in the schema is what made the stronger check possible]",
        group="replication",
        guarded=True,
        body=_REPLICATION_CREATE_BODY,
        body_required=("sourceBucket", "target"),
    ),
    # ── Observability: the gap between what Capella exposes and what we expose ──
    #
    # Asked "does this server have Capella health tools?", the honest answer was three
    # near-misses: capella_cluster_get's currentState (lifecycle, not health), the two
    # event lists, and an App Endpoint resync status. Nothing named health, no metrics,
    # no statistics, no alerts. Meanwhile the self-managed side has admin_stats_*,
    # admin_node_list, admin_alerts_* and admin_logs_collect_start -- none of which work
    # against Capella, because Capella does not expose ns_server's admin REST API to
    # tenants. So an instance in capella mode has almost no observability surface.
    #
    # Part of that is the platform: v4 has no real-time metrics and no node-level
    # diagnostics, and that is a genuine limitation worth escalating. Part of it was
    # ours -- everything below EXISTS in the v4 reference and we simply never wired it.
    #
    # All [LIVE+METHOD 200]: transcribed from the reference, never confirmed against a live control
    # plane, and therefore parked rather than shipped. Bodies are left empty where the
    # reference does not pin the shape; --method-probe settles both.
    Op(
        name="capella_cluster_stats_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/stats",
        summary=(
            "Cluster capacity statistics. The closest thing v4 offers to a health "
            "reading, and the first thing to reach for when the question is 'is this "
            "cluster under pressure?' rather than 'is it deployed?'. [DOC]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_event_get",
        method="GET",
        # The reference also appears to document an ORGANIZATION-scoped variant at
        # /v4/organizations/{organization_id}/events/{event_id}, which would mirror
        # capella_events_list. Two readings disagreed about whether both exist or only
        # the project-scoped one, exactly as with the managed-backup restore path -- so
        # the probe settles it before either ships. If both are real, add the org-scoped
        # op alongside this one rather than replacing it.
        path="/v4/organizations/{organization_id}/projects/{project_id}/events/{event_id}",
        summary=(
            "One event by id, with its full detail. capella_project_events_list gives "
            "the summaries; this is the follow-up when a provisioning call succeeded "
            "and the cluster never became healthy. [LIVE+METHOD 200]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_cluster_audit_log_config_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLog",
        summary=(
            "Which audit events the cluster is recording. Worth reading before trusting "
            "an audit trail: a filter that excludes the event class you care about is "
            "indistinguishable from that event never happening. [LIVE+METHOD 200]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_cluster_audit_log_config_set",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLog",
        summary=(
            "Change which audit events the cluster records. A WRITE to the audit "
            "configuration, so it can be used to stop recording the very operations an "
            "auditor would look for -- guarded, and it should stay that way. "
            "[LIVE+METHOD 422 -- a real PUT, refused with 'your support package does "
            "not include audit logging'. Path and method confirmed; the entitlement is "
            "a property of the test cluster, not of the operation]"
        ),
        group="diagnostics",
        guarded=True,
        body=_AUDIT_SETTINGS_BODY,
        body_required=("auditEnabled", "disabledUsers", "enabledEventIDs"),
    ),
    Op(
        name="capella_cluster_audit_log_events_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLogEvents",
        summary=(
            "The audit event types available to filter on, which is how you discover "
            "what the configuration above can name. [LIVE+METHOD 200]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=_PAGE_QUERY,
    ),
    Op(
        name="capella_cluster_audit_log_export_create",
        method="POST",
        # NOTE, and it matters beyond this op: this is the async initiate-then-poll
        # pattern that the proposed bucket-backup export API (IDEA-1901) is explicitly
        # modelled on. So the pattern is not a design analogy -- it is already in v4,
        # here. That strengthens the case for a cluster-level export following the same
        # shape rather than inventing one.
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLogExports",
        summary=(
            "Start an audit-log export job. ASYNCHRONOUS: returns a job id, not the "
            "log. Poll capella_cluster_audit_log_export_get for the download. [LIVE 405]"
        ),
        group="diagnostics",
        body=_AUDIT_EXPORT_BODY,
        body_required=("start", "end"),
    ),
    Op(
        name="capella_cluster_audit_log_exports_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLogExports",
        summary="List audit-log export jobs for a cluster. [LIVE+METHOD 200]",
        group="diagnostics",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=_PAGE_QUERY,
    ),
    # ── Alert integrations ──────────────────────────────────────────────────
    #
    # The outbound half of observability: where Capella sends an alert. Reads are
    # ordinary; the writes send data to a caller-named destination (a Slack or Teams
    # webhook), which is the egress shape this server guards everywhere else -- so the
    # create/update/test trio must go through the egress allowlist when it ships, not
    # just the project allowlist.
    Op(
        name="capella_alert_integrations_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/alertIntegrations",
        summary="List alert integrations for a project. [LIVE+METHOD 200]",
        group="diagnostics",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=_PAGE_QUERY,
    ),
    Op(
        name="capella_alert_integration_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/alertIntegrations",
        summary=(
            "Create an alert integration. THE CREATE CALL ITSELF PERFORMS EGRESS -- "
            "observed live: Capella immediately sent a real POST to the URL in the body, "
            "got 405 back from https://example.com, and REFUSED the create. So this is "
            "not 'store a destination for later'. It is a synchronous outbound HTTP "
            "request to a caller-named host, carrying caller-supplied credentials, and "
            "the response body comes back inside the error. An SSRF-shaped primitive: "
            "the egress allowlist has to clear it BEFORE the call, not before the first "
            "alert fires, and the error must be redacted before a model sees it because "
            "it can contain whatever the probed host returned. [LIVE+METHOD 422 -- a real POST, refused on its contents. Upgraded from [LIVE 405] once the body schema existed]"
        ),
        group="diagnostics",
        guarded=True,
        body=_ALERT_INTEGRATION_BODY,
        body_required=("name", "kind", "config"),
    ),
    Op(
        name="capella_alert_integration_test",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/alertIntegrationTest",
        summary=(
            "Send a test alert. Note the path is NOT under alertIntegrations/{id} -- it "
            "is a sibling collection, so the body identifies the target. Same egress "
            "consideration as create. [LIVE+METHOD 422 -- a real POST, refused on its contents. Upgraded from [LIVE 405] once the body schema existed]"
        ),
        group="diagnostics",
        # GUARDED, and this was missed at promotion. The parked record's own comment said
        # the create/update/test trio "must go through the egress allowlist when it
        # ships" -- create and update carried guarded=True across, test did not.
        #
        # It is the worst one to miss. create at least persists something an operator can
        # later see in the console; test sends a request to a caller-named host and
        # leaves no trace behind. Its entire purpose is the outbound call.
        guarded=True,
        body=_ALERT_INTEGRATION_TEST_BODY,
        body_required=("kind", "config"),
    ),
    # ── Also promoted 2026-09-01, once a function existed to point at ───────
    #
    # These four were skipped in three earlier runs for want of a function_name, and the
    # reason turned out to be a bug rather than an empty cluster: the eventing list uses
    # the nested {"data":[{"data":{...}}]} shape and the discovery helper only read the
    # flat one. Fixing that found the function immediately.
    #
    # Two of them — code_get and logs_get — had been written off as unsourced, because
    # the Terraform provider carries no /code or /logs endpoint. Calling them returned
    # 200. An absent source is not evidence of an absent route.
    #
    # Their siblings that WRITE (update, state_set, code_set) stay parked: their paths
    # are confirmed and their request bodies are not, and a write tool with no body
    # schema is a tool that cannot work. See
    # test_no_shipped_write_tool_is_missing_its_body_schema.
    Op(
        name="capella_eventing_function_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventingFunctions/{function_name}",
        summary=(
            "Fetch one eventing function's settings and bindings. Whether this "
            "response is directly re-postable to capella_eventing_function_create "
            "without rewriting bucket and keyspace references for a different "
            "cluster is UNCONFIRMED — assume a transform is needed. [LIVE+METHOD 200]"
        ),
        group="eventing",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_eventing_function_code_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventingFunctions/{function_name}/code",
        summary="Fetch an eventing function's JavaScript source. [LIVE+METHOD 200] The Terraform provider does not carry this sub-resource -- only the function, its activationState and the list. It was parked as unsourced on that basis and then the 2026-09-01 probe simply CALLED it and got 200, which is better evidence than any source: the segment is real",
        group="eventing",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_eventing_function_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventingFunctions/{function_name}",
        summary="Delete an eventing function. IRREVERSIBLE. [LIVE 405]",
        group="eventing",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_eventing_function_logs_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventingFunctions/{function_name}/logs",
        summary="Fetch an eventing function's logs. [LIVE+METHOD 200] The Terraform provider does not carry this sub-resource -- only the function, its activationState and the list. It was parked as unsourced on that basis and then the 2026-09-01 probe simply CALLED it and got 200, which is better evidence than any source: the segment is real",
        group="eventing",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_eventing_function_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventingFunctions/{function_name}",
        summary="Replace an eventing function's settings. [LIVE 405]",
        group="eventing",
        guarded=True,
        idempotent=True,
        body=_EVENTING_FUNCTION_UPDATE_BODY,
        body_required=(),
    ),
    Op(
        name="capella_eventing_function_state_set",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventingFunctions/{function_name}/activationState",
        summary=(
            "Deploy, undeploy, pause or resume an eventing function. A function "
            "created from a fixture is NOT running until its state is set. [LIVE 405]"
        ),
        group="eventing",
        guarded=True,
        idempotent=True,
        body=_EVENTING_FUNCTION_STATE_BODY,
        body_required=("state",),
    ),
    # ── Shipped 2026-09-01 WITHOUT live verification — see SHIPPED_UNVERIFIED ──
    #
    # A deliberate exception, recorded rather than disguised. /replications is confirmed;
    # these two need a {replication_id} the test organization cannot supply.
    Op(
        name="capella_replication_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/replications/{replication_id}",
        summary="Fetch one XDCR replication's configuration. [LIVE+METHOD 200]",
        group="replication",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_replication_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/replications/{replication_id}",
        summary="Delete an XDCR replication. [LIVE 405 + METHOD additionally confirmed on 2026-09-02 by a deliberate operator DELETE against a disposable object, which returned 204. That is NOT recorded in LIVE_VERIFIED: a write carrying a 2xx there would mean the PROBE performed it, and the probe did not -- it OPTIONS-probed this, as it must for anything destructive. Provenance belongs here; the probe's record stays the probe's.]",
        group="replication",
        destructive=True,
        guarded=True,
    ),
    # ── Promoted 2026-09-01 (final batch) ───────────────────────────────────
    #
    # These six waited on objects the test organization did not have, and on one bug of
    # mine: the index sweep reported the decoded bucket NAME while sending the base64 id,
    # so it asked for a keyspace that does not exist and got an accurate "Index not found
    # in key space" twelve times over. With the name actually sent, ix_trial_count turned
    # up in harvester.governance.trial_signals immediately.
    #
    # capella_query_index_definitions_list was HELD BACK in the first batch because its
    # only evidence was a 404 without a Capella domain code, and this repository's rule is
    # that such a 404 proves nothing. It now answers 200. The rule did not have to move.
    # ── Cloud snapshot backups ───────────────────────────────────────────────
    #
    # A SECOND, SEPARATE backup subsystem, live on Capella and implemented
    # nowhere in this server until now. spec_pending.py flagged it on
    # 2026-09-01 as an unexamined gap and argued it may be the better primitive
    # for "give me a restorable environment on demand"; a live sweep on
    # 2026-09-12 confirmed all six of its routes exist.
    #
    # Why it is a different shape from the managed backups above:
    #
    #   * /restores is a LISTABLE COLLECTION, so a restore is a first-class
    #     object that can be found and tracked afterwards. Managed backup has
    #     no equivalent -- you fire a restore and watch the cluster.
    #   * /regions returns the provider regions, which implies the subsystem
    #     understands cross-REGION placement, not only cross-cluster.
    #
    # ONLY THE READS ARE HERE. The write routes answered 405 to a GET, which
    # proves the route exists and says nothing about which method or body they
    # take. Shipping a create or a restore on that would be inventing a schema.
    Op(
        name="capella_cloud_snapshot_backups_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/cloudsnapshotbackups",
        summary=(
            "List cloud snapshot backups for a cluster. A different subsystem "
            "from capella_backups_list: snapshots are cluster-level rather than "
            "per-bucket, and their restores are trackable objects. Observed "
            "returning a standard cursor envelope. [LIVE 200]"
        ),
        group="backup",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=_PAGE_QUERY,
    ),
    Op(
        name="capella_cloud_snapshot_regions_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/cloudsnapshotbackups/regions",
        summary=(
            "List the provider regions a cloud snapshot can be placed in. "
            "Returns a bare JSON ARRAY of region names, not a cursor envelope -- "
            "v4 list responses are not uniform and this one is the plain-array "
            "shape. [LIVE 200]"
        ),
        group="backup",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_cloud_snapshot_restores_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/cloudsnapshotbackups/restores",
        summary=(
            "List cloud snapshot RESTORES. The managed-backup family has no "
            "counterpart: this is what makes a restore auditable after the fact "
            "rather than a fire-and-watch operation, which is the difference "
            "that matters for an automated environment-refresh workflow. "
            "[LIVE 200]"
        ),
        group="backup",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=_PAGE_QUERY,
    ),
    Op(
        name="capella_backup_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/backups/{backup_id}",
        summary="Fetch one managed backup record by id. [LIVE+METHOD 200]",
        group="backup",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_backup_cycle_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/backups/{backup_id}",
        summary=(
            "Delete the backup CYCLE for a bucket. This removes the bucket's managed "
            "backup history, not a single backup. IRREVERSIBLE. [LIVE 405]"
        ),
        group="backup",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_backup_restore",
        method="POST",
        # DISPUTE SETTLED 2026-09-12 — shape (b), which is what is written here.
        # Two reads of the v4 reference had disagreed:
        #   (a) .../clusters/{cluster_id}/backup/restore              (no backup id)
        #   (b) .../clusters/{cluster_id}/backups/{backup_id}/restore
        # Two independent sources now agree on (b): the published Operational
        # Management API reference lists
        #   POST /v4/organizations/{organizationId}/projects/{projectId}
        #        /clusters/{clusterId}/backups/{backupId}/restore
        # and LIVE_VERIFIED records 405 for this operation, which only an OPTIONS
        # probe of a MATCHED route returns -- a wrong path answers 404.
        #
        # So the design question the dispute raised is also answered: the backup
        # id is in the path alongside a cluster id, which makes cross-cluster
        # restore a primitive rather than an orchestration problem.
        #
        # WHICH CLUSTER IS IN THE PATH — CORRECTED 2026-09-13, BY MEASUREMENT
        # ------------------------------------------------------------------
        # This comment and the summary below both said the path names the TARGET
        # and the body names the SOURCE. That is BACKWARDS, and a model following
        # it built a body that cannot succeed. Capella says so itself, in its own
        # error vocabulary, on a real POST:
        #
        #   POST .../clusters/<TARGET>/backups/<backup>/restore
        #   body sourceClusterID=<SOURCE> targetClusterID=<TARGET>
        #   -> 422 {"code": 5026,
        #           "message": "The source cluster ID is invalid. Please ensure
        #                       the source cluster id matches the id in the path.",
        #           "hint": "Returned when attempting to restore a backup and the
        #                    source cluster id does not match the cluster id in
        #                    the url path of the request."}
        #
        # A dedicated error code for this exact confusion is not an accident; it
        # exists because the confusion is common. The rule it states:
        #
        #   PATH cluster  == sourceClusterID   — the cluster that OWNS the backup
        #   targetClusterID (body only)        — the cluster that is OVERWRITTEN
        #
        # Which is consistent with the resource model: a backup is a child of the
        # cluster that took it, so its URL is under that cluster. The destination
        # is an argument, not a location.
        #
        # This matters beyond a wrong sentence. The ownership guardrail in
        # handlers/capella/__init__.py fetches the PATH cluster, so on this one
        # operation it was guarding the cluster that is only READ while leaving
        # the cluster that gets OVERWRITTEN unchecked. See the note there.
        #
        # 405 verified the route and said nothing about any of this, which is the
        # standing argument for why a path-only verification is not a verified
        # operation. Two wrong preconditions and one wrong path segment all sat
        # underneath a route that had been "verified" for weeks.
        #
        # PERFORMED 2026-09-13: 202 Accepted, cross-cluster, with the path and
        # both preconditions right. See LIVE_VERIFIED_OUT_OF_BAND above.
        #
        # A SECOND PRECONDITION, ALSO MEASURED: BOTH CLUSTERS MUST BE HEALTHY.
        # Same day, once the path was right:
        #
        #   -> 422 {"code": 5022,
        #           "message": "Unable to target a restore for a cluster that is
        #                       not in a healthy state."}
        #
        # The target was in `peering` -- an XDCR replication was establishing its
        # network path. Worth stating because a cluster leaves `healthy` for
        # ordinary reasons long after it finishes provisioning, so "it deployed
        # fine" is not the same claim. Check currentState on BOTH ends with
        # capella_cluster_get before calling this.
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/backups/{backup_id}/restore",
        summary=(
            "Restore a managed backup. The cluster in the path is the SOURCE — "
            "the cluster that OWNS the backup — and it MUST equal sourceClusterID "
            "in the body; Capella answers 422 code 5026 when they differ. The "
            "cluster that gets OVERWRITTEN is targetClusterID, which appears in "
            "the body only. "
            "Documented as able to restore into the same cluster or another cluster "
            "in the same organization, provided both are on the same cloud provider "
            "— Azure to Azure is fine, Azure to AWS is not. DESTRUCTIVE: overwrites "
            "data in the target. Indexes come back DEFERRED, so the target is not "
            "performance-comparable to its source until builds complete — trigger "
            "them and poll capella_query_index_build_status before treating it as "
            "ready. Both clusters must report currentState 'healthy' or Capella "
            "answers 422 code 5022. [LIVE+METHOD 422]"
        ),
        group="backup",
        destructive=True,
        guarded=True,
        body=_BACKUP_RESTORE_BODY,
        body_required=("backupID", "sourceClusterID", "targetClusterID", "services"),
    ),
    # ── Query indexes ────────────────────────────────────────────────────────
    # /definitions is the read-back that system:indexes does NOT provide: the
    # documented system:indexes metadata object carries only last_scan_time,
    # num_replica and stats, with no definition field.
    Op(
        name="capella_query_index_definitions_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/queryService/indexes",
        summary=(
            "Read back the index definition statements for a cluster's GSI indexes. "
            "This is the CREATE-statement source for a fixture manifest. Response "
            "shape UNCONFIRMED — the rendered v4 reference truncates before the "
            "schema. [LIVE+METHOD 200]"
            # HELD BACK on 2026-09-01, and not because it failed. The run performed this
            # GET against bucket=harvester, scope=_default, collection=_default and got:
            #
            #     404 {'code': 404,
            #          'hint': 'Please review your request and ensure that all required
            #                   parameters are correctly provided.',
            #          'httpStatusCode': 404,
            #          'message': 'Index not found in key space'}
            #
            # The message names a domain object and a keyspace, which only the
            # query-index handler could have produced, so the route DID match. But
            # `code` is the HTTP status echoed back, not a Capella domain code, and this
            # repository's rule — test_the_recorded_statuses_are_ones_that_prove_a_route
            # _matched — is that a 404 without a domain code is not proof.
            #
            # Admitting this one record by relaxing that rule would be settling the
            # question by moving the bar. Point the probe at a keyspace that HAS an index
            # and it answers 200; promote on that.
        ),
        group="query_index",
        read_only=True,
        idempotent=True,
        # KEYSPACE QUERY PARAMETERS, from the provider's ListIndexDefinitionsParams /
        # IndexDefinitionParams / IndexBuildStatusParams. `bucket` is REQUIRED -- a call
        # without it answers 400 with Capella code 1000, which is how this was found.
        # `scope` and `collection` default to _default when omitted.
        query=_KEYSPACE_QUERY,
    ),
    Op(
        name="capella_query_index_properties_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/queryService/indexes/{index_name}",
        summary="Index properties for a cluster. [LIVE+METHOD 200]",
        group="query_index",
        read_only=True,
        idempotent=True,
        # KEYSPACE QUERY PARAMETERS, from the provider's ListIndexDefinitionsParams /
        # IndexDefinitionParams / IndexBuildStatusParams. `bucket` is REQUIRED -- a call
        # without it answers 400 with Capella code 1000, which is how this was found.
        # `scope` and `collection` default to _default when omitted.
        query=_KEYSPACE_QUERY,
    ),
    Op(
        name="capella_query_index_build_status",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/queryService/indexBuildStatus/{index_name}",
        summary=(
            "Build status for a cluster's GSI indexes. This is the gate that makes a "
            "restored or imported environment honest: an index whose definition "
            "exists but is not ONLINE means the cluster is not yet "
            "performance-comparable to its source, and a load test started against "
            "it produces numbers that read as a Couchbase performance problem. Poll "
            "this before reporting ready. [LIVE+METHOD 200]"
        ),
        group="query_index",
        read_only=True,
        idempotent=True,
        # KEYSPACE QUERY PARAMETERS, from the provider's ListIndexDefinitionsParams /
        # IndexDefinitionParams / IndexBuildStatusParams. `bucket` is REQUIRED -- a call
        # without it answers 400 with Capella code 1000, which is how this was found.
        # `scope` and `collection` default to _default when omitted.
        query=_KEYSPACE_QUERY,
    ),
    # ── Shipped 2026-09-01 WITHOUT live verification — see SHIPPED_UNVERIFIED ──
    #
    # The alert-integration trio and the audit-log export getter. Their collection paths
    # are confirmed live; each needs an object id the test organization cannot produce —
    # creating an alert integration requires an https endpoint that answers 2xx, and
    # audit-log export retention requires an Enterprise plan.
    Op(
        name="capella_cluster_audit_log_export_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLogExports/{export_id}",
        summary=(
            "One audit-log export job: its status and, once ready, the download. The "
            "response carries a signed URL, so it is redacted before it reaches a "
            "model context or the log. [TF -- see SHIPPED_UNVERIFIED]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
        sensitive_response=True,
    ),
    Op(
        name="capella_alert_integration_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/alertIntegrations/{alert_integration_id}",
        summary=(
            "One alert integration. The response may echo the configured webhook URL, "
            "which is a credential in URL form. [LIVE+METHOD 200]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
        sensitive_response=True,
    ),
    Op(
        name="capella_alert_integration_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/alertIntegrations/{alert_integration_id}",
        summary="Update an alert integration. Same egress consideration as create. [LIVE 405 -- OPTIONS-probed on purpose: the API accepts an empty body here, so the empty-body probe would PERFORM this rather than be refused. See empty_body_accepted]",
        group="diagnostics",
        guarded=True,
        # Observed live 2026-09-01: PUT with an empty body answers 200 -- and, read back,
        # had changed nothing (version still 1, modifiedAt == createdAt). Capella accepts
        # the empty body and ignores it.
        #
        # The flag stays regardless. "It happened to be a no-op" is not a property the
        # probe can check BEFORE sending, and nothing promises it holds for the next
        # field, endpoint or API version. See Op.empty_body_accepted.
        empty_body_accepted=True,
        body=_ALERT_INTEGRATION_UPDATE_BODY,
        body_required=("config",),
    ),
    Op(
        name="capella_alert_integration_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/alertIntegrations/{alert_integration_id}",
        summary=(
            "Delete an alert integration. Destructive in the way that matters for "
            "monitoring: afterwards the alerts simply stop arriving, silently. [LIVE 405 + METHOD additionally confirmed on 2026-09-02 by a deliberate operator DELETE against a disposable object, which returned 204. That is NOT recorded in LIVE_VERIFIED: a write carrying a 2xx there would mean the PROBE performed it, and the probe did not -- it OPTIONS-probed this, as it must for anything destructive. Provenance belongs here; the probe's record stays the probe's.]"
        ),
        group="diagnostics",
        destructive=True,
        guarded=True,
    ),
    # ── Promoted 2026-09-01, the last parked operation ──────────────────────
    #
    # Held back because its request body had no source: the Terraform provider carries no
    # /code endpoint and the reference does not give the shape. Settled by calling the
    # GETTER, which returns the source as a bare JSON string — so the setter takes one.
    # The only operation here whose body is not an object.
    Op(
        name="capella_eventing_function_code_set",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventingFunctions/{function_name}/code",
        summary="Replace an eventing function's JavaScript source. [LIVE 405] Base path corrected to /eventingFunctions, but THIS sub-resource appears nowhere in the Terraform provider's generated client -- only the function, its activationState and the list do. So the segment is still unsourced and this stays parked even if its siblings promote",
        group="eventing",
        guarded=True,
        idempotent=True,
        body_scalar=_EVENTING_CODE_BODY,
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

    if op.body_scalar:
        # A non-object body. Required whenever declared: there is no partial form of
        # "the request body IS this value".
        properties["body"] = dict(op.body_scalar)
        required.append("body")
    elif op.body:
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


#: Prefix added to the description of anything in SHIPPED_UNVERIFIED. A caller deciding
#: whether to trust a result needs this at the point of use, not in a register it will
#: never read.
#
# The wording here is load-bearing. `_is_inferred` in scripts/verify_capella_paths.py
# detects the inferred-path provenance tag by substring, deliberately, so that qualified
# forms of it are caught as well as the bare one. The first draft of this notice opened
# with a bracket followed by the letters P-A-T-H, which that detector matched — so every
# unverified operation would have been reported as an inferred path too, conflating two
# states that mean different things.
#
# Caught by test_no_operation_in_the_spec_is_still_inferred, which scans this file's
# SOURCE. That is also why this comment spells the letters out rather than quoting the
# tag: a comment describing the collision was itself enough to trip the same check.
_UNVERIFIED_NOTICE = (
    "[UNVERIFIED PATH — not confirmed against a live control plane. Shipped deliberately "
    "so it can be exercised; a 404 here may mean the path is wrong rather than the object "
    "absent. Report one rather than working around it.] "
)


def build_tools() -> list[Tool]:
    return [
        Tool(
            name=op.name,
            description=(
                _UNVERIFIED_NOTICE + op.summary
                if op.name in SHIPPED_UNVERIFIED
                else op.summary
            ),
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
