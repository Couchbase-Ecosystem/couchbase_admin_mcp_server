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
    "capella_app_endpoint_update": (
        "2026-09-14, scripts/probe_access_control_function.py --perform, ROUTE 3. "
        "PERFORMED: the endpoint document from capella_app_endpoint_get, with "
        "adminURL/metricsURL/publicURL/state/requireResync/isRequireResync/audit "
        "removed and scopes.inventory.collections.airline.accessControlFunction "
        "replaced, PUT to .../appEndpoints/test -> 204.\n"
        "This operation did not exist until that measurement. It was found while "
        "failing to make the DEDICATED access control function path work: 43 "
        "combinations against .../accessControlFunction all drew one message, and "
        "the endpoint document was tried as a last resort because the Terraform "
        "provider's app_endpoint resource manages the function as an attribute "
        "rather than through a resource of its own.\n"
        "Both routes now work, for different reasons and with different encodings "
        "-- the document carries the source as a JSON string, the dedicated path "
        "takes it raw as application/javascript. The dedicated path's failure was "
        "never about the body shape; see handlers/capella/client.py."
    ),
    "capella_cluster_onoff_schedule_delete": (
        "2026-09-14: DELETE answered 204 and the schedule created earlier the "
        "same night was gone. Recorded here rather than in LIVE_VERIFIED "
        "because a 2xx on a write may not go in that register.\n"
        "It was deleted because it was WORKING: a 'custom' day is off outside "
        "its boundaries, so the fixture cluster powered down and every write to "
        "it was refused with 422 'Temporarily unavailable while the Cluster is "
        "in the Turning On state' until it came back.\n"
        "WHICH DRIVER SENT THAT 204 WAS NOT RECORDED AT THE TIME, and this "
        "entry will not invent one. Two paths could have: the cleanup step in "
        "scripts/probe_onoff_schedule.py --perform, which sends DELETE when the "
        "cluster had no prior schedule, or a deliberate later call. Naming the "
        "likelier of the two would be a reconstruction, and a register that "
        "accepts reconstructions is worth nothing.\n"
        "RE-CONFIRMED 2026-09-14 through scripts/dump_tool.py "
        "capella_cluster_onoff_schedule_delete --perform --allow-destructive: "
        "404 with Capella code 11040, 'Returned from the API when a database "
        "does not have an existing On/Off schedule'. That is a SEMANTIC 404 "
        "from a real handler -- it names the resource's own precondition rather "
        "than reporting an unrouted path -- so it re-proves route and method "
        "through the MCP surface, and independently confirms the schedule is "
        "gone and the cluster is as it was found. It is not evidence of the "
        "delete SUCCEEDING, which is why the 204 above still carries that."
    ),
    "capella_cluster_onoff_schedule_set": (
        "2026-09-14, scripts/probe_onoff_schedule.py --perform. PERFORMED: "
        "seven 'custom' days, from {hour 0, minute 0} to {hour 23, minute 30}, "
        "timezone America/New_York, ACCEPTED with 204. The schedule was then "
        "DELETED (204) because the cluster had none before the run, so the "
        "measurement cost the cluster nothing.\n"
        "Six other bodies were refused in the same transcript, and each refusal "
        "is one clause of the schema: a non-custom day may not carry a boundary; "
        "a custom day must; minute is 0 or 30 and nothing else; hour is 0-23, so "
        "24:00 is not midnight; from/to are objects, not 'HH:MM' strings; and "
        "PUT against a cluster with no schedule answers 404, which makes POST "
        "the create and PUT the update.\n"
        "THE 500 IS REAL AND IT IS NARROW. Seven whole-day 'on' days -- a body "
        "that breaks none of those clauses -- answers 500 code 10000, measured "
        "four times across three runs. So a caller cannot express 'never turn "
        "this off' as a schedule; the way to say that is to have no schedule. "
        "This registry recommended the 500-ing body as 'the safe shape' until "
        "this run, which is why the advice is now retracted in the summary."
    ),
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
    # ── In-place updates, shipped 2026-09-14 ─────────────────────────────────
    #
    # Four PUTs whose absence made every one of these settings a
    # delete-and-recreate. Paths and bodies from the provider's generated client
    # per CLAUDE.md rule 1.5. Each carries its own promotion path, because they
    # are not equally cheap to verify and pretending otherwise is how the easy
    # one gets done and the other three sit here for a year.
    "capella_bucket_update": (
        "2026-09-14. PATH, METHOD and BODY from openapi.gen.go:28401 "
        "(durabilityLevel, memoryAllocationInMb, replicas, "
        "timeToLiveInSeconds, flush). Not yet exercised live.\n"
        "PROMOTE WITH A REFUSAL, not a success. memoryAllocationInMb far beyond "
        "the cluster's free quota answers 422 and changes nothing -- the same "
        "refusal the create path already produces, so the behaviour is known. "
        "Do NOT promote it by performing a real resize: `replicas` triggers a "
        "rebalance and shrinking the quota makes the bucket eject to fit, and "
        "both return before the work finishes."
    ),
    "capella_collection_update": (
        "2026-09-14. PATH and METHOD from openapi.gen.go:29516; the body is "
        "maxTTL alone. Not yet exercised live. THE CHEAPEST OF THE FOUR TO "
        "VERIFY HONESTLY: setting maxTTL on a throwaway collection is reversible "
        "by setting it back, affects no existing document (the new maximum "
        "applies only to documents written afterwards), and needs no rebalance. "
        "A negative maxTTL should earn a 422 without writing anything, which "
        "promotes it with no change at all."
    ),
    "capella_database_credential_update": (
        "2026-09-14. PATH and METHOD from openapi.gen.go:33681. Not yet "
        "exercised live, and NOT safe to verify on a credential anything "
        "depends on: `access` REPLACES the existing grants, so a call that omits "
        "one revokes it, and a password change breaks every client holding the "
        "old one at its next connection. The test organization's mcptest-data "
        "credential is what the fixture tools authenticate with.\n"
        "Promote it against a throwaway credential created for the purpose, or "
        "with a deliberately malformed `access` array that earns a 422."
    ),
    "capella_project_update": (
        "2026-09-14. PATH and METHOD from openapi.gen.go:18127; the body is "
        "name and description. Not yet exercised live. Verifying it means "
        "renaming a real project, and the project this organization uses is the "
        "one named in CAPELLA_ALLOWED_PROJECTS -- renaming it does NOT move it "
        "out of the allowlist, which holds UUIDs, but it does change what a "
        "human reads when deciding whether a destructive call is safe. Promote "
        "it on a scratch project, created and deleted for the purpose."
    ),
    "capella_app_service_update": (
        "2026-09-14. PATH, METHOD and BODY from the Terraform provider's "
        "generated client, openapi.gen.go:5811 (UpdateAppServiceRequest = "
        "{compute: {cpu, ram}, nodes}), per CLAUDE.md rule 1.5. Not yet "
        "exercised against a live App Service.\n"
        "WHY IT IS NOT CHEAPLY VERIFIABLE, unlike the import filter's setter. "
        "The invalid-body trick that promoted that op works because the App "
        "Endpoint validator refuses bad input without acting. Here the plausible "
        "refusals are 422s on capacity -- nodes outside 2-12, or a cpu/ram pair "
        "the provider does not offer -- and the test organization has exactly "
        "ONE App Service, which capella_env_* depends on. A 422 is safe, but a "
        "typo that happens to be VALID resizes a live App Service "
        "asynchronously, and the resize cannot be cancelled mid-flight.\n"
        "Promote it with a deliberate 422: nodes=1 is refused with 'The "
        "instance desired capacity must be between 2 and 12', which is measured "
        "on the create path and writes nothing. Do that against a throwaway App "
        "Service, not the one the environment tools use."
    ),
    # ── App Endpoint import filter DELETE, shipped 2026-09-14 ────────────────
    #
    # Its two siblings were promoted to LIVE_VERIFIED the same day, on a 200 and a
    # 400 measured against a live App Service. This one stays because the cheap
    # proof does not exist for it -- see the entry.
    "capella_app_endpoint_import_filter_delete": (
        "2026-09-14. PATH AND METHOD from openapi.gen.go:24036. Unverified, and "
        "the HARDEST of the three to verify honestly: a DELETE that succeeds "
        "removes the filter, which WIDENS the endpoint so every document in the "
        "collection becomes eligible for import, and re-adding the filter does "
        "not undo it -- documents already imported stay until a resync. So the "
        "cheap proof used elsewhere, perform it and then put it back, does not "
        "apply here. Promote it only against a collection whose filter can be "
        "lost, or leave it here and say so."
    ),
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
    # 200 WITH AN EMPTY BODY, 2026-09-14, exactly as its twin above -- the
    # prediction in this op's description was made before the call and held.
    "capella_app_endpoint_import_filter_get": "200",
    # 400 "collection \"airline\" import filter error: invalid javascript
    # syntax: (anonymous): Line 1:7 Unexpected identifier (and 3 more errors)",
    # 2026-09-14, from a PUT carrying the text "this is not javascript at all".
    #
    # THIS IS A STRONGER RESULT THAN A PATH PROOF, and the difference from the
    # twin is the whole point. capella_app_endpoint_access_control_function_set
    # answers "JavaScript source does not evaluate to a function" for every
    # input INCLUDING text that is not JavaScript -- boilerplate, proving the
    # source never reached a validator. This op answers with a LINE AND COLUMN
    # pointing at the offending token, which is a real parse. So the raw
    # application/javascript body reached the JavaScript engine: the handling
    # inherited from the twin is now MEASURED on this op, not assumed.
    #
    # It also corroborates the retraction recorded against the twin: a
    # validator at this level of this resource clearly can report real syntax
    # errors, so the twin's refusal to do so was never a verdict on the source.
    "capella_app_endpoint_import_filter_set": "400",
    "capella_app_endpoint_access_control_function_set": "405",
    "capella_app_endpoint_cors_set": "405",
    "capella_app_endpoint_create": "405",
    # 400 "The Update App Endpoint payload name does not match the App Endpoint
    # name in the URL", from an empty body sent to the real route on 2026-09-14.
    # Route and method proven, nothing written -- which is exactly what this
    # register is for. The 204 from the real write is in
    # LIVE_VERIFIED_OUT_OF_BAND, because a 2xx on a write may not be recorded here.
    "capella_app_endpoint_update": "400",
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
    # 405 was the OPTIONS-era path proof. A real POST was PERFORMED on
    # 2026-09-14 and answered 204; the schedule it created was then deleted, so
    # the cluster is as it was found. A 2xx on a write is forbidden in this
    # register -- see test_no_write_is_recorded_with_a_success_status -- so the
    # 204 lives in LIVE_VERIFIED_OUT_OF_BAND and this stays the probe's answer.
    "capella_cluster_onoff_schedule_set": "405",
    "capella_data_api_get": "200",
    # 400 'body contains incorrect JSON type for field "enableDataApi"', from a
    # PUT whose enableDataApi was a string, 2026-09-14. Route and method proven,
    # nothing changed -- a BODY refusal, which is what this register wants.
    #
    # An earlier attempt the same night answered 422 "Temporarily unavailable
    # while the Cluster is in the Turning On state" instead. That is a STATE
    # refusal and proves less: it says the route matched, not that the body was
    # read. The cluster was mid-cycle because of the on/off schedule the fixture
    # had just created -- worth knowing, because for those minutes every write to
    # that cluster is refused for a reason that has nothing to do with the write.
    #
    # THE FIELD NAME DISPUTE IS SETTLED, and it was never a dispute. The docs say
    # enableDataAPI, the provider's struct says enableDataApi, and BOTH spellings
    # drew one error naming `enableDataApi`: Go's encoding/json matches keys
    # case-insensitively, so they reach the same field. Use the provider's
    # spelling; neither is wrong at the wire.
    "capella_data_api_set": "400",
    # 422 "The timezone 'Mars/Olympus' is not a valid IANA timezone", from a real
    # PUT with a deliberately invalid body at a cluster that HAS a schedule,
    # 2026-09-14. Route and method proven, nothing written.
    #
    # It was briefly in SHIPPED_UNVERIFIED on 404 evidence -- a PUT at a cluster
    # with no schedule. test_write_operations_are_path_verified_only refused that,
    # correctly: 404 cannot tell "route exists, object does not" from "no such
    # route". The 404 is still the useful finding (PUT updates, cannot create);
    # it is just not proof of a route.
    "capella_cluster_onoff_schedule_update": "422",
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
    #: Content-Type for the request body. Only two values occur.
    #:
    #: "application/javascript" means the body is the SOURCE TEXT ITSELF, sent raw.
    #: The App Endpoint access control function and import filter are both like
    #: this, and both were shipped as JSON operations that could never work. See
    #: the note in handlers/capella/client.py for the 43 measurements that finally
    #: settled it and the provider source that explains them.
    body_content_type: str = "application/json"

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
    # FROM THE PROVIDER, 2026-09-14. Both were absent and both are load-bearing:
    # configurationType is how a caller asks for a cheap single-node cluster
    # instead of a three-node one, and zones is how single-AZ placement is
    # requested. openapi.gen.go CreateClusterRequest carries them alongside
    # cmekId and enablePrivateDNSResolution.
    "configurationType": {
        "type": "string",
        "enum": ["singleNode", "multiNode"],
        "description": (
            "singleNode is the cheap, non-HA shape -- the right default for an "
            "ephemeral test environment. Immutable after creation."
        ),
    },
    "zones": {
        "type": "array",
        "items": {"type": "string"},
        "description": "Availability zones to place nodes in. Single-AZ needs one.",
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
    # ABSENT UNTIL 2026-09-14. CreateBucketRequest also carries priority,
    # vbuckets and flushEnabled; this is the one callers actually set, and
    # getting it wrong on a magma bucket is a performance decision made by
    # default rather than on purpose.
    "evictionPolicy": {
        "type": "string",
        "enum": ["fullEviction", "valueOnly"],
        "description": (
            "fullEviction keeps only metadata in memory; valueOnly keeps values "
            "too. couchstore buckets default to valueOnly, magma to fullEviction."
        ),
    },
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

#: Body for capella_bucket_update. FIVE FIELDS, from openapi.gen.go:28401.
#:
#: NOT A SUBSET OF THE CREATE BODY, and the omissions decide what a caller can
#: and cannot change without destroying the data:
#:
#:   * NO `name`. A bucket cannot be renamed.
#:   * NO `type`, NO `storageBackend`, NO `bucketConflictResolution`,
#:     NO `evictionPolicy`. These are fixed at creation. Changing storage engine
#:     is a migration (there is a separate bucketStorageMigration endpoint, which
#:     this server deliberately does not ship -- see P3 in the surface TODO).
#:
#: Every field here is otherwise a delete-and-recreate today, which on a bucket
#: means destroying every document in it to change a setting.
_BUCKET_UPDATE_BODY: dict[str, Any] = {
    "memoryAllocationInMb": {
        "type": "integer",
        "description": (
            "Per-node RAM quota. Must fit the cluster's free quota or v4 answers "
            "422. SHRINKING one is not free: the bucket ejects to fit, so a "
            "reduction on a loaded bucket is a latency event, not a config edit."
        ),
    },
    "durabilityLevel": {
        "type": "string",
        "enum": ["none", "majority", "majorityAndPersistActive", "persistToMajority"],
        "description": (
            "Raising this makes every subsequent write slower and more durable. "
            "It does NOT retroactively harden writes already acknowledged."
        ),
    },
    "replicas": {
        "type": "integer",
        "description": (
            "Changing this triggers a REBALANCE. The call returns before the "
            "rebalance finishes, and the cluster is degraded in throughput until "
            "it does."
        ),
    },
    "flush": {"type": "boolean", "description": "Enable or disable flush."},
    "timeToLiveInSeconds": {
        "type": "integer",
        "description": (
            "Bucket-level maximum TTL. Applies to documents written AFTER the "
            "change; existing documents keep the expiry they were written with, "
            "so setting this does not retroactively expire anything."
        ),
    },
}

#: Body for capella_collection_update. ONE FIELD, from openapi.gen.go:29516.
#:
#: maxTTL and nothing else -- a collection cannot be renamed, and its scope
#: cannot be changed.
_COLLECTION_UPDATE_BODY: dict[str, Any] = {
    "maxTTL": {
        "type": "integer",
        "description": (
            "Maximum TTL in seconds for documents in this collection. Applies to "
            "documents written AFTER the change; it does not retroactively "
            "expire what is already there. 0 means no collection-level maximum."
        ),
    },
}

#: Body for capella_database_credential_update, from openapi.gen.go:33681.
#:
#: ROTATES A PASSWORD IN PLACE, which is the point: today rotating a credential
#: means deleting and recreating it, and every client holding the old password
#: fails in the window between.
_DB_CREDENTIAL_UPDATE_BODY: dict[str, Any] = {
    "password": {
        "type": "string",
        "description": (
            "New password. UNLIKE THE CREATE OP, omitting this does not have "
            "Capella generate one -- create returns a generated password in its "
            "response and this operation has no such response to put one in. "
            "Supply a password, and note that every client using the old one "
            "fails on its next connection: rotation is not zero-downtime unless "
            "the application is holding two credentials."
        ),
    },
    "access": {
        "type": "array",
        "description": (
            "Privilege grants, REPLACING the existing set outright rather than "
            "adding to it. Same shape as the create op: [{'privileges': "
            "['data_reader'], 'resources': {...}}]. An update that omits a grant "
            "the credential currently has REVOKES it."
        ),
        "items": {"type": "object"},
    },
}

#: The node range Capella accepts for an App Service. Named, because the wrong value was
#: hard-coded in three places and a live 422 was the only thing that found it.
MIN_APP_SERVICE_NODES = 2
MAX_APP_SERVICE_NODES = 12

#: Body for capella_app_service_update. DELIBERATELY NARROWER THAN THE CREATE BODY.
#:
#: UpdateAppServiceRequest is {compute: {cpu, ram}, nodes} and nothing else
#: (openapi.gen.go:5811). It is not a partial version of the create body, and the
#: omissions are the interesting part:
#:
#:   * NO `version`. A PUT cannot upgrade an App Service. See the op summary --
#:     this is the single most misleading thing about the word "update" here.
#:   * NO `name`, NO `description`. So the mcp-env marker an environment writes
#:     into the description at create time CANNOT be changed by this op, and any
#:     tool that needs to re-mark an App Service has to delete and recreate it.
#:
#: Shipping the create body here with fields quietly dropped on the wire would be
#: worse than not shipping the op: the caller would set `version`, get a 204, and
#: reasonably conclude the upgrade happened.
_APP_SERVICE_UPDATE_BODY: dict[str, Any] = {
    "nodes": {
        "type": "integer",
        "description": (
            f"New node count, {MIN_APP_SERVICE_NODES}-{MAX_APP_SERVICE_NODES}. "
            f"Outside that range Capella answers 422 'The instance desired "
            f"capacity must be between 2 and 12', measured on the create path."
        ),
    },
    "compute": {
        "type": "object",
        "description": (
            "{'cpu': 2, 'ram': 4} -- must be a combination the cloud provider "
            "offers, or Capella answers 422 naming the offending field."
        ),
        "properties": {"cpu": {"type": "integer"}, "ram": {"type": "integer"}},
        "required": ["cpu", "ram"],
    },
}


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
#: Request body for capella_app_endpoint_resync_start.
#:
#: THE OPERATION SHIPPED WITH body={} AND IT TAKES ONE. The provider builds
#: PostAppEndpointResyncJSONRequestBody{Scopes: &converted}
#: (internal/resources/app_endpoint_resync.go:263) against
#: `Scopes *map[string]ResyncScopes` where ResyncScopes = []string
#: (openapi.gen.go:5589). Omitting it resyncs EVERYTHING, which on a large
#: endpoint is the difference between minutes and hours -- and a caller reading
#: our schema had no way to know a narrower option existed.
_RESYNC_BODY: dict[str, Any] = {
    "scopes": {
        "type": "object",
        "description": (
            "Which collections to resync, as {\"<scope>\": [\"<collection>\", ...]}. "
            "OMIT IT TO RESYNC THE WHOLE ENDPOINT -- that is the expensive "
            "default, not a safe one. A resync re-runs the access control "
            "function over every document it covers."
        ),
    },
}


#: Request body for capella_app_endpoint_update.
#:
#: Derived from the endpoint document a GET returns, minus the fields the server
#: adds and refuses back. Measured 2026-09-14: a round-trip of the document with
#: those fields stripped answered 204.
_APP_ENDPOINT_UPDATE_BODY: dict[str, Any] = {
    "name": {
        "type": "string",
        "description": (
            "MUST equal the app_endpoint_name in the path, exactly. A mismatch "
            "is refused with 400."
        ),
    },
    "bucket": {"type": "string", "description": "Backing Capella bucket."},
    "scopes": {
        "type": "object",
        "description": (
            "scopes.<scope>.collections.<collection>.{accessControlFunction, "
            "importFilter} -- the JavaScript for each collection, as STRINGS in "
            "this JSON document. Note the asymmetry: here the source is a normal "
            "JSON string, while the dedicated "
            "capella_app_endpoint_access_control_function_set sends it raw as "
            "application/javascript. Same source, two encodings, depending on "
            "which route you take."
        ),
    },
    "cors": {
        "type": "object",
        "description": (
            "CORS configuration, same shape capella_app_endpoint_cors_set takes: "
            "origin, loginOrigin, headers, maxAge, disabled. Free-form here "
            "because this operation REPLACES the whole document -- send back what "
            "capella_app_endpoint_get returned unless you mean to change it."
        ),
    },
    "oidc": {
        "type": "array",
        "description": "OpenID Connect providers, replaced wholesale.",
        "items": {
            "type": "object",
            "description": (
                "One provider: issuer and clientId are required, plus optional "
                "discoveryUrl, register, rolesClaim, userPrefix, usernameClaim."
            ),
        },
    },
    "deltaSyncEnabled": {"type": "boolean"},
    "disablePublicAllDocs": {"type": "boolean"},
    "userXattrKey": {
        "type": "string",
        "description": (
            "User xattr key readable from the access control function. Empty "
            "disables the feature."
        ),
    },
}


#: One entry in an on/off schedule's `days` list.
#:
#: MEASURED 2026-09-14 against a live cluster, one 422 at a time. Every rule below
#: is the server's own sentence, not a reading of a docs page:
#:
#:   state 'on'/'off' with a boundary
#:     422 "Monday in the schedule is a non-custom day but it contains an
#:          'on' time boundary."
#:   state 'custom' without one
#:     422 "Monday in the schedule is a custom day but it does not have a
#:          'from' time boundary."
#:   minute 59
#:     422 "...invalid minute value of '59'. The valid minute values are 0 and 30."
#:   hour 24
#:     422 "...invalid hour value of '24'. The valid hour values are from 0 to 23
#:          inclusive."
#:   from/to as "HH:MM" strings
#:     400 'body contains incorrect JSON type for field "days.from"'
#:
#: THE WHOLE-DAY 'on' SHAPE ANSWERS 500. Seven days of {"state": "on"} with no
#: boundaries breaks none of the rules above and is refused with code 10000, "An
#: internal server error occurred." That was measured four times across three
#: runs. It is recorded here because the previous version of this record
#: recommended exactly that body as "the safe shape", which was advice that could
#: not work.
#:
#: The widest window the rules permit is 00:00 to 23:30 on a custom day. It was
#: ACCEPTED (204). So a schedule cannot express "up continuously" -- 30 minutes a
#: day is the floor -- and any caller who wants a cluster never turned off should
#: have no schedule at all rather than a permissive one.
_ONOFF_DAY: dict[str, Any] = {
    "type": "object",
    "properties": {
        "day": {
            "type": "string",
            "enum": ["monday", "tuesday", "wednesday", "thursday",
                     "friday", "saturday", "sunday"],
        },
        "state": {
            "type": "string",
            "enum": ["on", "off", "custom"],
            "description": (
                "'on' and 'off' are whole-day states and must NOT carry from/to. "
                "'custom' is the only state that may, and it MUST: a custom day "
                "without a 'from' is refused. Note that seven whole-day 'on' days "
                "-- valid by every stated rule -- answers 500."
            ),
        },
        "from": {
            "type": "object",
            "description": (
                "Start of the on-window, for a 'custom' day only. An OBJECT, not "
                "a 'HH:MM' string."
            ),
            "properties": {
                "hour": {"type": "integer", "minimum": 0, "maximum": 23},
                "minute": {
                    "type": "integer",
                    "enum": [0, 30],
                    "description": "Only 0 and 30 are accepted. Not free-form.",
                },
            },
            "required": ["hour", "minute"],
        },
        "to": {
            "type": "object",
            "description": "End of the on-window. Same constraints as `from`.",
            "properties": {
                "hour": {"type": "integer", "minimum": 0, "maximum": 23},
                "minute": {"type": "integer", "enum": [0, 30]},
            },
            "required": ["hour", "minute"],
        },
    },
    "required": ["day", "state"],
}


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

#: Body schema for capella_app_endpoint_access_control_function_set.
#:
#: SENT RAW, AS application/javascript -- see Op.body_content_type. This schema
#: describes what the CALLER passes (a string); the client does not JSON-encode it.
#:
#: History, because two wrong answers are recorded in this file's git log and both
#: looked reasonable at the time. The op shipped with body={"function": "<src>"} and
#: answered 400 "JavaScript source does not evaluate to a function" for every input,
#: including the function Capella itself had stored. That was read first as "the
#: source must be parenthesised" (wrong) and then as "the body is a bare JSON string"
#: (also wrong -- it answers "value is not an object"). 43 combinations later, a
#: discriminator settled what the message actually means: text that is not JavaScript
#: draws the same sentence, so the validator never sees a source and the message is
#: boilerplate. The Terraform provider's client names the cause outright.
_ACCESS_CONTROL_FUNCTION_BODY: dict[str, Any] = {
    "type": "string",
    "description": (
        "The complete JavaScript source of the access control / validation (sync) "
        "function, as a bare JSON string -- NOT wrapped in an object. Replaces the "
        "existing function outright. Read the current source from "
        "capella_app_endpoint_get at scopes.<scope>.collections.<collection>."
        "accessControlFunction -- the dedicated getter answers 200 with an empty body."
    ),
}


#: Body schema for capella_app_endpoint_import_filter_set.
#:
#: THE EXACT TWIN of _ACCESS_CONTROL_FUNCTION_BODY, and it inherits that finding
#: rather than rediscovering it. Sent RAW as application/javascript -- see
#: Op.body_content_type -- because json.Marshal would add escape characters to the
#: payload and make it invalid JavaScript, which is the Terraform provider's own
#: stated reason for special-casing this content type.
#:
#: The cost of NOT inheriting it is on the record: the access control function took
#: 43 measured attempts and produced two retracted claims before the provider's
#: client was read. This op is the same shape at the same level of the same
#: resource, so it is shipped with the same handling from the start. If it turns
#: out to differ, that is a measurement to record here -- not a reason to have
#: started from scratch.
_IMPORT_FILTER_BODY: dict[str, Any] = {
    "type": "string",
    "description": (
        "The complete JavaScript source of the import filter, as a bare JSON "
        "string -- NOT wrapped in an object. A filter returning false for a "
        "document keeps that document OUT of the App Endpoint. Replaces the "
        "existing filter outright. Read the current source from "
        "capella_app_endpoint_get at scopes.<scope>.collections.<collection>."
        "importFilter."
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
        name="capella_project_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}",
        summary=(
            "Rename a project or change its description, in place.\n"
            "RENAMING A PROJECT DOES NOT MOVE IT OUT OF, OR INTO, THE GUARDRAIL "
            "ALLOWLIST. CAPELLA_ALLOWED_PROJECTS holds project UUIDs, and the "
            "UUID does not change here — so a project renamed to look like "
            "production is still reapable, and one renamed to look like a test "
            "project is still protected. That is the correct behaviour and it is "
            "worth stating, because the name is what a human reads when deciding "
            "whether a destructive call is safe. "
            "UNVERIFIED PATH: from the provider's generated client "
            "(openapi.gen.go:18127), not yet exercised live. A 404 here "
            "may be the path rather than the id. [TF]"
        ),
        group="projects",
        guarded=True,
        body={"name": {"type": "string"}, "description": {"type": "string"}},
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
            "{'timezone': 'America/New_York', 'days': [{'day': 'monday', "
            "'state': 'on', 'from': {...}, 'to': {...}}]}.\n"
            "TIMEZONE MUST BE IANA. This description said 'ET' until 2026-09-14 "
            "and Capella refuses it: 422 code 11041, 'The timezone ET is not a "
            "valid IANA timezone.' Anyone following the example failed. Use "
            "'America/New_York', 'Europe/London', 'UTC'.\n"
            "ALL SEVEN DAYS ARE REQUIRED. An empty list answers 422 code 11042, "
            "'The schedule contains 0 days. The On/Off schedule requires 7 days "
            "for the schedule, one for each day of the week.'\n"
            "RETRACTED 2026-09-14: this record used to say that seven whole-day "
            "'on' days were 'the safe shape when you want the resource present "
            "without risking a hibernation'. That body answers 500 code 10000 "
            "and has never once succeeded. The advice was inferred from the "
            "rules rather than measured against the server.\n"
            "WHAT ACTUALLY WORKS, measured 204: seven 'custom' days with "
            "from {hour 0, minute 0} to {hour 23, minute 30}. See _ONOFF_DAY for "
            "the full constraint set and the 422 that established each one. "
            "There is NO schedule that keeps a cluster up continuously — 30 "
            "minutes a day off is the floor — so 'never turn it off' means "
            "having no schedule, not a permissive one.\n"
            "POST CREATES, PUT UPDATES. A PUT against a cluster with no schedule "
            "answers 404 'Failed to get On/Off schedule for the database', which "
            "reads like a missing route and is not one. [LIVE+METHOD 204]"
        ),
        group="clusters",
        body={
            "timezone": {
                "type": "string",
                "description": (
                    "IANA name. 'ET' is refused with 422 code 11041; use "
                    "'America/New_York', 'Europe/London', 'UTC'."
                ),
            },
            "days": {
                "type": "array",
                "description": "Exactly seven entries, one per day of the week.",
                "items": _ONOFF_DAY,
                "minItems": 7,
                "maxItems": 7,
            },
        },
        body_required=("timezone", "days"),
        guarded=True,
    ),
    Op(
        name="capella_data_api_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/dataAPI",
        summary=(
            "Data API status for a cluster: whether it is enabled, its state, "
            "whether it is enabled for network peering, and — the part nothing "
            "else supplies — the CONNECTION STRING to reach it.\n"
            "THE HOST IS NOT DERIVABLE FROM THE CLUSTER ID. "
            "handlers/capella/fixture.py documented the Data API base as "
            "https://{clusterId}.data.cloud.couchbase.com, which was a pattern "
            "read off one example. The provider takes it from this response's "
            "`connectionString`, which is an empty string while the Data API is "
            "off. Anything that needs the Data API — document export, import, "
            "Search index definitions — starts here. [TF data_api.go]"
        ),
        group="clusters",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_data_api_set",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/dataAPI",
        summary=(
            "Enable or disable the Data API on a cluster. ASYNCHRONOUS: answers "
            "202 and the cluster works through a state change, so poll "
            "capella_data_api_get until `state` settles and `connectionString` "
            "is non-empty.\n"
            "BOTH FIELDS ARE SENT EVERY TIME. The provider's UpdateDataApiRequest "
            "carries enableDataApi and enableNetworkPeering as plain bools with "
            "no omitempty, so this is a replace: omitting enableNetworkPeering "
            "sends false and turns peering off. Read the current status first "
            "and send back what you are not changing. [TF data_api.go]"
        ),
        group="clusters",
        body={
            "enableDataApi": {
                "type": "boolean",
                "description": "Turn the Data API on or off for this cluster.",
            },
            "enableNetworkPeering": {
                "type": "boolean",
                "description": (
                    "Whether the Data API is reachable over network peering. "
                    "NOT optional in effect — see the summary."
                ),
            },
        },
        body_required=("enableDataApi",),
        guarded=True,
    ),
    Op(
        name="capella_cluster_onoff_schedule_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/onOffSchedule",
        summary=(
            "Update the EXISTING on/off schedule. Same body as "
            "capella_cluster_onoff_schedule_set — see _ONOFF_DAY for the "
            "constraints, all of them measured.\n"
            "POST CREATES, PUT UPDATES, AND THEY ARE NOT INTERCHANGEABLE. POST "
            "against a cluster that already has a schedule answers 422 code "
            "11050, 'Cannot create a new on/off schedule as a schedule already "
            "exists for the cluster. If you want to update the existing "
            "schedule, use the Update on/off schedule API.' PUT against a "
            "cluster with NO schedule answers 404 'Failed to get On/Off schedule "
            "for the database', which reads like a missing route and is not one. "
            "Read capella_cluster_onoff_schedule_get first: 404 code 11040 means "
            "use POST, 200 means use this. [LIVE+METHOD 404]"
        ),
        group="clusters",
        body={
            "timezone": {
                "type": "string",
                "description": "IANA name. 'ET' is refused with 422 code 11041.",
            },
            "days": {
                "type": "array",
                "description": "Exactly seven entries, one per day of the week.",
                "items": _ONOFF_DAY,
                "minItems": 7,
                "maxItems": 7,
            },
        },
        body_required=("timezone", "days"),
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
        name="capella_bucket_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}",
        summary=(
            "Change a bucket's settings IN PLACE: memory quota, durability, "
            "replicas, flush, TTL. Without this every one of those is a "
            "delete-and-recreate, which on a bucket means destroying every "
            "document in it to change a setting.\n"
            "WHAT IT CANNOT CHANGE: name, type, storageBackend, conflict "
            "resolution, eviction policy. Those are fixed at creation.\n"
            "TWO OF THESE FIELDS ARE OPERATIONS, NOT SETTINGS. Changing "
            "`replicas` triggers a REBALANCE, and shrinking "
            "`memoryAllocationInMb` makes the bucket eject to fit. Both return "
            "before the work finishes and both degrade the cluster while it "
            "runs, so neither belongs in an unattended loop. "
            "UNVERIFIED PATH: from the provider's generated client "
            "(openapi.gen.go:28401), not yet exercised live. A 404 here "
            "may be the path rather than the id. [TF]"
        ),
        group="buckets",
        guarded=True,
        body=_BUCKET_UPDATE_BODY,
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
        name="capella_collection_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/scopes/{scope_name}/collections/{collection_name}",
        summary=(
            "Change a collection's maxTTL in place. That is the only field "
            "UpdateCollectionRequest carries -- a collection cannot be renamed "
            "and cannot be moved between scopes.\n"
            "IT DOES NOT RETROACTIVELY EXPIRE ANYTHING. The new maximum applies "
            "to documents written after the change; documents already in the "
            "collection keep the expiry they were written with. Lowering it to "
            "clear out old data does not work and looks like it should. "
            "UNVERIFIED PATH: from the provider's generated client "
            "(openapi.gen.go:29516), not yet exercised live. A 404 here "
            "may be the path rather than the id. [TF]"
        ),
        group="buckets",
        guarded=True,
        body=_COLLECTION_UPDATE_BODY,
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
        name="capella_database_credential_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/users/{user_id}",
        summary=(
            "Rotate a database credential's password, or replace its access "
            "grants, IN PLACE. Today rotation means delete and recreate, and "
            "every client holding the old password fails in the window between.\n"
            "`access` REPLACES the existing grants rather than adding to them, "
            "so an update that omits a privilege the credential currently has "
            "REVOKES it. Read the current grants with "
            "capella_database_credential_get first.\n"
            "UNLIKE THE CREATE OP, omitting `password` does not have Capella "
            "generate one: create returns a generated password in its response "
            "and this operation has no such response to carry one. "
            "UNVERIFIED PATH: from the provider's generated client "
            "(openapi.gen.go:33681), not yet exercised live. A 404 here "
            "may be the path rather than the id. [TF]"
        ),
        group="credentials",
        guarded=True,
        sensitive_response=True,
        body=_DB_CREDENTIAL_UPDATE_BODY,
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
        name="capella_app_service_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}",
        summary=(
            "RESIZE an App Service: node count and compute, nothing else.\n"
            "THIS CANNOT UPGRADE AN APP SERVICE, and the name says otherwise. "
            "UpdateAppServiceRequest carries no `version` field at all "
            "(openapi.gen.go:5811), and version is immutable after creation. "
            "Upgrading means DELETE AND RECREATE at the new version — which "
            "destroys the App Service's App Endpoints along with it. Anyone "
            "planning an upgrade needs capella_app_endpoint_create and "
            "capella_app_endpoint_update as part of the procedure, not as an "
            "afterthought: read every endpoint's definition first, because "
            "nothing else holds a copy.\n"
            "It also cannot change `name` or `description`, so an App Service's "
            "mcp-env marker cannot be re-written by this op.\n"
            "Asynchronous, like create: a 204 means accepted, not resized. Poll "
            "capella_app_service_get until currentState leaves its transitional "
            "value. [TF openapi.gen.go:5811 — UNVERIFIED PATH: not yet exercised "
            "against a live App Service, so a 404 here may be the path rather "
            "than the id.]"
        ),
        group="app_services",
        body=_APP_SERVICE_UPDATE_BODY,
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
        name="capella_app_endpoint_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_name}",
        summary=(
            "Replace an App Endpoint's configuration document. This is the ONLY "
            "way to reach most of an endpoint's settings: scopes and their "
            "per-collection accessControlFunction and importFilter, cors, oidc, "
            "deltaSyncEnabled, userXattrKey and disablePublicAllDocs. Eleven App "
            "Endpoint operations shipped before this one and not one of them "
            "wrote the document, which made all of those settings unreachable.\n"
            "A REPLACE, NOT A MERGE. Read the current document with "
            "capella_app_endpoint_get, change what you need, send the whole "
            "thing back. Omitting a field drops it.\n"
            "body.name MUST EQUAL the name in the path, exactly, casing "
            "included. A mismatch answers 400 'The Update App Endpoint payload "
            "name does not match the App Endpoint name in the URL' — which is "
            "also what an empty body earns, since a missing name cannot match.\n"
            "DROP THE READ-ONLY FIELDS a GET adds before sending: adminURL, "
            "metricsURL, publicURL, state, requireResync, isRequireResync, "
            "audit. [LIVE+METHOD 400; a real PUT answered 204 — see "
            "LIVE_VERIFIED_OUT_OF_BAND]"
        ),
        group="app_endpoints",
        body=_APP_ENDPOINT_UPDATE_BODY,
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
            "sync topology.\n"
            "THE BODY IS RAW JAVASCRIPT, SENT AS application/javascript. It is "
            "not a JSON object, and it is not a JSON string either — the source "
            "text goes on the wire unquoted and unescaped. Sending it as JSON "
            "answers 400 'invalid javascript syntax: JavaScript source does not "
            "evaluate to a function', which reads as a verdict on the JavaScript "
            "and is nothing of the kind: text that is not JavaScript at all draws "
            "the identical message, so nothing is being compiled. That error cost "
            "43 measured attempts on 2026-09-14 — five key vocabularies, four "
            "source forms, three routes — and was settled by the Terraform "
            "provider's own client, which special-cases this exact content type "
            "with the comment 'json.Marshal will add escape characters to the "
            "string payload which makes it invalid javascript'. Two earlier "
            "claims in this record are RETRACTED: that the source needed "
            "parentheses, and that the body was a bare JSON string.\n"
            "THE KEYSPACE IS NOT THE APP ENDPOINT NAME. It is "
            "`<endpoint>.<scope>.<collection>` — the function is per COLLECTION. "
            "Sending the endpoint name alone answers 404 'App Endpoint keyspace "
            "<name> not found', measured 2026-09-14, which reads as a missing "
            "endpoint and is not. capella_app_endpoint_get returns the shape "
            "that shows it: scopes.<scope>.collections.<collection>."
            "accessControlFunction. [LIVE+METHOD 404]"
        ),
        group="app_endpoints",
        body_scalar=_ACCESS_CONTROL_FUNCTION_BODY,
        body_content_type="application/javascript",
        guarded=True,
    ),
    Op(
        name="capella_app_endpoint_access_control_function_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_keyspace}/accessControlFunction",
        summary=(
            "Get the current access control and validation function for a COLLECTION. "
            "The path segment is a keyspace (endpoint.scope.collection), not a bare "
            "App Endpoint name — see app_endpoint_keyspace.\n"
            "ANSWERS 200 WITH AN EMPTY BODY on App Service 4.1.1, measured "
            "2026-09-14 against a collection that demonstrably HAS a function: "
            "capella_app_endpoint_get returns the source at "
            "scopes.<scope>.collections.<collection>.accessControlFunction, and "
            "this getter returns nothing at all. A 200 with an empty body is "
            "NOT evidence that no function is configured — read the endpoint "
            "document instead. [LIVE+METHOD 200, EMPTY BODY]"
        ),
        group="app_endpoints",
        read_only=True,
        idempotent=True,
    ),
    # ── App Endpoint import filter ───────────────────────────────────────────
    #
    # THE MATCHED PAIR. An App Endpoint's per-collection JavaScript comes in two
    # halves: the access control function decides what a document may do once it
    # is in, and the import filter decides whether it comes in at all. Shipping
    # only the first is what this server did until now, and the consequence is
    # not cosmetic: an App Endpoint with NO import filter imports every document
    # in the collection. On a shared bucket that is a correctness problem and a
    # cost problem at once, with no way to narrow it through this server.
    #
    # Paths from the Terraform provider's generated client
    # (openapi.gen.go:24098 GET / 24160 PUT / 24036 DELETE). Same keyspace
    # segment as the access control function, same raw application/javascript
    # body, same expected 204 on write.
    Op(
        name="capella_app_endpoint_import_filter_set",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_keyspace}/importFilter",
        summary=(
            "Upsert the import filter — the JavaScript that decides which "
            "documents in the collection enter the App Endpoint at all. A filter "
            "returning false keeps the document out.\n"
            "THE BODY IS RAW JAVASCRIPT, SENT AS application/javascript, exactly "
            "as capella_app_endpoint_access_control_function_set. It is not a "
            "JSON object and not a JSON string: the source goes on the wire "
            "unquoted and unescaped, because JSON encoding would add escape "
            "characters and make it invalid JavaScript. That finding cost 43 "
            "measured attempts on its twin; this op inherits it rather than "
            "repeating it.\n"
            "THE KEYSPACE IS NOT THE APP ENDPOINT NAME. It is "
            "`<endpoint>.<scope>.<collection>` — the filter is per COLLECTION. "
            "Sending the endpoint name alone answers 404 'App Endpoint keyspace "
            "<name> not found', which reads as a missing endpoint and is not. "
            "MEASURED 2026-09-14. A PUT carrying the text 'this is not "
            "javascript at all' answered 400 'invalid javascript syntax: "
            "(anonymous): Line 1:7 Unexpected identifier' -- a REAL parse, "
            "with a line and column. That is stronger than a path proof: it "
            "shows the raw body reached the JavaScript engine, so the "
            "application/javascript handling inherited from the twin is "
            "measured on this op rather than assumed. Note the twin answers "
            "boilerplate for the same input and never parses at all. "
            "[LIVE+METHOD 400]"
        ),
        group="app_endpoints",
        body_scalar=_IMPORT_FILTER_BODY,
        body_content_type="application/javascript",
        guarded=True,
    ),
    Op(
        name="capella_app_endpoint_import_filter_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_keyspace}/importFilter",
        summary=(
            "Get the current import filter for a COLLECTION. The path segment is "
            "a keyspace (endpoint.scope.collection), not a bare App Endpoint "
            "name — see app_endpoint_keyspace.\n"
            "EXPECT THE SAME EMPTY-BODY BEHAVIOUR AS ITS TWIN until measured "
            "otherwise: capella_app_endpoint_access_control_function_get answers "
            "200 with an EMPTY body on App Service 4.1.1 even for a collection "
            "that demonstrably has a function. If this getter does the same, a "
            "200 with nothing in it is NOT evidence that no filter is "
            "configured — read capella_app_endpoint_get instead, at "
            "scopes.<scope>.collections.<collection>.importFilter. "
            "MEASURED 2026-09-14: answers 200 WITH AN EMPTY BODY, exactly as "
            "its twin does. The empty body was PREDICTED from the twin before "
            "the call and the prediction held, which is why the warning above "
            "is worth trusting: a 200 here is not evidence that no filter is "
            "configured. [LIVE+METHOD 200, EMPTY BODY]"
        ),
        group="app_endpoints",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_app_endpoint_import_filter_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_keyspace}/importFilter",
        summary=(
            "Remove the import filter from a COLLECTION.\n"
            "DESTRUCTIVE IN A WAY THAT DOES NOT LOOK DESTRUCTIVE. Deleting a "
            "filter does not delete data — it WIDENS the endpoint, so every "
            "document in the collection becomes eligible for import where "
            "previously some were excluded. On a shared bucket that can pull in "
            "documents the endpoint's users were never meant to see, and it is "
            "not undone by re-adding the filter: documents already imported stay "
            "imported until a resync. Read the current source with "
            "capella_app_endpoint_get before removing it, because there is no "
            "other copy. "
            "UNVERIFIED PATH: from the provider's generated client "
            "(openapi.gen.go:24036), not yet exercised against a live App "
            "Service. A 404 from this op may be the path rather than the "
            "keyspace. [TF]"
        ),
        group="app_endpoints",
        destructive=True,
        guarded=True,
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
        # ORIGIN IS REQUIRED AND WE DID NOT SAY SO. It is the only non-pointer,
        # non-omitempty field in the provider's CORS struct (openapi.gen.go:1630,
        # `Origin []string \`json:"origin"\``); every sibling is *T + omitempty.
        # A caller following this schema could omit it and be refused for a
        # reason the schema had the information to prevent.
        body_required=("origin",),
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
        body=_RESYNC_BODY,
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
