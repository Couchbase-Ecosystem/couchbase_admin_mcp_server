"""
handlers/capella/spec_pending.py — Capella v4 operations written but NOT shipped.

Kept in a SEPARATE module from spec.py for two reasons:

  * ``OPS`` in spec.py is the shipped registry. ``build_tools()`` and
    ``OPS_BY_NAME`` derive from it, so nothing here can reach a caller as a
    working tool.
  * ``scripts/verify_capella_paths.py`` STATICALLY PARSES spec.py and compares
    what it finds against the live registry. A pending block inside spec.py makes
    that comparison disagree with itself, which is why these live here instead.

An earlier version of this docstring said "two mechanisms DEPEND on it", which was
not true: nothing imported this module and nothing tested it, so a typo in a parked
record was invisible until someone tried to promote it. tests/test_capella_pending.py
now checks the shape of every record here.

Every path below is tagged ``[DOC]``: transcribed from the v4 reference and never
confirmed against a live control plane. The repository refuses to ship such paths,
and that refusal is load-bearing —
``test_every_operation_has_been_verified_against_a_live_organization`` exists
because a commit message once claimed all paths were verified while ten were not.
Moving these into ``OPS`` and relaxing that test would recreate the same failure
one layer up.

TO PROMOTE
==========
  1. Run ``scripts/verify_capella_paths.py --method-probe --include-pending`` against a
     Couchbase-internal test organization. WITHOUT ``--include-pending`` the script reads
     spec.py alone and never sees a single record in this file — it re-checks what is
     already verified. That was true of every run made before the flag existed, which is
     why nothing here had moved.
  2. Move confirmed records into ``OPS`` in spec.py and DELETE the copy here. A name in
     both registries stops the next probe run rather than being probed twice.
  3. Retag ``[LIVE]`` or ``[LIVE+METHOD]`` in each summary. The run's promotion report
     says which one each record earned; ``[LIVE+METHOD]`` requires the operation's own
     method to have been sent, not an OPTIONS probe of its path.
  4. Record each observed status in ``LIVE_VERIFIED``.

WHAT A RUN CAN AND CANNOT SETTLE
================================
An operation whose path needs an identifier reports SKIPPED when no such object exists in
the target organization — correct, and not progress. The identifiers this file needs
beyond org/project/cluster are ``bucket_id``, ``backup_id``, ``function_name``,
``replication_id``, ``event_id``, ``export_id`` and ``alert_integration_id``; all seven
are discovered by the probe when ``--include-pending`` is passed, but only if the objects
are there. See CONTRIBUTING.md for what to provision.

BLOCKERS
========
  * ``capella_backup_restore`` carries a DISPUTED path — see its inline comment.
    The probe settles path and body together through the 422 empty-body response,
    and that answer also decides whether cross-cluster restore is a primitive or
    an orchestration problem.
  * ``{function_name}`` and ``{replication_id}`` are now discovered by
    ``scripts/verify_capella_paths.py``, so the eventing and replication operations
    can be probed. The discovery step reports the list endpoint's status explicitly,
    because "this cluster has no eventing functions" and "we asked the wrong URL" are
    indistinguishable from an absent identifier — and a 404 there means the parked LIST
    path is wrong, which is a finding rather than a skip.

NOT WRITTEN AT ALL: THE CLOUD SNAPSHOT BACKUP SUBSYSTEM
=======================================================
Neither spec.py nor this file mentions ``cloudsnapshotbackups``. The Terraform provider's
generated client carries a whole subsystem we have never looked at:

    GET/POST    /v4/.../clusters/{cluster_id}/cloudsnapshotbackups
    GET/PUT/DEL /v4/.../clusters/{cluster_id}/cloudsnapshotbackups/{snapshot_id}
    POST        /v4/.../clusters/{cluster_id}/cloudsnapshotbackups/{snapshot_id}/restore
    GET         /v4/.../clusters/{cluster_id}/cloudsnapshotbackups/regions
    GET         /v4/.../clusters/{cluster_id}/cloudsnapshotbackups/restores
    GET/PUT/DEL /v4/.../clusters/{cluster_id}/cloudsnapshotbackupschedule

This matters beyond completeness. The managed-backup group above is the wrong primitive
for the "give me a restorable environment on demand, several times a day" request that
drove CBSE-23536 -- backups carry no user metadata, cannot be user-named, and their bytes
are only retrievable through a console download with an emailed URL. A snapshot subsystem
with an explicit restore endpoint, a retention edit, a schedule and a REGIONS endpoint has
a different shape, and ``/cloudsnapshotbackups/restores`` implies restores are first-class
objects that can be listed and tracked.

Nobody has established whether it is a better fit. That is a scoping question, not a
transcription exercise, so nothing is written here yet -- but a gap analysis that never
looked at it is not a gap analysis.

Design context for the fixture layer these support: docs/FIXTURE_DESIGN.md
"""

from __future__ import annotations

# _PAGE_QUERY is no longer imported: every parked operation that used it was promoted on
# 2026-09-01. It lives in spec.py and comes back here the moment a paginated record does.
from .spec import Op

__all__ = ["PENDING_OPS"]

#: RETRACTED 2026-09-12 — the per-bucket backup SCHEDULE endpoint does not exist.
#:
#: Four operations were parked here against
#:     /v4/.../clusters/{cluster_id}/buckets/{bucket_id}/backupSchedule
#: transcribed from the rendered Operational Management API reference. A live
#: sweep on 2026-09-12 returned Go's default ``404 page not found`` -- the body an
#: HTTP mux emits when NOTHING matched -- for that path and for six other
#: spellings of it, including the cluster-level forms.
#:
#: The verdict is sound because the discriminator was proved first rather than
#: assumed. A known-good route with a bogus id returns JSON:
#:     {"code": 5017, "hint": "Returned when the requested backup record could
#:      not be found.", "httpStatusCode": 404}
#: so a JSON body means the route matched and the object is missing, while plain
#: text means no route of that shape exists at all.
#:
#: The lesson is one this file already recorded and I did not follow: a rendered
#: docs page is a weaker source than the provider's generated client, and 19 of
#: the paths parked here were wrong for exactly that reason. The records are
#: DELETED rather than left parked -- a parked record implies "written, awaiting
#: confirmation", and these were disconfirmed.
#:
#: WHAT IS ACTUALLY THERE, observed live on the same sweep:
#:     GET /v4/.../clusters/{cluster_id}/cloudsnapshotbackups        -> 200
#:     GET /v4/.../clusters/{cluster_id}/cloudsnapshotbackupschedule -> 204
#: Both are routes. Neither is implemented anywhere in this server. See the
#: CLOUD SNAPSHOT section in the module docstring above, which called this out
#: as an unexamined subsystem before anyone had probed it -- it is not
#: hypothetical any more.

#: ── PARKED 2026-09-14: P1 items 4 and 5 ──────────────────────────────────────
#:
#: Eight operations from the Terraform provider's generated client. They are
#: PARKED rather than shipped for a reason worth stating, because shipping them
#: was the obvious move and would have been wrong:
#:
#: SHIPPED_UNVERIFIED is capped at 8 and currently holds 2. Adding eight
#: unverified operations would have taken it to 10, and the response to that cap
#: firing is to EARN EVIDENCE, not to raise the number -- the cap's own test says
#: "a cap that moves whenever it fires is decoration". This module is the
#: mechanism that already existed for exactly this, and using it keeps the
#: shipped registry honest while the paths are still unobserved.
#:
#: PROMOTE THEM WITH:
#:     uv run python scripts/verify_capella_paths.py --method-probe --include-pending
#: then move each confirmed record into spec.py, delete the copy here, retag
#: [LIVE] or [LIVE+METHOD], and record the observed status in LIVE_VERIFIED.
#:
#: Note two of these need identifiers the probe may not synthesise:
#: app_endpoint_keyspace (endpoint.scope.collection) and job_id, which only
#: exists in a capella_replication_create response. A SKIPPED verdict on those is
#: honest and is not progress.

PENDING_OPS: tuple[Op, ...] = (
    # ── P1 item 7: App Service admin user read and update ────────────────────
    #
    # We CREATE and DELETE these and can neither read one back nor change it. So
    # rotating an App Service admin user's password means deleting the user and
    # making a new one, and every harness holding the old credential fails in
    # between -- the same asymmetry the database credential had until today.
    Op(
        name="capella_app_service_admin_user_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/adminUsers/{admin_user_id}",
        summary=(
            "Update an App Service admin user: password, or endpoint access.\n"
            "EXPECT THE CREATE OP'S `access` RULE TO HOLD HERE, and do not assume "
            "it: exactly one of accessAllEndpoints or endpoints, never both and "
            "never neither, with {accessAllEndpoints: false} counting as NEITHER. "
            "That was measured on the create path and is recorded there; this "
            "record does not claim it has been measured on THIS one.\n"
            "NO BODY SCHEMA IS DECLARED. Only path and method were sourced. This "
            "is NOT promotable on a path probe alone -- "
            "test_no_shipped_write_tool_is_missing_its_body_schema will refuse "
            "it, and correctly, exactly as it refused "
            "capella_app_endpoint_audit_log_set on 2026-09-14. Read "
            "UpdateAppServiceAdminUserRequest from the provider before shipping. "
            "[TF openapi.gen.go:23336]"
        ),
        group="app_services",
        guarded=True,
    ),

    # ── P1 item 8: sample buckets ────────────────────────────────────────────
    #
    # We can LOAD a sample dataset and cannot list or unload one. That matters
    # for fixture teardown: a sample bucket loaded for a test run is 63,000
    # documents that nothing in this server can remove.

    # ── P1 item 6: bucket backup schedules and cycles ─────────────────────────
    #
    # PARKED WITH A WARNING ATTACHED. Four operations were once parked against
    # /v4/.../buckets/{bucket_id}/backupSchedule, transcribed from the rendered
    # reference, and a live sweep on 2026-09-12 returned Go's mux default
    # "404 page not found" for that path and six other spellings. Those records
    # were DELETED rather than left parked, and the retraction is recorded at the
    # top of this module.
    #
    # THIS IS A DIFFERENT PATH -- /backup/schedules, two segments, sourced from
    # the provider's generated client rather than a docs page. The distinction is
    # the whole reason these are parked rather than shipped: the same mistake in
    # the same subsystem twice would be indefensible, and one probe run settles
    # it. If these also answer plain-text 404, DELETE them as disconfirmed rather
    # than leaving them parked -- a parked record implies "awaiting confirmation".
    Op(
        name="capella_bucket_backup_schedule_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/backup/schedules",
        summary=(
            "Create a backup schedule for a bucket. NO BODY SCHEMA IS DECLARED; "
            "read CreateBackupScheduleRequest from the provider before shipping. "
            "[TF openapi.gen.go:28613]"
        ),
        group="backup",
        guarded=True,
    ),
    Op(
        name="capella_bucket_backup_schedule_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/backup/schedules",
        summary=(
            "Replace a bucket's backup schedule. NO BODY SCHEMA IS DECLARED. "
            "Note the path carries no schedule id, so this almost certainly "
            "REPLACES the bucket's single schedule rather than updating one of "
            "several -- which is a claim to verify, not to assume. "
            "[TF openapi.gen.go:28802]"
        ),
        group="backup",
        guarded=True,
    ),
    Op(
        name="capella_app_endpoint_audit_log_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_name}/auditLog",
        summary=(
            "Read an App Endpoint's audit logging configuration. "
            "[TF openapi.gen.go:24663] THE ROUTE ANSWERED 422 on 2026-09-14, "
            "which is progress and is not enough to ship. A GET is verified "
            "in this repository by a 200 or a 404; "
            "test_every_read_operation_was_verified_by_a_real_call refuses "
            "anything else, and rightly -- a 422 means the route answered "
            "and the READ never happened. Read it as an entitlement rather "
            "than a defect: the App Service level equivalent is refused in "
            "this organization with 'your support package does not include "
            "audit logging'. An organization with audit logging licensed "
            "promotes this in one call."
        ),
        group="app_endpoints",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_app_endpoint_audit_log_set",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/appservices/{app_service_id}/appEndpoints/{app_endpoint_name}/auditLog",
        summary=(
            "Configure an App Endpoint's audit logging.\n"
            "THE BODY SHAPE IS STILL NOT ESTABLISHED. The PATH and METHOD are "
            "now live-verified, and that is all: no body schema is declared, so "
            "this operation cannot be called usefully yet. It ships in that "
            "state deliberately rather than with an invented body -- only the "
            "path and method were taken from "
            "openapi.gen.go:24736; no body schema is declared, so this record is "
            "NOT promotable on a path probe alone. Shipping it with an invented "
            "body would repeat exactly the failure CLAUDE.md records: three wrong "
            "request bodies sat behind verified paths, and a path probe cannot "
            "catch that because it never sends a body.\n"
            "Note the App Service level equivalent is entitlement-gated in this "
            "organization (capella_cluster_audit_log_config_set answers 422 'your "
            "support package does not include audit logging'), so this may be "
            "unverifiable here for the same reason. [TF openapi.gen.go:24736]\n"
            "PATH AND METHOD CONFIRMED 405 on 2026-09-14, and that is still "
            "not enough. It was promoted on the probe report saying READY TO "
            "PROMOTE, and test_no_shipped_write_tool_is_missing_its_body_"
            "schema sent it straight back. The report judges PATHS; a path "
            "verdict says nothing about a body. The guard was right and the "
            "promotion was not."
        ),
        group="app_endpoints",
        guarded=True,
    ),
    # ── P1 item 4: the replication job a create actually returns ─────────────
    Op(
        name="capella_replication_job_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/replications/jobs/{job_id}",
        summary=(
            "Fetch one XDCR replication JOB by the id capella_replication_create "
            "returns.\n"
            "THIS CLOSES A GAP THE REGISTRY ALREADY WORKS AROUND. "
            "capella_replication_create answers with a jobId, NOT a replication "
            "id, so the only way to find the resulting replication today is to "
            "list replications afterwards and infer which one appeared -- which "
            "is ambiguous the moment two replications are created close "
            "together. [TF openapi.gen.go:33004]"
        ),
        group="replication",
        read_only=True,
        idempotent=True,
    ),

    # ── P1 item 5: App Endpoint completeness ─────────────────────────────────
    #
    # Each of these is the missing HALF of something already shipped. The pattern
    # matters: a surface that can SET a thing and not READ it back, or START a
    # thing and not STOP it, is one an operator cannot reason about.
)
