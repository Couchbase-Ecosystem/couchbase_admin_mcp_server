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
  1. Run ``scripts/verify_capella_paths.py --method-probe`` against a
     Couchbase-internal test organization.
  2. Move confirmed records into ``OPS`` in spec.py.
  3. Retag ``[LIVE]`` or ``[LIVE+METHOD]`` in each summary.
  4. Record each observed status in ``LIVE_VERIFIED``.

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

Design context for the fixture layer these support: docs/FIXTURE_DESIGN.md
"""

from __future__ import annotations

from .spec import _PAGE_QUERY, Op

__all__ = ["PENDING_OPS"]

PENDING_OPS: tuple[Op, ...] = (
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
            "API. [DOC]"
        ),
        group="backup",
        idempotent=False,
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
            "fixture manifest exists for. [DOC]"
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
        summary="Fetch one managed backup record by id. [DOC]",
        group="backup",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_backup_cycle_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/buckets/{bucket_id}/backups",
        summary=(
            "Delete the backup CYCLE for a bucket. This removes the bucket's managed "
            "backup history, not a single backup. IRREVERSIBLE. [DOC]"
        ),
        group="backup",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_backup_restore",
        method="POST",
        # WARNING — DISPUTED PATH. Two reads of the v4 reference disagreed:
        #   (a) .../clusters/{cluster_id}/backup/restore              (no backup id)
        #   (b) .../clusters/{cluster_id}/backups/{backup_id}/restore
        # Shape (b) is used here because a backup id in the path ALONGSIDE the
        # target cluster id is what makes cross-cluster restore a primitive: the
        # path is the TARGET, the body names the SOURCE. If (a) is correct the body
        # must carry both and cross-cluster becomes an orchestration problem.
        # --method-probe with an empty body returns 422 naming the required fields,
        # settling path and body together. DO NOT SHIP UNTIL PROBED.
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/backups/{backup_id}/restore",
        summary=(
            "Restore a managed backup. The cluster in the path is the TARGET. "
            "Documented as able to restore into the same cluster or another cluster "
            "in the same organization, provided both are on the same cloud provider "
            "— Azure to Azure is fine, Azure to AWS is not. DESTRUCTIVE: overwrites "
            "data in the target. Indexes come back DEFERRED, so the target is not "
            "performance-comparable to its source until builds complete — trigger "
            "them and poll capella_query_index_build_status before treating it as "
            "ready. [DOC — path disputed, see the comment on this op]"
        ),
        group="backup",
        destructive=True,
        guarded=True,
        body={},
    ),
    # ── Query indexes ────────────────────────────────────────────────────────
    # /definitions is the read-back that system:indexes does NOT provide: the
    # documented system:indexes metadata object carries only last_scan_time,
    # num_replica and stats, with no definition field.
    Op(
        name="capella_query_index_definitions_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/queryIndexes/definitions",
        summary=(
            "Read back the index definition statements for a cluster's GSI indexes. "
            "This is the CREATE-statement source for a fixture manifest. Response "
            "shape UNCONFIRMED — the rendered v4 reference truncates before the "
            "schema. [DOC]"
        ),
        group="query_index",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_query_index_properties_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/queryIndexes/properties",
        summary="Index properties for a cluster. [DOC]",
        group="query_index",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_query_index_build_status",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/queryIndexes/buildStatus",
        summary=(
            "Build status for a cluster's GSI indexes. This is the gate that makes a "
            "restored or imported environment honest: an index whose definition "
            "exists but is not ONLINE means the cluster is not yet "
            "performance-comparable to its source, and a load test started against "
            "it produces numbers that read as a Couchbase performance problem. Poll "
            "this before reporting ready. [DOC]"
        ),
        group="query_index",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_query_index_manage",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/queryIndexes",
        summary=(
            "Manage query indexes. Verb coverage UNCONFIRMED — whether this covers "
            "create, drop, build or alter is not documented in the rendered "
            "reference. Prefer plain CREATE INDEX / BUILD INDEX / DROP INDEX over "
            "the Data API query passthrough, which is predictable. [DOC]"
        ),
        group="query_index",
        guarded=True,
        body={},
    ),
    # ── Eventing functions ───────────────────────────────────────────────────
    # Settings and source are separate resources; a fixture must capture both.
    Op(
        name="capella_eventing_functions_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventing/functions",
        summary="List eventing functions on a cluster. [DOC]",
        group="eventing",
        read_only=True,
        idempotent=True,
        paginated=True,
    ),
    Op(
        name="capella_eventing_function_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventing/functions/{function_name}",
        summary=(
            "Fetch one eventing function's settings and bindings. Whether this "
            "response is directly re-postable to capella_eventing_function_create "
            "without rewriting bucket and keyspace references for a different "
            "cluster is UNCONFIRMED — assume a transform is needed. [DOC]"
        ),
        group="eventing",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_eventing_function_code_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventing/functions/{function_name}/code",
        summary="Fetch an eventing function's JavaScript source. [DOC]",
        group="eventing",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_eventing_function_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventing/functions",
        summary="Create an eventing function from a settings object. [DOC]",
        group="eventing",
        guarded=True,
        body={},
    ),
    Op(
        name="capella_eventing_function_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventing/functions/{function_name}",
        summary="Replace an eventing function's settings. [DOC]",
        group="eventing",
        guarded=True,
        idempotent=True,
        body={},
    ),
    Op(
        name="capella_eventing_function_code_set",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventing/functions/{function_name}/code",
        summary="Replace an eventing function's JavaScript source. [DOC]",
        group="eventing",
        guarded=True,
        idempotent=True,
        body={},
    ),
    Op(
        name="capella_eventing_function_state_set",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventing/functions/{function_name}/state",
        summary=(
            "Deploy, undeploy, pause or resume an eventing function. A function "
            "created from a fixture is NOT running until its state is set. [DOC]"
        ),
        group="eventing",
        guarded=True,
        idempotent=True,
        body={},
    ),
    Op(
        name="capella_eventing_function_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventing/functions/{function_name}",
        summary="Delete an eventing function. IRREVERSIBLE. [DOC]",
        group="eventing",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_eventing_function_logs_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/eventing/functions/{function_name}/logs",
        summary="Fetch an eventing function's logs. [DOC]",
        group="eventing",
        read_only=True,
        idempotent=True,
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
            "must be recreated afterwards unless captured first. [DOC]"
        ),
        group="replication",
        read_only=True,
        idempotent=True,
        paginated=True,
    ),
    Op(
        name="capella_replication_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/replications/{replication_id}",
        summary="Fetch one XDCR replication's configuration. [DOC]",
        group="replication",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_replication_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/replications",
        summary="Create an XDCR replication. [DOC]",
        group="replication",
        guarded=True,
        body={},
    ),
    Op(
        name="capella_replication_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/replications/{replication_id}",
        summary="Delete an XDCR replication. [DOC]",
        group="replication",
        destructive=True,
        guarded=True,
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
    # All [DOC]: transcribed from the reference, never confirmed against a live control
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
            "and the cluster never became healthy. [DOC]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_cluster_audit_log_config_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLogConfiguration",
        summary=(
            "Which audit events the cluster is recording. Worth reading before trusting "
            "an audit trail: a filter that excludes the event class you care about is "
            "indistinguishable from that event never happening. [DOC]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
    ),
    Op(
        name="capella_cluster_audit_log_config_set",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLogConfiguration",
        summary=(
            "Change which audit events the cluster records. A WRITE to the audit "
            "configuration, so it can be used to stop recording the very operations an "
            "auditor would look for -- guarded, and it should stay that way. [DOC]"
        ),
        group="diagnostics",
        guarded=True,
        body={},
    ),
    Op(
        name="capella_cluster_audit_log_events_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLogEvents",
        summary=(
            "The audit event types available to filter on, which is how you discover "
            "what the configuration above can name. [DOC]"
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
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLogExport",
        summary=(
            "Start an audit-log export job. ASYNCHRONOUS: returns a job id, not the "
            "log. Poll capella_cluster_audit_log_export_get for the download. [DOC]"
        ),
        group="diagnostics",
        body={},
    ),
    Op(
        name="capella_cluster_audit_log_exports_list",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLogExport",
        summary="List audit-log export jobs for a cluster. [DOC]",
        group="diagnostics",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=_PAGE_QUERY,
    ),
    Op(
        name="capella_cluster_audit_log_export_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/clusters/{cluster_id}/auditLogExport/{export_id}",
        summary=(
            "One audit-log export job: its status and, once ready, the download. The "
            "response carries a signed URL, so it is redacted before it reaches a "
            "model context or the log. [DOC]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
        sensitive_response=True,
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
        summary="List alert integrations for a project. [DOC]",
        group="diagnostics",
        read_only=True,
        idempotent=True,
        paginated=True,
        query=_PAGE_QUERY,
    ),
    Op(
        name="capella_alert_integration_get",
        method="GET",
        path="/v4/organizations/{organization_id}/projects/{project_id}/alertIntegrations/{alert_integration_id}",
        summary=(
            "One alert integration. The response may echo the configured webhook URL, "
            "which is a credential in URL form. [DOC]"
        ),
        group="diagnostics",
        read_only=True,
        idempotent=True,
        sensitive_response=True,
    ),
    Op(
        name="capella_alert_integration_create",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/alertIntegrations",
        summary=(
            "Create an alert integration. The body names an outbound destination, so "
            "this is an EGRESS primitive: it must pass the egress allowlist before it "
            "ships, or it becomes a way to point cluster alerts at a host the operator "
            "never approved. [DOC]"
        ),
        group="diagnostics",
        guarded=True,
        body={},
    ),
    Op(
        name="capella_alert_integration_update",
        method="PUT",
        path="/v4/organizations/{organization_id}/projects/{project_id}/alertIntegrations/{alert_integration_id}",
        summary="Update an alert integration. Same egress consideration as create. [DOC]",
        group="diagnostics",
        guarded=True,
        body={},
    ),
    Op(
        name="capella_alert_integration_delete",
        method="DELETE",
        path="/v4/organizations/{organization_id}/projects/{project_id}/alertIntegrations/{alert_integration_id}",
        summary=(
            "Delete an alert integration. Destructive in the way that matters for "
            "monitoring: afterwards the alerts simply stop arriving, silently. [DOC]"
        ),
        group="diagnostics",
        destructive=True,
        guarded=True,
    ),
    Op(
        name="capella_alert_integration_test",
        method="POST",
        path="/v4/organizations/{organization_id}/projects/{project_id}/alertIntegrationTest",
        summary=(
            "Send a test alert. Note the path is NOT under alertIntegrations/{id} -- it "
            "is a sibling collection, so the body identifies the target. Same egress "
            "consideration as create. [DOC]"
        ),
        group="diagnostics",
        body={},
    ),
)
