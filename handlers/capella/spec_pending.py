"""
handlers/capella/spec_pending.py — Capella v4 operations written but NOT shipped.

Kept in a SEPARATE module from spec.py deliberately. Two mechanisms depend on it:

  * ``OPS`` in spec.py is the shipped registry. ``build_tools()`` and
    ``OPS_BY_NAME`` derive from it, so nothing here can reach a caller as a
    working tool.
  * ``scripts/verify_capella_paths.py`` STATICALLY PARSES spec.py and compares
    what it finds against the live registry. A pending block inside spec.py makes
    that comparison disagree with itself, which is why these live here instead.

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
  * ``{function_name}`` and ``{replication_id}`` are not yet suppliable by the
    verification script. They must be added there before the probe can cover the
    eventing and replication operations.

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
            "ready. [DOC — path disputed, see comment in spec.py]"
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
)
