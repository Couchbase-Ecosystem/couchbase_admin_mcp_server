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

PENDING_OPS: tuple[Op, ...] = ()