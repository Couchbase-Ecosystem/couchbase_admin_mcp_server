"""handlers/backup.py — Backup / Restore service.

Split out of the original monolithic ``extended.py`` for the standalone admin
server: the data-plane tools (``cb_transaction_run``, ``cb_analytics_query``)
stay in the CRUD server; only the ``admin_backup_*`` tools live here.

Wraps the backup service REST endpoints at ``/_p/backup/api/v1/...`` on the
cluster manager. Requires the backup service to be running on at least one node.

THE REPOSITORY STATE SEGMENT
============================
Every path here is ``/cluster/self/repository/<state>/...`` where state is one
of ``active``, ``imported`` or ``archived``. It is NOT optional, and omitting it
was why all five of these tools returned 404 against a cluster that was running
the Backup service perfectly well:

  * the listing was ``/repository`` -- a path the service does not serve at all;
  * ``admin_backup_repository_get`` sent ``/repository/<repository_id>``, so the
    repository id landed in the slot the service reads as the STATE, and any id
    that was not literally the word "active" was rejected as an unknown state;
  * ``admin_backup_list`` used ``/<id>/backups``, which does not exist -- the
    individual backups come back inside the repository INFO response, so the
    endpoint is ``/<state>/<id>/info``.

RESTORE, PERFORMED 2026-09-12
-----------------------------
`admin_backup_restore_run` had never been executed -- not cross-cluster, not
same-cluster, not once -- so "backup and restore works" was half proven, and the
unproven half is the one a customer reaches for on their worst day.

It was run against the `mcptest` repository and answered:

    {"task_name": "RESTORE-dd7647a6-1c4b-4bf9-b04d-dca634b444fe"}

That settles the request body, and the two candidate shapes did NOT agree. This
module's own schema described a filter block; the service wants a flat object
whose `target` is the DESTINATION CLUSTER URL with `user` and `password`
alongside. The schema is corrected above from the shape that was accepted.

Still never run: CROSS-cluster restore. The body carries source and target
separately, so it is one call rather than an export/import -- but there is one
Capella cluster and nowhere to restore into. See CLAUDE.md section 6.

CROSS-CLUSTER IS DOCUMENTED, AND IT IS NOT XDCR
-----------------------------------------------
The reference for this endpoint says of `target`: the address of "the cluster
onto which the data is to be restored. Note that this need not be the host
cluster." So restoring a repository held by one cluster's Backup service INTO a
different cluster is the documented behaviour of this one call, with no
replication set up and no export/import step. That is a stronger claim than
"cross-cluster restore exists in Capella v4" and it is reachable from Enterprise
Edition.

Whether that target may be a CAPELLA cluster is a separate and UNSETTLED
question. Two facts sit either side of it:

  - `cbbackupmgr restore -c couchbases://...` into Capella is explicitly
    documented, with --cacert and either --capella (7.6+) or the full set of
    --disable-analytics / --disable-cluster-analytics / --disable-bucket-query /
    --disable-cluster-query / --disable-views. Capella database credentials
    cannot create buckets, so buckets must pre-exist, and indexes come back
    unbuilt.
  - This REST body carries the disable_* flags, but carries NO field for a CA
    certificate, no --no-ssl-verify, and no --capella. The Backup service runs
    cbbackupmgr underneath, so the TLS material is the open question, not the
    direction of travel.

Do not describe EE -> Capella restore through this tool as supported until it
has been performed. The cbbackupmgr path to Capella IS supported and is the
answer to give a customer today.

References:
  https://docs.couchbase.com/server/current/rest-api/backup-restore-data.html
  https://docs.couchbase.com/cloud/clusters/cli-backup-restore.html

CONFIRMED AGAINST A RUNNING SERVICE, 2026-09-12
-----------------------------------------------
The correction came from the service's API reference, which is a source and not
an observation. It was then measured, once the Backup service was actually added
to the cluster -- every earlier sweep had 404'd for the mundane reason that no
node was running it, which proves nothing about a path:

    OLD  /cluster/self/repository                  -> 404  no such route
    NEW  /cluster/self/repository/active           -> 200  answered
         /cluster/self/repository/imported         -> 200  answered
         /cluster/self/repository/archived         -> 200  answered

And the diagnosis for the worst of the five confirmed itself:

    OLD  /cluster/self/repository/<repository_id>  -> 400, NOT 404

Only a handler that ran can call a request malformed. A 400 there is the service
saying "<repository_id> is not one of active, imported, archived" -- the id in
the state slot, exactly as described above.

THE PLAN ENDPOINT IS ANOTHER ONE THE REFERENCE GETS WRONG
---------------------------------------------------------
The reference gives `/api/v1/cluster/plan` for listing plans. Measured
2026-09-12:

    /api/v1/plan          -> 200, the built-in plans
    /api/v1/cluster/plan  -> 400 {"msg":"Remote cluster not supported",
                                  "extras":"Invalid cluster: plan"}
    /api/v1/plans         -> 404

The 400 explains itself: `/cluster/<name>` takes a cluster name and "self" is
the only valid one, so the service read "plan" as a cluster. That is a matched
route rejecting its argument, not a missing route -- which is why a probe that
treats 400 as inconclusive throws away its best evidence.

Four candidate paths were tried against a live cluster before the reference
settled it. Recorded here rather than silently corrected, because "the Backup
service is broken" was the working theory for a while and it was wrong.

Reference: https://docs.couchbase.com/server/current/rest-api/backup-rest-api.html
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .egress import guard_nested_host_fields
from .shared import admin_request, arg_truthy, err, ok, quote_path

# ── Paths ────────────────────────────────────────────────────────────────────

#: The Backup service behind ns_server's proxy. Direct, the service listens on
#: 8097; through the cluster manager on 8091/18091 it is reached under this
#: prefix, which is what lets one credential and one port serve every tool here.
_BACKUP = "/_p/backup/api/v1"

#: The repository states the service recognises. A repository moves between
#: them, so the same id can exist under more than one.
_STATES = ("active", "imported", "archived")


def _repository_path(args: dict, *, suffix: str = "") -> str:
    """`/cluster/self/repository/<state>/<id>`, with the state segment REQUIRED.

    `state` defaults to "active" because that is the state a repository is in
    while it is being backed up to, and therefore the only one most callers ever
    name. It is still declared on every tool: an archived repository is exactly
    what someone restoring from last quarter needs, and there is no other way to
    address one.
    """
    state = (args.get("state") or "active").strip().lower()
    if state not in _STATES:
        raise ValueError(
            f"state must be one of {', '.join(_STATES)}, not {state!r}"
        )
    rid = quote_path(args["repository_id"])
    return f"{_BACKUP}/cluster/self/repository/{state}/{rid}{suffix}"


#: Declared on every repository-addressed tool, so the schema carries the same
#: vocabulary the service does.
_STATE_PROPERTY = {
    "type": "string",
    "enum": list(_STATES),
    "default": "active",
    "description": (
        "Which repository state to address. Defaults to 'active'; use "
        "'archived' to reach a repository that has been archived, or "
        "'imported' for one imported from another cluster."
    ),
}

# ── Tool definitions ─────────────────────────────────────────────────────────

TOOLS: list[Tool] = [
    Tool(
        name="admin_backup_repository_list",
        description=(
            "List active backup repositories on the backup service. Requires "
            "the backup service to be running on at least one node."
        ),
        inputSchema={
            "type": "object",
            "properties": {"state": _STATE_PROPERTY},
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_backup_plans_list",
        description=(
            "List the backup PLANS the service knows: the schedules a "
            "repository can be created against. Couchbase ships built-ins such "
            "as _daily_backups and _hourly_backups. A repository must name one, "
            "so this is the first call when creating one."
        ),
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_backup_repository_create",
        description=(
            "Create a backup repository. Without one, every other backup tool "
            "here has nothing to act on -- listing, running and restoring all "
            "address a repository. Needs a plan name (admin_backup_plans_list) "
            "and an archive path the BACKUP SERVICE can write, which is a path "
            "inside the service's own filesystem, not the caller's."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "repository_id": {
                    "type": "string",
                    "description": "Name for the new repository.",
                },
                "plan": {
                    "type": "string",
                    "description": (
                        "A plan name from admin_backup_plans_list, e.g. "
                        "'_daily_backups'."
                    ),
                },
                "archive": {
                    "type": "string",
                    "description": (
                        "Where the backup data is written. A filesystem path as "
                        "the SERVICE sees it (in a container deployment, a path "
                        "inside that container), or a cloud URI such as "
                        "s3://bucket/prefix. A cloud destination is subject to "
                        "the egress allowlist."
                    ),
                },
                "bucket_name": {
                    "type": "string",
                    "description": (
                        "Restrict the repository to one bucket. Omit to back up "
                        "every bucket -- which is the default and is rarely what "
                        "is wanted for a test repository."
                    ),
                },
                "confirm": {"type": "boolean"},
            },
            "required": ["repository_id", "plan", "archive"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
        ),
    ),
    Tool(
        name="admin_backup_repository_get",
        description="Get details of a specific backup repository.",
        inputSchema={
            "type": "object",
            "properties": {
                "repository_id": {"type": "string"},
                "state": _STATE_PROPERTY,
            },
            "required": ["repository_id"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_backup_list",
        description="List all backups stored in a repository.",
        inputSchema={
            "type": "object",
            "properties": {
                "repository_id": {"type": "string"},
                "state": _STATE_PROPERTY,
            },
            "required": ["repository_id"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_backup_run",
        description=(
            "Trigger a backup operation on the specified repository. Returns "
            "task ID; monitor progress with admin_cluster_tasks."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "repository_id": {"type": "string"},
                "state": _STATE_PROPERTY,
                "full_backup": {
                    "type": "boolean",
                    "description": "Default false (incremental); true = full backup",
                },
            },
            "required": ["repository_id"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
        ),
    ),
    Tool(
        name="admin_backup_restore_run",
        description=(
            "Trigger a restore. OVERWRITES data in the target cluster — the "
            "only tool here that destroys anything. Requires confirm:true.\n"
            "The `target` object is the request body and its shape was WRONG in "
            "this schema until 2026-09-12: it described a filter block "
            "(filter_keys, mappings, include, exclude) when the service wants a "
            "flat object whose `target` is the destination cluster URL. A model "
            "following the old description would have built a body the service "
            "rejects. Corrected from a performed restore, not from a docs page."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "repository_id": {"type": "string"},
                "state": _STATE_PROPERTY,
                "target": {
                    "type": "object",
                    "description": (
                        "The restore request, sent to the Backup service verbatim. "
                        "OBSERVED SHAPE, from a performed restore on 2026-09-12 "
                        "(task RESTORE-dd7647a6...): a FLAT object whose `target` "
                        "is the DESTINATION CLUSTER URL, not a filter block.\n"
                        "  target   (required) cluster to restore INTO, e.g. "
                        "'http://127.0.0.1:8091'\n"
                        "  user, password  (required) credentials for that cluster\n"
                        "  auto_create_buckets  create missing buckets. Default "
                        "false; a restore that invents buckets is rarely wanted.\n"
                        "  force_updates  OVERWRITE documents the target holds a "
                        "NEWER copy of. This is the flag that turns a restore "
                        "into data loss on a live cluster. Omit unless you mean "
                        "it.\n"
                        "  auto_remove_collections  drop scopes and collections "
                        "the backup records as deleted. Off by default, so a "
                        "restore does not silently remove what the target has.\n"
                        "  enable_bucket_config  restore bucket SETTINGS as well "
                        "as data, overwriting the target bucket's configuration.\n"
                        "  replace_ttl  'all' | 'none' | 'expired' -- reset expiry "
                        "on restored documents. 'all' rewrites the expiry of every "
                        "document, including ones that had none.\n"
                        "  replace_ttl_with  the new expiry: an RFC3339 time, or "
                        "'0' for no expiry. Required when replace_ttl is not "
                        "'none'.\n"
                        "  map_data  remap on restore, e.g. 'mcptest=mcptest_copy'\n"
                        "  filter_keys, filter_values  regular expressions\n"
                        "  start, end  bound which backups in the repository\n"
                        "  disable_data, disable_analytics, disable_eventing, "
                        "disable_ft, disable_gsi_indexes, disable_views  skip a "
                        "service\n"
                        "Returns a task name; the restore is ASYNCHRONOUS."
                    ),
                },
                "confirm": {"type": "boolean"},
            },
            "required": ["repository_id", "target"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
        ),
    ),
]


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        if name == "admin_backup_repository_list":
            state = (args.get("state") or "active").strip().lower()
            if state not in _STATES:
                return err(
                    f"state must be one of {', '.join(_STATES)}, not {state!r}",
                    tool=name,
                )
            return ok(
                admin_request(
                    "GET", f"{_BACKUP}/cluster/self/repository/{state}"
                )
            )

        if name == "admin_backup_plans_list":
            # `/plan`, NOT `/cluster/plan`. The published reference says the
            # latter; the service reads that segment as a CLUSTER NAME and
            # answers 400 "Invalid cluster: plan", because /cluster/<name> takes
            # only "self". Measured 2026-09-12: /plan -> 200 with the built-in
            # plans, /cluster/plan -> 400, /plans -> 404.
            return ok(admin_request("GET", f"{_BACKUP}/plan"))

        if name == "admin_backup_repository_create":
            # A repository is always created in the ACTIVE state -- imported and
            # archived are states a repository REACHES, not ones it starts in --
            # so this path is fixed rather than taking the state argument the
            # other tools accept.
            rid = quote_path(args["repository_id"])

            body: dict = {
                "plan": args["plan"],
                "archive": args["archive"],
            }
            if args.get("bucket_name"):
                body["bucket_name"] = args["bucket_name"]

            # `archive` can be a cloud URI (s3://, az://, gs://), which makes it
            # a destination this server is about to send cluster data to. The
            # same guard the restore target gets applies: an archive pointing at
            # an unallowlisted host is exfiltration with a backup's name on it.
            guard_nested_host_fields(body, tool=name, path="archive")

            return ok(
                admin_request(
                    "POST",
                    f"{_BACKUP}/cluster/self/repository/active/{rid}",
                    data=body,
                    json_body=True,
                )
            )

        if name == "admin_backup_repository_get":
            return ok(admin_request("GET", _repository_path(args)))

        if name == "admin_backup_list":
            # `/info`, not `/backups`. The service has no endpoint that returns
            # backups on their own; the repository info response carries them in
            # a "backups" array alongside the buckets, item counts and mutation
            # counts, which is why a path built from the tool's own name 404s.
            return ok(admin_request("GET", _repository_path(args, suffix="/info")))

        if name == "admin_backup_run":
            payload: dict = {}
            # arg_truthy: "false" is a non-empty string, so raw truthiness ran a
            # FULL backup -- hours of I/O and repository growth -- when the caller
            # explicitly asked for an incremental one.
            if args.get("full_backup") is not None:
                payload["full_backup"] = arg_truthy(args["full_backup"])
            # ALWAYS SEND A BODY, EVEN AN EMPTY ONE.
            #
            # This read `data=payload if payload else None`, so the common call --
            # admin_backup_run with only a repository_id -- sent NO body, and the
            # Backup service refused it:
            #
            #   400 {'status': 400, 'msg': 'invalid request body', 'extras': 'EOF'}
            #
            # 'EOF' is the service saying it began decoding a JSON body and found
            # the request empty. `{}` is a valid request; absent is not.
            #
            # MEASURED 2026-09-13, the first time this tool was ever EXECUTED. It
            # had only ever been exercised through the confirmation gate and the
            # dry-run preview, both of which stop before the HTTP call -- so a
            # tool that could never have worked passed every check the surface
            # harness makes, for as long as the harness has existed. A write tool
            # is not verified until a real one has been performed.
            #
            # admin_request sends `data={}` as the body `{}` because it tests
            # `data is not None`, so passing the empty dict is sufficient here.
            return ok(
                admin_request(
                    "POST",
                    _repository_path(args, suffix="/backup"),
                    data=payload,
                    json_body=True,
                )
            )

        if name == "admin_backup_restore_run":
            # `target` is a free-form object forwarded verbatim to the Backup Service,
            # and this module had no egress guard of any kind. A restore target can
            # name remote locations and credentials, so the same walk the eventing
            # definitions get applies here: any destination-shaped value at any depth
            # must be in the allowlist.
            guard_nested_host_fields(args["target"], tool=name, path="target")
            return ok(
                admin_request(
                    "POST",
                    _repository_path(args, suffix="/restore"),
                    data=args["target"],
                    json_body=True,
                )
            )

        return err(f"Unknown backup tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
