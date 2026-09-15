"""Create, through the MCP tools themselves, the objects the surface check needs.

WHY THIS EXISTS
===============
`scripts/verify_mcp_surface.py --write-preview` reports two different kinds of
SKIPPED, and only one of them is a gap in the harness:

    "no request body could be built from the shipped schema"
        — a limitation of the checker. Fixed in the checker.

    "no <id> exists on this cluster — create one and this tool becomes testable"
        — a fact about the ENVIRONMENT. No amount of work on the checker moves
          it. The object has to exist.

The second kind dominates, and every one of them names an object that one of
this server's own write tools can create. So the setup for the check is itself a
test: each create below is a write tool being exercised with a REAL body against
a real control plane, which is strictly more than the preview phase can prove.
A tool that creates the fixture for another tool has verified itself on the way
past.

WHAT IT CREATES
---------------
    scope        mcptest                     -> capella_scope_create
    collection   mcptest.events              -> capella_collection_create
    collection   mcptest.meta                -> capella_collection_create
    credential   mcptest-cred                -> capella_database_credential_create
    allowed CIDR 192.0.2.1/32                -> capella_allowed_cidr_create
    backup       of the named bucket         -> capella_backup_create
    replication  to the other cluster        -> capella_replication_create
    eventing fn  mcptest-fn                  -> capella_eventing_function_create
    query index  mcptest_idx_<collection>     -> capella_query_index_manage
                 (deferred, one per collection)
    audit export one past hour               -> capella_cluster_audit_log_export_create

Two collections rather than one is not padding: an Eventing function's
`eventMetadataStorage` MUST be a different keyspace from its `eventSource`, and
pointing both at the same collection is rejected.

THE CIDR IS DELIBERATELY USELESS
--------------------------------
192.0.2.1/32 is TEST-NET-1 (RFC 5737), reserved for documentation and not
routable on the public internet. It exercises capella_allowed_cidr_create and
gives capella_allowed_cidr_delete an id to address, while granting access to
nobody. An allowlist entry created by a test script should not be able to let
anything in, and "it was only a test" is not a property an entry has after the
script exits.

WHAT IT WILL NOT DO
-------------------
It refuses any cluster holding a bucket outside the throwaway set, so it cannot
be pointed at the cluster carrying real work. That check reads the LIVE bucket
list rather than trusting the name passed on the command line.

The alert integration is OFF unless --webhook-url is given. Creating one makes
Capella send a REAL request to that URL immediately, the scheme must be https,
and the endpoint must answer 2xx or the create fails — so there is no safe
default and inventing one would produce a failure that looks like a broken tool.

USAGE
-----
    uv run python scripts/capella_populate_test_cluster.py --cluster <id|name|host>
    uv run python scripts/capella_populate_test_cluster.py --cluster <...> --perform

Dry run is the default. Every step is idempotent: an object that already exists
is reported as present and not re-created, so the script can be re-run after a
partial failure without producing duplicates.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ERROR_MARKER = "_is_error"

#: Buckets whose presence means this is NOT a throwaway cluster. Checked against
#: the live bucket list, not against the cluster name.
REAL_WORK = {"harvester", "supportal"}

#: Everything this script makes carries this prefix, so a transcript six weeks
#: later says plainly which objects were synthetic.
PREFIX = "mcptest"

#: RFC 5737 TEST-NET-1. Documentation-only, not routable. See the module docstring.
SAFE_CIDR = "192.0.2.1/32"

#: Written only when the App Endpoint collection has no access control function
#: to round-trip. Deliberately the smallest thing that is still a function: it
#: assigns every document to one named channel and asserts nothing, so it cannot
#: reject a write the rest of the fixture depends on. Sent as a BARE STRING --
#: see the comment in _access_control_function for why that matters.
_DEFAULT_ACCESS_CONTROL_FUNCTION = (
    "function (doc, oldDoc, meta) {\n  channel('" + PREFIX + "');\n}"
)


def _client_env(*, dry_run: bool) -> dict[str, str]:
    env = dict(os.environ)
    env["CB_ADMIN_TRANSPORT"] = "stdio"
    env["CB_ADMIN_READ_ONLY_MODE"] = "false"
    if dry_run:
        env["CB_ADMIN_DRY_RUN"] = "true"
    else:
        env.pop("CB_ADMIN_DRY_RUN", None)
    env.setdefault("CB_ADMIN_PROFILE", "workstation")
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env


def _payload(response: Any) -> dict:
    for block in getattr(response, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return {"_raw": text}
            return parsed if isinstance(parsed, dict) else {"_list": parsed}
    return {}


def _schema_refusal(body: dict) -> str:
    """The MCP SDK's own validation message, when the call never reached a tool.

    NOT AN ERROR SHAPE THIS SCRIPT KNEW ABOUT, and that cost a false green on
    2026-09-14. capella_alert_integration_create was sent without the required
    `method` field, and the SDK refused it before dispatch with a plain-text
    body that _payload could not parse as JSON:

        {"_raw": "Input validation error: 'method' is a required property"}

    It carries no `_is_error`, no `requires_confirmation` and no HTTP status, so
    create() fell through to `self.check(True, ...)` and reported

        + alert integration mcptest-alerts

    in the created list. Nothing had been created. The run was green about a
    call that never left the client.

    A refusal from the SDK is a failure of THIS SCRIPT's arguments, not of the
    server, and it must read that way: the message names the missing field.
    """
    raw = body.get("_raw")
    if isinstance(raw, str) and "validation error" in raw.lower():
        return raw.strip()
    return ""


def _rows(body: dict) -> list:
    if "_list" in body:
        return body["_list"]
    for key in (
        "data",
        "items",
        "backups",
        "buckets",
        "clusters",
        "projects",
        "scopes",
        "collections",
        "replications",
    ):
        value = body.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict) and isinstance(value.get("data"), list):
            return value["data"]
    return []


def _matches(cluster: dict, needle: str) -> bool:
    needle = needle.strip().lower()
    if not needle:
        return False
    return any(
        needle in str(cluster.get(k, "")).lower()
        for k in ("id", "name", "connectionString")
    )


def _is_already_exists(result: dict) -> bool:
    """Does this error say the object is already there?

    Capella's 409 covers two unrelated situations with one status code:

        {"code": 409, "message": "An eventing function with the requested
         name already exists."}                      -> fixture already built
        {"code": 409, ... cluster is deploying/scaling/rebalancing ...}
                                                     -> create did NOT happen

    Only the first is a success. Matching on status alone would swallow the
    second and report a cluster that refused every write as fully populated.
    """
    text = f"{result.get('error', '')} {result.get('message', '')}".lower()

    # NOT EVERY "ALREADY THERE" IS A 409. The on/off schedule says it with a 422:
    #
    #   422 code 11050 "Cannot create a new on/off schedule as a schedule already
    #   exists for the cluster. If you want to update the existing schedule, use
    #   the Update on/off schedule API."
    #
    # Measured 2026-09-14, on the run immediately after the first successful
    # create. Matching on 409 alone reported a fixture that was correctly built
    # as a failed check -- the same false-negative this function exists to stop,
    # one status code over. The code is matched as well as the words because
    # 11050 is unambiguous where "already exists" is merely likely.
    if "11050" in text and "already exists" in text:
        return True

    if result.get("status") != 409 and "409" not in str(result.get("error", "")):
        return False
    return "already exists" in text or "duplicate" in text


class Populate:
    def __init__(self, args) -> None:
        self.args = args
        self.failures: list[str] = []
        self.created: list[str] = []
        self.present: list[str] = []
        self.performed = not args.dry_run

    def say(self, text: str = "") -> None:
        print(text, flush=True)

    def check(self, ok: bool, label: str, detail: str = "") -> bool:
        self.say(f"   {'PASS' if ok else 'FAIL'}  {label}")
        if detail:
            self.say(f"         {detail}")
        if not ok:
            self.failures.append(label)
        return ok

    async def call(self, session, tool: str, arguments: dict) -> dict:
        self.say(f"\n-> {tool}")
        for key, value in arguments.items():
            rendered = repr(value)
            if len(rendered) > 260:
                rendered = rendered[:260] + " ..."
            self.say(f"     {key} = {rendered}")
        response = await asyncio.wait_for(
            session.call_tool(tool, arguments), timeout=self.args.timeout
        )
        body = _payload(response)
        rendered = json.dumps(body, indent=2)
        if len(rendered) > 700:
            rendered = rendered[:700] + "\n     ..."
        self.say(f"   <- {rendered}")
        return body

    async def create(self, session, tool: str, arguments: dict, label: str) -> dict:
        """One create, gate first.

        The unconfirmed call is not ceremony. A write that proceeds without
        `confirm: true` means the gate is not in the dispatch path for that tool,
        and the only way to find that out is to try it on every tool rather than
        on a representative one.
        """
        unconfirmed = await self.call(session, tool, arguments)
        # A SCHEMA REFUSAL IS NOT A GATE REFUSAL, and conflating them hides the
        # bug in whichever one is broken. If the SDK rejected the arguments, the
        # gate was never reached and nothing has been learned about it -- say so
        # and stop, rather than sending the same invalid arguments again with
        # confirm:true and reporting whatever comes back as a creation.
        refusal = _schema_refusal(unconfirmed)
        if refusal:
            self.check(False, f"{tool} arguments do not match its schema", refusal)
            self.say(
                f"   NOT ATTEMPTED: {label}. The gate was never exercised, "
                f"so this run says nothing about it either way."
            )
            return unconfirmed
        self.check(
            unconfirmed.get("requires_confirmation") is True
            or unconfirmed.get(ERROR_MARKER) is True,
            f"{tool} without confirm is refused",
        )
        result = await self.call(session, tool, {**arguments, "confirm": True})

        refusal = _schema_refusal(result)
        if refusal:
            self.check(False, f"{label} created", refusal)
            return result

        if not self.performed:
            self.check(
                result.get("dry_run") is True and result.get("executed") is False,
                f"{tool} is previewed, not executed",
            )
            return result

        if result.get(ERROR_MARKER) is True:
            # A 409 that says the object already exists is the DESIRED END STATE
            # reached by an earlier run, not a failure. Reporting it as one is
            # what the second Capella run did on 2026-09-13: every check passed
            # except `eventing function mcptest-fn created`, which "failed"
            # because it had succeeded an hour earlier.
            #
            # Narrow on purpose. Capella also answers 409 when the cluster is
            # mid-operation (deploying, scaling, rebalancing, turning on/off),
            # and THAT 409 is a real failure to report — the create did not
            # happen and will not happen until the cluster is healthy. The two
            # are distinguished by the message, not by the status, so match the
            # message and let every other 409 fail.
            if _is_already_exists(result):
                self.say(
                    f"   {label} is already present (the create was refused "
                    f"as a duplicate)"
                )
                self.present.append(label)
                return result
            # The message is the finding. A 422 that names a field is the schema
            # this registry has been carrying on faith; record it rather than
            # calling the tool broken.
            self.check(False, f"{label} created", json.dumps(result)[:400])
            return result

        self.check(True, f"{label} created")
        self.created.append(label)
        return result

    # ── scope ────────────────────────────────────────────────────────────────

    async def run(self, session) -> None:
        self.say("=" * 70)
        self.say("populate a Capella test cluster, through the tools themselves")
        self.say(
            f"mode   {'PERFORM (real writes)' if self.performed else 'DRY RUN (preview)'}"
        )
        self.say("=" * 70)

        scope_ids = await self.scope(session)
        if scope_ids is None:
            return
        ids, bucket_id, other = scope_ids

        b = {**ids, "bucket_id": bucket_id}

        # 1. scope, then two collections under it.
        existing = {
            s.get("name")
            for s in _rows(await self.call(session, "capella_scopes_list", dict(b)))
            if isinstance(s, dict)
        }
        if PREFIX in existing:
            self.say(f"   scope {PREFIX!r} is already present")
            self.present.append(f"scope {PREFIX}")
        else:
            await self.create(
                session,
                "capella_scope_create",
                {**b, "body": {"name": PREFIX}},
                f"scope {PREFIX}",
            )

        # Re-read the scopes so the collection check sees the scope just made.
        present_collections: set[str] = set()
        for row in _rows(await self.call(session, "capella_scopes_list", dict(b))):
            if isinstance(row, dict) and row.get("name") == PREFIX:
                present_collections = {
                    c.get("name")
                    for c in (row.get("collections") or [])
                    if isinstance(c, dict)
                }
        for collection in ("events", "meta"):
            if collection in present_collections:
                self.say(f"   collection {PREFIX}.{collection} is already present")
                self.present.append(f"collection {PREFIX}.{collection}")
                continue
            await self.create(
                session,
                "capella_collection_create",
                {**b, "scope_name": PREFIX, "body": {"name": collection}},
                f"collection {PREFIX}.{collection}",
            )

        # 2. A database credential. No password field: Capella generates one and
        #    returns it once, so nothing secret has to be invented here or end up
        #    in this transcript.
        if await self._already(
            session,
            "capella_database_credentials_list",
            dict(ids),
            "name",
            f"{PREFIX}-cred",
            f"credential {PREFIX}-cred",
        ):
            pass
        else:
            await self.create(
                session,
                "capella_database_credential_create",
                {
                    **ids,
                    "body": {
                        "name": f"{PREFIX}-cred",
                        "access": [{"privileges": ["data_reader"]}],
                    },
                },
                f"credential {PREFIX}-cred",
            )

        # 3. The allowlist entry that lets nobody in.
        if not await self._already(
            session,
            "capella_allowed_cidrs_list",
            dict(ids),
            "cidr",
            SAFE_CIDR,
            f"allowed CIDR {SAFE_CIDR}",
        ):
            await self.create(
                session,
                "capella_allowed_cidr_create",
                {
                    **ids,
                    "body": {
                        "cidr": SAFE_CIDR,
                        "comment": f"{PREFIX} — RFC 5737, grants no access",
                    },
                },
                f"allowed CIDR {SAFE_CIDR}",
            )

        # 4. A backup, so capella_backup_get and capella_backup_cycle_delete have
        #    an id on THIS cluster rather than on the one holding real work.
        # NOT idempotent, deliberately. A backup is additive and a second one is
        # a second restore point, not a duplicate object — so there is nothing to
        # skip and skipping would be the surprising behaviour.
        await self.create(
            session, "capella_backup_create", dict(b), f"backup of {self.args.bucket}"
        )

        # 5. XDCR INTO the test cluster, never out of it.
        #
        # DIRECTION REVERSED 2026-09-14, and the reversal is the safety property.
        # This used to replicate FROM the test cluster INTO `other`, and then
        # refuse whenever `other` held real work -- correct, but it meant the
        # fixture could never create a replication at all on the only pair of
        # clusters that exists here.
        #
        # A replication WRITES to its target and only READS its source. So make
        # the throwaway cluster the TARGET: reading travel-sample out of the
        # other cluster changes nothing there, and the documents land in the
        # cluster that exists to be overwritten. That is safe in the direction
        # the old code refused, and it needs no override flag.
        #
        # NOTE WHICH CLUSTER IS IN THE PATH. capella_replication_create's path
        # cluster is the SOURCE -- the same asymmetry that made defect #8 out of
        # capella_backup_restore. So cluster_id here is `other`, not the cluster
        # this script is populating, and the guardrail in handlers/capella
        # checks `target.cluster` because that is the end being written.
        if other is None:
            self.say("\n   no second cluster — skipping capella_replication_create")
        else:
            await self.create(
                session,
                "capella_replication_create",
                {
                    **ids,
                    "cluster_id": str(other.get("id")),
                    "body": {
                        "sourceBucket": bucket_id,
                        "target": {
                            "bucket": bucket_id,
                            "cluster": ids["cluster_id"],
                            "type": "capella",
                        },
                        "direction": "oneWay",
                        "priority": "low",
                    },
                },
                f"replication from {other.get('name')} into this cluster",
            )

        # 6. Eventing. Source and metadata MUST be different keyspaces.
        await self.create(
            session,
            "capella_eventing_function_create",
            {
                **ids,
                "body": {
                    "name": f"{PREFIX}-fn",
                    "eventSource": {
                        "bucket": self.args.bucket,
                        "scope": PREFIX,
                        "collection": "events",
                    },
                    "eventMetadataStorage": {
                        "bucket": self.args.bucket,
                        "scope": PREFIX,
                        "collection": "meta",
                    },
                    "code": "function OnUpdate(doc, meta) { log('mcptest', meta.id); }",
                    "description": f"{PREFIX} fixture",
                },
            },
            f"eventing function {PREFIX}-fn",
        )

        # 7. A query index, so index_name resolves.
        #
        # capella_query_index_manage takes ONE statement -- the tool's own schema
        # says multiple delimited queries are rejected -- and a deferred build,
        # because building on a 63k-document bucket during a fixture run is time
        # nobody asked for. capella_query_index_build_status then has something
        # real to report, which is the point.
        # ONE INDEX PER COLLECTION, and that is not belt-and-braces.
        #
        # Every /queryService/ read takes bucket+scope+collection as REQUIRED
        # query parameters, and answers 404 "Index not found in key space" for a
        # keyspace that holds no index. The surface harness resolves `collection`
        # from whichever entry the scope listing hands back first, which on
        # 2026-09-13 was `meta` while the only index sat on `events`. Result: a
        # correct tool, a correct spec and a 404, reported as an UPSTREAM defect.
        #
        # Indexing both collections removes the ordering dependency instead of
        # teaching the harness to prefer one, which would only move the guess.
        index_names = []
        for collection in ("events", "meta"):
            index_name = f"{PREFIX}_idx_{collection}"
            index_names.append(index_name)
            await self.create(
                session,
                "capella_query_index_manage",
                {
                    **ids,
                    "body": {
                        "definition": (
                            f"CREATE INDEX `{index_name}` ON "
                            f"`{self.args.bucket}`.`{PREFIX}`.`{collection}`(`id`) "
                            'WITH {"defer_build": true}'
                        ),
                    },
                },
                f"query index {index_name}",
            )

        # 8. An audit-log export, so export_id resolves.
        #
        # The window is in the PAST and one hour wide. An export of a future
        # window is rejected, and a wide one is a large job on somebody's cluster
        # for no benefit -- this exists so an id exists.
        from datetime import datetime, timedelta, timezone

        end = datetime.now(timezone.utc).replace(microsecond=0)
        start = end - timedelta(hours=1)
        await self.create(
            session,
            "capella_cluster_audit_log_export_create",
            {
                **ids,
                "body": {
                    "start": start.isoformat().replace("+00:00", "Z"),
                    "end": end.isoformat().replace("+00:00", "Z"),
                },
            },
            "audit log export",
        )

        # 9. Alert integration, only with a real endpoint. See the module docstring.
        if self.args.webhook_url:
            await self.create(
                session,
                "capella_alert_integration_create",
                {
                    **ids,
                    "body": {
                        "name": f"{PREFIX}-alerts",
                        "kind": "webhook",
                        "config": {
                            "webhook": {
                                "url": self.args.webhook_url,
                                # REQUIRED, and omitting it cost a run. _ALERT_WEBHOOK in
                                # handlers/capella/spec.py declares required ["url",
                                # "method"]; this body sent only the url and the SDK
                                # refused the call before dispatch with
                                #   Input validation error: 'method' is a required property
                                # The schema was right. The caller was wrong.
                                "method": "POST",
                                "token": self.args.webhook_token or "mcptest",
                            }
                        },
                    },
                },
                f"alert integration {PREFIX}-alerts",
            )
        else:
            self.say(
                "\n   no --webhook-url — skipping capella_alert_integration_create."
            )
            self.say("   Capella sends a REAL request on create and fails the create")
            self.say(
                "   unless it answers 2xx over https, so there is no safe default."
            )

        # 10. An on/off schedule, so capella_cluster_onoff_schedule_get has
        #     something to return instead of 404 code 11040.
        #
        # THE SHAPE BELOW IS THE ONE CAPELLA ACCEPTED (204), and it is not the
        # one this script sent for three runs. The measured rules, each from its
        # own 422 in scripts/probe_onoff_schedule.py:
        #
        #   * seven days, always (422 code 11042)
        #   * IANA timezone (422 code 11041 for 'ET')
        #   * 'on' and 'off' are whole-day states and must carry NO boundary
        #   * 'custom' is the only state that may carry one, and must
        #   * minute is 0 or 30; hour is 0-23; from/to are objects
        #
        # OFF BY DEFAULT SINCE 2026-09-14, AND THE REASON IS NOT TIDINESS.
        #
        # 00:00-23:30 is the widest window the rules allow, so any schedule this
        # script can create leaves the cluster OFF for thirty minutes a night.
        # That stopped being theoretical within the hour: the fixture cluster
        # powered down, and every write to it -- including enabling the Data API
        # -- was refused with
        #
        #   422 "Temporarily unavailable while the Cluster is in the Turning On
        #        state."
        #
        # which names the cluster's state and not the caller's mistake. Someone
        # debugging that at 2am reads it as a broken tool.
        #
        # The seven whole-day "on" shape, chosen precisely because it could never
        # hibernate anything, breaks no stated rule and answers 500 code 10000
        # every time. So a fixture cannot have both "the resource exists" and
        # "nothing ever turns off", and the default now favours the cluster
        # staying up. Pass --with-onoff-schedule when the point of the run IS to
        # exercise the schedule tools.
        _WEEK = (
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        )

        # WHICH VERB DEPENDS ON WHETHER ONE IS ALREADY THERE. POST creates and
        # refuses a duplicate with 422 code 11050; PUT updates and refuses a
        # missing one with 404 code 11040. Reading the schedule first turns a
        # guess into a lookup, and costs one GET.
        if not getattr(self.args, "with_onoff_schedule", False):
            self.say(
                "\n   skipping the on/off schedule: it powers the cluster "
                "down for 30 minutes a night, which refuses every write "
                "with 422 'Turning On' while it cycles. Pass "
                "--with-onoff-schedule to create one."
            )
            return

        existing = await self.call(
            session, "capella_cluster_onoff_schedule_get", dict(ids)
        )
        tool = (
            "capella_cluster_onoff_schedule_update"
            if not existing.get(ERROR_MARKER)
            else "capella_cluster_onoff_schedule_set"
        )
        await self.create(
            session,
            tool,
            {
                **ids,
                "body": {
                    "timezone": "America/New_York",
                    "days": [
                        {
                            "day": day,
                            "state": "custom",
                            "from": {"hour": 0, "minute": 0},
                            "to": {"hour": 23, "minute": 30},
                        }
                        for day in _WEEK
                    ],
                },
            },
            "on/off schedule (custom days, 00:00-23:30)",
        )

        # 11. An access control function on the App Endpoint, so
        #     capella_app_endpoint_access_control_function_get stops answering
        #     404 because none is configured.
        #
        #     The function channels each document by its own id and authorises
        #     nothing further. Deliberately NOT a permissive one: a fixture that
        #     grants blanket write access is a bad thing to leave behind in a
        #     cluster somebody later reuses for something real.
        app_services = _rows(
            await self.call(session, "capella_app_services_list", dict(ids))
        )
        if app_services:
            # 12. An App Service admin user, so capella_app_service_admin_user_delete
            #     and capella_app_service_admin_users_list have a real subject.
            #
            #     `access` is REQUIRED and is a oneOf: EXACTLY ONE of
            #     accessAllEndpoints or endpoints. Neither, or both, is 422
            #     "contains or lacks both". Scoped to the one endpoint rather
            #     than all of them -- a fixture credential with blanket access
            #     is a bad thing to leave behind.
            asid = str(app_services[0].get("id"))
            if not await self._already(
                session,
                "capella_app_service_admin_users_list",
                {**ids, "app_service_id": asid},
                "name",
                f"{PREFIX}-admin",
                f"app service admin user {PREFIX}-admin",
            ):
                endpoint_rows = _rows(
                    await self.call(
                        session,
                        "capella_app_endpoints_list",
                        {**ids, "app_service_id": asid},
                    )
                )
                endpoint_names = [
                    str(r.get("name"))
                    for r in endpoint_rows
                    if isinstance(r, dict) and r.get("name")
                ]
                await self.create(
                    session,
                    "capella_app_service_admin_user_create",
                    {
                        **ids,
                        "app_service_id": asid,
                        "body": {
                            "name": f"{PREFIX}-admin",
                            "password": "mcptest-Passw0rd!",
                            "access": (
                                {"endpoints": endpoint_names}
                                if endpoint_names
                                else {"accessAllEndpoints": True}
                            ),
                        },
                    },
                    f"app service admin user {PREFIX}-admin",
                )

        if not app_services:
            self.say(
                "\n   no App Service on this cluster — skipping the access "
                "control function."
            )
            return
        app_service_id = str(app_services[0].get("id"))
        endpoints = _rows(
            await self.call(
                session,
                "capella_app_endpoints_list",
                {**ids, "app_service_id": app_service_id},
            )
        )
        if not endpoints:
            self.say(
                "\n   the App Service has no App Endpoint — skipping the "
                "access control function."
            )
            return
        # KEYSPACE = <endpoint>.<scope>.<collection>. The endpoint NAME alone
        # earns 404 "App Endpoint keyspace <name> not found", measured
        # 2026-09-14 -- the access control function is per collection, and the
        # endpoint document shows it: scopes.<scope>.collections.<collection>.
        endpoint = endpoints[0]
        keyspace = ""
        existing_function = ""
        scopes = endpoint.get("scopes")
        if isinstance(scopes, dict):
            for scope_name, scope in scopes.items():
                collections = (scope or {}).get("collections")
                if isinstance(collections, dict) and collections:
                    collection_name, collection = next(iter(collections.items()))
                    keyspace = f"{endpoint.get('name')}.{scope_name}.{collection_name}"
                    # THE FUNCTION LIVES IN THE ENDPOINT DOCUMENT, not in the
                    # response of its own getter.
                    #
                    # capella_app_endpoint_access_control_function_get answers
                    # 200 with an EMPTY BODY (measured 2026-09-14) while
                    # capella_app_endpoint_get carries the source right here, at
                    # scopes.<scope>.collections.<collection>.
                    # accessControlFunction. So read it from the document that
                    # has it; a 200 with nothing in it is not a source of truth.
                    if isinstance(collection, dict):
                        existing_function = str(
                            collection.get("accessControlFunction") or ""
                        )
                    break
        if not keyspace:
            self.say(
                "\n   the App Endpoint names no scope/collection — skipping "
                "the access control function. A two-part keyspace is not a "
                "keyspace and the 404 it earns teaches nothing."
            )
            return
        # THE BODY IS A BARE STRING, AND THAT WAS THE WHOLE BUG.
        #
        # Three inputs were refused with the identical 400 "invalid javascript
        # syntax: JavaScript source does not evaluate to a function": a plain
        # `function (doc, oldDoc, meta) {...}` declaration, the same source
        # wrapped in parentheses, and -- decisively -- the function Capella
        # itself had stored, read out of the endpoint document and sent back
        # verbatim. A real syntax validator would have accepted the server's own
        # function. One identical error from three valid inputs means the source
        # never reached the validator at all.
        #
        # The cause was the envelope: the op wrapped the source in
        # {"function": "<source>"}. App Services wants the source as a BARE JSON
        # STRING, the same shape capella_eventing_function_code_set takes. The
        # op now carries body_scalar; this call passes the string itself.
        #
        # The round-trip is still preferred when the endpoint already has a
        # function -- it proves the PUT path, the keyspace and the body shape
        # without depending on any syntax claim of mine. Only when there is
        # nothing to read back do we write a minimal channel-assignment
        # function of our own.
        source = existing_function or _DEFAULT_ACCESS_CONTROL_FUNCTION
        label = "round-tripped" if existing_function else "seeded"
        await self.create(
            session,
            "capella_app_endpoint_access_control_function_set",
            {
                **ids,
                "app_service_id": app_service_id,
                "app_endpoint_keyspace": keyspace,
                "body": source,
            },
            f"access control function {label} on {keyspace}",
        )

    async def _already(
        self, session, list_tool: str, args: dict, field: str, value: str, label: str
    ) -> bool:
        """Is `value` already present, by `field`, in `list_tool`'s rows?

        THE DOCSTRING PROMISED THIS AND THE CODE DID NOT DO IT. Only the scope
        was checked; everything else was created unconditionally, so a second
        run answered 409 on objects that already existed and reported it as a
        FAILED CHECK. A script whose re-run reports failures nobody caused
        teaches people to ignore its output, which is the opposite of the point.

        A list call that errors returns False — better to attempt the create and
        get a real 409 than to skip a step because a read failed.
        """
        body = await self.call(session, list_tool, args)
        if body.get(ERROR_MARKER) is True:
            return False
        for row in _rows(body):
            if isinstance(row, dict) and str(row.get(field, "")) == value:
                self.say(f"   {label} is already present")
                self.present.append(label)
                return True
        return False

    async def _holds_real_work(self, session, ids: dict, cluster: dict) -> bool:
        """Does this cluster carry a bucket from the do-not-touch set?

        Asked of the LIVE bucket list, same as the startup check. A cluster is
        not a throwaway because of its name.
        """
        buckets = _rows(
            await self.call(
                session,
                "capella_buckets_list",
                {
                    **{k: ids[k] for k in ("organization_id", "project_id")},
                    "cluster_id": cluster.get("id"),
                },
            )
        )
        names = {b.get("name") for b in buckets if isinstance(b, dict)}
        return bool(REAL_WORK & names)

    async def scope(self, session):
        body = await self.call(session, "capella_organizations_list", {})
        orgs = _rows(body)
        if not self.check(bool(orgs), "an organization is visible"):
            return None
        org = self.args.org or orgs[0].get("id")

        body = await self.call(
            session, "capella_projects_list", {"organization_id": org}
        )
        projects = _rows(body)
        if not self.check(bool(projects), "a project is visible"):
            return None
        project = self.args.project or projects[0].get("id")

        scope = {"organization_id": org, "project_id": project}
        rows = [
            c
            for c in _rows(
                await self.call(session, "capella_clusters_list", dict(scope))
            )
            if isinstance(c, dict)
        ]

        picked = [c for c in rows if _matches(c, self.args.cluster)]
        if not self.check(
            len(picked) == 1,
            f"--cluster {self.args.cluster!r} names exactly one cluster",
            f"matched {len(picked)} of {len(rows)}",
        ):
            return None
        cluster = picked[0]
        others = [c for c in rows if c.get("id") != cluster.get("id")]
        ids = {**scope, "cluster_id": cluster.get("id")}

        buckets = [
            b
            for b in _rows(await self.call(session, "capella_buckets_list", dict(ids)))
            if isinstance(b, dict)
        ]
        names = {b.get("name"): b.get("id") for b in buckets}

        # The safety check, made against the LIVE bucket list. A cluster is a
        # throwaway because of what is on it, not because of what it is called.
        found_real = REAL_WORK & set(names)
        if found_real and not self.args.override:
            self.check(
                False,
                f"{cluster.get('name')!r} is a throwaway cluster",
                f"it holds {', '.join(sorted(found_real))}, which is real "
                "work. This script CREATES objects; pass "
                "--i-know-what-im-doing only if that is genuinely intended.",
            )
            return None
        self.check(
            True,
            f"{cluster.get('name')!r} holds no real work",
            f"buckets: {sorted(names)}",
        )

        if not self.check(
            self.args.bucket in names,
            f"bucket {self.args.bucket!r} exists",
            f"available: {sorted(names)}",
        ):
            return None
        return ids, names[self.args.bucket], (others[0] if len(others) == 1 else None)


async def main_async(args) -> int:
    try:
        from mcp import ClientSession, StdioServerParameters, stdio_client
    except ImportError:
        print("the `mcp` package is not importable. Run with `uv run python`.")
        return 1

    if not os.environ.get("CAPELLA_API_KEY_SECRET"):
        print("CAPELLA_API_KEY_SECRET is not set. Run cbenv.bat, then a NEW window.")
        return 1

    run = Populate(args)
    params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(REPO_ROOT, "server.py")],
        env=_client_env(dry_run=args.dry_run),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=args.timeout)
            await run.run(session)

    print()
    if run.created:
        print(f"created {len(run.created)}:")
        for item in run.created:
            print(f"  + {item}")
    if run.present:
        print(f"already present {len(run.present)}:")
        for item in run.present:
            print(f"  = {item}")
    if run.failures:
        print(f"\n{len(run.failures)} check(s) failed:")
        for failure in run.failures:
            print(f"  * {failure}")
        return 1
    print("\nevery check passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cluster",
        required=True,
        help="the cluster to populate, by id, name, or a fragment "
        "of its connection string. WRITTEN TO.",
    )
    parser.add_argument("--bucket", default="travel-sample")
    parser.add_argument(
        "--webhook-url",
        default="",
        help="https endpoint for an alert integration. Capella "
        "calls it on create and fails unless it answers 2xx.",
    )
    parser.add_argument("--webhook-token", default="")
    parser.add_argument(
        "--with-onoff-schedule",
        action="store_true",
        help="create an on/off schedule. OFF by default: the "
        "widest legal window still powers the cluster down "
        "for 30 minutes a night, and every write during the "
        "cycle is refused with a 422 about cluster state.",
    )
    parser.add_argument("--perform", dest="dry_run", action="store_false", default=True)
    parser.add_argument("--org", default=None)
    parser.add_argument("--project", default=None)
    parser.add_argument(
        "--i-know-what-im-doing",
        dest="override",
        action="store_true",
        help="permit a cluster that holds real work",
    )
    parser.add_argument("--timeout", type=float, default=180.0)
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
