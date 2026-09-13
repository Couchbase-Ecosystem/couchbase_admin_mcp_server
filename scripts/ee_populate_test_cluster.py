"""Create, through the MCP tools themselves, the objects the EE surface needs.

THE SAME ARGUMENT AS THE CAPELLA SCRIPT, ON THE OTHER SURFACE
=============================================================
`scripts/verify_mcp_surface.py --write-preview` reports three kinds of SKIPPED,
and only two of them are the harness's fault:

    "no value for X"                    an id nothing looked for  -> discovery
    "no request body could be built"    a limit of the checker    -> the checker
    "no <id> exists on this cluster"    a fact about the world    -> CREATE IT

This script is the third one for the self-managed side. Every object below is
created by one of this server's own write tools, which means the setup is itself
a test: each create exercises a write tool with a REAL body against a real
cluster, which is strictly more than the preview phase can prove. A tool that
builds the fixture for another tool has verified itself on the way past.

WHAT IT CREATES, AND WHAT THAT UNBLOCKS
---------------------------------------
    scope mcptest              admin_scope_create        -> scope_name
    collections events, meta   admin_collection_create   -> collection_name
    user   mcptest-user        admin_user_create         -> username  (6 tools)
    group  mcptest-group       admin_group_create        -> group_name (2 tools)
    FTS index mcptest-fts      admin_fts_index_create    -> index_name (6 tools)
    eventing fn mcptest-fn     admin_eventing_create_or_update -> function_name (7)
    backup repository          admin_backup_repository_create  -> repository_id (4)

Two collections rather than one is not padding: an Eventing function's metadata
keyspace MUST differ from its source keyspace, and pointing both at the same
collection is rejected.

THE BACKUP REPOSITORY IS THE INTERESTING ONE
--------------------------------------------
It needs `archive`, a path AS THE BACKUP SERVICE SEES IT. In a container that is
a path inside the container, not on this machine, and it must exist and be
writable by the service. Create it first:

    docker exec cb-mcp-ee mkdir -p /opt/couchbase/var/lib/couchbase/backup-archive

A repository is also what makes admin_backup_run and admin_backup_restore_run
addressable. Those were already PERFORMED against a live Backup service on
2026-09-12 -- this does not re-prove them, it makes the container fixture
complete so the whole family is reachable from one reproducible setup.

SAFETY
======
It refuses any cluster holding a bucket outside the throwaway set, read from the
LIVE bucket list rather than trusted from a flag. This script CREATES things,
including a USER -- and a user created on the wrong cluster is a security
problem, not an untidy one.

USAGE
-----
    uv run python scripts/ee_populate_test_cluster.py
    uv run python scripts/ee_populate_test_cluster.py --perform

Dry run is the default. Every step is idempotent: an object that already exists
is reported as present and not re-created.
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

PREFIX = "mcptest"

#: Buckets that mark a cluster as safe to create things on. Anything else and
#: this is somebody's real cluster.
THROWAWAY_BUCKETS = {"travel-sample", "beer-sample", "gamesim-sample"}

#: Least privilege that still makes the user a usable fixture. NOT an admin
#: role: nothing here needs one, and a test script that mints cluster admins is
#: a habit worth not forming.
USER_ROLES = "data_reader[*]"
GROUP_ROLES = "data_reader[*]"


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
    # A Capella key alongside a connection string resolves the deployment to
    # 'both', which switches capability gating off. This script is self-managed
    # only; drop the key so the server cannot land in that posture because of
    # what happens to be in the shell.
    env.pop("CAPELLA_API_KEY_SECRET", None)
    env.pop("CAPELLA_ACCESS_KEY_ID", None)
    return env


def _payload(response: Any) -> Any:
    for block in getattr(response, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"_raw": text}
    return {}


def _rows(body: Any) -> list:
    """Rows out of a response, INCLUDING the two shapes that are not lists.

    The "is it already there?" checks all walk a list of dicts and compare one
    field. Two self-managed reads do not hand back that shape, so both checks
    answered "not present" about objects that were plainly present, and the
    create that followed hit the server's own duplicate error:

        admin_fts_index_list -> {"indexDefs": {"indexDefs": {"<name>": {...}}}}
            a MAP keyed by index name, nested one level deep, no list anywhere
        admin_eventing_list  -> {"functions": ["<name>"]}
            a list of STRINGS, so row.get("appname") never ran

    Measured 2026-09-13: the FTS create then failed with HTTP 400 "an index
    with the same name already exists" on a cluster whose index list, printed
    two lines earlier in the same transcript, contained that index. Same defect
    class as verify_mcp_surface.py's _ROWS_READER, and the same remedy.
    """
    if isinstance(body, list):
        return [{"name": r, "appname": r, "id": r} if isinstance(r, str) else r
                for r in body]
    if not isinstance(body, dict):
        return []

    # FTS: a map keyed by index name, nested under indexDefs.indexDefs.
    defs = body.get("indexDefs")
    if isinstance(defs, dict):
        inner = defs.get("indexDefs")
        if isinstance(inner, dict):
            return [{"name": name, **(d if isinstance(d, dict) else {})}
                    for name, d in inner.items()]

    for key in ("data", "items", "buckets", "users", "groups", "indexes",
                "repositories", "functions", "scopes"):
        value = body.get(key)
        if isinstance(value, list):
            # Eventing hands back bare names; give every caller a dict so a
            # .get() on a row can never silently miss.
            return [{"name": r, "appname": r, "id": r} if isinstance(r, str) else r
                    for r in value]
    lists = [v for v in body.values() if isinstance(v, list)]
    if len(lists) != 1:
        return []
    return [{"name": r, "appname": r, "id": r} if isinstance(r, str) else r
            for r in lists[0]]


def _is_already_exists(result: Any) -> bool:
    """Does this error say the object is already there?

    Message, not status. The duplicate answers observed on this surface are
    HTTP 400 (FTS: "an index with the same name already exists") and HTTP 409
    (Capella eventing: "already exists") — and a bare 409 also means the
    cluster is deploying, scaling or rebalancing, which is a real failure.
    """
    if not isinstance(result, dict):
        return False
    text = f"{result.get('error', '')} {result.get('message', '')}".lower()
    return "already exists" in text or "duplicate" in text


def _fts_definition(name: str, bucket: str) -> dict:
    """A minimal, dynamic full-text index over one bucket's default scope.

    Dynamic mapping on purpose: this fixture exists so index_name resolves, and
    a hand-written field mapping would be one more thing to keep true as the
    sample data changes.
    """
    return {
        "type": "fulltext-index",
        "name": name,
        "sourceType": "gocbcore",
        "sourceName": bucket,
        "planParams": {"maxPartitionsPerPIndex": 1024, "indexPartitions": 1},
        "params": {
            "doc_config": {"mode": "type_field", "type_field": "type"},
            "mapping": {
                "default_analyzer": "standard",
                "default_datetime_parser": "dateTimeOptional",
                "default_field": "_all",
                "default_mapping": {"dynamic": True, "enabled": True},
                "default_type": "_default",
                "index_dynamic": True,
                "store_dynamic": False,
            },
            "store": {"indexType": "scorch"},
        },
    }


def _eventing_definition(name: str, bucket: str) -> dict:
    """appname / appcode / depcfg, the three keys the tool documents as required.

    source and metadata keyspaces MUST differ -- hence two collections. The
    handler is deliberately inert: it logs. A fixture function that mutated data
    would make every other tool's reading of this cluster depend on it.
    """
    return {
        "appname": name,
        "appcode": "function OnUpdate(doc, meta) { log('mcptest', meta.id); }",
        "depcfg": {
            "source_bucket": bucket,
            "source_scope": PREFIX,
            "source_collection": "events",
            "metadata_bucket": bucket,
            "metadata_scope": PREFIX,
            "metadata_collection": "meta",
            "buckets": [],
        },
    }


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

    async def call(self, session, tool: str, arguments: dict) -> Any:
        self.say(f"\n-> {tool}")
        for key, value in arguments.items():
            rendered = repr(value)
            if len(rendered) > 240:
                rendered = rendered[:240] + " ..."
            self.say(f"     {key} = {rendered}")
        response = await asyncio.wait_for(
            session.call_tool(tool, arguments), timeout=self.args.timeout
        )
        body = _payload(response)
        rendered = json.dumps(body, indent=2) if not isinstance(body, str) else body
        if len(rendered) > 600:
            rendered = rendered[:600] + "\n     ..."
        self.say(f"   <- {rendered}")
        return body

    async def create(self, session, tool: str, arguments: dict, label: str) -> Any:
        """One create, gate first.

        The unconfirmed call is not ceremony: a write that proceeds without
        `confirm: true` means the gate is not in the dispatch path FOR THAT TOOL,
        and the only way to learn that is to try it on each one.
        """
        unconfirmed = await self.call(session, tool, arguments)
        gated = isinstance(unconfirmed, dict) and (
            unconfirmed.get("requires_confirmation") is True
            or unconfirmed.get(ERROR_MARKER) is True
        )
        self.check(gated, f"{tool} without confirm is refused")

        result = await self.call(session, tool, {**arguments, "confirm": True})

        if not self.performed:
            ok = isinstance(result, dict) and result.get("dry_run") is True
            self.check(ok, f"{tool} is previewed, not executed")
            return result

        if isinstance(result, dict) and result.get(ERROR_MARKER) is True:
            # Already-there is the desired end state, not a failure — and the
            # status code does not say which it is. ns_server answers 400 for a
            # duplicate FTS index, Capella answers 409 for a duplicate eventing
            # function, and 409 ALSO means "cluster is mid-operation", where the
            # write really did not happen. So match the message, never the code,
            # and let every other error fail loudly.
            if _is_already_exists(result):
                self.say(f"   {label} is already present "
                         "(the server refused the duplicate)")
                self.present.append(label)
                return result
            self.check(False, f"{label} created", json.dumps(result)[:400])
            return result
        self.check(True, f"{label} created")
        self.created.append(label)
        return result

    async def _already(self, session, tool: str, args: dict,
                       field: str, value: str, label: str) -> bool:
        body = await self.call(session, tool, args)
        if isinstance(body, dict) and body.get(ERROR_MARKER) is True:
            return False
        for row in _rows(body):
            if isinstance(row, dict) and str(row.get(field, "")) == value:
                self.say(f"   {label} is already present")
                self.present.append(label)
                return True
        return False

    # ── the run ──────────────────────────────────────────────────────────────

    async def run(self, session) -> None:
        self.say("=" * 70)
        self.say("populate a self-managed test cluster, through the tools themselves")
        self.say(f"mode   {'PERFORM (real writes)' if self.performed else 'DRY RUN (preview)'}")
        self.say("=" * 70)

        buckets = _rows(await self.call(session, "admin_bucket_list", {}))
        names = {b.get("name") for b in buckets if isinstance(b, dict)}
        if not self.check(bool(names), "the cluster has at least one bucket",
                          "create one first; every keyspace tool needs it"):
            return
        stranger = {n for n in names
                    if n not in THROWAWAY_BUCKETS and not str(n).startswith(PREFIX)}
        if stranger and not self.args.override:
            self.check(False, "this is a throwaway cluster",
                       f"it holds {', '.join(sorted(stranger))}, which is not a sample "
                       "bucket. This script CREATES objects including a USER; pass "
                       "--i-know-what-im-doing only if that is genuinely intended.")
            return
        self.check(True, "this is a throwaway cluster", f"buckets: {sorted(names)}")

        bucket = self.args.bucket if self.args.bucket in names else sorted(names)[0]
        self.say(f"\n   working in {bucket!r}")

        # 1. scope + two collections.
        scopes = _rows(await self.call(session, "admin_scope_list",
                                       {"bucket_name": bucket}))
        have_scope = any(isinstance(s, dict) and s.get("name") == PREFIX
                         for s in scopes)
        if have_scope:
            self.say(f"   scope {PREFIX!r} is already present")
            self.present.append(f"scope {PREFIX}")
        else:
            await self.create(session, "admin_scope_create",
                              {"bucket_name": bucket, "scope_name": PREFIX},
                              f"scope {PREFIX}")

        existing_collections: set[str] = set()
        for row in _rows(await self.call(session, "admin_scope_list",
                                         {"bucket_name": bucket})):
            if isinstance(row, dict) and row.get("name") == PREFIX:
                existing_collections = {
                    c.get("name") for c in (row.get("collections") or [])
                    if isinstance(c, dict)
                }
        for collection in ("events", "meta"):
            if collection in existing_collections:
                self.say(f"   collection {PREFIX}.{collection} is already present")
                self.present.append(f"collection {PREFIX}.{collection}")
                continue
            await self.create(
                session, "admin_collection_create",
                {"bucket_name": bucket, "scope_name": PREFIX,
                 "collection_name": collection},
                f"collection {PREFIX}.{collection}",
            )

        # 2. A group first, then a user -- a user can reference a group only if
        #    the group exists, and doing it the other way round would work here
        #    but teaches the wrong order.
        if not await self._already(session, "admin_group_list", {}, "id",
                                   f"{PREFIX}-group", f"group {PREFIX}-group"):
            await self.create(
                session, "admin_group_create",
                {"group_name": f"{PREFIX}-group", "roles": GROUP_ROLES,
                 "description": "mcptest fixture"},
                f"group {PREFIX}-group",
            )

        if not await self._already(session, "admin_user_list", {}, "id",
                                   f"{PREFIX}-user", f"user {PREFIX}-user"):
            await self.create(
                session, "admin_user_create",
                {"username": f"{PREFIX}-user",
                 "password": self.args.user_password,
                 "name": "mcptest fixture",
                 "roles": USER_ROLES},
                f"user {PREFIX}-user",
            )

        # 3. FTS index.
        if not await self._already(session, "admin_fts_index_list", {}, "name",
                                   f"{PREFIX}-fts", f"FTS index {PREFIX}-fts"):
            await self.create(
                session, "admin_fts_index_create",
                {"index_name": f"{PREFIX}-fts",
                 "definition": _fts_definition(f"{PREFIX}-fts", bucket)},
                f"FTS index {PREFIX}-fts",
            )

        # 4. Eventing function.
        if not await self._already(session, "admin_eventing_list", {}, "appname",
                                   f"{PREFIX}-fn", f"eventing function {PREFIX}-fn"):
            await self.create(
                session, "admin_eventing_create_or_update",
                {"function_name": f"{PREFIX}-fn",
                 "definition": _eventing_definition(f"{PREFIX}-fn", bucket)},
                f"eventing function {PREFIX}-fn",
            )

        # 5. Backup repository. Needs a PLAN that exists and an ARCHIVE the
        #    service can write, so both are read or stated rather than assumed.
        plans_body = await self.call(session, "admin_backup_plans_list", {})
        plans = _rows(plans_body)
        plan_names = [p.get("name") for p in plans if isinstance(p, dict)]
        if not plan_names:
            self.say("\n   no backup plans are listable — skipping the repository.")
            # Print what the server ACTUALLY said. "If this is a 404" was a
            # guess printed as guidance: on 2026-09-13 the answer was a 500
            # from a Backup service still starting after a container restart,
            # and the note sent the reader looking for a missing service.
            self.say(f"   the read answered: {json.dumps(plans_body)[:300]}")
            self.say("   404 'Service backup not running' -> the service is absent;")
            self.say("   500 -> it is present but not ready, wait and re-run;")
            self.say("   check /pools/default/nodeServices for backupAPI before")
            self.say("   suspecting admin_backup_*. See CLAUDE.md.")
        else:
            plan = self.args.plan if self.args.plan in plan_names else plan_names[0]
            self.say(f"\n   using plan {plan!r} of {plan_names}")
            if not await self._already(session, "admin_backup_repository_list", {},
                                       "id", f"{PREFIX}-repo",
                                       f"backup repository {PREFIX}-repo"):
                await self.create(
                    session, "admin_backup_repository_create",
                    {"repository_id": f"{PREFIX}-repo",
                     "plan": plan,
                     "archive": self.args.archive,
                     "bucket_name": bucket},
                    f"backup repository {PREFIX}-repo",
                )


async def main_async(args) -> int:
    try:
        from mcp import ClientSession, StdioServerParameters, stdio_client
    except ImportError:
        print("the `mcp` package is not importable. Run with `uv run python`.")
        return 1

    if not os.environ.get("CB_CONNECTION_STRING"):
        print("CB_CONNECTION_STRING is not set — there is no cluster to populate.")
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
    parser.add_argument("--bucket", default="travel-sample")
    parser.add_argument("--user-password", default="mcptest-Passw0rd!",
                        help="Password for the fixture user. It is a FIXTURE "
                             "credential on a throwaway cluster; do not reuse it.")
    parser.add_argument("--plan", default="_daily_backups",
                        help="Backup plan name. Falls back to the first plan the "
                             "service lists, so a wrong name is not fatal.")
    parser.add_argument("--archive", default="/opt/couchbase/var/lib/couchbase/backup-archive",
                        help="Archive path AS THE BACKUP SERVICE SEES IT — inside "
                             "the container, not on this machine. Must exist: "
                             "docker exec <container> mkdir -p <path>")
    parser.add_argument("--perform", dest="dry_run", action="store_false",
                        default=True)
    parser.add_argument("--i-know-what-im-doing", dest="override",
                        action="store_true",
                        help="permit a cluster holding non-sample buckets")
    parser.add_argument("--timeout", type=float, default=120.0)
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
