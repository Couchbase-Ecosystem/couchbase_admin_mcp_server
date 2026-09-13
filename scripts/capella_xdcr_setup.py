"""Create a ONE-WAY XDCR replication between two Capella clusters, by name.

WHY A SEPARATE SCRIPT
=====================
Direction is the whole safety property of a replication, and it is not something
to infer. `capella_populate_test_cluster.py` builds fixtures on ONE cluster and
would naturally replicate outward from it; that is the wrong way round when the
far end is the cluster holding real work. So the direction is spelled out here
as two required arguments, and the guard is applied to the end being WRITTEN:

    --from   the SOURCE. Read. May be a cluster holding real work.
    --to     the TARGET. WRITTEN BY REPLICATION, continuously. Guarded.

A replication is not a one-off write. Once it exists, every mutation on the
source keeps arriving at the target for as long as it runs, which makes a
wrong-way replication worse than a wrong-way restore: the restore finishes.

ONE-WAY ONLY, DELIBERATELY
--------------------------
`direction` is fixed to 'oneWay' and there is no flag to change it. A two-way
replication makes the target a source, so the guard above stops meaning
anything — the protected cluster would be written by the very replication whose
target was checked and found safe. If a two-way replication is genuinely wanted,
create it from the Capella UI where the consequence is visible, not from a
script whose name says setup.

This was not hypothetical. A two-way replication was running earlier in this
cluster pair and had already moved ~31,592 documents before anyone looked.

WHAT IT PROVES
--------------
`capella_replication_create` has never been called with a real body. The
registry carries it as a path confirmed by an OPTIONS probe; the `target` object
(`bucket`, `cluster`, `type`) is the reference's shape, not an observation. This
is the call that settles it, and it gives capella_replication_get,
capella_replications_list and capella_replication_delete an id to address.

USAGE
-----
    uv run python scripts/capella_xdcr_setup.py --from Bride --to vn1kiibitcyvwrw
    uv run python scripts/capella_xdcr_setup.py --from Bride --to vn1kiibitcyvwrw --perform

Dry run is the default.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import sys
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ERROR_MARKER = "_is_error"

#: Buckets whose presence means a cluster must not be a replication TARGET.
REAL_WORK = {"harvester", "supportal"}


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


def _rows(body: dict) -> list:
    if "_list" in body:
        return body["_list"]
    for key in ("data", "items", "clusters", "projects", "buckets", "replications"):
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
    return any(needle in str(cluster.get(k, "")).lower()
               for k in ("id", "name", "connectionString"))


class Xdcr:
    def __init__(self, args) -> None:
        self.args = args
        self.failures: list[str] = []
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
            self.say(f"     {key} = {value!r}")
        response = await asyncio.wait_for(
            session.call_tool(tool, arguments), timeout=self.args.timeout
        )
        body = _payload(response)
        rendered = json.dumps(body, indent=2)
        if len(rendered) > 800:
            rendered = rendered[:800] + "\n     ..."
        self.say(f"   <- {rendered}")
        return body

    async def _buckets(self, session, scope: dict, cluster: dict) -> dict:
        rows = _rows(await self.call(
            session, "capella_buckets_list",
            {**scope, "cluster_id": cluster.get("id")}))
        return {b.get("name"): b.get("id") for b in rows if isinstance(b, dict)}

    async def run(self, session) -> None:
        self.say("=" * 70)
        self.say("capella XDCR — one-way replication")
        self.say(f"mode   {'PERFORM (real write)' if self.performed else 'DRY RUN (preview)'}")
        self.say("=" * 70)

        body = await self.call(session, "capella_organizations_list", {})
        orgs = _rows(body)
        if not self.check(bool(orgs), "an organization is visible"):
            return
        org = self.args.org or orgs[0].get("id")

        projects = _rows(await self.call(session, "capella_projects_list",
                                         {"organization_id": org}))
        if not self.check(bool(projects), "a project is visible"):
            return
        scope = {"organization_id": org,
                 "project_id": self.args.project or projects[0].get("id")}

        rows = [c for c in _rows(await self.call(
            session, "capella_clusters_list", dict(scope))) if isinstance(c, dict)]

        pair = {}
        for role, needle in (("source", getattr(self.args, "from")),
                             ("target", self.args.to)):
            picked = [c for c in rows if _matches(c, needle)]
            if not self.check(len(picked) == 1,
                              f"--{'from' if role == 'source' else 'to'} {needle!r} "
                              "names exactly one cluster",
                              f"matched {len(picked)} of {len(rows)}"):
                return
            pair[role] = picked[0]

        source, target = pair["source"], pair["target"]
        if not self.check(source.get("id") != target.get("id"),
                          "source and target are different clusters"):
            return

        self.say(f"\n   FROM  {source.get('name')!r}  {source.get('id')}"
                 "   <- read")
        self.say(f"   INTO  {target.get('name')!r}  {target.get('id')}"
                 "   <- WRITTEN, continuously, for as long as this runs")

        # The guard, on the end being written, read off the LIVE bucket list.
        target_buckets = await self._buckets(session, scope, target)
        found = REAL_WORK & set(target_buckets)
        if found and not self.args.override:
            self.check(False, f"{target.get('name')!r} is safe as a replication TARGET",
                       f"it holds {', '.join(sorted(found))}. A replication writes "
                       "to its target continuously; pass --i-know-what-im-doing "
                       "only if that is genuinely intended.")
            return
        self.check(True, f"{target.get('name')!r} is safe as a replication TARGET",
                   f"buckets: {sorted(target_buckets)}")

        source_buckets = await self._buckets(session, scope, source)
        name = self.args.bucket
        if not self.check(name in source_buckets, f"source holds {name!r}",
                          f"available: {sorted(source_buckets)}"):
            return
        if not self.check(name in target_buckets, f"target holds {name!r}",
                          f"available: {sorted(target_buckets)}. XDCR replicates "
                          "INTO an existing bucket; create it first."):
            return

        # v4 addresses both ends by bucket ID, not by name — the ids differ per
        # cluster even when the bucket name is identical, so each is read from
        # its own cluster's list rather than reused.
        args = {
            **scope,
            "cluster_id": source.get("id"),
            "body": {
                "sourceBucket": source_buckets[name],
                "target": {
                    "bucket": target_buckets[name],
                    "cluster": str(target.get("id")),
                    "type": "capella",
                },
                "direction": "oneWay",
                "priority": self.args.priority,
            },
        }

        unconfirmed = await self.call(session, "capella_replication_create", args)
        self.check(
            unconfirmed.get("requires_confirmation") is True
            or unconfirmed.get(ERROR_MARKER) is True,
            "replication_create without confirm is refused",
        )

        result = await self.call(session, "capella_replication_create",
                                 {**args, "confirm": True})

        if not self.performed:
            self.check(result.get("dry_run") is True
                       and result.get("executed") is False,
                       "replication_create is previewed, not executed")
            self.say("\nDry run complete. No replication was created.")
            return

        if result.get(ERROR_MARKER) is True:
            message = str(result.get("error", ""))
            # 409 ALREADY EXISTS IS NOT A FAILURE. Capella answers it with the
            # replication's own id, which is the thing this script exists to
            # produce -- so a re-run that reports FAIL here is reporting success
            # as a defect, and the id it needs is sitting in the message.
            #
            # The id is base64 of "<uuid>/<sourceBucket>/<targetBucket>", which
            # is worth decoding rather than echoing: an operator comparing it
            # against capella_replications_list needs to recognise it.
            if result.get("status") == 409 and "already exists" in message.lower():
                ids = re.findall(r"\[([^\]]+)\]", message)
                self.check(True, "a replication already exists for this pair",
                           f"id(s): {ids[0] if ids else 'not named in the message'}")
                for raw in (ids[0].split(",") if ids else []):
                    try:
                        decoded = base64.b64decode(raw.strip() + "==").decode("utf-8")
                    except Exception:
                        continue
                    self.say(f"     {raw.strip()}")
                    self.say(f"       decodes to {decoded!r} "
                             "(cluster uuid / source bucket / target bucket)")
                self.say("\n   Nothing was created; the existing replication is "
                         "unchanged. Delete it first if you meant to recreate it.")
                return
            self.say("\n   Rejected. Read the message as the finding: if it names a "
                     "field, that is the body spec.py should carry.")
            self.check(False, "replication_create was accepted",
                       json.dumps(result)[:500])
            return

        self.check(True, "replication_create was accepted",
                   "the target object shape is now OBSERVED, not transcribed")
        self.say("\n   XDCR is CONTINUOUS. It will keep writing to "
                 f"{target.get('name')!r} until it is paused or deleted, and it "
                 "puts a cluster into `peering` while it establishes its network "
                 "path — which blocks a restore. Delete it before the next "
                 "backup/restore cycle.")


async def main_async(args) -> int:
    try:
        from mcp import ClientSession, StdioServerParameters, stdio_client
    except ImportError:
        print("the `mcp` package is not importable. Run with `uv run python`.")
        return 1

    if not os.environ.get("CAPELLA_API_KEY_SECRET"):
        print("CAPELLA_API_KEY_SECRET is not set. Run cbenv.bat, then a NEW window.")
        return 1

    run = Xdcr(args)
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
    if run.failures:
        print(f"{len(run.failures)} check(s) failed:")
        for failure in run.failures:
            print(f"  * {failure}")
        return 1
    print("every check passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", required=True, metavar="ID|NAME|HOST",
                        help="SOURCE cluster. Read only.")
    parser.add_argument("--to", required=True, metavar="ID|NAME|HOST",
                        help="TARGET cluster. WRITTEN continuously.")
    parser.add_argument("--bucket", default="travel-sample",
                        help="Must already exist on BOTH clusters.")
    parser.add_argument("--priority", default="low",
                        choices=["low", "medium", "high"])
    parser.add_argument("--perform", dest="dry_run", action="store_false",
                        default=True)
    parser.add_argument("--org", default=None)
    parser.add_argument("--project", default=None)
    parser.add_argument("--i-know-what-im-doing", dest="override",
                        action="store_true",
                        help="permit a target holding real work")
    parser.add_argument("--timeout", type=float, default=180.0)
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
