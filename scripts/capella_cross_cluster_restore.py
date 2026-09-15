"""Restore a Capella managed backup INTO A DIFFERENT CLUSTER, through the MCP tool.

WHAT THIS CLOSES
================
`capella_backup_restore` is the last tool in this server whose behaviour was
asserted rather than observed. Its status in `handlers/capella/spec.py` is
`[LIVE 405]` -- an OPTIONS probe matched the route. OPTIONS sends no body, so
405 says the PATH exists and says nothing about the four fields the body
declares as required. Three bodies in this registry were wrong while their paths
were 405-verified, so an unprobed body is not a theoretical gap.

It is also the one operation whose whole point is the cross-cluster case. The
body names `sourceClusterID` AND `targetClusterID` separately, which means one
call, not an export/import dance -- but until now there was one Capella cluster
and nowhere to restore into.

DIRECTION IS NOT SYMMETRIC, AND THIS SCRIPT ENFORCES IT
=======================================================
Restore OVERWRITES the target. The source cluster holds real work; the target is
a cluster provisioned empty for this test. So this script restores

    FROM  the cluster that owns the backup      (read only, never written)
    INTO  the empty cluster named by --target   (written, and only this one)

and it REFUSES to run the other way, or to target any cluster whose bucket is
not empty, unless --i-know-what-im-doing is passed. A flag reversal here is not
a failed test, it is data loss on a cluster nobody wanted touched.

THE PREFLIGHT IS THE INTERESTING PART
=====================================
Capella documents five constraints on a cross-cluster restore. Each is checked
BEFORE the POST and named on its own line, because a 422 that says "invalid
request" six minutes into a run is indistinguishable from a bug in the tool:

  1. Same organization.            "You can only restore to a cluster in the
                                    same organization."
  2. Same cloud provider.          "...only to a bucket in the same Cloud
                                    Service Provider (CSP) as the one used to
                                    create the backup -- such as Azure to
                                    Azure."
  3. Target version >= source.     "...the same major version or later as the
                                    cluster that created the bucket backup."
  4. Source cluster still exists.  "The source cluster that created the bucket
                                    backup must still exist."
  5. TARGET BUCKET ALREADY EXISTS, same name AND same conflict resolution.
                                   "You can only restore data to an existing
                                    bucket with the same name and conflict
                                    resolution methods as the bucket from the
                                    backup."

Constraint 5 is the one that bites: a freshly provisioned cluster has no
buckets, and the v4 restore body carries no auto-create flag -- unlike the
self-managed Backup Service body, which has `auto_create_buckets`. So the target
bucket must be created first. This script does that with `capella_bucket_create`
rather than the UI, which means the setup step PROVES A SECOND WRITE TOOL
instead of merely enabling the first.

Reference:
  https://docs.couchbase.com/cloud/clusters/manage-restore.html

USAGE
-----
    uv run python scripts/capella_cross_cluster_restore.py --target <host-or-id>
    uv run python scripts/capella_cross_cluster_restore.py --target <...> --perform

Dry run is the default and previews every write. `--perform` is required to
create the bucket or to restore.
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

#: Buckets that must never be the TARGET of a restore. The source side is read
#: only, so these are safe to restore FROM; nothing is safe to restore ONTO.
PROTECTED = {"harvester", "supportal", "N1QL_SYSTEM_BUCKET"}


def _client_env(*, dry_run: bool) -> dict[str, str]:
    env = dict(os.environ)
    env["CB_ADMIN_TRANSPORT"] = "stdio"
    # Read-only mode refuses a write BEFORE the dry-run interceptor sees it, so a
    # preview taken with writes off proves the read-only gate and nothing about
    # previews.
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
    """v4 list envelopes are not uniform; the MCP layer may unwrap or not."""
    if "_list" in body:
        return body["_list"]
    for key in ("data", "items", "backups", "buckets", "clusters", "projects"):
        value = body.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict) and isinstance(value.get("data"), list):
            return value["data"]
    return []


def _provider(cluster: dict) -> str:
    """CSP, which v4 spells differently depending on how the cluster was made."""
    for path in (
        ("cloudProvider", "type"),
        ("cloudProvider", "provider"),
        ("provider",),
        ("cloudProvider",),
    ):
        node: Any = cluster
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        if isinstance(node, str) and node:
            return node.lower()
    return ""


def _version(cluster: dict) -> str:
    for path in (("couchbaseServer", "version"), ("version",), ("serverVersion",)):
        node: Any = cluster
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        if isinstance(node, str) and node:
            return node
    return ""


def _major(version: str) -> int:
    head = version.split(".", 1)[0].strip()
    return int(head) if head.isdigit() else -1


def _matches(cluster: dict, needle: str) -> bool:
    """Match a cluster by id, name, or any substring of its connection string.

    The user knows this cluster as a hostname off the Capella console; v4 knows
    it as a uuid. Accepting either is the difference between a copy-paste and a
    lookup, and a hostname fragment cannot collide -- it is the cluster's own
    DNS label.
    """
    needle = needle.strip().lower()
    if not needle:
        return False
    for key in ("id", "name", "connectionString"):
        value = cluster.get(key)
        if isinstance(value, str) and needle in value.lower():
            return True
    return False


class Restore:
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
            rendered = repr(value)
            if len(rendered) > 300:
                rendered = rendered[:300] + " ..."
            self.say(f"     {key} = {rendered}")
        response = await asyncio.wait_for(
            session.call_tool(tool, arguments), timeout=self.args.timeout
        )
        body = _payload(response)
        rendered = json.dumps(body, indent=2)
        if len(rendered) > 900:
            rendered = rendered[:900] + "\n     ..."
        self.say(f"   <- {rendered}")
        return body

    # ── discovery ────────────────────────────────────────────────────────────

    async def scope(self, session) -> dict | None:
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
        return {"organization_id": org, "project_id": project}

    async def clusters(self, session, scope: dict) -> tuple[dict, dict] | None:
        body = await self.call(session, "capella_clusters_list", dict(scope))
        rows = [c for c in _rows(body) if isinstance(c, dict)]
        self.say("\n   clusters in this project:")
        for c in rows:
            self.say(
                f"     {c.get('name')!r}  id={c.get('id')}  "
                f"provider={_provider(c) or '?'}  version={_version(c) or '?'}"
            )

        if not self.check(
            len(rows) >= 2,
            "at least two clusters exist",
            "a cross-cluster restore needs somewhere to restore INTO",
        ):
            return None

        targets = [c for c in rows if _matches(c, self.args.target)]
        if not self.check(
            len(targets) == 1,
            f"--target {self.args.target!r} names exactly one cluster",
            f"matched {len(targets)}",
        ):
            return None
        target = targets[0]

        if self.args.source:
            sources = [c for c in rows if _matches(c, self.args.source)]
            if not self.check(
                len(sources) == 1,
                f"--source {self.args.source!r} names exactly one cluster",
                f"matched {len(sources)}",
            ):
                return None
            source = sources[0]
        else:
            others = [c for c in rows if c.get("id") != target.get("id")]
            # The detail belongs to the FAILURE. Printing it unconditionally put
            # "more than two clusters exist" underneath a PASS, which reads as a
            # warning about the run that just succeeded.
            if len(others) != 1:
                self.check(
                    False,
                    "the source cluster is unambiguous",
                    f"{len(others)} candidate(s) besides the target -- "
                    "name one with --source",
                )
                return None
            self.check(True, "the source cluster is unambiguous")
            source = others[0]

        if not self.check(
            source.get("id") != target.get("id"),
            "source and target are different clusters",
        ):
            return None

        self.say(
            f"\n   FROM  {source.get('name')!r}  {source.get('id')}"
            "   <- read only, and the cluster in the request PATH"
        )
        self.say(
            f"   INTO  {target.get('name')!r}  {target.get('id')}"
            "   <- OVERWRITTEN, named in the body only"
        )
        return source, target

    # ── the five documented constraints ──────────────────────────────────────

    def preflight(self, source: dict, target: dict) -> bool:
        self.say("\n" + "-" * 70)
        self.say(
            "preflight: the constraints Capella documents on a cross-cluster restore"
        )
        self.say("-" * 70)

        # 1 and 4 hold by construction: both clusters came out of one
        # capella_clusters_list call scoped to one organization, which is a
        # stronger statement than comparing two strings we were handed.
        self.check(
            True,
            "same organization",
            "both were returned by one clusters_list in this org and project",
        )
        self.check(
            True,
            "the source cluster still exists",
            "it answered capella_clusters_list in this run",
        )

        sp, tp = _provider(source), _provider(target)
        ok = bool(sp) and sp == tp
        self.check(
            ok,
            "same cloud provider",
            f"source={sp or '?'} target={tp or '?'}"
            + ("" if ok else "  -- Capella refuses across CSPs"),
        )

        # 6. BOTH CLUSTERS HEALTHY. Capella has a dedicated code for this too:
        #    422 / 5022 "Unable to target a restore for a cluster that is not in
        #    a healthy state." Measured 2026-09-13 with the target in `peering`
        #    while XDCR established its network path -- a cluster can leave
        #    `healthy` for ordinary reasons long after it finished provisioning,
        #    so checking once at creation time is not enough. Checked here so the
        #    refusal names the state rather than arriving as a 422 after the
        #    bucket has already been created.
        for role, cluster in (("source", source), ("target", target)):
            state = str(cluster.get("currentState") or "")
            self.check(
                state == "healthy",
                f"{role} cluster is healthy",
                f"{cluster.get('name')!r} is {state or 'in an unreported state'}"
                + (
                    ""
                    if state == "healthy"
                    else " — Capella refuses a restore with 422 code 5022. Wait for "
                    "it to settle; `peering` means a network change (XDCR, a "
                    "private endpoint) is still in progress."
                ),
            )

        sv, tv = _version(source), _version(target)
        smaj, tmaj = _major(sv), _major(tv)
        if smaj < 0 or tmaj < 0:
            # Unreadable is not the same as wrong. Say so rather than passing a
            # check on a version string nobody parsed.
            self.check(
                False,
                "target major version >= source",
                f"could not read a version: source={sv or '?'} target={tv or '?'}",
            )
        else:
            self.check(
                tmaj >= smaj,
                "target major version >= source",
                f"source={sv} target={tv}",
            )
        return not self.failures

    # ── constraint 5: the bucket must already be there ───────────────────────

    async def ensure_bucket(
        self, session, scope: dict, source: dict, target: dict
    ) -> bool:
        name = self.args.bucket
        src_scope = {**scope, "cluster_id": source.get("id")}
        tgt_scope = {**scope, "cluster_id": target.get("id")}

        src_buckets = {
            b.get("name"): b
            for b in _rows(await self.call(session, "capella_buckets_list", src_scope))
            if isinstance(b, dict)
        }
        if not self.check(
            name in src_buckets,
            f"the source holds {name!r}",
            f"source buckets: {sorted(src_buckets)}",
        ):
            return False
        src_res = (
            src_buckets[name].get("bucketConflictResolution")
            or src_buckets[name].get("conflictResolution")
            or "seqno"
        )

        tgt_buckets = {
            b.get("name"): b
            for b in _rows(await self.call(session, "capella_buckets_list", tgt_scope))
            if isinstance(b, dict)
        }

        if name in tgt_buckets:
            tgt_res = (
                tgt_buckets[name].get("bucketConflictResolution")
                or tgt_buckets[name].get("conflictResolution")
                or "seqno"
            )
            self.check(
                tgt_res == src_res,
                "target bucket's conflict resolution matches the source",
                f"source={src_res} target={tgt_res}",
            )
            if name in PROTECTED and not self.args.override:
                self.check(
                    False,
                    f"target bucket {name!r} is not protected",
                    "restore OVERWRITES it; pass --i-know-what-im-doing",
                )
                return False
            return True

        # Not there. Create it -- and this is a real write, gated like any other.
        self.say(f"\n   the target has no {name!r}. Creating it: the v4 restore body")
        self.say("   carries no auto-create flag, unlike the self-managed one.")

        # Copy the SOURCE bucket's shape. Capella documents only name and
        # conflict resolution as requirements, but a target built to different
        # defaults is a different bucket: couchstore where the source is magma
        # changes how the restored data is stored, and a quota smaller than the
        # source's cannot hold it. The CLI flags stay as overrides and win only
        # when passed, which is why their defaults are None rather than values.
        src = src_buckets[name]
        body = {
            "name": name,
            "type": src.get("type") or "couchbase",
            "storageBackend": (
                self.args.storage or src.get("storageBackend") or "couchstore"
            ),
            "memoryAllocationInMb": (
                self.args.quota or src.get("memoryAllocationInMb") or 256
            ),
            "bucketConflictResolution": src_res,
            "replicas": (
                self.args.replicas
                if self.args.replicas is not None
                else src.get("replicas", 1)
            ),
            "flush": True,
        }
        self.say(
            f"   copied from the source bucket: "
            f"storage={body['storageBackend']} "
            f"quota={body['memoryAllocationInMb']}MB "
            f"replicas={body['replicas']} conflict={src_res}"
        )
        args = {**tgt_scope, "body": body}

        unconfirmed = await self.call(session, "capella_bucket_create", args)
        self.check(
            unconfirmed.get("requires_confirmation") is True
            or unconfirmed.get(ERROR_MARKER) is True,
            "bucket_create without confirm is refused",
        )

        created = await self.call(
            session, "capella_bucket_create", {**args, "confirm": True}
        )
        if not self.performed:
            self.check(
                created.get("dry_run") is True and created.get("executed") is False,
                "bucket_create is previewed, not executed",
            )
            return True
        if created.get(ERROR_MARKER) is True:
            self.check(False, "bucket_create was accepted", json.dumps(created)[:400])
            return False
        self.check(
            True,
            "bucket_create was accepted",
            f"conflict resolution {src_res!r}, copied from the source",
        )
        return True

    # ── the restore itself ───────────────────────────────────────────────────

    async def run(self, session) -> None:
        self.say("=" * 70)
        self.say("capella CROSS-CLUSTER restore")
        self.say(
            f"mode   {'PERFORM (real restore)' if self.performed else 'DRY RUN (preview)'}"
        )
        self.say("=" * 70)

        scope = await self.scope(session)
        if scope is None:
            return
        pair = await self.clusters(session, scope)
        if pair is None:
            return
        source, target = pair

        if not self.preflight(source, target):
            self.say("\nPreflight failed. Nothing was sent.")
            return

        if not await self.ensure_bucket(session, scope, source, target):
            return

        src_scope = {**scope, "cluster_id": source.get("id")}
        backups = [
            b
            for b in _rows(await self.call(session, "capella_backups_list", src_scope))
            if isinstance(b, dict)
        ]
        mine = [
            b
            for b in backups
            if (b.get("bucketName") or b.get("bucket")) in (None, self.args.bucket)
        ]
        if not self.check(
            bool(mine),
            f"the source has a backup of {self.args.bucket!r}",
            f"{len(backups)} backup(s) on the source",
        ):
            return

        # Newest by DATE, not by position. v4 happens to return newest first,
        # but that ordering is not documented, and "restore whichever row came
        # back first" is not a sentence anyone wants to read after restoring the
        # wrong month onto a cluster. Undated rows sort last rather than crashing.
        mine.sort(
            key=lambda b: str(b.get("date") or b.get("createdAt") or ""), reverse=True
        )
        backup = mine[0]
        if self.args.backup:
            picked = [b for b in mine if b.get("id") == self.args.backup]
            if not self.check(
                len(picked) == 1, f"--backup {self.args.backup!r} exists"
            ):
                return
            backup = picked[0]
        backup_id = backup.get("id")
        # Name the BUCKET as well as the id. The filter above already excluded
        # other buckets' backups, but a transcript that does not say so cannot be
        # used to prove it afterwards -- and this cluster also holds backups of
        # harvester and supportal.
        self.say(f"\n   restoring backup {backup_id}")
        self.say(
            f"     bucket : {backup.get('bucketName') or backup.get('bucket') or '?'}"
        )
        self.say(
            f"     taken  : {backup.get('date') or backup.get('createdAt') or 'undated'}"
        )
        self.say(
            f"     method : {backup.get('method') or '?'}   "
            f"items={((backup.get('stats') or {}).get('items', '?'))}"
        )
        self.say(
            f"     chosen as the newest of {len(mine)} backup(s) of "
            f"{self.args.bucket!r}"
        )

        # THE PATH CLUSTER IS THE SOURCE.
        #
        # This script had it the other way round on its first run and Capella
        # answered 422 code 5026: "The source cluster ID is invalid. Please
        # ensure the source cluster id matches the id in the path." A dedicated
        # error code for this confusion exists because the confusion is common,
        # and the registry's own summary was wrong in the same direction.
        #
        # The rule, and the reason: a backup is a CHILD of the cluster that took
        # it, so its URL sits under that cluster. The destination is an argument,
        # not a location.
        #
        #   path cluster_id  == sourceClusterID   read only
        #   targetClusterID  (body only)          OVERWRITTEN
        args = {
            **scope,
            "cluster_id": source.get("id"),
            "backup_id": backup_id,
            "body": {
                "backupID": backup_id,
                "sourceClusterID": source.get("id"),
                "targetClusterID": target.get("id"),
                "services": self.args.services,
            },
        }

        unconfirmed = await self.call(session, "capella_backup_restore", args)
        self.check(
            unconfirmed.get("requires_confirmation") is True
            or unconfirmed.get(ERROR_MARKER) is True,
            "restore without confirm is refused",
            "this is the destructive tool; the gate matters more here than anywhere",
        )

        result = await self.call(
            session, "capella_backup_restore", {**args, "confirm": True}
        )

        if not self.performed:
            self.check(
                result.get("dry_run") is True and result.get("executed") is False,
                "restore is previewed, not executed",
            )
            self.say("\nDry run complete. Nothing was restored.")
            self.say("Re-run with --perform to settle the request body.")
            return

        if result.get(ERROR_MARKER) is True:
            # A 422 naming fields is a RESULT. It is the schema the four required
            # fields were transcribed from a reference rather than observed.
            self.say("\n   The restore was rejected. Read the message as the finding:")
            self.say("   if it names fields, that is the body spec.py should carry.")
            self.check(False, "restore was accepted", json.dumps(result)[:600])
            return

        self.check(
            True,
            "restore was accepted",
            "the four required fields are now OBSERVED, not transcribed",
        )
        self.say("\n   Capella restores are ASYNCHRONOUS. Poll the target with")
        self.say("   capella_buckets_list until its item count stops climbing;")
        self.say("   indexes come back DEFERRED and must be built before the")
        self.say("   target is performance-comparable to its source.")


async def main_async(args) -> int:
    try:
        from mcp import ClientSession, StdioServerParameters, stdio_client
    except ImportError:
        print("the `mcp` package is not importable. Run with `uv run python`.")
        return 1

    if not os.environ.get("CAPELLA_API_KEY_SECRET"):
        print("CAPELLA_API_KEY_SECRET is not set. Run cbenv.bat, then a NEW window.")
        print("It is the SECRET, not CAPELLA_ACCESS_KEY_ID.")
        return 1

    restore = Restore(args)
    params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(REPO_ROOT, "server.py")],
        env=_client_env(dry_run=args.dry_run),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=args.timeout)
            await restore.run(session)

    print()
    if restore.failures:
        print(f"{len(restore.failures)} check(s) failed:")
        for failure in restore.failures:
            print(f"  * {failure}")
        return 1
    print("every check passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        required=True,
        help="the cluster to restore INTO, by id, name, or a "
        "fragment of its connection string. THIS ONE IS "
        "WRITTEN.",
    )
    parser.add_argument(
        "--source",
        default="",
        help="the cluster that owns the backup. Inferred when "
        "exactly two clusters exist.",
    )
    parser.add_argument("--bucket", default="travel-sample")
    parser.add_argument(
        "--backup",
        default="",
        help="restore this backup id rather than the first listed.",
    )
    parser.add_argument(
        "--services",
        nargs="+",
        default=["data"],
        help="services to restore. 'data' alone is the honest "
        "default: index definitions restore DEFERRED.",
    )
    parser.add_argument(
        "--quota",
        type=int,
        default=None,
        help="per-node RAM for a target bucket this script "
        "creates. Default: whatever the source bucket has.",
    )
    parser.add_argument(
        "--replicas",
        type=int,
        default=None,
        help="Default: whatever the source bucket has.",
    )
    parser.add_argument(
        "--storage",
        default=None,
        choices=["couchstore", "magma"],
        help="Default: whatever the source bucket has.",
    )
    parser.add_argument("--perform", dest="dry_run", action="store_false", default=True)
    parser.add_argument("--org", default=None)
    parser.add_argument("--project", default=None)
    parser.add_argument(
        "--i-know-what-im-doing",
        dest="override",
        action="store_true",
        help="permit a protected bucket as the RESTORE TARGET",
    )
    parser.add_argument("--timeout", type=float, default=180.0)
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
