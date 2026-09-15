"""Restore, through a real MCP client. The half that has never been run.

WHY THIS EXISTS
===============
Backup is verified end to end on both surfaces. RESTORE is not verified at all
-- `admin_backup_restore_run` has never been executed, not cross-cluster, not
same-cluster, not once. So "backup and restore works" is half proven, and the
unproven half is the one a customer reaches for on their worst day.

THE BODY IS THE UNKNOWN, AND THE SHIPPED SCHEMA DISAGREES WITH THE SERVICE
=========================================================================
`admin_backup_restore_run` takes a free-form `target` OBJECT forwarded verbatim.
Its schema says:

    "Typical fields: filter_keys, filter_values, mappings, include, exclude"

The Backup service's own reference shows something else -- a flat body whose
`target` is a CLUSTER URL, alongside `user`, `password`, `auto_create_buckets`,
`force_updates`, `map_data` and friends:

    {"target":"http://127.0.0.1:8091","user":"...","password":"...", ...}

Those are different shapes. Only a real call settles which the service accepts,
and a 400 naming the fields it wanted is a RESULT, not a failure.

SAFETY
======
A restore OVERWRITES. This script:

  * refuses any bucket outside --allow (default: mcptest) -- it will not point a
    restore at harvester, supportal, staging or magicband;
  * never sends `force_updates`, which overwrites documents in the target even
    where the target's copy is NEWER. That is the flag that turns a restore into
    data loss on a live cluster;
  * previews by default. `--perform` is required, and even then the confirmation
    gate is exercised first;
  * reads the bucket's item count from ns_server's stats before and after, so
    "it restored" is a measurement rather than the absence of an error. Item
    count is eventually consistent and includes tombstones, so it is evidence
    rather than proof -- the repository /info document is the authoritative
    record of what the backup held.

USAGE
-----
    uv run python scripts/restore_cycle_test.py --repository <name>
    uv run python scripts/restore_cycle_test.py --repository <name> --perform

Find the repository name with admin_backup_repository_list, or read it off the
backup cycle run that created it.
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

#: Buckets a restore may target. Everything else is refused: a restore is the
#: one operation here that destroys data, and the cluster holds real work.
DEFAULT_ALLOWED = ("mcptest",)


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
            shown = value
            if isinstance(value, dict):
                shown = {
                    k: ("***" if "pass" in k.lower() else v) for k, v in value.items()
                }
            self.say(f"     {key} = {shown!r}")
        response = await asyncio.wait_for(
            session.call_tool(tool, arguments), timeout=self.args.timeout
        )
        body = _payload(response)
        rendered = json.dumps(body, indent=2)
        if len(rendered) > 900:
            rendered = rendered[:900] + "\n     ..."
        self.say(f"   <- {rendered}")
        return body

    async def count(self, session, bucket: str) -> int | None:
        """Items in the bucket, from ns_server's own stats via admin_bucket_list.

        NOT a SQL++ count. The first version of this called `cb_query_run`, which
        does not exist -- this server deliberately ships no arbitrary query
        execution; the data-plane tools live in the CRUD server, and the only
        statement-taking tool here is `cb_explain_query`, which explains rather
        than runs.

        Writing a probe against a tool that was never checked to exist is the
        same mistake as a path taken from a docs page, so the count comes from a
        tool observed answering: admin_bucket_list returned 37KB of real bucket
        stats from inside a container.
        """
        body = await self.call(session, "admin_bucket_list", {})
        buckets = (
            body.get("_list")
            if isinstance(body.get("_list"), list)
            else body.get("buckets")
        )
        if not isinstance(buckets, list):
            return None
        for entry in buckets:
            if not isinstance(entry, dict) or entry.get("name") != bucket:
                continue
            stats = entry.get("basicStats") or entry.get("stats") or {}
            for key in ("itemCount", "item_count", "items"):
                value = stats.get(key)
                if isinstance(value, int):
                    return value
        return None

    async def run(self, session) -> None:
        bucket = self.args.bucket
        allowed = tuple(self.args.allow)

        self.say("=" * 70)
        self.say(f"restore cycle   repository={self.args.repository}  bucket={bucket}")
        self.say(
            f"mode            {'PERFORM (OVERWRITES DATA)' if self.performed else 'DRY RUN (preview)'}"
        )
        self.say("=" * 70)

        if bucket not in allowed:
            self.check(
                False,
                f"{bucket!r} is not in the allowed list {allowed}",
                "a restore overwrites; this cluster holds harvester, supportal, "
                "staging and magicband. Pass --allow to widen deliberately.",
            )
            return

        # The repository must exist and hold a completed backup, or a restore
        # has nothing to restore FROM and the failure says something unrelated.
        info = await self.call(
            session,
            "admin_backup_list",
            {"repository_id": self.args.repository, "state": self.args.state},
        )
        backups = info.get("backups") or []
        self.check(
            bool(backups),
            "the repository holds at least one backup",
            f"{len(backups)} found",
        )
        if not backups:
            self.say("\n   Run scripts/backup_cycle_test.py --perform first.")
            return
        complete = [b for b in backups if b.get("complete")]
        self.check(
            bool(complete),
            "at least one backup is COMPLETE",
            "an in-flight backup is not a restore source",
        )

        before = await self.count(session, bucket)
        self.say(f"\n   documents before: {before}")

        # The body. FLAT, per the Backup service reference -- not the
        # filter-only shape the tool's schema describes. Which of the two the
        # service accepts is exactly what this run settles.
        target: dict = {
            "target": self.args.cluster_url,
            "user": os.environ.get("CB_USERNAME", ""),
            "password": os.environ.get("CB_PASSWORD", ""),
            "auto_create_buckets": False,
            # NOT force_updates. That overwrites documents whose copy in the
            # target is NEWER than the backup's, which is how a restore becomes
            # data loss on a cluster someone is still using.
            "disable_analytics": True,
            "disable_eventing": True,
            "disable_ft": True,
            "disable_views": True,
        }
        if self.args.map_data:
            target["map_data"] = self.args.map_data

        # Unconfirmed first: a DESTRUCTIVE tool that proceeds without confirm is
        # the gate missing from the dispatch path, and that is worth one call.
        unconfirmed = await self.call(
            session,
            "admin_backup_restore_run",
            {
                "repository_id": self.args.repository,
                "state": self.args.state,
                "target": target,
            },
        )
        self.check(
            unconfirmed.get("requires_confirmation") is True
            or unconfirmed.get(ERROR_MARKER) is True,
            "restore without confirm is refused",
            "this is the destructive one; the gate matters most here",
        )

        result = await self.call(
            session,
            "admin_backup_restore_run",
            {
                "repository_id": self.args.repository,
                "state": self.args.state,
                "target": target,
                "confirm": True,
            },
        )

        if not self.performed:
            self.check(
                result.get("dry_run") is True and result.get("executed") is False,
                "restore is previewed, not executed",
            )
            self.say("\nDry run complete. Nothing was restored.")
            self.say(
                "The body above is what --perform would send. Read it before running it."
            )
            return

        if result.get(ERROR_MARKER) is True:
            self.say(
                "\n   The restore was REJECTED. That is the finding, not a failure:"
            )
            self.say("   the message names what the service wanted, and the tool's own")
            self.say(
                "   schema describes a different shape (filter_keys, mappings...)."
            )
            self.say(
                "   Record the real shape in handlers/backup.py and the body stops"
            )
            self.say("   being a guess.")
            self.check(
                False, "the service accepted the restore body", json.dumps(result)[:400]
            )
            return

        self.check(
            True,
            "the service accepted the restore body",
            "the flat shape from the reference is correct, by observation",
        )

        self.say("\n   A restore is ASYNCHRONOUS. Counting again proves it landed;")
        self.say("   an unchanged count immediately after means in flight, not failed.")
        after = await self.count(session, bucket)
        self.say(f"   documents after: {after}")
        if before is not None and after is not None:
            self.check(
                after >= before,
                "the document count did not go backwards",
                f"{before} -> {after}",
            )


async def main_async(args) -> int:
    try:
        from mcp import ClientSession, StdioServerParameters, stdio_client
    except ImportError:
        print("the `mcp` package is not importable. Run with `uv run python`.")
        return 1

    cycle = Restore(args)
    params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(REPO_ROOT, "server.py")],
        env=_client_env(dry_run=args.dry_run),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=args.timeout)
            await cycle.run(session)

    print()
    if cycle.failures:
        print(f"{len(cycle.failures)} check(s) failed:")
        for failure in cycle.failures:
            print(f"  * {failure}")
        return 1
    print("every check passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--state", default="active")
    parser.add_argument("--bucket", default="mcptest")
    parser.add_argument(
        "--allow",
        nargs="*",
        default=list(DEFAULT_ALLOWED),
        help="buckets a restore may target",
    )
    parser.add_argument(
        "--cluster-url",
        default="http://127.0.0.1:8091",
        help="the TARGET cluster, as the BACKUP SERVICE sees it",
    )
    parser.add_argument(
        "--map-data",
        default=None,
        help="remap on restore, e.g. mcptest=mcptest_restored",
    )
    parser.add_argument("--perform", dest="dry_run", action="store_false", default=True)
    parser.add_argument("--timeout", type=float, default=180.0)
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
