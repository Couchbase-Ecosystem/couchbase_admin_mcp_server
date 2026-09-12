"""Drive a Capella managed-backup cycle through a real MCP client.

THE ONE THING THIS SETTLES
==========================
`handlers/capella/spec.py` records these statuses, observed live:

    capella_backups_list   200   the real GET was performed
    capella_backup_get     200   the real GET was performed
    capella_backup_create  405   an OPTIONS probe matched the ROUTE

405 confirms the URL and says nothing about the request body -- OPTIONS never
sends one. `capella_backup_create` declares `body={}`, which is a statement that
nobody has checked what it wants. Three bodies in this registry were wrong while
their paths were 405-verified, so this is not a theoretical gap.

Only a real POST closes it. This is that POST, driven through the MCP client so
what gets tested is the TOOL -- gating, the confirmation gate, dry-run
interception, argument marshalling, the audit record -- and not the endpoint.

SAFETY
======
The target bucket defaults to `travel-sample` and the script REFUSES to name
`harvester` or `supportal` without --i-know-what-im-doing. Those hold real work
on a cluster whose support plan is `basic`, and an on-demand backup of them is
not something to do by accident while testing a tool.

Creating a backup is ADDITIVE -- it adds a backup record, changes no data, and
deletes nothing. Restore is the destructive one and this script does not call it.

USAGE
-----
    uv run python scripts/capella_backup_cycle.py            # preview only
    uv run python scripts/capella_backup_cycle.py --perform

Identifiers are discovered from the organization the API key can see, so the
usual case needs no arguments. The VPN does not matter: this is the v4 control
plane on 443, which the per-cluster IP allowlist does not gate.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ERROR_MARKER = "_is_error"

#: Buckets this script will not touch without an explicit override.
PROTECTED = {"harvester", "supportal", "N1QL_SYSTEM_BUCKET"}


def _client_env(*, dry_run: bool) -> dict[str, str]:
    env = dict(os.environ)
    env["CB_ADMIN_TRANSPORT"] = "stdio"
    # Writes on: read-only mode refuses a write BEFORE the dry-run interceptor
    # sees it, so a preview taken with writes off proves the read-only gate and
    # nothing about previews.
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


class Cycle:
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
        if len(rendered) > 700:
            rendered = rendered[:700] + "\n     ..."
        self.say(f"   <- {rendered}")
        return body

    async def discover(self, session) -> dict | None:
        """org / project / cluster / bucket, read off the control plane."""
        ids: dict = {}

        body = await self.call(session, "capella_organizations_list", {})
        orgs = _rows(body)
        if not self.check(bool(orgs), "an organization is visible"):
            return None
        ids["organization_id"] = self.args.org or orgs[0].get("id")

        body = await self.call(
            session, "capella_projects_list",
            {"organization_id": ids["organization_id"]},
        )
        projects = _rows(body)
        if not self.check(bool(projects), "a project is visible"):
            return None
        ids["project_id"] = self.args.project or projects[0].get("id")

        body = await self.call(
            session, "capella_clusters_list",
            {"organization_id": ids["organization_id"], "project_id": ids["project_id"]},
        )
        clusters = _rows(body)
        if not self.check(bool(clusters), "a cluster is visible"):
            return None
        ids["cluster_id"] = self.args.cluster or clusters[0].get("id")

        body = await self.call(session, "capella_buckets_list", dict(ids))
        buckets = _rows(body)
        names = {b.get("name"): b.get("id") for b in buckets if isinstance(b, dict)}
        self.check(bool(names), "buckets are listable", f"{sorted(names)}")

        wanted = self.args.bucket
        if wanted in PROTECTED and not self.args.override:
            self.check(
                False,
                f"{wanted!r} is protected",
                "holds real work on a basic-plan cluster; pass "
                "--i-know-what-im-doing to override",
            )
            return None
        if wanted not in names:
            self.check(False, f"bucket {wanted!r} exists", f"available: {sorted(names)}")
            return None

        # v4 addresses a bucket by a base64 id, keyspaces use NAMES, and
        # ns_server uses bucket_name. Three vocabularies for one object, and
        # this is the one place they meet.
        ids["bucket_id"] = names[wanted] or base64.b64encode(wanted.encode()).decode()
        self.say(f"\n   target: {wanted!r}  bucket_id={ids['bucket_id']}")
        return ids

    async def run(self, session) -> None:
        self.say("=" * 70)
        self.say(f"capella backup cycle   bucket={self.args.bucket}")
        self.say(f"mode                   {'PERFORM (real write)' if self.performed else 'DRY RUN (preview)'}")
        self.say("=" * 70)

        ids = await self.discover(session)
        if ids is None:
            return

        cluster_scope = {k: ids[k] for k in
                         ("organization_id", "project_id", "cluster_id")}

        before = _rows(await self.call(session, "capella_backups_list", dict(cluster_scope)))
        self.say(f"   backups before: {len(before)}")

        # Unconfirmed first: a write that proceeds without confirm:true means
        # the gate is not in the dispatch path, which is worth one extra call.
        unconfirmed = await self.call(session, "capella_backup_create", dict(ids))
        self.check(
            unconfirmed.get("requires_confirmation") is True
            or unconfirmed.get(ERROR_MARKER) is True,
            "create without confirm is refused",
        )

        created = await self.call(
            session, "capella_backup_create", {**ids, "confirm": True}
        )

        if not self.performed:
            self.check(
                created.get("dry_run") is True and created.get("executed") is False,
                "create is previewed, not executed",
            )
            self.say("\nDry run complete. Nothing was created on Capella.")
            self.say("Re-run with --perform to settle the request body.")
            return

        # THE ANSWER. An empty body either works, or the API names what it
        # wanted -- and a 422 naming fields is a RESULT, not a failure: it is
        # the schema `body={}` has been missing.
        if created.get(ERROR_MARKER) is True:
            self.say("\n   The create was rejected. This is the finding, not a failure:")
            self.say("   the message below is what the API wants in the body, which")
            self.say("   `capella_backup_create` declares as empty. Record it in")
            self.say("   handlers/capella/spec.py and the body is no longer a guess.")
            self.check(False, "create accepted an empty body", json.dumps(created)[:400])
            return

        self.check(True, "create accepted an empty body",
                   "so body={} in spec.py is correct, now by observation")

        after = _rows(await self.call(session, "capella_backups_list", dict(cluster_scope)))
        self.say(f"   backups after: {len(after)}")
        self.check(
            len(after) >= len(before),
            "the backup list did not shrink",
            "Capella backups are ASYNCHRONOUS -- a count that has not grown yet "
            "means scheduled, not failed. Re-run capella_backups_list shortly.",
        )


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

    cycle = Cycle(args)
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
    parser.add_argument("--perform", dest="dry_run", action="store_false", default=True)
    parser.add_argument("--bucket", default="travel-sample")
    parser.add_argument("--org", default=None)
    parser.add_argument("--project", default=None)
    parser.add_argument("--cluster", default=None)
    parser.add_argument("--i-know-what-im-doing", dest="override", action="store_true",
                        help="permit a protected bucket")
    parser.add_argument("--timeout", type=float, default=120.0)
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
