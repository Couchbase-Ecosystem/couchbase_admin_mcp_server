"""Drive a whole backup cycle through a real MCP client. Level 3.

WHAT THIS IS FOR
================
`verify_mcp_surface.py` proves a client can CALL every tool -- startup, gating,
the confirmation gate, dry-run interception, argument marshalling, the audit
record. It stops short of performing writes, deliberately.

This performs them, in the one order that makes the surface meaningful:

    plans_list  ->  repository_create  ->  repository_get  ->  backup_run
                ->  backup_list (the repository /info document)

That sequence is the point. Each of the five shipped backup tools addresses a
repository, and until 2026-09-12 nothing in this server could MAKE one -- so on
any cluster where nobody had created one by hand, every backup tool answered
honestly that there was nothing there and the whole family was correct and
useless. Nothing failed. That is exactly the shape this script exists to catch:
a surface that is individually green and collectively unusable.

WRITES. REALLY.
---------------
`--dry-run` (the default) sends the same calls with CB_ADMIN_DRY_RUN=true and
asserts each write comes back previewed and NOT executed. `--perform` does them
for real. Nothing is deleted either way: the repository is left behind, named
with a timestamp, so a failed run can be inspected rather than tidied away.

USAGE
-----
    uv run python scripts/backup_cycle_test.py                 # preview only
    uv run python scripts/backup_cycle_test.py --perform \
        --archive /opt/couchbase/var/lib/couchbase/backup \
        --bucket mcptest

The archive is a path the BACKUP SERVICE can write, which in a containerised
cluster is a path inside that container -- not one on the machine running this.
Create it as the service's own user, or the service cannot write to it:

    docker exec -u couchbase <container> mkdir -p /opt/couchbase/var/lib/couchbase/backup
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ERROR_MARKER = "_is_error"


def _client_env(*, dry_run: bool) -> dict[str, str]:
    env = dict(os.environ)
    env["CB_ADMIN_TRANSPORT"] = "stdio"
    # Writes must be ENABLED even in the preview run: read-only mode refuses a
    # write before the dry-run interceptor ever sees it, so a preview taken with
    # writes off would prove the read-only gate and nothing about the previews.
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
            if key != "confirm":
                self.say(f"     {key} = {value!r}")
        response = await asyncio.wait_for(
            session.call_tool(tool, arguments), timeout=self.args.timeout
        )
        body = _payload(response)
        rendered = json.dumps(body, indent=2)
        if len(rendered) > 900:
            rendered = rendered[:900] + "\n     ..."
        self.say(f"   <- {rendered}")
        return body

    # ── The cycle ────────────────────────────────────────────────────────────

    async def run(self, session) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        repository = self.args.repository or f"mcpcycle-{stamp}"

        self.say("=" * 70)
        self.say(f"backup cycle  repository={repository}")
        self.say(f"mode          {'PERFORM (real writes)' if self.performed else 'DRY RUN (previews)'}")
        self.say("=" * 70)

        # 1. Plans. A repository must name one, and the plan list is also the
        #    proof that /plan is right -- the reference says /cluster/plan,
        #    which answers 400.
        body = await self.call(session, "admin_backup_plans_list", {})
        plans = body.get("_list") or body.get("plans") or []
        names = [p.get("name") for p in plans if isinstance(p, dict)]
        self.check(bool(names), "plans are listable", f"{names[:6]}")

        plan = self.args.plan
        if plan and names and plan not in names:
            self.check(False, f"requested plan {plan!r} exists", f"available: {names}")
            return
        if not plan:
            plan = names[0] if names else "_daily_backups"
            self.say(f"   using plan {plan!r}")

        # 2. Create. Unconfirmed FIRST: a write tool that performs without
        #    confirm:true is the gate not working, and that is worth one extra
        #    call to establish before sending a confirmed one.
        unconfirmed = await self.call(
            session,
            "admin_backup_repository_create",
            {"repository_id": repository, "plan": plan, "archive": self.args.archive,
             **({"bucket_name": self.args.bucket} if self.args.bucket else {})},
        )
        self.check(
            unconfirmed.get("requires_confirmation") is True
            or unconfirmed.get(ERROR_MARKER) is True,
            "create without confirm is refused",
            "a write that proceeds unconfirmed means the gate is not in the path",
        )

        created = await self.call(
            session,
            "admin_backup_repository_create",
            {"repository_id": repository, "plan": plan, "archive": self.args.archive,
             "confirm": True,
             **({"bucket_name": self.args.bucket} if self.args.bucket else {})},
        )

        if not self.performed:
            self.check(
                created.get("dry_run") is True and created.get("executed") is False,
                "create is previewed, not executed",
                "CB_ADMIN_DRY_RUN is an operator control a caller cannot override",
            )
            self.say("\nDry run complete. Nothing was created.")
            self.say("Re-run with --perform to exercise the real cycle.")
            return

        self.check(
            created.get(ERROR_MARKER) is not True,
            "repository created",
            json.dumps(created)[:300],
        )
        if created.get(ERROR_MARKER) is True:
            self.say("\n   The create failed. Read the message above: an archive the")
            self.say("   service cannot write is the usual cause, and it is a path")
            self.say("   INSIDE the service's container, not on this machine.")
            return

        # 3. Read it back. A create that reports success and leaves nothing is
        #    the failure this step exists for.
        listed = await self.call(session, "admin_backup_repository_list", {"state": "active"})
        text = json.dumps(listed)
        self.check(repository in text, "the new repository appears in the active list")

        got = await self.call(
            session, "admin_backup_repository_get",
            {"repository_id": repository, "state": "active"},
        )
        self.check(got.get(ERROR_MARKER) is not True, "the repository is readable by id")

        # 4. Back it up.
        run = await self.call(
            session, "admin_backup_run",
            {"repository_id": repository, "state": "active",
             "full_backup": True, "confirm": True},
        )
        self.check(run.get(ERROR_MARKER) is not True, "a backup was triggered",
                   json.dumps(run)[:300])

        # 5. And the backups come back through /info, which is the path that
        #    used to be /backups and 404'd.
        info = await self.call(
            session, "admin_backup_list",
            {"repository_id": repository, "state": "active"},
        )
        self.check(info.get(ERROR_MARKER) is not True,
                   "the repository info document is readable")
        self.say("\n   NOTE: a backup is asynchronous. An empty `backups` array here")
        self.say("   means it has not finished, not that it failed -- re-run")
        self.say("   admin_backup_list, or watch admin_cluster_tasks.")


async def main_async(args) -> int:
    try:
        from mcp import ClientSession, StdioServerParameters, stdio_client
    except ImportError:
        print("the `mcp` package is not importable. Run with `uv run python`.")
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
    parser.add_argument("--perform", dest="dry_run", action="store_false", default=True,
                        help="actually create the repository and run the backup")
    parser.add_argument("--archive",
                        default="/opt/couchbase/var/lib/couchbase/backup",
                        help="path the BACKUP SERVICE can write, inside its own filesystem")
    parser.add_argument("--plan", default=None,
                        help="plan name; defaults to the first the service lists")
    parser.add_argument("--bucket", default=os.environ.get("CB_BUCKET") or None,
                        help="restrict the repository to one bucket")
    parser.add_argument("--repository", default=None,
                        help="repository name; defaults to a timestamped one")
    parser.add_argument("--timeout", type=float, default=120.0)
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
