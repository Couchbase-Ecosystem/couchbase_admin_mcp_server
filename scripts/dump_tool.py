"""Call ONE tool through a real MCP client and print its WHOLE response.

WHY THIS EXISTS
===============
Every defect this project has found was found by reading a response, and most
of them hid in a field the caller never printed: an id spelled `exportId` in a
create and `id` in a list, a repository whose `name` is a uuid while its `id` is
the operator's string, an FTS index list that is a MAP and not an array.

`verify_mcp_surface.py` truncates -- it has 250 tools to get through. The
populate scripts print the first 400 characters. Both are right for their job
and neither is any use when the question is "what EXACTLY did the server send
back", which is the question that settles a wrong-field bug.

So: one tool, all of it, no truncation.

READ-ONLY BY DEFAULT, AND THE SAFETY IS NOT ADVISORY
----------------------------------------------------
The server is started with CB_ADMIN_READ_ONLY_MODE=true, so write tools are not
even advertised and cannot be called by accident or by typo. `--write` lowers
that to read_only=false AND forces CB_ADMIN_DRY_RUN=true, so a write is
previewed and never performed. There is deliberately no flag here that performs
a write: this is a debugging lens, and a lens that can change what it looks at
is a bad lens. To perform writes, use the scripts built for it.

USAGE
-----
    uv run python scripts\\dump_tool.py capella_cluster_audit_log_exports_list
    uv run python scripts\\dump_tool.py capella_backup_get -a backup_id=0d874a02-...
    uv run python scripts\\dump_tool.py admin_backup_list -a repository_id=mcptest-repo
    uv run python scripts\\dump_tool.py --list                  # what is advertised
    uv run python scripts\\dump_tool.py capella_backup_get --schema   # its input schema

organization_id, project_id and cluster_id are filled from CAPELLA_ORG_ID,
CAPELLA_PROJECT_ID and CAPELLA_CLUSTER_ID when present, because typing a uuid
three times is how the wrong uuid gets typed. Anything given with -a wins.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

# Schemas are read through mcp_compat, never off the tool object as an attribute.
# mcp 2.x renames those fields, so a direct read raises AttributeError there --
# which is why tests/test_mcp_compat.py enumerates every module that must go
# through the shim. This script was caught by it within minutes of being
# written, comment included: the check greps the source, so even mentioning the
# old spelling in prose trips it. The convention holds only because it is a test.
from mcp_compat import input_schema as _input_schema  # noqa: E402

#: Env var -> argument name, for the three ids every Capella path carries.
_ENV_DEFAULTS: tuple[tuple[str, str], ...] = (
    ("CAPELLA_ORG_ID", "organization_id"),
    ("CAPELLA_PROJECT_ID", "project_id"),
    ("CAPELLA_CLUSTER_ID", "cluster_id"),
)


def _rows(body: Any) -> list:
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in ("data", "items"):
            if isinstance(body.get(key), list):
                return body[key]
    return []


def _one(rows: list, what: str, wanted: str | None) -> str | None:
    """The single matching row's id, or None after saying why not.

    AMBIGUITY IS REFUSED, NOT RESOLVED BY TAKING ROW ZERO. The surface harness
    learned this the hard way: a --capella-cluster that matched two clusters and
    silently used the first produced a transcript that was internally consistent
    and about the wrong cluster. Better to print the choices and stop.
    """
    if wanted:
        rows = [r for r in rows
                if wanted in (str(r.get("id", "")), str(r.get("name", "")))
                or wanted in str(r.get("connectionString", ""))]
    if not rows:
        print(f"no {what} matched" + (f" {wanted!r}" if wanted else ""))
        return None
    if len(rows) > 1:
        print(f"{len(rows)} {what}s match" + (f" {wanted!r}" if wanted else "")
              + "; name one:")
        for row in rows:
            print(f"   {row.get('name')!r}  {row.get('id')}")
        return None
    return str(rows[0].get("id"))


def _client_env(*, allow_writes: bool) -> dict[str, str]:
    env = dict(os.environ)
    env["CB_ADMIN_TRANSPORT"] = "stdio"
    env.setdefault("CB_ADMIN_PROFILE", "workstation")
    env.setdefault("PYTHONUNBUFFERED", "1")
    if allow_writes:
        # Both, together, always. read_only=false alone would advertise write
        # tools with nothing in front of them.
        env["CB_ADMIN_READ_ONLY_MODE"] = "false"
        env["CB_ADMIN_DRY_RUN"] = "true"
    else:
        env["CB_ADMIN_READ_ONLY_MODE"] = "true"
    return env


def _payload(response: Any) -> Any:
    """The tool's own JSON, not the MCP envelope."""
    for block in getattr(response, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
    return None


def _parse_arg(raw: str) -> tuple[str, Any]:
    """`name=value`. A value that parses as JSON is used as JSON.

    So -a full_backup=true sends a boolean and -a body='{"x":1}' sends an
    object, while -a name=mcptest sends the string. Without this every argument
    would be a string and every boolean-typed field would be wrong.
    """
    if "=" not in raw:
        raise SystemExit(f"--arg must be name=value, got {raw!r}")
    name, _, value = raw.partition("=")
    try:
        return name, json.loads(value)
    except json.JSONDecodeError:
        return name, value


async def run(args) -> int:
    from mcp import ClientSession, StdioServerParameters, stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(REPO_ROOT, "server.py")],
        env=_client_env(allow_writes=args.write),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=args.timeout)
            advertised = (await session.list_tools()).tools

            if args.list:
                for tool in sorted(advertised, key=lambda t: t.name):
                    print(tool.name)
                return 0

            match = next((t for t in advertised if t.name == args.tool), None)
            if match is None:
                print(f"{args.tool!r} is not advertised in this posture.")
                # NAME THE LIKELY REASON rather than leaving the reader to guess
                # between a typo and the read-only filter.
                if not args.write:
                    print("It may be a write tool — re-run with --write to "
                          "advertise writes under a forced dry run.")
                near = [t.name for t in advertised if args.tool in t.name]
                if near:
                    print("closest advertised: " + ", ".join(sorted(near)))
                return 2

            if args.schema:
                print(json.dumps(_input_schema(match), indent=2))
                return 0

            arguments: dict[str, Any] = {}
            schema = _input_schema(match)
            declared = set(schema.get("properties") or {})
            for env_name, arg_name in _ENV_DEFAULTS:
                value = os.environ.get(env_name)
                if value and arg_name in declared:
                    arguments[arg_name] = value
            for raw in args.arg:
                name, value = _parse_arg(raw)
                arguments[name] = value

            # DISCOVER WHAT IS STILL MISSING rather than making the caller paste
            # uuids. Typing a uuid by hand is how the wrong uuid gets typed, and
            # a dump against the wrong cluster looks exactly like a dump against
            # the right one.
            required = set(schema.get("required") or [])
            if "organization_id" in required and "organization_id" not in arguments:
                orgs = _rows(_payload(
                    await session.call_tool("capella_organizations_list", {})))
                picked = _one(orgs, "organization", args.org)
                if picked is None:
                    return 2
                arguments["organization_id"] = picked
            if "project_id" in required and "project_id" not in arguments:
                projects = _rows(_payload(await session.call_tool(
                    "capella_projects_list",
                    {"organization_id": arguments["organization_id"]})))
                picked = _one(projects, "project", args.project)
                if picked is None:
                    return 2
                arguments["project_id"] = picked
            if "cluster_id" in required and "cluster_id" not in arguments:
                clusters = _rows(_payload(await session.call_tool(
                    "capella_clusters_list",
                    {"organization_id": arguments["organization_id"],
                     "project_id": arguments["project_id"]})))
                picked = _one(clusters, "cluster", args.cluster)
                if picked is None:
                    return 2
                arguments["cluster_id"] = picked

            print(f"-> {args.tool}")
            for name in sorted(arguments):
                shown = arguments[name]
                print(f"     {name} = {shown!r}")
            print()

            response = await asyncio.wait_for(
                session.call_tool(args.tool, arguments), timeout=args.timeout
            )
            body = _payload(response)
            print(json.dumps(body, indent=2, sort_keys=args.sort)
                  if not isinstance(body, str) else body)

            if args.keys and isinstance(body, dict):
                # The question behind most uses of this script is "what is this
                # object's id field called", so answer it without being asked.
                print("\ntop-level keys: " + ", ".join(sorted(body)))
                for name, value in body.items():
                    if isinstance(value, list) and value and isinstance(value[0], dict):
                        print(f"keys of {name}[0]: "
                              + ", ".join(sorted(value[0])))
            return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Call one MCP tool and print its entire response."
    )
    parser.add_argument("tool", nargs="?", help="tool name")
    parser.add_argument("-a", "--arg", action="append", default=[],
                        metavar="NAME=VALUE",
                        help="argument; JSON values are parsed as JSON")
    parser.add_argument("--list", action="store_true",
                        help="list advertised tools and exit")
    parser.add_argument("--schema", action="store_true",
                        help="print the tool's input schema and exit")
    parser.add_argument("--write", action="store_true",
                        help="advertise write tools, under a FORCED dry run")
    parser.add_argument("--keys", action="store_true", default=True,
                        help="summarise top-level and row keys (default on)")
    parser.add_argument("--no-keys", dest="keys", action="store_false")
    parser.add_argument("--sort", action="store_true",
                        help="sort keys in the printed JSON")
    parser.add_argument("--org", help="organization name or id, when several exist")
    parser.add_argument("--project", help="project name or id, when several exist")
    parser.add_argument("--cluster",
                        help="cluster name, id or connection host, when several exist")
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    if not args.tool and not args.list:
        parser.error("give a tool name, or --list")
    try:
        from mcp import ClientSession  # noqa: F401
    except ImportError:
        print("the `mcp` package is not importable. Run with `uv run python`.")
        return 1
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
