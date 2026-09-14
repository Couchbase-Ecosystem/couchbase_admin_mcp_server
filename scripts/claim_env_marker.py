#!/usr/bin/env python3
r"""
claim_env_marker.py - tag an existing cluster as a managed environment.

WHY THIS IS A SCRIPT AND NOT A HAND-BUILT TOOL CALL
===================================================
capella_env_list decides what is a "managed environment" by parsing an
`mcp-env:{...}` marker out of the cluster's DESCRIPTION. A cluster without one is
listed as unmanaged with "no mcp-env marker -- not created by this server", which
is correct and is why capella_env_status and capella_env_connection_info have
nothing to resolve.

Writing that description means PUT .../clusters/{id}, and that operation is a
REPLACE, not a merge. The provider's UpdateClusterRequest
(openapi.gen.go:5956-5961) requires FOUR fields:

    description, name, serviceGroups, support

Send a body with only `description` and you have not renamed the cluster -- you
have told Capella the cluster has no service groups. Hand-escaping that JSON in a
PowerShell one-liner, against a live cluster, is a bad way to find out what the
API does with it.

So this reads the cluster first, changes ONE field, and sends the rest back
verbatim. It prints the exact body and refuses to send without --perform.

WHAT IT DOES NOT DO
===================
It does not create anything and it does not resize anything. If the cluster
already carries a marker it says so and stops -- overwriting an existing
environment's identity is not a thing to do by accident.

ttl_h defaults to 0, which means PINNED: capella_env_reap will never collect it.
A TTL on a cluster somebody is using is how a fixture disappears overnight. Pass
--ttl-hours deliberately if you want it reapable.

USAGE
=====
    $env:CAPELLA_API_KEY_SECRET = '<the API key SECRET>'
    uv run python scripts/claim_env_marker.py --cluster vn1kiibitcyvwrw --env mcptest
    uv run python scripts/claim_env_marker.py --cluster vn1kiibitcyvwrw --env mcptest --perform
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from probe_access_control_function import (  # noqa: E402
    call,
    resolve_credentials,
    _message,
    _rows,
)

#: Must match handlers/capella/guardrails.ENV_MARKER_PREFIX. Imported rather than
#: retyped where possible -- see _marker_prefix.
_FALLBACK_PREFIX = "mcp-env:"


def _marker_prefix() -> str:
    """The real prefix from guardrails, or the fallback if it will not import.

    Retyping a constant that another module owns is how two spellings of the same
    marker end up in one repository, one of which parses and one of which does
    not.
    """
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
        from handlers.capella.guardrails import ENV_MARKER_PREFIX  # type: ignore
        return ENV_MARKER_PREFIX
    except Exception:
        return _FALLBACK_PREFIX


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cluster", required=True,
                    help="cluster id, or a unique prefix of its connection string")
    ap.add_argument("--env", required=True, help="environment name to record")
    ap.add_argument("--owner", default="", help="optional owner recorded in the marker")
    ap.add_argument("--ttl-hours", type=int, default=0,
                    help="0 (default) pins the environment against capella_env_reap")
    ap.add_argument("--project", default="")
    ap.add_argument("--env-file", default=None)
    ap.add_argument("--perform", action="store_true",
                    help="actually send the PUT (without this, the body is printed)")
    args = ap.parse_args()

    token, org, src = resolve_credentials(args.env_file)
    if not token:
        print("no Capella API key found. Set CAPELLA_API_KEY_SECRET.")
        return 2
    print(f"[auth] credential from {src}")

    if not org:
        status, text = call("GET", "/v4/organizations", token)
        rows = _rows(text)
        if status != 200 or len(rows) != 1:
            print(f"could not resolve exactly one organization (status {status})")
            return 2
        org = rows[0]["id"]

    project = args.project
    if not project:
        status, text = call("GET", f"/v4/organizations/{org}/projects", token)
        rows = _rows(text)
        if status != 200 or len(rows) != 1:
            print(f"could not resolve exactly one project (status {status}); pass --project")
            return 2
        project = rows[0]["id"]

    base = f"/v4/organizations/{org}/projects/{project}/clusters"
    status, text = call("GET", base, token)
    rows = _rows(text)
    if status != 200:
        print(f"clusters list failed: {status} {_message(text)}")
        return 2
    matched = [c for c in rows
               if c.get("id") == args.cluster
               or args.cluster in str(c.get("connectionString", ""))]
    if len(matched) != 1:
        print(f"--cluster '{args.cluster}' matched {len(matched)} of {len(rows)}")
        for c in rows:
            print(f"    {c.get('id')}  {c.get('name')}  {c.get('connectionString')}")
        return 2
    cluster = matched[0]
    cluster_id = cluster["id"]
    print(f"[ids] cluster {cluster_id}  ({cluster.get('name')})")

    prefix = _marker_prefix()
    existing = str(cluster.get("description") or "")
    if prefix in existing:
        print(f"\nthis cluster ALREADY carries a marker:\n    {existing}")
        print("Refusing to overwrite it. An environment's identity is not "
              "something to replace by accident; edit it deliberately if that is "
              "what you mean.")
        return 1

    from datetime import datetime, timezone
    payload = {"env": args.env,
               "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "ttl_h": args.ttl_hours}
    if args.owner:
        payload["owner"] = args.owner
    marker = prefix + json.dumps(payload, separators=(",", ":"), sort_keys=True)

    # KEEP WHAT THE HUMAN WROTE. guardrails._extract_marker_json finds the prefix
    # with a search and then brace-counts from there, so a description of
    # "<whatever someone wrote> mcp-env:{...}" parses exactly as well as a bare
    # marker. Replacing the whole description would have discarded
    # "test for cross cluster backup and restore" -- a note that tells the next
    # person what the cluster is for -- to satisfy a parser that never needed it.
    description = f"{existing.strip()} {marker}".strip() if existing.strip() else marker

    # READ-MODIFY-WRITE. Every field but description is echoed back exactly as the
    # server gave it. serviceGroups in particular: this operation replaces the
    # cluster document, and a body without them is a request to have none.
    body = {
        "name": cluster.get("name"),
        "description": description,
        "support": cluster.get("support"),
        "serviceGroups": cluster.get("serviceGroups"),
    }
    missing = [k for k, v in body.items() if v in (None, "")]
    if [k for k in missing if k != "description"]:
        print(f"\nthe cluster document is missing {missing}, which this PUT "
              f"requires. Refusing to send a partial replace.")
        print(json.dumps(cluster, indent=2)[:1200])
        return 2

    print(f"\nold description: {existing!r}")
    print(f"new description: {description!r}")
    print(f"\nPUT {base}/{cluster_id}")
    print(json.dumps(body, indent=2)[:2000])

    if not args.perform:
        print("\nNOT SENT. Re-run with --perform once the body above looks right.")
        print("Everything except `description` is the server's own value, echoed "
              "back unchanged.")
        return 0

    status, text = call("PUT", f"{base}/{cluster_id}", token, body)
    print(f"\n  {status}  {_message(text)[:300]}")
    if 200 <= status < 300:
        print("\nDone. capella_env_list should now report this cluster under "
              "'managed', and capella_env_status / capella_env_connection_info "
              f"resolve env_name={args.env!r}.")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
