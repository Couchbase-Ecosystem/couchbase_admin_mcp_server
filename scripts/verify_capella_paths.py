#!/usr/bin/env python3
"""
verify_capella_paths.py — confirm every Capella v4 path this server uses is real.

WHY THIS EXISTS
===============
The 61 operations in handlers/capella/spec.py are tagged by provenance:

    [TF]   read out of the official Terraform provider's Go source
    [DOC]  taken from Capella's published API documentation
    [PAT]  INFERRED from a confirmed sibling, not individually verified

The [PAT] ones are the risk. They follow the pattern of endpoints that are confirmed,
but nobody has watched them return a response. A wrong path fails with a 404 and carries
no data risk — but `capella_env_ensure` would fail part-way through reconciling an
environment, and collection creation sits squarely on the path this server was built for.

This script answers the question by asking Capella, which is the only authority.

WHAT IT DOES AND DOES NOT DO
============================
By default it is READ-ONLY and NON-DESTRUCTIVE:

  * GET operations are called for real.
  * Write operations (POST/PUT/DELETE) are probed with OPTIONS, a method the API does
    not implement. That distinguishes "this route does not exist" (404) from "this route
    exists and does not accept OPTIONS" (405/401/403), which verifies the PATH without
    creating, modifying or deleting anything.

It never sends POST, PUT, PATCH or DELETE unless you pass --write-probe, and even then
only for operations you name explicitly with --only.

HOW TO READ THE OUTPUT
======================
  VERIFIED    the route exists — 2xx, or 401/403/405/409/422, all of which require the
              route to have been matched before whatever rejected the call
  MISSING     404 with no sign the route matched — the path is wrong, fix spec.py
  SKIPPED     needs an identifier that could not be discovered (no App Service exists in
              the target project, say), so the path was not exercised
  ERROR       network or credential trouble; not a verdict about the path

Exit status is 0 only when nothing is MISSING, so this is usable in CI.

USAGE
=====
    export CB_CAPELLA_API_KEY='<the API key SECRET, not its id>'
    python3 scripts/verify_capella_paths.py --org <organization_id>

    # just the four inferred paths
    python3 scripts/verify_capella_paths.py --org <org> --only-pat

    # pin the project/cluster if the org has several
    python3 scripts/verify_capella_paths.py --org <org> --project <id> --cluster <id>

The key needs only read access for the default mode: create one under
Organization Settings -> API Keys with the Organization Member role plus read access to
the project you point it at.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get(
    "CB_CAPELLA_API_URL", "https://cloudapi.cloud.couchbase.com"
).rstrip("/")
TIMEOUT = 30

#: Statuses that prove the route was MATCHED. 401/403 mean authentication or
#: authorization rejected the call, which can only happen after routing. 405 means the
#: path exists but not for that method — exactly what the OPTIONS probe looks for.
_PATH_EXISTS = {200, 201, 202, 204, 400, 401, 403, 405, 409, 422, 429}

#: Phrases in a 404 body that indicate the ROUTE matched and the OBJECT was absent.
#: Without this, verifying a path that needs an id we could not discover would report a
#: false MISSING — the most likely way for this script to be confidently wrong.
_OBJECT_ABSENT_HINTS = (
    "not found in",
    "does not exist",
    "notfound",
    "could not be found",
)
_OBJECT_WORDS = ("bucket", "scope", "collection", "cluster", "user", "service", "index")


class Result:
    def __init__(self, op, verdict, status=None, detail=""):
        self.op = op
        self.verdict = verdict
        self.status = status
        self.detail = detail


def _request(method: str, path: str, token: str, body=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")
    except Exception as exc:  # network, DNS, TLS
        return None, f"{type(exc).__name__}: {exc}"


def _first_id(payload: str, *keys: str) -> str | None:
    """Pull the first identifier out of a v4 list response.

    v4 wraps lists as {"data": [...], "cursor": {...}}, but not uniformly across
    endpoints, so both the wrapped and bare-array shapes are handled rather than
    assumed.
    """
    try:
        parsed = json.loads(payload)
    except Exception:
        return None
    items = parsed.get("data") if isinstance(parsed, dict) else parsed
    if isinstance(items, dict):
        items = items.get("items") or []
    if not isinstance(items, list) or not items:
        return None
    first = items[0]
    if not isinstance(first, dict):
        return None
    for key in keys:
        if first.get(key):
            return str(first[key])
    return None


def discover(token: str, args) -> dict:
    """Find real identifiers so paths are filled with values that actually exist.

    Substituting a made-up UUID would make every nested path return 404 and the run
    would report MISSING for paths that are perfectly correct.
    """
    ids: dict[str, str] = {"organization_id": args.org}
    print(f"  organization : {args.org}")

    if args.project:
        ids["project_id"] = args.project
    else:
        status, body = _request("GET", f"/v4/organizations/{args.org}/projects", token)
        found = _first_id(body, "id", "projectId")
        if found:
            ids["project_id"] = found
        else:
            print(f"  project      : NONE FOUND (GET projects -> {status})")
            print(f"                 {body[:200]}")
    if ids.get("project_id"):
        print(f"  project      : {ids['project_id']}")

    if args.cluster:
        ids["cluster_id"] = args.cluster
    elif ids.get("project_id"):
        _, body = _request(
            "GET",
            f"/v4/organizations/{args.org}/projects/{ids['project_id']}/clusters",
            token,
        )
        found = _first_id(body, "id", "clusterId")
        if found:
            ids["cluster_id"] = found

    if ids.get("cluster_id"):
        print(f"  cluster      : {ids['cluster_id']}")
    else:
        print("  cluster      : NONE FOUND (cluster-scoped paths will be SKIPPED)")
        return ids

    base = (
        f"/v4/organizations/{args.org}/projects/{ids['project_id']}"
        f"/clusters/{ids['cluster_id']}"
    )

    _, body = _request("GET", f"{base}/buckets", token)
    bucket = _first_id(body, "id", "bucketId")
    if bucket:
        ids["bucket_id"] = bucket
        print(f"  bucket       : {bucket}")
        _, sbody = _request("GET", f"{base}/buckets/{bucket}/scopes", token)
        ids["scope_name"] = _first_id(sbody, "name", "id") or "_default"
        print(f"  scope        : {ids['scope_name']}")

        # A collection name, so capella_collection_delete gets a real verdict rather
        # than SKIPPED. Collections exist on any provisioned cluster and the list
        # endpoint is itself [DOC]-confirmed, so discovering one costs nothing.
        _, cbody = _request(
            "GET",
            f"{base}/buckets/{bucket}/scopes/{ids['scope_name']}/collections",
            token,
        )
        collection = _first_id(cbody, "name", "id")
        if collection:
            ids["collection_name"] = collection
            print(f"  collection   : {collection}")
        else:
            print("  collection   : none in that scope (collection paths SKIPPED)")
    else:
        print("  bucket       : NONE FOUND (bucket-scoped paths will be SKIPPED)")

    _, body = _request("GET", f"{base}/appservices", token)
    app = _first_id(body, "id", "appServiceId")
    if app:
        ids["app_service_id"] = app
        print(f"  app service  : {app}")
        # Likewise for the App Services admin user, so its delete path gets a verdict.
        _, abody = _request("GET", f"{base}/appservices/{app}/adminUsers", token)
        admin = _first_id(abody, "id", "userId", "name")
        if admin:
            ids["admin_user_id"] = admin
            print(f"  admin user   : {admin}")
        else:
            print("  admin user   : none (admin-user paths SKIPPED)")
    else:
        print("  app service  : NONE FOUND (App Services paths will be SKIPPED)")

    # Identifiers that only exist once something has been created are left ABSENT on
    # purpose, so the affected operations report SKIPPED rather than a false MISSING.
    return ids


def fill(path: str, ids: dict) -> tuple[str | None, list[str]]:
    """Substitute {placeholders}. Returns (path, missing_placeholder_names)."""
    missing = [p for p in re.findall(r"\{(\w+)\}", path) if not ids.get(p)]
    if missing:
        return None, missing
    filled = re.sub(
        r"\{(\w+)\}",
        lambda m: urllib.parse.quote(str(ids[m.group(1)]), safe=""),
        path,
    )
    return filled, []


def probe(op, ids: dict, token: str, allow_writes: bool) -> Result:
    path, missing = fill(op.path, ids)
    if path is None:
        return Result(op, "SKIPPED", detail=f"no value for {', '.join(missing)}")

    if op.method == "GET":
        status, body = _request("GET", path, token)
    elif allow_writes:
        status, body = _request(op.method, path, token, body={} if op.body else None)
    else:
        status, body = _request("OPTIONS", path, token)

    if status is None:
        return Result(op, "ERROR", detail=body[:160])

    if status == 404:
        lowered = body.lower()
        if any(h in lowered for h in _OBJECT_ABSENT_HINTS) and any(
            w in lowered for w in _OBJECT_WORDS
        ):
            return Result(op, "VERIFIED", status, "route matched; object absent")
        return Result(op, "MISSING", status, body[:160].replace("\n", " "))

    if status in _PATH_EXISTS:
        return Result(op, "VERIFIED", status)
    return Result(op, "ERROR", status, body[:160].replace("\n", " "))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--org", required=True, help="Capella organization id")
    parser.add_argument("--project", help="project id (discovered if omitted)")
    parser.add_argument("--cluster", help="cluster id (discovered if omitted)")
    parser.add_argument(
        "--only-pat", action="store_true", help="only the [PAT] inferred paths"
    )
    parser.add_argument(
        "--only", action="append", default=[], help="verify named operations only"
    )
    parser.add_argument(
        "--write-probe",
        action="store_true",
        help="ACTUALLY send the write method. Requires --only. Can create or delete.",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    token = os.environ.get("CB_CAPELLA_API_KEY", "").strip()
    if not token:
        print(
            "CB_CAPELLA_API_KEY is not set. It must be the API key SECRET, not its id.",
            file=sys.stderr,
        )
        return 2

    if args.write_probe and not args.only:
        print(
            "--write-probe requires --only; it will not be run across the whole surface.",
            file=sys.stderr,
        )
        return 2

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella.spec import OPS_BY_NAME

    ops = list(OPS_BY_NAME.values())
    if args.only:
        wanted = set(args.only)
        ops = [o for o in ops if o.name in wanted]
        unknown = wanted - {o.name for o in ops}
        if unknown:
            print(f"unknown operation(s): {sorted(unknown)}", file=sys.stderr)
            return 2
    elif args.only_pat:
        ops = [o for o in ops if "[PAT]" in (o.summary or "")]

    if not ops:
        print("no operations selected", file=sys.stderr)
        return 2

    print(f"Capella v4 path verification — {len(ops)} operation(s) against {BASE}")
    if args.write_probe:
        print("  *** --write-probe: real write methods WILL be sent ***")
    print("Discovering identifiers:")
    ids = discover(token, args)
    print()

    results = []
    for op in sorted(ops, key=lambda o: (o.group, o.name)):
        result = probe(op, ids, token, args.write_probe)
        results.append(result)
        if not args.json:
            tag = "[PAT]" if "[PAT]" in (op.summary or "") else "     "
            status = result.status if result.status is not None else "---"
            print(
                f"  {result.verdict:9} {tag} {op.method:7} {op.name:44} "
                f"{status} {result.detail}"
            )
        time.sleep(0.1)  # be polite to the control plane

    counts: dict[str, int] = {}
    for result in results:
        counts[result.verdict] = counts.get(result.verdict, 0) + 1

    if args.json:
        print(
            json.dumps(
                {
                    "base": BASE,
                    "counts": counts,
                    "results": [
                        {
                            "name": r.op.name,
                            "method": r.op.method,
                            "path": r.op.path,
                            "inferred": "[PAT]" in (r.op.summary or ""),
                            "verdict": r.verdict,
                            "status": r.status,
                            "detail": r.detail,
                        }
                        for r in results
                    ],
                },
                indent=2,
            )
        )
        return 1 if counts.get("MISSING") else 0

    print()
    print("  " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    missing = [r for r in results if r.verdict == "MISSING"]
    if missing:
        print()
        print("  PATHS THAT NEED FIXING IN handlers/capella/spec.py:")
        for r in missing:
            print(f"    {r.op.name}")
            print(f"      {r.op.method} {r.op.path}")
            print(f"      -> {r.detail}")

    skipped = [r for r in results if r.verdict == "SKIPPED"]
    if skipped:
        print()
        print("  Not exercised (no identifier available — not a failure):")
        for r in skipped:
            print(f"    {r.op.name}: {r.detail}")

    errors = [r for r in results if r.verdict == "ERROR"]
    if errors:
        print()
        print("  Errors (credentials or network, not a path verdict):")
        for r in errors:
            print(f"    {r.op.name}: {r.status} {r.detail}")

    return 1 if counts.get("MISSING") else 0


if __name__ == "__main__":
    sys.exit(main())
