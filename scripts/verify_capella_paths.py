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
Run it from the REPOSITORY ROOT, not from inside scripts/.

Windows PowerShell:

    $env:CB_CAPELLA_API_KEY = 'paste-the-key-secret-here'
    python scripts\verify_capella_paths.py --only-pat

Linux / macOS:

    export CB_CAPELLA_API_KEY='paste-the-key-secret-here'
    python3 scripts/verify_capella_paths.py --only-pat

Do NOT copy angle brackets out of a usage example on PowerShell. `<` is a reserved
redirection operator there, so the shell fails to parse the line before Python starts and
the error mentions redirection rather than this script.

The organization is discovered from the API key, which can only see organizations it
belongs to. Pass --org only if the key can see more than one (the script will say so and
list them). Add --project / --cluster to pin those if the org has several. Omit --only-pat
to check all 61 operations rather than the four inferred ones. --json gives
machine-readable output.

The key needs only read access for the default mode: create one under
Organization Settings -> API Keys with the Organization Member role plus read access to
the project you point it at. The value to use is the key SECRET, not the key id — that is
the usual stumble.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import pathlib
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


class _StaticOp:
    """An operation read straight out of the source, with no imports required."""

    __slots__ = ("body", "group", "method", "name", "path", "summary")

    def __init__(self, name, method, path, summary, group, body):
        self.name = name
        self.method = method
        self.path = path
        self.summary = summary
        self.group = group
        self.body = body


def _ops_by_static_parse(spec_path: str) -> list:
    """Read the Op(...) declarations out of spec.py with the ast module.

    WHY THIS EXISTS
    ---------------
    spec.py imports mcp.types to BUILD MCP tool objects, so importing it requires the
    MCP SDK and, transitively, a working project install. This script only needs the
    URL templates. Demanding a full dependency install in order to read a list of
    strings is friction in exactly the wrong place: the natural time to run this is on
    a laptop with a fresh checkout, or in a CI step that has installed nothing yet.

    Parsing the AST needs nothing but the standard library, and it cannot drift from
    the real registry because it reads the same declarations the server does.
    """
    tree = ast.parse(pathlib.Path(spec_path).read_text(encoding="utf-8"))
    ops = []

    def literal(node):
        try:
            return ast.literal_eval(node)
        except Exception:
            return None

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Op"):
            continue
        fields = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        name = literal(fields.get("name")) if "name" in fields else None
        path = literal(fields.get("path")) if "path" in fields else None
        if not name or not path:
            continue
        ops.append(
            _StaticOp(
                name=name,
                method=(literal(fields.get("method")) if "method" in fields else "GET")
                or "GET",
                path=path,
                # Concatenated string summaries are common here, and literal_eval
                # handles them; anything it cannot read becomes empty, which only
                # affects the [PAT] tag in the output.
                summary=(literal(fields.get("summary")) if "summary" in fields else "")
                or "",
                group=(literal(fields.get("group")) if "group" in fields else "") or "",
                body=(literal(fields.get("body")) if "body" in fields else None),
            )
        )
    return ops


_PLACEHOLDER_HINTS = (
    "<",
    ">",
    "your-",
    "your_",
    "organization_id",
    "api key secret",
    "the api key",
    "xxx",
    "todo",
    "replace",
)


def _looks_like_a_placeholder(value: str) -> bool:
    """Whether a value is obviously an unsubstituted example rather than a real one."""
    if not value:
        return False
    lowered = value.strip().lower()
    return any(hint in lowered for hint in _PLACEHOLDER_HINTS)


def load_ops() -> list:
    """Every operation, preferring the real registry and falling back to a static parse.

    The import is tried first because it is the authority — it is what the server
    actually runs. The fallback exists so a missing dependency does not stop someone
    verifying paths.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, root)
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    try:
        from handlers.capella.spec import OPS_BY_NAME

        return list(OPS_BY_NAME.values())
    except Exception as exc:
        spec_path = os.path.join(root, "handlers", "capella", "spec.py")
        ops = _ops_by_static_parse(spec_path)
        print(
            f"note: could not import the op registry ({type(exc).__name__}: {exc}); "
            f"read {len(ops)} operations directly from spec.py instead. "
            "Install the project to use the registry itself.",
            file=sys.stderr,
        )
        return ops


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--org",
        default=os.environ.get("CB_CAPELLA_ORG_ID", "").strip(),
        help=(
            "Capella organization id. Optional: if omitted it is discovered from the "
            "API key, which can only see the organizations it belongs to. May also be "
            "given as CB_CAPELLA_ORG_ID."
        ),
    )
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

    # Reject values that are obviously still a placeholder. Copying a usage line
    # verbatim is the single most common way to run this wrong, and on PowerShell a
    # literal <angle-bracket> placeholder is worse than wrong: `<` is a reserved
    # redirection operator, so the shell fails to parse the command before Python is
    # even started, with an error that says nothing about this script.
    for label, value in (("--org", args.org), ("CB_CAPELLA_API_KEY", token)):
        if _looks_like_a_placeholder(value):
            print(
                f"{label} still looks like a placeholder, not a real value: {value!r}\n"
                "Substitute the actual value. Note that on PowerShell you must not "
                "include the angle brackets from a usage example — `<` is a redirection "
                "operator there and the command will not parse.",
                file=sys.stderr,
            )
            return 2

    # Discover the organization from the key if it was not given. A Capella API key can
    # only see the organizations it belongs to, so this is unambiguous in the common
    # case of one, and it removes the most error-prone argument entirely.
    if not args.org:
        status, body = _request("GET", "/v4/organizations", token)
        orgs = []
        try:
            parsed = json.loads(body)
            items = parsed.get("data") if isinstance(parsed, dict) else parsed
            for item in items or []:
                data = item.get("data", item) if isinstance(item, dict) else {}
                if data.get("id"):
                    orgs.append((data["id"], data.get("name", "")))
        except Exception:
            orgs = []

        if len(orgs) == 1:
            args.org = orgs[0][0]
            print(f"Discovered organization: {orgs[0][0]}  {orgs[0][1]}".rstrip())
        elif len(orgs) > 1:
            print(
                "This API key can see several organizations; name the one you want "
                "with --org:",
                file=sys.stderr,
            )
            for oid, oname in orgs:
                print(f"  {oid}  {oname}".rstrip(), file=sys.stderr)
            return 2
        else:
            print(
                "Could not discover the organization from the API key "
                f"(GET /v4/organizations returned {status}).\n"
                f"  {body[:300]}\n"
                "Pass it explicitly with --org, or check that CB_CAPELLA_API_KEY is the "
                "key SECRET rather than its id.",
                file=sys.stderr,
            )
            return 2

    if args.write_probe and not args.only:
        print(
            "--write-probe requires --only; it will not be run across the whole surface.",
            file=sys.stderr,
        )
        return 2

    ops = load_ops()
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
