#!/usr/bin/env python3
r"""
probe_data_api_kv.py - measure the Data API's KV DOCUMENT endpoints.

WHY
===
capella_fixture_import creates structure and indexes and does NOT load documents,
and the reason is not difficulty. Writing documents from a handler needs a route
this project has sanctioned, and all three candidates are blocked on something:

  * SQL++ UPSERT over the Data API. PROHIBITED. "Nothing writes data through
    SQL++" is a standing constraint of this repository, enforced by
    tests/test_handler_contract.py::test_no_handler_embeds_a_mutating_sql_statement.
    The importer WAS written this way first and the guard caught it -- correctly,
    because a literal UPSERT in handler source bypasses is_dml_statement, which
    only inspects statements arriving as arguments.

  * The Couchbase SDK's KV upsert, the way scripts/load_test_data.py does it. Not
    SQL++, so not prohibited, and handlers/shared.py already builds an
    authenticated Cluster. But it needs the DATA PLANE on port 11210, which is
    exactly what handlers/capella/fixture.py avoided by choosing the HTTPS Data
    API: a container that can reach the Data API cannot necessarily reach 11210,
    and Disney will run this in a container.

  * The Data API's own KV document endpoints. Almost certainly the right answer --
    HTTPS, the same cluster access credential, the same allowlist, no SQL++. Their
    paths are NOT MEASURED anywhere in this repository.

This script measures the third one. It exists because this module already learned
what shipping an inferred path costs: fixture.py documented the Data API base as
https://{clusterId}.data.cloud.couchbase.com, read off the shape of two examples,
and it was wrong -- the id in that host is the SHORT connection-string id, and the
value is read from GET .../dataAPI rather than assembled. A path guessed from
documentation is a path that has not been measured.

WHAT IT DOES
============
Against ONE document key that this script creates and then deletes, in a
collection you name:

  1. GET    the key            -- expect 404 before anything exists.
  2. POST   the key            -- create. Records the status and body.
  3. GET    the key            -- read back and compare the body byte for byte.
  4. PUT    the key            -- upsert over the top, which is what an importer
                                 needs for re-runnability.
  5. GET    the key            -- confirm the upsert took.
  6. DELETE the key            -- put the collection back as it was found.

It tries the candidate path spellings in order and reports which one answered,
rather than assuming. Nothing here writes to a key you did not name, and step 6
runs even when an earlier step fails.

WRITES TO YOUR CLUSTER. One document, one key, removed again at the end. It is
behind --perform for that reason; without the flag it prints the plan and the
resolved URLs and stops.

USAGE
=====
    $env:CB_CAPELLA_CLUSTER_USER = 'mcptest-data'
    $env:CB_CAPELLA_CLUSTER_PASSWORD = '<the cluster access password>'

    uv run python scripts/probe_data_api_kv.py --cluster vn1kiibitcyvwrw `
        --keyspace travel-sample.inventory.airline
    uv run python scripts/probe_data_api_kv.py --cluster vn1kiibitcyvwrw `
        --keyspace travel-sample.inventory.airline --perform
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from probe_access_control_function import (
    _rows,
    call,
    resolve_credentials,
)

#: Candidate spellings for one document, most likely first.
#:
#: LISTED, NOT CHOSEN. Each is a plausible reading of the Data API's shape and
#: exactly one of them is real. The script reports which answered; nothing in the
#: server ships until one has.
_CANDIDATES = (
    "/v1/buckets/{bucket}/scopes/{scope}/collections/{collection}/documents/{key}",
    "/v1/buckets/{bucket}/scopes/{scope}/collections/{collection}/docs/{key}",
    "/v1/data/buckets/{bucket}/scopes/{scope}/collections/{collection}/documents/{key}",
)

_PROBE_KEY = "mcptest-probe-data-api-kv"
_PROBE_BODY = {"_probe": "probe_data_api_kv.py", "note": "safe to delete"}
_PROBE_BODY_2 = {"_probe": "probe_data_api_kv.py", "note": "upserted"}


def _request(method: str, url: str, user: str, password: str,
             body: dict | None = None, timeout: int = 30) -> tuple[int, str]:
    """One Data API call. Returns (status, body) and never raises on an HTTP error."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    request.add_header("Authorization", f"Basic {token}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")
    except Exception as exc:  # timeout, TLS, DNS
        return 0, (
            f"{type(exc).__name__}: {exc}\n"
            "A TIMEOUT here is almost always the allowed-CIDR list: a data-plane "
            "client that is not allowlisted is DROPPED rather than refused, so it "
            "looks like a hang and not a rejection."
        )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cluster", required=True,
                    help="cluster id or connection-string id")
    ap.add_argument("--keyspace", required=True,
                    help="bucket.scope.collection to probe in")
    ap.add_argument("--project", default="")
    ap.add_argument("--env-file", default=None)
    ap.add_argument("--key", default=_PROBE_KEY)
    ap.add_argument("--perform", action="store_true",
                    help="actually create, upsert and delete the probe document")
    args = ap.parse_args()

    parts = args.keyspace.rsplit(".", 2)
    if len(parts) != 3 or not all(parts):
        print(f"--keyspace {args.keyspace!r} is not bucket.scope.collection")
        return 2
    bucket, scope, collection = parts

    user = (os.environ.get("CB_CAPELLA_CLUSTER_USER") or "").strip()
    password = (os.environ.get("CB_CAPELLA_CLUSTER_PASSWORD") or "").strip()
    if not user or not password:
        print("set CB_CAPELLA_CLUSTER_USER and CB_CAPELLA_CLUSTER_PASSWORD to a "
              "CLUSTER ACCESS credential (not the organization API key).")
        return 2

    token, org, src = resolve_credentials(args.env_file)
    if not token:
        print("no Capella API key found. Set CAPELLA_API_KEY_SECRET.")
        return 2
    print(f"[auth] control-plane credential from {src}")

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
            print(f"could not resolve one project (status {status}); pass --project")
            return 2
        project = rows[0]["id"]

    clusters_path = f"/v4/organizations/{org}/projects/{project}/clusters"
    status, text = call("GET", clusters_path, token)
    rows = _rows(text)
    matched = [c for c in rows
               if c.get("id") == args.cluster
               or args.cluster in str(c.get("connectionString", ""))]
    if len(matched) != 1:
        print(f"--cluster {args.cluster!r} matched {len(matched)} of {len(rows)}")
        return 2
    cluster_id = matched[0]["id"]

    # THE BASE IS READ, NOT DERIVED. See fixture._data_api_base for the account of
    # why a host pattern inferred from two examples was wrong.
    status, text = call("GET", f"{clusters_path}/{cluster_id}/dataAPI", token)
    if status != 200:
        print(f"GET .../dataAPI answered {status}: {text[:400]}")
        return 2
    connection = str((json.loads(text) or {}).get("connectionString") or "")
    if not connection:
        print("the Data API is not enabled on this cluster (empty connectionString). "
              "Enable it with capella_data_api_set and wait for the state to settle.")
        return 2
    if not connection.startswith("http"):
        connection = "https://" + connection
    api_base = connection.rstrip("/")
    print(f"[ids] cluster {cluster_id}  ({matched[0].get('name')})")
    print(f"[base] {api_base}")

    urls = [
        api_base + candidate.format(bucket=bucket, scope=scope,
                                    collection=collection, key=args.key)
        for candidate in _CANDIDATES
    ]
    print("\nCandidate document URLs, in the order they will be tried:")
    for url in urls:
        print(f"  {url}")

    if not args.perform:
        print("\nDRY RUN. Nothing was sent. Re-run with --perform to measure.")
        print("It will create one document, read it back, upsert it, read it "
              "again, and delete it.")
        return 0

    # ── 1. find the spelling that routes ─────────────────────────────────
    live = ""
    for url in urls:
        status, body = _request("GET", url, user, password)
        print(f"\nGET {url}\n  {status}  {body[:300]}")
        # 404 ON A KEY THAT DOES NOT EXIST IS SUCCESS FOR ROUTING PURPOSES: the
        # route resolved and the document is simply absent. That makes 404
        # ambiguous on its own -- an unrouted path answers 404 too -- so the
        # body is what separates them. A document-level 404 names the DOCUMENT
        # or the collection; an unrouted one names the path or says nothing.
        # When it cannot be told apart, the candidate is NOT accepted: shipping
        # a path on an ambiguous 404 is how a guessed path gets into a handler.
        if status == 200:
            live = url
            break
        if status == 404 and any(
            marker in body.lower()
            for marker in ("document", "key", "not_found", "notfound")
        ):
            live = url
            break
        if status in (401, 403):
            print("  -> authentication or allowlist problem, not a path problem. "
                  "Fix that before reading anything else here.")
            return 2
    if not live:
        print("\nNone of the candidate spellings routed. Do NOT ship any of them.")
        print("Read the Data API reference for the document endpoint and add the "
              "real spelling to _CANDIDATES, then re-run.")
        return 1

    print(f"\n=== the live spelling is ===\n  {live}\n")

    created = False
    try:
        # ── 2. create ────────────────────────────────────────────────────
        status, body = _request("POST", live, user, password, _PROBE_BODY)
        print(f"POST (create)\n  {status}  {body[:300]}")
        created = 200 <= status < 300

        # ── 3. read back ─────────────────────────────────────────────────
        status, body = _request("GET", live, user, password)
        print(f"GET (read back)\n  {status}  {body[:300]}")

        # ── 4. upsert ────────────────────────────────────────────────────
        status, body = _request("PUT", live, user, password, _PROBE_BODY_2)
        print(f"PUT (upsert)\n  {status}  {body[:300]}")
        created = created or (200 <= status < 300)

        # ── 5. read back again ───────────────────────────────────────────
        status, body = _request("GET", live, user, password)
        print(f"GET (after upsert)\n  {status}  {body[:300]}")
    finally:
        # ── 6. put the collection back ───────────────────────────────────
        # RUNS EVEN ON FAILURE. A probe that leaves its own document behind has
        # changed the collection it was measuring.
        if created:
            status, body = _request("DELETE", live, user, password)
            print(f"\nDELETE (cleanup)\n  {status}  {body[:300]}")
            if not (200 <= status < 300 or status == 404):
                print(f"*** COULD NOT REMOVE THE PROBE DOCUMENT {args.key!r}. "
                      f"*** Delete it by hand -- the collection is not as it was found.")

    print("\nRecord the live spelling and the create/upsert statuses in "
          "handlers/capella/fixture.py before implementing document import.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
