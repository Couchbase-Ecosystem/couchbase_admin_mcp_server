"""Put real data into `mcptest` so the admin tools have something to act on.

WHY THIS EXISTS
===============
A backup of an empty bucket succeeds and proves nothing. So do the stats tools,
the index tools and the search tools. Several of the SKIPPED verdicts in
`verify_mcp_surface.py` are not harness limits at all -- they are tools whose
arguments could not be resolved because there was no scope, no collection and no
index to discover.

WHAT IT MAKES
=============
The same shape on both sides, so a local Enterprise Edition run and a Capella
run are comparable rather than merely both green:

    mcptest / ops / events        ~2000 documents, a date range, a few statuses
    mcptest / ops / assets        ~200 documents referenced by the events
    mcptest / _default / _default a handful, so the default keyspace is not empty

    a primary index on ops.events, and a secondary index on (status, occurred_at)

IDEMPOTENT. Re-running upserts over the same keys rather than duplicating, so it
is safe to run before every verification pass.

USAGE
-----
    # local Enterprise Edition
    uv run python scripts/load_test_data.py

    # Capella (VPN OFF -- the data plane is allowlist-gated; see
    # CAPELLA-CONNECTIVITY.md, which records why the VPN question is still open)
    uv run python scripts/load_test_data.py --capella
"""

from __future__ import annotations

import argparse
import os
import random
import sys
from datetime import datetime, timedelta, timezone

SCOPE = "ops"
EVENTS = "events"
ASSETS = "assets"

#: Seeded, so two runs -- and the local and Capella sides -- produce identical
#: documents. A backup/restore comparison is only meaningful if both ends hold
#: the same bytes.
SEED = 20260912

STATUSES = ("ok", "degraded", "failed", "pending")
REGIONS = ("us-east-1", "us-west-2", "eu-west-1", "ap-southeast-2")


def _connect(args):
    try:
        from couchbase.auth import PasswordAuthenticator
        from couchbase.cluster import Cluster
        from couchbase.options import ClusterOptions
    except ImportError:
        sys.exit(
            "the couchbase SDK is not importable. Run this with `uv run python`, "
            "not a bare interpreter."
        )

    if args.capella:
        conn = os.environ.get("CB_CAPELLA_CONNECTION_STRING") or os.environ.get(
            "CB_CONNECTION_STRING"
        )
        user = os.environ.get("CB_CAPELLA_USERNAME") or os.environ.get("CB_USERNAME")
        pwd = os.environ.get("CB_CAPELLA_PASSWORD") or os.environ.get("CB_PASSWORD")
        if not conn or "cloud.couchbase.com" not in conn:
            sys.exit(
                "--capella needs CB_CAPELLA_CONNECTION_STRING (couchbases://...). "
                "A Capella DATABASE credential, not the org API key -- they are "
                "different objects and the API key cannot open a KV connection."
            )
    else:
        conn = os.environ.get("CB_CONNECTION_STRING") or "couchbase://localhost"
        user = os.environ.get("CB_USERNAME")
        pwd = os.environ.get("CB_PASSWORD")

    if not user or not pwd:
        sys.exit(
            "CB_USERNAME / CB_PASSWORD are not set. Run cbenv.bat, then a NEW shell."
        )

    print(f"connecting to {conn}")
    options = ClusterOptions(PasswordAuthenticator(user, pwd))
    if args.capella:
        # Capella terminates TLS with a public CA, so no cert file is needed --
        # but the SDK still needs to be told this is a TLS connection, which the
        # couchbases:// scheme does.
        options.apply_profile("wan_development")
    cluster = Cluster(conn, options)

    from datetime import timedelta as _td

    cluster.wait_until_ready(_td(seconds=args.timeout))
    return cluster


def _ensure_keyspaces(cluster, bucket_name: str) -> None:
    """Create the scope and collections if they are not there.

    Through the SDK's collection manager rather than SQL++ so this works before
    any index exists, and so a permission failure names the collection manager
    rather than surfacing as a query error.
    """
    from couchbase.exceptions import (
        CollectionAlreadyExistsException,
        ScopeAlreadyExistsException,
    )

    manager = cluster.bucket(bucket_name).collections()

    try:
        manager.create_scope(SCOPE)
        print(f"  created scope {SCOPE}")
    except ScopeAlreadyExistsException:
        print(f"  scope {SCOPE} already there")

    for collection in (EVENTS, ASSETS):
        try:
            manager.create_collection(SCOPE, collection)
            print(f"  created collection {SCOPE}.{collection}")
        except CollectionAlreadyExistsException:
            print(f"  collection {SCOPE}.{collection} already there")


def _assets(count: int) -> list[dict]:
    rng = random.Random(SEED)
    return [
        {
            "type": "asset",
            "asset_id": f"asset-{i:04d}",
            "name": f"Asset {i:04d}",
            "region": rng.choice(REGIONS),
            "capacity": rng.randint(10, 500),
            "tags": rng.sample(["ride", "queue", "retail", "food", "transit"], k=2),
        }
        for i in range(count)
    ]


def _events(count: int, asset_count: int) -> list[dict]:
    rng = random.Random(SEED + 1)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    out = []
    for i in range(count):
        occurred = start + timedelta(minutes=rng.randint(0, 60 * 24 * 240))
        out.append(
            {
                "type": "event",
                "event_id": f"event-{i:05d}",
                "asset_id": f"asset-{rng.randrange(asset_count):04d}",
                "status": rng.choice(STATUSES),
                "occurred_at": occurred.isoformat(),
                "duration_ms": rng.randint(1, 30_000),
                "wait_minutes": rng.randint(0, 180),
                "notes": f"synthetic record {i} for MCP admin surface verification",
            }
        )
    return out


def _upsert(collection, documents: list[dict], key: str) -> int:
    written = 0
    for doc in documents:
        collection.upsert(doc[key], doc)
        written += 1
        if written % 500 == 0:
            print(f"    {written}/{len(documents)}")
    return written


def _index(cluster, bucket: str) -> None:
    """Primary plus one secondary.

    The secondary is what makes the index tools, the plan analysis tools and the
    stats tools return something other than an empty list -- and an EXPLAIN over
    an index that does not exist is not a test of anything.
    """
    statements = [
        f"CREATE PRIMARY INDEX IF NOT EXISTS ON `{bucket}`.`{SCOPE}`.`{EVENTS}`",
        f"CREATE PRIMARY INDEX IF NOT EXISTS ON `{bucket}`.`{SCOPE}`.`{ASSETS}`",
        (
            f"CREATE INDEX IF NOT EXISTS idx_events_status_time "
            f"ON `{bucket}`.`{SCOPE}`.`{EVENTS}`(`status`, `occurred_at`)"
        ),
        (
            f"CREATE INDEX IF NOT EXISTS idx_events_asset "
            f"ON `{bucket}`.`{SCOPE}`.`{EVENTS}`(`asset_id`)"
        ),
    ]
    for statement in statements:
        label = statement.split("ON")[0].strip()
        try:
            cluster.query(statement).execute()
            print(f"  {label}")
        except Exception as exc:
            print(f"  {label} FAILED: {type(exc).__name__}: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", default=os.environ.get("CB_BUCKET") or "mcptest")
    parser.add_argument("--events", type=int, default=2000)
    parser.add_argument("--assets", type=int, default=200)
    parser.add_argument("--capella", action="store_true")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument(
        "--skip-indexes",
        action="store_true",
        help="load documents only; use if the Index service is not on this cluster",
    )
    args = parser.parse_args()

    side = "Capella" if args.capella else "local / self-managed"
    print(f"\n== loading {args.bucket} on {side} ==\n")

    cluster = _connect(args)
    bucket = cluster.bucket(args.bucket)

    print("keyspaces:")
    _ensure_keyspaces(cluster, args.bucket)

    scope = bucket.scope(SCOPE)
    print("\ndocuments:")
    n = _upsert(scope.collection(ASSETS), _assets(args.assets), "asset_id")
    print(f"  {SCOPE}.{ASSETS}: {n}")
    n = _upsert(scope.collection(EVENTS), _events(args.events, args.assets), "event_id")
    print(f"  {SCOPE}.{EVENTS}: {n}")

    default = bucket.default_collection()
    for i in range(5):
        default.upsert(f"marker-{i}", {"type": "marker", "n": i})
    print("  _default._default: 5")

    if args.skip_indexes:
        print("\nindexes: skipped by request")
    else:
        print("\nindexes:")
        _index(cluster, args.bucket)

    print("\nverifying by reading back:")
    total = args.events + args.assets + 5
    try:
        rows = list(
            cluster.query(
                f"SELECT COUNT(*) AS n FROM `{args.bucket}`.`{SCOPE}`.`{EVENTS}`"
            )
        )
        counted = rows[0]["n"] if rows else 0
        print(f"  {SCOPE}.{EVENTS} holds {counted} documents")
        if counted < args.events:
            print(
                f"  NOTE: expected {args.events}. Indexes are eventually "
                "consistent; re-read in a few seconds before concluding anything."
            )
    except Exception as exc:
        print(f"  count query failed ({type(exc).__name__}: {exc})")
        print(
            "  the documents may still be there -- this is the INDEX, not the KV write."
        )

    print(f"\ndone. ~{total} documents in {args.bucket}.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
