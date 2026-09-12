"""Find a connection string the SDK can actually use against a local cluster.

WHY THIS EXISTS
===============
A containerised Couchbase advertises its node address from inside the container
network -- 172.18.0.2 on this laptop. REST keeps working, because that is reached
on a published port. Every SDK call hangs, because the SDK bootstraps, reads the
cluster map, and dials an address the host cannot route to. The two symptoms look
nothing alike and the second one is silent.

Alternate addresses are the documented fix, but setting them is not sufficient on
its own: with `network=auto` the SDK selects the external map only when the
bootstrap host MATCHES an advertised alternate hostname, and `localhost` is not
the string `127.0.0.1`. So a cluster can be correctly configured and still be
unreachable from a client that spelled the host differently.

This tries each variant with a short timeout and reports which ones work, instead
of one 30-second hang at a time with a hypothesis attached to each.

    uv run python scripts/probe_local_sdk.py
    uv run python scripts/probe_local_sdk.py --port 21210   # the two-node cluster
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import timedelta


def variants(port: int | None) -> list[str]:
    suffix = f":{port}" if port else ""
    return [
        f"couchbase://localhost{suffix}",
        f"couchbase://127.0.0.1{suffix}",
        f"couchbase://localhost{suffix}?network=external",
        f"couchbase://127.0.0.1{suffix}?network=external",
        f"couchbase://127.0.0.1{suffix}?network=default",
    ]


def probe(connection: str, username: str, password: str, seconds: float) -> str:
    """Try one connection string. Returns a one-line verdict."""
    from couchbase.auth import PasswordAuthenticator
    from couchbase.cluster import Cluster
    from couchbase.options import ClusterOptions

    try:
        cluster = Cluster(
            connection, ClusterOptions(PasswordAuthenticator(username, password))
        )
        cluster.wait_until_ready(timedelta(seconds=seconds))
    # A bare `except Exception` on purpose: the exception IS the result here.
    except Exception as exc:
        # The message matters more than the type. A timeout and an auth failure
        # are both "did not connect" and mean entirely different things.
        text = str(exc).replace("\n", " ")[:160]
        return f"FAILED  {type(exc).__name__}: {text}"

    # Connecting is not the same as being able to read. A cluster whose map points
    # somewhere unroutable can still answer wait_until_ready in some versions, so
    # the useful probe is one that needs a second round trip.
    try:
        names = sorted(b for b in cluster.buckets().get_all_buckets())
    except Exception as exc:
        return f"PARTIAL ready, but listing buckets failed: {type(exc).__name__}"
    return f"OK      {len(names)} bucket(s)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=None, help="Non-default KV port.")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args(argv)

    username = os.environ.get("CB_USERNAME", "")
    password = os.environ.get("CB_PASSWORD", "")
    if not username or not password:
        raise SystemExit("CB_USERNAME and CB_PASSWORD must be set. Run cbenv.bat.")

    print(f"user    : {username}")
    print(f"timeout : {args.timeout:g}s per variant")
    print()

    working = []
    for connection in variants(args.port):
        print(f"  {connection:<48} ", end="", flush=True)
        verdict = probe(connection, username, password, args.timeout)
        print(verdict)
        if verdict.startswith("OK"):
            working.append(connection)

    print()
    if working:
        print("  Use this in CB_CONNECTION_STRING:")
        print(f"    $env:CB_CONNECTION_STRING = '{working[0]}'")
        return 0

    print("  None worked. The cluster map is still pointing somewhere unroutable.")
    print("  Check what it advertises:")
    print("    GET /pools/nodes -> .nodes.hostname and .nodes.alternateAddresses")
    print("  A private address there with no matching alternate address is the cause.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
