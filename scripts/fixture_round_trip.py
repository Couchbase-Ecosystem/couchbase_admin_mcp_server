"""Prove a fixture family by round-tripping it: export, import elsewhere, export back, compare.

WHY THIS EXISTS, AND WHY NOTHING ELSE WILL DO
=============================================
On 2026-09-14 the Capella fixture exporter was writing the WRONG DOCUMENT KEY for
every document whose body happened to contain a field called `id`. The export
query read

    SELECT META().id AS id, META().expiration AS exp, d.*

and `d.*` comes last, so a document's own `id` field overwrote the metadata
alias. travel-sample's airline documents are `{"id": 10, ...}` keyed
`airline_10`; every exported fixture recorded `10`. Popping `id` off the row to
use as the key then stripped that field from the body as well, so the payload was
lossy on top of being mis-keyed.

**Nothing caught it.** Not the per-file sha256, not the line counts, not
`capella_fixture_verify`'s cluster-side `COUNT(*)`. Every one of those checks
compares a fixture against ITSELF: the hash of a wrong file still matches the
hash recorded for that wrong file, and 188 wrong documents still count as 188.

What found it was a round trip. Export, import into a scratch keyspace, export
back, compare the two exports: 187 of 188 KEYS differed while zero BODIES did.
The single key that matched was `_sync:syncInfo`, whose body has no fields at
all — which is itself the diagnosis, sitting in the output.

So this script is not a convenience. It is the only check in this repository
that compares a fixture against something other than itself, and it is what
turns "carefully written code" into "a verified capability" for either plane.

    A count is a necessary condition. A round trip is closer to a sufficient one.

WHAT IT DOES
============
    1. export   source keyspace            -> <work>/first
    2. import   <work>/first               -> the scratch keyspace
    3. export   the scratch keyspace       -> <work>/second
    4. compare  first vs second, per key AND per body
    5. report   what to delete, and refuse to delete it itself

Step 5 is deliberate. This script creates a scope on somebody's cluster and does
not remove it: a verification tool that deletes things is a verification tool
that can destroy the evidence of the failure it just found. It prints the tool
call to run.

USAGE
-----
Capella:

    uv run python scripts\\fixture_round_trip.py --plane capella ^
        --keyspace travel-sample.inventory.airline ^
        --scratch travel-sample.roundtrip.airline ^
        --work C:\\Work\\Development\\roundtrip ^
        --perform

Enterprise Edition:

    uv run python scripts\\fixture_round_trip.py --plane ee ^
        --keyspace travel-sample.inventory.airline ^
        --scratch travel-sample.roundtrip.airline ^
        --work C:\\Work\\Development\\roundtrip-ee ^
        --perform

Without `--perform` it prints the four calls it WOULD make and exits, so the
plan can be read before anything runs. The exports are reads either way; the
import is the only write, and it needs `--perform`.

Capella additionally needs the cluster ids that every other Capella script
needs — CAPELLA_ORG_ID, CAPELLA_PROJECT_ID, CAPELLA_CLUSTER_ID — plus the Data
API enabled and CB_CAPELLA_CLUSTER_USER / CB_CAPELLA_CLUSTER_PASSWORD set.
Enterprise Edition needs only what the server already needs to reach ns_server.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
import sys
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

#: Which tool names each plane uses. The two families are deliberately separate
#: implementations sharing one manifest format -- see docs/FIXTURE_DESIGN.md --
#: so the round trip is the same procedure over different tools.
_TOOLS = {
    "capella": {
        "export": "capella_fixture_export",
        "import": "capella_fixture_import",
        "verify": "capella_fixture_verify",
    },
    "ee": {
        "export": "admin_fixture_export",
        "import": "admin_fixture_import",
        "verify": "admin_fixture_verify",
    },
}

#: Capella's tools take the cluster by id; EE's take it from the connection.
_CAPELLA_IDS = {
    "organization_id": "CAPELLA_ORG_ID",
    "project_id": "CAPELLA_PROJECT_ID",
    "cluster_id": "CAPELLA_CLUSTER_ID",
}


def _client_env(*, perform: bool) -> dict[str, str]:
    """Writes advertised, dry run lowered ONLY when performing.

    Same shape as scripts/dump_tool.py deliberately. The import still needs its
    own `confirm: true` in the arguments -- this lowers the dry run, not the
    confirmation gate.
    """
    env = dict(os.environ)
    env["CB_ADMIN_TRANSPORT"] = "stdio"
    env.setdefault("CB_ADMIN_PROFILE", "workstation")
    env.setdefault("PYTHONUNBUFFERED", "1")
    env["CB_ADMIN_READ_ONLY_MODE"] = "false"
    env["CB_ADMIN_DRY_RUN"] = "false" if perform else "true"
    return env


def _payload(response: Any) -> Any:
    for block in getattr(response, "content", None) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
    return None


def _capella_ids() -> dict[str, str]:
    ids = {}
    missing = []
    for field, variable in _CAPELLA_IDS.items():
        value = (os.environ.get(variable) or "").strip()
        if not value:
            missing.append(variable)
        else:
            ids[field] = value
    if missing:
        raise SystemExit(
            f"the Capella plane needs {missing} in the environment. Typing a "
            f"uuid three times is how the wrong uuid gets typed, so they are "
            f"read from there rather than from flags."
        )
    return ids


# ── the comparison, which is the whole point ─────────────────────────────────


def _read_rows(path: pathlib.Path) -> dict[str, dict]:
    """{document key: row} from one JSON Lines payload file.

    A DUPLICATE KEY IS A FINDING, not something to overwrite silently. Two rows
    with the same key in one export means the exporter's pagination repeated a
    page, and collapsing them here would hide exactly that.
    """
    rows: dict[str, dict] = {}
    duplicates: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            key = row.get("id")
            if key in rows:
                duplicates.append(f"{key!r} appears twice (line {number})")
                continue
            rows[key] = row
    if duplicates:
        raise SystemExit(
            f"{path} contains duplicate document keys, which means the export "
            f"paged over the same rows twice:\n  " + "\n  ".join(duplicates)
        )
    return rows


def _payload_files(fixture: pathlib.Path) -> list[pathlib.Path]:
    data = fixture / "data"
    return sorted(data.glob("*.jsonl")) if data.is_dir() else []


def compare(first: pathlib.Path, second: pathlib.Path) -> dict:
    """Compare two exports of what should be the same data.

    REPORTS KEYS AND BODIES SEPARATELY, and that separation is the diagnosis.
    The Capella bug produced 187 differing keys and ZERO differing bodies, which
    says immediately that the document CONTENT survived the trip and the KEY did
    not -- a completely different repair from the other way round.
    """
    first_files = _payload_files(first)
    second_files = _payload_files(second)
    if not first_files:
        raise SystemExit(
            f"{first} holds no payload files. Either the source keyspace was "
            f"empty -- in which case this round trip proves nothing and needs a "
            f"keyspace with documents in it -- or the export failed."
        )

    first_rows: dict[str, dict] = {}
    for path in first_files:
        first_rows.update(_read_rows(path))
    second_rows: dict[str, dict] = {}
    for path in second_files:
        second_rows.update(_read_rows(path))

    only_first = sorted(set(first_rows) - set(second_rows))
    only_second = sorted(set(second_rows) - set(first_rows))
    shared = sorted(set(first_rows) & set(second_rows))

    body_differences = []
    expiry_differences = []
    for key in shared:
        if first_rows[key].get("doc") != second_rows[key].get("doc"):
            body_differences.append(key)
        if first_rows[key].get("exp") != second_rows[key].get("exp"):
            expiry_differences.append(key)

    # THE TELL. Bodies that all match while keys do not is the signature of a
    # metadata alias being overwritten by a document field, which is the exact
    # bug this script was written after. Naming it here means the next person
    # does not have to re-derive the diagnosis from two lists of uuids.
    signature = None
    if only_first and not body_differences and len(shared) < len(first_rows):
        signature = (
            "KEYS DIFFER AND BODIES DO NOT. That is the signature of the export "
            "recording something other than the document key -- a metadata "
            "alias overwritten by a document field of the same name. Check the "
            "export statement's aliases before looking anywhere else: "
            "handlers/fixture_core.py, META_ID_ALIAS."
        )

    return {
        "first": str(first),
        "second": str(second),
        "first_documents": len(first_rows),
        "second_documents": len(second_rows),
        "keys_matching": len(shared),
        "keys_only_in_first": only_first[:20],
        "keys_only_in_first_total": len(only_first),
        "keys_only_in_second": only_second[:20],
        "keys_only_in_second_total": len(only_second),
        "bodies_differing": body_differences[:20],
        "bodies_differing_total": len(body_differences),
        "expiries_differing_total": len(expiry_differences),
        "identical": (not only_first and not only_second and not body_differences),
        "signature": signature,
    }


# ── the run ──────────────────────────────────────────────────────────────────


async def run(args) -> int:
    from mcp import ClientSession, StdioServerParameters, stdio_client

    tools = _TOOLS[args.plane]
    work = pathlib.Path(args.work).expanduser().resolve()
    first = work / "first"
    second = work / "second"

    base: dict[str, Any] = _capella_ids() if args.plane == "capella" else {}

    export_first = dict(
        base,
        fixture_id="roundtrip-first",
        fixture_path=str(first),
        keyspaces=[args.keyspace],
        include_data=True,
        tags={"purpose": "round trip", "stage": "first"},
    )
    import_args = dict(
        base,
        fixture_path=str(first),
        keyspace_map={args.keyspace: args.scratch},
        confirm=True,
    )
    export_second = dict(
        base,
        fixture_id="roundtrip-second",
        fixture_path=str(second),
        keyspaces=[args.scratch],
        include_data=True,
        tags={"purpose": "round trip", "stage": "second"},
    )

    plan = [
        (tools["export"], export_first),
        (tools["import"], import_args),
        (tools["export"], export_second),
    ]

    if not args.perform:
        print("PLAN ONLY. Nothing was called. Re-run with --perform.\n")
        for name, arguments in plan:
            print(f"  {name}")
            print("    " + json.dumps(arguments, indent=4).replace("\n", "\n    "))
        print(
            "\nThe two exports are reads. The import is the only write, and it "
            "\ncreates the scratch scope and collection on the cluster."
        )
        return 0

    params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(REPO_ROOT, "server.py")],
        env=_client_env(perform=True),
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=args.timeout)
            advertised = {t.name for t in (await session.list_tools()).tools}

            missing = [name for name, _ in plan if name not in advertised]
            if missing:
                print(f"these tools are not advertised in this posture: {missing}")
                print(
                    "The deployment mode decides which family loads. A Capella "
                    "round trip needs CB_DEPLOYMENT=capella; an EE one needs "
                    "self_managed. One container, one control plane."
                )
                return 2

            for step, (name, arguments) in enumerate(plan, start=1):
                print(f"\n=== {step}/{len(plan)}  {name}")
                response = await asyncio.wait_for(
                    session.call_tool(name, arguments), timeout=args.timeout
                )
                payload = _payload(response)
                print(json.dumps(payload, indent=1)[: args.print_limit])
                if getattr(response, "isError", False):
                    print(
                        f"\n{name} FAILED. Stopping here: the comparison below "
                        f"would be between a fixture and nothing."
                    )
                    return 1

    print("\n=== comparison")
    try:
        report = compare(first, second)
    except SystemExit as exc:
        print(str(exc))
        return 1
    print(json.dumps(report, indent=1))

    print(
        f"\nThe scratch keyspace {args.scratch} was CREATED and is NOT removed "
        f"by this script.\nA verification tool that deletes things can destroy "
        f"the evidence of the failure it just found.\nRemove it yourself when "
        f"you are done reading the result."
    )

    if report["identical"]:
        print(
            f"\nROUND TRIP CLEAN: {report['first_documents']} documents went out "
            f"and came back with the same keys, bodies and expiries.\n"
            f"That is the strongest statement available about this fixture "
            f"family on this plane."
        )
        return 0

    print("\nROUND TRIP DID NOT MATCH.")
    if report["signature"]:
        print(report["signature"])
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export, import elsewhere, export back, compare.",
    )
    parser.add_argument(
        "--plane",
        choices=sorted(_TOOLS),
        required=True,
        help="capella uses capella_fixture_*; ee uses admin_fixture_*",
    )
    parser.add_argument(
        "--keyspace",
        required=True,
        help="source bucket.scope.collection, with documents in it",
    )
    parser.add_argument(
        "--scratch",
        required=True,
        help="bucket.scope.collection to import INTO. Must not "
        "be the source, and should not be anything you "
        "mind being overwritten.",
    )
    parser.add_argument("--work", required=True, help="directory for the two exports")
    parser.add_argument(
        "--perform",
        action="store_true",
        help="actually run it. Without this the plan is printed and nothing is called.",
    )
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--print-limit", type=int, default=4000)
    args = parser.parse_args()

    if args.keyspace == args.scratch:
        raise SystemExit(
            "--scratch must differ from --keyspace. Importing a fixture back "
            "over its own source would overwrite the data being verified, and a "
            "comparison against data this script just rewrote proves nothing."
        )
    for field in ("keyspace", "scratch"):
        value = getattr(args, field)
        if len(value.rsplit(".", 2)) != 3:
            raise SystemExit(
                f"--{field} must be bucket.scope.collection, got {value!r}"
            )

    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
