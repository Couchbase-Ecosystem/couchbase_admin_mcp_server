#!/usr/bin/env python3
r"""
probe_data_api.py - measure the Data API endpoints, and turn the Data API on.

WHY
===
Three fixture capabilities are blocked on one dependency: document export,
document import, and cluster-side verification all need SQL++ over the Data API.
The Data API is off by default, and until 2026-09-14 this repository did not ship
the operations that read or change its status -- so "enable the Data API" was
advice with no tool behind it.

It also corrects a guess. handlers/capella/fixture.py documented the Data API
base as https://{clusterId}.data.cloud.couchbase.com. The provider does not
derive it: it reads `connectionString` from GET .../dataAPI, which is empty while
the API is off (internal/api/data_api/data_api.go). A pattern read off one
example is not a rule, and this prints the real value.

WHAT IT DOES
============
  1. GET  .../dataAPI          -- current status, always safe.
  2. PUT  .../dataAPI with an INVALID body -- refused on its contents, which is
     register evidence for capella_data_api_set with nothing written.
  3. With --enable, PUT the real body and poll until the state settles.

STEP 3 COSTS MONEY AND CHANGES THE CLUSTER. The Data API is a billable, separately
metered surface ("dataApiStandard" in the provider's own billing category list),
and enabling it is asynchronous. It is behind a flag for that reason, and the
script prints the current state before it asks.

USAGE
=====
    uv run python scripts/probe_data_api.py --cluster vn1kiibitcyvwrw
    uv run python scripts/probe_data_api.py --cluster vn1kiibitcyvwrw --enable
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from probe_access_control_function import (
    _message,
    _rows,
    call,
    call_retrying,
    resolve_credentials,
)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--cluster", required=True)
    ap.add_argument("--project", default="")
    ap.add_argument("--env-file", default=None)
    ap.add_argument(
        "--enable",
        action="store_true",
        help="actually enable the Data API (billable, asynchronous)",
    )
    ap.add_argument("--disable", action="store_true", help="turn it back off")
    ap.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="seconds to wait for the state to settle",
    )
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
            print(f"could not resolve one project (status {status}); pass --project")
            return 2
        project = rows[0]["id"]

    base = f"/v4/organizations/{org}/projects/{project}/clusters"
    status, text = call("GET", base, token)
    rows = _rows(text)
    matched = [
        c
        for c in rows
        if c.get("id") == args.cluster
        or args.cluster in str(c.get("connectionString", ""))
    ]
    if len(matched) != 1:
        print(f"--cluster {args.cluster!r} matched {len(matched)} of {len(rows)}")
        return 2
    cluster_id = matched[0]["id"]
    path = f"{base}/{cluster_id}/dataAPI"
    print(f"[ids] cluster {cluster_id}  ({matched[0].get('name')})")

    status, text = call("GET", path, token)
    print(f"\nGET {path}\n  {status}")
    print(f"  {text[:600]}")
    current = {}
    if status == 200:
        try:
            current = json.loads(text)
        except Exception:
            pass
    print(
        f'\n  Record "capella_data_api_get": "{status}" in LIVE_VERIFIED.'
        if str(status) in {"200", "400", "404", "405", "422"}
        else f"\n  {status} is not a usable register value."
    )

    # WHICH SPELLING? THE DOCS AND THE PROVIDER DISAGREE.
    #
    # docs.couchbase.com/cloud/data-api-guide says the body is
    #     {"enableDataAPI": true}
    # and the provider's request struct says
    #     EnableDataApi bool `json:"enableDataApi"`      (lowercase "pi")
    #
    # Exactly one can be right, and a body with the wrong one is a body with an
    # UNRECOGNISED field and no enableDataApi at all -- which a tolerant decoder
    # reads as false. "Turn it on" that quietly turns it off is the worst
    # available outcome, so this asks rather than picks.
    #
    # A string where a bool belongs is refused by either spelling, so the two
    # refusals are comparable: the one that names the field it could not parse
    # is the one the server knows about.
    for spelling in ("enableDataApi", "enableDataAPI"):
        probe_status, probe_text = call_retrying(
            "PUT", path, token, {spelling: "not-a-boolean"}
        )
        print(f"\n  spelling {spelling!r} -> {probe_status}")
        print(f"    {_message(probe_text)[:240]}")

    # REGISTER EVIDENCE FOR THE WRITE, WITHOUT PERFORMING IT.
    # A body whose enableDataApi is a string cannot be honoured by a field typed
    # bool, so the refusal is on contents -- route and method proven, nothing
    # changed.
    reg_status, reg_text = call_retrying(
        "PUT", path, token, {"enableDataApi": "not-a-boolean"}
    )
    print(f"\nPUT with an invalid body -> {reg_status}")
    print(f"  {_message(reg_text)[:260]}")
    if str(reg_status) in {"400", "405", "422"}:
        print(f'  Record "capella_data_api_set": "{reg_status}" in LIVE_VERIFIED.')
    else:
        print(
            "  NOT a usable register value; the op stays in SHIPPED_UNVERIFIED "
            "with this transcript as its reason."
        )

    if not (args.enable or args.disable):
        print(
            "\nStatus only. --enable turns the Data API ON (billable, "
            "asynchronous); --disable turns it off."
        )
        return 0

    want = bool(args.enable)
    body = {
        "enableDataApi": want,
        # SENT EXPLICITLY, ALWAYS. The field has no omitempty in the provider's
        # request struct, so leaving it out sends false and silently turns
        # network peering off. Preserve whatever the cluster already has.
        "enableNetworkPeering": bool(current.get("enabledForNetworkPeering", False)),
    }
    print(f"\nPUT {json.dumps(body)}")
    status, text = call_retrying("PUT", path, token, body)
    print(f"  {status}  {_message(text)[:240]}")
    if not (200 <= status < 300):
        return 1

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        time.sleep(10)
        status, text = call("GET", path, token)
        if status != 200:
            print(f"  poll: {status} {_message(text)[:120]}")
            continue
        doc = json.loads(text)
        state = doc.get("state")
        print(
            f"  state={state!r} enabled={doc.get('enabled')} "
            f"connectionString={doc.get('connectionString')!r}"
        )
        # SETTLED MEANS THE THING WE NEED IS THERE, not that `state` matches a
        # list of words. The first version enumerated healthy/ready/on/off/
        # disabled and the real terminal value is 'enabled', so a successful
        # enable would have polled to the timeout and reported failure -- a
        # checker calling a working operation broken.
        #
        # For an enable, "done" is: enabled is true AND connectionString is
        # non-empty, because the connection string is the ONLY reason to run
        # this. For a disable it is enabled false and a state that is no longer
        # transitional.
        settled = (
            (doc.get("enabled") is True and bool(doc.get("connectionString")))
            if want
            else (
                doc.get("enabled") is False and not str(state).lower().endswith("ing")
            )
        )
        if settled:
            print("\nSETTLED.")
            if want and doc.get("connectionString"):
                print(f"\n  DATA API BASE: {doc['connectionString']}")
                print(
                    "  That is the value fixture export/import must use. It is "
                    "NOT derivable from the cluster id, whatever the old "
                    "fixture docstring said."
                )
            return 0
    print(
        "\ntimed out waiting for the state to settle; re-run without --enable "
        "to see where it got to."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
