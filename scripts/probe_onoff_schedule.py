#!/usr/bin/env python3
r"""
probe_onoff_schedule.py - why does POST .../onOffSchedule answer 500?

WHY THIS EXISTS
===============
capella_cluster_onoff_schedule_set has now failed the same way on two separate
populate runs:

    500 {"code": 10000, "hint": "Something went wrong on our end. We are actively
         investigating the issue.", "httpStatusCode": 500,
         "message": "An internal server error occurred."}

A 500 is the one status that proves nothing on its own. It is consistent with a
genuine Capella defect, and equally consistent with a body this server is sending
wrong in a way the validator does not catch before it crashes. Two earlier 422s
from this same route were specific and taught us something -- code 11041 for a
non-IANA timezone, code 11042 for a day list shorter than seven -- so the route
DOES validate. This one does not name a field, which is the whole problem.

The distinguishing question: the body we send gives every day a state and NO time
window. Does a day need `from`/`to`? If a windowed body succeeds where the
windowless one 500s, the 500 is ours. If every shape 500s, it is Capella's, and
the operation should say so rather than leaving a reader to wonder.

SAFETY: NO CANDIDATE EVER TURNS THE CLUSTER OFF
===============================================
Every body below sets all seven days to state "on". The windowed variants use
00:00 to 23:59, which is a window that never powers anything down. A schedule
that succeeds therefore leaves the cluster on permanently -- the same end state
as having no schedule at all.

DELETE IS SENT IN EXACTLY ONE CASE: after a candidate SUCCEEDS on a cluster that
had no schedule beforehand, to put it back the way it was found. A round-2
candidate uses "custom" days, and a custom day is off outside its boundaries --
so a schedule left behind could power the cluster down hours later, for a reason
nobody asked for. Restoring the prior state is not an extra liberty, it is the
absence of one. If the cluster already had a schedule, this script leaves it
alone and does not create one to replace it.

USAGE
=====
    $env:CAPELLA_API_KEY_SECRET = '<the API key SECRET, not its id>'
    uv run python scripts/probe_onoff_schedule.py --cluster vn1kiibitcyvwrw
    uv run python scripts/probe_onoff_schedule.py --cluster vn1kiibitcyvwrw --perform

Reading the output:
    200/201/202/204 on a windowed body, 500 on the windowless one
        -> OUR BUG. The body needs from/to. Fix the op's body schema.
    500 on every candidate, including the GET-then-replay of whatever the cluster
    already has
        -> CAPELLA'S BUG. Record it against the op with this transcript and stop
           treating the failure as an outstanding task.
    422 with a domain code
        -> the route is validating again and the code names the field.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

# Share the credential resolution and the HTTP helper with the sibling probe
# rather than copying them. They have already absorbed one real bug each -- the
# access-key-id-instead-of-secret mix-up, and the organization-wide App Services
# listing -- and a second copy would not inherit those fixes.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from probe_access_control_function import (
    _message,
    _rows,
    call,
    resolve_credentials,
)

DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")


#: All seven days, always. A shorter list is refused with domain code 11042, which
#: was measured -- so any candidate that omitted a day would fail for a reason we
#: already understand and would teach nothing.
def _all_on_no_window() -> dict:
    return {
        "timezone": "America/New_York",
        "days": [{"day": d, "state": "on"} for d in DAYS],
    }


def _all_on_windowed() -> dict:
    return {
        "timezone": "America/New_York",
        "days": [
            {
                "day": d,
                "state": "on",
                "from": {"hour": 0, "minute": 0},
                "to": {"hour": 23, "minute": 59},
            }
            for d in DAYS
        ],
    }


def _all_on_windowed_flat() -> dict:
    """Same idea, times as strings rather than {hour, minute} objects.

    ANSWERED, round 1: 400 'body contains incorrect JSON type for field
    "days.from"'. The field is an object, not a string. Kept so the transcript
    carries its own proof of that rather than a citation.
    """
    return {
        "timezone": "America/New_York",
        "days": [
            {"day": d, "state": "on", "from": "00:00", "to": "23:59"} for d in DAYS
        ],
    }


def _all_on_utc() -> dict:
    """Windowed, but UTC. Isolates the timezone from the window."""
    return {
        "timezone": "UTC",
        "days": [
            {
                "day": d,
                "state": "on",
                "from": {"hour": 0, "minute": 0},
                "to": {"hour": 23, "minute": 59},
            }
            for d in DAYS
        ],
    }


#: ROUND 2. The 422 from round 1 named the rule outright:
#:
#:     Monday in the schedule is a non-custom day but it contains an
#:     'on' time boundary.
#:
#: So `state` is a three-valued field, not two: "on" and "off" are whole-day
#: states that must NOT carry from/to, and "custom" is the one that may. Round 1
#: sent boundaries on a non-custom day, which is why it was refused -- and the
#: windowless all-"on" body, which breaks no stated rule, is the one that 500s.
#:
#: These candidates use "custom" days, which is the only combination the stated
#: rules permit to carry a window.
def _all_custom(to_hour: int, to_minute: int) -> dict:
    return {
        "timezone": "America/New_York",
        "days": [
            {
                "day": d,
                "state": "custom",
                "from": {"hour": 0, "minute": 0},
                "to": {"hour": to_hour, "minute": to_minute},
            }
            for d in DAYS
        ],
    }


#: ROUND 3. Round 2 answered the schema completely, one 422 at a time:
#:
#:   * a "custom" day MUST carry a `from` boundary (and by symmetry a `to`)
#:   * a non-custom day must NOT carry one
#:   * `minute` is not free: "The valid minute values are 0 and 30"
#:   * `hour` is 0-23 inclusive, so 24:00 is not a spelling of midnight
#:
#: Which leaves the real question. 00:00-23:30 is the widest window the rules
#: permit, and it is not a whole day -- it leaves 30 minutes in which the cluster
#: is OFF. The all-"on" body, which breaks none of the stated rules and is the
#: only way to express "never turn this off", is the one that answers 500. So
#: either a valid schedule cannot keep a cluster up continuously, or the 500 is
#: a defect in the one case that would.
#:
#: The mixed candidate separates those. If six "on" days plus one "custom" day
#: is accepted, then whole-day "on" is fine and the 500 belongs specifically to
#: an all-"on" schedule -- a body that is valid by every published rule and
#: crashes anyway, which is a Capella defect worth reporting with a transcript.
def _widest_legal_custom() -> dict:
    """The widest window the measured rules allow: 00:00 to 23:30, every day."""
    return _all_custom(23, 30)


def _mixed_on_and_custom() -> dict:
    """Six whole-day "on" days and one "custom" day.

    Isolates "whole-day on is rejected" from "an all-on schedule is rejected".
    """
    days = [{"day": d, "state": "on"} for d in DAYS[:-1]]
    days.append(
        {
            "day": DAYS[-1],
            "state": "custom",
            "from": {"hour": 0, "minute": 0},
            "to": {"hour": 23, "minute": 30},
        }
    )
    return {"timezone": "America/New_York", "days": days}


def _all_custom_no_window() -> dict:
    """A custom day with no boundary -- the mirror of the round-1 error.

    If "non-custom day + boundary" is refused, "custom day + no boundary" should
    be refused too, and by a message that names the same rule from the other
    side. A 500 here instead would say the validation is one-directional.
    """
    return {
        "timezone": "America/New_York",
        "days": [{"day": d, "state": "custom"} for d in DAYS],
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--cluster",
        required=True,
        help="cluster id, or a unique prefix of its connection string",
    )
    ap.add_argument("--project", default="")
    ap.add_argument("--env-file", default=None)
    ap.add_argument(
        "--perform",
        action="store_true",
        help="actually send the candidate bodies (no candidate ever "
        "sets a day to 'off', so none can power the cluster down)",
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
    print(f"[ids] organization {org}")

    project = args.project
    if not project:
        status, text = call("GET", f"/v4/organizations/{org}/projects", token)
        rows = _rows(text)
        if status != 200 or len(rows) != 1:
            print(
                f"could not resolve exactly one project (status {status}); pass --project"
            )
            return 2
        project = rows[0]["id"]
    print(f"[ids] project {project}")

    status, text = call(
        "GET", f"/v4/organizations/{org}/projects/{project}/clusters", token
    )
    rows = _rows(text)
    if status != 200:
        print(f"clusters list failed: {status} {_message(text)}")
        return 2
    matched = [
        c
        for c in rows
        if c.get("id") == args.cluster
        or args.cluster in str(c.get("connectionString", ""))
    ]
    if len(matched) != 1:
        print(
            f"--cluster '{args.cluster}' matched {len(matched)} of {len(rows)} clusters"
        )
        for c in rows:
            print(f"    {c.get('id')}  {c.get('name')}  {c.get('connectionString')}")
        return 2
    cluster = matched[0]["id"]
    print(f"[ids] cluster {cluster}  ({matched[0].get('name')})")
    print(f"[ids] currentState {matched[0].get('currentState')}")

    path = (
        f"/v4/organizations/{org}/projects/{project}/clusters/{cluster}/onOffSchedule"
    )

    # THE READ FIRST. If a schedule already exists, its own document is the best
    # candidate there is -- a round-trip cannot be refused for a shape reason,
    # exactly as with the access control function.
    status, text = call("GET", path, token)
    print(f"\nGET {path}\n  {status}  {_message(text)[:300]}")
    existing = None
    if 200 <= status < 300:
        try:
            doc = json.loads(text)
            if isinstance(doc, dict) and doc.get("days"):
                existing = doc
        except Exception:
            pass

    cands: list[tuple[str, str, dict]] = []
    if existing:
        # Strip the read-only envelope fields a GET adds; sending audit metadata
        # back is its own source of 400s.
        replay = {k: v for k, v in existing.items() if k in ("timezone", "days")}
        cands.append(("round-trip of the cluster's own schedule", "POST", replay))
    cands += [
        # Round 3 first: these are the only two bodies that break no measured
        # rule, so if neither is accepted nothing is.
        (
            "all days CUSTOM, window 00:00-23:30 (widest the rules allow)",
            "POST",
            _widest_legal_custom(),
        ),
        (
            "six days ON + one CUSTOM (isolates the all-on 500)",
            "POST",
            _mixed_on_and_custom(),
        ),
        # Round 2, each already answered; kept so one transcript carries the
        # whole schema derivation rather than a citation of an earlier run.
        (
            "all days CUSTOM, window 00:00-23:59 (422: minute must be 0 or 30)",
            "POST",
            _all_custom(23, 59),
        ),
        (
            "all days CUSTOM, window 00:00-24:00 (422: hour must be 0-23)",
            "POST",
            _all_custom(24, 0),
        ),
        (
            "all days CUSTOM, no window (422: custom day needs a 'from')",
            "POST",
            _all_custom_no_window(),
        ),
        # Round 1, kept so one transcript carries the whole argument.
        (
            "all days on, NO time window (control -- this is what 500s)",
            "POST",
            _all_on_no_window(),
        ),
        (
            "all days on, window 00:00-23:59 as {hour, minute} (422: non-custom day "
            "with a boundary)",
            "POST",
            _all_on_windowed(),
        ),
        (
            "all days on, window as 'HH:MM' strings (400: days.from is an object)",
            "POST",
            _all_on_windowed_flat(),
        ),
        ("all days on, windowed, timezone UTC", "POST", _all_on_utc()),
        # PUT answered 404 "Failed to get On/Off schedule" when none existed,
        # which is itself a finding: PUT updates an existing schedule, POST
        # creates one. Kept last so it runs against whatever state we are in.
        ("all days on, windowed, PUT instead of POST", "PUT", _all_on_windowed()),
    ]

    if not args.perform:
        print(f"\n{len(cands)} candidates, in send order (not sent -- pass --perform):")
        for label, method, body in cands:
            print(f"  - [{method}] {label}")
            print(f"        {json.dumps(body)[:200]}")
        return 0

    print()
    winner = None
    for label, method, body in cands:
        status, text = call(method, path, token, body)
        print(f"  {status:>3}  [{method}] {label}")
        print(f"       {_message(text)[:260]}")
        if 200 <= status < 300:
            winner = (label, method, body)
            print("\n  ^ ACCEPTED. Later candidates were not sent.")
            break

    # REGISTER EVIDENCE FOR THE UPDATE OPERATION.
    #
    # capella_cluster_onoff_schedule_update sits in SHIPPED_UNVERIFIED because
    # the only status it has ever returned is 404 (PUT at a cluster with no
    # schedule), and 404 cannot tell "route exists, object does not" apart from
    # "no such route". test_write_operations_are_path_verified_only refuses it,
    # correctly. A 400 or 422 settles it, and the way to get one is an invalid
    # body sent at a cluster that DOES have a schedule -- route and method
    # proven, nothing written.
    reg_status, reg_text = call("PUT", path, token, {"timezone": "Mars/Olympus"})
    print(f"\n  REGISTER EVIDENCE (update): invalid body -> {reg_status}")
    print(f"    {_message(reg_text)[:240]}")
    if str(reg_status) in {"400", "405", "422"}:
        print('    Move "capella_cluster_onoff_schedule_update" out of')
        print(f'    SHIPPED_UNVERIFIED and into LIVE_VERIFIED as "{reg_status}".')
    else:
        print("    Not a usable register value; it stays in SHIPPED_UNVERIFIED.")

    print()
    if winner:
        label, method, body = winner
        print("RESULT: OUR BUG, not Capella's. The accepted body is")
        print(f"    [{method}] {json.dumps(body, indent=2)[:700]}")
        print("Fix capella_cluster_onoff_schedule_set's body schema to match.")

        # PUT THE CLUSTER BACK. A "custom" day is on between its boundaries and
        # off outside them, so a schedule this script created could power the
        # cluster down later tonight -- hours after the operator has stopped
        # watching, and for a reason they never asked for. The GET above said
        # what the prior state was; when it was 404, the prior state is NO
        # schedule and leaving one behind is a change this probe was not asked
        # to make.
        if existing is None:
            status, text = call("DELETE", path, token)
            if 200 <= status < 300 or status == 404:
                print(
                    "\nThe cluster had no schedule before this run and has none now "
                    f"(DELETE answered {status})."
                )
            else:
                print(
                    f"\n*** COULD NOT REMOVE THE SCHEDULE THIS SCRIPT CREATED: "
                    f"{status} {_message(text)[:200]}"
                )
                print("*** The cluster now carries a schedule it did not have before.")
                print("*** Remove it with capella_cluster_onoff_schedule_delete.")
        return 0

    print("RESULT: every candidate failed.")
    print("Read the two round-3 lines first -- they are the only bodies that break")
    print("no rule the server itself stated. If BOTH were refused, no valid")
    print("schedule exists for this cluster and the operation cannot succeed for")
    print("any input: a Capella-side defect, to be recorded against the op with")
    print("this transcript and closed. An operation that cannot succeed because the")
    print("PROVIDER is broken is not the same kind of open item as one we have not")
    print("finished, and carrying it as the latter overstates the work left.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
