#!/usr/bin/env python3
"""
verify_capella_paths.py — confirm every Capella v4 path this server uses is real.

WHY THIS EXISTS
===============
The 61 operations in handlers/capella/spec.py are tagged by provenance:

    [TF]           read out of the official Terraform provider's Go source
    [DOC]          taken from Capella's published API documentation / OpenAPI spec
    [LIVE]         path confirmed against a real organization by this script
    [LIVE+METHOD]  path and method both confirmed
    [PAT]          INFERRED from a confirmed sibling, not individually verified

The [PAT] ones are the risk: they follow the pattern of endpoints that are confirmed, but
nobody has watched them return a response. A wrong path fails as an opaque 404 that looks
like a missing resource.

Running this against a live organization has already earned its keep. It found that
`GET .../clusters/{id}/appservices` does not exist — that path is POST-only, App Services
are listed organization-wide — which had made every App Services operation unreachable and
was invisible from reading the code. It also found `/certificate` where the API wants
`/certificates`.

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

CLOSING THE APP SERVICES GAP
============================
22 of the 61 operations are App Services and App Endpoint paths. Their paths cannot be
filled in unless an App Service exists, so they report SKIPPED — honest, but not evidence.

    python scripts/verify_capella_paths.py --bootstrap-app-service --yes-really-mutate

creates a single-node App Service, verifies those paths, and deletes it again. The delete is
in a `finally`, so it also runs if verification fails or you interrupt the run.

This CREATES BILLABLE INFRASTRUCTURE and provisioning takes several minutes, which is why it
needs the second flag. If the target project already has an App Service on the cluster, that
one is reused and nothing is created. Add --keep-app-service to leave it running.

After that, 14 operations still report SKIPPED — every one because a list endpoint answered
200 with an EMPTY array, so there was no id to put in the path. Add:

    --bootstrap-child-objects

and it creates a database credential, a cluster allowlist entry, an App Service allowlist
entry, an App Services admin user and an App Endpoint; verifies those paths; then deletes
them, children before the App Service. Free and near-instant, unlike the App Service itself.

Nine of those 14 are the App Endpoint subtree — the surface a Couchbase Lite replicator
actually targets — so it is the half worth verifying most.

Both allowlist entries use 192.0.2.x/32 from RFC 5737 TEST-NET-1, which is reserved for
documentation and assigned to no real host, so neither grants access to anything. They also
carry a one-hour expiresAt, so a teardown that never runs still leaves a rule that lapses.
Full sweep:

    python scripts/verify_capella_paths.py \
        --bootstrap-app-service --bootstrap-child-objects --yes-really-mutate

THE PARKED SET
==============
handlers/capella/spec_pending.py holds 36 operations that are WRITTEN BUT NOT SHIPPED:
their paths were transcribed from the v4 reference and never confirmed against a live
control plane, and this repository refuses to ship a path on that basis.

    python scripts/verify_capella_paths.py --method-probe --include-pending

loads those records alongside the shipped ones, tags them [PEND] in the report, and ends
with a PROMOTION REPORT splitting them three ways: ready to promote, path is wrong (a
404 — fix the record, do not promote it), and still unsettled (no identifier available,
so nothing was learned).

Without --include-pending this script reads spec.py only, so it re-checks paths that are
already verified and says nothing about the ones that need verifying. That was the state
of it for some time, which is why the promotion procedure in CONTRIBUTING.md had never
been carried out.

A parked operation reports SKIPPED when the object it needs does not exist in the target
organization. To settle the whole parked set in one run, the organization needs: a
deployed eventing function, an XDCR replication, a completed managed backup, a GSI index,
an alert integration, and audit logging enabled. Anything absent leaves its group honestly
unsettled rather than falsely verified.

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
list them). Add --project / --cluster to pin those if the org has several. --only-pat
narrows to the paths still tagged [PAT]; run with no selector to check all 61. --json gives
machine-readable output.

The key needs only read access for the default mode: create one under
Organization Settings -> API Keys with the Organization Member role plus read access to
the project you point it at. The value to use is the key SECRET, not the key id — that is
the usual stumble.
"""

from __future__ import annotations

import argparse
import ast
import base64
import contextlib
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
#: 429 is deliberately ABSENT. It proves the request was rejected before routing was
#: relevant, so counting it as proof of existence meant a rate-limited run reported
#: every path VERIFIED and exited 0 -- and adding 500/502/503 to this set survived the
#: whole suite, so nothing pinned its upper bound either.
#:
#: THE 403 REASONING ABOVE HAS A HOLE, found live on 2026-09-02. It says a 403 "requires
#: authentication to have succeeded first, which requires routing" — true of a 403 the
#: API emits, and false of one the EDGE emits. A POST to
#: /v4/.../cloudsnapshotbackups/{id}/clone came back as an nginx HTML error page:
#:
#:     403 Forbidden
#:     403 Forbidden
#:     nginx
#:
#: No Capella error envelope, no domain code, no JSON at all. That request never reached
#: the API, so it says nothing about whether the route exists — and this set would have
#: recorded it VERIFIED. See _looks_like_an_edge_rejection.
_PATH_EXISTS = {200, 201, 202, 204, 400, 403, 405, 409, 422}


#: A response that did not come from the API at all.
#:
#: Capella answers errors with a JSON envelope carrying `code`, `hint`, `httpStatusCode`
#: and `message`. A reverse proxy in front of it answers with HTML. The distinction
#: matters for exactly one purpose and it is the purpose of this whole script: an edge
#: rejection is not evidence about a route.
def _looks_like_an_edge_rejection(body: str) -> bool:
    """Whether a response body came from a proxy rather than from Capella.

    Deliberately narrow. It is not "the body is not JSON" — an empty body on a 204 is
    normal and proves plenty. It is specifically the shape of a proxy error page.
    """
    if not body:
        return False
    sample = body.strip()[:400].lower()
    if sample.startswith(("{", "[")):
        return False  # a JSON body, whoever produced it
    return any(
        marker in sample
        for marker in ("<html", "<!doctype", "nginx", "<head>", "<title>", "cloudfront")
    )


#: 401 is deliberately ABSENT, and this was established live rather than assumed:
#: Capella answers 401 for a bad secret AND for an IP-allowlist rejection, on any path,
#: BEFORE routing. So 401 is not evidence a route exists -- it is evidence the
#: credential did not work. Counting it meant a run with a dead key reported every
#: reachable path as VERIFIED and exited 0, having verified nothing at all. 403 stays:
#: that one requires authentication to have succeeded first, which requires routing.
_CREDENTIAL_REJECTED = {401}

#: Statuses that mean "retry, then treat as ERROR" -- never as a verdict about routing.
_RATE_LIMITED = {429}

#: Phrases in a 404 body that indicate the ROUTE matched and the OBJECT was absent.
#: Without this, verifying a path that needs an id we could not discover would report a
#: false MISSING — the most likely way for this script to be confidently wrong.
#: Prose fallback, kept only as a second opinion behind the structural check below.
#:
#: Scanned against the `message` FIELD, never the whole body — see _object_absent_prose.
_OBJECT_ABSENT_HINTS = (
    "not found in",
    "does not exist",
    "does not have",
    "notfound",
    "could not be found",
    "no existing",
)

#: The lowest value a CAPELLA DOMAIN error code takes. Capella's own codes are four or
#: five digits (11040, 4025, ...); a bare HTTP status would be 404. Anything at or above
#: this threshold identifies an error the API's own handler generated, which it can only
#: do after routing the request.
_DOMAIN_CODE_FLOOR = 1000

#: The keys a Capella error response carries. Go's http.ServeMux answers an
#: unrouted request with the PLAIN TEXT "404 page not found", so a body with this
#: shape cannot have come from anywhere but one of the API's own handlers -- and a
#: handler runs after routing. See the 404 branch in verify() for the measurement
#: that made this necessary.
_ERROR_ENVELOPE_KEYS = ("httpStatusCode", "message")


def _capella_error_envelope(body: str) -> bool:
    """Whether a body is a Capella error object, regardless of its code."""
    try:
        parsed = json.loads(body)
    except Exception:
        return False
    if not isinstance(parsed, dict):
        return False
    return all(key in parsed for key in _ERROR_ENVELOPE_KEYS)


def _response_shape(body: str, limit: int = 24) -> list:
    """The KEY NAMES a 200 response carries — never the values.

    Written for capella_eventing_function_code_set, whose path is confirmed and whose
    REQUEST BODY has no source anywhere: the Terraform provider has no /code endpoint at
    all. GET on the same path answers 200, and whatever shape it returns is what the
    setter round-trips — so reading the getter settles the setter without sending
    anything. That generalises: a parked read whose response shape nobody has seen is a
    tool whose output contract is a guess.

    Keys only, and never for an operation marked sensitive_response. A key name is schema;
    a value can be a signed URL, a credential or a customer's document.
    """
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return []
    if isinstance(parsed, dict):
        items = parsed.get("data")
        # For a list envelope, the interesting shape is one ELEMENT, not {"data","cursor"}.
        if isinstance(items, list) and items and isinstance(items[0], dict):
            inner = items[0].get("data")
            element = inner if isinstance(inner, dict) else items[0]
            return sorted(element)[:limit]
        return sorted(parsed)[:limit]
    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
        return sorted(parsed[0])[:limit]
    # A bare scalar or string body is itself the answer — say so rather than "no keys".
    return [f"<{type(parsed).__name__}, not an object>"]


def _object_absent_prose(body: str) -> bool:
    """Whether a 404's MESSAGE says the object was absent.

    The scan used to run over the whole response body, and Capella's error envelope has a
    `hint` field carrying generic boilerplate that is not about this request at all. One
    real hint reads "Returned from the API when a database does not have an existing
    On/Off schedule" — which contains BOTH "does not have" and "no existing". A generic
    router 404 that happened to carry that hint would have been read as proof the route
    matched, on the strength of a sentence describing a different endpoint.

    So only `message` is scanned, which is the field that describes what actually
    happened. The live example this was built from:

        {"code":404,
         "hint":"Please review your request and ensure that all required parameters ...",
         "httpStatusCode":404,
         "message":"Index not found in key space"}

    `code` is 404 — the HTTP status echoed back, not a Capella domain code — so the
    structural check correctly declined it. The message names a domain object and a
    keyspace, which only the query-index handler could have produced, so the route did
    match. Falling back to the whole body when there is no `message` keeps the old
    behaviour for non-JSON responses.
    """
    try:
        payload = json.loads(body)
        message = payload.get("message") if isinstance(payload, dict) else None
    except (ValueError, TypeError):
        message = None
    haystack = (message if isinstance(message, str) else body).lower()
    return any(hint in haystack for hint in _OBJECT_ABSENT_HINTS)


def _is_inferred(op) -> bool:
    """Whether an operation's path is still INFERRED rather than sourced.

    Matches `[PAT` and not `[PAT]`, which is the whole point.

    The three call sites that needed this each carried their own `"[PAT]" in summary`, and
    that misses the form actually used in spec.py:

        [PAT — verify if 404]
        [PAT — sibling of the confirmed scopes path]

    Ten of the sixty-one operations were tagged that way. None of them matched, so
    --only-pat selected nothing and printed "No [PAT] paths remain: every operation now
    cites a primary source" — a confident all-clear covering ten unverified paths. Worse
    than no check, because it closed the question.
    """
    return "[PAT" in (getattr(op, "summary", "") or "")


#: Names loaded out of handlers/capella/spec_pending.py by the most recent load_ops()
#: call. Op is a frozen dataclass, so "this record is parked" cannot be stamped onto the
#: object itself; keeping the answer here means the report can tell a PROMOTION CANDIDATE
#: apart from a re-verification of something already shipped, which is the entire reason
#: for probing the parked set.
_PENDING_NAMES: set[str] = set()


def _is_pending(op) -> bool:
    """Whether this operation is PARKED — written but not shipped."""
    return getattr(op, "name", "") in _PENDING_NAMES


def _capella_domain_error(body: str) -> int | None:
    """The Capella error code in a response body, if it carries one.

    THIS IS THE RELIABLE SIGNAL, and it replaced a keyword scan that got it wrong.

    Capella answers a 404 in two quite different situations: the route does not exist, and
    the route exists but the named object does not. Distinguishing them by looking for
    phrases like "does not exist" failed on a real response —

        {"code":11040,
         "hint":"Returned from the API when a database does not have an existing On/Off
                 schedule.",
         "httpStatusCode":404,
         "message":"Failed to get On/Off schedule..."}

    — which says plainly that the route was reached and the schedule was absent, but
    matched none of the phrases and named none of the object words. The tool reported
    MISSING for a path that is correct, which is precisely the "confidently wrong" outcome
    this script exists to avoid.

    A structured error carrying a domain `code` is a much better discriminator: only the
    API's own handlers produce those, and they cannot run before the request has been
    routed.
    """
    try:
        parsed = json.loads(body)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    code = parsed.get("code")
    if isinstance(code, bool) or not isinstance(code, int):
        return None
    return code if code >= _DOMAIN_CODE_FLOOR else None


class Result:
    def __init__(self, op, verdict, status=None, detail="", method_sent=None):
        self.op = op
        self.verdict = verdict
        self.status = status
        self.detail = detail
        #: The HTTP method actually put on the wire, which is NOT always op.method:
        #: a write is usually probed with OPTIONS, and --method-probe falls back to
        #: OPTIONS for an operation it must not send an empty body to.
        #:
        #: Recorded rather than inferred from the status, because inferring it is
        #: exactly the mistake that would hand out a [LIVE+METHOD] tag on the strength
        #: of an OPTIONS probe — the one claim this script must never make loosely.
        self.method_sent = method_sent


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


def _list_items(parsed) -> list:
    """The list inside a v4 response, whatever the envelope calls it.

    v4 is NOT uniform. Most list endpoints answer {"data": [...], "cursor": {...}}, but
    GET /buckets/{id}/scopes answers {"scopes": [...]} and a scope answers
    {"collections": [...]}. Both helpers here assumed "data", so a scopes list read as
    EMPTY — and the caller had `or "_default"` behind it, which turned a parse failure
    into a plausible-looking default nobody questioned.

    The cost was invisible until the index sweep printed its work: three buckets, three
    keyspaces, all "_default._default", all "(scopes list empty — assuming _default)".
    Every bucket has at least a _default scope, so three empty scope lists was never a
    fact about the organization.

    Rather than enumerate envelope names, take the single list-valued key. Ambiguity
    fails closed: an object with two lists in it is one this function does not
    understand, and guessing between them is how the first version got here.
    """
    if isinstance(parsed, list):
        return parsed
    if not isinstance(parsed, dict):
        return []
    data = parsed.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return data["items"]
    lists = [value for value in parsed.values() if isinstance(value, list)]
    return lists[0] if len(lists) == 1 else []


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
    items = _list_items(parsed)
    if not items:
        return None
    first = items[0]
    if not isinstance(first, dict):
        return None
    # v4 sometimes nests the object one level deeper: {"data": [{"data": {...}}]}. The
    # App Services discovery unwrapped that and this helper did not, so an endpoint using
    # the nested shape read as an EMPTY LIST — "the cluster has none" for a cluster that
    # has some. Unwrap first, then fall back to the item itself.
    inner = first.get("data") if isinstance(first.get("data"), dict) else first
    for candidate in (inner, first):
        for key in keys:
            if candidate.get(key):
                return str(candidate[key])
    return None


def _keys_on_first_row(payload: str) -> list[str]:
    """The key names on a list response's first row, or [] if there are no rows.

    THE POINT IS TO TELL TWO THINGS APART THAT _first_id CANNOT.
    It returns None both when a list is genuinely empty and when it has rows
    whose id key is spelled differently than the caller guessed, and those
    demand opposite reactions: the first is a fact about the cluster, the second
    is a limitation of this script reported AS a fact about the cluster.

    That has now happened three times:

      * A nested {"data": [{"data": {...}}]} shape read as an empty list --
        recorded in _first_id's own docstring.
      * app_endpoint_name and app_endpoint_keyspace were never discovered at all,
        so twenty operations reported "no identifier available" as though the
        objects did not exist. Six of them were shipped operations.
      * The backup-cycle discovery looked for `cycleId`. The rows carry `cycleID`,
        capital ID, so it printed "this bucket has no cycles" in the same run
        where capella_bucket_backup_cycles_list returned rows.

    Every one of those read as a statement about the customer's cluster. A
    harness that cannot find something must say which of the two it means.
    """
    try:
        parsed = json.loads(payload)
    except Exception:
        return []
    items = _list_items(parsed)
    if not items or not isinstance(items[0], dict):
        return []
    first = items[0]
    inner = first.get("data") if isinstance(first.get("data"), dict) else first
    return sorted({*inner.keys(), *first.keys()})


def _absence_detail(payload: str, keys: tuple[str, ...]) -> str:
    """Why no identifier came back, in words that do not blame the cluster."""
    present = _keys_on_first_row(payload)
    if not present:
        return "no rows -- the path is right and this cluster genuinely has none"
    return (
        f"*** ROWS WERE RETURNED AND NONE CARRIED {list(keys)}. The keys present "
        f"are {present}. This is a limitation of THIS SCRIPT, not an empty "
        f"cluster -- fix the key names above rather than provisioning anything"
    )


#: Smallest App Service Capella will actually create. Kept in step with
#: spec.MIN_APP_SERVICE_NODES by a test, not by an import — see bootstrap_app_service.
_MIN_APP_SERVICE_NODES = 2

#: Poll settings for the App Services bootstrap. Provisioning takes minutes, not seconds.
_BOOTSTRAP_POLL_SECONDS = 15
_BOOTSTRAP_TIMEOUT_SECONDS = 1800  # 30 min

#: Marker embedded in the description of anything this script creates. Makes an orphan
#: identifiable in the Capella console, and lets the teardown refuse to delete an App
#: Service it did not create.
_BOOTSTRAP_MARKER = "created-by-verify_capella_paths"


def _app_service_state(token: str, base: str, app_service_id: str) -> str | None:
    """The current state of one App Service, or None if it cannot be read."""
    status, body = _request("GET", f"{base}/appservices/{app_service_id}", token)
    if status is None or status >= 400:
        return None
    try:
        parsed = json.loads(body)
    except Exception:
        return None
    data = parsed.get("data", parsed) if isinstance(parsed, dict) else {}
    return str(data.get("currentState") or data.get("state") or "") or None


def bootstrap_app_service(token: str, base: str, args) -> str | None:
    """Create an App Service and wait for it to become usable. Returns its id, or None.

    WHY THIS IS PART OF THE VERIFIER
    ================================
    22 of the 61 operations are App Services and App Endpoint paths. They cannot be
    exercised without an App Service existing, so every run reported them SKIPPED — not a
    failure, but not evidence either. Closing that gap meant clicking through the Capella
    console and then re-running, which is exactly the kind of manual step that does not get
    repeated, so the paths stayed unverified.

    It is also the operation the customer engagement needs anyway: standing an App Service up
    and tearing it down is the Couchbase Lite sync test loop.

    THIS COSTS MONEY AND TAKES TIME
    ===============================
    An App Service is billable infrastructure and provisioning is measured in minutes. So
    this is behind BOTH --bootstrap-app-service and --yes-really-mutate, matching the gate
    already in front of --write-probe, and the created object carries a marker in its
    description so the teardown can refuse to delete anything it did not create.
    """
    import time

    name = f"verify-{int(time.time())}"
    payload = {
        "name": name,
        "description": (
            f"Ephemeral App Service for v4 path verification. {_BOOTSTRAP_MARKER}. "
            "Safe to delete."
        ),
        # TWO nodes, not one. `{"nodes": 1}` looks like the cheap choice and it is simply
        # refused:
        #
        #   422 {"code":422,"httpStatusCode":422,
        #        "message":"The instance desired capacity must be between 2 and 12."}
        #
        # spec.py asserted the opposite ("1 suffices for testing"), and the same wrong value
        # was hard-coded in capella_env_create's App Service phase, so that phase could
        # never have succeeded. This run is what found it.
        #
        # Duplicated from spec.MIN_APP_SERVICE_NODES rather than imported: this script must
        # run with nothing installed — it falls back to parsing spec.py with `ast` when the
        # package is absent, which is how it ran here. A test asserts the two agree.
        "nodes": _MIN_APP_SERVICE_NODES,
        "compute": {"cpu": 2, "ram": 4},
    }

    print(f"  creating App Service {name!r} (this takes several minutes)...")
    status, body = _request("POST", f"{base}/appservices", token, body=payload)
    if status is None or status >= 400:
        print(f"  create FAILED: HTTP {status} — {body[:300]}")
        return None

    try:
        created = json.loads(body)
        data = created.get("data", created) if isinstance(created, dict) else {}
        app_service_id = str(data.get("id") or "")
    except Exception:
        app_service_id = ""

    if not app_service_id:
        # The create succeeded but the id is not where expected. Do NOT return None and
        # walk away: something is now running and billing. Say so loudly with the response
        # body, so it can be found and removed by hand.
        print(
            f"  create returned HTTP {status} but no id could be read from the response.\n"
            f"  An App Service named {name!r} may now exist and BILL. Check the Capella "
            f"console.\n  response: {body[:400]}"
        )
        return None

    print(f"  created {app_service_id}; waiting for a terminal state...")
    deadline = time.time() + _BOOTSTRAP_TIMEOUT_SECONDS
    state = None
    while time.time() < deadline:
        state = _app_service_state(token, base, app_service_id)
        if state in ("healthy", "turnedOff"):
            print(f"  App Service is {state}")
            return app_service_id
        if state in ("deploymentFailed", "degraded"):
            # Still return the id. A degraded App Service is useless for serving traffic but
            # perfectly good for confirming that a URL resolves, which is all this is for —
            # and the teardown still has to run either way.
            print(
                f"  App Service reached {state}; paths are still resolvable, continuing"
            )
            return app_service_id
        print(
            f"    state={state or 'unknown'} — polling again in {_BOOTSTRAP_POLL_SECONDS}s"
        )
        time.sleep(_BOOTSTRAP_POLL_SECONDS)

    print(
        f"  TIMED OUT after {_BOOTSTRAP_TIMEOUT_SECONDS}s with state={state!r}. "
        f"App Service {app_service_id} EXISTS and is billing; teardown will still run."
    )
    return app_service_id


#: RFC 5737 TEST-NET-1. Reserved for documentation and examples, so it is guaranteed not to
#: be assigned to any real host — allowlisting it grants access to nothing. Deliberately not
#: an RFC 1918 range: 10/8 and 192.168/16 are somebody's actual private network.
_DOC_CIDR_CLUSTER = "192.0.2.10/32"
_DOC_CIDR_APP_SERVICE = "192.0.2.11/32"


def _throwaway_password() -> str:
    """A password for an object that exists for a few minutes and is then deleted.

    Never printed and never returned to the caller. Capella will generate one if the field is
    omitted, but it then returns it in the create response — so supplying one keeps the
    generated secret out of a response body this script parses and might report on.
    """
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Vv1!" + "".join(secrets.choice(alphabet) for _ in range(20))


def _bucket_name(token: str, base: str, bucket_id: str) -> str | None:
    """The bucket's NAME, which App Endpoint creation wants instead of its v4 id."""
    status, body = _request("GET", f"{base}/buckets/{bucket_id}", token)
    if status is None or status >= 400:
        return None
    try:
        parsed = json.loads(body)
    except Exception:
        return None
    data = parsed.get("data", parsed) if isinstance(parsed, dict) else {}
    return str(data.get("name") or "") or None


def bootstrap_child_objects(token: str, base: str, ids: dict, overrides: dict) -> list:
    """Create the small objects the last 14 skipped paths need. Returns teardown records.

    WHY
    ===
    After an App Service exists, 14 operations still reported SKIPPED — and every one for the
    same reason: the list endpoint answered 200 with an EMPTY array, so there was no id to
    put in the path. Nine of them are the App Endpoint subtree, which is the surface a
    Couchbase Lite replicator actually talks to. Leaving those unverified while verifying the
    App Service that hosts them would be verifying the easy half.

    Unlike the App Service, none of these cost anything or take more than a moment.

    WHAT IS CREATED, AND WHY EACH IS SAFE
    =====================================
    * a database credential — a name and a throwaway password, deleted at the end
    * a cluster allowlist entry, and an App Service allowlist entry — both on
      192.0.2.x/32 from RFC 5737 TEST-NET-1, reserved for documentation and therefore
      assigned to no real host, so neither grants access to anything. Both also carry a
      short `expiresAt`, so even a teardown that fails leaves a rule that lapses on its own.
      That belt-and-braces matters more here than elsewhere: an allowlist entry is the one
      object in this list whose survival would WIDEN network exposure.
    * an App Services admin user — again name plus throwaway password
    * an App Endpoint bound to the discovered bucket/scope/collection, which yields both
      `app_endpoint_name` and `app_endpoint_keyspace`

    Each is created independently and a failure is reported and skipped rather than aborting,
    because they are not prerequisites for one another — and a 422 body is the fastest way to
    learn a body shape this registry has only ever had from documentation.
    """
    import datetime

    created: list[tuple[str, str]] = []  # (label, DELETE path)
    stamp = int(time.time())
    expires = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _create(
        label: str, path: str, payload: dict, *, fallback_id: str | None = None
    ):
        """POST, extract the new object's id, and record how to delete it.

        `fallback_id` is the identifier to assume when the create SUCCEEDS but returns no
        usable body. App Endpoint creation does exactly that — 2xx with an empty body — and
        its identifier is the `name` the caller chose, so it is knowable without being
        returned. Without the fallback, the endpoint was created, reported as a failure, and
        given NO TEARDOWN RECORD. It only got cleaned up because deleting the App Service
        takes its endpoints with it, which is luck rather than design.
        """
        status, body = _request("POST", path, token, body=payload)
        if status is None or status >= 400:
            # Not fatal. The point of the run is to learn, and the rejection body names the
            # field that is wrong — which is how the App Service node floor was found.
            #
            # 500 characters, not 220. The App Services admin user rejection was cut off
            # mid-word at "contains or lacks b", which is the part that would have said what
            # to fix. A truncated diagnostic is barely a diagnostic.
            print(f"  {label:14s}: create failed HTTP {status} — {body[:500]}")
            return None
        try:
            parsed = json.loads(body)
            data = parsed.get("data", parsed) if isinstance(parsed, dict) else {}
        except Exception:
            data = {}
        new_id = str(data.get("id") or data.get("name") or "") or (fallback_id or "")
        if not new_id:
            # The create WORKED and something now exists that this run cannot name, so it
            # cannot be deleted either. Say so with the status and body.
            print(
                f"  {label:14s}: created (HTTP {status}) but no id could be read and no "
                f"fallback is known — it will NOT be torn down. body={body[:200]!r}"
            )
            return None
        note = "" if data else "  (id assumed from the requested name)"
        print(f"  {label:14s}: {new_id}{note}")
        created.append((label, f"{path}/{urllib.parse.quote(new_id, safe='')}"))
        return new_id

    # ── Database credential ─────────────────────────────────────────────────
    # `access` is NOT optional, whatever spec.py's body_required said:
    #
    #   422 "Can not create new dataplane user without at least (1) valid permission being
    #        specified"
    #
    # Narrowest useful grant: read-only, and `resources` omitted rather than naming a bucket,
    # because a bucket-scoped grant is one more thing that can 422 on a cluster whose buckets
    # this script did not choose. It is data_reader on a credential that lives for minutes.
    user_id = _create(
        "db credential",
        f"{base}/users",
        {
            "name": f"verify-{stamp}",
            "password": _throwaway_password(),
            "access": [{"privileges": ["data_reader"]}],
        },
    )
    if user_id:
        ids["user_id"] = user_id

    # ── Cluster allowlist entry ─────────────────────────────────────────────
    cidr_id = _create(
        "cluster cidr",
        f"{base}/allowedcidrs",
        {
            "cidr": _DOC_CIDR_CLUSTER,
            "comment": f"{_BOOTSTRAP_MARKER} — RFC 5737 documentation range, routes nowhere",
            "expiresAt": expires,
        },
    )
    if cidr_id:
        ids["allowed_cidr_id"] = cidr_id

    app_service_id = ids.get("app_service_id")
    if not app_service_id:
        print("  (no App Service, so the App Service child objects are skipped)")
        return created

    as_base = f"{base}/appservices/{urllib.parse.quote(str(app_service_id), safe='')}"

    # ── App Service allowlist entry ─────────────────────────────────────────
    # Its id goes in an OVERRIDE, not in `ids`. Both allowlist routes use the placeholder
    # {allowed_cidr_id}, and they are different objects — see probe().
    as_cidr_id = _create(
        "as cidr",
        f"{as_base}/allowedcidrs",
        {
            "cidr": _DOC_CIDR_APP_SERVICE,
            "comment": f"{_BOOTSTRAP_MARKER} — RFC 5737 documentation range, routes nowhere",
            "expiresAt": expires,
        },
    )
    if as_cidr_id:
        overrides["capella_app_service_allowed_cidr_delete"] = {
            "allowed_cidr_id": as_cidr_id
        }

    # ── App Services admin user ─────────────────────────────────────────────
    # `accessAllEndpoints` must be TRUE, not false. The full message is:
    #
    #   422 "Payload for creating or modifying app service admin user contains or lacks
    #        both, list of endpoints and all endpoints flag."
    #
    # `false` with no `endpoints` list is not "the narrow option", it is NEITHER option: the
    # user would be granted access to nothing, and Capella counts that as failing to specify
    # access at all. Trying to be least-privilege here produced the same 422 as omitting the
    # field entirely.
    #
    # The grant is acceptable because the App Service is the one this run just created and
    # deletes minutes later, and the user's password is random and never printed. On the
    # REUSE path — an App Service the project already had — this grants a throwaway admin
    # access to that App Service's endpoints for the length of the run, which is why it is
    # created last and deleted first.
    admin_id = _create(
        "as admin user",
        f"{as_base}/adminUsers",
        {
            "name": f"verify{stamp}",
            "password": _throwaway_password(),
            "access": {"accessAllEndpoints": True},
        },
    )
    if admin_id:
        ids["admin_user_id"] = admin_id

    # ── App Endpoint ────────────────────────────────────────────────────────
    # The one that matters most: nine of the fourteen skips are this subtree, and it is what
    # a Couchbase Lite replicator targets.
    bucket_id = ids.get("bucket_id")
    bucket = _bucket_name(token, base, bucket_id) if bucket_id else None
    if not bucket:
        print("  app endpoint  : skipped, could not resolve the bucket NAME")
        return created

    # A THROWAWAY scope and collection, not the ones discovery found.
    #
    # This originally bound the endpoint to the discovered scope and collection, which on a
    # real cluster means `_default._default` of a bucket holding real data. That is wrong on
    # two counts:
    #
    #   1. Configuring an App Endpoint over a collection turns on Sync Gateway for it and
    #      writes sync metadata into the bucket. A verification tool must not start syncing
    #      somebody's data as a side effect of checking a URL.
    #   2. It does not even work twice. The metadata outlives the App Service, so a second
    #      run answered
    #        409 "App Endpoint config value or collection conflicts with one already in use"
    #      on a freshly created App Service — the conflict being the leftovers of the first.
    #
    # A scope created for this run is inert, unique per run, and removed afterwards. The
    # endpoint is skipped entirely if it cannot be made, because falling back to the real
    # collection is the behaviour being fixed.
    verify_scope = f"verify{stamp}"
    verify_collection = "sync"
    scope_id = _create(
        "verify scope",
        f"{base}/buckets/{urllib.parse.quote(str(bucket_id), safe='')}/scopes",
        {"name": verify_scope},
        fallback_id=verify_scope,
    )
    if not scope_id:
        print(
            "  app endpoint  : skipped — no throwaway scope, and binding the real "
            "collection is what this avoids"
        )
        return created

    scope_base = (
        f"{base}/buckets/{urllib.parse.quote(str(bucket_id), safe='')}"
        f"/scopes/{urllib.parse.quote(verify_scope, safe='')}"
    )
    collection_id = _create(
        "verify collection",
        f"{scope_base}/collections",
        {"name": verify_collection},
        fallback_id=verify_collection,
    )
    if not collection_id:
        print("  app endpoint  : skipped — no throwaway collection")
        return created

    endpoint_name = f"verify{stamp}"
    endpoint_id = _create(
        "app endpoint",
        f"{as_base}/appEndpoints",
        {
            "name": endpoint_name,
            "bucket": bucket,
            # Only ONE scope is permitted per App Endpoint, so this names exactly the one
            # created above.
            "scopes": {verify_scope: {"collections": {verify_collection: {}}}},
            # `deltaSyncEnabled`, not `deltaSync` — the short name is silently ignored.
            "deltaSyncEnabled": False,
        },
        # Creation answers 2xx with an EMPTY body, so there is no id to read — and there does
        # not need to be: an App Endpoint is addressed by the name supplied here, which is
        # why every path in this subtree uses {app_endpoint_name} rather than an id.
        fallback_id=endpoint_name,
    )
    if endpoint_id:
        ids["app_endpoint_name"] = endpoint_id
        # A keyspace is endpoint.scope.collection. A bare endpoint name is accepted but v4
        # reads it as `<endpoint>._default._default`, which silently targets the wrong
        # collection on a cluster with named scopes — so it is spelled out.
        ids["app_endpoint_keyspace"] = (
            f"{endpoint_id}.{verify_scope}.{verify_collection}"
        )

    return created


def teardown_child_objects(token: str, created: list) -> None:
    """Delete what bootstrap_child_objects created, most recent first.

    Reverse order because the App Endpoint and admin user live under the App Service, and the
    caller deletes the App Service after this returns.
    """
    for label, path in reversed(created):
        status, body = _request("DELETE", path, token)
        if status is not None and status < 400:
            print(f"  deleted {label}")
        else:
            print(
                f"  DELETE of {label} returned HTTP {status} — {body[:160]}\n"
                f"    path: {path}"
            )


def teardown_app_service(token: str, base: str, app_service_id: str) -> None:
    """Delete an App Service this script created. Refuses anything it did not create.

    Runs from a `finally`, so it also runs when verification raised or the user interrupted —
    the failure mode to avoid is leaving billable infrastructure behind because the run did
    not reach its last line.
    """
    status, body = _request("GET", f"{base}/appservices/{app_service_id}", token)
    description = ""
    if status is not None and status < 400:
        try:
            parsed = json.loads(body)
            data = parsed.get("data", parsed) if isinstance(parsed, dict) else {}
            description = str(data.get("description") or "")
        except Exception:
            description = ""

    if _BOOTSTRAP_MARKER not in description:
        # Belt and braces. --bootstrap-app-service only ever passes an id it just created,
        # so reaching here means something is wrong with that assumption — and deleting a
        # customer's App Service is not a recoverable mistake.
        print(
            f"  REFUSING to delete {app_service_id}: its description does not carry "
            f"{_BOOTSTRAP_MARKER!r}, so this script did not create it. Delete it by hand "
            "if it is in fact an orphan."
        )
        return

    print(f"  deleting App Service {app_service_id}...")
    status, body = _request("DELETE", f"{base}/appservices/{app_service_id}", token)
    if status is not None and status < 400:
        print("  deleted (Capella removes it asynchronously; confirm in the console)")
    else:
        print(
            f"  DELETE returned HTTP {status} — {body[:200]}\n"
            f"  App Service {app_service_id} may still exist and BILL. Remove it in the "
            "Capella console."
        )


#: Buckets Couchbase creates for its own use. They are returned by the buckets list like
#: any other, and taking the first item picked one of these on a real organization —
#: N1QL_SYSTEM_BUCKET, which is not a valid keyspace for the query-index API and made
#: /queryService/indexes answer 404 for a bucket rather than for the route.
_INTERNAL_BUCKET_NAMES = frozenset(
    {"N1QL_SYSTEM_BUCKET", "_system", "beer-sample", "travel-sample", "gamesim-sample"}
)


def _preferred_bucket(body: str) -> str | None:
    """A USER bucket if there is one, falling back to whatever exists.

    The fallback matters: probing an internal bucket is better than probing none, and a
    cluster with nothing but a system bucket should still get a verdict. But when a real
    bucket is present it is the one that answers questions about real keyspaces.
    """
    try:
        parsed = json.loads(body)
        items = parsed.get("data") if isinstance(parsed, dict) else parsed
    except Exception:
        return _first_id(body, "id", "bucketId")

    fallback = None
    for item in items or []:
        data = item.get("data", item) if isinstance(item, dict) else {}
        identifier = str(data.get("id") or data.get("bucketId") or "")
        if not identifier:
            continue
        name = str(data.get("name") or "")
        if not name:
            # Capella ids for buckets are base64 of the name, so decode rather than
            # give up — the name is what says whether it is ours.
            try:
                name = base64.b64decode(identifier + "===").decode("utf-8", "replace")
            except Exception:
                name = ""
        if name and name not in _INTERNAL_BUCKET_NAMES:
            return identifier
        fallback = fallback or identifier
    return fallback


def _count_items(body: str) -> int:
    """How many entries a v4 list response carried."""
    try:
        parsed = json.loads(body)
        items = parsed.get("data") if isinstance(parsed, dict) else parsed
        return len(items) if isinstance(items, list) else 0
    except Exception:
        return 0


def _warn_if_arbitrary(what: str, body: str, chosen) -> None:
    """Say when a pick was one of several, and how to override it.

    Discovery takes the first project and the first cluster. On an organization with one
    of each that is unambiguous; on a shared one it is a coin toss, and it was silent —
    so a run reported "this cluster has no eventing functions" about a cluster nobody
    chose, while the function sat on another one. The output has to distinguish a survey
    of the organization from a look at one corner of it.
    """
    total = _count_items(body)
    if not chosen or total <= 1:
        return
    print(
        f"                 (1 of {total} {what}s — this is the FIRST, not a survey. "
        f"Use --{what} to choose:)"
    )
    # NAMING the alternatives, because "1 of 2" without saying what the other one is
    # sends someone to the Capella console to copy a UUID out of a URL. The id is the
    # thing they need and it is already in the response.
    try:
        parsed = json.loads(body)
        items = parsed.get("data") if isinstance(parsed, dict) else parsed
    except Exception:
        return
    for item in (items or [])[:10]:
        data = item.get("data", item) if isinstance(item, dict) else {}
        identifier = str(data.get("id") or "")
        if not identifier:
            continue
        label = str(data.get("name") or "")
        here = "  <- probing this one" if identifier == str(chosen) else ""
        print(f"                     {identifier}  {label}{here}".rstrip())


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
            _warn_if_arbitrary("project", body, found)
        else:
            print(f"  project      : NONE FOUND (GET projects -> {status})")
            print(f"                 {body[:200]}")
    if ids.get("project_id"):
        print(f"  project      : {ids['project_id']}")

    if args.cluster:
        ids["cluster_id"] = args.cluster
    elif ids.get("project_id"):
        # The FIRST of possibly many, which on a shared organization is close to
        # arbitrary. Every "this cluster has none" printed below is a statement about
        # whichever cluster happened to sort first, and it was being read — including by
        # me — as a statement about the organization.
        _, body = _request(
            "GET",
            f"/v4/organizations/{args.org}/projects/{ids['project_id']}/clusters",
            token,
        )
        found = _first_id(body, "id", "clusterId")
        if found:
            ids["cluster_id"] = found
        _warn_if_arbitrary("cluster", body, found)

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
    bucket = _preferred_bucket(body)
    if bucket:
        ids["bucket_id"] = bucket
        # A KEYSPACE is named by name: `bucket`.`scope`.`collection`. The scope and
        # collection selectors were already names while the bucket was a base64 id, which
        # is not a keyspace anything would recognise — and the API answered "Index not
        # found in key space", which is true of a keyspace that does not exist.
        ids["bucket_name"] = _bucket_label(bucket)
        print(f"  bucket       : {bucket}  ({ids['bucket_name']})")
        _, sbody = _request("GET", f"{base}/buckets/{bucket}/scopes", token)
        discovered_scope = _first_id(sbody, "name", "id")
        ids["scope_name"] = discovered_scope or "_default"
        # The `or "_default"` is a reasonable fallback and a terrible silence. It printed
        # "_default" whether the scopes list said so or could not be read at all, and the
        # second of those went unnoticed for the whole of this exercise.
        print(
            f"  scope        : {ids['scope_name']}"
            + (
                ""
                if discovered_scope
                else "  (ASSUMED — the scopes list read as empty)"
            )
        )

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

    # Two more cluster-scoped ids, both from lists that already answer 200. Without these
    # three operations reported SKIPPED for want of an identifier that was sitting in a
    # list the script had not thought to read — indistinguishable in the output from an
    # identifier that genuinely does not exist.
    _, body = _request("GET", f"{base}/users", token)
    credential = _first_id(body, "id", "userId")
    if credential:
        ids["user_id"] = credential
        print(f"  db credential: {credential}")
    else:
        print("  db credential: none (credential paths SKIPPED)")

    _, body = _request("GET", f"{base}/allowedcidrs", token)
    cidr = _first_id(body, "id", "allowedCidrId")
    if cidr:
        ids["allowed_cidr_id"] = cidr
        print(f"  allowed cidr : {cidr}")
    else:
        print("  allowed cidr : none (CIDR delete SKIPPED)")

    # App Services are listed ORGANIZATION-WIDE. The cluster-level /appservices path
    # accepts POST only, so the GET this used to make returned 405 — and because a 405
    # body yields no id, the result was reported as "NONE FOUND" exactly as an empty list
    # would be. Every App Services path was therefore SKIPPED, and the discovery output
    # gave no hint that the request had been rejected rather than answered.
    status, body = _request(
        "GET",
        f"/v4/organizations/{args.org}/appservices?projectId={ids['project_id']}",
        token,
    )
    # NOT a `return ids`, which is what this used to do. Everything discovered BELOW this
    # point — eventing functions, XDCR replications, and the parked-set identifiers — is
    # unrelated to App Services, so one 403 on the org-wide App Services list silently
    # cost every one of those a verdict. The failure is reported and the walk continues.
    app_services_unreadable = status is not None and status >= 400
    if app_services_unreadable:
        print(f"  app service  : list returned HTTP {status} — {body[:110]}")
        body = ""

    # There is no clusterId query parameter, so narrow client-side. Taking the first item
    # would pick an App Service belonging to some other cluster in the organization.
    app = None
    try:
        parsed = json.loads(body)
        items = parsed.get("data") if isinstance(parsed, dict) else parsed
        for item in items or []:
            data = item.get("data", item) if isinstance(item, dict) else {}
            if str(data.get("clusterId") or "") == str(ids["cluster_id"]):
                app = str(data.get("id") or "")
                break
    except Exception:
        app = None

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

        # ── App Endpoints: the identifier 20 operations were blocked on ──────
        #
        # MEASURED GAP, 2026-09-14. A --method-probe --include-pending run
        # reported SKIPPED for TWENTY operations -- fourteen needing
        # app_endpoint_name and six needing app_endpoint_keyspace -- purely
        # because this script never discovered either. Six of those twenty are
        # SHIPPED operations, so a third of the App Endpoint surface had never
        # been path-probed at all, and the run said so in a way that read like
        # "the objects do not exist" rather than "this harness cannot look".
        #
        # They do exist: scripts/verify_mcp_surface.py discovers both from the
        # same two calls made here, and has done all along. The two harnesses
        # disagreeing about what is discoverable is the actual defect.
        _, ep_body = _request("GET", f"{base}/appservices/{app}/appEndpoints", token)
        endpoint = _first_id(ep_body, "name", "id")
        if endpoint:
            ids["app_endpoint_name"] = endpoint
            print(f"  app endpoint : {endpoint}")

            # THE KEYSPACE IS NOT THE ENDPOINT NAME. It is
            # <endpoint>.<scope>.<collection>, because the access control
            # function and the import filter are per COLLECTION. Sending the
            # bare endpoint name answers 404 "App Endpoint keyspace <name> not
            # found", which reads as a missing endpoint and is not one.
            _, doc = _request(
                "GET",
                f"{base}/appservices/{app}/appEndpoints/"
                f"{urllib.parse.quote(str(endpoint), safe='')}",
                token,
            )
            keyspace = ""
            try:
                parsed = json.loads(doc)
                scopes = parsed.get("scopes") if isinstance(parsed, dict) else None
                if isinstance(scopes, dict):
                    for scope_name, scope in scopes.items():
                        collections = (scope or {}).get("collections")
                        if isinstance(collections, dict) and collections:
                            keyspace = (
                                f"{endpoint}.{scope_name}.{next(iter(collections))}"
                            )
                            break
            except Exception:
                keyspace = ""
            if keyspace:
                ids["app_endpoint_keyspace"] = keyspace
                print(f"  ep keyspace  : {keyspace}")
            else:
                # A two-part keyspace is not a keyspace, and a 404 earned by
                # sending one teaches nothing. Skip honestly instead.
                print(
                    "  ep keyspace  : endpoint names no scope/collection "
                    "(keyspace paths SKIPPED)"
                )
        else:
            print("  app endpoint : none (App Endpoint paths SKIPPED)")
    elif not app_services_unreadable:
        print("  app service  : NONE FOUND (App Services paths will be SKIPPED)")

    # ── Backup cycles, which hang off a BUCKET rather than the cluster ──────
    #
    # Added 2026-09-14 for P1 item 6, and deliberately separate from the loop
    # below because the path needs {bucket_id} interpolated. Same three outcomes,
    # and one of them matters more here than anywhere else in this file: four
    # operations were once parked against /buckets/{id}/backupSchedule and a live
    # sweep returned Go's PLAIN-TEXT mux default for that path and six other
    # spellings. Those records were deleted as disconfirmed. The parked records
    # this discovers for use /backup/cycles, a different path from a stronger
    # source -- and if it too answers a plain-text 404, that is the same verdict
    # and the same remedy: delete, do not leave parked.
    bucket_for_backup = ids.get("bucket_id")
    if bucket_for_backup:
        cycles_path = (
            f"{base}/buckets/{urllib.parse.quote(str(bucket_for_backup), safe='')}"
            f"/backup/cycles"
        )
        status, cbody = _request("GET", cycles_path, token)
        if status is None:
            print("  backup cycle: request failed; cycle_id paths SKIPPED")
        elif status == 404:
            print(
                "  backup cycle: HTTP 404 on backup/cycles — the PARKED LIST PATH "
                "IS WRONG, not merely empty. This is the second path in this "
                "subsystem to be probed; see the RETRACTED note in "
                f"spec_pending.py. Body: {cbody[:90]}"
            )
        elif status >= 400:
            print(f"  backup cycle: HTTP {status} — {cbody[:90]}; cycle_id SKIPPED")
        else:
            # cycleID, NOT cycleId. MEASURED 2026-09-14: this looked for "cycleId",
            # found nothing, and printed "this bucket has no cycles" in the same
            # run where capella_bucket_backup_cycles_list returned rows keyed
            # createdAt and cycleID. A discovery step that reports absence when
            # it means "I looked under the wrong name" is worse than one that
            # errors, because it reads as a fact about the cluster.
            found = _first_id(cbody, "cycleID", "cycleId", "id")
            if found:
                ids["cycle_id"] = found
                print(f"  backup cycle: {found}")
            else:
                print(
                    f"  backup cycle: HTTP {status}, "
                    f"{_absence_detail(cbody, ('cycleID', 'cycleId', 'id'))}. "
                    "cycle_id paths SKIPPED"
                )

    # ── Eventing functions and XDCR replications ────────────────────────────
    #
    # These two identifiers were listed as a BLOCKER in spec_pending.py: without them
    # every eventing and replication operation reported SKIPPED, so a probe run could
    # never say anything about roughly a third of the parked records.
    #
    # The list endpoints used here are themselves PARKED and unverified, which is the
    # point rather than a problem. Three outcomes, all informative:
    #
    #   * items returned  -> an identifier for the detail paths, AND the list path is
    #                        confirmed to exist
    #   * 2xx but empty   -> the path is right and the cluster simply has none; the
    #                        detail paths stay SKIPPED, honestly
    #   * 404             -> the parked LIST path is WRONG, which is a finding in its
    #                        own right and is printed as one
    #
    # So the discovery step doubles as a probe of the two list paths. The status is
    # reported either way rather than being swallowed, because "no functions exist" and
    # "we asked the wrong URL" look identical from an empty `ids` dict.
    for label, segment, id_key, keys in (
        (
            "eventing fn ",
            # Was "eventing/functions", which 404s. The Terraform provider's generated
            # OpenAPI client spells it eventingFunctions, and the provider is generated
            # from Couchbase's own API document.
            "eventingFunctions",
            "function_name",
            ("name", "appname", "id"),
        ),
        ("replication ", "replications", "replication_id", ("id", "replicationId")),
        # Added 2026-09-14 for P1 item 8. sampleBuckets is cluster-level like the
        # two above, and the same three outcomes apply -- so this both finds
        # sample_bucket_id for the get/delete paths AND probes the list path
        # that capella_sample_bucket_load has never had a counterpart for.
        ("sample bucket", "sampleBuckets", "sample_bucket_id", ("id", "name")),
    ):
        status, rbody = _request("GET", f"{base}/{segment}", token)
        if status is None:
            print(f"  {label}: request failed; {id_key} paths SKIPPED")
            continue
        if status == 404:
            print(
                f"  {label}: HTTP 404 on {segment} — the PARKED LIST PATH IS WRONG, "
                f"not merely empty. Fix it in spec_pending.py before probing."
            )
            continue
        if status >= 400:
            print(f"  {label}: HTTP {status} — {rbody[:90]}; {id_key} paths SKIPPED")
            continue
        found = _first_id(rbody, *keys)
        if found:
            ids[id_key] = found
            print(f"  {label}: {found}")
        else:
            # WHICH KIND OF NOTHING THIS IS -- see _absence_detail. "The cluster
            # has none" and "this script looked under the wrong key" were
            # indistinguishable here, and the second was printed as the first
            # three times.
            print(
                f"  {label}: {segment} answered HTTP {status}; "
                f"{_absence_detail(rbody, keys)}. If the organization has the "
                f"object on another cluster, pass --project/--cluster to point "
                f"here. {id_key} paths SKIPPED"
            )

    # ── Identifiers used ONLY by the parked set ─────────────────────────────
    #
    # Gated on --include-pending because nothing in the shipped registry consumes any of
    # these four, and an unconditional walk would spend four requests per run buying
    # nothing. Without them, seven parked operations could never be anything but
    # SKIPPED — a permanent floor on how much a probe run can settle:
    #
    #   backup_id             capella_backup_get, capella_backup_cycle_delete
    #   event_id              capella_event_get
    #   export_id             capella_cluster_audit_log_export_get
    #   alert_integration_id  capella_alert_integration_{get,update,delete}
    #
    # Three of the four list endpoints are themselves PARKED, so — exactly as with
    # eventing and replication above — the discovery call doubles as a probe of the list
    # path, and its status is printed rather than swallowed. "This cluster has no
    # backups" and "we asked the wrong URL" are indistinguishable from an absent id, and
    # only the second is a finding.
    #
    # capella_events_list is the exception: it is SHIPPED and [LIVE], so a failure there
    # is a credential or scope problem rather than a wrong path.
    if getattr(args, "include_pending", False):
        project_base = f"/v4/organizations/{args.org}/projects/{ids['project_id']}"
        for label, url, id_key, keys, parked in (
            (
                "backup      ",
                f"{base}/backups",
                "backup_id",
                ("id", "backupId"),
                True,
            ),
            (
                "event       ",
                f"{project_base}/events",
                "event_id",
                ("id", "eventId"),
                False,
            ),
            (
                "audit export",
                # PLURAL. The singular 404s; the provider has auditLogExports.
                f"{base}/auditLogExports",
                "export_id",
                ("id", "exportId", "jobId"),
                True,
            ),
            (
                "alert integ ",
                f"{project_base}/alertIntegrations",
                "alert_integration_id",
                ("id", "alertIntegrationId"),
                True,
            ),
        ):
            status, rbody = _request("GET", url, token)
            if status is None:
                print(f"  {label}: request failed; {id_key} paths SKIPPED")
                continue
            if status == 404:
                # The SAME test probe() applies, and it was missing here. A 404 carrying
                # a Capella domain code means the route matched and the named object was
                # absent — /queryService/indexes?bucket=<a bucket with no indexes> is
                # exactly that, and this branch called it "the PARKED LIST PATH IS WRONG"
                # in a message telling someone to go and edit a correct record.
                code = _capella_domain_error(rbody)
                by_text = _object_absent_prose(rbody)
                if code is not None:
                    print(
                        f"  {label}: HTTP 404, route MATCHED (Capella error {code}); "
                        f"the object is absent, not the path wrong. "
                        f"{id_key} paths SKIPPED"
                    )
                    continue
                if by_text:
                    # Printed "Capella error None", which reads as a missing value rather
                    # than as "a different, weaker test was used". Name the test and show
                    # the body: this is the branch a reader most needs to second-guess.
                    print(
                        f"  {label}: HTTP 404, route matched per the response TEXT (no "
                        f"Capella error code, so weaker evidence — check it): "
                        f"{rbody[:120].strip()}"
                    )
                    continue
                if parked:
                    print(
                        f"  {label}: HTTP 404 on {url.split('/')[-1]} — the PARKED LIST "
                        f"PATH IS WRONG, not merely empty. Fix it in spec_pending.py "
                        f"before promoting anything in this group."
                    )
                else:
                    print(
                        f"  {label}: HTTP 404 on a SHIPPED path ({url}) — that is a "
                        f"regression in spec.py, not a parked-path problem."
                    )
                continue
            if status >= 400:
                print(
                    f"  {label}: HTTP {status} — {rbody[:90]}; {id_key} paths SKIPPED"
                )
                continue
            found = _first_id(rbody, *keys)
            if found:
                ids[id_key] = found
                print(f"  {label}: {found}")
            else:
                # Same distinction as the cluster-level loop -- see
                # _absence_detail. This branch kept the old wording through the
                # 2026-09-14 fix, which is exactly how the pattern survived
                # three times: each site was corrected on its own.
                print(
                    f"  {label}: HTTP {status}; {_absence_detail(rbody, keys)}. "
                    f"Pass --project/--cluster to probe a cluster that has them. "
                    f"{id_key} paths SKIPPED"
                )

    # ── An index, wherever one happens to live ──────────────────────────────
    #
    # Not folded into the loop above because a single guess is not good enough here. The
    # first attempt asked one keyspace — the first bucket's _default._default — and got
    # "Index not found in key space", which is a true answer to a question nobody meant
    # to ask: an organization can easily have indexes and none in that one spot. Three
    # parked operations then stayed parked on the strength of it.
    #
    # So this SWEEPS, bounded, and stops at the first keyspace that answers.
    if getattr(args, "include_pending", False):
        _discover_an_index(token, base, ids)

    # Identifiers that only exist once something has been created are left ABSENT on
    # purpose, so the affected operations report SKIPPED rather than a false MISSING.
    return ids


#: Ceilings on the index sweep. It is a convenience, not a survey, and an organization
#: with many buckets should not turn one probe run into hundreds of requests.
#
# 12 was too mean. Split fairly across two buckets it gave six keyspaces each, and
# harvester.governance alone has eight collections — so the sweep stopped two short of
# the end of the FIRST scope it looked at and reported "no index" about a bucket it had
# barely entered. These are fast unauthenticated-cache GETs with no sleep between them;
# 60 of them costs a few seconds, and a wrong "none found" costs a round trip through a
# human.
_INDEX_SWEEP_BUCKETS = 8
_INDEX_SWEEP_KEYSPACES = 60


def _discover_an_index(token: str, base: str, ids: dict) -> None:
    """Find one index name, trying keyspaces until one answers.

    Records `index_name` when it finds one. Says what it looked at when it does not,
    because "this organization has no indexes" and "we looked in one empty corner of it"
    are different conclusions and only the first is worth acting on.
    """
    _, bbody = _request("GET", f"{base}/buckets", token)
    buckets = []
    try:
        parsed = json.loads(bbody)
        for item in (parsed.get("data") if isinstance(parsed, dict) else parsed) or []:
            data = item.get("data", item) if isinstance(item, dict) else {}
            identifier = str(data.get("id") or data.get("bucketId") or "")
            if identifier:
                buckets.append(identifier)
    except Exception:
        buckets = [ids["bucket_id"]] if ids.get("bucket_id") else []

    # Internal buckets first: four of the twelve keyspaces in one live run went to
    # N1QL_SYSTEM_BUCKET, whose scopes are Couchbase's own bookkeeping. Nobody looking
    # for a user index wants that budget spent there.
    buckets = [
        b for b in buckets if _bucket_label(b) not in _INTERNAL_BUCKET_NAMES
    ] or buckets

    looked = []
    for bucket in buckets[:_INDEX_SWEEP_BUCKETS]:
        _, sbody = _request("GET", f"{base}/buckets/{bucket}/scopes", token)
        scopes = _names(sbody)
        scope_note = "" if scopes else " (scopes list empty — assuming _default)"
        for scope in scopes or ["_default"]:
            _, cbody = _request(
                "GET", f"{base}/buckets/{bucket}/scopes/{scope}/collections", token
            )
            collections = _names(cbody)
            for collection in collections or ["_default"]:
                # A PER-BUCKET share of the budget, not first-come. Depth-first spent the
                # whole ceiling inside one bucket's scopes and never reached the third
                # bucket at all — so "we looked everywhere" was false in a way the report
                # could not show.
                per_bucket = max(
                    1,
                    _INDEX_SWEEP_KEYSPACES
                    // max(1, min(len(buckets), _INDEX_SWEEP_BUCKETS)),
                )
                if (
                    sum(
                        1
                        for k, _ in looked
                        if k.startswith(f"{_bucket_label(bucket)}.")
                    )
                    >= per_bucket
                ):
                    break
                if len(looked) >= _INDEX_SWEEP_KEYSPACES:
                    _report_sweep(looked, buckets, capped=True)
                    return
                # The NAME, matching the label printed below it. This sent the base64
                # id while the report showed the decoded name, so the run claimed to have
                # asked "harvester.governance.trial_signals" and actually asked
                # "aGFydmVzdGVy.governance.trial_signals" — a keyspace that does not
                # exist, answered accurately with "Index not found in key space".
                #
                # The name fix went into _required_query, which probe() uses, and not
                # here. A report that does not print the request it made is worse than no
                # report: it is the only thing a reader has to check the tool against.
                query = urllib.parse.urlencode(
                    {
                        "bucket": _bucket_label(bucket),
                        "scope": scope,
                        "collection": collection,
                    }
                )
                status, rbody = _request(
                    "GET", f"{base}/queryService/indexes?{query}", token
                )
                looked.append(
                    (
                        f"{_bucket_label(bucket)}.{scope}.{collection}"
                        + ("" if collections else " (collections list empty)")
                        + scope_note,
                        status,
                    )
                )
                if status == 200:
                    found = _first_id(rbody, "indexName", "name", "id")
                    if found:
                        ids["index_name"] = found
                        print(
                            f"  query index : {found}  (in {scope}.{collection} of "
                            f"bucket {_bucket_label(bucket)})"
                        )
                        return
    _report_sweep(looked, buckets, capped=False)


def _bucket_label(bucket_id: str) -> str:
    """A bucket id rendered as its name where possible. Capella ids are base64 of the
    name, and a run that prints only the base64 is unreadable to the person reading it."""
    try:
        decoded = base64.b64decode(bucket_id + "===").decode("utf-8")
    except Exception:
        return bucket_id
    return decoded if decoded.isprintable() else bucket_id


def _report_sweep(looked: list, buckets: list, capped: bool) -> None:
    """Print exactly which keyspaces were asked and what each said.

    A bare "none found" is not a usable answer when the operator knows there ARE indexes:
    it gives them nothing to compare against what they can see in the console. Listing the
    keyspaces turns "the sweep is wrong somehow" into "it never looked at the one I mean",
    which is a fact rather than a theory.
    """
    tail = " (stopped at the ceiling)" if capped else ""
    print(
        f"  query index : no index in the {len(looked)} keyspace(s) asked, across "
        f"{min(len(buckets), _INDEX_SWEEP_BUCKETS)} of {len(buckets)} bucket(s)"
        f"{tail}. The route ANSWERS. index_name paths SKIPPED. Asked:"
    )
    for keyspace, status in looked:
        print(f"                     {status}  {keyspace}")


def _names(body: str) -> list:
    """Every `name` in a v4 list response, in order."""
    try:
        items = _list_items(json.loads(body))
    except Exception:
        return []
    out = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        # Same nesting as _first_id had to learn: {"data":[{"data":{...}}]}. This helper
        # kept the flat reading, so a scopes or collections list in the nested shape came
        # back EMPTY and the sweep fell back to ["_default"] — one keyspace per bucket,
        # then "this organization simply has no index" from three lookups in an
        # organization that has plenty.
        data = item.get("data") if isinstance(item.get("data"), dict) else item
        name = data.get("name") or data.get("id")
        if name:
            out.append(str(name))
    return out


#: Query parameters that SELECT A RESOURCE rather than page or sort it, mapped to the
#: identifier discovery stores. Omitting one of these is not "fewer results" — it is a
#: 400, because the API cannot tell which keyspace is meant.
_SELECTOR_QUERY_IDS = {
    # NAME, not id, and the fallback keeps a run working where the name is unknown.
    "bucket": ("bucket_name", "bucket_id"),
    "scope": ("scope_name",),
    "collection": ("collection_name",),
}


def _required_query(op, ids: dict) -> str:
    """The query string an operation needs in order to be answerable at all.

    /queryService/indexes is a GET that 400s without `bucket`, and a 400 counts as
    VERIFIED — the route matched — so the run reported the path confirmed while never
    once seeing the endpoint work. That is the weakest evidence that still looks like
    evidence, and promoting on it would ship a tool nobody has watched return data.

    Only SELECTORS are sent. Paging and sorting parameters are deliberately left off: an
    endpoint that needs them to answer is a different kind of finding.
    """
    declared = getattr(op, "query", ()) or ()
    pairs = []
    for name, keys in _SELECTOR_QUERY_IDS.items():
        if name not in declared:
            continue
        value = next((ids[k] for k in keys if ids.get(k)), None)
        if value:
            pairs.append((name, value))
    if not pairs:
        return ""
    return "?" + urllib.parse.urlencode(pairs)


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


#: A rejected PAYLOAD, which is what an empty-body probe is trying to provoke. Reaching
#: this means the route matched AND the method was accepted AND the request was then
#: refused on its contents — so nothing was created or changed.
_PAYLOAD_REJECTED = {400, 422}


#: Sentinel for "this field was never populated", as distinct from "declared false".
_UNKNOWN = object()


def _is_destructive(op) -> bool:
    """Whether performing this operation destroys something.

    Fails CLOSED. This was `getattr(op, "destructive", False)`, which defaults to "safe"
    when the attribute is missing — backwards for a guard, since an operation we know
    nothing about is precisely the one to refuse. Under the static fallback the attribute
    was missing on all 61 operations, so the guard against a destructive --write-probe
    never fired for anyone running without the SDK installed, which is the common case.
    """
    value = getattr(op, "destructive", _UNKNOWN)
    if value is _UNKNOWN or value is None:
        return True
    return bool(value)


def _has_required_body(op) -> bool:
    """Whether an empty-body probe is guaranteed to be rejected.

    Fails closed: unknown means "cannot prove an empty body would be refused", so
    --method-probe falls back to OPTIONS rather than risk a request that mutates.

    AND fails closed on observation. `body_required` is a claim about what a caller must
    send; it is NOT a promise about what the server refuses, and this function treated the
    two as the same thing. capella_alert_integration_update declares `config` required --
    correctly, the provider's type has it non-optional -- and the live API answers 200 to
    a PUT with {}. The probe sent it. The operation was performed on a real object.
    `empty_body_accepted` records that observation and overrides the inference.
    """
    if getattr(op, "empty_body_accepted", False):
        return False
    value = getattr(op, "body_required", _UNKNOWN)
    if value is _UNKNOWN or value is None:
        return False
    return bool(value)


def probe(
    op, ids: dict, token: str, mode: str = "options", overrides: dict | None = None
) -> Result:
    """Check one operation.

    ``mode`` is one of:

      options  Send OPTIONS, which the API does not implement. A 404 means the route
               does not exist; a 405 means it does. Verifies the PATH only, and mutates
               nothing. The default.

      method   Send the real method with an EMPTY body. Only where the operation
               declares required body fields AND IS NOT DESTRUCTIVE, because then the
               payload is guaranteed invalid and the control plane answers 400/422 —
               which proves the METHOD is accepted while changing nothing. This mode was
               discovered by accident: a --write-probe of capella_collection_create
               returned 422 rather than creating a collection, because the probe body was
               empty. That is a strictly better result than performing the write, so it
               is now a mode of its own rather than a lucky side effect.

               THE DESTRUCTIVE EXCLUSION IS NOT DECORATIVE. "An empty body is guaranteed
               to be rejected" is an assumption about the server, not a guarantee — and
               this function already has a branch for the case where it is wrong, which
               reports "an EMPTY body was ACCEPTED — this operation may have just been
               performed". For capella_backup_restore, "may have just been performed"
               means a cluster's data was overwritten.

               The hazard was latent rather than theoretical. That record is destructive,
               declares a body, and had body_required=() — so the empty-body probe did
               not fire. The moment anyone recorded its required fields, which is exactly
               what the promotion procedure asks for once a 422 names them, a probe run
               would have POSTed to .../backups/{backup_id}/restore for real. The guard
               against that existed only for --write-probe.

      write    Actually perform the operation.

    ``overrides`` maps an operation NAME to identifiers that apply only to it.

    Needed because two different routes share the placeholder ``{allowed_cidr_id}``: the
    cluster allowlist and the App Service allowlist. They are separate objects with separate
    ids, and a single flat ``ids`` dict can only hold one — so whichever op did not own the
    stored id would be probed with the other's, and answer a 404 that has to be argued about
    rather than a clean verdict. Per-op overrides let each be probed with its own.
    """
    effective = ids
    extra = (overrides or {}).get(op.name)
    if extra:
        effective = {**ids, **extra}

    path, missing = fill(op.path, effective)
    if path is None:
        return Result(op, "SKIPPED", detail=f"no value for {', '.join(missing)}")

    path += _required_query(op, effective)

    #: Appended to the verdict when the path was checked but the method deliberately was
    #: not. Empty for every other case, so an unqualified VERIFIED still means what it
    #: has always meant.
    method_note = ""
    #: The method actually sent. Set by each branch below.
    method_sent = "OPTIONS"

    if op.method == "GET":
        method_sent = "GET"
        status, body = _request("GET", path, token)
        if (
            status in (200, 201, 202, 204)
            and _is_pending(op)
            and not getattr(op, "sensitive_response", False)
        ):
            shape = _response_shape(body)
            if shape:
                method_note = f" — response keys: {', '.join(shape)}"
    elif mode == "write":
        method_sent = op.method
        status, body = _request(op.method, path, token, body={} if op.body else None)
    elif mode == "method" and _has_required_body(op) and not _is_destructive(op):
        method_sent = op.method
        status, body = _request(op.method, path, token, body={})
        if status in _PAYLOAD_REJECTED:
            return Result(
                op,
                "VERIFIED",
                status,
                f"{op.method} accepted; payload rejected, nothing changed",
                method_sent=op.method,
            )
        if status in (200, 201, 202, 204):
            return Result(
                op,
                "ERROR",
                status,
                "an EMPTY body was ACCEPTED — this operation may have just been "
                "performed. Check the target and tighten body_required in spec.py.",
                method_sent=op.method,
            )
    else:
        # FALLING BACK, not skipping. This branch used to `return SKIPPED` whenever
        # --method-probe met an operation with no required body fields — the empty-body
        # probe would then be a real write, so refusing it is right, but refusing to
        # check the PATH along with it was not. The stronger flag returned strictly LESS
        # information than the default, and did so silently: one live run lost 22 of 97
        # operations that way, a third of the surface, including nine parked records that
        # a plain OPTIONS probe would have settled.
        #
        # A flag that means "confirm more" must never confirm less. So the method is left
        # unconfirmed and the path is checked exactly as the default mode would.
        if mode == "method":
            if _is_destructive(op):
                reason = "it is DESTRUCTIVE"
            elif getattr(op, "empty_body_accepted", False):
                reason = (
                    "the API is KNOWN to accept an empty body here, so the empty-body "
                    "probe would PERFORM the operation rather than be refused by it"
                )
            else:
                reason = "it declares no required body fields"
            method_note = (
                f" — METHOD NOT CONFIRMED: {reason}. Sending the real method could have "
                "changed something, so the PATH was checked with OPTIONS instead; use "
                "--write-probe deliberately to settle the method."
            )
        status, body = _request("OPTIONS", path, token)

    if status is None:
        return Result(op, "ERROR", detail=body[:160], method_sent=method_sent)

    if status == 404:
        # A Capella domain error code proves the request was ROUTED: only the API's own
        # handlers emit those, and they run after routing. So the path is correct and the
        # named object simply is not there.
        code = _capella_domain_error(body)
        if code is not None:
            return Result(
                op,
                "VERIFIED",
                status,
                f"route matched; object absent (Capella error {code})",
                method_sent=method_sent,
            )
        # A CAPELLA ERROR ENVELOPE, even without a domain code, proves routing.
        #
        # MEASURED 2026-09-14. capella_app_endpoint_cors_get was reported as
        # "PATH IS WRONG: 404 with no sign the route matched" and listed under
        # PATHS THAT NEED FIXING. Its body was:
        #
        #   {"code":404, "hint":"Please review your request ...",
        #    "httpStatusCode":404, "message":"App Endpoint CORS is not enabled"}
        #
        # The path is correct. That endpoint simply has no CORS configured, which
        # is its normal state until cors_set is called. Two things hid it: `code`
        # echoes the HTTP status (404), so it sits below _DOMAIN_CODE_FLOOR, and
        # "is not enabled" is not one of the phrases _object_absent_prose knows.
        #
        # The discriminator spec_pending.py already documents is the right one and
        # is not a keyword match: Go's mux default for an unrouted request is the
        # PLAIN TEXT "404 page not found". A well-formed JSON error envelope with
        # hint/httpStatusCode/message can only have come from a handler, and a
        # handler runs after routing. Weaker than a domain code, because it does
        # not name the object -- so it carries the body, like the prose branch.
        if _capella_error_envelope(body):
            return Result(
                op,
                "VERIFIED",
                status,
                "route matched; the response is a Capella error ENVELOPE rather "
                "than Go's plain-text mux default, so a handler ran. No domain "
                "code, so this is weaker than the branch above. Body: "
                f"{body[:200].replace(chr(10), ' ')}",
                method_sent=method_sent,
            )
        # Second opinion for a 404 that is not a structured domain error — and it is a
        # WEAKER one, so it carries the body.
        #
        # It said only "route matched; object absent", which reads with exactly the
        # confidence of the domain-code branch above and rests on a keyword match instead.
        # A live 404 on /queryService/indexes was accepted on this branch and there was
        # then no way to tell, from the run's own output, whether the route had really
        # matched — the evidence had been discarded at the moment of judging it.
        if _object_absent_prose(body):
            return Result(
                op,
                "VERIFIED",
                status,
                "route matched; object absent — inferred from the response TEXT, not a "
                f"Capella error code, so this is weaker evidence. Body: "
                f"{body[:200].replace(chr(10), ' ')}",
                method_sent=method_sent,
            )
        return Result(
            op,
            "MISSING",
            status,
            body[:160].replace("\n", " "),
            method_sent=method_sent,
        )

    if status in _CREDENTIAL_REJECTED:
        return Result(
            op,
            "ERROR",
            status,
            "401: the credential was rejected before routing, so this says nothing "
            "about whether the path exists. Check CAPELLA_API_KEY_SECRET (the SECRET, "
            "not the key id) and the key's allowed-IP list.",
            method_sent=method_sent,
        )
    if status in _RATE_LIMITED:
        # Rate limiting says nothing about whether the route exists -- the request was
        # rejected before routing mattered. Counting it as VERIFIED meant a
        # rate-limited run reported the entire surface as confirmed and exited 0.
        return Result(
            op,
            "ERROR",
            status,
            "rate limited (429); no conclusion about this path. Re-run more slowly.",
        )
    if status in _PATH_EXISTS:
        # An EDGE rejection is inconclusive, not a pass. A 403 from the API means the
        # request was routed and then refused; a 403 from nginx means it never arrived.
        # Only the first says anything about whether the path is real.
        if _looks_like_an_edge_rejection(body):
            return Result(
                op,
                "ERROR",
                status,
                f"HTTP {status} from a PROXY, not from Capella — no error envelope, so "
                "the request never reached the API and this says nothing about the "
                f"route. Body: {body.strip()[:120]!r}",
                method_sent=method_sent,
            )
        return Result(
            op,
            "VERIFIED",
            status,
            method_note.lstrip(" —").strip(),
            method_sent=method_sent,
        )
    return Result(
        op,
        "ERROR",
        status,
        body[:160].replace("\n", " ") + method_note,
        method_sent=method_sent,
    )


#: Every Op field this script reads. The static fallback MUST carry all of them.
#:
#: It carried six, and the two it omitted were `destructive` and `body_required` — the
#: two that drive the safety decisions. `getattr(op, "destructive", False)` then
#: defaulted to "not destructive", so under the fallback the guard against a destructive
#: --write-probe was INERT, and --method-probe skipped every write operation with the
#: message "no required body fields" about operations that plainly declare them.
#:
#: That is the worst shape this kind of bug takes: the control works when tested with the
#: SDK installed, and is silently absent in the configuration someone without it runs.
#: NOTE on `body`: only its TRUTHINESS is used (`body={} if op.body else None`), so the
#: static parse need not reproduce nested schemas built from f-strings and constants —
#: which ast.literal_eval cannot evaluate anyway.
#: `query` was added to this tuple only after the failure it exists to prevent happened
#: AGAIN. Selector query parameters were read with `getattr(op, "query", ())`, the field
#: was not registered here, and so under the static fallback every operation reported no
#: query parameters at all. /queryService/indexes was therefore probed WITHOUT the
#: `bucket` it requires, answered 400, and was recorded VERIFIED — on a live run, on the
#: machine that has the API key, which is precisely the configuration with no SDK
#: installed. The registry path worked; the path everyone actually uses did not.
#:
#: The lesson the earlier note drew is the right one and was not enough on its own: this
#: tuple has to be the ONLY list, and `_StaticOp` raises when a field here is unpopulated
#: so that adding one forces the parser to keep up. What was missing was a test that runs
#: the static parse and compares it against the real registry field by field —
#: test_the_static_parse_populates_every_consulted_field now does that.
CONSULTED_FIELDS = (
    "body",
    "body_required",
    "destructive",
    "group",
    "method",
    "name",
    "path",
    "query",
    # Read by the response-shape capture. Registered here rather than reached with a bare
    # getattr, because that is precisely the mistake `query` made: under the static
    # fallback the attribute would be absent, getattr(..., False) would answer "not
    # sensitive", and the one guard stopping a signed URL reaching the report would be
    # inert on the only configuration anyone runs.
    "empty_body_accepted",
    "sensitive_response",
    "summary",
)


class _StaticOp:
    """An operation read straight out of the source, with no imports required."""

    __slots__ = CONSULTED_FIELDS

    def __init__(self, **fields):
        missing = [f for f in CONSULTED_FIELDS if f not in fields]
        if missing:
            raise TypeError(
                f"_StaticOp is missing {missing}; every field the script consults must "
                "be populated, or a safety check silently reads a default"
            )
        for field in CONSULTED_FIELDS:
            setattr(self, field, fields[field])


#: Stands in for a body schema that is declared but not statically readable.
_BODY_PRESENT_UNPARSED = {"__declared_but_not_statically_readable__": True}


def _static_body(fields: dict, literal):
    """The body schema, or a marker meaning "declared, contents unreadable"."""
    if "body" not in fields:
        return {}  # matches the Op dataclass default
    value = literal(fields["body"])
    if value is None:
        return dict(_BODY_PRESENT_UNPARSED)
    return value


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

    # Module-level constants, so a field declared as `query=_KEYSPACE_QUERY` resolves to
    # its value rather than to None. Shared tuples like _PAGE_QUERY and _KEYSPACE_QUERY
    # are the normal way these specs avoid repetition, so a parser that cannot follow one
    # silently reads "no query parameters" for every operation that uses them.
    constants: dict[str, object] = {}
    # Seed from spec.py first: spec_pending.py does `from .spec import _PAGE_QUERY, Op`,
    # so a parse of the pending file alone resolves none of the shared tuples.
    sibling = os.path.join(os.path.dirname(spec_path), "spec.py")
    bodies = []
    if os.path.abspath(sibling) != os.path.abspath(spec_path) and os.path.exists(
        sibling
    ):
        with contextlib.suppress(Exception):
            bodies.append(
                ast.parse(pathlib.Path(sibling).read_text(encoding="utf-8")).body
            )
    bodies.append(tree.body)
    for node in [n for body in bodies for n in body]:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if node.value is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                with contextlib.suppress(Exception):
                    constants[target.id] = ast.literal_eval(node.value)

    def literal(node):
        """Evaluate a declaration, resolving module constants literal_eval cannot.

        Three shapes appear in these specs and all three must work:

            query=_PAGE_QUERY                     a bare NAME
            query=("projectId", *_PAGE_QUERY)     a tuple SPLICING one
            query=("bucket", "scope")             an ordinary literal

        literal_eval handles only the third and returns None for the others, which is
        indistinguishable from "this field was not declared".
        """
        if isinstance(node, ast.Name):
            return constants.get(node.id)
        if isinstance(node, (ast.Tuple, ast.List)):
            out = []
            for element in node.elts:
                if isinstance(element, ast.Starred):
                    spliced = literal(element.value)
                    if spliced is None:
                        return None  # cannot be read completely; say so rather than lie
                    out.extend(spliced)
                else:
                    value = literal(element)
                    if value is None:
                        return None
                    out.append(value)
            return tuple(out) if isinstance(node, ast.Tuple) else out
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
                # affects the provenance tag in the output.
                summary=(literal(fields.get("summary")) if "summary" in fields else "")
                or "",
                group=(literal(fields.get("group")) if "group" in fields else "") or "",
                # PRESENCE is knowable even when the contents are not. Several body
                # schemas embed f-strings and module constants in their descriptions, so
                # literal_eval returns None for them — and None is falsey, which made the
                # parse report "no body" for operations that plainly declare one. Since
                # only truthiness is used, an unreadable-but-present body is recorded as a
                # marker rather than dropped.
                body=_static_body(fields, literal),
                # Selector query parameters decide whether a request is answerable at
                # all, so an unread `query` is not a cosmetic loss.
                query=(literal(fields.get("query")) if "query" in fields else ()) or (),
                sensitive_response=bool(
                    literal(fields.get("sensitive_response"))
                    if "sensitive_response" in fields
                    else False
                ),
                # Registered because the alternative is a guard that works only with the
                # SDK installed — the mistake `query` made, on a field whose absence lets
                # the probe perform a write.
                empty_body_accepted=bool(
                    literal(fields.get("empty_body_accepted"))
                    if "empty_body_accepted" in fields
                    else False
                ),
                # These two drive the SAFETY decisions, so they are read explicitly.
                # Absent from the declaration means the dataclass default applies, which
                # for both is falsey — that is a real answer, not a missing one.
                body_required=(
                    literal(fields.get("body_required"))
                    if "body_required" in fields
                    else ()
                ),
                destructive=(
                    literal(fields.get("destructive"))
                    if "destructive" in fields
                    else False
                ),
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
    # The literal placeholder in this file's OWN usage text
    # (`$env:CB_CAPELLA_API_KEY = 'paste-the-key-secret-here'`), and therefore the single
    # most likely value to be pasted verbatim. It matched none of the hints above.
    "paste",
)


def _looks_like_a_placeholder(value: str) -> bool:
    """Whether a value is obviously an unsubstituted example rather than a real one."""
    if not value:
        return False
    lowered = value.strip().lower()
    return any(hint in lowered for hint in _PLACEHOLDER_HINTS)


def load_ops(include_pending: bool = False) -> list:
    """Every operation, preferring the real registry and falling back to a static parse.

    The import is tried first because it is the authority — it is what the server
    actually runs. The fallback exists so a missing dependency does not stop someone
    verifying paths.

    THE PARKED SET
    --------------
    ``include_pending`` adds the operations in handlers/capella/spec_pending.py, which are
    written but deliberately not shipped: their paths were transcribed from the v4
    reference and never confirmed against a live control plane.

    Until this argument existed, this function read spec.py and nothing else — so the
    promotion procedure documented in CONTRIBUTING.md ("run the probe, then move the
    confirmed records") could not be carried out at all. The probe reported on the 61
    operations that were ALREADY verified and never touched the 36 that needed verifying.
    A verifier that cannot see the things awaiting verification is not a small gap; it is
    the gap that kept the parked set parked.

    Both registries are loaded by the same two mechanisms, in the same order, so the
    parked records get exactly the fidelity the shipped ones get rather than a
    second-class static read.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, root)
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")

    _PENDING_NAMES.clear()

    try:
        from handlers.capella.spec import OPS_BY_NAME

        ops = list(OPS_BY_NAME.values())
        if include_pending:
            from handlers.capella.spec_pending import PENDING_OPS

            shipped = {op.name for op in ops}
            # A name in BOTH registries means a promotion was half-completed: the record
            # was copied into spec.py and never deleted from spec_pending.py. Probing it
            # twice would report the same path under the same name with two verdicts, so
            # say so and stop rather than produce a report nobody can act on.
            duplicated = sorted(op.name for op in PENDING_OPS if op.name in shipped)
            if duplicated:
                raise SystemExit(
                    "These operations appear in BOTH spec.py and spec_pending.py: "
                    f"{duplicated}.\n"
                    "That is a half-finished promotion — the record was copied into OPS "
                    "and not removed from PENDING_OPS. Delete the parked copy."
                )
            _PENDING_NAMES.update(op.name for op in PENDING_OPS)
            ops.extend(PENDING_OPS)
        return ops
    except SystemExit:
        raise
    except Exception as exc:
        spec_path = os.path.join(root, "handlers", "capella", "spec.py")
        ops = _ops_by_static_parse(spec_path)
        sources = "spec.py"
        if include_pending:
            pending_path = os.path.join(root, "handlers", "capella", "spec_pending.py")
            pending = _ops_by_static_parse(pending_path)
            _PENDING_NAMES.update(op.name for op in pending)
            ops.extend(pending)
            sources = "spec.py and spec_pending.py"
        print(
            f"note: could not import the op registry ({type(exc).__name__}: {exc}); "
            f"read {len(ops)} operations directly from {sources} instead. "
            "Install the project to use the registry itself.",
            file=sys.stderr,
        )
        return ops


def _exit_code(counts: dict) -> int:
    """Exit non-zero unless the run actually verified something.

    `return 1 if counts.get("MISSING") else 0` treated ERROR and SKIPPED as success, so
    the two states that mean "nothing was checked" were indistinguishable from a clean
    pass:

      * a dead endpoint gave {'SKIPPED': 56, 'ERROR': 5} and exit 0;
      * a key with no project access gave {'SKIPPED': 56, 'VERIFIED': 5} and exit 0 --
        and those five were "verified" by a 401.

    A green CI check that verified nothing is worse than a red one, because it is
    evidence people act on. Both branches (text and --json) now use this.
    """
    # KNOWN, and it is not this script's bug: capella_cluster_create and
    # capella_app_service_create answer HTTP 500 to an empty-body POST where every other
    # create answers 422. Filed as CBSE-23617. A run against a live organization will
    # therefore report 2 ERRORs and exit non-zero until that is fixed. The alternative --
    # treating a 5xx as evidence -- is the thing this function exists to refuse.
    verified = counts.get("VERIFIED", 0)
    errors = counts.get("ERROR", 0)
    skipped = counts.get("SKIPPED", 0)
    if counts.get("MISSING"):
        return 1
    if errors:
        print(
            f"\n  FAILING: {errors} path(s) ended in ERROR (credentials or network). "
            "Nothing can be concluded about those paths, so this run does not pass.",
            file=sys.stderr,
        )
        return 1
    if not verified:
        print(
            "\n  FAILING: 0 paths were VERIFIED. Either the credential cannot reach "
            "the organization or every path was skipped; either way this run is not "
            "evidence that any path exists.",
            file=sys.stderr,
        )
        return 1
    if skipped and verified < skipped:
        print(
            f"\n  WARNING: {verified} verified but {skipped} skipped. Most of the "
            "surface was not checked -- supply the ids needed to fill those paths "
            "before treating this as a full verification.",
            file=sys.stderr,
        )
    return 0


#: The real stdout, kept aside when --json redirects human output. The JSON document
#: itself must still reach it.
_REAL_STDOUT = None


def _redirect_human_output_to_stderr() -> None:
    """Send everything `print` writes to stderr, keeping stdout for the JSON document."""
    global _REAL_STDOUT
    _REAL_STDOUT = sys.stdout
    sys.stdout = sys.stderr


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
        "--include-pending",
        action="store_true",
        help=(
            "Also probe the operations PARKED in handlers/capella/spec_pending.py — "
            "written, never confirmed against a live control plane, and therefore not "
            "shipped. This is the flag that makes the promotion procedure in "
            "CONTRIBUTING.md possible: without it the probe only re-checks paths that "
            "are already verified. Parked operations are tagged [PEND] in the report and "
            'carry "pending": true in --json.'
        ),
    )
    parser.add_argument(
        "--method-probe",
        action="store_true",
        help=(
            "Prove the METHOD is accepted without changing anything, by sending the real "
            "method with a deliberately empty body. Only valid for operations that "
            "declare required body fields, so the payload is guaranteed to be rejected. "
            "Safe to run across the whole surface."
        ),
    )
    parser.add_argument(
        "--write-probe",
        action="store_true",
        help=(
            "ACTUALLY perform the operation. Requires --only. For a destructive "
            "operation it also requires --yes-really-mutate."
        ),
    )
    parser.add_argument(
        "--yes-really-mutate",
        action="store_true",
        help=(
            "Required alongside --write-probe for a destructive operation, and alongside "
            "--bootstrap-app-service."
        ),
    )
    parser.add_argument(
        "--bootstrap-app-service",
        action="store_true",
        help=(
            "CREATE a temporary App Service, verify the 22 App Services and App Endpoint "
            "paths that need one, then DELETE it. Costs money and takes several minutes. "
            "Requires --yes-really-mutate. Skipped if the project already has an App "
            "Service on the target cluster."
        ),
    )
    parser.add_argument(
        "--bootstrap-child-objects",
        action="store_true",
        help=(
            "CREATE the small objects the remaining skips need — a database credential, a "
            "cluster and an App Service allowlist entry on RFC 5737 documentation "
            "addresses, an App Services admin user, and an App Endpoint — verify those "
            "paths, then delete them. Free and near-instant, unlike the App Service. "
            "Requires --yes-really-mutate."
        ),
    )
    parser.add_argument(
        "--keep-app-service",
        action="store_true",
        help=(
            "With --bootstrap-app-service, do not delete it afterwards. It will keep "
            "billing until you remove it."
        ),
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--out",
        metavar="PATH",
        help=(
            "Write the JSON document to PATH in UTF-8. IMPLIES --json — there is nothing "
            "else this flag could mean, and refusing it on its own was a guard that only "
            "ever caught the person who used it correctly. Use this on Windows: "
            "PowerShell's `>` encodes redirected output as UTF-16 with a BOM, which no "
            "JSON reader will accept."
        ),
    )
    args = parser.parse_args()

    # --out asks for the machine-readable document in a file. Requiring --json alongside
    # it added nothing a reader could act on and rejected an unambiguous intent, which is
    # a guard that costs a run and prevents no mistake.
    if args.out:
        args.json = True

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

    if args.write_probe and args.method_probe:
        print(
            "--write-probe and --method-probe are mutually exclusive: the first performs "
            "the operation, the second deliberately avoids performing it.",
            file=sys.stderr,
        )
        return 2

    ops = load_ops(include_pending=args.include_pending)
    if args.only:
        wanted = set(args.only)
        ops = [o for o in ops if o.name in wanted]
        unknown = wanted - {o.name for o in ops}
        if unknown:
            print(f"unknown operation(s): {sorted(unknown)}", file=sys.stderr)
            # Naming a PARKED operation without --include-pending is the likeliest way to
            # land here, and "unknown operation" is a misleading answer to it: the record
            # exists, it is simply not in the shipped registry this run loaded.
            if not args.include_pending:
                parked = {o.name for o in load_ops(include_pending=True)} & unknown
                if parked:
                    print(
                        f"  {sorted(parked)} are PARKED in "
                        "handlers/capella/spec_pending.py, not shipped. Add "
                        "--include-pending to probe them.",
                        file=sys.stderr,
                    )
                # Restore the selection state this diagnostic just clobbered.
                load_ops(include_pending=False)
            return 2
    elif args.only_pat:
        ops = [o for o in ops if _is_inferred(o)]

    if not ops:
        if args.only_pat:
            # Not an error — the opposite. Every path now has a primary source, so there
            # is nothing left to infer. Exiting 2 here would fail a CI step for having
            # succeeded.
            print(
                "No [PAT] paths remain: every operation in spec.py now cites a primary "
                "source (Terraform provider, Couchbase's OpenAPI document, or a live "
                "verification). Run without --only-pat to re-check the whole surface."
            )
            return 0
        print("no operations selected", file=sys.stderr)
        return 2

    mode = (
        "write" if args.write_probe else ("method" if args.method_probe else "options")
    )

    # A --write-probe of a DESTRUCTIVE operation performs the destruction. There is no
    # probe-shaped version of DELETE: it either happens or it does not.
    #
    # This guard exists because the hazard is one keystroke away from a safe command. The
    # invocation that proved capella_collection_create was
    #
    #     --write-probe --only capella_collection_create
    #
    # and it changed nothing, because the empty body was rejected. The same command with
    # `_delete` on the end would have deleted the _default collection out of a real
    # bucket, with no additional confirmation and nothing in the output to suggest the
    # two were different in kind.
    if mode == "write":
        destructive = [op for op in ops if _is_destructive(op)]
        if destructive and not args.yes_really_mutate:
            print(
                "Refusing to --write-probe a destructive operation without "
                "--yes-really-mutate:",
                file=sys.stderr,
            )
            for op in destructive:
                print(f"  {op.method} {op.name}", file=sys.stderr)
            print(
                "\nUnlike a create, a DELETE has no harmless probe form — it either "
                "happens or it does not. If the goal is to confirm the PATH, the default "
                "OPTIONS probe already does that without mutating anything, and it is "
                "what verified these paths in the first place.",
                file=sys.stderr,
            )
            return 2

    if args.bootstrap_app_service and not args.yes_really_mutate:
        print(
            "Refusing to --bootstrap-app-service without --yes-really-mutate.\n"
            "\n"
            "It CREATES an App Service in the target project. That is billable "
            "infrastructure and provisioning takes several minutes. It is deleted at the "
            "end (including on failure or Ctrl-C), but a crash between the two leaves it "
            "running — so the second flag is deliberate.\n"
            "\n"
            "Without it, the 22 App Services and App Endpoint operations report SKIPPED, "
            "which is honest: their paths come from Couchbase's published API document, "
            "they have simply never been watched returning a response.",
            file=sys.stderr,
        )
        return 2

    if args.bootstrap_child_objects and not args.yes_really_mutate:
        print(
            "Refusing to --bootstrap-child-objects without --yes-really-mutate.\n"
            "\n"
            "It CREATES a database credential, two allowlist entries, an App Services admin "
            "user and an App Endpoint in the target project, then deletes them. None of it "
            "is billable and none of it takes more than a moment, but they are real objects "
            "in a real organization.\n"
            "\n"
            "The allowlist entries are the ones worth understanding: both use addresses from "
            "RFC 5737 TEST-NET-1 (192.0.2.0/24), which is reserved for documentation and "
            "assigned to no real host, so neither grants access to anything. They also carry "
            "a one-hour expiresAt, so a failed teardown leaves a rule that lapses by itself.",
            file=sys.stderr,
        )
        return 2

    if args.keep_app_service and not args.bootstrap_app_service:
        print(
            "--keep-app-service only means something with --bootstrap-app-service.",
            file=sys.stderr,
        )
        return 2

    # With --json, every human line goes to STDERR so that stdout is a single JSON
    # document. It was not: `... --json > out.json` produced a file with the discovery
    # preamble in front of the object, which no JSON reader will parse — the promotion
    # step this flag exists to feed had to be hand-edited first. The preamble also names
    # the organization, project and cluster, so it was the identifying part of the run
    # that leaked into a file someone might share.
    if args.json:
        _redirect_human_output_to_stderr()

    print(f"Capella v4 path verification — {len(ops)} operation(s) against {BASE}")
    if args.write_probe:
        print("  *** --write-probe: real write methods WILL be sent ***")
    print("Discovering identifiers:")
    ids = discover(token, args)

    # The bootstrap runs AFTER discovery, so an App Service the project already has is used
    # instead of creating a second one. Paying to provision infrastructure that is already
    # sitting there would be the obvious way to make this feature annoying enough to avoid.
    created_app_service = None
    if args.bootstrap_app_service:
        print()
        if ids.get("app_service_id"):
            print(
                f"  --bootstrap-app-service: not needed, reusing the existing "
                f"{ids['app_service_id']}"
            )
        elif not ids.get("cluster_id"):
            print("  --bootstrap-app-service: no cluster to attach one to; skipping")
        else:
            base = (
                f"/v4/organizations/{args.org}/projects/{ids['project_id']}"
                f"/clusters/{ids['cluster_id']}"
            )
            created_app_service = bootstrap_app_service(token, base, args)
            if created_app_service:
                ids["app_service_id"] = created_app_service
                # Re-discover the App Services admin user, which only exists once the App
                # Service does, so its delete path gets a verdict rather than a skip.
                _, abody = _request(
                    "GET",
                    f"{base}/appservices/{created_app_service}/adminUsers",
                    token,
                )
                admin = _first_id(abody, "id", "userId", "name")
                if admin:
                    ids["admin_user_id"] = admin
                    print(f"  admin user   : {admin}")

    # Identifiers that apply to ONE operation only. See probe(): the cluster and App Service
    # allowlists both use {allowed_cidr_id} and are different objects.
    overrides: dict[str, dict] = {}
    created_children: list = []
    if args.bootstrap_child_objects:
        if not ids.get("cluster_id"):
            print()
            print("  --bootstrap-child-objects: no cluster; skipping")
        else:
            print()
            print("Creating child objects:")
            base = (
                f"/v4/organizations/{args.org}/projects/{ids['project_id']}"
                f"/clusters/{ids['cluster_id']}"
            )
            created_children = bootstrap_child_objects(token, base, ids, overrides)

    try:
        return _run_probes(ops, ids, token, mode, args, overrides)
    finally:
        # In a finally so an exception or Ctrl-C during verification does not leave anything
        # behind. This is the whole reason the bootstrap is safe to offer.
        #
        # Children first: the App Endpoint and admin user live UNDER the App Service, and
        # deleting the parent first would orphan the DELETE calls that verify them.
        if created_children:
            print()
            print("Tearing down child objects:")
            teardown_child_objects(token, created_children)

        if created_app_service and not args.keep_app_service:
            print()
            print("Tearing down:")
            base = (
                f"/v4/organizations/{args.org}/projects/{ids['project_id']}"
                f"/clusters/{ids['cluster_id']}"
            )
            teardown_app_service(token, base, created_app_service)
        elif created_app_service:
            print()
            print(
                f"--keep-app-service: {created_app_service} is still running and BILLING. "
                "Delete it in the Capella console when you are done with it."
            )


def _run_probes(ops, ids, token, mode, args, overrides=None) -> int:
    """Probe every selected operation and print the report. Returns the exit code."""
    print()

    results = []
    for op in sorted(ops, key=lambda o: (o.group, o.name)):
        result = probe(op, ids, token, mode, overrides)
        results.append(result)
        if not args.json:
            # A parked record is a PROMOTION CANDIDATE, and that is a different thing
            # from re-checking a shipped path — so it gets its own tag rather than
            # blending into the report. [PEND] wins over [PAT] when both would apply:
            # nothing parked can be promoted on the strength of an inferred sibling.
            if _is_pending(op):
                tag = "[PEND]"
            elif _is_inferred(op):
                tag = "[PAT] "
            else:
                tag = "      "
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
        document = json.dumps(
            {
                "base": BASE,
                "counts": counts,
                "results": [
                    {
                        "name": r.op.name,
                        "method": r.op.method,
                        "path": r.op.path,
                        "inferred": _is_inferred(r.op),
                        "pending": _is_pending(r.op),
                        "verdict": r.verdict,
                        "status": r.status,
                        # The method that actually reached the wire. A promotion is
                        # decided on this: only an operation whose OWN method was sent
                        # may be retagged [LIVE+METHOD].
                        "method_sent": getattr(r, "method_sent", None),
                        "detail": r.detail,
                    }
                    for r in results
                ],
            },
            indent=2,
        )
        # --out writes the file itself, in UTF-8. On Windows PowerShell 5.1 `>` encodes
        # redirected output as UTF-16LE with a BOM, so `... --json > out.json` produced a
        # file that reads as JSON to nobody — every byte doubled and a BOM in front. That
        # is not something the caller should have to know; the script can just write it.
        if args.out:
            pathlib.Path(args.out).write_text(document, encoding="utf-8")
            print(f"\nWrote {args.out} ({len(document)} bytes, UTF-8).")
        else:
            print(document, file=(_REAL_STDOUT or sys.stdout))
        return _exit_code(counts)

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
        # Grouped by CAUSE. Listing each operation with its own copy of the same reason
        # printed the same sentence 22 times and buried the one thing an operator can act
        # on: which single missing object would unlock the whole group.
        by_reason: dict[str, list[str]] = {}
        for r in skipped:
            by_reason.setdefault(r.detail, []).append(r.op.name)

        print()
        print("  Not exercised — no identifier available. NOT failures:")
        for reason, names in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
            print(f"    {len(names):>2} operation(s): {reason}")
            for name in sorted(names):
                print(f"        {name}")

    if skipped and not [r for r in results if r.verdict == "MISSING"]:
        needs_app_service = [r for r in skipped if "app_service_id" in r.detail]
        if needs_app_service:
            print()
            print(
                f"  {len(needs_app_service)} of the skips need an App Service to exist in "
                "the target project. Creating one there — which Couchbase Lite sync "
                "testing needs anyway — would let a re-run verify all of them."
            )

    errors = [r for r in results if r.verdict == "ERROR"]
    if errors:
        print()
        print("  Errors (credentials or network, not a path verdict):")
        for r in errors:
            print(f"    {r.op.name}: {r.status} {r.detail}")

    # ── The promotion report ────────────────────────────────────────────────
    #
    # The point of --include-pending. Reading a 97-line table and working out by hand
    # which parked records now have evidence behind them is the step at which this would
    # stop getting done, so the script does it.
    #
    # Deliberately three lists, not one. A parked path that came back MISSING is a
    # FINDING — the record is wrong and needs fixing before it can ever be promoted — and
    # burying it under "not promotable yet" alongside the ones that merely lacked an
    # identifier would lose the only result here that says something is broken.
    pending_results = [r for r in results if _is_pending(r.op)]
    if pending_results:
        promotable = [r for r in pending_results if r.verdict == "VERIFIED"]
        wrong = [r for r in pending_results if r.verdict == "MISSING"]
        unsettled = [
            r for r in pending_results if r.verdict not in ("VERIFIED", "MISSING")
        ]

        print()
        print(
            f"  PARKED SET — {len(pending_results)} operation(s) from "
            "handlers/capella/spec_pending.py"
        )

        if promotable:
            print()
            print(
                f"    READY TO PROMOTE ({len(promotable)}): the route answered, so the "
                "path is real."
            )
            for r in sorted(promotable, key=lambda r: r.op.name):
                # [LIVE+METHOD] only where the real method was accepted. An OPTIONS probe
                # confirms the PATH and says nothing about the method, so tagging its
                # result [LIVE+METHOD] would overstate exactly the evidence this script
                # exists to keep honest.
                tag = "[LIVE+METHOD]" if mode_confirmed_method(r) else "[LIVE]"
                print(f"      {r.op.name:44} {r.status:>3}  retag {tag}")
            print()
            print(
                "    For each: move the record into OPS in handlers/capella/spec.py, "
                "retag its\n"
                "    summary as shown, add the observed status to LIVE_VERIFIED, and run "
                "the suite."
            )

        if wrong:
            print()
            print(
                f"    PATH IS WRONG ({len(wrong)}): 404 with no sign the route matched. "
                "Fix the record\n"
                "    in spec_pending.py — do NOT promote it."
            )
            for r in sorted(wrong, key=lambda r: r.op.name):
                print(f"      {r.op.name:44} {r.op.method} {r.op.path}")
                print(f"        -> {r.detail}")

        if unsettled:
            by_verdict: dict[str, list[str]] = {}
            for r in unsettled:
                by_verdict.setdefault(r.verdict, []).append(r.op.name)
            print()
            print(
                f"    STILL UNSETTLED ({len(unsettled)}): nothing was learned, so these "
                "stay parked."
            )
            for verdict, names in sorted(by_verdict.items()):
                print(f"      {verdict}: {len(names)}")
                for name in sorted(names):
                    print(f"        {name}")
            print()
            print(
                "    A SKIPPED parked operation usually means the object it needs does "
                "not exist in\n"
                "    this organization — no deployed eventing function, no XDCR "
                "replication, no\n"
                "    completed backup, no alert integration. Provision one and re-run; "
                "the path\n"
                "    itself may well be fine."
            )

    return _exit_code(counts)


def mode_confirmed_method(result) -> bool:
    """Whether the METHOD was exercised, not merely the path.

    A GET is confirmed by having been performed. A write is confirmed only when the real
    method was sent and rejected on its CONTENTS (400/422) — which is what --method-probe
    provokes with an empty body. An OPTIONS probe returning 405 proves the route exists
    and proves nothing whatever about whether POST is accepted there.
    """
    method = getattr(result.op, "method", "").upper()
    # Whether the operation's OWN method reached the wire. An OPTIONS probe answering
    # 405 — or, conceivably, 400 — must never be read as evidence about POST.
    if getattr(result, "method_sent", None) not in (None, method):
        return False
    if method == "GET":
        # 2xx ONLY. This was `status not in (401, 403, 405)`, which handed [LIVE+METHOD]
        # to a GET that answered 400 — the route matched and the call was refused, so
        # nobody has seen the operation return data. Promoting on that ships a read tool
        # whose response shape is still a guess.
        return result.verdict == "VERIFIED" and result.status in (200, 201, 202, 204)
    return result.status in _PAYLOAD_REJECTED


if __name__ == "__main__":
    sys.exit(main())
