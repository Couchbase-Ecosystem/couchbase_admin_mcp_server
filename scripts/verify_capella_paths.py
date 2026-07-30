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
#: Prose fallback, kept only as a second opinion behind the structural check below.
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
    if status is not None and status >= 400:
        print(f"  app service  : list returned HTTP {status} — {body[:110]}")
        return ids

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

    Also fails closed: unknown means "cannot prove an empty body would be refused", so
    --method-probe skips rather than risk a request that succeeds and mutates.
    """
    value = getattr(op, "body_required", _UNKNOWN)
    if value is _UNKNOWN or value is None:
        return False
    return bool(value)


def probe(op, ids: dict, token: str, mode: str = "options") -> Result:
    """Check one operation.

    ``mode`` is one of:

      options  Send OPTIONS, which the API does not implement. A 404 means the route
               does not exist; a 405 means it does. Verifies the PATH only, and mutates
               nothing. The default.

      method   Send the real method with an EMPTY body. Only meaningful where the
               operation declares required body fields, because then the payload is
               guaranteed invalid and the control plane answers 400/422 — which proves
               the METHOD is accepted while changing nothing. This mode was discovered by
               accident: a --write-probe of capella_collection_create returned 422 rather
               than creating a collection, because the probe body was empty. That is a
               strictly better result than performing the write, so it is now a mode of
               its own rather than a lucky side effect.

      write    Actually perform the operation.
    """
    path, missing = fill(op.path, ids)
    if path is None:
        return Result(op, "SKIPPED", detail=f"no value for {', '.join(missing)}")

    if op.method == "GET":
        status, body = _request("GET", path, token)
    elif mode == "write":
        status, body = _request(op.method, path, token, body={} if op.body else None)
    elif mode == "method":
        if not _has_required_body(op):
            return Result(
                op,
                "SKIPPED",
                detail=(
                    "no required body fields, so an empty-body probe could SUCCEED and "
                    "mutate; use --write-probe deliberately instead"
                ),
            )
        status, body = _request(op.method, path, token, body={})
        if status in _PAYLOAD_REJECTED:
            return Result(
                op,
                "VERIFIED",
                status,
                f"{op.method} accepted; payload rejected, nothing changed",
            )
        if status in (200, 201, 202, 204):
            return Result(
                op,
                "ERROR",
                status,
                "an EMPTY body was ACCEPTED — this operation may have just been "
                "performed. Check the target and tighten body_required in spec.py.",
            )
    else:
        status, body = _request("OPTIONS", path, token)

    if status is None:
        return Result(op, "ERROR", detail=body[:160])

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
            )
        # Second opinion for a 404 that is not a structured domain error.
        lowered = body.lower()
        if any(h in lowered for h in _OBJECT_ABSENT_HINTS):
            return Result(op, "VERIFIED", status, "route matched; object absent")
        return Result(op, "MISSING", status, body[:160].replace("\n", " "))

    if status in _PATH_EXISTS:
        return Result(op, "VERIFIED", status)
    return Result(op, "ERROR", status, body[:160].replace("\n", " "))


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
CONSULTED_FIELDS = (
    "body",
    "body_required",
    "destructive",
    "group",
    "method",
    "name",
    "path",
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
        "--keep-app-service",
        action="store_true",
        help=(
            "With --bootstrap-app-service, do not delete it afterwards. It will keep "
            "billing until you remove it."
        ),
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

    if args.write_probe and args.method_probe:
        print(
            "--write-probe and --method-probe are mutually exclusive: the first performs "
            "the operation, the second deliberately avoids performing it.",
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

    if args.keep_app_service and not args.bootstrap_app_service:
        print(
            "--keep-app-service only means something with --bootstrap-app-service.",
            file=sys.stderr,
        )
        return 2

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

    try:
        return _run_probes(ops, ids, token, mode, args)
    finally:
        # In a finally so an exception or Ctrl-C during verification does not leave billable
        # infrastructure behind. This is the whole reason the bootstrap is safe to offer.
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


def _run_probes(ops, ids, token, mode, args) -> int:
    """Probe every selected operation and print the report. Returns the exit code."""
    print()

    results = []
    for op in sorted(ops, key=lambda o: (o.group, o.name)):
        result = probe(op, ids, token, mode)
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

    return 1 if counts.get("MISSING") else 0


if __name__ == "__main__":
    sys.exit(main())
