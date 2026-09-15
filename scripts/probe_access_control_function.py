#!/usr/bin/env python3
r"""
probe_access_control_function.py - what body shape does
PUT .../appEndpoints/{keyspace}/accessControlFunction actually want?

WHY THIS EXISTS
===============
capella_app_endpoint_access_control_function_set has now been refused in two
different ways, and the two refusals contradict each other:

    body {"function": "<source>"}
      400 bad request: 1 errors:
          collection "airline" sync function error: invalid javascript syntax:
          JavaScript source does not evaluate to a function

    body "<source>"                     (a bare JSON string)
      400 bad request: 1 errors:
          collection "airline" sync function error: invalid javascript syntax:
          value is not an object

Read together they are a schema. The second says the request body MUST be a JSON
object -- the validator calls the body "value". The first says that when it IS an
object, the validator looks inside it for the source, does not find it under the
key "function", and reports the absence as "does not evaluate to a function".

So the shape is an object under some OTHER key, and this script finds out which
by asking the server instead of by reasoning about it. Three guesses have already
been spent on this operation; a fourth guess is not worth more than one probe.

WHAT THIS CAN CHANGE
====================
Every candidate is built FROM the endpoint's own current function, read out of
capella_app_endpoint_get immediately beforehand. Round 1 sent that text verbatim
in every candidate, so a success would have been a literal no-op. Round 2 also
sends three REWRITES of it -- parenthesised, named, arrow -- so a success there
would replace the stored text with a semantically identical function: same
parameters, same body, same channel assignment, different spelling.

That is a real write, and this note exists because the earlier version of this
section claimed it was not. It is safe on a fixture cluster and it is not safe
on anything carrying real sync behaviour. The script prints the current function
before it sends anything; copy that line if you want to be able to put it back.

A candidate that fails writes nothing.

If the endpoint has no function at all the script REFUSES to run: it would then
have to invent a source, and an invented source cannot distinguish "wrong
envelope" from "wrong JavaScript", which is the entire question.

The script stops at the first 2xx. Candidates after a success are not sent.

USAGE
=====
    $env:CAPELLA_API_KEY_SECRET = '<the API key SECRET, not its id>'
    uv run python scripts\probe_access_control_function.py --cluster vn1kiibitcyvwrw
    uv run python scripts\probe_access_control_function.py --cluster vn1kiibitcyvwrw --perform

Without --perform it resolves the keyspace, prints the current function and lists
the candidate bodies without sending any of them. With --perform it sends them in
order and prints each status and message.

Reading the output:
    200/201/204   THIS IS THE SHAPE. Put it in handlers/capella/spec.py.
    400 "value is not an object"          the body was not an object at all
    400 "does not evaluate to a function" object, but the source was not found
                                          under that key
    404                                   the keyspace is wrong, not the body
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote

# Windows consoles default to cp1252. Keep every literal ASCII and force UTF-8
# where the runtime allows it, so a long run cannot die on its own output.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE = os.environ.get(
    "CB_CAPELLA_API_URL", "https://cloudapi.cloud.couchbase.com"
).rstrip("/")

#: Same order and same reasoning as scripts/probe_pending.py. CAPELLA_API_KEY_SECRET
#: first because that is the name handlers/capella/client.py reads; preferring the
#: other one once cost a debugging round when the access-key ID was in it.
_KEY_NAMES = ("CAPELLA_API_KEY_SECRET", "CB_CAPELLA_API_KEY")
_ORG_NAMES = ("CAPELLA_ORG_ID", "CB_CAPELLA_ORG_ID")


def _load_dotenv(path: pathlib.Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip("'\"")
    return out


def resolve_credentials(env_file: str | None) -> tuple[str, str, str]:
    found = [
        (n, os.environ[n].strip()) for n in _KEY_NAMES if os.environ.get(n, "").strip()
    ]
    if found:
        name, value = found[0]
        org = next(
            (os.environ[n] for n in _ORG_NAMES if os.environ.get(n, "").strip()), ""
        )
        return value, org.strip(), f"environment ${name}"
    candidates = (
        [pathlib.Path(env_file)]
        if env_file
        else [
            pathlib.Path(".env"),
            pathlib.Path(__file__).resolve().parent.parent / ".env",
        ]
    )
    for path in candidates:
        data = _load_dotenv(path)
        key = next((data[n] for n in _KEY_NAMES if data.get(n)), "")
        if key:
            org = next((data[n] for n in _ORG_NAMES if data.get(n)), "")
            return key, org, str(path)
    return "", "", ""


def call(method: str, path: str, token: str, body=None):
    """Returns (status, text). status 0 means the request never completed."""
    data = None
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode(errors="replace")[:4000]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:4000]
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


def call_retrying(method: str, path: str, token: str, body=None, attempts: int = 3):
    """call(), but a TRANSPORT failure is retried rather than recorded as a result.

    Round 2 lost one of its sixteen combinations to

        URLError: [WinError 10054] An existing connection was forcibly closed
                  by the remote host

    and reported it as status 0 alongside fifteen real answers. A reset is not a
    verdict -- that combination simply was not tested, and a matrix with a hole
    in it cannot support "none of them worked". Retry the transport; never retry
    a status the server actually returned.
    """
    for attempt in range(1, attempts + 1):
        status, text = call(method, path, token, body)
        if status != 0 or attempt == attempts:
            return status, text
        time.sleep(1.5 * attempt)
    return 0, "unreachable"


def _rows(payload: str) -> list:
    try:
        doc = json.loads(payload)
    except Exception:
        return []
    if isinstance(doc, dict):
        data = doc.get("data")
        if isinstance(data, list):
            return data
    return doc if isinstance(doc, list) else []


def _message(payload: str) -> str:
    """The server's own message, when there is one, else the raw text."""
    try:
        doc = json.loads(payload)
    except Exception:
        return payload.strip()[:300]
    if isinstance(doc, dict) and isinstance(doc.get("message"), str):
        return doc["message"]
    return payload.strip()[:300]


def candidates(source: str, scope: str, collection: str) -> list[tuple[str, object]]:
    """(label, body) in the order they will be sent.

    ROUND 1 VARIED THE ENVELOPE AND NOT THE SOURCE, and that was the flaw in it.
    Nine shapes were tried -- accessControlFunction, syncFunction, code, source,
    function, by-collection, nested, collections, scopes -- and all nine answered
    the SAME error:

        invalid javascript syntax: JavaScript source does not evaluate to a function

    Nine different envelopes cannot all be wrong in the same words. Every one of
    them carried the identical source string, read out of the endpoint document:

        function (doc, oldDoc, meta) {channel('airline');}

    That is an ANONYMOUS FUNCTION DECLARATION. As a standalone program it is not
    merely un-evaluable, it is not valid JavaScript at all -- a function
    declaration requires a name. So "does not evaluate to a function" may have
    been a true statement about the source every single time, and the envelope
    may have been right from the first attempt.

    That Capella stores this exact string is not a counter-argument. It was
    stored through App Endpoint creation, which evidently accepts a form this
    PUT does not.

    So round 2 crosses SHAPE with SOURCE FORM. The four source forms are the four
    ways to hand JavaScript something that evaluates to a function: the stored
    text as-is (the control), the same wrapped in parentheses so it is an
    expression, a NAMED declaration, and an arrow function. Sources vary fastest,
    so if the source was the whole problem the first four requests say so.
    """
    # THE DISCRIMINATOR, AND IT RUNS FIRST.
    #
    # 32 combinations have now produced one sentence. Before a 33rd shape is
    # tried, settle whether that sentence is a finding or a fixed string: send
    # source text that is NOT VALID JAVASCRIPT AT ALL.
    #
    # A validator that actually parses must say something different about
    # `}}} not javascript (((` than about a well-formed function -- a parse
    # error, a position, anything. If it answers "does not evaluate to a
    # function" for that too, it never compiled anything, the message is
    # boilerplate for "I could not find a source here", and no amount of
    # further shape-guessing can be distinguished from noise. That is the point
    # at which this stops being a probe and becomes a question for Couchbase.
    #
    # The other two are calibration: an empty string, and `42` -- valid
    # JavaScript that genuinely does not evaluate to a function, so it is the
    # one input for which that message would be CORRECT.
    discriminators: list[tuple[str, object]] = [
        (
            "DISCRIMINATOR: syntactically broken JavaScript",
            {"accessControlFunction": "}}} not javascript ((("},
        ),
        ("DISCRIMINATOR: empty string", {"accessControlFunction": ""}),
        (
            "DISCRIMINATOR: valid JS that is not a function (42)",
            {"accessControlFunction": "42"},
        ),
    ]

    sources: list[tuple[str, str]] = [
        ("stored text as-is (control)", source),
        ("parenthesised expression", f"({source})"),
        ("named declaration", _named(source)),
        ("arrow function", _arrow(source)),
    ]

    #: (label, builder). The builder takes the source and returns the body, so a
    #: shape is defined once and applied to every source form.
    shapes: list[tuple[str, object]] = [
        # ROUND 3, AND THE FIRST KEY HERE IS NOT A GUESS LIKE THE OTHERS WERE.
        #
        # Capella App Services is managed Sync Gateway, and a Sync Gateway
        # database config has always named this function `sync` -- per database
        # in 2.x, and per collection under
        # scopes.<scope>.collections.<collection>.sync in 3.x. Every key tried in
        # rounds 1 and 2 came from Capella's v4 vocabulary (the path segment, the
        # document field). None came from the vocabulary of the thing actually
        # doing the validating, and the error text -- "sync function error" --
        # is in that second vocabulary, not the first.
        # ROUND 4, from the Terraform provider's app_endpoint schema. Its
        # `scopes` attribute defaults to
        #   {_default: {collections: {_default: {
        #       accessControlFunction: "function(doc){channel(doc.channels);}",
        #       importFilter: "function(doc){...}"}}}}
        # so a collection's JS config is a PAIR of fields, and every shape tried
        # so far sent only one of them. If the server unmarshals the body into a
        # struct with both and then validates what it got, a body missing
        # importFilter could plausibly fail on the field it did find.
        (
            "{accessControlFunction + importFilter}",
            lambda src: {
                "accessControlFunction": src,
                "importFilter": "function(doc){return true;}",
            },
        ),
        (
            "{collections.<collection>.{acf + importFilter}}",
            lambda src: {
                "collections": {
                    collection: {
                        "accessControlFunction": src,
                        "importFilter": "function(doc){return true;}",
                    }
                }
            },
        ),
        ("{sync}  <- Sync Gateway's own config key", lambda src: {"sync": src}),
        ("{sync_fn}", lambda src: {"sync_fn": src}),
        (
            "{collections.<collection>.sync}",
            lambda src: {"collections": {collection: {"sync": src}}},
        ),
        (
            "{scopes.<scope>.collections.<collection>.sync}",
            lambda src: {
                "scopes": {scope: {"collections": {collection: {"sync": src}}}}
            },
        ),
        # Rounds 1-2, kept so one transcript carries the whole matrix. The
        # accessControlFunction + parenthesised cell is the one round 2 lost to a
        # connection reset; call_retrying closes that hole.
        ("{accessControlFunction}", lambda src: {"accessControlFunction": src}),
        ("{function}", lambda src: {"function": src}),
        (f"{{{collection}}}", lambda src: {collection: src}),
        (
            "{collections.<collection>.accessControlFunction}",
            lambda src: {"collections": {collection: {"accessControlFunction": src}}},
        ),
    ]

    out: list[tuple[str, object]] = list(discriminators)
    for shape_label, build in shapes:
        for source_label, src in sources:
            out.append((f"{shape_label} + {source_label}", build(src)))
    return out


def _named(source: str) -> str:
    """`function (a, b)` -> `function sync(a, b)`, leaving everything else alone.

    A named declaration is valid JavaScript where an anonymous one is not, which
    is the entire point of trying it.
    """
    stripped = source.strip()
    if stripped.startswith("function") and stripped[8:].lstrip().startswith("("):
        head, _, rest = stripped.partition("(")
        return f"{head.rstrip()} syncFn({rest}"
    return stripped


def _arrow(source: str) -> str:
    """`function (a, b) {body}` -> `(a, b) => {body}`.

    Falls back to the original text when the shape is not recognised; a bad
    transform would produce a syntax error that looks like a server answer.
    """
    stripped = source.strip()
    if not stripped.startswith("function"):
        return stripped
    open_paren = stripped.find("(")
    close_paren = stripped.find(")", open_paren)
    brace = stripped.find("{", close_paren)
    if -1 in (open_paren, close_paren, brace):
        return stripped
    params = stripped[open_paren : close_paren + 1]
    body = stripped[brace:]
    return f"{params} => {body}"


#: Fields a GET adds that a PUT must not carry back.
_READ_ONLY_ENDPOINT_FIELDS = (
    "adminURL",
    "metricsURL",
    "publicURL",
    "state",
    "requireResync",
    "isRequireResync",
    "audit",
)


def try_endpoint_document(
    base: str,
    app_service: str,
    endpoint: dict,
    token: str,
    scope: str,
    collection: str,
    source: str,
) -> bool:
    """Set the function by writing the ENDPOINT DOCUMENT, not the dedicated path.

    WHY THIS IS THE ROUTE THAT SHOULD HAVE BEEN TRIED FIRST.

    The Terraform provider has no resource for an access control function. It
    models the function as an attribute of the app_endpoint resource:

        scopes.<scope>.collections.<collection>.access_control_function

    with a default value that shows the API shape underneath it --
    {accessControlFunction, importFilter} per collection. A provider manages a
    thing the way the API lets it be managed, so if the provider sets this by
    writing the endpoint, the endpoint is where it is settable.

    That matters beyond this probe. This repo ships no
    capella_app_endpoint_update at all -- eleven App Endpoint operations and not
    one of them writes the document. If this works, that absence is the real
    defect, the dedicated /accessControlFunction path is a side road, and the
    fix is a new operation rather than a corrected body on the old one.

    Round-trips the document the server just gave us, with the function
    replaced, minus the fields a GET adds and a PUT cannot accept.
    """
    name = endpoint.get("name")
    body = {k: v for k, v in endpoint.items() if k not in _READ_ONLY_ENDPOINT_FIELDS}
    scopes = body.get("scopes")
    if not isinstance(scopes, dict):
        print("  the endpoint document carries no scopes map -- cannot round-trip it")
        return False
    try:
        scopes[scope]["collections"][collection]["accessControlFunction"] = source
    except (KeyError, TypeError):
        print(f"  {scope}.{collection} is not in the document's scopes map")
        return False

    path = f"{base}/appservices/{app_service}/appEndpoints/{quote(name)}"
    for method in ("PUT", "POST"):
        status, text = call_retrying(method, path, token, body)
        print(f"  {status:>3}  [{method}] full endpoint document, function replaced")
        print(f"       {_message(text)[:260]}")
        if 200 <= status < 300:
            print("\n  ^ ACCEPTED. The function is settable through the ENDPOINT")
            print("    DOCUMENT. Ship capella_app_endpoint_update with this body and")
            print(f"    this method ({method}); the dedicated /accessControlFunction")
            print("    path is not the way in.")

            # ONE MORE NUMBER, AND IT IS NOT CURIOSITY.
            #
            # spec.py's LIVE_VERIFIED register only accepts statuses a
            # NON-MUTATING probe could have produced -- 200, 400, 404, 405, 422 --
            # and test_no_write_is_recorded_with_a_success_status enforces that. A
            # 204 from a real write cannot go in it; it belongs in
            # LIVE_VERIFIED_OUT_OF_BAND with its provenance.
            #
            # So the new operation still needs a register entry, and inventing one
            # is exactly the false claim that register exists to prevent. Send an
            # empty body to the same route: it is refused on its contents, which
            # proves route AND method without writing anything, and the status it
            # returns is a legitimate LIVE_VERIFIED value.
            reg_status, reg_text = call_retrying(method, path, token, {})
            print()
            print(f"  REGISTER EVIDENCE: empty body -> {reg_status}")
            print(f"    {_message(reg_text)[:240]}")
            if str(reg_status) in {"200", "400", "404", "405", "422"}:
                print(
                    f'    Put "capella_app_endpoint_update": "{reg_status}" in '
                    f"LIVE_VERIFIED."
                )
            else:
                print(
                    "    NOT a usable register value. The op needs a different "
                    "refusal to record, or it goes in SHIPPED_UNVERIFIED with "
                    "this transcript as its reason."
                )
            return True
    return False


def try_name_path_variants(
    base: str,
    app_service: str,
    endpoint_name: str,
    token: str,
    scope: str,
    collection: str,
    source: str,
) -> bool:
    """The endpoint NAME in the path, with scope and collection carried separately.

    WHY THIS IS A NEW HYPOTHESIS AND NOT A 33rd GUESS.

    The Terraform provider's app_endpoint_access_control_function resource takes
    SIX required fields -- organization_id, project_id, cluster_id,
    app_service_id, app_endpoint_name, access_control_function -- and then
    `scope` and `collection` as OPTIONAL extras. Note what is required: the
    endpoint NAME. Not a keyspace.

    Every request this probe has sent put the keyspace in the path
    (test.inventory.airline) and carried nothing else. If the API instead takes
    the endpoint name in the path and the scope and collection somewhere else,
    then a keyspace-in-path request is addressing the DEFAULT collection of an
    endpoint named "test.inventory.airline" -- and "no such thing" would be
    reported by whatever handler runs after routing, which is exactly the
    undifferentiated 400 we keep getting.

    That also explains the one result that never fit: sending the bare endpoint
    name earlier answered 404 "App Endpoint keyspace test not found". Under this
    reading that 404 is correct and complete -- the name alone, with no scope or
    collection supplied, resolves to test._default._default, which does not
    exist on this endpoint. The provider's own doc says exactly that: "If only an
    App Endpoint name is provided this will be interpreted as
    endpoint1._default._default."

    So: name in the path, scope and collection as query parameters, and the body
    both ways round.
    """
    body_shapes: list[tuple[str, object]] = [
        ("{accessControlFunction}", {"accessControlFunction": source}),
        ("bare string", source),
        ("{function}", {"function": source}),
    ]
    path_shapes = [
        (
            "name + ?scope=&collection=",
            f"{base}/appservices/{app_service}/appEndpoints/{quote(endpoint_name)}"
            f"/accessControlFunction?scope={quote(scope)}&collection={quote(collection)}",
        ),
        (
            "name + ?keyspace=",
            f"{base}/appservices/{app_service}/appEndpoints/{quote(endpoint_name)}"
            f"/accessControlFunction?keyspace="
            f"{quote(f'{endpoint_name}.{scope}.{collection}')}",
        ),
    ]
    for path_label, path in path_shapes:
        for body_label, body in body_shapes:
            status, text = call_retrying("PUT", path, token, body)
            print(f"  {status:>3}  [{path_label}] + {body_label}")
            print(f"       {_message(text)[:240]}")
            if 200 <= status < 300:
                print("\n  ^ ACCEPTED. The path takes the endpoint NAME and the")
                print("    collection is carried as a query parameter, not baked")
                print("    into the path segment. Correct the Op's path and its")
                print(f"    body to: {path_label} + {body_label}")
                return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--cluster",
        required=True,
        help="cluster id, or a unique prefix of its connection string "
        "(the same value capella_populate_test_cluster.py takes)",
    )
    ap.add_argument("--project", default="", help="project id; discovered when absent")
    ap.add_argument(
        "--keyspace",
        default="",
        help="endpoint.scope.collection; discovered when absent",
    )
    ap.add_argument("--env-file", default=None)
    ap.add_argument(
        "--perform",
        action="store_true",
        help="actually send the candidate bodies (each carries the "
        "endpoint's own current function, so a success is a no-op)",
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
            print(
                f"could not resolve exactly one organization (status {status}); "
                f"pass CAPELLA_ORG_ID"
            )
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

    base = f"/v4/organizations/{org}/projects/{project}/clusters/{cluster}"

    # APP SERVICES ARE LISTED ORGANIZATION-WIDE, filtered on clusterId.
    #
    # An earlier revision of this script issued GET on
    # .../clusters/{cluster}/appservices and got 405, then reported "no App
    # Service on this cluster" -- a statement about the environment, drawn from
    # a fact about the route. That cluster-scoped path exists for the CREATE
    # (POST) only; GET is not allowed on it, which is what 405 says. The list
    # lives at /v4/organizations/{org}/appservices with an optional projectId
    # query and NO clusterId one, so the cluster filter is applied here, on the
    # returned rows. capella_app_services_list in handlers/capella/spec.py has
    # recorded this since it was written; the probe simply did not follow it.
    status, text = call(
        "GET", f"/v4/organizations/{org}/appservices?projectId={project}", token
    )
    if status == 405:
        print(
            "405 listing App Services. That is a route fact, not an environment "
            "fact -- the list is organization-wide, not cluster-scoped."
        )
        return 2
    rows = [r for r in _rows(text) if r.get("clusterId") == cluster]
    if status != 200:
        print(f"App Services list failed: {status} {_message(text)}")
        return 2
    if not rows:
        print(f"no App Service on cluster {cluster} -- nothing to probe")
        return 2
    app_service = rows[0]["id"]
    print(f"[ids] app service {app_service}  ({rows[0].get('name')})")

    status, text = call("GET", f"{base}/appservices/{app_service}/appEndpoints", token)
    rows = _rows(text)
    if status != 200 or not rows:
        print(f"no App Endpoint (status {status}) -- nothing to probe")
        return 2
    endpoint = rows[0]

    # THE FUNCTION COMES OUT OF THE ENDPOINT DOCUMENT, not out of its own getter.
    # capella_app_endpoint_access_control_function_get answers 200 with an EMPTY
    # body (measured 2026-09-14) while this document carries the source.
    scope = collection = source = ""
    if args.keyspace:
        parts = args.keyspace.split(".")
        if len(parts) != 3:
            print("--keyspace must be endpoint.scope.collection")
            return 2
        _, scope, collection = parts
    scopes = endpoint.get("scopes") or {}
    for scope_name, scope_doc in scopes.items():
        if scope and scope_name != scope:
            continue
        for coll_name, coll in (scope_doc or {}).get("collections", {}).items():
            if collection and coll_name != collection:
                continue
            fn = (coll or {}).get("accessControlFunction") or ""
            if fn:
                scope, collection, source = scope_name, coll_name, fn
                break
        if source:
            break

    if not source:
        print(
            "no collection on this endpoint carries an accessControlFunction.\n"
            "REFUSING to probe: every candidate would have to carry an invented\n"
            "source, and an invented source cannot tell 'wrong envelope' apart\n"
            "from 'wrong JavaScript' -- which is the only question being asked."
        )
        return 2

    keyspace = f"{endpoint.get('name')}.{scope}.{collection}"
    path = f"{base}/appservices/{app_service}/appEndpoints/{keyspace}/accessControlFunction"
    print(f"[ids] keyspace {keyspace}")
    print(f"\ncurrent function, read from the endpoint document:\n    {source!r}\n")

    cands = candidates(source, scope, collection)
    if not args.perform:
        print(
            f"{len(cands)} candidate bodies, in send order (not sent -- pass --perform):"
        )
        for label, body in cands:
            print(f"  - {label}: {json.dumps(body)[:160]}")
        return 0

    print(f"PUT {path}\n")
    winner = None
    discriminator_answers: list[tuple[str, int, str]] = []
    for label, body in cands:
        status, text = call_retrying("PUT", path, token, body)
        msg = _message(text)
        print(f"  {status:>3}  {label}")
        print(f"       {msg[:260]}")
        if label.startswith("DISCRIMINATOR"):
            discriminator_answers.append((label, status, msg))
        if 200 <= status < 300:
            winner = (label, body)
            print("\n  ^ ACCEPTED. Later candidates were not sent.")
            break

    print()
    if winner:
        label, body = winner
        print("RESULT: the body shape is")
        print(f"    {json.dumps(body, indent=2)}")
        print(f"keyed '{label}'. It wrote back the endpoint's own function, so nothing")
        print("changed. Put this shape in handlers/capella/spec.py.")
        return 0

    if discriminator_answers:
        distinct = {msg for _, _, msg in discriminator_answers}
        print("DISCRIMINATOR VERDICT")
        for label, status, msg in discriminator_answers:
            print(f"  {status:>3}  {label}")
            print(f"       {msg[:200]}")
        if len(distinct) == 1:
            print("\n  All three inputs -- including text that is not JavaScript --")
            print("  produced the SAME message. Nothing was ever compiled. That")
            print("  message is boilerplate for 'no source found here', it is not a")
            print("  verdict about the JavaScript, and no further shape can be")
            print("  distinguished from any other by it. STOP PROBING: the body")
            print("  shape is not discoverable from the outside, and the next step")
            print("  is Couchbase, not a 33rd combination.")
        else:
            print("\n  The messages DIFFER, so the validator does read the source.")
            print("  The envelope in these three is therefore right, and the")
            print("  remaining question is only which source form it wants.")
        print()

    # THE DEDICATED PATH HAS NOW FAILED IN EVERY SHAPE. Before concluding
    # anything, try the two routes that are not that path at all.
    print("=" * 66)
    print("ROUTE 2: endpoint NAME in the path, collection carried separately")
    print("=" * 66)
    if try_name_path_variants(
        base, app_service, str(endpoint.get("name")), token, scope, collection, source
    ):
        return 0

    print()
    print("=" * 66)
    print("ROUTE 3: write the endpoint DOCUMENT (what Terraform does)")
    print("=" * 66)
    if try_endpoint_document(
        base, app_service, endpoint, token, scope, collection, source
    ):
        return 0

    print()
    print(f"RESULT: none of the {len(cands)} combinations was accepted.")
    print("That is a stronger negative than round 1's, because this round varied")
    print("the SOURCE as well as the envelope. If every failure still says")
    print("'does not evaluate to a function' -- including the named declaration")
    print("and the arrow function, both of which unambiguously evaluate to one --")
    print("then the request never reaches a JavaScript engine at all and the")
    print("message is boilerplate. At that point the next move is the provider's")
    print("generated client, not a seventeenth guess: see spec_pending.py on why")
    print("a rendered docs page is the weaker source.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
