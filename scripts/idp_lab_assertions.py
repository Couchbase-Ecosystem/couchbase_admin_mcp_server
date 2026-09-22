"""Drive the running MCP server with real IdP-issued tokens.

WHAT THIS IS FOR
────────────────
The authorization model — scope gate, automation mode, hard ceiling, audit
principal — was only ever exercised by tokens the test suite minted for itself.
This drives it with tokens a real Keycloak issued, over the real HTTP transport,
against a running server. See deploy/keycloak/README.md for the realm.

It is a LAB tool. Against Keycloak it hardcodes the lab realm's client secrets,
which are in git on purpose, and it must never be pointed at anything that
matters.

TWO PROVIDERS, ONE SET OF ASSERTIONS
────────────────────────────────────
Keycloak proves the PLUMBING. It does not prove where a given tenant puts the
grant, and that is the failure most likely to bite: Keycloak itself put the
entire grant in `realm_access.roles` with the top-level `scope` claim carrying
only `profile email`, so a server reading the obvious claims saw a fully
authorized automation principal as holding nothing.

So the provider is pluggable and the assertions are not. `--idp okta` runs the
same checks against a real Okta authorization server, which is what Couchbase
uses internally — the point being that a shape difference shows up as a FAILING
ASSERTION here rather than as a surprise in front of a customer.

OKTA CONFIGURATION, all from the environment because these are real secrets:

    IDP_LAB_OKTA_ISSUER      https://<org>.okta.com/oauth2/<authServerId>
    IDP_LAB_OKTA_SCOPE_READ        default couchbase-admin-mcp:read
    IDP_LAB_OKTA_SCOPE_WRITE       default couchbase-admin-mcp:write
    IDP_LAB_OKTA_SCOPE_AUTOMATION  default couchbase-admin-mcp:automation
    IDP_LAB_OKTA_<PRINCIPAL>_ID       e.g. IDP_LAB_OKTA_READER_ID
    IDP_LAB_OKTA_<PRINCIPAL>_SECRET   e.g. IDP_LAB_OKTA_READER_SECRET

Okta needs a CUSTOM authorization server: the org authorization server cannot
carry custom scopes or a configurable audience, so it cannot express this
server's grants at all. See docs/OKTA_LAB.md.

Okta also differs from Keycloak in a way that matters here: it grants only the
scopes the token request ASKS for, so each principal names its scopes rather
than receiving them from a role assignment.

USAGE (PowerShell, from the repo root, with the server running)

    uv run python scripts/idp_lab_assertions.py tools --principal automation
    uv run python scripts/idp_lab_assertions.py call  --principal reader --tool <name>
    uv run python scripts/idp_lab_assertions.py audience
    uv run python scripts/idp_lab_assertions.py claims --principal automation

    uv run python scripts/idp_lab_assertions.py --idp okta tools --principal reader

Licensed under the Apache License, Version 2.0. Copyright 2026 Couchbase, Inc.
See the LICENSE and NOTICE files at the repository root.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

KEYCLOAK = "http://localhost:8080/realms/mcp"
MCP = "http://127.0.0.1:8000/mcp"

# Lab realm principals. The secrets are the ones in
# deploy/keycloak/realm-cb-admin-mcp.json and are deliberately not secret.
PRINCIPALS = {
    "reader": ("cb-admin-mcp-reader", "reader-secret"),
    "writer": ("cb-admin-mcp-writer", "writer-secret"),
    "automation": ("cb-admin-mcp-automation", "automation-secret"),
    # No grant AND no audience mapper: refused at token validation for a MISSING
    # aud claim, never reaching the scope gate.
    "stranger": ("cb-admin-mcp-stranger", "stranger-secret"),
    # A WELL-FORMED token that simply belongs to someone else: correct issuer,
    # correct signature, a real `aud` -- for a different application -- and the
    # write role. This is the Disney-shaped case and the stronger of the two: a
    # missing-claim refusal proves the required-claims check, not the audience
    # COMPARISON, and every token minted for another app in a shared tenant will
    # have an aud.
    "otherapp": ("cb-admin-mcp-otherapp", "otherapp-secret"),
}

PROTOCOL_VERSION = "2025-06-18"


#: Which provider the current run is minting tokens from. Set once from --idp.
IDP = "keycloak"


def _okta_issuer() -> str:
    issuer = (os.environ.get("IDP_LAB_OKTA_ISSUER") or "").strip().rstrip("/")
    if not issuer:
        raise SystemExit(
            "IDP_LAB_OKTA_ISSUER is not set. It is the CUSTOM authorization\n"
            "server's issuer, https://<org>.okta.com/oauth2/<authServerId> --\n"
            "NOT https://<org>.okta.com, which is the org authorization server\n"
            "and cannot carry custom scopes or a configurable audience.\n"
            "See docs/OKTA_LAB.md."
        )
    if "/oauth2/" not in issuer:
        raise SystemExit(
            f"IDP_LAB_OKTA_ISSUER is {issuer!r}, which has no /oauth2/<id> "
            f"segment.\nThat is the ORG authorization server. It cannot mint a "
            f"token carrying this\nserver's scopes, so every call would be "
            f"denied for a reason that has nothing\nto do with the code under "
            f"test. See docs/OKTA_LAB.md."
        )
    return issuer


#: Scopes each principal asks Okta for. Keycloak hands out role assignments
#: whatever the request asks for; Okta grants only what is REQUESTED, so the
#: grant has to be named here as well as allowed in the tenant.
def _okta_scopes(principal: str) -> str:
    read = os.environ.get("IDP_LAB_OKTA_SCOPE_READ", "couchbase-admin-mcp:read")
    write = os.environ.get("IDP_LAB_OKTA_SCOPE_WRITE", "couchbase-admin-mcp:write")
    automation = os.environ.get(
        "IDP_LAB_OKTA_SCOPE_AUTOMATION", "couchbase-admin-mcp:automation"
    )
    return {
        "reader": read,
        "writer": write,
        "automation": f"{write} {automation}",
        # The two negative principals ask for a grant on purpose: the refusal
        # under test is the AUDIENCE, and a token refused for holding nothing
        # would prove a different thing.
        "stranger": read,
        "otherapp": write,
    }[principal]


def _okta_credentials(principal: str) -> tuple[str, str]:
    prefix = f"IDP_LAB_OKTA_{principal.upper()}"
    client_id = (os.environ.get(f"{prefix}_ID") or "").strip()
    secret = (os.environ.get(f"{prefix}_SECRET") or "").strip()
    if not client_id or not secret:
        raise SystemExit(
            f"{prefix}_ID and {prefix}_SECRET must both be set to run the "
            f"{principal!r}\nprincipal against Okta. They are real credentials, "
            f"so they are read from the\nenvironment and never stored in this "
            f"repository. See docs/OKTA_LAB.md."
        )
    return client_id, secret


def token_for(principal: str) -> str:
    """A client-credentials access token for one lab principal.

    THE TOKEN REQUEST IS THE ONLY PROVIDER-SPECIFIC PART. Everything after it --
    the MCP handshake, the tool listing, the call, the refusals -- is identical,
    which is the point: a difference between providers has to surface as a
    failing assertion about the SERVER, not as a different test.
    """
    if IDP == "okta":
        # Issuer FIRST. Pointing at the org authorization server is the mistake
        # that costs the most time, and a missing-credential message would send
        # the reader looking for a secret when the endpoint is the problem.
        issuer = _okta_issuer()
        client_id, secret = _okta_credentials(principal)
        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "scope": _okta_scopes(principal),
            }
        ).encode()
        # HTTP Basic, which is Okta's default client authentication method for
        # a service app (`client_secret_basic`).
        basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
        req = urllib.request.Request(
            f"{issuer}/v1/token",
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Authorization": f"Basic {basic}",
            },
        )
    else:
        client_id, secret = PRINCIPALS[principal]
        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": secret,
            }
        ).encode()
        req = urllib.request.Request(
            f"{KEYCLOAK}/protocol/openid-connect/token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return str(json.load(resp)["access_token"])
    except urllib.error.HTTPError as exc:
        # THE IdP's OWN MESSAGE, not a stack trace. Every failure here is a
        # tenant configuration problem -- an unassigned scope, a client not
        # permitted the grant type, the wrong authorization server -- and the
        # body says which. Swallowing it sends the reader to the code instead.
        detail = exc.read().decode("utf-8", "replace").strip()
        raise SystemExit(
            f"{IDP} refused to mint a token for {principal!r}: "
            f"HTTP {exc.code}\n{detail}"
        ) from exc


def decode_claims(token: str) -> dict:
    """The access token's payload, WITHOUT verifying it.

    For reading what the tenant actually put in the token, which is the one
    thing no amount of local testing can predict. Never used to decide
    anything -- the server verifies properly; this only prints.
    """
    try:
        payload = token.split(".")[1]
    except IndexError:
        return {}
    payload += "=" * (-len(payload) % 4)
    try:
        return dict(json.loads(base64.urlsafe_b64decode(payload)))
    except Exception:
        return {}


def _parse(raw: bytes, content_type: str) -> dict | None:
    """Streamable HTTP answers as JSON or as a single SSE event. Accept both."""
    text = raw.decode("utf-8", "replace").strip()
    if not text:
        return None
    if "text/event-stream" in content_type:
        for line in text.splitlines():
            if line.startswith("data:"):
                return dict(json.loads(line[5:].strip()))
        return None
    return dict(json.loads(text))


class Session:
    """One MCP streamable-HTTP session, with the handshake done properly.

    A tool call without a session id is refused, and the session id only exists
    after `initialize`. Skipping the `notifications/initialized` that follows it
    leaves the server waiting, so both steps are here rather than optional.
    """

    def __init__(self, token: str) -> None:
        self.token = token
        self.session_id: str | None = None

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            # Both, because the server may answer either way.
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {self.token}",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    def post(self, payload: dict) -> tuple[int, dict | None, dict[str, str]]:
        req = urllib.request.Request(
            MCP, data=json.dumps(payload).encode(), headers=self._headers()
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                parsed = _parse(resp.read(), headers.get("content-type", ""))
                return resp.status, parsed, headers
        except urllib.error.HTTPError as exc:
            headers = {k.lower(): v for k, v in exc.headers.items()}
            body = exc.read()
            try:
                parsed = _parse(body, headers.get("content-type", ""))
            except Exception:
                parsed = {"raw": body.decode("utf-8", "replace")[:400]}
            return exc.code, parsed, headers

    def initialize(self) -> tuple[int, dict | None]:
        status, parsed, headers = self.post(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "idp-lab-assertions", "version": "1"},
                },
            }
        )
        self.session_id = headers.get("mcp-session-id")
        if status == 200 and self.session_id:
            # Fire-and-forget; a 202 with no body is the expected answer.
            self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return status, parsed


def cmd_tools(args: argparse.Namespace) -> int:
    session = Session(token_for(args.principal))
    status, parsed = session.initialize()
    print(f"initialize -> HTTP {status}  session={session.session_id!r}")
    if status != 200:
        print(json.dumps(parsed, indent=2)[:1200])
        return 1
    status, parsed, _ = session.post(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    )
    tools = ((parsed or {}).get("result") or {}).get("tools") or []
    print(f"tools/list -> HTTP {status}, {len(tools)} tools")
    for tool in tools:
        if args.grep and args.grep not in tool.get("name", ""):
            continue
        hints = tool.get("annotations") or {}
        flags = "RO" if hints.get("readOnlyHint") else "WRITE"
        print(f"  {flags:5}  {tool.get('name')}")
    return 0


def cmd_call(args: argparse.Namespace) -> int:
    session = Session(token_for(args.principal))
    status, parsed = session.initialize()
    print(f"initialize -> HTTP {status}  session={session.session_id!r}")
    if status != 200:
        print(json.dumps(parsed, indent=2)[:1200])
        return 1
    call_args = json.loads(args.args) if args.args else {}
    # --arg key=value, repeatable. PowerShell mangles embedded double quotes when
    # passing a JSON string to a native command, which turns a tool-argument typo
    # into a JSON parse error and sends you debugging the wrong thing. key=value
    # has no quoting to get wrong. Values are passed as strings; a bare true/false
    # or integer is converted, since tool schemas do care.
    for pair in args.arg or []:
        if "=" not in pair:
            print(f"--arg must be key=value, got {pair!r}")
            return 2
        key, _, raw = pair.partition("=")
        if raw.lower() in ("true", "false"):
            call_args[key] = raw.lower() == "true"
        elif raw.lstrip("-").isdigit():
            call_args[key] = int(raw)
        else:
            call_args[key] = raw
    status, parsed, _ = session.post(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": args.tool, "arguments": call_args},
        }
    )
    print(f"tools/call {args.tool} as {args.principal} -> HTTP {status}")
    print(json.dumps(parsed, indent=2)[:3000])
    return 0


def cmd_audience(args: argparse.Namespace) -> int:
    """Both audience refusals, because they are not the same refusal.

    `stranger` carries no audience mapper at all, so it fails the required-claims
    check with MissingRequiredClaimError. That proves the claim is demanded.

    `otherapp` carries a real `aud` of `some-other-app` AND the write role. It is
    correctly signed by the right issuer and is, to every check except the
    audience comparison, a valid administrator. It is the one that proves the
    comparison happens -- and it is the realistic case, because a large shared
    tenant mints tokens for other applications all day and every one of them has
    an aud.

    Both must be refused at token validation, before the scope gate. A refusal
    that came from the scope gate instead would mean an unrelated token had
    already been admitted as a principal.
    """
    failures = 0
    for principal, expect_detail in (
        ("stranger", "missing aud"),
        ("otherapp", "wrong aud"),
    ):
        session = Session(token_for(principal))
        status, parsed = session.initialize()
        ok = status == 401
        failures += 0 if ok else 1
        print(
            f"{principal:10} ({expect_detail:11}) -> HTTP {status} "
            f"{'OK' if ok else 'NOT REFUSED — investigate'}"
        )
        print("           " + json.dumps(parsed or {})[:300])
    return 0 if failures == 0 else 1


def cmd_claims(args: argparse.Namespace) -> int:
    """Print the token's claims, and what THIS SERVER would read from them.

    The one command to run against an unfamiliar tenant. Everything else tests
    the server; this answers the question the server cannot: where did your IdP
    put the grant, and did we look there.
    """
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from auth.scope_gate import _claims_scopes, principal_of

    token = token_for(args.principal)
    claims = decode_claims(token)
    if not claims:
        print("the token payload could not be decoded")
        return 2

    print(f"--- claims as {IDP} minted them for {args.principal!r}")
    print(json.dumps(claims, indent=1, sort_keys=True))

    grants = _claims_scopes(claims)
    principal = principal_of(claims)
    print("\n--- what this server reads from them")
    print(f"  grants     {sorted(grants) or 'NOTHING'}")
    print(f"  principal  {principal['principal']!r}")
    print(f"  client_id  {principal['client_id']!r}")
    print(f"  automation {principal['automation']}")
    print(f"  issuer     {principal['issuer']!r}")

    if not grants:
        # THE FAILURE THIS COMMAND EXISTS TO CATCH, stated rather than left to
        # be inferred from an empty list. Keycloak put the whole grant in
        # realm_access.roles while `scope` carried only `profile email`; a
        # tenant can put it somewhere else again.
        print(
            "\n*** THE GATE READ NO GRANTS FROM THIS TOKEN. Every write will be "
            "refused and\n    automation will be silently off. Compare the "
            "claims above against the ones\n    auth/scope_gate.py reads: "
            "scope, scp, scopes, roles, permissions, realm_access.roles\n    "
            "and resource_access.<client>.roles. If the grant is in a claim not "
            "on that\n    list, the token is fine and the READER is the defect."
        )
        return 1
    if not principal["principal"] or not principal["client_id"]:
        print(
            "\n*** THE AUDIT RECORD WOULD NAME NOBODY. The call would be "
            "authorized and\n    executed with no identity recorded, which for "
            "an unattended deployment is\n    the only identity there is."
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--idp",
        default=os.environ.get("IDP_LAB_PROVIDER", "keycloak"),
        choices=("keycloak", "okta"),
        help="which identity provider mints the tokens. The assertions are the "
        "same either way; only the token request differs.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_tools = sub.add_parser("tools", help="list the tools this principal sees")
    p_tools.add_argument("--principal", default="automation", choices=PRINCIPALS)
    p_tools.add_argument("--grep", default="", help="substring filter on tool name")
    p_tools.set_defaults(func=cmd_tools)

    p_call = sub.add_parser("call", help="call one tool as one principal")
    p_call.add_argument("--principal", required=True, choices=PRINCIPALS)
    p_call.add_argument("--tool", required=True)
    p_call.add_argument("--args", default="", help="JSON object of tool arguments")
    p_call.add_argument(
        "--arg",
        action="append",
        metavar="KEY=VALUE",
        help="a single tool argument; repeatable. Avoids shell JSON quoting.",
    )
    p_call.set_defaults(func=cmd_call)

    p_aud = sub.add_parser("audience", help="the stranger-token refusal")
    p_aud.set_defaults(func=cmd_audience)

    p_claims = sub.add_parser(
        "claims", help="print the token's claims and what this server reads"
    )
    p_claims.add_argument("--principal", default="automation", choices=PRINCIPALS)
    p_claims.set_defaults(func=cmd_claims)

    args = parser.parse_args()

    global IDP
    IDP = args.idp
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
