"""Drive the running MCP server with real IdP-issued tokens.

WHAT THIS IS FOR
────────────────
The authorization model — scope gate, automation mode, hard ceiling, audit
principal — was only ever exercised by tokens the test suite minted for itself.
This drives it with tokens a real Keycloak issued, over the real HTTP transport,
against a running server. See deploy/keycloak/README.md for the realm.

It is a LAB tool. It hardcodes the lab realm's client secrets, which are in git
on purpose, and it must never be pointed at anything that matters.

USAGE (PowerShell, from the repo root, with the server running)

    uv run python scripts/idp_lab_assertions.py tools --principal automation
    uv run python scripts/idp_lab_assertions.py call  --principal reader --tool <name>
    uv run python scripts/idp_lab_assertions.py audience

Licensed under the Apache License, Version 2.0. Copyright 2026 Couchbase, Inc.
See the LICENSE and NOTICE files at the repository root.
"""

from __future__ import annotations

import argparse
import json
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


def token_for(principal: str) -> str:
    """A client-credentials access token from the lab realm."""
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
    with urllib.request.urlopen(req, timeout=15) as resp:
        return str(json.load(resp)["access_token"])


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
