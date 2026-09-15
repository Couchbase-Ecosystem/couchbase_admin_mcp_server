"""The tool listing is scoped to the principal, and agrees with the gate.

WHY THIS FILE EXISTS
====================
Authentication on `list_tools` was added after it was found to have none: any
client that completed the handshake got the full inventory. Authorization was
not. A token that validated got everything the deployment had loaded, whatever
it was actually permitted to invoke.

MEASURED 2026-09-15, against a real Keycloak realm rather than a synthetic
claim dictionary: a service account holding only `couchbase-admin-mcp:read` was
offered 146 tools, `admin_scope_create` and `admin_scope_delete` among them,
with their full argument schemas -- and was then correctly refused at call time
with "requires scope 'couchbase-admin-mcp:write'".

Nothing escalated. The gate held; that is why this is a disclosure finding and
not a bypass. What a reader token could read off the listing was the
deployment's posture -- which tools are loaded, that writes are enabled at all,
what arguments they take -- and the weakest credential in a tenant is the one
handed out most widely.

THE PROPERTY THIS FILE DEFENDS
==============================
The listing and the gate must be ONE decision. Two classifiers agree until they
do not, and the disagreement has two shapes:

  advertised, then refused   confusing, and how this was found
  omitted, but still callable   a control that LOOKS enforced and is not

The second is the dangerous one, which is why `test_the_listing_never_implies_a
_control_it_does_not_have` asserts the gate independently rather than trusting
the filter. The listing is not a security boundary. The gate is.

Licensed under the Apache License, Version 2.0. Copyright 2026 Couchbase, Inc.
See the LICENSE and NOTICE files at the repository root.
"""

from __future__ import annotations

import asyncio
import importlib

READ = "couchbase-admin-mcp:read"
WRITE = "couchbase-admin-mcp:write"
AUTOMATION = "couchbase-admin-mcp:automation"


def _run(coro):
    """Own the loop rather than borrowing the ambient one.

    asyncio.get_event_loop() is deprecated with no running loop and, under
    pytest-randomly, picks up whatever a previously-ordered test left behind.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _server_under_http_auth(monkeypatch):
    """A freshly-imported server on the HTTP transport with auth demanded."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "http")
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")

    import server

    importlib.reload(server)
    return server


def _catalog_of_one_each(monkeypatch, server):
    """Replace the catalog with exactly one read tool and one write tool.

    WHY NOT THE REAL CATALOG
    ────────────────────────
    Setting CB_ADMIN_READ_ONLY_MODE=false and reloading server does NOT load the
    write tools. server.py's own note says why: handlers.shared snapshots that
    variable at ITS import time, and READ_ONLY_MODE is imported from there, so a
    reload of server alone cannot move it.

    The first version of this file did exactly that and its two leak assertions
    passed against a catalog containing no write tools at all -- "no write tool
    was disclosed" is trivially true when none exist. Caught only by the vacuity
    guard in test_an_automation_token_still_sees_the_write_surface, which is the
    entire reason that guard is written as an assertion rather than a comment.

    What this file tests is the FILTER. Whether a particular deployment loads
    write tools is a different property, owned by the read-only-mode tests. So
    the catalog is made deterministic here instead of coaxed into shape.

    The write tool is built by copying a real one and dropping its annotations:
    _is_read_side() treats an unannotated tool as write-side -- unknown intent,
    stronger gate -- which server.py's _is_write_tool docstring states outright.
    That avoids fabricating an mcp.types.Tool by hand and depending on the
    constructor's field names.
    """
    read_tool = next(
        (t for t in server._TOOLS if scope_gate_module().is_read_side(t)), None
    )
    assert read_tool is not None, "no read tool in the catalog; fixture cannot build"

    write_tool = read_tool.model_copy(
        update={"name": "zz_fabricated_write_tool", "annotations": None}
    )
    assert not scope_gate_module().is_read_side(write_tool), (
        "fabricated tool still classifies read-side; the unannotated-means-write "
        "rule this fixture relies on has changed"
    )

    monkeypatch.setattr(server, "_TOOLS", [read_tool, write_tool])
    return read_tool.name, write_tool.name


def scope_gate_module():
    from auth import scope_gate

    return scope_gate


def _listed_for(monkeypatch, claims):
    """(read tool name, write tool name, names listed) for a principal."""
    scope_gate = scope_gate_module()
    server = _server_under_http_auth(monkeypatch)
    read_name, write_name = _catalog_of_one_each(monkeypatch, server)

    scope_gate.set_token_claims(claims)
    try:
        names = [t.name for t in _run(server.list_tools())]
    finally:
        scope_gate.clear_token_claims()
    return server, read_name, write_name, names


def test_a_read_token_is_not_offered_write_tools(monkeypatch):
    """The finding, as a regression: 2026-09-15, a real Keycloak reader token was
    offered 146 tools including admin_scope_create, then refused at call time."""
    _, read_name, write_name, names = _listed_for(
        monkeypatch, {"sub": "svc", "scope": READ}
    )
    assert read_name in names, "a read-scoped principal lost the read surface"
    assert write_name not in names, (
        "a write tool was disclosed to a read-only principal"
    )


def test_a_write_token_is_not_offered_read_tools(monkeypatch):
    """The two scopes are independent, and the filter must not quietly assume
    everyone gets the read surface for free."""
    _, read_name, write_name, names = _listed_for(
        monkeypatch, {"sub": "svc", "scope": WRITE}
    )
    assert write_name in names, "a write-scoped principal lost the write surface"
    assert read_name not in names, "a read tool was disclosed to a write-only principal"


def test_an_automation_token_still_sees_the_write_surface(monkeypatch):
    """Automation never substitutes for write, but it must not subtract either."""
    claims = {"sub": "svc", "realm_access": {"roles": [WRITE, AUTOMATION]}}
    _, _, write_name, names = _listed_for(monkeypatch, claims)
    assert write_name in names, "an automation principal lost the write surface"


def test_the_listing_never_implies_a_control_it_does_not_have(monkeypatch):
    """Listing and gate must agree, checked through the GATE's own entry point.

    Asserting the filter against itself would be tautological. This asks
    check_scope() -- the function the CALL path uses, reached through the
    contextvar rather than the resolved-claims argument -- about every tool in
    the catalog, and requires the listing to match it exactly.

    The omission direction is the one that matters: a tool absent from the
    listing that check_scope would still allow means the listing is doing
    security work the gate is not, and someone will eventually rely on it.
    """
    scope_gate = scope_gate_module()
    claims = {"sub": "svc", "scope": READ}
    server, _, _, names = _listed_for(monkeypatch, claims)
    listed = set(names)

    scope_gate.set_token_claims(claims)
    try:
        allowed = {t.name for t in server._TOOLS if scope_gate.check_scope(t) is None}
    finally:
        scope_gate.clear_token_claims()

    assert listed == allowed, (
        "listing and gate disagree — "
        f"advertised but refused: {sorted(listed - allowed)}; "
        f"omitted but callable: {sorted(allowed - listed)}"
    )


def test_an_unauthenticated_caller_still_gets_nothing(monkeypatch):
    """The authentication refusal predates this change and must survive it:
    filtering by scope must not turn 'no token' into 'the read subset'."""
    from auth import scope_gate

    server = _server_under_http_auth(monkeypatch)
    scope_gate.clear_token_claims()
    assert _run(server.list_tools()) == []
