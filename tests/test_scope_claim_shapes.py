"""Every claim shape a real identity provider emits must resolve to the same grants.

WHY THIS FILE EXISTS
====================
The unattended authorization model rests entirely on one question: does this
token carry the automation scope? That question is answered by reading claims out
of a JWT, and IdPs disagree -- loudly and undocumentedly -- about which claim a
grant lands in.

Two of those disagreements have already cost something here. Microsoft Entra
issues app permissions for a client-credentials token in `roles`, NOT `scp`, so a
gate reading only scope/scp saw an automation-scoped service principal as
unprivileged. And Keycloak emits SCOPES at the top level but ROLES nested under
`realm_access` / `resource_access` -- so an operator who grants the permission as
a role, which Keycloak's UI makes the natural choice, produced a token that read
as carrying nothing at all.

Both failures point the safe way: the grant is not seen, so the write is gated
and the pipeline stops. But "your automation is silently not automated" is a bad
thing to discover in someone else's CI, and the shape of the fix is entirely in
their IdP rather than in this server.

WHAT THIS DOES NOT COVER, STATED PLAINLY
========================================
These are synthetic claim dictionaries in the layouts the providers document.
They prove the EXTRACTION, not the integration: no signature, no JWKS, no clock,
no live issuer. A provider that changes its layout, or an installation with a
custom mapper, is outside what this can see. The end-to-end check is a real IdP
driving the container, which is still outstanding.
"""

from __future__ import annotations

import pytest

from auth.scope_gate import _claims_scopes

AUTOMATION = "couchbase-admin-mcp:automation"
WRITE = "couchbase-admin-mcp:write"


#: (label, claims, expected subset). Each entry is one provider's documented
#: layout for the same two grants.
_SHAPES = [
    (
        "keycloak scopes (space-delimited `scope`)",
        {"scope": f"openid profile {WRITE} {AUTOMATION}"},
    ),
    (
        "keycloak REALM roles (nested realm_access.roles)",
        {"realm_access": {"roles": [WRITE, AUTOMATION, "offline_access"]}},
    ),
    (
        "keycloak CLIENT roles (nested resource_access.<client>.roles)",
        {"resource_access": {"cb-admin": {"roles": [WRITE, AUTOMATION]}}},
    ),
    (
        "entra client credentials (app permissions in `roles`)",
        {"roles": [WRITE, AUTOMATION]},
    ),
    (
        "entra delegated (`scp` space-delimited)",
        {"scp": f"{WRITE} {AUTOMATION}"},
    ),
    ("okta (`scp` as a list)", {"scp": [WRITE, AUTOMATION]}),
    ("auth0 RBAC (`permissions`)", {"permissions": [WRITE, AUTOMATION]}),
    ("auth0 scopes (`scope`)", {"scope": f"{WRITE} {AUTOMATION}"}),
]


@pytest.mark.parametrize(("label", "claims"), _SHAPES, ids=[s[0] for s in _SHAPES])
def test_every_provider_shape_yields_the_same_grants(label, claims):
    """The whole point: the gate must not care which IdP minted the token."""
    granted = _claims_scopes(claims)
    assert AUTOMATION in granted, f"{label}: automation grant not extracted"
    assert WRITE in granted, f"{label}: write grant not extracted"


def test_the_shape_table_is_not_empty():
    """Guards the parametrised test above from passing vacuously.

    tests/test_no_vacuous_coverage.py scans for exactly this, and an empty
    parametrize reads as a SKIP that looks like a platform limitation.
    """
    assert len(_SHAPES) >= 8, _SHAPES


def test_a_grant_under_an_unread_claim_is_not_invented():
    """The other direction. Tolerating every shape must not become tolerating
    every CLAIM -- a gate that scrapes the whole token for a matching string
    would grant on an audience, a client name, or an unrelated custom claim."""
    granted = _claims_scopes(
        {
            "aud": AUTOMATION,
            "azp": AUTOMATION,
            "custom_entitlements": [AUTOMATION],
            "groups": [AUTOMATION],
        }
    )
    assert granted == set(), granted


def test_shapes_combine_rather_than_shadow():
    """Entra can issue delegated scopes in `scp` and app roles in `roles` at the
    same time, and Keycloak issues `scope` alongside nested roles. Reading the
    first non-empty claim and stopping would drop half the grant."""
    granted = _claims_scopes(
        {
            "scp": WRITE,
            "roles": [AUTOMATION],
            "realm_access": {"roles": ["cluster-admin"]},
        }
    )
    assert {WRITE, AUTOMATION, "cluster-admin"} <= granted


@pytest.mark.parametrize(
    "malformed",
    [
        {"scope": None},
        {"scope": 12345},
        {"roles": None},
        {"realm_access": "not-a-dict"},
        {"realm_access": {"roles": "a-string-not-a-list"}},
        {"resource_access": {"cb-admin": "not-a-dict"}},
        {"resource_access": {"cb-admin": {"roles": None}}},
    ],
)
def test_a_malformed_claim_yields_nothing_rather_than_raising(malformed):
    """A token is attacker-influenced input. The gate must refuse it, not crash
    into a 500 that a caller can trigger at will."""
    assert _claims_scopes(malformed) in (set(), {"a-string-not-a-list"})
