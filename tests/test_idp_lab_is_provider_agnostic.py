"""The IdP lab must run the SAME assertions against every provider.

WHY THIS FILE EXISTS
====================
Keycloak proved the plumbing and nothing about where a given tenant puts the
grant — which is the failure most likely to bite, because Keycloak itself put
the entire grant in `realm_access.roles` while `scope` carried only
`profile email`.

Okta is the second provider, and it is the one Couchbase uses internally. The
value of running it is precisely that a shape difference shows up as a FAILING
ASSERTION about the server. That only holds if the assertions are shared and
only the token request differs — a second provider with its own checks would
test something else and report a pass.

So this pins the shape of the harness, not the behaviour of any IdP: no tenant
is contacted by anything here.
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib

import pytest

_SCRIPT = (
    pathlib.Path(__file__).resolve().parent.parent / "scripts" / "idp_lab_assertions.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("idp_lab_assertions", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LAB = _module()
TREE = ast.parse(_SCRIPT.read_text(encoding="utf-8"))


def test_the_script_loads_and_declares_both_providers():
    """Premise for everything below."""
    assert _SCRIPT.is_file()
    assert LAB.IDP in ("keycloak", "okta")


def test_only_the_token_request_branches_on_the_provider():
    """THE property that makes a second provider worth running.

    If the MCP handshake, the tool listing or the call branched on which IdP
    minted the token, the two providers would be running different tests and a
    pass against one would say nothing about the other.
    """
    branching = []
    for node in ast.walk(TREE):
        if not isinstance(node, ast.FunctionDef):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Compare) and any(
                isinstance(c, ast.Constant) and c.value in ("okta", "keycloak")
                for c in inner.comparators
            ):
                branching.append(node.name)
    assert set(branching) <= {"token_for"}, (
        f"these functions branch on the identity provider: {sorted(set(branching))}. "
        "Only token acquisition may differ -- everything after it is the "
        "assertion, and an assertion that differs per provider tests two "
        "different things while reporting one result."
    )


@pytest.mark.parametrize(
    "principal", ["reader", "writer", "automation", "stranger", "otherapp"]
)
def test_every_principal_has_okta_scopes_declared(principal):
    """Okta grants only what the request ASKS for, unlike Keycloak's role
    assignments. A principal with no scopes named would come back holding
    nothing and its assertion would fail for the wrong reason."""
    scopes = LAB._okta_scopes(principal)
    assert scopes and scopes.strip(), principal


def test_the_negative_principals_still_request_a_grant():
    """`stranger` and `otherapp` test the AUDIENCE. A token refused for holding
    no grant would prove the scope gate instead, and report a pass for a check
    that never ran."""
    for principal in ("stranger", "otherapp"):
        assert LAB._okta_scopes(principal).strip(), principal


def test_the_automation_principal_requests_write_as_well_as_automation():
    """Automation alone grants nothing -- it lifts the confirmation requirement
    on a write the token must separately be allowed to make."""
    scopes = LAB._okta_scopes("automation").split()
    assert len(scopes) == 2, scopes
    assert any("automation" in s for s in scopes)
    assert any(s.endswith(":write") for s in scopes)


def test_the_org_authorization_server_is_refused_by_name(monkeypatch):
    """Okta's ORG authorization server cannot carry custom scopes or a
    configurable audience, so it cannot express this server's model at all.
    Pointed at it, every call is denied for a reason that has nothing to do with
    the code -- so it is refused up front, with the reason."""
    monkeypatch.setenv("IDP_LAB_OKTA_ISSUER", "https://example.okta.com")
    with pytest.raises(SystemExit) as refusal:
        LAB._okta_issuer()
    assert "ORG authorization server" in str(refusal.value)


def test_a_custom_authorization_server_is_accepted(monkeypatch):
    """Guards the refusal above from rejecting everything."""
    monkeypatch.setenv("IDP_LAB_OKTA_ISSUER", "https://example.okta.com/oauth2/aus1/")
    assert LAB._okta_issuer() == "https://example.okta.com/oauth2/aus1"


def test_okta_credentials_are_read_from_the_environment_only(monkeypatch):
    """They are real secrets. The Keycloak lab's are in git deliberately because
    the realm is a throwaway; a corporate Okta service app's are not."""
    for suffix in ("ID", "SECRET"):
        monkeypatch.delenv(f"IDP_LAB_OKTA_READER_{suffix}", raising=False)
    with pytest.raises(SystemExit) as refusal:
        LAB._okta_credentials("reader")
    assert "IDP_LAB_OKTA_READER_ID" in str(refusal.value)

    source = _SCRIPT.read_text(encoding="utf-8")
    assert ".okta.com/oauth2/aus" not in source.replace(
        "https://<org>.okta.com/oauth2/<authServerId>", ""
    ), "a real Okta issuer looks hardcoded in the lab script"


def test_the_claims_command_exists_and_reports_an_unread_grant():
    """The one command to run against an unfamiliar tenant. It must FAIL rather
    than print an empty list when the gate reads nothing -- an empty list looks
    like a token problem, and the finding is usually the reader."""
    assert hasattr(LAB, "cmd_claims")
    source = ast.get_source_segment(
        _SCRIPT.read_text(encoding="utf-8"),
        next(
            n
            for n in TREE.body
            if isinstance(n, ast.FunctionDef) and n.name == "cmd_claims"
        ),
    )
    assert "READ NO GRANTS" in source
    assert "NAME NOBODY" in source
    assert "return 1" in source


def test_the_token_decoder_never_decides_anything():
    """It does not verify the signature, so nothing may depend on it. The server
    validates properly; this only prints."""
    source = _SCRIPT.read_text(encoding="utf-8")
    decoder = source.split("def decode_claims", 1)[1].split("\ndef ", 1)[0]
    assert "WITHOUT verifying" in decoder
    for verb in ("validate_token", "set_token_claims"):
        assert verb not in decoder
