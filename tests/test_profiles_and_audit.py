"""
Tests for the two deployment profiles and the audit record.

The two deployments have genuinely different trust models:

  workstation  Developer laptop, stdio, Claude Desktop. A HUMAN IS PRESENT, so
               `confirm: true` is a real second look. No IdP, no token; identity
               is the OS user.
  enterprise   git push -> workflow-manager agent -> child agent -> MCP ->
               Couchbase. NO HUMAN at the moment of action, by design. The
               authorization is the automation scope in the child's IdP-issued
               token; `confirm: true` would be the model rubber-stamping itself.

Getting those defaults backwards is what produced several of the real findings, so
the profile is a stated decision and incoherent combinations refuse to start.
"""

from __future__ import annotations

import importlib
import json

import pytest

import profile_config
from auth import scope_gate


@pytest.fixture(autouse=True)
def _clean_profile_env(monkeypatch):
    for key in (
        "CB_ADMIN_PROFILE",
        "CB_ADMIN_READ_ONLY_MODE",
        "CB_ADMIN_HTTP_REQUIRE_AUTH",
        "OAUTH_ENABLED",
        "OAUTH_ISSUER",
        "OAUTH_AUDIENCE",
        "OAUTH_SKIP_VERIFY",
        "CB_GUI_INSECURE_NO_AUTH",
        "CB_ADMIN_EGRESS_ALLOW_ANY",
        "CB_ADMIN_TLS_INSECURE",
        "CB_ADMIN_TRANSPORT",
        "CB_ADMIN_LOG_SINKS",
        "CB_ADMIN_GUI_AUTOMATION",
        "CB_ADMIN_HOST",
        "CB_ADMIN_AUDIT_FILE",
    ):
        monkeypatch.delenv(key, raising=False)


# ── Profile application ──────────────────────────────────────────────────────


def test_no_profile_is_reported_rather_than_guessed(monkeypatch):
    """Silently picking a default would mean the posture is whatever the first
    deployment happened to inherit."""
    name, notes = profile_config.apply_profile()
    assert name is None
    assert any("CB_ADMIN_PROFILE is not set" in n for n in notes)


def test_workstation_profile_does_not_demand_auth(monkeypatch):
    """There is no IdP on a laptop; requiring auth would fail closed for nothing."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    name, _ = profile_config.apply_profile()
    assert name == profile_config.WORKSTATION
    import os

    assert os.environ["CB_ADMIN_HTTP_REQUIRE_AUTH"] == "false"
    assert os.environ["CB_ADMIN_TRANSPORT"] == "stdio"
    assert os.environ["CB_ADMIN_HOST"] == "127.0.0.1"


def test_enterprise_profile_demands_auth_and_sso(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    name, _ = profile_config.apply_profile()
    assert name == profile_config.ENTERPRISE
    import os

    assert os.environ["CB_ADMIN_HTTP_REQUIRE_AUTH"] == "true"
    assert os.environ["OAUTH_ENABLED"] == "true"
    assert os.environ["CB_GUI_INSECURE_NO_AUTH"] == "0"


def test_explicit_settings_always_win_over_the_profile(monkeypatch):
    """An operator who has made a decision keeps it; the profile only fills gaps."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.setenv("CB_ADMIN_LOG_SINKS", "stderr")
    profile_config.apply_profile()
    import os

    assert os.environ["CB_ADMIN_LOG_SINKS"] == "stderr"


# ── Refusing incoherent postures ─────────────────────────────────────────────


def test_enterprise_refuses_skip_verify(monkeypatch):
    """The unattended model rests entirely on token validation."""
    monkeypatch.setenv("OAUTH_SKIP_VERIFY", "true")
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example")
    monkeypatch.setenv("OAUTH_AUDIENCE", "api://cb")
    errors = profile_config.validate(profile_config.ENTERPRISE)
    assert any("OAUTH_SKIP_VERIFY" in e for e in errors)


def test_enterprise_refuses_an_unauthenticated_console(monkeypatch):
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example")
    monkeypatch.setenv("OAUTH_AUDIENCE", "api://cb")
    errors = profile_config.validate(profile_config.ENTERPRISE)
    assert any("CB_GUI_INSECURE_NO_AUTH" in e for e in errors)


def test_enterprise_requires_issuer_and_audience():
    errors = profile_config.validate(profile_config.ENTERPRISE)
    assert any("OAUTH_ISSUER" in e for e in errors)
    assert any("OAUTH_AUDIENCE" in e for e in errors)


def test_enterprise_refuses_insecure_tls(monkeypatch):
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example")
    monkeypatch.setenv("OAUTH_AUDIENCE", "api://cb")
    monkeypatch.setenv("CB_ADMIN_TLS_INSECURE", "true")
    errors = profile_config.validate(profile_config.ENTERPRISE)
    assert any("CB_ADMIN_TLS_INSECURE" in e for e in errors)


def test_a_correct_enterprise_posture_has_no_errors(monkeypatch):
    monkeypatch.setenv("OAUTH_ISSUER", "https://login.microsoftonline.com/t/v2.0")
    monkeypatch.setenv("OAUTH_AUDIENCE", "api://cb-admin")
    # Both of these are now required, and both were previously unchecked: an
    # explicit CB_ADMIN_HTTP_REQUIRE_AUTH=false passed validation and produced full
    # unauthenticated admin on a loopback bind, and with no durable audit sink an
    # unattended write left no record that survived the process.
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", "/var/log/cb/audit.log")
    assert profile_config.validate(profile_config.ENTERPRISE) == []


def test_enterprise_requires_authentication_to_be_on(monkeypatch):
    """The variable the entire enterprise model rests on was never validated."""
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example")
    monkeypatch.setenv("OAUTH_AUDIENCE", "api://cb")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", "/tmp/a.log")
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "false")
    errors = profile_config.validate(profile_config.ENTERPRISE)
    assert any("CB_ADMIN_HTTP_REQUIRE_AUTH" in e for e in errors)


def test_enterprise_requires_a_durable_audit_sink(monkeypatch):
    """stderr is the default sink and a spawned server discards it, so an unattended
    write would leave no record that outlives the process."""
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example")
    monkeypatch.setenv("OAUTH_AUDIENCE", "api://cb")
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    monkeypatch.delenv("CB_ADMIN_AUDIT_FILE", raising=False)
    monkeypatch.setenv("CB_ADMIN_LOG_SINKS", "stderr")
    errors = profile_config.validate(profile_config.ENTERPRISE)
    assert any("audit sink" in e for e in errors)


def test_skip_verify_is_fatal_in_every_profile(monkeypatch):
    """It returns claims for an UNSIGNED token, and those claims can name the
    automation scope — which skips the confirmation gate entirely. Previously only
    the enterprise profile refused it."""
    monkeypatch.setenv("OAUTH_SKIP_VERIFY", "true")
    assert any(
        "OAUTH_SKIP_VERIFY" in e
        for e in profile_config.validate(profile_config.WORKSTATION)
    )


def test_an_unset_profile_is_itself_an_error():
    """An unstated profile previously received zero validation, so a server could
    start with no posture at all."""
    assert any("CB_ADMIN_PROFILE" in e for e in profile_config.validate(None))


def test_workstation_is_not_held_to_enterprise_rules(monkeypatch):
    """A laptop with no IdP must not be refused for having no issuer."""
    assert profile_config.validate(profile_config.WORKSTATION) == []


# ── The automation scope: the enterprise authorization path ──────────────────


def test_entra_client_credentials_automation_scope_is_recognised():
    """Microsoft Entra puts APP permissions in `roles`, not `scp`. Reading only
    scope/scp/scopes made a workflow service principal's automation grant
    invisible — silently demoting an authorized autonomous caller to
    'needs per-call confirmation'. Okta uses scp and Auth0 scope, so this would
    have passed testing against either and failed against Entra."""
    claims = {
        "sub": "sp-workflow-manager",
        "appid": "0000-app",
        "roles": ["couchbase-admin-mcp:write", "couchbase-admin-mcp:automation"],
    }
    scope_gate.set_token_claims(claims)
    try:
        assert scope_gate.session_has_automation_scope() is True
    finally:
        scope_gate.clear_token_claims()


@pytest.mark.parametrize(
    "claims",
    [
        {"scp": ["couchbase-admin-mcp:automation"]},
        {"scope": "couchbase-admin-mcp:automation couchbase-admin-mcp:write"},
        {"scopes": ["couchbase-admin-mcp:automation"]},
        {"permissions": ["couchbase-admin-mcp:automation"]},
        {"roles": ["couchbase-admin-mcp:automation"]},
    ],
    ids=["okta-scp", "auth0-scope", "scopes", "auth0-permissions", "entra-roles"],
)
def test_every_idp_scope_claim_shape_is_read(claims):
    scope_gate.set_token_claims(claims)
    try:
        assert scope_gate.session_has_automation_scope() is True
    finally:
        scope_gate.clear_token_claims()


def test_scope_claims_are_unioned_not_first_match():
    """A token can carry delegated scopes in scp AND app roles in roles at once;
    taking only the first non-empty claim would discard half the grant."""
    claims = {
        "scp": "couchbase-admin-mcp:read",
        "roles": ["couchbase-admin-mcp:automation"],
    }
    assert scope_gate._claims_scopes(claims) == {
        "couchbase-admin-mcp:read",
        "couchbase-admin-mcp:automation",
    }


def test_automation_is_false_without_a_token():
    """stdio / workstation: no token, so automation mode is never reached by
    default."""
    scope_gate.clear_token_claims()
    assert scope_gate.session_has_automation_scope() is False


def test_principal_of_records_the_service_principal_and_automation_flag():
    claims = {
        "sub": "sp-workflow-manager",
        "appid": "0000-app",
        "iss": "https://login.microsoftonline.com/t/v2.0",
        "roles": ["couchbase-admin-mcp:write", "couchbase-admin-mcp:automation"],
    }
    p = scope_gate.principal_of(claims)
    assert p["principal"] == "sp-workflow-manager"
    assert p["client_id"] == "0000-app"
    assert p["automation"] is True
    assert "couchbase-admin-mcp:write" in p["scopes"]


# ── The audit record ─────────────────────────────────────────────────────────


def _audit():
    return importlib.import_module("audit")


def test_record_carries_who_why_and_provenance():
    audit = _audit()
    record = audit.build_record(
        tool="admin_bucket_create",
        arguments={
            "bucket_name": "orders",
            "correlation_id": "git:9f2c1ab workflow-run:4821",
        },
        decision="allowed",
        principal={
            "principal": "sp-workflow-manager",
            "client_id": "0000-app",
            "scopes": ["couchbase-admin-mcp:write", "couchbase-admin-mcp:automation"],
            "automation": True,
            "auth": "oauth",
        },
    )
    assert record["principal"] == "sp-workflow-manager"
    # The single most important fact about an unattended write.
    assert record["automation"] is True
    # The field that reaches back to the human who pushed the code.
    assert record["correlation_id"] == "git:9f2c1ab workflow-run:4821"
    assert record["decision"] == "allowed"
    assert record["tool"] == "admin_bucket_create"


def test_correlation_id_is_stripped_from_the_logged_arguments():
    """It is provenance, not a tool parameter."""
    audit = _audit()
    record = audit.build_record(
        tool="t", arguments={"x": 1, "correlation_id": "abc"}, decision="allowed"
    )
    assert "correlation_id" not in record["args"]
    assert record["correlation_id"] == "abc"


def test_correlation_id_cannot_forge_log_lines():
    """Caller-supplied text in a log line: CR/LF would let an attacker fabricate
    whole records and bury the real operation."""
    audit = _audit()
    forged = 'abc\n2026-01-01 - couchbase-admin - INFO - AUDIT {"decision":"allowed"}'
    record = audit.build_record(
        tool="t", arguments={"correlation_id": forged}, decision="allowed"
    )
    assert "\n" not in record["correlation_id"]
    assert "\r" not in record["correlation_id"]


def test_correlation_id_is_length_capped():
    audit = _audit()
    record = audit.build_record(
        tool="t", arguments={"correlation_id": "x" * 5000}, decision="allowed"
    )
    assert len(record["correlation_id"]) < 400


def test_credentials_never_reach_the_audit_record():
    audit = _audit()
    record = audit.build_record(
        tool="admin_user_create",
        arguments={"username": "svc", "password": "Sup3rSecret"},
        decision="allowed",
    )
    assert "Sup3rSecret" not in json.dumps(record)
    assert record["args"]["password"] == "***REDACTED***"


def test_denials_are_recorded_too():
    """A refused call is the more interesting half of an audit trail."""
    audit = _audit()
    record = audit.build_record(
        tool="admin_bucket_delete",
        arguments={},
        decision="denied_scope",
        reason="token lacks write scope",
    )
    assert record["decision"] == "denied_scope"
    assert record["reason"] == "token lacks write scope"


def test_auth_failures_are_recorded():
    """Previously an invalid token left no trace, so probing was invisible."""
    audit = _audit()
    emitted = []
    original = audit.emit
    audit.emit = emitted.append
    try:
        audit.emit_auth_failure(
            reason="invalid token: ExpiredSignatureError", source="10.1.2.3:5555"
        )
    finally:
        audit.emit = original
    assert emitted[0]["event"] == "auth_failure"
    assert emitted[0]["decision"] == "denied_authentication"
    assert emitted[0]["source"] == "10.1.2.3:5555"


def test_workstation_identity_is_recorded_when_there_is_no_token():
    """No IdP on a laptop, but "who did what" must still resolve."""
    identity = profile_config.local_identity()
    assert identity["os_user"]
    assert identity["host"]
