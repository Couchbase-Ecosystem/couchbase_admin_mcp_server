"""Tests for credential redaction in handlers.shared."""

from __future__ import annotations

from handlers.shared import REDACTED, err, redact


def test_top_level_password_redacted():
    r = redact({"username": "u", "password": "p"})
    assert r["password"] == REDACTED
    assert r["username"] == "u"


def test_varied_sensitive_key_names():
    r = redact(
        {
            "new_password": "x",
            "api_key": "x",
            "access_key": "x",
            "secret": "x",
            "passphrase": "x",
            "token": "x",
            "credential": "x",
        }
    )
    assert all(v == REDACTED for v in r.values())


def test_auth_method_is_allowlisted():
    # names the mechanism, not a credential
    r = redact({"auth_method": "cert", "authentication_type": "ldap"})
    assert r["auth_method"] == "cert"
    assert r["authentication_type"] == "ldap"


def test_nested_and_listed_values():
    r = redact(
        {
            "kmip": {"passphrase": "p", "host": "h"},
            "items": [{"secret": "s", "name": "n"}],
        }
    )
    assert r["kmip"]["passphrase"] == REDACTED
    assert r["kmip"]["host"] == "h"
    assert r["items"][0]["secret"] == REDACTED
    assert r["items"][0]["name"] == "n"


def test_non_container_passthrough():
    assert redact("plain") == "plain"
    assert redact(42) == 42
    assert redact(None) is None


def test_err_redacts_echoed_args():
    out = err(
        "boom",
        tool="admin_user_create",
        args={"username": "alice", "password": "hunter2"},
    )
    text = out[0].text
    assert "hunter2" not in text
    assert REDACTED in text
    assert "alice" in text  # non-sensitive preserved for diagnostics
