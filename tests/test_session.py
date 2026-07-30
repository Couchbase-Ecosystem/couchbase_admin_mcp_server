"""
Session cookies for the console: signing, expiry, and the two flags that matter.

This module had ZERO test coverage. Writing these tests found three defects, each of which
has its own test below:

  1. `secure=request.is_secure` dropped the Secure flag behind a TLS-terminating proxy —
     the enterprise shape the runbook documents.
  2. OAUTH_SESSION_SECRET was never checked at startup, so the console booted and then
     500'd on the first login attempt.
  3. OAUTH_SESSION_TTL_SECONDS was parsed in two places with different failure behaviour;
     the console's bare `int()` raised inside the OAuth callback, after the token exchange
     had already succeeded.

The store is process-global, so every test clears it. Without that, `test_purge` would pass
or fail depending on what ran before it — and with pytest-randomly, differently each run.
"""

from __future__ import annotations

import time

import pytest

from auth import session

SECRET = "0" * 64


@pytest.fixture(autouse=True)
def clean_store(monkeypatch):
    """A signing secret and an empty store for every test."""
    monkeypatch.setenv("OAUTH_SESSION_SECRET", SECRET)
    monkeypatch.delenv("OAUTH_SESSION_TTL_SECONDS", raising=False)
    session._store.clear()
    yield
    session._store.clear()


# ── Signing ──────────────────────────────────────────────────────────────────


def test_a_session_round_trips():
    cookie = session.create_session({"user": "ada"})
    assert session.get_session(cookie) == {"user": "ada"}


def test_the_cookie_does_not_contain_the_session_data():
    """The cookie is a reference, not a container. Token material must never leave the
    process, so a cookie carrying the access token would defeat the whole design."""
    cookie = session.create_session({"access_token": "super-secret-value"})
    assert "super-secret-value" not in cookie


def test_a_tampered_signature_is_rejected():
    cookie = session.create_session({"user": "ada"})
    body, _, signature = cookie.rpartition(".")
    forged = f"{body}.{'A' * len(signature)}"
    assert session.get_session(forged) is None


def test_a_tampered_session_id_is_rejected():
    """The attack that matters: keep a valid-looking signature, swap the ID for another
    session's. Without the HMAC covering the ID, guessing an ID would be enough."""
    victim = session.create_session({"user": "victim"})
    attacker = session.create_session({"user": "attacker"})
    victim_id_part = victim.split(".")[0]
    attacker_signature = attacker.split(".")[1]
    assert session.get_session(f"{victim_id_part}.{attacker_signature}") is None


def test_a_session_signed_with_a_different_secret_is_rejected(monkeypatch):
    """Rotating the secret must invalidate outstanding sessions rather than accept them."""
    cookie = session.create_session({"user": "ada"})
    monkeypatch.setenv("OAUTH_SESSION_SECRET", "f" * 64)
    assert session.get_session(cookie) is None


@pytest.mark.parametrize(
    "malformed",
    ["", "no-dot-at-all", ".", "...", "!!!.!!!", "a." + "b" * 500],
    ids=["empty", "no separator", "bare dot", "three dots", "not base64", "long"],
)
def test_malformed_cookies_return_none_rather_than_raising(malformed):
    """These arrive from the network unfiltered. An exception here is a 500 on a request
    that should simply be unauthenticated."""
    assert session.get_session(malformed) is None


def test_an_unset_signing_secret_refuses_rather_than_signing_with_empty(monkeypatch):
    """An empty HMAC key still produces a valid-looking signature that anyone who knows the
    scheme can forge. Refusing is the only safe behaviour."""
    monkeypatch.delenv("OAUTH_SESSION_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="OAUTH_SESSION_SECRET"):
        session.create_session({"user": "ada"})


def test_session_ids_are_unpredictable():
    """Guessable IDs would make the signature the only barrier."""
    ids = {session._unsign(session.create_session({})) for _ in range(50)}
    assert len(ids) == 50
    assert all(len(i) >= 32 for i in ids)


# ── Expiry ───────────────────────────────────────────────────────────────────


def test_an_expired_session_is_refused(monkeypatch):
    monkeypatch.setenv("OAUTH_SESSION_TTL_SECONDS", "1")
    cookie = session.create_session({"user": "ada"})
    session_id = session._unsign(cookie)
    session._store[session_id]["created"] = time.time() - 5
    assert session.get_session(cookie) is None


def test_reading_an_expired_session_also_removes_it(monkeypatch):
    """Otherwise expired entries accumulate until the next login triggers a purge."""
    monkeypatch.setenv("OAUTH_SESSION_TTL_SECONDS", "1")
    cookie = session.create_session({"user": "ada"})
    session._store[session._unsign(cookie)]["created"] = time.time() - 5
    session.get_session(cookie)
    assert session._store == {}


def test_a_session_inside_its_ttl_survives(monkeypatch):
    """Guards the expiry tests from passing because everything is refused."""
    monkeypatch.setenv("OAUTH_SESSION_TTL_SECONDS", "3600")
    cookie = session.create_session({"user": "ada"})
    session._store[session._unsign(cookie)]["created"] = time.time() - 60
    assert session.get_session(cookie) == {"user": "ada"}


def test_creating_a_session_purges_other_expired_ones(monkeypatch):
    monkeypatch.setenv("OAUTH_SESSION_TTL_SECONDS", "10")
    stale = session.create_session({"user": "stale"})
    session._store[session._unsign(stale)]["created"] = time.time() - 999
    session.create_session({"user": "fresh"})
    assert len(session._store) == 1


def test_an_unparseable_ttl_falls_back_rather_than_raising(monkeypatch):
    """Read on every request, so raising would turn a typo into a total outage.
    `validate_startup` is what reports it."""
    monkeypatch.setenv("OAUTH_SESSION_TTL_SECONDS", "eight hours")
    assert session._session_ttl() == session.DEFAULT_TTL_SECONDS


# ── Update and delete ────────────────────────────────────────────────────────


def test_update_merges_into_an_existing_session():
    cookie = session.create_session({"user": "ada", "expires_at": 1})
    assert session.update_session(cookie, {"expires_at": 2}) is True
    assert session.get_session(cookie) == {"user": "ada", "expires_at": 2}


def test_update_of_an_unknown_session_reports_failure():
    """The token-refresh path calls this; a silent success would leave the caller believing
    it had stored a refreshed token that went nowhere."""
    unknown = session._sign("never-created")
    assert session.update_session(unknown, {"x": 1}) is False


def test_update_with_a_forged_cookie_is_refused():
    cookie = session.create_session({"user": "ada"})
    forged = cookie.split(".")[0] + ".AAAA"
    assert session.update_session(forged, {"user": "attacker"}) is False
    assert session.get_session(cookie) == {"user": "ada"}


def test_delete_removes_the_session():
    cookie = session.create_session({"user": "ada"})
    session.delete_session(cookie)
    assert session.get_session(cookie) is None
    assert session._store == {}


def test_delete_with_a_forged_cookie_does_not_remove_anyone_elses():
    """Logout must not become a way to sign other people out."""
    victim = session.create_session({"user": "victim"})
    session.delete_session(victim.split(".")[0] + ".AAAA")
    assert session.get_session(victim) == {"user": "victim"}


def test_delete_of_an_unknown_session_is_quiet():
    session.delete_session(session._sign("never-created"))  # must not raise


# ── The Secure flag (defect 1) ───────────────────────────────────────────────


def test_the_cookie_is_secure_when_tls_is_terminated_upstream(monkeypatch):
    """THE DEFECT. `secure=request.is_secure` is False behind a TLS-terminating proxy,
    because the scheme Flask sees is plain http. The runbook's enterprise deployment is
    exactly this, so the session cookie was issued without Secure and would be sent over
    cleartext on any downgrade to http://.
    """
    monkeypatch.setenv("CB_ADMIN_TLS_TERMINATED_EXTERNALLY", "1")
    monkeypatch.delenv("CB_ADMIN_TLS_CERT_FILE", raising=False)
    assert session.cookie_is_secure() is True


def test_the_cookie_is_secure_when_this_process_terminates_tls(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_TLS_CERT_FILE", "/etc/tls/server.crt")
    monkeypatch.setenv("CB_ADMIN_TLS_KEY_FILE", "/etc/tls/server.key")
    monkeypatch.delenv("CB_ADMIN_TLS_TERMINATED_EXTERNALLY", raising=False)
    assert session.cookie_is_secure() is True


def test_the_cookie_is_not_secure_for_plain_http_local_development(monkeypatch):
    """Not an oversight. Secure would stop the browser returning the cookie over
    http://127.0.0.1 and break local login outright. `tls_config.validate()` is what stops
    this configuration reaching a non-loopback bind."""
    for key in (
        "CB_ADMIN_TLS_CERT_FILE",
        "CB_ADMIN_TLS_KEY_FILE",
        "CB_ADMIN_TLS_TERMINATED_EXTERNALLY",
    ):
        monkeypatch.delenv(key, raising=False)
    assert session.cookie_is_secure() is False


def test_a_forwarded_proto_header_cannot_influence_the_secure_flag(monkeypatch):
    """The obvious repair for defect 1 — read X-Forwarded-Proto — would be a second defect.
    That header is attacker-settable, and the console's own loopback check already refuses
    to trust forwarding headers. The decision comes from configuration only, so there is
    no request state for an attacker to reach.
    """
    import inspect

    source = inspect.getsource(session.cookie_is_secure)
    body = source.split('"""')[-1]  # skip the docstring, which discusses the header
    assert "Forwarded" not in body
    assert "request" not in body


def test_the_console_sets_the_cookie_from_configuration_not_the_request():
    """The fix has to be at the call site to have any effect — `cookie_is_secure` returning
    the right answer is worth nothing if `set_cookie` still passes `request.is_secure`."""
    import inspect
    from pathlib import Path

    source = (
        Path(inspect.getsourcefile(session)).parent.parent / "gui" / "gui_server.py"
    )
    text = source.read_text(encoding="utf-8")
    assert "secure=request.is_secure" not in text, (
        "the console is back to deciding the Secure flag from the request scheme, "
        "which is http behind a TLS-terminating proxy"
    )
    assert "secure=_session.cookie_is_secure()" in text


# ── Startup validation (defects 2 and 3) ─────────────────────────────────────


def test_a_missing_signing_secret_is_a_startup_error(monkeypatch):
    """DEFECT 2. Previously the console started fine and the first login returned an opaque
    500 from deep inside the cookie code."""
    monkeypatch.delenv("OAUTH_SESSION_SECRET", raising=False)
    errors = session.validate_startup()
    assert len(errors) == 1
    assert "OAUTH_SESSION_SECRET" in errors[0]


def test_a_whitespace_only_secret_is_treated_as_missing(monkeypatch):
    monkeypatch.setenv("OAUTH_SESSION_SECRET", "   ")
    assert any("OAUTH_SESSION_SECRET" in e for e in session.validate_startup())


def test_a_valid_configuration_produces_no_errors():
    """Guards the tests above from passing because validate_startup always complains."""
    assert session.validate_startup() == []


def test_an_unparseable_ttl_is_a_startup_error(monkeypatch):
    """DEFECT 3, reported once at boot rather than as a 500 mid-callback. The silent
    fallback is the trap: an operator shortening the TTL would get 8 hours instead."""
    monkeypatch.setenv("OAUTH_SESSION_TTL_SECONDS", "8h")
    errors = session.validate_startup()
    assert len(errors) == 1
    assert "OAUTH_SESSION_TTL_SECONDS" in errors[0]
    assert "8h" in errors[0]


@pytest.mark.parametrize("ttl", ["0", "-1"])
def test_a_non_positive_ttl_is_a_startup_error(monkeypatch, ttl):
    """Expires every session on creation, so nobody can log in — and the symptom is an
    immediate redirect back to login with no error anywhere."""
    monkeypatch.setenv("OAUTH_SESSION_TTL_SECONDS", ttl)
    assert any("OAUTH_SESSION_TTL_SECONDS" in e for e in session.validate_startup())


def test_an_empty_ttl_is_accepted_as_unset(monkeypatch):
    """Docker Compose supplies `KEY=` for an unset variable, which would otherwise be
    reported as a typo on every documented deployment."""
    monkeypatch.setenv("OAUTH_SESSION_TTL_SECONDS", "")
    assert session.validate_startup() == []


def test_the_cookie_lifetime_matches_the_session_lifetime(monkeypatch):
    """DEFECT 3's other half. Two independent reads of the same variable can drift; a cookie
    outliving its session gives a browser that thinks it is logged in and a server that
    disagrees, and the reverse silently logs people out early."""
    monkeypatch.setenv("OAUTH_SESSION_TTL_SECONDS", "60")
    assert session.cookie_max_age() == session._session_ttl() == 60


def test_the_console_reads_the_cookie_lifetime_from_this_module():
    import inspect
    from pathlib import Path

    source = (
        Path(inspect.getsourcefile(session)).parent.parent / "gui" / "gui_server.py"
    )
    text = source.read_text(encoding="utf-8")
    assert 'os.environ.get("OAUTH_SESSION_TTL_SECONDS"' not in text, (
        "the console is parsing OAUTH_SESSION_TTL_SECONDS itself again; a bare int() here "
        "raises inside the OAuth callback, after the token exchange has already succeeded"
    )
    assert "max_age=_session.cookie_max_age()" in text


# ── The startup check is actually wired in ───────────────────────────────────
#
# `validate_startup()` returning the right errors is worthless if nothing calls it. These
# drive the console's real `_enforce_gui_posture()`, which is the function that exits.


def _run_gui_posture(env: dict) -> list[str]:
    """Run the console's real startup validation under `env`.

    Snapshots and restores the whole environment rather than using monkeypatch, because
    `profile_config.apply_profile()` WRITES to os.environ — monkeypatch only undoes what
    monkeypatch itself set, so profile-derived values would leak into later tests and change
    their outcome under a different random ordering. This bit us once already.
    """
    import importlib
    import os
    import sys

    snapshot = dict(os.environ)
    try:
        for key in [
            k for k in list(os.environ) if k.startswith(("CB_", "OAUTH_", "GUI_"))
        ]:
            os.environ.pop(key, None)
        os.environ.update(env)

        import audit
        import profile_config
        import tls_config

        importlib.reload(profile_config)
        importlib.reload(tls_config)
        audit.reset_audit_sink()

        # A fresh import, not a reload: the module runs `_enforce_gui_posture()` at import
        # and captures OAUTH_ENABLED into module-level constants, so it has to be built
        # under this environment. Popping first is what makes the import actually re-execute.
        sys.modules.pop("gui.gui_server", None)
        import gui.gui_server  # noqa: F401

        return []
    except SystemExit:
        # _enforce_gui_posture prints each problem then raises SystemExit(2). The reasons go
        # to stderr, which pytest captures; the caller checks that instead.
        return ["refused"]
    finally:
        os.environ.clear()
        os.environ.update(snapshot)

        import audit
        import profile_config
        import tls_config

        importlib.reload(profile_config)
        importlib.reload(tls_config)
        audit.reset_audit_sink()

        # gui_server captures OAUTH_ENABLED and friends into module-level constants at
        # import, so a copy left loaded under this test's environment would change the
        # behaviour of any later test that touches the console — and only under the
        # orderings where this test happens to run first. Drop it rather than reload it:
        # reloading needs a valid ambient environment, which is not this function's to
        # assume, and the next importer will build a fresh one under whatever is current.
        sys.modules.pop("gui.gui_server", None)


_WORKING_GUI_ENV = {
    "CB_ADMIN_PROFILE": "workstation",
    "CB_CONNECTION_STRING": "couchbase://localhost",
    "CB_USERNAME": "admin",
    "CB_PASSWORD": "password",
    "GUI_HOST": "127.0.0.1",
}


def test_the_console_refuses_to_start_with_oauth_on_and_no_signing_secret(capsys):
    """The wiring test for defect 2. Without this the console starts and the failure
    surfaces as a 500 to whoever logs in first."""
    result = _run_gui_posture(
        {**_WORKING_GUI_ENV, "OAUTH_ENABLED": "true", "CB_GUI_INSECURE_NO_AUTH": ""}
    )
    assert result == ["refused"]
    assert "OAUTH_SESSION_SECRET" in capsys.readouterr().err


def test_the_console_starts_with_oauth_on_and_a_secret_present():
    """Guards the test above from passing because OAuth-enabled never starts at all."""
    assert (
        _run_gui_posture(
            {
                **_WORKING_GUI_ENV,
                "OAUTH_ENABLED": "true",
                "OAUTH_SESSION_SECRET": SECRET,
                "OAUTH_ISSUER": "https://issuer.example.com",
                "OAUTH_CLIENT_ID": "cb-admin",
                "OAUTH_CLIENT_SECRET": "shh",
            }
        )
        == []
    )


def test_no_signing_secret_is_required_when_oauth_is_off():
    """With auth disabled no session cookie is ever issued, so demanding a signing secret
    would break every existing local install for no gain."""
    assert (
        _run_gui_posture(
            {
                **_WORKING_GUI_ENV,
                "OAUTH_ENABLED": "false",
                "CB_GUI_INSECURE_NO_AUTH": "1",
            }
        )
        == []
    )
