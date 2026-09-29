"""
The console's OAuth routes, static serving, and config endpoint.

WHY THESE, SPECIFICALLY
======================
`/auth/callback` validates the `state` parameter. That is the CSRF control on login: without
it, an attacker can complete an authorization flow they started and have the victim's browser
adopt the resulting session — login CSRF, which ends with the victim driving an admin console
as the attacker's identity. It had no test.

`/auth/login` validates the `next` parameter. Without that it is an open redirect on an
authenticated admin endpoint, which is a credible phishing primitive.

`_get_session_claims` silently refreshes an expiring access token. Its failure paths decide
whether a dead session is treated as logged out or as still valid.

None of these were covered: 54% for the module, and the uncovered part was the whole browser
login flow.
"""

from __future__ import annotations

import importlib
import json
import sys
import time

import pytest

pytest.importorskip("flask")


@pytest.fixture
def gui(monkeypatch, tmp_path):
    """The console with OAuth ENABLED, and the IdP stubbed at `auth.oidc`.

    Enabled is the point: the existing console tests run with OAuth off, which is why every
    line of the login flow was unreached.
    """
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "stdio")
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "false")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(tmp_path / "audit.log"))
    monkeypatch.setenv("OAUTH_ENABLED", "true")
    monkeypatch.setenv("OAUTH_SESSION_SECRET", "0" * 64)
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example.com/realms/mcp")
    monkeypatch.setenv("OAUTH_CLIENT_ID", "cb-admin")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "shh")
    monkeypatch.setenv("OAUTH_REDIRECT_URI", "http://localhost:5173/auth/callback")
    monkeypatch.delenv("CB_GUI_INSECURE_NO_AUTH", raising=False)
    monkeypatch.delenv("CB_GUI_ALLOWED_ORIGINS", raising=False)

    import audit

    audit.reset_audit_sink()
    # RELOAD in place, never sys.modules.pop.
    # Popping rebinds these to NEW module objects, so another test file
    # holding a reference to the old one fails on its own importlib.reload
    # with "module not in sys.modules". That silently disabled 6 tests in
    # test_audit_and_profile.py -- including two enterprise-profile security
    # refusals -- whenever this file collected first. reload re-executes the
    # module body, which is what the pop was for, without breaking identity.
    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)
    # gui.gui_server is POPPED, not reloaded: its posture enforcement runs at IMPORT
    # time and that side effect is what these tests assert on, so it must genuinely
    # re-execute. Popping it is safe -- unlike the shared policy modules, no other test
    # file holds a long-lived reference to this module object.
    sys.modules.pop("gui.gui_server", None)
    import profile_config

    importlib.reload(profile_config)
    module = importlib.import_module("gui.gui_server")
    module.app.config.update(TESTING=True)
    # BOTH stores. They are process-global, so sessions created by earlier tests in this
    # module survive into later ones — which made `_store == {}` fail for the right reason
    # (seven leftover sessions) and `next(iter(_store))` pick an arbitrary one.
    module._pkce_store.clear()
    module._session._store.clear()

    # Stub the IdP. What matters is the console's own logic, not that `requests` works.
    #
    # THROUGH monkeypatch, not by assignment. `module._oidc` IS `auth.oidc`, so a plain
    # `module._oidc.validate_token = ...` replaces the real function for the whole session —
    # every later test in the process then "validated" any token by returning a fixed claims
    # dict. It showed up as 47 unrelated failures in `test_token_validation.py`, which runs
    # after this file alphabetically, and as a passing HTTP-auth test that should have been
    # rejecting an unauthenticated caller.
    monkeypatch.setattr(
        module._oidc,
        "build_authorization_url",
        lambda state, code_challenge: f"https://idp.example.com/auth?state={state}",
    )
    monkeypatch.setattr(
        module._oidc,
        "exchange_code",
        lambda code, code_verifier: {
            "access_token": "at-1",
            "id_token": "it-1",
            "refresh_token": "rt-1",
            "expires_in": 3600,
        },
    )
    monkeypatch.setattr(
        module._oidc,
        "validate_token",
        lambda token: {
            "sub": "user-1",
            "email": "ada@example.com",
            "scope": "couchbase:read couchbase:write",
            "exp": int(time.time()) + 3600,
        },
    )
    monkeypatch.setattr(
        module._oidc,
        "refresh_access_token",
        lambda refresh_token: {
            "access_token": "at-2",
            "refresh_token": "rt-2",
            "expires_in": 3600,
        },
    )
    yield module
    module._pkce_store.clear()
    module._session._store.clear()
    audit.reset_audit_sink()


@pytest.fixture
def client(gui):
    return gui.app.test_client()


# ── /auth/status ─────────────────────────────────────────────────────────────


def test_status_reports_that_oauth_is_enabled(client):
    """The front end decides whether to show a login button from this. Reporting wrongly
    means either an unusable console or a login prompt that goes nowhere."""
    response = client.get("/auth/status")
    assert response.status_code == 200
    assert response.get_json()["oauth_enabled"] is True


def test_status_needs_no_authentication(client):
    """It has to be reachable before login, or there is no way to discover that login is
    required."""
    assert client.get("/auth/status").status_code == 200


# ── /auth/login ──────────────────────────────────────────────────────────────


def test_login_redirects_to_the_idp_with_a_state_value(client, gui):
    response = client.get("/auth/login")
    assert response.status_code in (302, 303)
    assert response.headers["Location"].startswith("https://idp.example.com/auth?")
    assert len(gui._pkce_store) == 1, (
        "no state was recorded, so the callback cannot verify"
    )


def test_the_pkce_verifier_is_kept_server_side(client, gui):
    """It must never reach the browser: the verifier is what proves the code was redeemed by
    the client that requested it."""
    response = client.get("/auth/login")
    (entry,) = gui._pkce_store.values()
    assert entry["verifier"]
    assert entry["verifier"] not in response.headers["Location"]
    assert entry["verifier"] not in response.get_data(as_text=True)


def test_state_values_are_unpredictable(client, gui):
    """A guessable state defeats the CSRF check as thoroughly as no check."""
    for _ in range(20):
        client.get("/auth/login")
    states = set(gui._pkce_store)
    assert len(states) == 20
    assert all(len(s) >= 32 for s in states)


def test_a_relative_next_path_is_preserved(client, gui):
    client.get("/auth/login?next=/tools/buckets")
    (entry,) = gui._pkce_store.values()
    assert entry["next"] == "/tools/buckets"


@pytest.mark.parametrize(
    "hostile",
    [
        "https://evil.example.com/phish",
        "//evil.example.com/phish",
        "http://evil.example.com",
        "javascript:alert(1)",
    ],
)
def test_an_absolute_next_url_is_refused(client, gui, hostile):
    """OPEN REDIRECT. `next` is followed after a successful login, so an absolute URL turns
    an authenticated admin endpoint into a redirector — a link that genuinely starts at the
    company's console and ends at the attacker's page."""
    client.get(f"/auth/login?next={hostile}")
    (entry,) = gui._pkce_store.values()
    assert entry["next"] == "/", f"{hostile} survived as a redirect target"


def test_login_is_refused_when_oauth_is_disabled(monkeypatch, tmp_path):
    """Otherwise it starts a flow that cannot complete, and the failure appears at the
    callback rather than at the click."""
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "stdio")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(tmp_path / "a.log"))
    # RELOAD in place, never sys.modules.pop.
    # Popping rebinds these to NEW module objects, so another test file
    # holding a reference to the old one fails on its own importlib.reload
    # with "module not in sys.modules". That silently disabled 6 tests in
    # test_audit_and_profile.py -- including two enterprise-profile security
    # refusals -- whenever this file collected first. reload re-executes the
    # module body, which is what the pop was for, without breaking identity.
    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)
    # gui.gui_server is POPPED, not reloaded: its posture enforcement runs at IMPORT
    # time and that side effect is what these tests assert on, so it must genuinely
    # re-execute. Popping it is safe -- unlike the shared policy modules, no other test
    # file holds a long-lived reference to this module object.
    sys.modules.pop("gui.gui_server", None)
    import profile_config

    importlib.reload(profile_config)
    module = importlib.import_module("gui.gui_server")
    module.app.config.update(TESTING=True)

    assert module.app.test_client().get("/auth/login").status_code == 400


def test_a_configuration_error_from_the_idp_helper_is_reported_not_a_traceback(
    client, gui, monkeypatch
):
    def _explode(state, code_challenge):
        raise RuntimeError("OAUTH_CLIENT_ID is not set")

    monkeypatch.setattr(gui._oidc, "build_authorization_url", _explode)
    response = client.get("/auth/login")
    assert response.status_code == 500
    assert "OAUTH_CLIENT_ID" in response.get_json()["error"]


# ── /auth/callback: the CSRF control ─────────────────────────────────────────


def _start_login(client, gui, next_url="/"):
    client.get(f"/auth/login?next={next_url}")
    return next(iter(gui._pkce_store))


def test_a_successful_callback_creates_a_session(client, gui):
    state = _start_login(client, gui)
    response = client.get(f"/auth/callback?code=auth-code&state={state}")
    assert response.status_code in (302, 303)
    cookies = response.headers.getlist("Set-Cookie")
    assert any(gui._session.SESSION_COOKIE in c for c in cookies)


def test_the_session_cookie_is_httponly_and_samesite(client, gui):
    """HttpOnly keeps the session id away from any script on the page; SameSite=Lax stops it
    riding along on a cross-site request."""
    state = _start_login(client, gui)
    response = client.get(f"/auth/callback?code=c&state={state}")
    cookie = next(
        c
        for c in response.headers.getlist("Set-Cookie")
        if gui._session.SESSION_COOKIE in c
    )
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_a_callback_with_an_unknown_state_is_refused(client, gui):
    """THE CSRF CONTROL. Without it, an attacker completes their own authorization flow and
    then causes the victim's browser to hit the callback, so the victim's console adopts a
    session belonging to the attacker's identity."""
    response = client.get("/auth/callback?code=attacker-code&state=never-issued")
    assert response.status_code == 400
    assert not any(
        gui._session.SESSION_COOKIE in c for c in response.headers.getlist("Set-Cookie")
    )


def test_an_unknown_state_is_refused_even_when_the_cookie_agrees(client, gui):
    """The SERVER-SIDE half of the CSRF control, which the test above no longer reaches.

    `state=never-issued` fails the shape check and carries no login cookie, so once the
    state/cookie binding was added it is refused before the store is ever consulted --
    and mutation round 5 duly reported that deleting the store lookup was caught by
    nothing. The fix for one control had hidden the test for another.

    Here the login is started for real, so the cookie and the query state agree exactly
    as they would for the browser that began the flow; only the server-side record is
    gone. A state the server never issued (or already redeemed) must not be exchangeable,
    and the store is the only thing that knows the difference.

    Asserted on the outcome, not the message: the fake IdP in this module exchanges any
    code successfully, so a build that skips the store lookup answers 302 with a session
    cookie -- an attacker-supplied code turned into a session.
    """
    state = _start_login(client, gui)
    gui._pkce_store.clear()
    response = client.get(f"/auth/callback?code=attacker-code&state={state}")
    assert response.status_code == 400, (
        "a state with no server-side record was accepted; the store lookup is what "
        "distinguishes a state this server issued from one an attacker fabricated"
    )
    assert not any(
        gui._session.SESSION_COOKIE in c for c in response.headers.getlist("Set-Cookie")
    )


def test_a_callback_with_no_state_at_all_is_refused(client, gui):
    response = client.get("/auth/callback?code=c")
    assert response.status_code == 400


def test_a_state_value_cannot_be_replayed(client, gui):
    """One authorization code, one session. A reusable state means a captured callback URL
    is a reusable login."""
    state = _start_login(client, gui)
    first = client.get(f"/auth/callback?code=c&state={state}")
    assert first.status_code in (302, 303)

    second = client.get(f"/auth/callback?code=c&state={state}")
    assert second.status_code == 400, "the same state was accepted twice"


def test_an_error_from_the_idp_is_surfaced_rather_than_ignored(client, gui):
    """`?error=access_denied` means the user declined or the IdP refused. Treating it as a
    successful callback would produce a session with no tokens."""
    state = _start_login(client, gui)
    response = client.get(f"/auth/callback?error=access_denied&state={state}")
    assert response.status_code >= 400
    assert not any(
        gui._session.SESSION_COOKIE in c for c in response.headers.getlist("Set-Cookie")
    )


def test_a_failed_code_exchange_does_not_create_a_session(client, gui, monkeypatch):
    def _explode(code, code_verifier):
        raise RuntimeError("invalid_grant")

    monkeypatch.setattr(gui._oidc, "exchange_code", _explode)
    state = _start_login(client, gui)
    response = client.get(f"/auth/callback?code=stale&state={state}")
    assert response.status_code >= 400
    assert not any(
        gui._session.SESSION_COOKIE in c for c in response.headers.getlist("Set-Cookie")
    )


def test_a_token_that_fails_validation_does_not_create_a_session(
    client, gui, monkeypatch
):
    """The exchange succeeded, so the IdP is reachable and the code was good — but the token
    it issued does not validate. Trusting it because the exchange worked would skip the whole
    verification step."""
    import jwt

    def _reject(token):
        raise jwt.InvalidSignatureError("bad signature")

    monkeypatch.setattr(gui._oidc, "validate_token", _reject)
    state = _start_login(client, gui)
    response = client.get(f"/auth/callback?code=c&state={state}")
    assert response.status_code == 401
    assert not any(
        gui._session.SESSION_COOKIE in c for c in response.headers.getlist("Set-Cookie")
    )


def test_the_callback_returns_to_the_recorded_next_path(client, gui):
    state = _start_login(client, gui, next_url="/tools/indexes")
    response = client.get(f"/auth/callback?code=c&state={state}")
    assert response.headers["Location"].endswith("/tools/indexes")


def test_the_next_path_comes_from_the_server_side_record_not_the_callback_query(
    client, gui
):
    """Otherwise the open-redirect check on /auth/login is bypassable by putting the hostile
    URL on the callback instead."""
    state = _start_login(client, gui, next_url="/safe")
    response = client.get(
        f"/auth/callback?code=c&state={state}&next=https://evil.example.com"
    )
    assert "evil.example.com" not in response.headers["Location"]


# ── Session refresh ──────────────────────────────────────────────────────────


def _login(client, gui):
    state = _start_login(client, gui)
    client.get(f"/auth/callback?code=c&state={state}")


def test_an_authenticated_request_is_served(client, gui):
    _login(client, gui)
    assert client.get("/auth/me").status_code == 200


def test_an_expiring_access_token_is_refreshed_silently(client, gui, monkeypatch):
    """The user should not be logged out mid-task because an access token reached its
    lifetime; that is what the refresh token is for."""
    _login(client, gui)
    for entry in gui._session._store.values():
        entry["data"]["expires_at"] = time.time() + 10  # inside the 60s refresh window

    refreshed: list[str] = []
    monkeypatch.setattr(
        gui._oidc,
        "refresh_access_token",
        lambda rt: refreshed.append(rt) or {"access_token": "at-2", "expires_in": 3600},
    )

    assert client.get("/auth/me").status_code == 200
    assert refreshed == ["rt-1"]


def test_a_session_with_no_refresh_token_is_treated_as_logged_out(client, gui):
    """Client-credentials style tokens have no refresh token. Continuing to accept an expired
    access token because there is no way to renew it would be the wrong direction."""
    _login(client, gui)
    for entry in gui._session._store.values():
        entry["data"]["expires_at"] = time.time() - 1
        entry["data"]["refresh_token"] = ""

    assert client.get("/auth/me").status_code == 401
    assert gui._session._store == {}, "the dead session was left in the store"


def test_a_failed_refresh_ends_the_session(client, gui, monkeypatch):
    """The IdP has revoked or expired the grant. Keeping the session would leave the console
    acting on claims the IdP no longer stands behind."""
    _login(client, gui)
    for entry in gui._session._store.values():
        entry["data"]["expires_at"] = time.time() - 1

    def _explode(refresh_token):
        raise RuntimeError("invalid_grant")

    monkeypatch.setattr(gui._oidc, "refresh_access_token", _explode)

    assert client.get("/auth/me").status_code == 401
    assert gui._session._store == {}


def test_claims_are_revalidated_after_a_refresh(client, gui, monkeypatch):
    """A refreshed token can carry different scopes — a revoked role, for instance. Reusing
    the old claims would keep granting an authority the IdP has withdrawn."""
    _login(client, gui)
    for entry in gui._session._store.values():
        entry["data"]["expires_at"] = time.time() + 10

    monkeypatch.setattr(
        gui._oidc,
        "validate_token",
        lambda token: {
            "sub": "user-1",
            "scope": "couchbase:read",
            "exp": int(time.time()) + 3600,
        },
    )

    response = client.get("/auth/me")
    assert response.status_code == 200
    stored = next(iter(gui._session._store.values()))["data"]["claims"]
    assert stored["scope"] == "couchbase:read", "the pre-refresh claims were kept"


# ── /auth/logout ─────────────────────────────────────────────────────────────


def test_logout_clears_the_session_and_the_cookie(client, gui):
    _login(client, gui)
    response = client.get("/auth/logout")

    assert gui._session._store == {}
    cookie_headers = " ".join(response.headers.getlist("Set-Cookie"))
    assert gui._session.SESSION_COOKIE in cookie_headers
    assert "Expires=Thu, 01 Jan 1970" in cookie_headers or "Max-Age=0" in cookie_headers


def test_logout_without_a_session_is_not_an_error(client, gui):
    """A logout link on a page the user reached after the session already expired must not
    produce a 500."""
    assert client.get("/auth/logout").status_code in (200, 302, 303)


def test_a_request_after_logout_is_unauthenticated(client, gui):
    _login(client, gui)
    client.get("/auth/logout")
    assert client.get("/auth/me").status_code == 401


# ── /api/config ──────────────────────────────────────────────────────────────


def test_the_config_endpoint_requires_authentication(client, gui):
    assert client.get("/api/config").status_code == 401


def test_the_config_endpoint_reports_the_current_settings(client, gui):
    _login(client, gui)
    response = client.get("/api/config")
    assert response.status_code == 200
    assert isinstance(response.get_json(), dict)


def test_the_config_endpoint_does_not_disclose_credentials(client, gui, monkeypatch):
    """It reports configuration to a browser. A connection string with a password in its
    userinfo, or a credential path, must not be part of that."""
    monkeypatch.setenv("CB_PASSWORD", "pw-in-env-do-not-leak")
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbases://admin:pw-in-uri@cb.host")
    _login(client, gui)

    body = client.get("/api/config").get_data(as_text=True)
    assert "pw-in-env-do-not-leak" not in body
    assert "pw-in-uri" not in body


# ── Static serving ───────────────────────────────────────────────────────────


def test_the_index_page_is_served_at_the_root(client, gui):
    response = client.get("/")
    assert response.status_code == 200
    assert b"<html" in response.data.lower() or b"<!doctype" in response.data.lower()


def test_an_unknown_path_falls_back_to_the_index_page(client, gui):
    """It is a single-page app: a deep link the router handles must not 404 on reload."""
    response = client.get("/tools/buckets")
    assert response.status_code == 200
    assert b"<html" in response.data.lower() or b"<!doctype" in response.data.lower()


def test_a_real_static_asset_is_served(client, gui):
    """The vendored Babel bundle. If this 404s the console renders blank, which is how it
    shipped once before."""
    response = client.get("/vendor/babel.min.js")
    assert response.status_code == 200
    assert len(response.data) > 1000


@pytest.mark.parametrize(
    "attempt",
    [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "static/../../../etc/passwd",
        "....//....//etc/passwd",
    ],
)
def test_path_traversal_does_not_escape_the_static_directory(client, gui, attempt):
    """The catch-all route joins the request path onto the static folder. Anything that
    escapes it would read arbitrary files as the server user — including the audit log and
    any mounted credential."""
    response = client.get(f"/{attempt}")
    assert b"root:x:0:0" not in response.data, (
        "a file outside the static folder was served"
    )
    assert b"BEGIN PRIVATE KEY" not in response.data


def test_the_traversal_test_would_notice_a_real_leak(
    client, gui, tmp_path, monkeypatch
):
    """Guards the test above from passing because /etc/passwd is simply absent. Serves a
    known file from OUTSIDE the static folder and asserts the route refuses it."""
    secret = tmp_path / "secret.txt"
    secret.write_text("root:x:0:0:sentinel")
    # A path that would reach it if the join were unsanitised.
    import os

    relative = os.path.relpath(secret, gui.app.static_folder)
    response = client.get("/" + relative.replace(os.sep, "/"))
    assert b"sentinel" not in response.data


# ── /api/tools ───────────────────────────────────────────────────────────────


def test_the_tool_list_requires_authentication(client, gui):
    assert client.get("/api/tools").status_code == 401


def test_the_tool_list_is_served_to_an_authenticated_caller(client, gui):
    _login(client, gui)
    response = client.get("/api/tools")
    assert response.status_code == 200
    payload = response.get_json()
    assert isinstance(payload, (list, dict))
    assert json.dumps(payload)
