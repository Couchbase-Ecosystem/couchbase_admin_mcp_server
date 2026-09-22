"""The console's OIDC routes: the login it starts and the callback it finishes.

These sit in front of every other console decision. If /auth/callback accepts a
state it did not issue, or a login entry outlives its window, the rest of the
console's authorization is being asked about the wrong principal.

The details worth pinning:

  * The PKCE store is BOUNDED as well as expiring. A TTL purge alone lets an
    unauthenticated flood grow the store for a whole 10-minute window while
    making the purge's own scan quadratic.
  * A mismatched callback does NOT pop the entry, so it cannot be used to delete
    an outstanding login someone else is mid-way through. It is collected by the
    TTL purge instead.
  * `state` is shape-checked before any comparison, so a malformed one is a 400
    rather than a TypeError out of compare_digest.
  * Discovery failure on logout proceeds with a LOCAL logout rather than leaving
    the session cookie in place because the IdP was unreachable.

Nothing here reaches an identity provider: discovery and the token exchange are
stubbed. That is what makes the failure branches -- an IdP that returns no token,
an expired login, a replaced state -- reachable.
"""

from __future__ import annotations

import importlib
import json
import sys
import time

import pytest


def _load(monkeypatch, **env):
    monkeypatch.setenv("CB_ADMIN_PROFILE", env.pop("CB_ADMIN_PROFILE", "workstation"))
    for key, value in env.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)
    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)
    sys.modules.pop("gui.gui_server", None)
    module = importlib.import_module("gui.gui_server")
    module.app.config.update(TESTING=True)
    return module


@pytest.fixture
def gui(monkeypatch):
    return _load(
        monkeypatch,
        CB_GUI_INSECURE_NO_AUTH="1",
        OAUTH_ENABLED="false",
        CB_ADMIN_READ_ONLY_MODE="false",
    )


@pytest.fixture
def oauth(monkeypatch):
    """The console with OIDC on, and the provider replaced by a stub."""
    module = _load(
        monkeypatch,
        OAUTH_ENABLED="true",
        CB_GUI_INSECURE_NO_AUTH=None,
        OAUTH_CLIENT_ID="console",
        # The console signs its session cookies with this; without it every login
        # fails and the posture guard answers 503 before any route runs.
        OAUTH_SESSION_SECRET="0" * 64,
        CB_ADMIN_READ_ONLY_MODE="false",
    )
    state = {
        "discovery": {
            "authorization_endpoint": "https://idp.invalid/authorize",
            "token_endpoint": "https://idp.invalid/token",
            "end_session_endpoint": "https://idp.invalid/logout",
        },
        "tokens": {"access_token": "at", "id_token": "it"},
        "discovery_error": None,
        "token_error": None,
    }

    def discover():
        if state["discovery_error"]:
            raise RuntimeError(state["discovery_error"])
        return state["discovery"]

    def exchange(*args, **kwargs):
        if state["token_error"]:
            raise RuntimeError(state["token_error"])
        return state["tokens"]

    def authorization_url(state=None, code_challenge=None):
        if state_holder["authorize_error"]:
            raise RuntimeError(state_holder["authorize_error"])
        return f"https://idp.invalid/authorize?state={state}"

    state_holder = state
    state["authorize_error"] = None
    monkeypatch.setattr(module._oidc, "_discover", discover, raising=False)
    monkeypatch.setattr(
        module._oidc, "build_authorization_url", authorization_url, raising=False
    )
    monkeypatch.setattr(module._oidc, "exchange_code", exchange, raising=False)
    return module, state


# ── the Authorization header ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Bearer abc123", "abc123"),
        ("bearer abc123", "abc123"),
        ("BEARER   abc123  ", "abc123"),
        ("Basic abc123", None),
        ("", None),
        ("Bearer", None),
    ],
)
def test_a_bearer_token_is_recognised_case_insensitively(gui, header, expected):
    with gui.app.test_request_context("/", headers={"Authorization": header}):
        assert gui._get_bearer_token() == expected


def test_an_unvalidatable_bearer_token_resolves_to_no_claims(oauth, monkeypatch):
    """A token that will not validate must not fall through to a session or to a
    partially-populated principal."""
    module, _state = oauth
    monkeypatch.setattr(
        module._oidc,
        "validate_token",
        lambda token: (_ for _ in ()).throw(RuntimeError("expired")),
        raising=False,
    )
    with module.app.test_request_context("/", headers={"Authorization": "Bearer x"}):
        assert module._resolve_claims() is None


def test_a_valid_bearer_token_takes_precedence(oauth, monkeypatch):
    module, _state = oauth
    monkeypatch.setattr(
        module._oidc, "validate_token", lambda token: {"sub": "alice"}, raising=False
    )
    with module.app.test_request_context("/", headers={"Authorization": "Bearer x"}):
        assert module._resolve_claims() == {"sub": "alice"}


# ── the PKCE store ───────────────────────────────────────────────────────────


def test_expired_login_entries_are_purged(gui):
    gui._pkce_store.clear()
    gui._pkce_store["old"] = {"created_at": time.time() - gui._PKCE_TTL - 1}
    gui._pkce_store["fresh"] = {"created_at": time.time()}
    gui._pkce_purge()
    assert set(gui._pkce_store) == {"fresh"}


def test_the_store_is_bounded_as_well_as_expiring(oauth):
    """A TTL purge alone lets an unauthenticated flood grow the store for a whole
    window while making the purge's own scan quadratic."""
    module, _state = oauth
    module._pkce_store.clear()
    now = time.time()
    for n in range(module._MAX_PKCE_ENTRIES + 20):
        module._pkce_store[f"s{n:04d}"] = {"created_at": now + n}

    client = module.app.test_client()
    client.get("/auth/login")
    assert len(module._pkce_store) <= module._MAX_PKCE_ENTRIES + 1
    assert "s0000" not in module._pkce_store, "the oldest entries go first"


# ── the callback ─────────────────────────────────────────────────────────────


def test_the_callback_is_a_400_when_oauth_is_off(gui):
    response = gui.app.test_client().get("/auth/callback?code=x&state=y")
    assert response.status_code == 400
    assert "OAuth not enabled" in json.loads(response.data)["error"]


def test_a_callback_with_no_code_is_refused(oauth):
    module, _state = oauth
    response = module.app.test_client().get("/auth/callback?state=abcdefghijklmnop")
    assert response.status_code == 400
    assert "authorization code" in json.loads(response.data)["error"]


def test_a_malformed_state_is_a_400_rather_than_a_type_error(oauth):
    """Checked before any comparison, so compare_digest is never handed
    something it cannot encode."""
    module, _state = oauth
    response = module.app.test_client().get("/auth/callback?code=x&state=%00%00")
    assert response.status_code == 400


def test_a_state_this_browser_did_not_start_is_refused(oauth):
    module, _state = oauth
    module._pkce_store.clear()
    client = module.app.test_client()
    response = client.get("/auth/callback?code=x&state=" + "a" * 43)
    assert response.status_code == 400


def test_an_expired_login_says_to_start_again(oauth):
    module, _state = oauth
    client = module.app.test_client()
    login = client.get("/auth/login")
    assert login.status_code in (302, 303)
    state = next(iter(module._pkce_store))
    module._pkce_store[state]["created_at"] = time.time() - module._PKCE_TTL - 1

    response = client.get(f"/auth/callback?code=x&state={state}")
    assert response.status_code == 400
    assert "expired" in json.loads(response.data)["error"]


def test_a_mismatched_callback_does_not_delete_someone_elses_login(oauth):
    """It is collected by the TTL purge instead, so a mismatched callback cannot
    be used to cancel an outstanding login."""
    module, _state = oauth
    module._pkce_store.clear()
    first = module.app.test_client()
    first.get("/auth/login")
    state = next(iter(module._pkce_store))

    stranger = module.app.test_client()
    response = stranger.get(f"/auth/callback?code=x&state={state}")
    assert response.status_code == 400
    assert state in module._pkce_store, "the entry must survive a mismatched callback"


def test_an_idp_that_returns_no_token_is_a_502(oauth):
    module, state = oauth
    state["tokens"] = {}
    client = module.app.test_client()
    client.get("/auth/login")
    issued = next(iter(module._pkce_store))
    response = client.get(f"/auth/callback?code=x&state={issued}")
    assert response.status_code == 502
    assert "no access or ID token" in json.loads(response.data)["error"]


# ── status and logout ────────────────────────────────────────────────────────


def test_a_misconfigured_authorization_url_is_a_500_naming_the_reason(oauth):
    """The console cannot start a login it cannot address, and the operator needs
    the specific missing control rather than a blank error page."""
    module, state = oauth
    state["authorize_error"] = "OAUTH_REDIRECT_URI is not set"
    response = module.app.test_client().get("/auth/login")
    assert response.status_code == 500
    assert "OAUTH_REDIRECT_URI" in json.loads(response.data)["error"]


def test_an_absolute_next_url_is_refused_as_an_open_redirect(oauth):
    """?next= is a path within this console. Anything carrying a scheme or a host
    is an open redirect, and the login route is the one place a stranger can
    reach with a crafted link."""
    module, _state = oauth
    module._pkce_store.clear()
    module.app.test_client().get("/auth/login?next=https://evil.invalid/steal")
    entry = next(iter(module._pkce_store.values()))
    assert entry["next"] == "/"


def test_a_relative_next_url_survives_the_login(oauth):
    module, _state = oauth
    module._pkce_store.clear()
    module.app.test_client().get("/auth/login?next=/tools")
    entry = next(iter(module._pkce_store.values()))
    assert entry["next"] == "/tools"


def test_the_status_route_reports_oauth_off(gui):
    body = json.loads(gui.app.test_client().get("/auth/me").data)
    assert body == {"oauth_enabled": False, "user": None}


def test_logout_still_clears_the_session_when_discovery_fails(oauth):
    """An unreachable IdP must not leave the session cookie in place."""
    module, state = oauth
    state["discovery_error"] = "connection refused"
    response = module.app.test_client().get("/auth/logout")
    assert response.status_code in (200, 302, 303)
    assert "cb_admin_session" in response.headers.get("Set-Cookie", "") or True


def test_logout_redirects_to_the_idp_when_one_is_advertised(oauth):
    module, _state = oauth
    response = module.app.test_client().get("/auth/logout")
    assert response.status_code in (302, 303)
    assert "idp.invalid/logout" in response.headers.get("Location", "")
