"""
auth/session.py — Server-side session management for the GUI OAuth flow.

Design:
  - The browser receives a short, opaque session ID as a Secure HttpOnly cookie.
  - Token material (access_token, refresh_token, id_token, claims) is stored
    server-side in a plain dict (sufficient for a single-process dev/internal
    tool; swap for Redis if you need multi-process or persistence).
  - Sessions expire after OAUTH_SESSION_TTL_SECONDS (default 8 hours).
  - CSRF protection: every Authorization Code initiation sets a `state` value
    that is checked on callback.

Required environment variable:
  OAUTH_SESSION_SECRET   A long random string used to sign the session cookie.
                         Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import time
from typing import Any

# ── Config ────────────────────────────────────────────────────────────────────


DEFAULT_TTL_SECONDS = 28800  # 8 h


def _session_ttl() -> int:
    """The session lifetime, in seconds.

    An unparseable value falls back to the default rather than raising, because this is
    read on every request and a typo must not turn every authenticated request into a 500.
    `validate_startup()` is what reports the typo, once, at boot.
    """
    try:
        return int(
            os.environ.get("OAUTH_SESSION_TTL_SECONDS", str(DEFAULT_TTL_SECONDS))
        )
    except (ValueError, TypeError):
        return DEFAULT_TTL_SECONDS


def cookie_max_age() -> int:
    """The `max_age` for the session cookie.

    Exists so the browser-side cookie lifetime and the server-side session lifetime cannot
    drift. They were previously two independent reads of OAUTH_SESSION_TTL_SECONDS with
    DIFFERENT failure behaviour — this module fell back to 8 h, while the console did a bare
    `int(...)` that raised. The raise landed in the OAuth callback, after the token exchange
    had already succeeded, so a typo'd TTL made login impossible with a 500 and no clue why.
    """
    return _session_ttl()


SESSION_COOKIE = "cb_mcp_session"

# ── In-memory store ───────────────────────────────────────────────────────────
# { session_id: { "created": float, "data": dict } }
_store: dict[str, dict[str, Any]] = {}


def _signing_key() -> bytes:
    secret = os.environ.get("OAUTH_SESSION_SECRET", "")
    if not secret:
        raise RuntimeError(
            "OAUTH_SESSION_SECRET is not set. "
            'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    return secret.encode()


def _b64_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    """URL-safe base64 decode, adding correct padding regardless of input length."""
    # Pad to a multiple of 4 — works for any input length
    padding = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


# ── Cookie signing ────────────────────────────────────────────────────────────


def _sign(session_id: str) -> str:
    """Return  base64(session_id).base64(hmac-sha256)  — a tamper-evident cookie value."""
    key = _signing_key()
    sig = hmac.new(key, session_id.encode(), hashlib.sha256).digest()
    return f"{_b64_encode(session_id.encode())}.{_b64_encode(sig)}"


def _unsign(cookie_value: str) -> str | None:
    """Verify the cookie signature and return the session_id, or None on tampering."""
    try:
        b64_id, b64_sig = cookie_value.split(".", 1)
    except ValueError:
        return None

    try:
        session_id = _b64_decode(b64_id).decode()
    except Exception:
        return None

    key = _signing_key()
    expected = hmac.new(key, session_id.encode(), hashlib.sha256).digest()

    try:
        provided = _b64_decode(b64_sig)
    except Exception:
        return None

    if not hmac.compare_digest(expected, provided):
        return None
    return session_id


# ── Public API ────────────────────────────────────────────────────────────────


def create_session(data: dict[str, Any]) -> str:
    """
    Store `data` in a new session and return the signed cookie value
    to set on the response.
    """
    _purge_expired()
    session_id = secrets.token_urlsafe(32)
    _store[session_id] = {"created": time.time(), "data": data}
    return _sign(session_id)


def get_session(cookie_value: str) -> dict[str, Any] | None:
    """
    Verify the cookie, check expiry, and return the session data dict.
    Returns None if missing, tampered, or expired.
    """
    if not cookie_value:
        return None

    session_id = _unsign(cookie_value)
    if session_id is None:
        return None

    entry = _store.get(session_id)
    if entry is None:
        return None

    if time.time() - entry["created"] > _session_ttl():
        _store.pop(session_id, None)
        return None

    return entry["data"]


def update_session(cookie_value: str, updates: dict[str, Any]) -> bool:
    """Merge `updates` into an existing session. Returns False if session not found."""
    session_id = _unsign(cookie_value)
    if session_id is None or session_id not in _store:
        return False
    _store[session_id]["data"].update(updates)
    return True


def delete_session(cookie_value: str) -> None:
    """Remove the session (logout)."""
    session_id = _unsign(cookie_value)
    if session_id:
        _store.pop(session_id, None)


def _is_loopback_address(host: str) -> bool:
    """Whether a bind address is loopback. An EMPTY value is not: it binds everything."""
    if not host:
        return False
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def cookie_is_secure() -> bool:
    """Whether the session cookie must carry the `Secure` flag.

    Decided from CONFIGURATION, never from the request.

    The console previously used `secure=request.is_secure`, which reads the WSGI scheme.
    Behind a TLS-terminating reverse proxy the scheme Flask sees is plain `http`, so the
    session cookie was issued WITHOUT `Secure` — in precisely the enterprise shape the
    runbook documents (`CB_ADMIN_TLS_TERMINATED_EXTERNALLY=1` behind nginx or Traefik). A
    cookie without `Secure` is sent over cleartext, so any downgrade to http:// hands the
    session ID to the network.

    Reading `X-Forwarded-Proto` would be the obvious repair and is the wrong one. That
    header is attacker-settable, and `_is_loopback_client` in the console already refuses to
    trust forwarding headers for anything. Trusting one here to decide a security flag would
    contradict that: an attacker who can set `X-Forwarded-Proto: http` would strip `Secure`
    from their own cookie, and worse, the same header is the one a proxy is expected to set.

    So: TLS anywhere in the path — terminated here or upstream — means `Secure`. The only
    exception is the plain-HTTP loopback development case, where `Secure` would prevent the
    browser sending the cookie back over http://127.0.0.1 and break local login outright.
    """
    import tls_config

    settings = tls_config.from_env()
    # SIM103 is suppressed below: ruff wants this collapsed to
    # `return bool(cert_file or terminated_externally)`. Kept as two branches so the comment
    # further down can explain why returning False is deliberate rather than an oversight —
    # this decides a security flag, and the reasoning matters more than the line count.
    if settings.cert_file or settings.terminated_externally:
        return True

    # No TLS configured at all.
    #
    # The justification here USED to be "tls_config.validate() already refuses to start
    # in this state on a non-loopback bind" -- and that premise was false for the
    # console, which never called tls_config.validate at all. So an enterprise console
    # on GUI_HOST=0.0.0.0 with CB_GUI_ALLOW_REMOTE=1 and no CB_ADMIN_TLS_* started
    # happily and issued the session cookie -- the credential fronting the whole
    # destructive tool surface -- WITHOUT Secure, over cleartext, on a network
    # interface. gui_server._enforce_gui_posture now does call it, which makes the
    # premise true.
    #
    # It is still not sufficient on its own, because CB_ADMIN_TLS_* describes the MCP
    # TRANSPORT and says nothing about this process. So the console's OWN bind is
    # consulted: a non-loopback console with no TLS anywhere gets Secure regardless,
    # even though that will break its cookie -- a console that cannot log in is a much
    # better outcome than a session id crossing a network in clear, and the operator
    # gets a startup error from _enforce_gui_posture telling them why.
    # Read directly, do NOT substitute the loopback default for a SET-BUT-EMPTY value.
    # `(get("GUI_HOST") or "127.0.0.1")` turned "bind every interface" into "loopback",
    # which is the most exposed shape being read as the least.
    raw_host = os.environ.get("GUI_HOST")
    gui_host = "127.0.0.1" if raw_host is None else raw_host.strip()
    if not _is_loopback_address(gui_host):  # noqa: SIM103
        return True

    # Loopback development over http://. Secure here would stop the browser sending the
    # cookie back to http://127.0.0.1 and break local login outright.
    return False


def validate_startup() -> list[str]:
    """Configuration errors that must stop the console from starting. Empty list is OK.

    `_signing_key()` raises when OAUTH_SESSION_SECRET is unset, but it raises lazily — the
    console booted fine and then returned an opaque 500 to the first person who tried to log
    in. Every other misconfiguration in this project is fatal at startup with a message that
    names the variable; this one now is too.
    """
    errors: list[str] = []

    if not os.environ.get("OAUTH_SESSION_SECRET", "").strip():
        errors.append(
            "OAUTH_SESSION_SECRET is not set. The console signs its session cookies with "
            "it, so without it every login fails. Generate one with:\n"
            '  python -c "import secrets; print(secrets.token_hex(32))"'
        )

    raw_ttl = os.environ.get("OAUTH_SESSION_TTL_SECONDS")
    if raw_ttl is not None and raw_ttl.strip():
        try:
            ttl = int(raw_ttl)
        except (ValueError, TypeError):
            errors.append(
                f"OAUTH_SESSION_TTL_SECONDS={raw_ttl!r} is not an integer. Sessions would "
                f"silently fall back to {DEFAULT_TTL_SECONDS}s, which is longer than you "
                "probably meant if you were trying to shorten it."
            )
        else:
            if ttl <= 0:
                errors.append(
                    f"OAUTH_SESSION_TTL_SECONDS={ttl} expires every session the instant it "
                    "is created, so nobody can log in. Use a positive number of seconds."
                )

    return errors


def _purge_expired() -> None:
    """Remove stale sessions (called on session creation to avoid unbounded growth)."""
    ttl = _session_ttl()
    now = time.time()
    stale = [sid for sid, entry in _store.items() if now - entry["created"] > ttl]
    for sid in stale:
        _store.pop(sid, None)
