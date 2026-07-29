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
import os
import secrets
import time
from typing import Any

# ── Config ────────────────────────────────────────────────────────────────────


def _session_ttl() -> int:
    try:
        return int(os.environ.get("OAUTH_SESSION_TTL_SECONDS", "28800"))  # 8 h
    except (ValueError, TypeError):
        return 28800


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


def _purge_expired() -> None:
    """Remove stale sessions (called on session creation to avoid unbounded growth)."""
    ttl = _session_ttl()
    now = time.time()
    stale = [sid for sid, entry in _store.items() if now - entry["created"] > ttl]
    for sid in stale:
        _store.pop(sid, None)
