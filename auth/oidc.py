"""
auth/oidc.py — Generic OIDC / OAuth 2.0 provider abstraction.

Supports:
  - Authorization Code + PKCE  (GUI browser login)
  - Client Credentials          (machine-to-machine API access)

Works with any OIDC-compliant identity provider (Okta, Entra ID, Keycloak,
Auth0, Google Workspace, Ping, etc.).

Required environment variables
──────────────────────────────
  OAUTH_ISSUER               https://your-idp.example.com/realms/mcp
  OAUTH_CLIENT_ID            <app client ID>
  OAUTH_CLIENT_SECRET        <app client secret>
  OAUTH_REDIRECT_URI         http://localhost:5173/auth/callback
  OAUTH_SCOPES               openid profile email   (space-separated, optional)
  OAUTH_AUDIENCE             <API audience / resource indicator, optional>

Optional — client credentials only
  OAUTH_CC_CLIENT_ID         (defaults to OAUTH_CLIENT_ID)
  OAUTH_CC_CLIENT_SECRET     (defaults to OAUTH_CLIENT_SECRET)
  OAUTH_CC_SCOPES            (defaults to OAUTH_SCOPES minus openid/profile/email)

Optional — token validation
  OAUTH_JWKS_URI             (auto-discovered via /.well-known/openid-configuration)
  OAUTH_ALGORITHMS           RS256  (space-separated list)
  OAUTH_SKIP_VERIFY          false  (set true ONLY in development — skips sig check)
"""

from __future__ import annotations

import hashlib
import os
import secrets
import urllib.parse
from typing import Any

import jwt
import requests as _requests

# ── Config helpers ────────────────────────────────────────────────────────────


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()


def _env_required(key: str) -> str:
    val = _env(key)
    if not val:
        raise RuntimeError(
            f"OIDC configuration error: {key} is not set. "
            "Check your .env file or environment."
        )
    return val


# ── OIDC discovery (cached) ───────────────────────────────────────────────────

_discovery_cache: dict[str, Any] = {}
_jwks_clients: dict[str, Any] = {}  # jwks_uri -> PyJWKClient (cached per URI)
_JWKS_TTL = 3600  # PyJWKClient cache lifespan in seconds


def _discover() -> dict[str, Any]:
    """Fetch and cache the OIDC discovery document."""
    issuer = _env_required("OAUTH_ISSUER").rstrip("/")
    if issuer in _discovery_cache:
        return _discovery_cache[issuer]

    # Standard discovery URL (RFC 8414 / OpenID Connect Discovery 1.0)
    well_known = f"{issuer}/.well-known/openid-configuration"
    resp = _requests.get(well_known, timeout=10)
    resp.raise_for_status()
    doc = resp.json()
    _discovery_cache[issuer] = doc
    return doc


# ── Authorization Code + PKCE ─────────────────────────────────────────────────


def generate_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = __import__("base64").urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def build_authorization_url(state: str, code_challenge: str) -> str:
    """Build the full Authorization Code + PKCE redirect URL."""
    doc = _discover()
    auth_ep = doc["authorization_endpoint"]
    scopes = _env("OAUTH_SCOPES") or "openid profile email"
    aud = _env("OAUTH_AUDIENCE")

    params: dict[str, str] = {
        "response_type": "code",
        "client_id": _env_required("OAUTH_CLIENT_ID"),
        "redirect_uri": _env_required("OAUTH_REDIRECT_URI"),
        "scope": scopes,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if aud:
        params["audience"] = aud

    return f"{auth_ep}?{urllib.parse.urlencode(params)}"


def exchange_code(code: str, code_verifier: str) -> dict[str, Any]:
    """
    Exchange an authorization code for tokens.
    Returns the full token response dict (access_token, id_token, refresh_token, …).
    """
    doc = _discover()
    token_ep = doc["token_endpoint"]
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _env_required("OAUTH_REDIRECT_URI"),
        "client_id": _env_required("OAUTH_CLIENT_ID"),
        "client_secret": _env_required("OAUTH_CLIENT_SECRET"),
        "code_verifier": code_verifier,
    }
    resp = _requests.post(token_ep, data=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()


def refresh_access_token(refresh_token: str) -> dict[str, Any]:
    """Use a refresh token to get a new access token."""
    doc = _discover()
    token_ep = doc["token_endpoint"]
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": _env_required("OAUTH_CLIENT_ID"),
        "client_secret": _env_required("OAUTH_CLIENT_SECRET"),
    }
    resp = _requests.post(token_ep, data=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()


# ── Client Credentials ────────────────────────────────────────────────────────


def client_credentials_token() -> dict[str, Any]:
    """
    Obtain an access token via the Client Credentials flow.
    Uses OAUTH_CC_* vars when set, falls back to OAUTH_CLIENT_*.
    Returns the full token response dict.
    """
    doc = _discover()
    token_ep = doc["token_endpoint"]

    client_id = _env("OAUTH_CC_CLIENT_ID") or _env_required("OAUTH_CLIENT_ID")
    client_secret = _env("OAUTH_CC_CLIENT_SECRET") or _env_required(
        "OAUTH_CLIENT_SECRET"
    )
    scopes = _env("OAUTH_CC_SCOPES")
    aud = _env("OAUTH_AUDIENCE")

    # Default CC scopes: strip OIDC-only scopes that don't apply to M2M
    if not scopes:
        base = _env("OAUTH_SCOPES") or ""
        scopes = (
            " ".join(
                s
                for s in base.split()
                if s not in ("openid", "profile", "email", "address", "phone")
            )
            or "api"
        )

    payload: dict[str, str] = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scopes,
    }
    if aud:
        payload["audience"] = aud

    resp = _requests.post(token_ep, data=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()


# ── Token validation ──────────────────────────────────────────────────────────


def validate_token(token: str) -> dict[str, Any]:
    """
    Validate a JWT access token.

    - Fetches the provider's public keys via JWKS (cached).
    - Verifies signature, expiry, issuer, and audience (if configured).
    - Returns the decoded claims dict on success.
    - Raises jwt.PyJWTError (or a subclass) on failure.

    Setting OAUTH_SKIP_VERIFY=true skips signature verification.
    USE ONLY IN DEVELOPMENT — this makes authentication meaningless.
    """
    skip = _env("OAUTH_SKIP_VERIFY", "false").lower() in ("1", "true", "yes")
    if skip:
        # Decode without verification — dev only
        return jwt.decode(token, options={"verify_signature": False})

    algorithms = (_env("OAUTH_ALGORITHMS") or "RS256").split()
    issuer = _env("OAUTH_ISSUER").rstrip("/")
    audience = _env("OAUTH_AUDIENCE") or None

    # Resolve the JWKS URI once (from explicit env var or discovery), then
    # use a module-cached PyJWKClient so the fetched key set persists between
    # calls (a fresh client per call would refetch JWKS every time).
    jwks_uri = _env("OAUTH_JWKS_URI") or _discover()["jwks_uri"]
    jwks_client = _jwks_clients.get(jwks_uri)
    if jwks_client is None:
        jwks_client = jwt.PyJWKClient(jwks_uri, cache_jwk_set=True, lifespan=_JWKS_TTL)
        _jwks_clients[jwks_uri] = jwks_client
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    decode_opts: dict[str, Any] = {}
    if not audience:
        # Some providers (Keycloak) put the client_id as the audience;
        # others don't set aud at all. Only enforce if explicitly configured.
        decode_opts["options"] = {"verify_aud": False}

    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=algorithms,
        issuer=issuer,
        audience=audience,
        **decode_opts,
    )
    return claims


def userinfo_from_claims(claims: dict[str, Any]) -> dict[str, str]:
    """Extract displayable user info from decoded JWT claims."""
    return {
        "sub": claims.get("sub", ""),
        "email": claims.get("email", claims.get("preferred_username", "")),
        "name": claims.get("name", claims.get("given_name", "")),
    }
