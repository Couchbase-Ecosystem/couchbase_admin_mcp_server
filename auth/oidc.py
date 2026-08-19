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
import threading
import time
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


#: kid values recently observed to be absent from the JWKS, with the time seen.
#: PER-KID, and consulted only on a genuine cache miss.
#:
#: The first attempt at this was itself a denial of service, worse than the problem
#: it solved: the throttle ran on EVERY validation and recorded a global
#: `_last_refetch`, so one unauthenticated request carrying a random `kid` refused
#: every legitimate token for the next 60 seconds. The lesson is that a rate limit
#: on a shared resource must be keyed to the thing being abused, not to the resource.
_UNKNOWN_KID_WINDOW = 60.0
_unknown_kids: dict[str, float] = {}
_MAX_TRACKED_KIDS = 512

#: All mutation of the two structures below happens under this lock.
#:
#: validate_token now runs on worker threads from two places (the edge middleware and
#: the dispatch), so a plain dict was genuinely racy: building the stale-entry list
#: with a comprehension over _unknown_kids.items() raised "dictionary changed size
#: during iteration" under concurrent load. That RuntimeError is swallowed upstream
#: and becomes a denial — so LEGITIMATE tokens were intermittently rejected, and the
#: enterprise deployment is a fan-out of concurrent child agents, i.e. concurrency is
#: the normal case rather than the edge one.
_throttle_lock = threading.Lock()


#: Token bucket over ACTUAL JWKS refreshes, regardless of which kid caused them.
#:
#: The per-kid memo alone did not mitigate the attack it was written for. `kid` comes
#: from the UNVERIFIED header, so it is entirely attacker-chosen: varying it every
#: request never hits a per-kid entry, and each novel kid costs one outbound fetch
#: because PyJWT's refresh=True bypasses its own lifespan cache. Measured at 200
#: requests -> 200 fetches. That is 1:1 amplification against the customer's IdP from
#: a trusted source address, plus one blocked worker thread per request.
#:
#: A budget on the scarce resource — the outbound fetch — cannot be evaded by
#: choosing a different key, because there is no key-derived state to miss.
def _int_env(key: str, default: int) -> int:
    raw = (os.environ.get(key) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


_REFRESH_BUDGET = _int_env("CB_ADMIN_JWKS_REFRESH_BUDGET", 10)
_REFRESH_WINDOW = 60.0
_refresh_times: list[float] = []


def _refresh_budget_available(now: float) -> bool:
    """Whether another JWKS refresh is permitted in the current window."""
    cutoff = now - _REFRESH_WINDOW
    _refresh_times[:] = [t for t in _refresh_times if t > cutoff]
    return len(_refresh_times) < _REFRESH_BUDGET


#: Claims an authorization decision depends on, required to be PRESENT.
#:
#: jwt.decode only validates exp/nbf when present, so a token minted without exp was
#: accepted forever; and one without `sub` produces principal: null, i.e. an
#: unattributable admin action. Named as a module constant so a test can assert on it —
#: every test monkeypatches validate_token, so the requirement itself was uncovered and
#: could be silently dropped.
REQUIRED_CLAIM_NAMES: tuple[str, ...] = ("exp", "iss", "sub")


#: Kids that have successfully resolved, per JWKS URI. Deliberately ours rather than
#: PyJWT's: PyJWT's cache has a lifespan, and an EXPIRED cache is what turned the
#: unknown-kid gate into an amplifier. A kid that once existed is evidence enough that
#: a token bearing it is not the invented-kid abuse this gate is aimed at, and being
#: wrong here costs one extra fetch, not a security property.
_resolved_kids: dict[str, set[str]] = {}

#: Bound on the record, so a rotating IdP cannot grow it without limit.
_MAX_RESOLVED_KIDS = 64


def _jwks_uri_of(jwks_client: Any) -> str:
    return str(getattr(jwks_client, "uri", "") or "")


def _remember_resolved_kid(jwks_uri: str, kid: str | None) -> None:
    if not kid:
        return
    with _throttle_lock:
        known = _resolved_kids.setdefault(jwks_uri, set())
        if len(known) >= _MAX_RESOLVED_KIDS:
            known.clear()
        known.add(kid)


def _kid_of(token: str) -> str | None:
    try:
        return jwt.get_unverified_header(token).get("kid")
    except Exception:
        return None  # malformed header: normal validation rejects it


def _kid_is_known(jwks_client: Any, kid: str | None) -> bool:
    """Whether the kid is already in the CACHED key set — no network call.

    A missing or empty kid is never "known": PyJWT will look up None, match nothing,
    and refresh. Returning False here is what routes that case into the throttle.
    """
    if not kid:
        return False
    # Read the CACHE OBJECT, not get_signing_keys(refresh=False).
    #
    # PyJWT resolves that call by FETCHING whenever the cached key set is absent or
    # past its lifespan -- so the gate consumed the outbound request it exists to
    # budget, before the budget was consulted. Measured: 50 requests carrying the same
    # unknown kid produced 51 outbound JWKS fetches despite the per-kid memo refusing
    # 49 of them, and 30 unknown-kid requests against an expired cache produced 40
    # fetches with the budget set to 10. That is 1:1 amplification against the
    # customer's IdP, worst exactly when the IdP is already unhealthy, and each fetch
    # also ties up a default-executor worker for PyJWT's timeout.
    # 1. Our OWN record of kids that have resolved before. Checked first because it
    #    is the only source that cannot cause a network call and cannot expire.
    if kid in _resolved_kids.get(_jwks_uri_of(jwks_client), ()):
        return True
    try:
        # 2. PyJWT's cached key set, read directly. get_signing_keys(refresh=False)
        #    was used here, and PyJWT resolves that by FETCHING whenever the cache is
        #    absent or past its lifespan -- so the gate consumed the outbound request
        #    it exists to budget, before the budget was consulted. Measured: 50
        #    requests with one unknown kid produced 51 fetches, and 30 unknown-kid
        #    requests against an expired cache produced 40 fetches against a budget of
        #    10. That is 1:1 amplification against the customer's IdP, worst exactly
        #    when the IdP is already unhealthy.
        cache = getattr(jwks_client, "jwk_set_cache", None)
        jwk_set = cache.get() if cache is not None else None
        if jwk_set is not None:
            for key in getattr(jwk_set, "keys", []) or []:
                if getattr(key, "key_id", None) == kid:
                    return True
            return False
        # 3. Cold start only: nothing cached and nothing ever resolved for this URI, so
        #    there is no way to answer without one fetch -- and that fetch is the one
        #    a first legitimate request needs anyway. Once anything resolves, step 1
        #    answers forever and the gate stops fetching.
        for key in jwks_client.get_signing_keys(refresh=False):
            if getattr(key, "key_id", None) == kid:
                return True
    except Exception:
        # An empty or unfetched cache is not evidence either way; treat as unknown
        # so the throttle below decides whether a fetch is permitted.
        return False
    return False


def gate_unknown_kid(jwks_client: Any, token: str, jwks_uri: str) -> None:
    """Decide whether this token may cause an outbound JWKS refresh.

    Extracted from validate_token so the COMPOSED decision is testable. Mutation
    testing showed why that matters: dropping the ``_kid_is_known`` check — which
    turns the throttle back into a denial of service against legitimate tokens —
    was caught by no test, because every test called the helpers individually and
    none exercised the two of them together.

    The cached key set is consulted FIRST so a token signed with a key we already hold
    is never throttled, however much abuse is in flight.
    """
    kid = _kid_of(token)

    # A FALSY kid must still be gated. `if kid and ...` short-circuited the whole
    # gate, and PyJWT then calls get_signing_key(None), which matches no key and
    # triggers get_signing_keys(refresh=True) anyway — so a caller omitting the kid
    # header entirely, or sending kid:"", restored the exact 1:1 amplification this
    # was written to stop (measured: 101 outbound fetches per 100 requests, identical
    # to the pre-fix baseline). The gate belongs on the MISS, not on the header being
    # present: a token whose key we cannot identify is precisely the case that costs a
    # fetch.
    if not _kid_is_known(jwks_client, kid):
        _refuse_if_recently_missed(jwks_uri, kid or "<no-kid>")


def _refuse_if_recently_missed(jwks_uri: str, kid: str) -> None:
    """Gate an outbound JWKS refresh for an unknown kid.

    Two checks, because they stop different things:

      * the per-kid memo stops a repeat of the SAME unknown kid, which is what a
        misconfigured client produces;
      * the global refresh budget stops a caller CYCLING kids, which is what an
        attacker produces, and which the per-kid memo cannot see by construction.

    Everything runs under a lock: this is called from worker threads.
    """
    now = time.monotonic()
    marker = f"{jwks_uri}|{kid}"

    with _throttle_lock:
        for stale in [
            k
            for k, seen in list(_unknown_kids.items())
            if now - seen > _UNKNOWN_KID_WINDOW
        ]:
            _unknown_kids.pop(stale, None)

        if marker in _unknown_kids:
            raise RuntimeError(
                "Unknown signing key id, and a JWKS refresh for this key was "
                "attempted moments ago. Refusing without another fetch."
            )

        if not _refresh_budget_available(now):
            raise RuntimeError(
                "JWKS refresh budget exhausted: too many tokens with unrecognised "
                "signing key ids in the last minute. Refusing without contacting the "
                "identity provider. Raise CB_ADMIN_JWKS_REFRESH_BUDGET if a "
                "legitimate key rotation needs more."
            )

        if len(_unknown_kids) >= _MAX_TRACKED_KIDS:
            _unknown_kids.clear()
        _unknown_kids[marker] = now
        _refresh_times.append(now)


def reset_jwks_throttle() -> None:
    """Clear throttle state. For tests, and for an explicit operator reset."""
    with _throttle_lock:
        _unknown_kids.clear()
        _refresh_times.clear()
        _resolved_kids.clear()


def _forget_unknown_kid(token: str, jwks_uri: str) -> None:
    """Clear the throttle entry once a kid has been resolved successfully.

    A legitimate key rotation costs exactly one refused request: the first token
    signed with the new kid triggers a refetch, and once the key resolves the entry
    is dropped so the next request is not throttled.
    """
    kid = _kid_of(token)
    if kid:
        _remember_resolved_kid(jwks_uri, kid)
        with _throttle_lock:
            _unknown_kids.pop(f"{jwks_uri}|{kid}", None)
            # DELIBERATELY does not refund the budget slot this fetch consumed.
            #
            # Refunding on success looks fair and is not: a caller holding any token
            # whose kid resolves could interleave one such request per invented kid
            # and hold the budget permanently open, restoring the IdP amplification
            # the budget exists to prevent.
            # test_forgetting_a_kid_does_not_reset_the_whole_budget pins this, and it
            # is correct to.
            #
            # ACCEPTED LIMITATION: the budget is global, so unauthenticated traffic
            # carrying invented kids can exhaust it and, until the window rolls, a
            # correctly-signed token for a newly rotated key is refused. Of the two
            # failure modes -- throttled authentication for up to
            # CB_ADMIN_JWKS_REFRESH_BUDGET's window, versus unbounded amplification
            # against the customer's IdP -- this is the safer one, and the window and
            # size are both operator-tunable. A per-client budget would be strictly
            # better but needs the request's identity, which this layer does not have;
            # it is the right fix if this ever bites in practice.


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
        # Refuse the combination outright rather than trusting a log line. The old
        # warning went to a logger that CB_ADMIN_LOG_LEVEL=ERROR discards, was
        # emitted per-token rather than at startup, and was accepted even with
        # CB_ADMIN_HTTP_REQUIRE_AUTH=true — so the "hardened" configuration could
        # silently be a no-op.
        if _env("CB_ADMIN_HTTP_REQUIRE_AUTH", "").lower() in ("1", "true", "yes", "on"):
            raise RuntimeError(
                "OAUTH_SKIP_VERIFY is enabled while CB_ADMIN_HTTP_REQUIRE_AUTH=true. "
                "That combination demands authentication and then verifies nothing, "
                "accepting any token including an unsigned one. Refusing to start. "
                "Unset OAUTH_SKIP_VERIFY."
            )
        host = _env("CB_ADMIN_HOST", "127.0.0.1")
        if host not in ("127.0.0.1", "localhost", "::1", ""):
            raise RuntimeError(
                f"OAUTH_SKIP_VERIFY is enabled while listening on {host!r}. "
                "Signature verification is disabled, so any caller that can reach "
                "this port is a full administrator. Refusing to start. This flag is "
                "for loopback development only."
            )
        # Decode without verification — dev only. Log loudly: if this is ever on
        # in a shared/production deployment it is a critical misconfiguration.
        import logging

        logging.getLogger("couchbase-admin.auth").warning(
            "OAUTH_SKIP_VERIFY is enabled — JWT signature/issuer/audience/expiry "
            "are NOT verified. Any token is accepted. NEVER use this in production."
        )
        return jwt.decode(token, options={"verify_signature": False})

    algorithms = (_env("OAUTH_ALGORITHMS") or "RS256").split()
    # Reject symmetric and "none" algorithms. With a JWKS public key in hand, an
    # HS256 acceptance is the classic algorithm-confusion path: the attacker signs
    # a token using the PUBLIC key as the HMAC secret. PyJWT happens to refuse the
    # key type today, but nothing stopped an operator adding "HS256" to make an IdP
    # work and silently re-opening it.
    unsafe = [
        a for a in algorithms if not a.upper().startswith(("RS", "PS", "ES", "ED"))
    ]
    if unsafe:
        raise RuntimeError(
            f"OAUTH_ALGORITHMS contains non-asymmetric algorithm(s) {unsafe}. Only "
            "RS*/PS*/ES*/Ed* are permitted; 'none' and HS* enable token forgery "
            "against a public verification key."
        )

    issuer = _env("OAUTH_ISSUER").rstrip("/")
    audience = _env("OAUTH_AUDIENCE") or None
    if not audience and _env("CB_ADMIN_HTTP_REQUIRE_AUTH", "").lower() in (
        "1",
        "true",
        "yes",
        "on",
    ):
        # Without an audience check, ANY validly-signed token from the issuer is
        # accepted — including one minted for an unrelated application in the same
        # corporate IdP tenant. In a large shared tenant that is a realistic path
        # from "holds any token" to "administers the cluster".
        raise RuntimeError(
            "OAUTH_AUDIENCE must be set when CB_ADMIN_HTTP_REQUIRE_AUTH=true. "
            "Without it every validly-signed token from the issuer is accepted, "
            "including tokens minted for other applications in the same tenant."
        )

    # Resolve the JWKS URI once (from explicit env var or discovery), then
    # use a module-cached PyJWKClient so the fetched key set persists between
    # calls (a fresh client per call would refetch JWKS every time).
    jwks_uri = _env("OAUTH_JWKS_URI") or _discover()["jwks_uri"]
    jwks_client = _jwks_clients.get(jwks_uri)
    if jwks_client is None:
        jwks_client = jwt.PyJWKClient(jwks_uri, cache_jwk_set=True, lifespan=_JWKS_TTL)
        _jwks_clients[jwks_uri] = jwks_client
    # Throttle ONLY a genuine miss. PyJWT reads `kid` from the UNVERIFIED header and,
    # when it is absent from the key set, calls get_signing_keys(refresh=True), which
    # bypasses its own lifespan cache — so an attacker choosing a random kid forced
    # one outbound JWKS fetch per request: a DoS on us and an amplification attack on
    # the customer's IdP. Checking the cached set first means a legitimate token (and
    # a legitimate key rotation, once the first request has fetched) is never
    # throttled, while a random kid costs one fetch per key per minute.
    gate_unknown_kid(jwks_client, token, jwks_uri)
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    # Require the claims an authorization decision depends on. jwt.decode only
    # validates exp/nbf when present, so a token minted without exp was previously
    # accepted forever, and one without sub produced an unattributable admin action.
    # `sub` is required, matching what the comment above already claimed. Without it a
    # token yields principal: null — the unattributable admin action the comment says
    # was fixed. Entra client-credentials tokens DO carry sub (the service principal's
    # object id), so this does not break the enterprise flow.
    required_claims = list(REQUIRED_CLAIM_NAMES) + (["aud"] if audience else [])
    decode_opts: dict[str, Any] = {
        "options": {"require": required_claims, "verify_exp": True},
        "leeway": 10,
    }
    if not audience:
        # Some providers (Keycloak) put the client_id as the audience;
        # others don't set aud at all. Only enforce if explicitly configured.
        decode_opts["options"]["verify_aud"] = False

    _forget_unknown_kid(token, jwks_uri)
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=algorithms,
        issuer=issuer,
        audience=audience,
        **decode_opts,
    )
    # PyJWT's `require` checks PRESENCE only, so `sub: ""` satisfied it. That
    # produced exactly the unattributable admin action the requirement exists to
    # prevent: scope_gate.principal_of() does `claims.get("sub") or ...`, which reads
    # "" as absent and returns principal None with automation True, and the audit
    # record then carries `"principal": null` for an unattended privileged write --
    # with no os_user fallback on the OAuth path. A required claim has to be
    # non-empty to mean anything.
    for claim in REQUIRED_CLAIM_NAMES:
        value = claims.get(claim)
        if isinstance(value, str) and not value.strip():
            raise jwt.InvalidTokenError(
                f"token claim {claim!r} is present but empty; it cannot identify "
                "the principal or the issuer, and an audit record without a "
                "principal cannot answer who performed an unattended write"
            )
    return claims


def userinfo_from_claims(claims: dict[str, Any]) -> dict[str, str]:
    """Extract displayable user info from decoded JWT claims."""
    return {
        "sub": claims.get("sub", ""),
        "email": claims.get("email", claims.get("preferred_username", "")),
        "name": claims.get("name", claims.get("given_name", "")),
    }
