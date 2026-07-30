"""
`validate_token` executed for real, against a real JWKS.

WHY THIS FILE EXISTS
====================
`auth.oidc.validate_token` is the function that makes every authorization decision in this
server, and **no test had ever executed it**. Every existing test that touches it replaces it:

    monkeypatch.setattr("auth.oidc.validate_token", lambda _t: claims)

That is the right thing to do when testing the dispatch layer — the point there is the layers
ABOVE the decision. But it left the decision itself unexercised, so nothing verified that:

  * a bad signature is rejected;
  * `exp`, `iss` and `sub` are REQUIRED to be present, not merely validated when present;
  * the audience is enforced when configured;
  * a token signed with HS256 using the public key as the HMAC secret is refused;
  * OAUTH_SKIP_VERIFY refuses to combine with CB_ADMIN_HTTP_REQUIRE_AUTH, or with a
    non-loopback bind.

Coverage said 52% for the module and looked unremarkable, because the JWKS throttle around it
IS well tested and `profile_config` has its own separate skip-verify check. The gap was
specifically the decision.

HOW
===
A 2048-bit RSA keypair is generated once per session, its public half is served as a real JWKS
document by a local HTTP server, and tokens are minted with PyJWT. So the path under test is
the production one: fetch JWKS, match `kid`, verify the signature, enforce the claims. No part
of `validate_token` is stubbed.
"""

from __future__ import annotations

import http.server
import json
import socket
import threading
import time
import urllib.parse
from typing import ClassVar

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER_PATH = "/realms/mcp"
KID = "test-key-1"
AUDIENCE = "couchbase-admin-mcp"


# ── A real keypair, and a real JWKS endpoint ─────────────────────────────────


@pytest.fixture(scope="module")
def keypair():
    """One 2048-bit RSA key for the session. Generation is the slow part, so it is shared."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks_document(public_key, kid: str = KID) -> dict:
    """The public key as a JWKS document, the way an IdP would publish it."""
    numbers = public_key.public_numbers()

    def b64(value: int) -> str:
        import base64

        length = (value.bit_length() + 7) // 8
        return (
            base64.urlsafe_b64encode(value.to_bytes(length, "big"))
            .rstrip(b"=")
            .decode()
        )

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": b64(numbers.n),
                "e": b64(numbers.e),
            }
        ]
    }


class _IdpHandler(http.server.BaseHTTPRequestHandler):
    """Serves discovery and JWKS. Counts JWKS fetches, which the throttle tests need."""

    jwks: ClassVar[dict] = {"keys": []}
    issuer: ClassVar[str] = ""
    jwks_fetches: ClassVar[int] = 0

    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path.endswith("/.well-known/openid-configuration"):
            payload = {
                "issuer": _IdpHandler.issuer,
                "jwks_uri": f"{_IdpHandler.issuer}/protocol/openid-connect/certs",
                "token_endpoint": f"{_IdpHandler.issuer}/protocol/openid-connect/token",
                "authorization_endpoint": f"{_IdpHandler.issuer}/protocol/openid-connect/auth",
            }
        elif self.path.endswith("/certs"):
            _IdpHandler.jwks_fetches += 1
            payload = _IdpHandler.jwks
        else:
            self.send_response(404)
            self.end_headers()
            return

        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def idp(keypair):
    """A local stand-in for the identity provider. Yields its issuer URL."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    issuer = f"http://127.0.0.1:{port}{ISSUER_PATH}"
    _IdpHandler.issuer = issuer
    _IdpHandler.jwks = _jwks_document(keypair.public_key())

    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _IdpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield issuer
    server.shutdown()


@pytest.fixture
def oidc(idp, monkeypatch):
    """`auth.oidc` configured against the local IdP, with all module caches cleared.

    The module caches the discovery document, the PyJWKClient per URI, and the throttle
    state. Left over between tests those make outcomes depend on order — and under
    pytest-randomly, differently each run.
    """
    import auth.oidc as module

    for key in (
        "OAUTH_ISSUER",
        "OAUTH_AUDIENCE",
        "OAUTH_ALGORITHMS",
        "OAUTH_JWKS_URI",
        "OAUTH_SKIP_VERIFY",
        "CB_ADMIN_HTTP_REQUIRE_AUTH",
        "CB_ADMIN_HOST",
    ):
        monkeypatch.delenv(key, raising=False)

    monkeypatch.setenv("OAUTH_ISSUER", idp)
    monkeypatch.setenv("OAUTH_AUDIENCE", AUDIENCE)

    module._discovery_cache.clear()
    module._jwks_clients.clear()
    module.reset_jwks_throttle()
    _IdpHandler.jwks_fetches = 0
    return module


def _token(keypair, *, kid=KID, algorithm="RS256", key=None, **claims):
    """Mint a real signed JWT. Defaults produce a valid one."""
    payload = {
        "sub": "user-123",
        "iss": _IdpHandler.issuer,
        "aud": AUDIENCE,
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
        "scope": "couchbase:read",
        **claims,
    }
    for name in [k for k, v in payload.items() if v is None]:
        del payload[name]
    return jwt.encode(
        payload,
        key if key is not None else keypair,
        algorithm=algorithm,
        headers={"kid": kid},
    )


# ── The happy path has to work, or every rejection below is vacuous ──────────


def test_a_valid_token_is_accepted_and_returns_its_claims(oidc, keypair):
    claims = oidc.validate_token(_token(keypair))
    assert claims["sub"] == "user-123"
    assert claims["scope"] == "couchbase:read"


def test_the_jwks_was_actually_fetched(oidc, keypair):
    """Proves the signature was checked against a key retrieved over the network, rather
    than the whole verification being skipped."""
    oidc.validate_token(_token(keypair))
    assert _IdpHandler.jwks_fetches >= 1


def test_the_key_set_is_cached_between_validations(oidc, keypair):
    """A fetch per request would be an amplification attack on the customer's IdP from a
    trusted source address."""
    for _ in range(5):
        oidc.validate_token(_token(keypair))
    assert _IdpHandler.jwks_fetches == 1, (
        f"{_IdpHandler.jwks_fetches} JWKS fetches for 5 validations"
    )


# ── Signature ────────────────────────────────────────────────────────────────


def test_a_token_signed_by_the_wrong_key_is_rejected(oidc):
    """The whole point. Signed correctly, structured correctly, wrong issuer key."""
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = _token(attacker_key, key=attacker_key)
    with pytest.raises(jwt.PyJWTError):
        oidc.validate_token(forged)


def test_a_tampered_payload_is_rejected(oidc, keypair):
    """Editing a claim after signing. The classic attempt at privilege escalation."""
    import base64

    valid = _token(keypair)
    header, payload, signature = valid.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
    decoded["scope"] = "couchbase:admin couchbase:automation"
    forged_payload = (
        base64.urlsafe_b64encode(json.dumps(decoded).encode()).rstrip(b"=").decode()
    )
    with pytest.raises(jwt.PyJWTError):
        oidc.validate_token(f"{header}.{forged_payload}.{signature}")
    # And the original still works, so the rejection is about the tampering.
    assert oidc.validate_token(valid)["scope"] == "couchbase:read"


def test_an_unsigned_token_is_rejected(oidc, keypair):
    """`alg: none`. The oldest JWT attack there is."""
    unsigned = jwt.encode(
        {
            "sub": "attacker",
            "iss": _IdpHandler.issuer,
            "aud": AUDIENCE,
            "exp": 9999999999,
        },
        key="",
        algorithm="none",
        headers={"kid": KID},
    )
    with pytest.raises(Exception):  # noqa: B017 - PyJWT's type varies by version
        oidc.validate_token(unsigned)


def test_an_hs256_token_signed_with_the_public_key_is_rejected(oidc, keypair):
    """ALGORITHM CONFUSION, and the reason OAUTH_ALGORITHMS is restricted.

    The JWKS public key is, by definition, public. If HS256 were accepted, an attacker
    could use that public key as the HMAC secret and mint tokens the server would verify
    as genuine. PyJWT refuses the key type today, but an operator adding "HS256" to make
    some IdP work would silently reopen it — which is why the refusal is on the
    CONFIGURATION and not left to the library.
    """
    import base64
    import hashlib
    import hmac

    from cryptography.hazmat.primitives import serialization

    public_pem = keypair.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Assembled by hand, because `jwt.encode` REFUSES to use a PEM key as an HMAC secret:
    #
    #   InvalidKeyError: The specified key is an asymmetric key or x509 certificate and
    #                    should not be used as an HMAC secret.
    #
    # That is a real second layer of defence, and worth recording. But it protects the
    # signer, and the attacker is not using our library — so minting the token the way an
    # attacker would is the only way to test OUR side of the exchange.
    def b64(raw: bytes) -> bytes:
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode())
    payload = b64(
        json.dumps(
            {
                "sub": "attacker",
                "iss": _IdpHandler.issuer,
                "aud": AUDIENCE,
                "exp": 9999999999,
            }
        ).encode()
    )
    signing_input = header + b"." + payload
    signature = b64(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
    forged = (signing_input + b"." + signature).decode()

    # Sanity: the forgery is well-formed and really is HS256 over the public key, so a
    # server that accepted HS256 WOULD be fooled by it. Without this the test could pass
    # because the token is simply malformed.
    assert jwt.get_unverified_header(forged)["alg"] == "HS256"
    assert hmac.compare_digest(
        signature,
        b64(hmac.new(public_pem, signing_input, hashlib.sha256).digest()),
    )

    with pytest.raises(Exception):  # noqa: B017
        oidc.validate_token(forged)


def test_configuring_a_symmetric_algorithm_is_refused_outright(
    oidc, monkeypatch, keypair
):
    """Refused at the configuration, before any token is examined — so it cannot be
    reached by any request at all."""
    monkeypatch.setenv("OAUTH_ALGORITHMS", "RS256 HS256")
    with pytest.raises(RuntimeError, match="non-asymmetric"):
        oidc.validate_token(_token(keypair))


@pytest.mark.parametrize("algorithms", ["none", "HS512", "RS256 none"])
def test_every_forgeable_algorithm_is_refused(oidc, monkeypatch, keypair, algorithms):
    monkeypatch.setenv("OAUTH_ALGORITHMS", algorithms)
    with pytest.raises(RuntimeError, match="non-asymmetric"):
        oidc.validate_token(_token(keypair))


def test_asymmetric_algorithms_are_permitted(oidc, monkeypatch, keypair):
    """Guards the refusals above from passing because everything is refused."""
    monkeypatch.setenv("OAUTH_ALGORITHMS", "RS256 PS256 ES256")
    assert oidc.validate_token(_token(keypair))["sub"] == "user-123"


# ── Required claims ──────────────────────────────────────────────────────────


def test_the_required_claims_are_the_ones_an_authorization_decision_needs(oidc):
    assert set(oidc.REQUIRED_CLAIM_NAMES) == {"exp", "iss", "sub"}


def test_a_token_with_no_expiry_is_rejected(oidc, keypair):
    """`jwt.decode` only VALIDATES exp when it is present, so a token minted without one
    was previously accepted forever. `require` is what closes that."""
    with pytest.raises(jwt.MissingRequiredClaimError):
        oidc.validate_token(_token(keypair, exp=None))


def test_an_expired_token_is_rejected(oidc, keypair):
    with pytest.raises(jwt.ExpiredSignatureError):
        oidc.validate_token(_token(keypair, exp=int(time.time()) - 3600))


def test_a_token_with_no_subject_is_rejected(oidc, keypair):
    """Without `sub` the principal is null, so the audit record cannot attribute the
    action — an unattributable administrative change is exactly what the audit trail
    exists to prevent."""
    with pytest.raises(jwt.MissingRequiredClaimError):
        oidc.validate_token(_token(keypair, sub=None))


def test_a_token_with_no_issuer_is_rejected(oidc, keypair):
    with pytest.raises(jwt.PyJWTError):
        oidc.validate_token(_token(keypair, iss=None))


def test_a_token_from_a_different_issuer_is_rejected(oidc, keypair):
    """Correctly signed by our key but claiming another issuer."""
    with pytest.raises(jwt.InvalidIssuerError):
        oidc.validate_token(_token(keypair, iss="https://evil.example.com/realms/mcp"))


def test_a_small_amount_of_clock_skew_is_tolerated(oidc, keypair):
    """A token that expired one second ago is almost certainly a clock difference, not an
    attack, and refusing it makes the server fragile against normal NTP drift."""
    assert oidc.validate_token(_token(keypair, exp=int(time.time()) - 1))


# ── Audience ─────────────────────────────────────────────────────────────────


def test_a_token_for_another_application_is_rejected(oidc, keypair):
    """THE realistic escalation in a large corporate IdP: the attacker holds a valid token
    for some unrelated app in the same tenant. Correct signature, correct issuer, wrong
    audience."""
    with pytest.raises(jwt.InvalidAudienceError):
        oidc.validate_token(_token(keypair, aud="some-other-application"))


def test_the_audience_check_can_be_disabled_for_providers_that_omit_it(
    oidc, monkeypatch, keypair
):
    """Some providers do not set `aud` at all. With OAUTH_AUDIENCE unset the check is
    skipped — permitted only because the next test makes that combination fatal in the
    configuration that demands authentication."""
    monkeypatch.delenv("OAUTH_AUDIENCE", raising=False)
    assert oidc.validate_token(_token(keypair, aud=None))["sub"] == "user-123"


def test_omitting_the_audience_is_fatal_when_auth_is_required(
    oidc, monkeypatch, keypair
):
    """Without an audience check ANY validly-signed token from the issuer is accepted,
    including one minted for an unrelated application in the same tenant. In a shared
    corporate tenant that is a realistic path from "holds a token" to "administers the
    cluster"."""
    monkeypatch.delenv("OAUTH_AUDIENCE", raising=False)
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    with pytest.raises(RuntimeError, match="OAUTH_AUDIENCE must be set"):
        oidc.validate_token(_token(keypair))


# ── OAUTH_SKIP_VERIFY, and the two combinations it must refuse ───────────────
#
# These are the refusals with no test behind them until now. `profile_config` has its own,
# separate skip-verify check, which is what made the coverage here look adequate.


def test_skip_verify_accepts_anything_on_loopback_development(oidc, monkeypatch):
    """The documented development behaviour, asserted so the refusals below are shown to be
    specific rather than skip-verify being broken outright."""
    monkeypatch.setenv("OAUTH_SKIP_VERIFY", "true")
    monkeypatch.setenv("CB_ADMIN_HOST", "127.0.0.1")
    unverifiable = jwt.encode({"sub": "dev"}, key="a" * 40, algorithm="HS256")
    assert oidc.validate_token(unverifiable)["sub"] == "dev"


def test_skip_verify_is_refused_when_authentication_is_required(oidc, monkeypatch):
    """The configuration that demands authentication and then verifies nothing, accepting
    any token including an unsigned one. Previously only a log line — emitted per token, to
    a logger CB_ADMIN_LOG_LEVEL=ERROR discards, so the "hardened" deployment could silently
    be a no-op."""
    monkeypatch.setenv("OAUTH_SKIP_VERIFY", "true")
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    monkeypatch.setenv("CB_ADMIN_HOST", "127.0.0.1")
    with pytest.raises(RuntimeError, match="OAUTH_SKIP_VERIFY"):
        oidc.validate_token(jwt.encode({"sub": "x"}, key="k" * 40, algorithm="HS256"))


@pytest.mark.parametrize("host", ["0.0.0.0", "10.1.2.3", "cb-admin.internal"])
def test_skip_verify_is_refused_on_a_network_interface(oidc, monkeypatch, host):
    """With verification off, any caller that can reach the port is a full administrator.
    Bound to a network interface that is a remote unauthenticated admin API."""
    monkeypatch.setenv("OAUTH_SKIP_VERIFY", "true")
    monkeypatch.setenv("CB_ADMIN_HOST", host)
    with pytest.raises(RuntimeError, match="OAUTH_SKIP_VERIFY"):
        oidc.validate_token(jwt.encode({"sub": "x"}, key="k" * 40, algorithm="HS256"))


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", ""])
def test_skip_verify_is_permitted_on_loopback(oidc, monkeypatch, host):
    """Guards the test above from passing because skip-verify refuses everything."""
    monkeypatch.setenv("OAUTH_SKIP_VERIFY", "true")
    monkeypatch.setenv("CB_ADMIN_HOST", host)
    assert oidc.validate_token(
        jwt.encode({"sub": "x"}, key="k" * 40, algorithm="HS256")
    )


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes"])
def test_skip_verify_is_recognised_in_every_documented_spelling(
    oidc, monkeypatch, value
):
    """A refusal that only fires for one spelling of the flag is a refusal an operator can
    step around by accident."""
    monkeypatch.setenv("OAUTH_SKIP_VERIFY", value)
    monkeypatch.setenv("CB_ADMIN_HOST", "0.0.0.0")
    with pytest.raises(RuntimeError, match="OAUTH_SKIP_VERIFY"):
        oidc.validate_token(jwt.encode({"sub": "x"}, key="k" * 40, algorithm="HS256"))


@pytest.mark.parametrize("value", ["false", "0", "no", ""])
def test_a_falsey_skip_verify_still_verifies(oidc, monkeypatch, keypair, value):
    """The dangerous inverse: a flag read as truthy when it is not would disable
    verification for a deployment that never asked."""
    monkeypatch.setenv("OAUTH_SKIP_VERIFY", value)
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(jwt.PyJWTError):
        oidc.validate_token(_token(attacker_key, key=attacker_key))


# ── Unknown kid: the throttle, exercised through validate_token ──────────────


def test_a_token_with_an_unknown_kid_is_rejected(oidc, keypair):
    with pytest.raises(Exception):  # noqa: B017
        oidc.validate_token(_token(keypair, kid="not-a-real-kid"))


def test_random_kids_do_not_cause_a_jwks_fetch_each(oidc, keypair):
    """The amplification attack the throttle exists for.

    `kid` comes from the UNVERIFIED header, so it is entirely attacker-chosen. PyJWT calls
    get_signing_keys(refresh=True) on a miss, which bypasses its own cache — measured at
    200 requests producing 200 outbound fetches against the customer's IdP.

    Exercised HERE through validate_token, where the existing tests call the throttle
    helpers directly; this is the path a request actually takes.
    """
    oidc.validate_token(_token(keypair))  # prime the cache legitimately
    baseline = _IdpHandler.jwks_fetches

    for index in range(40):
        with pytest.raises(Exception):  # noqa: B017
            oidc.validate_token(_token(keypair, kid=f"random-{index}"))

    fetches = _IdpHandler.jwks_fetches - baseline
    assert fetches <= 10, f"{fetches} JWKS fetches for 40 unknown-kid tokens"


def test_a_legitimate_token_still_validates_while_unknown_kids_are_throttled(
    oidc, keypair
):
    """The failure mode of the FIRST attempt at this throttle: it recorded one global
    timestamp, so a single unauthenticated request with a random kid refused every
    legitimate token for the next sixty seconds. A rate limit on a shared resource has to
    be keyed to the thing being abused."""
    oidc.validate_token(_token(keypair))
    for index in range(20):
        with pytest.raises(Exception):  # noqa: B017
            oidc.validate_token(_token(keypair, kid=f"junk-{index}"))

    assert oidc.validate_token(_token(keypair))["sub"] == "user-123"


def test_a_token_with_no_kid_at_all_does_not_bypass_the_gate(oidc, keypair):
    """A kid-less token skipped the gate entirely in an earlier version of this code —
    101 fetches per 100 requests. The bypass was in my own fix for the original problem."""
    oidc.validate_token(_token(keypair))
    baseline = _IdpHandler.jwks_fetches

    for _ in range(30):
        token = jwt.encode(
            {
                "sub": "x",
                "iss": _IdpHandler.issuer,
                "aud": AUDIENCE,
                "exp": int(time.time()) + 60,
            },
            keypair,
            algorithm="RS256",
        )
        with pytest.raises(Exception):  # noqa: B017
            oidc.validate_token(token)

    fetches = _IdpHandler.jwks_fetches - baseline
    assert fetches <= 10, f"{fetches} JWKS fetches for 30 kid-less tokens"


# ── Discovery ────────────────────────────────────────────────────────────────


def test_the_jwks_uri_is_discovered_from_the_issuer(oidc, keypair):
    """No OAUTH_JWKS_URI is set in these tests, so a passing happy path already proves
    discovery works. This asserts it explicitly, and that the document is cached."""
    oidc._discovery_cache.clear()
    document = oidc._discover()
    assert document["jwks_uri"].endswith("/certs")
    assert oidc._discover() is document, "the discovery document was refetched"


def test_an_explicit_jwks_uri_overrides_discovery(oidc, monkeypatch, keypair):
    """An operator behind a proxy, or an IdP with a non-standard document, needs this — and
    it must not silently fall back to discovery."""
    monkeypatch.setenv(
        "OAUTH_JWKS_URI", f"{_IdpHandler.issuer}/protocol/openid-connect/certs"
    )
    oidc._discovery_cache.clear()
    assert oidc.validate_token(_token(keypair))["sub"] == "user-123"
    # Discovery was never consulted.
    assert oidc._discovery_cache == {}


def test_a_missing_issuer_is_reported_by_name(oidc, monkeypatch):
    monkeypatch.delenv("OAUTH_ISSUER", raising=False)
    oidc._discovery_cache.clear()
    with pytest.raises(RuntimeError, match="OAUTH_ISSUER"):
        oidc._discover()


# ── Claims helper ────────────────────────────────────────────────────────────


def test_userinfo_is_extracted_from_claims(oidc, keypair):
    claims = oidc.validate_token(
        _token(keypair, email="ada@example.com", name="Ada Lovelace")
    )
    info = oidc.userinfo_from_claims(claims)
    assert info["email"] == "ada@example.com"


def test_userinfo_does_not_carry_the_raw_token_material(oidc, keypair):
    """It is put in responses and log lines, so it must not become a credential leak."""
    claims = oidc.validate_token(_token(keypair, email="ada@example.com"))
    info = oidc.userinfo_from_claims(claims)
    for value in info.values():
        assert "eyJ" not in str(value), "a JWT fragment reached the userinfo payload"


# ── The OAuth flow functions ─────────────────────────────────────────────────
#
# Five functions with no tests at all. Two of them implement CSRF controls for the browser
# login: PKCE binds the authorization code to the client that requested it, and `state` binds
# the callback to the session that started it. A silent regression in either turns the console
# login into something an attacker can drive.
#
# The token endpoint is stubbed at `_requests.post`, because what matters is the PAYLOAD this
# server sends, not that `requests` works.


class _TokenEndpoint:
    """Records what was POSTed to the IdP's token endpoint."""

    def __init__(self, response=None, status=200):
        self.calls: list[tuple[str, dict]] = []
        self.response = response if response is not None else {"access_token": "at"}
        self.status = status

    def __call__(self, url, data=None, timeout=None):
        self.calls.append((url, dict(data or {})))
        endpoint = self

        class _Response:
            status_code = endpoint.status

            def raise_for_status(self):
                if endpoint.status >= 400:
                    import requests

                    raise requests.HTTPError(f"HTTP {endpoint.status}")

            def json(self):
                return endpoint.response

        return _Response()


@pytest.fixture
def token_endpoint(oidc, monkeypatch):
    endpoint = _TokenEndpoint()
    monkeypatch.setattr(oidc._requests, "post", endpoint)
    monkeypatch.setenv("OAUTH_CLIENT_ID", "cb-admin")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "client-secret-value")
    monkeypatch.setenv("OAUTH_REDIRECT_URI", "http://localhost:5173/auth/callback")
    return endpoint


# ── PKCE ─────────────────────────────────────────────────────────────────────


def test_pkce_challenge_is_the_s256_hash_of_the_verifier(oidc):
    """The whole mechanism. If the challenge were not derived from the verifier — or were
    the verifier itself, which is the `plain` method — an attacker who intercepted the
    authorization code could redeem it, because PKCE would no longer bind the two."""
    import base64
    import hashlib

    verifier, challenge = oidc.generate_pkce_pair()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert challenge == expected
    assert challenge != verifier, (
        "this is the `plain` method, which provides no binding"
    )


def test_pkce_verifiers_are_unpredictable(oidc):
    """A guessable verifier defeats the binding as thoroughly as no binding at all."""
    verifiers = {oidc.generate_pkce_pair()[0] for _ in range(50)}
    assert len(verifiers) == 50
    # RFC 7636 requires 43-128 characters.
    assert all(43 <= len(v) <= 128 for v in verifiers)


def test_the_pkce_challenge_is_url_safe_and_unpadded(oidc):
    """It travels in a query string. Standard base64 `+`, `/` and `=` would be mangled or
    would silently alter the value the IdP compares against."""
    for _ in range(20):
        _verifier, challenge = oidc.generate_pkce_pair()
        assert "=" not in challenge
        assert "+" not in challenge
        assert "/" not in challenge


# ── The authorization URL ────────────────────────────────────────────────────


def test_the_authorization_url_carries_state_and_the_s256_challenge(
    oidc, monkeypatch, token_endpoint
):
    url = oidc.build_authorization_url("state-abc", "challenge-xyz")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)

    assert query["state"] == ["state-abc"], (
        "no state means no CSRF protection on callback"
    )
    assert query["code_challenge"] == ["challenge-xyz"]
    assert query["code_challenge_method"] == ["S256"], (
        "S256 is what makes PKCE binding cryptographic; `plain` does not"
    )
    assert query["response_type"] == ["code"]


def test_the_authorization_url_never_carries_the_client_secret(
    oidc, monkeypatch, token_endpoint
):
    """It is a redirect the BROWSER follows: everything in it is visible to the user, in
    their history, and in any referrer. The secret belongs only in the back-channel token
    exchange."""
    url = oidc.build_authorization_url("s", "c")
    assert "client-secret-value" not in url
    assert "client_secret" not in url


def test_the_authorization_url_points_at_the_discovered_endpoint(
    oidc, monkeypatch, token_endpoint
):
    url = oidc.build_authorization_url("s", "c")
    assert url.startswith(f"{_IdpHandler.issuer}/protocol/openid-connect/auth?")


def test_a_missing_client_id_is_reported_by_name(oidc, monkeypatch, token_endpoint):
    monkeypatch.delenv("OAUTH_CLIENT_ID", raising=False)
    with pytest.raises(RuntimeError, match="OAUTH_CLIENT_ID"):
        oidc.build_authorization_url("s", "c")


# ── Code exchange ────────────────────────────────────────────────────────────


def test_the_code_exchange_sends_the_verifier_and_the_secret(oidc, token_endpoint):
    """The back-channel call. The verifier is what proves this is the same client that
    started the flow; without it PKCE is decorative."""
    oidc.exchange_code("auth-code-123", "verifier-456")

    ((url, payload),) = token_endpoint.calls
    assert url.endswith("/protocol/openid-connect/token")
    assert payload["grant_type"] == "authorization_code"
    assert payload["code"] == "auth-code-123"
    assert payload["code_verifier"] == "verifier-456"
    assert payload["client_secret"] == "client-secret-value"


def test_the_code_exchange_sends_the_same_redirect_uri(oidc, token_endpoint):
    """The IdP compares it against the one in the authorization request; a mismatch is a
    rejected login that looks like a credential problem."""
    oidc.exchange_code("code", "verifier")
    assert (
        token_endpoint.calls[0][1]["redirect_uri"]
        == "http://localhost:5173/auth/callback"
    )


def test_a_rejected_code_exchange_raises(oidc, monkeypatch):
    """A failed exchange must not return a falsy token dict that a caller could mistake for
    a successful login with no tokens."""
    failing = _TokenEndpoint(status=400, response={"error": "invalid_grant"})
    monkeypatch.setattr(oidc._requests, "post", failing)
    monkeypatch.setenv("OAUTH_CLIENT_ID", "cb-admin")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "s")
    monkeypatch.setenv("OAUTH_REDIRECT_URI", "http://localhost:5173/auth/callback")

    import requests

    with pytest.raises(requests.HTTPError):
        oidc.exchange_code("stale-code", "verifier")


# ── Refresh ──────────────────────────────────────────────────────────────────


def test_the_refresh_call_sends_the_refresh_token_and_grant(oidc, token_endpoint):
    oidc.refresh_access_token("refresh-789")
    payload = token_endpoint.calls[0][1]
    assert payload["grant_type"] == "refresh_token"
    assert payload["refresh_token"] == "refresh-789"


def test_the_refresh_call_does_not_send_a_code_verifier(oidc, token_endpoint):
    """PKCE applies to the authorization code exchange only. Sending a stale verifier here
    is at best ignored and at worst a rejected refresh."""
    oidc.refresh_access_token("refresh-789")
    assert "code_verifier" not in token_endpoint.calls[0][1]


def test_a_rejected_refresh_raises_so_the_session_can_be_ended(oidc, monkeypatch):
    """The console treats a failed refresh as a dead session and logs the user out. A silent
    success would leave them holding an expired token."""
    failing = _TokenEndpoint(status=400, response={"error": "invalid_grant"})
    monkeypatch.setattr(oidc._requests, "post", failing)
    monkeypatch.setenv("OAUTH_CLIENT_ID", "cb-admin")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "s")

    import requests

    with pytest.raises(requests.HTTPError):
        oidc.refresh_access_token("expired")


# ── Client credentials (the machine-to-machine flow) ─────────────────────────


def test_client_credentials_uses_the_client_credentials_grant(oidc, token_endpoint):
    oidc.client_credentials_token()
    assert token_endpoint.calls[0][1]["grant_type"] == "client_credentials"


def test_client_credentials_prefers_its_own_dedicated_identity(
    oidc, token_endpoint, monkeypatch
):
    """A separate credential for machine access means the automation principal can be
    scoped, rotated and revoked without touching the browser login."""
    monkeypatch.setenv("OAUTH_CC_CLIENT_ID", "cb-admin-automation")
    monkeypatch.setenv("OAUTH_CC_CLIENT_SECRET", "automation-secret")

    oidc.client_credentials_token()

    payload = token_endpoint.calls[0][1]
    assert payload["client_id"] == "cb-admin-automation"
    assert payload["client_secret"] == "automation-secret"


def test_client_credentials_falls_back_to_the_main_identity(oidc, token_endpoint):
    """So the simple single-client deployment works with no extra configuration."""
    oidc.client_credentials_token()
    assert token_endpoint.calls[0][1]["client_id"] == "cb-admin"


def test_the_oidc_only_scopes_are_stripped_for_machine_access(
    oidc, token_endpoint, monkeypatch
):
    """`openid`, `profile` and `email` describe a HUMAN. Several providers reject a
    client-credentials request carrying them, so the failure would appear only in the
    unattended flow — the one with nobody watching."""
    monkeypatch.setenv("OAUTH_SCOPES", "openid profile email couchbase:admin")
    monkeypatch.delenv("OAUTH_CC_SCOPES", raising=False)

    oidc.client_credentials_token()

    scopes = token_endpoint.calls[0][1]["scope"].split()
    assert "couchbase:admin" in scopes
    for human_scope in ("openid", "profile", "email"):
        assert human_scope not in scopes


def test_explicit_machine_scopes_are_used_verbatim(oidc, token_endpoint, monkeypatch):
    monkeypatch.setenv("OAUTH_CC_SCOPES", "couchbase:read couchbase:automation")
    oidc.client_credentials_token()
    assert token_endpoint.calls[0][1]["scope"] == "couchbase:read couchbase:automation"


def test_stripping_every_scope_leaves_a_usable_default(
    oidc, token_endpoint, monkeypatch
):
    """An empty `scope` is rejected by some providers. Only reachable when the configured
    scopes are entirely OIDC-only, which is the default for a browser-first setup."""
    monkeypatch.setenv("OAUTH_SCOPES", "openid profile email")
    monkeypatch.delenv("OAUTH_CC_SCOPES", raising=False)

    oidc.client_credentials_token()
    assert token_endpoint.calls[0][1]["scope"].strip()


# ── A canary for stub leakage ────────────────────────────────────────────────


def test_validate_token_is_still_the_real_function():
    """Fails loudly if another test module has replaced it by assignment.

    This is not hypothetical. The console's OAuth fixture originally did

        module._oidc.validate_token = lambda token: {...}

    and `module._oidc` IS `auth.oidc`, so the replacement outlived the test — every later
    test in the process "validated" any token by returning a fixed claims dict. It surfaced as
    47 unrelated failures here, plus an HTTP-auth test that passed while accepting an
    unauthenticated caller. That second symptom is the dangerous one: a leaked stub makes an
    authorization test pass for the wrong reason.

    Anything that needs to stub it must go through monkeypatch, which undoes itself.
    """
    import auth.oidc

    function = auth.oidc.validate_token
    assert function.__module__ == "auth.oidc", (
        f"validate_token has been replaced by something from {function.__module__}"
    )
    assert function.__name__ == "validate_token", (
        f"validate_token has been replaced by {function.__name__!r} — a test module assigned "
        "over it instead of using monkeypatch"
    )
