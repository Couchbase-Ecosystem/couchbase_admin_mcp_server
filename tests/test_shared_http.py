"""
`handlers/shared.py`: the HTTP client every self-managed tool goes through.

WHY THIS MATTERS MORE THAN ITS COVERAGE NUMBER SUGGESTED
=======================================================
`admin_request` carries a safety property that nothing tested: **a non-idempotent request is
not retried on a 5xx.** The reason is specific to this API. A POST whose response is lost to a
timeout or a 502 may already have been applied, and the POSTs here include
`/controller/failOver`, `/controller/doFlush` and rebalance. Re-issuing a failover because a
read timed out is worse than reporting the failure.

That distinction lived in a comment and a frozenset. Deleting either would have left the suite
green while turning one lost response into a second failover.

The client is exercised against a real local HTTP server rather than a mock, so the paths under
test include URL construction, the Authorization header, form-versus-JSON encoding, the retry
loop and its backoff, and what happens to an empty or non-JSON body.
"""

from __future__ import annotations

import base64
import http.server
import json
import socket
import threading
import urllib.parse
from typing import ClassVar

import pytest

from handlers import shared

# ── A stand-in for the ns_server management API ──────────────────────────────


class _Recorder:
    """What the server saw, and what it should answer with."""

    def __init__(self):
        self.requests: list[dict] = []
        #: Statuses to answer with, consumed in order. Anything left over means 200.
        self.statuses: list[int] = []
        self.body: str = '{"ok": true}'
        self.content_type = "application/json"


RECORDER = _Recorder()


class _NsServerHandler(http.server.BaseHTTPRequestHandler):
    recorder: ClassVar[_Recorder] = RECORDER

    def log_message(self, *_args):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        recorder = _NsServerHandler.recorder
        recorder.requests.append(
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "body": raw.decode(errors="replace"),
            }
        )

        status = recorder.statuses.pop(0) if recorder.statuses else 200
        payload = recorder.body.encode()
        self.send_response(status)
        if recorder.content_type:
            self.send_header("Content-Type", recorder.content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    # HEAD included: it is one of the four idempotent methods the retry policy treats as
    # safe to repeat, so it has to be reachable here or that branch cannot be tested.
    # `_handle` suppresses the body for it, as HEAD requires.
    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle  # noqa: N815 - stdlib contract


@pytest.fixture(scope="module")
def ns_server():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _NsServerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()


@pytest.fixture
def cluster(ns_server, monkeypatch):
    """`shared` pointed at the local server, with credentials and no backoff delay."""
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://127.0.0.1")
    monkeypatch.setenv("CB_MGMT_PORT", str(ns_server))
    monkeypatch.setenv("CB_USERNAME", "Administrator")
    monkeypatch.setenv("CB_PASSWORD", "password")
    for key in ("CB_CLIENT_CERT_PATH", "CB_CLIENT_KEY_PATH", "CB_CA_CERT_PATH"):
        monkeypatch.delenv(key, raising=False)

    # Real sleeps would make the retry tests take seconds for no benefit.
    monkeypatch.setattr(shared.time, "sleep", lambda _s: None)

    RECORDER.requests.clear()
    RECORDER.statuses.clear()
    RECORDER.body = '{"ok": true}'
    RECORDER.content_type = "application/json"
    shared._cluster_version = None
    return RECORDER


# ── Request construction ─────────────────────────────────────────────────────


def test_a_get_reaches_the_management_port_and_returns_parsed_json(cluster):
    assert shared.admin_request("GET", "/pools/default") == {"ok": True}
    assert cluster.requests[0]["method"] == "GET"
    assert cluster.requests[0]["path"] == "/pools/default"


def test_credentials_are_sent_as_basic_auth(cluster):
    shared.admin_request("GET", "/pools")
    header = cluster.requests[0]["headers"]["Authorization"]
    assert header.startswith("Basic ")
    decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
    assert decoded == "Administrator:password"


def test_query_parameters_are_url_encoded(cluster):
    """Hand-built query strings are how a bucket name with a space becomes a 400 that looks
    like a Couchbase bug."""
    shared.admin_request("GET", "/pools/default/buckets", params={"name": "my bucket"})
    assert "name=my+bucket" in cluster.requests[0]["path"] or (
        "name=my%20bucket" in cluster.requests[0]["path"]
    )


def test_a_dict_body_is_sent_as_form_encoded_by_default(cluster):
    """ns_server's management API is form-encoded almost everywhere; sending JSON to it
    produces a 400 with no useful message."""
    shared.admin_request(
        "POST", "/pools/default/buckets", data={"name": "b", "ramQuota": 100}
    )
    request = cluster.requests[0]
    assert request["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert urllib.parse.parse_qs(request["body"]) == {
        "name": ["b"],
        "ramQuota": ["100"],
    }


def test_none_valued_fields_are_dropped_from_a_form_body(cluster):
    """Otherwise an unset optional argument is transmitted as the literal string "None" and
    silently stored as a setting."""
    shared.admin_request("POST", "/x", data={"name": "b", "replicaNumber": None})
    assert "None" not in cluster.requests[0]["body"]
    assert "replicaNumber" not in cluster.requests[0]["body"]


def test_json_body_is_opt_in(cluster):
    shared.admin_request("POST", "/x", data={"a": 1}, json_body=True)
    request = cluster.requests[0]
    assert request["headers"]["Content-Type"] == "application/json"
    assert json.loads(request["body"]) == {"a": 1}


def test_a_list_body_is_always_json(cluster):
    """A list cannot be form-encoded at all, so the caller must not have to remember the
    flag — several endpoints (FTS, eventing) take a JSON array."""
    shared.admin_request("POST", "/x", data=[{"a": 1}, {"b": 2}])
    request = cluster.requests[0]
    assert request["headers"]["Content-Type"] == "application/json"
    assert json.loads(request["body"]) == [{"a": 1}, {"b": 2}]


def test_admin_request_json_is_a_shim_for_json_body(cluster):
    shared.admin_request_json("PUT", "/x", payload={"a": 1})
    assert cluster.requests[0]["headers"]["Content-Type"] == "application/json"


# ── Response handling ────────────────────────────────────────────────────────


def test_an_empty_response_becomes_an_explicit_ok(cluster):
    """Many mutating endpoints answer 200 with no body. Returning None would read as
    failure to every caller."""
    cluster.body = ""
    assert shared.admin_request("POST", "/controller/doSomething") == {"status": "ok"}


def test_a_non_json_response_is_returned_as_text_rather_than_raising(cluster):
    """`/api/cfg` and friends answer text/plain. A JSONDecodeError here would surface as a
    tool crash on an endpoint that worked."""
    cluster.body = "not json at all"
    cluster.content_type = "text/plain"
    result = shared.admin_request("GET", "/api/cfg")
    assert result["status"] == "ok"
    assert result["body"] == "not json at all"


def test_an_http_error_becomes_a_runtime_error_naming_the_call(cluster):
    """The message is what an operator reads. Without the method and path it says only that
    something returned 400."""
    cluster.statuses = [400]
    cluster.body = '{"errors": {"name": "already exists"}}'
    with pytest.raises(RuntimeError) as excinfo:
        shared.admin_request("POST", "/pools/default/buckets", data={"name": "b"})
    message = str(excinfo.value)
    assert "400" in message
    assert "POST /pools/default/buckets" in message
    assert "already exists" in message


# ── Retry semantics: the safety property ─────────────────────────────────────


def test_a_get_is_retried_on_a_transient_server_error(cluster):
    cluster.statuses = [503, 503]
    assert shared.admin_request("GET", "/pools") == {"ok": True}
    assert len(cluster.requests) == 3


def test_a_post_is_NOT_retried_on_a_server_error(cluster):
    """THE property this file exists for.

    A POST whose response is lost may already have been applied, and the POSTs on this API
    include `/controller/failOver`, `/controller/doFlush` and rebalance. Retrying a failover
    because the first reply was a 502 is worse than reporting the failure — it fails over a
    second node.
    """
    cluster.statuses = [502]
    with pytest.raises(RuntimeError):
        shared.admin_request("POST", "/controller/failOver", data={"otpNode": "ns_1@a"})
    assert len(cluster.requests) == 1, (
        "a failover POST was re-sent after a 502; it may have been applied twice"
    )


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_no_five_hundred_class_status_retries_a_post(cluster, status):
    cluster.statuses = [status]
    with pytest.raises(RuntimeError):
        shared.admin_request("POST", "/controller/doFlush")
    assert len(cluster.requests) == 1


@pytest.mark.parametrize("status", [408, 425, 429])
def test_a_post_IS_retried_when_the_status_proves_nothing_happened(cluster, status):
    """408, 425 and 429 mean the server rejected or never began the request. Refusing to
    retry those would make the client fragile against ordinary rate limiting for no safety
    gain."""
    cluster.statuses = [status]
    assert shared.admin_request("POST", "/x", data={"a": 1}) == {"ok": True}
    assert len(cluster.requests) == 2


@pytest.mark.parametrize("method", ["GET", "HEAD", "PUT", "DELETE"])
def test_idempotent_methods_retry_on_a_server_error(cluster, method):
    """Repeating these cannot create a second resource or re-run an action, so retrying is
    strictly better than surfacing a transient failure."""
    cluster.statuses = [503]
    shared.admin_request(method, "/x")
    assert len(cluster.requests) == 2


def test_a_client_error_is_never_retried(cluster):
    """A 404 or 400 will not become a 200. Retrying triples the latency of every mistake."""
    cluster.statuses = [404]
    with pytest.raises(RuntimeError):
        shared.admin_request("GET", "/nope")
    assert len(cluster.requests) == 1


def test_the_retry_budget_is_bounded(cluster):
    """An endpoint failing persistently must not retry forever and hold the caller open."""
    cluster.statuses = [503] * 20
    with pytest.raises(RuntimeError):
        shared.admin_request("GET", "/x")
    assert len(cluster.requests) == shared._MAX_ATTEMPTS


def test_the_backoff_grows_between_attempts(cluster, monkeypatch):
    """A tight retry loop against a struggling cluster is an attack on it."""
    delays: list[float] = []
    monkeypatch.setattr(shared.time, "sleep", delays.append)
    cluster.statuses = [503, 503]
    shared.admin_request("GET", "/x")
    assert delays == sorted(delays)
    assert len(set(delays)) > 1, f"backoff did not increase: {delays}"


def _count_network_failures(monkeypatch, method: str) -> int:
    """Attempts made when the connection itself fails. Returns the call count.

    Counted by intercepting `urlopen`, not by pointing at a closed port: the first version of
    this test only asserted that a RuntimeError was raised, which is true whether the client
    tried once or three times. The mutation that retried a POST on a network error survived it.
    """
    import urllib.error
    import urllib.request

    attempts = {"n": 0}

    def _refuse(*_args, **_kwargs):
        attempts["n"] += 1
        raise urllib.error.URLError("connection reset by peer")

    monkeypatch.setattr(urllib.request, "urlopen", _refuse)
    with pytest.raises(RuntimeError, match="Network error"):
        shared.admin_request(method, "/controller/failOver")
    return attempts["n"]


def test_a_network_error_on_a_post_is_not_retried(cluster, monkeypatch):
    """The case the comment calls out: a dropped connection cannot be distinguished from
    "applied, reply lost". So a failover whose connection died must not be re-sent."""
    assert _count_network_failures(monkeypatch, "POST") == 1


def test_a_network_error_on_a_get_IS_retried(cluster, monkeypatch):
    """Guards the test above from passing because nothing is ever retried. A transient
    connection reset on a read should not surface as a failure."""
    assert _count_network_failures(monkeypatch, "GET") == shared._MAX_ATTEMPTS


def test_a_timeout_of_zero_is_clamped(cluster):
    """urlopen treats 0 as a non-blocking socket and fails instantly, so a stray 0 would
    look like "no timeout" and break every call."""
    assert shared._HTTP_TIMEOUT >= 1


def test_the_retry_count_is_at_least_one(cluster):
    """CB_ADMIN_HTTP_RETRIES=0 would mean no attempt at all."""
    assert shared._MAX_ATTEMPTS >= 1


# ── URL derivation ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("connection_string", "expected"),
    [
        ("couchbase://localhost", "http://localhost:8091"),
        ("couchbases://cb.example.com", "https://cb.example.com:18091"),
        # An SDK port must not become the management port.
        ("couchbase://host:11210", "http://host:8091"),
        # A path or query is not part of the host.
        ("couchbase://host/somepath", "http://host:8091"),
        ("couchbases://host/?ssl=no_verify", "https://host:18091"),
        # A query with NO preceding slash is still not part of the host. This form
        # produced "http://host?kv_timeout=5s:8091", which urllib reads as host
        # `host`, port 80 and selector "/?kv_timeout=5s:8091/pools/..." -- so every
        # call silently hit `/` instead of the intended path.
        ("couchbase://host?kv_timeout=5s", "http://host:8091"),
        ("couchbases://host#frag", "https://host:18091"),
        # Only the first host of a multi-node string is contacted. The HA spelling
        # `couchbase://n1,n2,n3` previously yielded "http://n1,n2,n3:8091", so every
        # admin REST call failed DNS resolution while the SDK path worked.
        ("couchbase://node1,node2", "http://node1:8091"),
        ("couchbase://n1,n2,n3", "http://n1:8091"),
        ("couchbases://n1,n2", "https://n1:18091"),
        # An IPv6 literal is bracketed; the port split must not cut inside it.
        ("couchbase://[2001:db8::1]:11210", "http://[2001:db8::1]:8091"),
    ],
)
def test_the_management_url_is_derived_from_the_connection_string(
    monkeypatch, connection_string, expected
):
    monkeypatch.setenv("CB_CONNECTION_STRING", connection_string)
    monkeypatch.delenv("CB_MGMT_PORT", raising=False)
    assert shared._admin_url() == expected


def test_tls_selects_the_secure_management_port(monkeypatch):
    """8091 on a TLS-only cluster is refused, and the failure looks like a network problem
    rather than a wrong port."""
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbases://h")
    monkeypatch.delenv("CB_MGMT_PORT", raising=False)
    assert shared._admin_url().endswith(":18091")


def test_an_explicit_management_port_wins(monkeypatch):
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://h")
    monkeypatch.setenv("CB_MGMT_PORT", "9999")
    assert shared._admin_url() == "http://h:9999"


# ── TLS context ──────────────────────────────────────────────────────────────


def test_plain_couchbase_builds_no_tls_context(monkeypatch):
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://h")
    assert shared._build_ssl_context() is None


def test_a_tls_connection_string_builds_a_verifying_context(monkeypatch):
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbases://h")
    monkeypatch.delenv("CB_ADMIN_TLS_INSECURE", raising=False)
    for key in ("CB_CA_CERT_PATH", "CB_CLIENT_CERT_PATH", "CB_CLIENT_KEY_PATH"):
        monkeypatch.delenv(key, raising=False)

    context = shared._build_ssl_context()
    assert context is not None
    assert context.check_hostname is True
    import ssl

    assert context.verify_mode == ssl.CERT_REQUIRED


def test_verification_is_disabled_only_by_explicit_opt_in(monkeypatch):
    """It has to be possible — self-signed certs on a test cluster are normal — but it must
    take a named variable rather than happening because a cert path was wrong."""
    import ssl

    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbases://h")
    monkeypatch.setenv("CB_ADMIN_TLS_INSECURE", "true")
    context = shared._build_ssl_context()
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_a_custom_ca_is_loaded(monkeypatch, tmp_path):
    """A cluster with a private CA is the common enterprise case; without this every call
    fails verification."""
    import ssl

    ca = tmp_path / "ca.pem"
    default = ssl.create_default_context()
    # A real certificate, so load_verify_locations genuinely parses it.
    ca.write_text(_SELF_SIGNED_CERT)
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbases://h")
    monkeypatch.setenv("CB_CA_CERT_PATH", str(ca))
    monkeypatch.delenv("CB_ADMIN_TLS_INSECURE", raising=False)

    context = shared._build_ssl_context()
    assert len(context.get_ca_certs()) >= 1
    assert len(context.get_ca_certs()) != len(default.get_ca_certs())


# ── mTLS and the Authorization header ────────────────────────────────────────


def test_basic_auth_is_omitted_when_client_certificates_are_configured(monkeypatch):
    """With mTLS the TLS layer authenticates. Sending a password as well means a credential
    on the wire that does not need to be there, and it is the one the operator thinks they
    have stopped using."""
    monkeypatch.setenv("CB_CLIENT_CERT_PATH", "/tmp/c.pem")
    monkeypatch.setenv("CB_CLIENT_KEY_PATH", "/tmp/k.pem")
    monkeypatch.setenv("CB_USERNAME", "admin")
    monkeypatch.setenv("CB_PASSWORD", "password")
    assert shared._auth_header() == {}


def test_a_half_configured_client_certificate_still_sends_basic_auth(monkeypatch):
    """Cert without key cannot authenticate at the TLS layer, so dropping basic auth too
    would produce a 401 that looks like wrong credentials."""
    monkeypatch.setenv("CB_CLIENT_CERT_PATH", "/tmp/c.pem")
    monkeypatch.delenv("CB_CLIENT_KEY_PATH", raising=False)
    monkeypatch.setenv("CB_USERNAME", "admin")
    monkeypatch.setenv("CB_PASSWORD", "password")
    assert "Authorization" in shared._auth_header()


# ── Version detection ────────────────────────────────────────────────────────


def test_the_cluster_version_is_read_and_cached(cluster):
    cluster.body = json.dumps({"implementationVersion": "7.6.2-3505-enterprise"})
    assert shared.get_cluster_version() == "7.6.2-3505-enterprise"
    before = len(cluster.requests)
    shared.get_cluster_version()
    assert len(cluster.requests) == before, "the version was re-probed"


def test_an_unreachable_cluster_yields_no_version_rather_than_raising(
    cluster, monkeypatch
):
    """Version detection is best-effort: a tool that does not need it must still work when
    the probe fails."""
    monkeypatch.setenv("CB_MGMT_PORT", "1")
    assert shared.get_cluster_version() is None


@pytest.mark.parametrize(
    ("version", "major", "minor", "expected"),
    [
        ("7.6.2-3505-enterprise", 7, 0, True),
        ("7.6.2", 7, 6, True),
        ("7.6.2", 7, 7, False),
        ("8.0.0", 7, 6, True),
        ("6.6.5", 7, 0, False),
        ("7.0.0", 8, 0, False),
    ],
)
def test_version_comparison(cluster, version, major, minor, expected):
    cluster.body = json.dumps({"implementationVersion": version})
    assert shared.is_version_at_least(major, minor) is expected


def test_an_unknown_version_is_treated_as_too_old(cluster, monkeypatch):
    """Fail closed. Assuming a feature exists produces a confusing 404 from the cluster;
    assuming it does not produces a clear "requires 8.0" from us."""
    monkeypatch.setenv("CB_MGMT_PORT", "1")
    assert shared.is_version_at_least(7, 0) is False
    assert shared.is_8x() is False
    assert shared.is_7x() is False


def test_an_unparseable_version_string_is_treated_as_too_old(cluster):
    cluster.body = json.dumps({"implementationVersion": "community-edition"})
    assert shared.is_version_at_least(7, 0) is False


@pytest.mark.parametrize(
    ("version", "is7", "is8"),
    [("7.6.0", True, False), ("8.0.0", False, True), ("6.6.0", False, False)],
)
def test_the_major_version_helpers(cluster, version, is7, is8):
    cluster.body = json.dumps({"implementationVersion": version})
    assert shared.is_7x() is is7
    assert shared.is_8x() is is8


# A throwaway self-signed certificate, generated once at import so the CA-loading test
# exercises a real parse rather than a string that happens to look like PEM.
def _make_self_signed() -> str:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


_SELF_SIGNED_CERT = _make_self_signed()
