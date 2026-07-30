"""
Transport encryption for the HTTP transport.

WHY THIS MATTERS MORE THAN IT LOOKS
===================================
uvicorn.Config was constructed with no ssl_certfile and no ssl_keyfile, so the
enterprise transport was cleartext. The bearer tokens it carries hold the automation
scope, and that token is the credential the whole unattended model rests on: the scope
gate, the hard ceiling and the audit principal are all downstream of "the caller holds
a legitimate token". An observer who captures one becomes an authorized child agent and
bypasses every one of them at once.

Two shapes are supported because both are real — the server terminating TLS itself, and
an ingress or service mesh terminating it in front. The acknowledgement for the second
is mandatory, because "a mesh handles it" and "nobody configured it" produce identical
processes and the only difference is whether a human decided.

The live test at the bottom completes a REAL handshake. uvicorn's ssl_* arguments have
moved across releases, and a config object that merely constructs is not evidence that
a client can connect.
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import subprocess
import sys
import time

import pytest

import tls_config

HTTP = "http"


# ── The posture matrix ───────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_tls_env(monkeypatch):
    for key in (
        "CB_ADMIN_TLS_CERT_FILE",
        "CB_ADMIN_TLS_KEY_FILE",
        "CB_ADMIN_TLS_KEY_PASSWORD",
        "CB_ADMIN_TLS_CLIENT_CA_FILE",
        "CB_ADMIN_TLS_TERMINATED_EXTERNALLY",
    ):
        monkeypatch.delenv(key, raising=False)


def test_stdio_needs_no_tls():
    """There is no socket, so there is nothing to encrypt."""
    assert tls_config.validate("0.0.0.0", "stdio") == []


def test_loopback_needs_no_tls():
    """Traffic that never leaves the host cannot be sniffed off the wire, and demanding
    certificates for 127.0.0.1 would be friction with no security return."""
    assert tls_config.validate("127.0.0.1", HTTP) == []
    assert tls_config.validate("localhost", HTTP) == []
    assert tls_config.validate("::1", HTTP) == []


def test_a_non_loopback_bind_with_no_tls_is_fatal():
    """The finding itself: cleartext bearer tokens on the network."""
    errors = tls_config.validate("0.0.0.0", HTTP)
    assert errors, "an exposed cleartext bind was accepted"
    assert "cleartext" in errors[0]
    # The message must name all three ways out, or the operator has to guess.
    assert "CB_ADMIN_TLS_CERT_FILE" in errors[0]
    assert "CB_ADMIN_TLS_TERMINATED_EXTERNALLY" in errors[0]
    assert "127.0.0.1" in errors[0]


def test_an_empty_host_counts_as_exposed():
    """uvicorn treats an empty host as all interfaces."""
    assert tls_config.validate("", HTTP)


def test_a_hostname_counts_as_exposed():
    """A non-literal cannot be judged without a DNS lookup, and resolving in the startup
    path is both unreliable and attacker-influenceable. Exposed is the safe direction."""
    assert tls_config.validate("cb-mcp.corp.example", HTTP)


def test_the_external_termination_acknowledgement_is_accepted(monkeypatch):
    """Most Kubernetes deployments terminate at the ingress. Refusing to support that
    would push operators into the direct mode where it does not fit."""
    monkeypatch.setenv("CB_ADMIN_TLS_TERMINATED_EXTERNALLY", "1")
    assert tls_config.validate("0.0.0.0", HTTP) == []
    assert "terminated externally" in tls_config.from_env().describe()


def test_a_certificate_pair_is_accepted(tmp_path, monkeypatch):
    cert = tmp_path / "s.crt"
    key = tmp_path / "s.key"
    cert.write_text("x")
    key.write_text("x")
    monkeypatch.setenv("CB_ADMIN_TLS_CERT_FILE", str(cert))
    monkeypatch.setenv("CB_ADMIN_TLS_KEY_FILE", str(key))
    assert tls_config.validate("0.0.0.0", HTTP) == []
    settings = tls_config.from_env()
    assert settings.direct
    assert settings.uvicorn_kwargs()["ssl_certfile"] == str(cert)


@pytest.mark.parametrize("present", ["CB_ADMIN_TLS_CERT_FILE", "CB_ADMIN_TLS_KEY_FILE"])
def test_a_half_configured_pair_is_fatal_even_on_loopback(
    present, tmp_path, monkeypatch
):
    """A certificate without its key cannot terminate TLS, and the server would
    otherwise fall back to cleartext while LOOKING configured — which is worse than
    being plainly unconfigured. Fatal on loopback too, because the operator's intent is
    unambiguous."""
    path = tmp_path / "half"
    path.write_text("x")
    monkeypatch.setenv(present, str(path))
    errors = tls_config.validate("127.0.0.1", HTTP)
    assert errors
    assert "half-configured" in errors[0]


def test_a_missing_certificate_file_is_fatal(monkeypatch):
    """Fail at startup, not at the first connection."""
    monkeypatch.setenv("CB_ADMIN_TLS_CERT_FILE", "/nonexistent/s.crt")
    monkeypatch.setenv("CB_ADMIN_TLS_KEY_FILE", "/nonexistent/s.key")
    errors = tls_config.validate("0.0.0.0", HTTP)
    assert len(errors) == 2, errors
    assert all("does not exist" in e for e in errors)


def test_a_client_ca_without_a_server_certificate_is_fatal(tmp_path, monkeypatch):
    """mTLS cannot be enforced by a process that is not terminating TLS."""
    ca = tmp_path / "ca.crt"
    ca.write_text("x")
    monkeypatch.setenv("CB_ADMIN_TLS_CLIENT_CA_FILE", str(ca))
    monkeypatch.setenv("CB_ADMIN_TLS_TERMINATED_EXTERNALLY", "1")
    errors = tls_config.validate("0.0.0.0", HTTP)
    assert errors
    assert "cannot verify client certificates" in errors[0]


def test_mutual_tls_sets_cert_required(tmp_path, monkeypatch):
    for name in ("s.crt", "s.key", "ca.crt"):
        (tmp_path / name).write_text("x")
    monkeypatch.setenv("CB_ADMIN_TLS_CERT_FILE", str(tmp_path / "s.crt"))
    monkeypatch.setenv("CB_ADMIN_TLS_KEY_FILE", str(tmp_path / "s.key"))
    monkeypatch.setenv("CB_ADMIN_TLS_CLIENT_CA_FILE", str(tmp_path / "ca.crt"))

    settings = tls_config.from_env()
    assert settings.require_client_cert
    kwargs = settings.uvicorn_kwargs()
    assert kwargs["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert kwargs["ssl_ca_certs"] == str(tmp_path / "ca.crt")
    assert "mutual TLS" in settings.describe()


def test_no_tls_means_no_uvicorn_ssl_arguments():
    """An unset posture must not pass ssl_* arguments at all; passing None to some
    uvicorn versions is an error rather than a no-op."""
    assert tls_config.from_env().uvicorn_kwargs() == {}


def test_the_server_refuses_to_start_on_an_exposed_cleartext_bind(monkeypatch):
    """The validation is wired into the startup path, not merely available.

    This is the composition, which is what the earlier rounds kept leaving uncovered.
    """
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "http")
    monkeypatch.setenv("CB_ADMIN_HOST", "0.0.0.0")
    monkeypatch.setenv("CB_ADMIN_WORKSTATION_CONTAINER_BIND", "1")
    monkeypatch.delenv("CB_ADMIN_AUDIT_FILE", raising=False)

    import importlib

    import profile_config
    import server

    importlib.reload(profile_config)
    importlib.reload(server)
    with pytest.raises(SystemExit) as excinfo:
        server._enforce_profile()
    assert excinfo.value.code == 2


# ── A real handshake ─────────────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    """A throwaway CA, server certificate and client certificate."""
    pytest.importorskip("cryptography")
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    d = tmp_path_factory.mktemp("tls")

    def build(cn, ca_key=None, ca_cert=None, is_ca=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_cert.subject if ca_cert else name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
        )
        if is_ca:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
        else:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
        return key, builder.sign(ca_key or key, hashes.SHA256())

    def write(stem, key, cert):
        (d / f"{stem}.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        (d / f"{stem}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    ca_key, ca_cert = build("test-ca", is_ca=True)
    write("ca", ca_key, ca_cert)
    write("server", *build("localhost", ca_key, ca_cert))
    write("client", *build("child-agent", ca_key, ca_cert))
    return d


def _boot(extra_env, port, root):
    env = {
        "PATH": os.environ["PATH"],
        "PYTHONPATH": str(root),
        "CB_ADMIN_PROFILE": "workstation",
        "CB_ADMIN_TRANSPORT": "http",
        "CB_ADMIN_HOST": "127.0.0.1",
        "CB_ADMIN_PORT": str(port),
        "CB_ADMIN_READ_ONLY_MODE": "true",
        "CB_ADMIN_LOG_SINKS": "stderr",
        "CB_CONNECTION_STRING": "couchbase://localhost",
        "CB_USERNAME": "u",
        "CB_PASSWORD": "p",
        **extra_env,
    }
    proc = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=str(root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for _ in range(80):
        time.sleep(0.25)
        if proc.poll() is not None:
            break
        with socket.socket() as sock:
            sock.settimeout(0.3)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return proc
    proc.kill()
    pytest.fail(f"server did not start: {proc.communicate()[1][-500:]}")


@pytest.mark.live
def test_a_real_client_completes_a_tls_handshake(certs):
    """The listener really is TLS: a verifying client connects, a cleartext client
    cannot, and an untrusting client rejects the chain (so the certificate is genuinely
    presented rather than the test passing on a plain socket)."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    port = _free_port()
    proc = _boot(
        {
            "CB_ADMIN_TLS_CERT_FILE": str(certs / "server.crt"),
            "CB_ADMIN_TLS_KEY_FILE": str(certs / "server.key"),
        },
        port,
        root,
    )
    try:
        ctx = ssl.create_default_context(cafile=str(certs / "ca.crt"))
        conn = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=15)
        conn.request("GET", "/mcp")
        conn.getresponse()  # any HTTP status proves the handshake completed
        assert conn.sock.version().startswith("TLSv1."), conn.sock.version()
        conn.close()

        # A cleartext client must fail, which is what proves the listener is TLS and
        # not a plain socket that happens to answer.
        with pytest.raises((OSError, http.client.HTTPException)):
            plain = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            plain.request("GET", "/mcp")
            plain.getresponse()

        with pytest.raises(ssl.SSLCertVerificationError):
            strict = http.client.HTTPSConnection(
                "localhost", port, context=ssl.create_default_context(), timeout=5
            )
            strict.request("GET", "/mcp")
            strict.getresponse()
    finally:
        proc.terminate()
        proc.communicate(timeout=15)


@pytest.mark.live
def test_mutual_tls_refuses_a_client_with_no_certificate(certs):
    """With CB_ADMIN_TLS_CLIENT_CA_FILE set, a stolen bearer token is not sufficient —
    the caller also needs a client certificate this CA signed."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    port = _free_port()
    proc = _boot(
        {
            "CB_ADMIN_TLS_CERT_FILE": str(certs / "server.crt"),
            "CB_ADMIN_TLS_KEY_FILE": str(certs / "server.key"),
            "CB_ADMIN_TLS_CLIENT_CA_FILE": str(certs / "ca.crt"),
        },
        port,
        root,
    )
    try:
        ctx = ssl.create_default_context(cafile=str(certs / "ca.crt"))
        ctx.load_cert_chain(str(certs / "client.crt"), str(certs / "client.key"))
        conn = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=15)
        conn.request("GET", "/mcp")
        conn.getresponse()
        conn.close()

        # Without a client certificate the handshake itself must fail.
        with pytest.raises((ssl.SSLError, OSError, http.client.HTTPException)):
            bare = ssl.create_default_context(cafile=str(certs / "ca.crt"))
            c = http.client.HTTPSConnection("localhost", port, context=bare, timeout=5)
            c.request("GET", "/mcp")
            c.getresponse()
    finally:
        proc.terminate()
        proc.communicate(timeout=15)
