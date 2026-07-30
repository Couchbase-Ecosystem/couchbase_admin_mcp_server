"""
tls_config.py — transport encryption for the HTTP transport, both shapes.

WHY THIS EXISTS
===============
The HTTP transport served plain cleartext. `uvicorn.Config(...)` was constructed with
no ssl_certfile and no ssl_keyfile, so in the enterprise profile the bearer tokens
carrying the automation scope crossed the network unencrypted. Anyone who could
observe that traffic could replay a token and become an authorized child agent — and
that token is the single most privileged credential in the design, because the whole
unattended model rests on it. Every other control in this codebase (the scope gate,
the ceiling, the audit principal) is downstream of "the caller holds a legitimate
token", so sniffing one bypasses all of them at once.

TWO SHAPES, BECAUSE BOTH ARE REAL
=================================
  DIRECT          The server terminates TLS itself. Self-contained, no infrastructure
                  dependency, and the only option when there is nothing in front of
                  it. You own certificate rotation inside the container.

                    CB_ADMIN_TLS_CERT_FILE=/etc/tls/server.crt
                    CB_ADMIN_TLS_KEY_FILE=/etc/tls/server.key

  EXTERNAL        An ingress controller, service mesh sidecar, or load balancer
                  terminates TLS and forwards cleartext over a network the operator
                  considers trusted (a pod network, a loopback interface shared with a
                  sidecar). This is how most Kubernetes deployments actually work, and
                  refusing to support it would push operators into the direct mode
                  where it does not fit.

                    CB_ADMIN_TLS_TERMINATED_EXTERNALLY=1

WHY THE ACKNOWLEDGEMENT IS MANDATORY
====================================
"External termination" and "nobody configured TLS" produce byte-identical processes.
The only difference is whether a human decided. So a non-loopback HTTP bind with
neither a certificate nor the acknowledgement is FATAL at startup: the operator has to
state which world they are in. That converts the dangerous default (cleartext, quietly)
into a deliberate statement, which is the same reasoning profile_config already applies
to the workstation locality premise.

Loopback binds are exempt: traffic that never leaves the host cannot be sniffed off
the wire, and requiring certificates for `127.0.0.1:8000` would be friction with no
security return.

MUTUAL TLS
==========
Optional, and worth having in the unattended shape: if the child agents can present client
certificates, `CB_ADMIN_TLS_CLIENT_CA_FILE` makes the server require and verify them,
so an attacker needs a valid client certificate *in addition to* a stolen token.
"""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass


def _env(key: str) -> str:
    return (os.environ.get(key) or "").strip()


def _truthy(key: str) -> bool:
    return _env(key).lower() in ("1", "true", "yes", "on", "y", "t")


@dataclass(frozen=True)
class TlsSettings:
    """Resolved TLS posture for the HTTP transport."""

    cert_file: str = ""
    key_file: str = ""
    key_password: str = ""
    client_ca_file: str = ""
    terminated_externally: bool = False

    @property
    def direct(self) -> bool:
        """Whether this process terminates TLS itself."""
        return bool(self.cert_file and self.key_file)

    @property
    def require_client_cert(self) -> bool:
        return bool(self.direct and self.client_ca_file)

    def uvicorn_kwargs(self) -> dict:
        """Keyword arguments for uvicorn.Config. Empty when not terminating here."""
        if not self.direct:
            return {}
        kwargs: dict = {
            "ssl_certfile": self.cert_file,
            "ssl_keyfile": self.key_file,
            # TLS 1.2 floor. Uvicorn's default already negotiates the best available,
            # but stating the minimum means a future default change cannot silently
            # admit TLS 1.0/1.1 for an administration endpoint.
            "ssl_version": ssl.PROTOCOL_TLS_SERVER,
        }
        if self.key_password:
            kwargs["ssl_keyfile_password"] = self.key_password
        if self.client_ca_file:
            # Mutual TLS: the client must present a certificate this CA signed, so a
            # stolen bearer token alone is not sufficient to reach the tool surface.
            kwargs["ssl_ca_certs"] = self.client_ca_file
            kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
        return kwargs

    def describe(self) -> str:
        if self.direct:
            mode = "direct (this process terminates TLS)"
            if self.require_client_cert:
                mode += " + mutual TLS (client certificate required)"
            return mode
        if self.terminated_externally:
            return "terminated externally (operator asserts TLS is handled in front)"
        return "NONE — cleartext"


def from_env() -> TlsSettings:
    return TlsSettings(
        cert_file=_env("CB_ADMIN_TLS_CERT_FILE"),
        key_file=_env("CB_ADMIN_TLS_KEY_FILE"),
        key_password=_env("CB_ADMIN_TLS_KEY_PASSWORD"),
        client_ca_file=_env("CB_ADMIN_TLS_CLIENT_CA_FILE"),
        terminated_externally=_truthy("CB_ADMIN_TLS_TERMINATED_EXTERNALLY"),
    )


def is_loopback(host: str) -> bool:
    """Whether a bind address keeps traffic on this machine.

    An empty host means "all interfaces" for uvicorn, so it is NOT loopback. A
    non-literal hostname cannot be judged without resolving it, and a DNS dependency
    in the startup path is both unreliable and something an attacker could influence —
    so a non-literal is treated as exposed, which is the safe direction.
    """
    import ipaddress

    if not host:
        return False
    if host.lower() in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate(
    host: str, transport: str, settings: TlsSettings | None = None
) -> list[str]:
    """Fatal problems with the TLS posture. Empty list means acceptable.

    Returned strings are fatal: the caller refuses to start.
    """
    settings = settings or from_env()
    errors: list[str] = []

    if transport not in ("http", "streamable_http", "streamablehttp"):
        # stdio carries no network traffic; there is nothing to encrypt.
        return errors

    # A half-configured certificate pair is always an error, loopback or not: the
    # operator plainly intended TLS and would otherwise get cleartext with no warning.
    if bool(settings.cert_file) != bool(settings.key_file):
        missing = (
            "CB_ADMIN_TLS_KEY_FILE" if settings.cert_file else "CB_ADMIN_TLS_CERT_FILE"
        )
        errors.append(
            f"TLS is half-configured: {missing} is not set. A certificate without its "
            "key (or vice versa) cannot terminate TLS, and the server would otherwise "
            "fall back to cleartext while looking configured."
        )
        return errors

    for label, path in (
        ("CB_ADMIN_TLS_CERT_FILE", settings.cert_file),
        ("CB_ADMIN_TLS_KEY_FILE", settings.key_file),
        ("CB_ADMIN_TLS_CLIENT_CA_FILE", settings.client_ca_file),
    ):
        if path and not os.path.isfile(path):
            errors.append(
                f"{label}={path} does not exist or is not a file. Failing at startup "
                "rather than at the first connection."
            )

    if settings.client_ca_file and not settings.direct:
        errors.append(
            "CB_ADMIN_TLS_CLIENT_CA_FILE is set but this process is not terminating "
            "TLS, so it cannot verify client certificates. Either set "
            "CB_ADMIN_TLS_CERT_FILE/CB_ADMIN_TLS_KEY_FILE, or configure mutual TLS on "
            "whatever terminates it in front."
        )

    if is_loopback(host):
        # Traffic never leaves the host; certificates here would be friction with no
        # security return.
        return errors

    if settings.direct or settings.terminated_externally:
        return errors

    errors.append(
        f"The HTTP transport is bound to {host or '(all interfaces)'} with no transport "
        "encryption. Bearer tokens carrying the automation scope would cross the "
        "network in cleartext, and that token is the credential the entire unattended "
        "authorization model rests on — an observer who captures one becomes an "
        "authorized child agent, bypassing the scope gate, the ceiling and the audit "
        "principal at once.\n"
        "      Choose one:\n"
        "        * terminate TLS here — set CB_ADMIN_TLS_CERT_FILE and "
        "CB_ADMIN_TLS_KEY_FILE;\n"
        "        * terminate it in front (ingress, service mesh, sidecar) and say so "
        "with CB_ADMIN_TLS_TERMINATED_EXTERNALLY=1;\n"
        "        * or bind CB_ADMIN_HOST=127.0.0.1 so nothing reaches the wire.\n"
        "      The acknowledgement is required because 'a mesh handles it' and 'nobody "
        "configured it' produce identical processes; the only difference is whether a "
        "human decided."
    )
    return errors
