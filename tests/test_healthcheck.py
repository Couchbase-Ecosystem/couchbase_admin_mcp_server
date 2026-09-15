"""The container probe must call a refusal healthy and a wedge unhealthy.

MEASURED 2026-09-15, the first time the image was ever run over HTTP: the
Dockerfile's inline probe hit /mcp with no Authorization header, the enterprise
profile requires CB_ADMIN_HTTP_REQUIRE_AUTH=true, and the container therefore sat
at `health: starting` forever while answering 401 every thirty seconds. The
Kubernetes manifests probed /healthz, a route this server does not have.

These tests never bind a port. The seam is urlopen, so patching it keeps them out
of the `live` marker -- which matters, because `live` tests are excluded from the
mutation harnesses, and a control nothing can mutate is a control nothing checks.
"""

from __future__ import annotations

import urllib.error

import pytest

import healthcheck


@pytest.fixture(autouse=True)
def _http_transport(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "http")
    monkeypatch.setenv("CB_ADMIN_HOST", "127.0.0.1")
    monkeypatch.setenv("CB_ADMIN_PORT", "8000")


def _raise(exc):
    def _urlopen(*args, **kwargs):
        raise exc
    return _urlopen


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("http://x/mcp", code, "refused", {}, None)


@pytest.mark.parametrize("code", [400, 401, 403, 404, 405, 429])
def test_an_application_refusal_is_healthy(code, monkeypatch):
    """The process answered. For 401 it also proves the auth layer is engaged --
    and 401 is the NORMAL state of an enterprise deployment, not an error."""
    monkeypatch.setattr(healthcheck.urllib.request, "urlopen", _raise(_http_error(code)))
    exit_code, reason = healthcheck.check()
    assert exit_code == 0, reason


@pytest.mark.parametrize("code", [500, 502, 503])
def test_a_server_error_is_not_healthy(code, monkeypatch):
    """Tolerating everything would move the failure rather than remove it: a
    wedged process answering 500 must not read as healthy."""
    monkeypatch.setattr(healthcheck.urllib.request, "urlopen", _raise(_http_error(code)))
    exit_code, reason = healthcheck.check()
    assert exit_code == 1, reason


def test_nothing_listening_is_not_healthy(monkeypatch):
    monkeypatch.setattr(
        healthcheck.urllib.request, "urlopen",
        _raise(urllib.error.URLError("connection refused")),
    )
    exit_code, reason = healthcheck.check()
    assert exit_code == 1, reason


def test_a_stdio_deployment_has_nothing_to_probe(monkeypatch):
    """The image runs stdio by default and there is no socket to dial. The probe
    must not fail a container that is working exactly as configured."""
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "stdio")
    monkeypatch.setattr(
        healthcheck.urllib.request, "urlopen",
        _raise(AssertionError("stdio must not be probed over HTTP")),
    )
    exit_code, reason = healthcheck.check()
    assert exit_code == 0, reason


def test_a_wildcard_bind_is_probed_on_loopback(monkeypatch):
    """0.0.0.0 is a bind address, not a destination. The compose and k8s shapes
    both set it, so dialing it verbatim is the common case."""
    monkeypatch.setenv("CB_ADMIN_HOST", "0.0.0.0")
    assert healthcheck._endpoint() == "http://127.0.0.1:8000/mcp"


def test_the_probe_reads_the_configured_port(monkeypatch):
    """Premise for the test above -- a hardcoded 8000 would pass it vacuously."""
    monkeypatch.setenv("CB_ADMIN_PORT", "9001")
    assert healthcheck._endpoint().endswith(":9001/mcp")
