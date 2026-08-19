"""
Round-two findings: retry safety and misleading success states.

  F9   POST was retried on 5xx and on network errors. A create that SUCCEEDED and
       then lost its response to a 502 or a dropped connection was retried,
       producing a duplicate cluster or credential — billed, and invisible to the
       caller. Retries are now method-aware.
  F10  capella_env_ensure reported phase "ready" for a cluster with an empty IP
       allowlist. The environment really is provisioned and every connection to
       it is still refused, which surfaces as a timeout that looks like a
       credential or DNS fault.
  F11  A requested scope was skipped silently when the bucket had no id yet, so
       "ready" was reported without the requested keyspace layout.
"""

from __future__ import annotations

import json
import urllib.error

import pytest

from handlers.capella import client, environment

# ── F9: method-aware retry ───────────────────────────────────────────────────


def test_f9_post_is_not_retried_on_server_error():
    """The core of the finding: repeating a create can duplicate a resource."""
    assert client._retryable(500, "POST") is False
    assert client._retryable(502, "POST") is False
    assert client._retryable(503, "POST") is False
    assert client._retryable(504, "POST") is False


def test_f9_post_is_retried_when_the_request_was_provably_not_processed():
    """429/408/425 mean the server rejected or never began the request, so no
    resource can have been created. Retrying is safe and desirable."""
    assert client._retryable(429, "POST") is True
    assert client._retryable(408, "POST") is True
    assert client._retryable(425, "POST") is True


def test_f9_idempotent_methods_still_retry_on_server_error():
    """Not retrying reads and idempotent writes would make the client fragile for
    no safety benefit."""
    for method in ("GET", "PUT", "DELETE", "HEAD"):
        assert client._retryable(503, method) is True, method


def test_f9_permanent_statuses_are_never_retried():
    for status in (400, 401, 403, 404, 409, 422):
        for method in ("GET", "POST", "DELETE"):
            assert client._retryable(status, method) is False


def _http_error(status: int):
    return urllib.error.HTTPError(
        url="https://cloudapi.cloud.couchbase.com/v4/x",
        code=status,
        msg="boom",
        hdrs=None,
        fp=None,
    )


def test_f9_post_makes_exactly_one_attempt_on_500(monkeypatch):
    """Behavioural proof, not just the predicate: only ONE request goes out."""
    attempts = []

    def fake_urlopen(req, timeout=None, context=None):
        attempts.append(req.get_method())
        raise _http_error(500)

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("CAPELLA_API_KEY_SECRET", "secret")
    monkeypatch.setenv("CAPELLA_HTTP_RETRIES", "3")

    with pytest.raises(client.CapellaError) as excinfo:
        client.capella_request(
            "POST", "/v4/organizations/o/projects/p/clusters", body={"name": "x"}
        )

    assert len(attempts) == 1, f"POST was retried {len(attempts)} times on a 500"
    assert "duplicate" in excinfo.value.hint.lower()


def test_f9_delete_retries_up_to_the_limit_on_500(monkeypatch):
    attempts = []

    def fake_urlopen(req, timeout=None, context=None):
        attempts.append(req.get_method())
        raise _http_error(503)

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(client.time, "sleep", lambda _s: None)
    monkeypatch.setenv("CAPELLA_API_KEY_SECRET", "secret")
    monkeypatch.setenv("CAPELLA_HTTP_RETRIES", "3")

    with pytest.raises(client.CapellaError):
        client.capella_request("DELETE", "/v4/organizations/o/projects/p/clusters/c")

    assert len(attempts) == 3


def test_f9_post_is_not_retried_on_a_dropped_connection(monkeypatch):
    """A dropped connection cannot be distinguished from "applied, reply lost"."""
    attempts = []

    def fake_urlopen(req, timeout=None, context=None):
        attempts.append(req.get_method())
        raise urllib.error.URLError("connection reset")

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(client.time, "sleep", lambda _s: None)
    monkeypatch.setenv("CAPELLA_API_KEY_SECRET", "secret")
    monkeypatch.setenv("CAPELLA_HTTP_RETRIES", "3")

    with pytest.raises(client.CapellaError) as excinfo:
        client.capella_request("POST", "/v4/x", body={"name": "x"})

    assert len(attempts) == 1
    assert "not retried" in excinfo.value.hint.lower()


def test_f9_get_is_retried_on_a_dropped_connection(monkeypatch):
    attempts = []

    def fake_urlopen(req, timeout=None, context=None):
        attempts.append(req.get_method())
        raise urllib.error.URLError("temporary dns failure")

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(client.time, "sleep", lambda _s: None)
    monkeypatch.setenv("CAPELLA_API_KEY_SECRET", "secret")
    monkeypatch.setenv("CAPELLA_HTTP_RETRIES", "2")

    with pytest.raises(client.CapellaError):
        client.capella_request("GET", "/v4/x")

    assert len(attempts) == 2


def test_f9_api_key_secret_never_appears_in_an_error(monkeypatch):
    """The Bearer token is a header; it must not leak through an exception."""

    def fake_urlopen(req, timeout=None, context=None):
        raise _http_error(403)

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("CAPELLA_API_KEY_SECRET", "super-secret-token-value")

    with pytest.raises(client.CapellaError) as excinfo:
        client.capella_request("GET", "/v4/x")

    blob = str(excinfo.value) + excinfo.value.hint
    assert "super-secret-token-value" not in blob


# ── F10 / F11: misleading success states in the reconciler ───────────────────


class MiniCapella:
    """Enough of v4 for the reconciler to reach 'ready' in one pass."""

    def __init__(self, with_cidr: bool = False, bucket_gets_id: bool = True):
        self.cidrs = [{"id": "x", "cidr": "10.0.0.0/8"}] if with_cidr else []
        self.buckets: list[dict] = []
        self.creds: list[dict] = []
        self.scopes: list[dict] = []
        self.bucket_gets_id = bucket_gets_id

    def request(self, method, path, *, params=None, body=None):
        if path.endswith("/allowedcidrs") and method == "POST":
            self.cidrs.append({"id": "n", "cidr": body["cidr"]})
        elif path.endswith("/buckets") and method == "POST":
            # bucket_gets_id=False models an import still settling: the bucket is
            # listed but carries no usable id yet.
            self.buckets.append(
                {"id": "b1", "name": body["name"]}
                if self.bucket_gets_id
                else {"name": body["name"]}
            )
        elif path.endswith("/users") and method == "POST":
            self.creds.append({"id": "u1", "name": body["name"]})
        elif path.endswith("/scopes") and method == "POST":
            self.scopes.append({"name": body["name"]})
        return {"status": "ok"}

    def listing(self, path, *, params=None, page_size=None, max_items=None):
        if path.endswith("/clusters"):
            data = [
                {
                    "id": "c1",
                    "name": "mcptest-env1",
                    "description": "mcp-env:{}",
                    "currentState": "healthy",
                    "connectionString": "couchbases://cb.c1.cloud.couchbase.com",
                }
            ]
        elif path.endswith("/allowedcidrs"):
            data = self.cidrs
        elif path.endswith("/buckets"):
            data = self.buckets
        elif path.endswith("/users"):
            data = self.creds
        elif path.endswith("/scopes"):
            data = self.scopes
        elif path.endswith("/appservices"):
            data = []
        else:
            data = []
        return {"data": data, "itemCount": len(data), "truncated": False}


@pytest.fixture
def mini(monkeypatch):
    monkeypatch.setenv("CAPELLA_ORG_ID", "org-1")
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    monkeypatch.delenv("CAPELLA_MAX_ENVIRONMENTS", raising=False)

    def install(api):
        monkeypatch.setattr(environment, "capella_request", api.request)
        monkeypatch.setattr(environment, "capella_list", api.listing)
        return api

    return install


def _ensure(**kwargs):
    payload = {"env_name": "env1", "project_id": "test-proj", **kwargs}
    return json.loads(environment.handle("capella_env_ensure", payload)[0].text)


def test_f10_ready_without_an_allowlist_carries_a_warning(mini):
    mini(MiniCapella(with_cidr=False))
    result = _ensure()
    assert result["phase"] == "ready"
    assert "warning_allowlist" in result
    assert "refuse every client connection" in result["warning_allowlist"]


def test_f10_no_warning_once_a_cidr_is_supplied(mini):
    mini(MiniCapella(with_cidr=False))
    result = _ensure(allowed_cidrs=["203.0.113.4/32"])
    assert result["phase"] == "ready"
    assert "warning_allowlist" not in result


def test_f10_no_warning_when_the_cluster_already_had_an_entry(mini):
    mini(MiniCapella(with_cidr=True))
    result = _ensure()
    assert result["phase"] == "ready"
    assert "warning_allowlist" not in result


def test_f10_internal_marker_does_not_leak_into_the_result(mini):
    mini(MiniCapella(with_cidr=True))
    result = _ensure()
    assert "_allowlist_present" not in result


def test_f11_requested_scope_that_cannot_be_created_is_not_reported_ready(mini):
    """Previously this returned phase 'ready' with the scope silently absent."""
    mini(MiniCapella(with_cidr=True, bucket_gets_id=False))
    result = _ensure(scope_name="orders", collection_name="line_items")
    assert result["done"] is False
    assert result["phase"] == "configuring"
    assert "orders" in result["error"]


def test_f11_scope_is_created_when_the_bucket_has_an_id(mini):
    api = mini(MiniCapella(with_cidr=True, bucket_gets_id=True))
    result = _ensure(scope_name="orders")
    assert result["phase"] == "ready"
    assert result["scope"] == "orders"
    assert [s["name"] for s in api.scopes] == ["orders"]
