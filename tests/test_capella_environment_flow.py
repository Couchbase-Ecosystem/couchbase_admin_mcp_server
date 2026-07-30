"""
Functional tests for the environment reconciler, against an in-memory fake
Capella.

What these are really testing is the two properties that cannot be checked by
inspection:

  * CONVERGENCE — capella_env_ensure must be safe to call repeatedly and must
    make progress each time, without duplicating resources. A reconciler that
    creates a second cluster on the second call is worse than useless in CI.
  * ORDERING — teardown must delete the App Service before the cluster, because
    Capella refuses the cluster delete while one is attached. Getting this wrong
    produces a stuck environment that bills until someone notices.

The fake models the one behaviour that makes this hard: cluster and App Service
creation are asynchronous, so a freshly created resource is not usable yet.
"""

from __future__ import annotations

import json

import pytest

from handlers.capella import environment


class FakeCapella:
    """Minimal in-memory v4, keyed by path, with asynchronous state transitions.

    ``ticks_to_healthy`` models deployment latency: each GET on a deploying
    resource advances it, so a test can drive the reconciler through its phases
    the same way a poll loop would.
    """

    def __init__(self, ticks_to_healthy: int = 1):
        self.clusters: dict[str, dict] = {}
        self.app_services: dict[str, dict] = {}
        self.buckets: dict[str, dict] = {}
        self.credentials: dict[str, dict] = {}
        self.cidrs: list[dict] = []
        self.app_endpoints: dict[str, dict] = {}
        self.endpoint_online: set[str] = set()
        self.ticks_to_healthy = ticks_to_healthy
        self.calls: list[tuple[str, str]] = []
        self._seq = 0

    def _only_cluster_id(self) -> str:
        """The cluster in this fake, so an App Service can name its owner."""
        return next(iter(self.clusters), "cluster-unknown")

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{self._seq}"

    def _advance(self, resource: dict) -> None:
        if resource.get("_ticks", 0) > 0:
            resource["_ticks"] -= 1
            if resource["_ticks"] == 0:
                resource["currentState"] = "healthy"

    def request(self, method, path, *, params=None, body=None):
        self.calls.append((method, path))
        parts = [p for p in path.split("/") if p]

        # ---- collection endpoints -------------------------------------------
        if path.endswith("/clusters"):
            if method == "POST":
                cid = self._next_id("cluster")
                self.clusters[cid] = {
                    "id": cid,
                    "name": body["name"],
                    "description": body.get("description", ""),
                    "currentState": "deploying",
                    "connectionString": f"couchbases://cb.{cid}.cloud.couchbase.com",
                    "_ticks": self.ticks_to_healthy,
                }
                return {"id": cid}
            for cluster in self.clusters.values():
                self._advance(cluster)
            return {
                "data": list(self.clusters.values()),
                "cursor": {"pages": {"page": 1, "last": 1}},
            }

        if path.endswith("/appservices") or "/appservices?" in path:
            # Two DIFFERENT routes share this suffix, and the real API treats them very
            # differently:
            #
            #   POST /organizations/{o}/projects/{p}/clusters/{c}/appservices   create
            #   GET  /organizations/{o}/appservices                             list, ORG-WIDE
            #
            # A GET against the cluster-scoped path returns 405 in the real API — that is
            # what a live run found, and because a 405 body yields no id the reconciler
            # read it as "no App Service exists" and looped forever creating one. The fake
            # mirrors the real behaviour so the test can catch that class of bug.
            if method == "POST":
                if "/clusters/" not in path:
                    return {"__status__": 405, "message": "method not allowed"}
                sid = self._next_id("appsvc")
                self.app_services[sid] = {
                    "id": sid,
                    "name": body["name"],
                    "description": body.get("description", ""),
                    "currentState": "deploying",
                    "hostname": f"{sid}.apps.cloud.couchbase.com",
                    # The org-wide list is the only list, so each item must say which
                    # cluster it belongs to or a caller cannot narrow it.
                    "clusterId": self._only_cluster_id(),
                    "_ticks": self.ticks_to_healthy,
                }
                return {"id": sid}
            if "/clusters/" in path:
                raise AssertionError(
                    "GET on the cluster-scoped /appservices path: the real API answers "
                    "405 there, App Services are listed organization-wide"
                )
            for svc in self.app_services.values():
                self._advance(svc)
            return {
                "data": list(self.app_services.values()),
                "cursor": {"pages": {"page": 1, "last": 1}},
            }

        if path.endswith("/buckets"):
            if method == "POST":
                bid = self._next_id("bucket")
                self.buckets[bid] = {"id": bid, "name": body["name"]}
                return {"id": bid}
            return {
                "data": list(self.buckets.values()),
                "cursor": {"pages": {"page": 1, "last": 1}},
            }

        if path.endswith("/users"):
            if method == "POST":
                uid = self._next_id("cred")
                self.credentials[uid] = {"id": uid, "name": body["name"]}
                return {"id": uid, "password": body.get("password", "generated")}
            return {
                "data": list(self.credentials.values()),
                "cursor": {"pages": {"page": 1, "last": 1}},
            }

        if path.endswith("/allowedcidrs"):
            if method == "POST":
                entry = {"id": self._next_id("cidr"), "cidr": body["cidr"]}
                self.cidrs.append(entry)
                return entry
            return {
                "data": list(self.cidrs),
                "cursor": {"pages": {"page": 1, "last": 1}},
            }

        if path.endswith("/appEndpoints"):
            if method == "POST":
                self.app_endpoints[body["name"]] = {
                    "name": body["name"],
                    "bucket": body["bucket"],
                }
                return {"name": body["name"]}
            return {
                "data": list(self.app_endpoints.values()),
                "cursor": {"pages": {"page": 1, "last": 1}},
            }

        if path.endswith("/activationStatus"):
            name = parts[-2]
            if method == "POST":
                self.endpoint_online.add(name)
            else:
                self.endpoint_online.discard(name)
            return {"status": "ok"}

        if path.endswith("/activationState"):
            cid = parts[-2]
            cluster = self.clusters.get(cid)
            if cluster is not None:
                cluster["currentState"] = (
                    "turningOn" if method == "POST" else "turningOff"
                )
                cluster["_ticks"] = self.ticks_to_healthy
            return {"status": "ok"}

        # ---- single-resource endpoints --------------------------------------
        if "/appservices/" in path and method == "DELETE":
            self.app_services.pop(parts[-1], None)
            return {"status": "ok"}

        if "/clusters/" in path and parts[-2] == "clusters":
            cid = parts[-1]
            if method == "DELETE":
                if self.app_services:
                    # Capella's real behaviour: refuses while an App Service exists.
                    raise AssertionError(
                        "cluster delete attempted while an App Service is still attached"
                    )
                self.clusters.pop(cid, None)
                return {"status": "ok"}
            cluster = self.clusters.get(cid)
            if cluster:
                self._advance(cluster)
                return cluster

        return {"status": "ok"}


@pytest.fixture
def fake(monkeypatch):
    api = FakeCapella()

    def request(method, path, *, params=None, body=None):
        return api.request(method, path, params=params, body=body)

    def listing(path, *, params=None, page_size=None, max_items=None):
        result = api.request("GET", path, params={"page": 1})
        if isinstance(result, dict) and "data" in result:
            return {
                "data": result["data"],
                "itemCount": len(result["data"]),
                "totalItems": len(result["data"]),
                "pagesFetched": 1,
                "truncated": False,
            }
        return result

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)
    monkeypatch.setenv("CAPELLA_ORG_ID", "org-1")
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    monkeypatch.setenv("CAPELLA_ENV_TTL_HOURS", "4")
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "5")
    return api


def _ensure(**kwargs):
    payload = {"env_name": "ios-4821", "project_id": "test-proj", **kwargs}
    return json.loads(environment.handle("capella_env_ensure", payload)[0].text)


# ── Convergence ──────────────────────────────────────────────────────────────


def test_first_call_creates_the_cluster_and_reports_a_retry_hint(fake):
    result = _ensure()
    assert result["phase"] == "creating_cluster"
    assert result["done"] is False
    assert result["retry_after_s"] > 0
    assert len(fake.clusters) == 1


def test_cluster_name_gets_the_configured_prefix(fake):
    _ensure()
    assert next(iter(fake.clusters.values()))["name"] == "mcptest-ios-4821"


def test_repeated_calls_do_not_create_a_second_cluster(fake):
    _ensure()
    _ensure()
    _ensure()
    assert len(fake.clusters) == 1, "reconciler duplicated the cluster"


def test_converges_to_ready_without_app_services(fake):
    phases = []
    for _ in range(6):
        result = _ensure(allowed_cidrs=["203.0.113.4/32"])
        phases.append(result["phase"])
        if result["done"]:
            break
    assert phases[-1] == "ready", phases
    assert len(fake.buckets) == 1
    assert len(fake.credentials) == 1
    assert [c["cidr"] for c in fake.cidrs] == ["203.0.113.4/32"]


def test_password_is_returned_once_then_reported_unavailable(fake):
    """Capella cannot return a password twice, so the second call must say so
    rather than emit a blank that looks like a value."""
    created_password = None
    for _ in range(6):
        result = _ensure()
        cred = result.get("credential")
        if cred and cred.get("password"):
            created_password = cred["password"]
            break
    assert created_password, "password was never surfaced at creation"

    # Converged environment, called again: no password, and an explanation.
    result = _ensure()
    assert result["credential"]["password"] is None
    assert "does not allow reading" in result["credential"]["password_note"].lower()


def test_app_services_path_creates_service_then_endpoint_then_brings_it_online(fake):
    phases = []
    for _ in range(10):
        result = _ensure(app_services=True, app_service_cidrs=["203.0.113.0/24"])
        phases.append(result["phase"])
        if result["done"]:
            break

    assert phases[-1] == "ready", phases
    assert "creating_app_service" in phases
    assert len(fake.app_services) == 1
    assert len(fake.app_endpoints) == 1
    # An endpoint that is never brought online accepts no replication, which
    # presents to a mobile client as an auth failure.
    assert fake.endpoint_online, "app endpoint was left offline"
    assert result["couchbase_lite_url"].startswith("wss://")


def test_ready_result_carries_what_a_client_needs(fake):
    for _ in range(6):
        result = _ensure(allowed_cidrs=["10.0.0.0/8"])
        if result["done"]:
            break
    assert result["connection_string"].startswith("couchbases://")
    assert result["bucket"] == "testdata"
    assert result["credential"]["name"] == "testapp"


def test_sample_bucket_is_used_instead_of_creating_an_empty_one(fake):
    for _ in range(6):
        result = _ensure(sample_bucket="travel-sample")
        if result["done"]:
            break
    assert result["bucket"] == "travel-sample"


def test_marker_is_written_so_the_environment_is_reapable(fake):
    from handlers.capella import guardrails

    _ensure(ttl_hours=2, owner="ci-pipeline")
    cluster = next(iter(fake.clusters.values()))
    marker = guardrails.parse_marker(cluster["description"])
    assert marker["env"] == "ios-4821"
    assert marker["ttl_h"] == 2
    assert marker["owner"] == "ci-pipeline"


def test_ceiling_refuses_a_new_environment(fake, monkeypatch):
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "1")
    _ensure()  # first environment
    payload = json.loads(
        environment.handle(
            "capella_env_ensure", {"env_name": "ios-second", "project_id": "test-proj"}
        )[0].text
    )
    assert payload.get("guardrail") is True
    assert "ceiling" in payload["error"].lower()


def test_ensure_refuses_a_project_outside_the_allowlist(fake):
    payload = json.loads(
        environment.handle(
            "capella_env_ensure", {"env_name": "x", "project_id": "production"}
        )[0].text
    )
    assert payload.get("guardrail") is True
    assert len(fake.clusters) == 0, "a refused call must not have created anything"


# ── Ordering on teardown ─────────────────────────────────────────────────────


def _teardown():
    return json.loads(
        environment.handle(
            "capella_env_teardown", {"env_name": "ios-4821", "project_id": "test-proj"}
        )[0].text
    )


def test_teardown_deletes_the_app_service_before_the_cluster(fake):
    for _ in range(10):
        if _ensure(app_services=True)["done"]:
            break
    assert fake.app_services and fake.clusters

    first = _teardown()
    assert first["result"] == "app_service_deleting"
    assert not fake.app_services
    assert fake.clusters, "cluster must survive the first teardown pass"

    # The fake raises if the ordering is violated, so reaching here proves it.
    second = _teardown()
    assert second["result"] == "cluster_deleting"
    assert not fake.clusters


def test_teardown_of_a_cluster_without_app_services_is_one_pass(fake):
    for _ in range(6):
        if _ensure()["done"]:
            break
    result = _teardown()
    assert result["result"] == "cluster_deleting"
    assert not fake.clusters


def test_teardown_is_idempotent_when_nothing_is_left(fake):
    assert _teardown()["result"] == "nothing_to_do"


def test_teardown_refuses_an_unprefixed_cluster(fake):
    """Simulates a hand-made production cluster inside the test project."""
    fake.clusters["prod-1"] = {
        "id": "prod-1",
        "name": "acme-prod",
        "description": "real cluster",
        "currentState": "healthy",
    }
    payload = json.loads(
        environment.handle(
            "capella_env_teardown",
            {"env_name": "acme-prod", "project_id": "test-proj"},
        )[0].text
    )
    assert payload.get("guardrail") is True
    assert "prod-1" in fake.clusters


# ── Park and resume ──────────────────────────────────────────────────────────


def test_park_turns_the_cluster_off(fake):
    for _ in range(6):
        if _ensure()["done"]:
            break
    payload = json.loads(
        environment.handle(
            "capella_env_park", {"env_name": "ios-4821", "project_id": "test-proj"}
        )[0].text
    )
    assert payload["state"] == "turning_off"
    assert next(iter(fake.clusters.values()))["currentState"] == "turningOff"


def test_resume_turns_the_linked_app_service_on_too(fake):
    """A live cluster behind a dead sync endpoint looks like a broken app."""
    for _ in range(6):
        if _ensure()["done"]:
            break
    environment.handle(
        "capella_env_park", {"env_name": "ios-4821", "project_id": "test-proj"}
    )
    environment.handle(
        "capella_env_resume", {"env_name": "ios-4821", "project_id": "test-proj"}
    )

    activation_bodies = [c for c in fake.calls if c[1].endswith("/activationState")]
    assert ("POST", activation_bodies[-1][1]) == activation_bodies[-1]


# ── Reaping ──────────────────────────────────────────────────────────────────


def test_reap_defaults_to_a_dry_run(fake):
    for _ in range(6):
        if _ensure(ttl_hours=0)["done"]:
            break
    payload = json.loads(
        environment.handle("capella_env_reap", {"project_id": "test-proj"})[0].text
    )
    assert payload["dry_run"] is True
    assert fake.clusters, "a dry run must not delete anything"


def test_reap_ignores_a_pinned_environment(fake):
    """ttl_hours=0 means never expire; the reaper must leave it alone."""
    for _ in range(6):
        if _ensure(ttl_hours=0)["done"]:
            break
    payload = json.loads(
        environment.handle(
            "capella_env_reap", {"project_id": "test-proj", "dry_run": False}
        )[0].text
    )
    assert payload["reaped_count"] == 0
    assert fake.clusters


def test_reap_collects_an_expired_environment(fake, monkeypatch):
    from handlers.capella import guardrails

    for _ in range(6):
        if _ensure(ttl_hours=1)["done"]:
            break
    # Backdate the marker rather than sleeping.
    cluster = next(iter(fake.clusters.values()))
    cluster["description"] = guardrails.build_marker(
        "ios-4821",
        ttl_hours=1,
        now=__import__("datetime").datetime(
            2020, 1, 1, tzinfo=__import__("datetime").timezone.utc
        ),
    )

    payload = json.loads(
        environment.handle("capella_env_reap", {"project_id": "test-proj"})[0].text
    )
    assert payload["would_delete_count"] == 1


def test_env_list_separates_managed_from_unmanaged(fake):
    for _ in range(6):
        if _ensure()["done"]:
            break
    fake.clusters["hand-1"] = {
        "id": "hand-1",
        "name": "someones-cluster",
        "description": "made in the UI",
        "currentState": "healthy",
    }
    payload = json.loads(
        environment.handle("capella_env_list", {"project_id": "test-proj"})[0].text
    )
    assert payload["managed_count"] == 1
    assert payload["unmanaged_count"] == 1
    assert payload["unmanaged"][0]["reapable"] is False


# ── Connection info ──────────────────────────────────────────────────────────


def test_connection_info_warns_about_an_empty_allowlist(fake):
    """The most common 'provisioned but unreachable' cause deserves to be called
    out rather than left for the user to discover through a timeout."""
    for _ in range(6):
        if _ensure()["done"]:
            break
    payload = json.loads(
        environment.handle(
            "capella_env_connection_info",
            {"env_name": "ios-4821", "project_id": "test-proj"},
        )[0].text
    )
    assert "warning_allowlist" in payload


def test_connection_info_has_no_allowlist_warning_when_cidrs_exist(fake):
    for _ in range(6):
        if _ensure(allowed_cidrs=["203.0.113.4/32"])["done"]:
            break
    payload = json.loads(
        environment.handle(
            "capella_env_connection_info",
            {"env_name": "ios-4821", "project_id": "test-proj"},
        )[0].text
    )
    assert "warning_allowlist" not in payload


def test_status_of_a_missing_environment_is_not_an_error(fake):
    payload = json.loads(
        environment.handle(
            "capella_env_status", {"env_name": "never-made", "project_id": "test-proj"}
        )[0].text
    )
    assert payload["exists"] is False
    assert "error" not in payload
