"""
Regression tests for guardrail hardening — one per real finding from the
security review.

Each test below corresponds to a hole that existed and was closed. They are kept
separate from test_capella.py so that the property each one defends stays
legible: if one of these fails, a specific containment guarantee has regressed,
not merely "a test broke".

The findings, in the order they appear here:

  F1  Child-resource mutations bypassed the name-prefix guard. An allowlisted
      project was sufficient to flush or delete a bucket on an UNMANAGED cluster
      sitting in that project. Highest-severity finding: capella_bucket_flush
      destroys all data in a bucket.
  F2  The cluster ownership check was wrapped in `if isinstance(cluster, dict)`,
      so an unexpected response shape SKIPPED the check and the delete proceeded.
      Fail-open.
  F3  `if project_id:` silently skipped the allowlist when the value was falsy.
  F4  The spend ceiling was enforced only in capella_env_ensure, not on the raw
      capella_cluster_create primitive.
  F5  Parking a cluster used assert_deletable, so Capella deletion protection
      blocked the cost-saving operation.
  F6  The generated password had a fixed 'Aa1!' prefix.
  F7  CAPELLA_PROTECTED_CLUSTERS matched only ids, so listing a cluster by name
      protected nothing while reading as configured.
  F8  Deletion protection expressed as the string "true" was not honored.
"""

from __future__ import annotations

import json
import string

import pytest

from handlers import capella
from handlers.capella import environment, guardrails
from handlers.capella.spec import OPS as _ALL_OPS


@pytest.fixture(autouse=True)
def _sandbox(monkeypatch):
    """A configured sandbox: one allowlisted project, prefix required."""
    monkeypatch.setenv("CAPELLA_ORG_ID", "org-1")
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    monkeypatch.delenv("CAPELLA_PROTECTED_CLUSTERS", raising=False)
    monkeypatch.delenv("CAPELLA_MAX_ENVIRONMENTS", raising=False)
    monkeypatch.delenv("CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE", raising=False)


class Recorder:
    """Records every request and returns a scripted cluster object."""

    def __init__(self, cluster: object, clusters: list | None = None):
        self.cluster = cluster
        self.clusters = clusters if clusters is not None else []
        self.requests: list[tuple[str, str]] = []

    def request(self, method, path, *, params=None, body=None):
        self.requests.append((method, path))
        # A single-cluster GET
        if method == "GET" and "/clusters/" in path:
            return self.cluster
        return {"status": "ok"}

    def listing(self, path, *, params=None, page_size=None, max_items=None):
        self.requests.append(("GET", path))
        return {
            "data": self.clusters,
            "itemCount": len(self.clusters),
            "totalItems": len(self.clusters),
            "pagesFetched": 1,
            "truncated": False,
        }

    @property
    def mutating_requests(self):
        return [r for r in self.requests if r[0] in ("POST", "PUT", "DELETE")]


@pytest.fixture
def api(monkeypatch):
    def make(cluster=None, clusters=None):
        rec = Recorder(cluster, clusters)
        monkeypatch.setattr(capella, "capella_request", rec.request)
        monkeypatch.setattr(capella, "capella_list", rec.listing)
        return rec

    return make


def _call(tool, **args):
    return json.loads(capella.handle(tool, args)[0].text)


UNMANAGED = {"id": "prod-cluster-1", "name": "acme-prod-ios"}
MANAGED = {"id": "test-cluster-1", "name": "mcptest-ios-4821"}


# ── F1: child-resource operations on an unmanaged cluster ────────────────────

# Every one of these addresses a cluster's CHILD. Before the fix, all of them
# reached Capella on the strength of the project allowlist alone.
CHILD_DESTRUCTIVE = [
    ("capella_bucket_delete", {"bucket_id": "b1"}),
    ("capella_bucket_flush", {"bucket_id": "b1"}),
    ("capella_scope_delete", {"bucket_id": "b1", "scope_name": "s1"}),
    (
        "capella_collection_delete",
        {"bucket_id": "b1", "scope_name": "s1", "collection_name": "c1"},
    ),
    ("capella_database_credential_delete", {"user_id": "u1"}),
    ("capella_app_service_delete", {"app_service_id": "as1"}),
    ("capella_allowed_cidr_delete", {"allowed_cidr_id": "cidr1"}),
    (
        "capella_app_endpoint_delete",
        {"app_service_id": "as1", "app_endpoint_name": "e1"},
    ),
]


@pytest.mark.parametrize(("tool", "extra"), CHILD_DESTRUCTIVE)
def test_f1_child_destructive_refused_on_unmanaged_cluster(api, tool, extra):
    rec = api(cluster=UNMANAGED)
    payload = _call(tool, project_id="test-proj", cluster_id="prod-cluster-1", **extra)

    assert payload.get("guardrail") is True, f"{tool} was NOT refused"
    assert "does not start with" in payload["error"]
    assert rec.mutating_requests == [], f"{tool} reached Capella despite refusal"


CHILD_MUTATING = [
    ("capella_allowed_cidr_create", {"body": {"cidr": "0.0.0.0/0"}}),
    ("capella_bucket_create", {"body": {"name": "x"}}),
    ("capella_database_credential_create", {"body": {"name": "x"}}),
    ("capella_cluster_update", {"body": {"name": "y"}}),
    (
        "capella_app_endpoint_access_control_function_set",
        {"app_service_id": "as1", "app_endpoint_name": "e1", "body": {"function": "f"}},
    ),
]


@pytest.mark.parametrize(("tool", "extra"), CHILD_MUTATING)
def test_f1_child_mutations_refused_on_unmanaged_cluster(api, tool, extra):
    """Not only deletes. Adding 0.0.0.0/0 to a production cluster's allowlist, or
    rewriting its sync access-control function, is just as far out of scope."""
    rec = api(cluster=UNMANAGED)
    payload = _call(tool, project_id="test-proj", cluster_id="prod-cluster-1", **extra)

    assert payload.get("guardrail") is True, f"{tool} was NOT refused"
    assert rec.mutating_requests == []


def test_f1_child_operations_allowed_on_a_managed_cluster(api):
    """The guard must not be so broad that it blocks the intended workflow."""
    rec = api(cluster=MANAGED)
    payload = _call(
        "capella_bucket_delete",
        project_id="test-proj",
        cluster_id="test-cluster-1",
        bucket_id="b1",
    )
    assert "guardrail" not in payload
    assert (
        "DELETE",
        "/v4/organizations/org-1/projects/test-proj/clusters/test-cluster-1/buckets/b1",
    ) in rec.requests


def test_f1_cluster_delete_still_refused_on_unmanaged_cluster(api):
    rec = api(cluster=UNMANAGED)
    payload = _call(
        "capella_cluster_delete", project_id="test-proj", cluster_id="prod-cluster-1"
    )
    assert payload.get("guardrail") is True
    assert rec.mutating_requests == []


# ── F2: fail-closed when ownership cannot be established ─────────────────────


@pytest.mark.parametrize(
    "bad_response",
    [
        None,
        [],
        "unexpected string body",
        {"status": "ok"},  # 2xx with no cluster fields
        {"id": "c1"},  # object with no name to check the prefix against
    ],
    ids=["none", "list", "string", "status-only", "no-name"],
)
def test_f2_unusable_cluster_response_fails_closed(api, bad_response):
    """A guard that disappears when the response shape is strange is not a guard.
    Previously `if isinstance(cluster, dict)` skipped the check entirely."""
    rec = api(cluster=bad_response)
    payload = _call("capella_cluster_delete", project_id="test-proj", cluster_id="c1")
    assert payload.get("guardrail") is True
    assert "ownership" in payload["error"].lower()
    assert rec.mutating_requests == []


# ── F3: missing project_id must refuse, not skip ─────────────────────────────


def test_f3_missing_project_id_is_refused_not_skipped(api):
    rec = api(cluster=MANAGED)
    payload = _call("capella_cluster_delete", project_id="", cluster_id="c1")
    assert payload.get("guardrail") is True
    assert "project_id" in payload["error"]
    assert rec.mutating_requests == []


def test_f3_project_delete_outside_allowlist_refused(api):
    rec = api(cluster=MANAGED)
    payload = _call("capella_project_delete", project_id="production-proj")
    assert payload.get("guardrail") is True
    assert rec.mutating_requests == []


# ── F4: spend ceiling on the raw primitive ───────────────────────────────────


def test_f4_ceiling_enforced_on_the_create_primitive(api, monkeypatch):
    """Previously enforced only inside capella_env_ensure, so an agent looping on
    capella_cluster_create could provision without bound."""
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "2")
    existing = [
        {"id": "c1", "name": "mcptest-a", "description": guardrails.build_marker("a")},
        {"id": "c2", "name": "mcptest-b", "description": guardrails.build_marker("b")},
    ]
    rec = api(cluster=MANAGED, clusters=existing)
    payload = _call(
        "capella_cluster_create",
        project_id="test-proj",
        body={"name": "mcptest-c"},
    )
    assert payload.get("guardrail") is True
    assert "ceiling" in payload["error"].lower()
    assert rec.mutating_requests == []


def test_f4_create_allowed_below_the_ceiling(api, monkeypatch):
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "5")
    rec = api(cluster=MANAGED, clusters=[])
    payload = _call(
        "capella_cluster_create", project_id="test-proj", body={"name": "mcptest-c"}
    )
    assert "guardrail" not in payload
    assert any(m == "POST" for m, _ in rec.requests)


def test_f4_create_still_enforces_the_name_prefix(api, monkeypatch):
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "5")
    rec = api(cluster=MANAGED, clusters=[])
    payload = _call(
        "capella_cluster_create", project_id="test-proj", body={"name": "prod-cluster"}
    )
    assert payload.get("guardrail") is True
    assert rec.mutating_requests == []


def test_f4_project_create_enforces_the_name_prefix(api):
    """project_create was previously unguarded, so it escaped the convention."""
    rec = api(cluster=MANAGED, clusters=[])
    payload = _call("capella_project_create", body={"name": "production"})
    assert payload.get("guardrail") is True
    assert rec.mutating_requests == []


# ── F5: parking must not be blocked by deletion protection ───────────────────

PROTECTED_MANAGED = {
    "id": "test-cluster-1",
    "name": "mcptest-ios-4821",
    "deletionProtection": True,
}


def test_f5_park_is_allowed_on_a_deletion_protected_cluster(monkeypatch):
    """Deletion protection means "do not destroy", not "do not touch". Blocking
    the cost-saving operation would push operators to switch protection off."""
    calls: list[tuple[str, str]] = []

    def request(method, path, *, params=None, body=None):
        calls.append((method, path))
        # The ownership re-fetch must receive the full cluster object; returning a
        # bare {"status": "ok"} would (correctly) make the guardrail fail closed.
        if method == "GET":
            return PROTECTED_MANAGED
        return {"status": "ok"}

    def listing(path, *, params=None, page_size=None, max_items=None):
        return {"data": [PROTECTED_MANAGED], "itemCount": 1, "truncated": False}

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    payload = json.loads(
        environment.handle(
            "capella_env_park", {"env_name": "ios-4821", "project_id": "test-proj"}
        )[0].text
    )
    assert "guardrail" not in payload, payload
    assert any(m == "DELETE" and p.endswith("/activationState") for m, p in calls)


def test_f5_teardown_is_still_refused_on_a_deletion_protected_cluster(monkeypatch):
    """A read (the ownership re-fetch) is expected; a MUTATION is not."""
    calls: list[tuple[str, str]] = []

    def request(method, path, *, params=None, body=None):
        calls.append((method, path))
        if method != "GET":
            raise AssertionError(f"teardown issued {method} on a protected cluster")
        return PROTECTED_MANAGED

    def listing(path, *, params=None, page_size=None, max_items=None):
        return {"data": [PROTECTED_MANAGED], "itemCount": 1, "truncated": False}

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    payload = json.loads(
        environment.handle(
            "capella_env_teardown", {"env_name": "ios-4821", "project_id": "test-proj"}
        )[0].text
    )
    assert payload.get("guardrail") is True
    assert "deletion protection" in payload["error"].lower()
    assert all(m == "GET" for m, _ in calls)


# ── F14: guardrail decisions must use the per-resource GET, not LIST data ─────


def test_f14_protection_visible_only_on_the_individual_get_is_honored(monkeypatch):
    """The exact Finding-2 scenario. Cloud LIST endpoints commonly return summary
    objects; here the list entry omits deletionProtection and only the per-cluster
    GET reveals it. A guardrail decision made from list data would delete a
    protected cluster — and would disagree with capella_cluster_delete, which does
    its own GET and refuses. Two paths disagreeing about whether a cluster may be
    destroyed is precisely the bug that only surfaces in production."""
    summary = {"id": "c1", "name": "mcptest-ios-4821"}  # no deletionProtection field
    full = {"id": "c1", "name": "mcptest-ios-4821", "deletionProtection": True}
    calls: list[tuple[str, str]] = []

    def request(method, path, *, params=None, body=None):
        calls.append((method, path))
        if method == "GET":
            return full
        raise AssertionError(f"{method} issued on a protected cluster")

    def listing(path, *, params=None, page_size=None, max_items=None):
        return {"data": [summary], "itemCount": 1, "truncated": False}

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    payload = json.loads(
        environment.handle(
            "capella_env_teardown", {"env_name": "ios-4821", "project_id": "test-proj"}
        )[0].text
    )
    assert payload.get("guardrail") is True, (
        "teardown decided from summarised LIST data and would have deleted a "
        "deletion-protected cluster"
    )
    assert "deletion protection" in payload["error"].lower()
    assert any(m == "GET" for m, _ in calls), "no individual re-fetch was performed"


# ── F15: env_ensure must not reconfigure a cluster it does not own ────────────


def test_f15_ensure_refuses_to_adopt_a_protected_cluster(monkeypatch):
    """capella_env_ensure adopts an existing cluster and then mutates it — new
    credentials, allowlist entries, buckets. Previously it checked only the project
    allowlist, so a prefix-matching cluster that an operator had explicitly placed
    in CAPELLA_PROTECTED_CLUSTERS was fully reconfigurable through this tool: the
    protection held against deletion and nothing else."""
    monkeypatch.setenv("CAPELLA_PROTECTED_CLUSTERS", "mcptest-ios-4821")
    existing = {
        "id": "c1",
        "name": "mcptest-ios-4821",
        "currentState": "healthy",
        "description": guardrails.build_marker("ios-4821"),
    }

    def request(method, path, *, params=None, body=None):
        if method != "GET":
            raise AssertionError(f"ensure issued {method} on a protected cluster")
        return existing

    def listing(path, *, params=None, page_size=None, max_items=None):
        data = [existing] if path.endswith("/clusters") else []
        return {"data": data, "itemCount": len(data), "truncated": False}

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    payload = json.loads(
        environment.handle(
            "capella_env_ensure",
            {
                "env_name": "ios-4821",
                "project_id": "test-proj",
                "allowed_cidrs": ["0.0.0.0/0"],
            },
        )[0].text
    )
    assert payload.get("guardrail") is True
    assert "PROTECTED_CLUSTERS" in payload["error"]


def test_f15_ensure_never_touches_an_unprefixed_cluster_of_the_same_env_name(
    monkeypatch,
):
    """An unmanaged cluster named exactly like the environment must be invisible to
    the reconciler. The correct outcome is that ensure treats the environment as
    absent and provisions a properly prefixed cluster of its own — never that it
    adopts and reconfigures the unmanaged one.

    This is why _get_cluster matches the PREFIXED name only, while the destructive
    paths additionally match the literal name so they can refuse out loud rather
    than reporting "nothing to do".
    """
    monkeypatch.delenv("CAPELLA_PROTECTED_CLUSTERS", raising=False)
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    unmanaged = {"id": "c1", "name": "ios-4821", "currentState": "healthy"}
    calls: list[tuple[str, str]] = []

    def request(method, path, *, params=None, body=None):
        calls.append((method, path))
        return {"id": "new-cluster", "status": "ok"}

    def listing(path, *, params=None, page_size=None, max_items=None):
        data = [unmanaged] if path.endswith("/clusters") else []
        return {"data": data, "itemCount": len(data), "truncated": False}

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    payload = json.loads(
        environment.handle(
            "capella_env_ensure", {"env_name": "ios-4821", "project_id": "test-proj"}
        )[0].text
    )

    assert payload["phase"] == "creating_cluster"
    # Nothing addressed the unmanaged cluster's id.
    assert not [p for _m, p in calls if "/clusters/c1" in p], calls
    # The one write was the create, on the collection endpoint.
    writes = [(m, p) for m, p in calls if m != "GET"]
    assert writes == [("POST", "/v4/organizations/org-1/projects/test-proj/clusters")]


# ── F16: the spend ceiling spans the whole sandbox, not one project ──────────


def test_f16_ceiling_counts_every_allowlisted_project(monkeypatch):
    """Counting only the current project made the effective ceiling
    (projects x configured value), so varying project_id multiplied the spend the
    guard was supposed to cap."""
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "proj-a,proj-b")
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "2")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")

    per_project = {
        "proj-a": [
            {
                "id": "a1",
                "name": "mcptest-a1",
                "description": guardrails.build_marker("a1"),
            }
        ],
        "proj-b": [
            {
                "id": "b1",
                "name": "mcptest-b1",
                "description": guardrails.build_marker("b1"),
            }
        ],
    }

    def listing(path, *, params=None, page_size=None, max_items=None):
        data = []
        if path.endswith("/clusters"):
            for proj, clusters in per_project.items():
                if f"/projects/{proj}/" in path:
                    data = clusters
        return {"data": data, "itemCount": len(data), "truncated": False}

    def request(method, path, *, params=None, body=None):
        if method != "GET":
            raise AssertionError("a third environment must not be created")
        return {"status": "ok"}

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    # One environment in each of the two allowlisted projects == 2 == the ceiling.
    payload = json.loads(
        environment.handle(
            "capella_env_ensure", {"env_name": "third", "project_id": "proj-a"}
        )[0].text
    )
    assert payload.get("guardrail") is True
    assert "ceiling" in payload["error"].lower()


# ── F6: password generation ──────────────────────────────────────────────────


def test_f6_password_has_no_fixed_prefix():
    passwords = {environment._generate_password() for _ in range(200)}
    assert len(passwords) == 200, "generated passwords collided"
    # The old implementation began every password with the literal 'Aa1!'.
    assert not any(p.startswith("Aa1!") for p in passwords)
    first_chars = {p[0] for p in passwords}
    assert len(first_chars) > 5, "first character is not varying"


def test_f6_password_satisfies_capella_complexity():
    for _ in range(50):
        p = environment._generate_password()
        assert len(p) >= 8
        assert any(c.isupper() for c in p)
        assert any(c.islower() for c in p)
        assert any(c.isdigit() for c in p)
        assert any(c in environment._PASSWORD_SYMBOLS for c in p)
        assert not any(c in string.whitespace for c in p)


# ── F7 / F8: protected clusters and protection-flag spellings ────────────────


def test_f7_protected_cluster_matches_by_name_not_only_id(monkeypatch):
    """Operators know clusters by name. A list that only matched UUIDs protected
    nothing while reading in the config as though it did."""
    monkeypatch.setenv("CAPELLA_PROTECTED_CLUSTERS", "mcptest-do-not-touch")
    with pytest.raises(guardrails.GuardrailError) as excinfo:
        guardrails.assert_managed(
            {"id": "some-uuid", "name": "mcptest-do-not-touch"}, "test-proj"
        )
    assert "PROTECTED_CLUSTERS" in str(excinfo.value)


def test_f7_protected_cluster_still_matches_by_id(monkeypatch):
    monkeypatch.setenv("CAPELLA_PROTECTED_CLUSTERS", "uuid-keep")
    with pytest.raises(guardrails.GuardrailError):
        guardrails.assert_managed({"id": "uuid-keep", "name": "mcptest-x"}, "test-proj")


@pytest.mark.parametrize(
    "flag_value", [True, "true", "TRUE", "enabled", "on", "yes", " True "]
)
def test_f8_deletion_protection_spellings_are_honored(flag_value):
    with pytest.raises(guardrails.GuardrailError) as excinfo:
        guardrails.assert_deletable(
            {"id": "c1", "name": "mcptest-x", "deletionProtection": flag_value},
            "test-proj",
        )
    assert "deletion protection" in str(excinfo.value).lower()


@pytest.mark.parametrize("flag_value", [False, "false", "disabled", "off", None, ""])
def test_f8_unprotected_values_do_not_block(flag_value):
    guardrails.assert_deletable(
        {"id": "c1", "name": "mcptest-x", "deletionProtection": flag_value}, "test-proj"
    )


def test_f8_alternate_flag_field_names(monkeypatch):
    for field in ("deletion_protection", "deletionProtectionEnabled"):
        with pytest.raises(guardrails.GuardrailError):
            guardrails.assert_deletable(
                {"id": "c1", "name": "mcptest-x", field: True}, "test-proj"
            )


# ── Credential leakage ───────────────────────────────────────────────────────


def test_sensitive_response_is_redacted_before_it_reaches_the_caller(monkeypatch):
    """A generated password must not enter the model's context via the raw
    primitive; capella_env_ensure is the one sanctioned path.

    Uses the monkeypatch FIXTURE rather than pytest.MonkeyPatch() — an earlier
    draft constructed a throwaway MonkeyPatch to patch and a second one to undo,
    which undoes nothing and leaks the stub into every later test in the session.
    """

    def request(method, path, *, params=None, body=None):
        if method == "GET":
            return MANAGED
        return {"id": "cred-1", "name": "app", "password": "SuperSecret123!"}

    monkeypatch.setattr(capella, "capella_request", request)

    payload = _call(
        "capella_database_credential_create",
        project_id="test-proj",
        cluster_id="test-cluster-1",
        body={"name": "app"},
    )
    assert "SuperSecret123!" not in json.dumps(payload)
    assert payload.get("password") == "***REDACTED***"
    assert "_note" in payload


def test_stubs_do_not_leak_between_tests():
    """Guards the property the previous test used to break: after a test that
    patches the client, the real function must be restored. A leaked stub makes
    later tests pass against a fake instead of the code under test."""
    from handlers.capella import client

    assert capella.capella_request is client.capella_request


def test_guardrail_refusals_never_echo_the_request_body(api):
    """err() echoes context; a refused credential create must not leak the
    password the caller supplied."""
    api(cluster=UNMANAGED)
    payload = _call(
        "capella_database_credential_create",
        project_id="test-proj",
        cluster_id="prod-cluster-1",
        body={"name": "app", "password": "PlaintextFromCaller1!"},
    )
    assert payload.get("guardrail") is True
    assert "PlaintextFromCaller1!" not in json.dumps(payload)


# ── F12: project delete as an indirect route to unmanaged clusters ───────────


def test_f12_project_delete_refused_when_it_holds_unmanaged_clusters(api):
    """No cluster tool is involved, so the per-cluster ownership check never
    fires. Deleting the project would take its clusters with it."""
    rec = api(
        cluster=MANAGED,
        clusters=[
            {"id": "c1", "name": "mcptest-ours"},
            {"id": "c2", "name": "acme-prod-ios"},
        ],
    )
    payload = _call("capella_project_delete", project_id="test-proj")

    assert payload.get("guardrail") is True
    assert "does not own" in payload["error"]
    assert "acme-prod-ios" in payload["error"]
    assert rec.mutating_requests == []


def test_f12_project_delete_allowed_when_every_cluster_is_ours(api):
    rec = api(
        cluster=MANAGED,
        clusters=[
            {"id": "c1", "name": "mcptest-a"},
            {"id": "c2", "name": "mcptest-b"},
        ],
    )
    payload = _call("capella_project_delete", project_id="test-proj")
    assert "guardrail" not in payload
    assert ("DELETE", "/v4/organizations/org-1/projects/test-proj") in rec.requests


def test_f12_empty_project_can_be_deleted(api):
    rec = api(cluster=MANAGED, clusters=[])
    payload = _call("capella_project_delete", project_id="test-proj")
    assert "guardrail" not in payload
    assert rec.mutating_requests != []


def test_f12_is_managed_name_permits_everything_without_a_prefix(monkeypatch):
    """Documents the consequence of leaving the prefix unset: the ownership guard
    degrades to the project allowlist alone."""
    monkeypatch.delenv("CAPELLA_ENV_NAME_PREFIX", raising=False)
    assert guardrails.is_managed_name("anything-at-all") is True


def test_f12_is_managed_name_respects_the_prefix(monkeypatch):
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    assert guardrails.is_managed_name("mcptest-x") is True
    assert guardrails.is_managed_name("acme-prod") is False


# ── Exhaustive coverage: every guarded op, not a hand-picked list ────────────
#
# The parametrized lists above name specific tools, which means a NEW guarded op
# added to spec.py later would not be covered by them. These two tests derive
# their cases from the registry itself, so containment cannot silently regress
# when the surface grows.


def _synthetic_args(op) -> dict:
    """Plausible arguments for every path placeholder of an op."""
    from handlers.capella.client import extract_placeholders

    fillers = {
        "organization_id": "org-1",
        "project_id": "test-proj",
        "cluster_id": "prod-cluster-1",
        "bucket_id": "b1",
        "scope_name": "s1",
        "collection_name": "c1",
        "user_id": "u1",
        "app_service_id": "as1",
        "app_endpoint_name": "e1",
        "allowed_cidr_id": "cidr1",
        "admin_user_id": "au1",
    }
    args = {p: fillers.get(p, "x") for p in extract_placeholders(op.path)}
    if op.body:
        args["body"] = {
            "name": "attacker-supplied",
            "cidr": "0.0.0.0/0",
            "function": "f",
        }
    return args


GUARDED_CLUSTER_OPS = [
    op for op in _ALL_OPS if op.guarded and "{cluster_id}" in op.path
]


@pytest.mark.parametrize("op", GUARDED_CLUSTER_OPS, ids=lambda o: o.name)
def test_every_guarded_cluster_op_is_refused_on_an_unmanaged_cluster(api, op):
    rec = api(cluster=UNMANAGED)
    payload = _call(op.name, **_synthetic_args(op))

    assert payload.get("guardrail") is True, (
        f"{op.name} reached Capella against an unmanaged cluster — the ownership "
        "guard does not cover it"
    )
    assert rec.mutating_requests == [], f"{op.name} issued a mutating request"


@pytest.mark.parametrize("op", GUARDED_CLUSTER_OPS, ids=lambda o: o.name)
def test_every_guarded_cluster_op_is_refused_outside_the_allowlist(api, op):
    """Same sweep, one layer out: a managed-looking cluster in a project that is
    not on the allowlist must also be refused."""
    rec = api(cluster=MANAGED)
    args = _synthetic_args(op)
    args["project_id"] = "production-proj"
    payload = _call(op.name, **args)

    assert payload.get("guardrail") is True, f"{op.name} escaped the project allowlist"
    assert rec.mutating_requests == []


def test_the_sweep_actually_covers_the_surface():
    """A sweep that silently matched zero ops would pass vacuously."""
    assert len(GUARDED_CLUSTER_OPS) >= 25, len(GUARDED_CLUSTER_OPS)


def test_no_guarded_op_lacks_both_a_project_and_a_cluster_placeholder():
    """Any guarded op addressing neither a project nor a cluster would receive no
    containment at all. Only the org-scoped creates may qualify, and each needs a
    deliberate entry in _NAME_CHECKED_CREATES."""
    from handlers import capella as cap

    for op in _ALL_OPS:
        if not op.guarded:
            continue
        has_scope = "{project_id}" in op.path or "{cluster_id}" in op.path
        assert has_scope or op.name in cap._NAME_CHECKED_CREATES, (
            f"{op.name} is guarded but addresses neither a project nor a cluster, "
            "and is not a name-checked create — it would be unconstrained"
        )


# ── F13: inert guardrails must be announced, not silently degraded ───────────


def test_f13_missing_name_prefix_is_reported_as_a_warning(monkeypatch):
    """Without a prefix the per-cluster ownership check passes for everything, so
    containment falls back to the project list alone. That must be visible."""
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.delenv("CAPELLA_ENV_NAME_PREFIX", raising=False)

    warnings = guardrails.policy_warnings()
    assert any("INERT" in w for w in warnings)
    assert any("CAPELLA_ENV_NAME_PREFIX" in w for w in warnings)


def test_f13_no_prefix_warning_once_a_prefix_is_configured(monkeypatch):
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    assert not any("INERT" in w for w in guardrails.policy_warnings())


def test_f13_unscoped_destructive_is_reported(monkeypatch):
    monkeypatch.setenv("CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE", "true")
    assert any("UNSCOPED" in w or "anywhere" in w for w in guardrails.policy_warnings())


def test_f13_unpinned_organization_is_reported(monkeypatch):
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.delenv("CAPELLA_ORG_ID", raising=False)
    assert any("CAPELLA_ORG_ID" in w for w in guardrails.policy_warnings())


def test_f13_zero_ttl_default_is_reported(monkeypatch):
    monkeypatch.setenv("CAPELLA_ENV_TTL_HOURS", "0")
    assert any("never expire" in w for w in guardrails.policy_warnings())


def test_f13_fully_configured_sandbox_has_no_warnings(monkeypatch):
    monkeypatch.setenv("CAPELLA_ORG_ID", "org-1")
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    monkeypatch.setenv("CAPELLA_ENV_TTL_HOURS", "4")
    monkeypatch.delenv("CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE", raising=False)
    assert guardrails.policy_warnings() == []


def test_f13_warnings_surface_in_the_status_tool(monkeypatch):
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.delenv("CAPELLA_ENV_NAME_PREFIX", raising=False)
    payload = json.loads(capella.handle("capella_guardrails_status", {})[0].text)
    assert payload["warnings"], "an operator asking for posture must see the caveats"


# ── F17: refetch must fail closed; F18: ceiling shared across both paths ─────


def test_f17_refetch_fails_closed_when_the_get_is_unusable(monkeypatch):
    """An earlier fix fell back to the LIST object when the GET returned something
    odd, which quietly reintroduced the weakness it was added to remove: the
    guardrail would then judge deletionProtection from a summary that may omit it."""
    summary = {"id": "c1", "name": "mcptest-ios-4821"}

    def request(method, path, *, params=None, body=None):
        if method == "GET":
            return {"status": "ok"}  # 2xx with no cluster fields
        raise AssertionError(f"{method} issued without verified ownership")

    def listing(path, *, params=None, page_size=None, max_items=None):
        return {"data": [summary], "itemCount": 1, "truncated": False}

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    payload = json.loads(
        environment.handle(
            "capella_env_teardown", {"env_name": "ios-4821", "project_id": "test-proj"}
        )[0].text
    )
    assert payload.get("guardrail") is True
    assert "verify ownership" in payload["error"]


def test_f17_refetch_fails_closed_when_the_listing_has_no_id(monkeypatch):
    def request(method, path, *, params=None, body=None):
        raise AssertionError(f"{method} issued without a cluster id")

    def listing(path, *, params=None, page_size=None, max_items=None):
        return {
            "data": [{"name": "mcptest-ios-4821"}],
            "itemCount": 1,
            "truncated": False,
        }

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    payload = json.loads(
        environment.handle(
            "capella_env_teardown", {"env_name": "ios-4821", "project_id": "test-proj"}
        )[0].text
    )
    assert payload.get("guardrail") is True


def test_f18_raw_create_primitive_counts_every_allowlisted_project(api, monkeypatch):
    """The ceiling has to mean the same thing on both paths. Counting only the
    project in the call let an agent call capella_cluster_create directly and
    round-robin project_id to reach (projects x ceiling)."""
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "proj-a,proj-b")
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "2")

    per_project = {
        "proj-a": [
            {
                "id": "a1",
                "name": "mcptest-a1",
                "description": guardrails.build_marker("a1"),
            }
        ],
        "proj-b": [
            {
                "id": "b1",
                "name": "mcptest-b1",
                "description": guardrails.build_marker("b1"),
            }
        ],
    }
    seen: list[str] = []

    def listing(path, *, params=None, page_size=None, max_items=None):
        seen.append(path)
        data = next(
            (v for k, v in per_project.items() if f"/projects/{k}/" in path), []
        )
        return {"data": data, "itemCount": len(data), "truncated": False}

    rec = Recorder(cluster=MANAGED)
    monkeypatch.setattr(capella, "capella_request", rec.request)
    monkeypatch.setattr(capella, "capella_list", listing)

    payload = _call(
        "capella_cluster_create", project_id="proj-a", body={"name": "mcptest-third"}
    )
    assert payload.get("guardrail") is True
    assert "ceiling" in payload["error"].lower()
    # Proof it looked beyond the project named in the call.
    assert any("proj-b" in p for p in seen), seen
    assert rec.mutating_requests == []


def test_f18_both_paths_share_one_counting_implementation():
    """Structural guard against the two definitions drifting apart again."""
    import inspect

    from handlers.capella import environment as env

    assert "count_managed_environments" in inspect.getsource(
        env._count_managed_environments
    )
    assert "count_managed_environments" in inspect.getsource(capella._apply_guardrails)


# ── F19-F21: reap identity, unscoped ceiling semantics, refusal memo ──────────


def test_f19_reap_refuses_when_marker_and_cluster_name_disagree(monkeypatch):
    """The reaper resolves a concrete cluster_id while listing, then previously threw
    it away and re-derived the target from the marker's env NAME. A marker naming a
    different environment would send teardown at a live, non-expired cluster — and
    every guardrail would pass, because that cluster is also inside the sandbox.
    The checks would simply have been applied to the wrong resource."""
    expired_marker = guardrails.build_marker(
        "some-other-live-env",
        ttl_hours=1,
        now=__import__("datetime").datetime(
            2020, 1, 1, tzinfo=__import__("datetime").timezone.utc
        ),
    )
    tampered = {
        "id": "cluster-A",
        "name": "mcptest-tampered",
        "description": expired_marker,
        "currentState": "healthy",
    }
    victim = {
        "id": "cluster-B",
        "name": "mcptest-some-other-live-env",
        "description": guardrails.build_marker("some-other-live-env", ttl_hours=0),
        "currentState": "healthy",
    }

    def request(method, path, *, params=None, body=None):
        if method == "GET":
            return victim if "cluster-B" in path else tampered
        raise AssertionError(f"{method} {path} — nothing should be deleted")

    def listing(path, *, params=None, page_size=None, max_items=None):
        data = [tampered, victim] if path.endswith("/clusters") else []
        return {"data": data, "itemCount": len(data), "truncated": False}

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    payload = json.loads(
        environment.handle(
            "capella_env_reap", {"project_id": "test-proj", "dry_run": False}
        )[0].text
    )
    assert payload["reaped_count"] == 0
    assert payload["refused"], "the mismatch was not reported"
    assert "mismatch" in payload["refused"][0]["error"].lower()


def test_f19_normal_reap_still_works_when_marker_matches(monkeypatch):
    """The identity check must not break the ordinary case."""
    old = __import__("datetime").datetime(
        2020, 1, 1, tzinfo=__import__("datetime").timezone.utc
    )
    cluster = {
        "id": "c1",
        "name": "mcptest-ios-4821",
        "description": guardrails.build_marker("ios-4821", ttl_hours=1, now=old),
        "currentState": "healthy",
    }
    deleted: list[str] = []

    def request(method, path, *, params=None, body=None):
        if method == "GET":
            return cluster
        if method == "DELETE":
            deleted.append(path)
        return {"status": "ok"}

    def listing(path, *, params=None, page_size=None, max_items=None):
        data = [cluster] if path.endswith("/clusters") else []
        return {"data": data, "itemCount": len(data), "truncated": False}

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    payload = json.loads(
        environment.handle(
            "capella_env_reap", {"project_id": "test-proj", "dry_run": False}
        )[0].text
    )
    assert payload["reaped_count"] == 1
    assert payload["refused"] == []
    assert any("/clusters/c1" in p for p in deleted)


def test_f20_unscoped_mode_declares_the_ceiling_is_per_project(monkeypatch):
    """With no allowlist there is no set of projects to sum across, so the ceiling
    genuinely is per-project. Stating it beats implying otherwise."""
    monkeypatch.delenv("CAPELLA_ALLOWED_PROJECTS", raising=False)
    monkeypatch.setenv("CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE", "true")
    warnings = guardrails.policy_warnings()
    assert any("PER PROJECT" in w for w in warnings)


def test_f21_ceiling_refusal_is_memoised(monkeypatch):
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "1")
    scope = "org-1|test-proj"
    assert not guardrails.ceiling_refusal_active(scope)
    with pytest.raises(guardrails.GuardrailError):
        guardrails.assert_capacity(1, scope=scope)
    assert guardrails.ceiling_refusal_active(scope)
    with pytest.raises(guardrails.GuardrailError) as excinfo:
        guardrails.raise_ceiling_refusal()
    assert "moments ago" in str(excinfo.value)


def test_f22_a_refusal_in_one_scope_does_not_block_another(monkeypatch):
    """The memo was originally one process-global timestamp. On the HTTP transport
    one process serves many callers, so a single saturated project refused every
    other project's creates for 15s — and re-polling that project re-stamped the
    memo, sustaining an org-wide block. Turning "this project is full" into
    "nothing may be created anywhere" is a denial of service, not an optimisation."""
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "1")
    monkeypatch.delenv("CAPELLA_ALLOWED_PROJECTS", raising=False)
    policy = guardrails.load_policy()

    saturated = guardrails.ceiling_scope_key(policy, "org-1", "proj-full")
    other = guardrails.ceiling_scope_key(policy, "org-1", "proj-empty")
    assert saturated != other

    with pytest.raises(guardrails.GuardrailError):
        guardrails.assert_capacity(1, scope=saturated)

    assert guardrails.ceiling_refusal_active(saturated)
    assert not guardrails.ceiling_refusal_active(other), (
        "a refusal in one project blocked an unrelated project"
    )


def test_f22_scope_covers_the_whole_allowlist_when_one_is_configured(monkeypatch):
    """With an allowlist the count sums across every allowlisted project, so a
    refusal genuinely applies to that whole set — and must be keyed that way."""
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "proj-a,proj-b")
    policy = guardrails.load_policy()
    key_a = guardrails.ceiling_scope_key(policy, "org-1", "proj-a")
    key_b = guardrails.ceiling_scope_key(policy, "org-1", "proj-b")
    assert key_a == key_b, "the summed scope must share one memo key"

    # A different organization is a different scope.
    assert guardrails.ceiling_scope_key(policy, "org-2", "proj-a") != key_a


def test_f22_memo_expires(monkeypatch):
    monkeypatch.setattr(guardrails, "_CEILING_MEMO_SECONDS", 0.0)
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "1")
    with pytest.raises(guardrails.GuardrailError):
        guardrails.assert_capacity(1, scope="s")
    assert not guardrails.ceiling_refusal_active("s")


def test_f22_reap_refuses_an_entry_with_no_pinned_cluster_id(monkeypatch):
    """Without a concrete id, teardown would fall back to name resolution — the
    ambiguity the identity check exists to prevent. Refuse, do not degrade."""
    old = __import__("datetime").datetime(
        2020, 1, 1, tzinfo=__import__("datetime").timezone.utc
    )
    entry = {
        "name": "mcptest-x",
        "description": guardrails.build_marker("x", ttl_hours=1, now=old),
        "currentState": "healthy",
    }  # deliberately no "id"

    def request(method, path, *, params=None, body=None):
        if method != "GET":
            raise AssertionError(f"{method} issued for an unpinned reap target")
        return entry

    def listing(path, *, params=None, page_size=None, max_items=None):
        data = [entry] if path.endswith("/clusters") else []
        return {"data": data, "itemCount": len(data), "truncated": False}

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    payload = json.loads(
        environment.handle(
            "capella_env_reap", {"project_id": "test-proj", "dry_run": False}
        )[0].text
    )
    assert payload["reaped_count"] == 0
    assert payload["refused"]
    assert "cannot be pinned" in payload["refused"][0]["error"]


def test_f21_memo_short_circuits_the_expensive_count(api, monkeypatch):
    """A looping agent must not re-trigger a multi-project paginated listing on
    every refused attempt."""
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "1")
    existing = [
        {"id": "c1", "name": "mcptest-a", "description": guardrails.build_marker("a")}
    ]
    rec = api(cluster=MANAGED, clusters=existing)

    first = _call(
        "capella_cluster_create", project_id="test-proj", body={"name": "mcptest-b"}
    )
    assert first.get("guardrail") is True
    listings_after_first = len([p for _m, p in rec.requests if p.endswith("/clusters")])

    second = _call(
        "capella_cluster_create", project_id="test-proj", body={"name": "mcptest-c"}
    )
    assert second.get("guardrail") is True
    listings_after_second = len(
        [p for _m, p in rec.requests if p.endswith("/clusters")]
    )

    assert listings_after_second == listings_after_first, (
        "the refused retry re-listed clusters instead of re-serving the memo"
    )


def test_f21_memo_only_caches_refusals_never_allowances(monkeypatch):
    """Caching an allowance would be fail-open. Under the ceiling, nothing is
    memoised, so the count is always genuinely re-taken before a create."""
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "5")
    guardrails.assert_capacity(2, scope="org-1|test-proj")
    assert not guardrails.ceiling_refusal_active("org-1|test-proj")


def test_f23_dry_run_and_real_run_agree_about_what_is_reapable(monkeypatch):
    """An operator sizing a sweep from the preview must get the number the real run
    will act on. The dry run previously counted entries the real run refused."""
    old = __import__("datetime").datetime(
        2020, 1, 1, tzinfo=__import__("datetime").timezone.utc
    )
    pinned = {
        "id": "c1",
        "name": "mcptest-good",
        "description": guardrails.build_marker("good", ttl_hours=1, now=old),
        "currentState": "healthy",
    }
    unpinnable = {  # no id
        "name": "mcptest-bad",
        "description": guardrails.build_marker("bad", ttl_hours=1, now=old),
        "currentState": "healthy",
    }

    def request(method, path, *, params=None, body=None):
        if method == "GET":
            return pinned
        return {"status": "ok"}

    def listing(path, *, params=None, page_size=None, max_items=None):
        data = [pinned, unpinnable] if path.endswith("/clusters") else []
        return {"data": data, "itemCount": len(data), "truncated": False}

    monkeypatch.setattr(environment, "capella_request", request)
    monkeypatch.setattr(environment, "capella_list", listing)

    preview = json.loads(
        environment.handle("capella_env_reap", {"project_id": "test-proj"})[0].text
    )
    real = json.loads(
        environment.handle(
            "capella_env_reap", {"project_id": "test-proj", "dry_run": False}
        )[0].text
    )

    assert preview["would_delete_count"] == 1
    assert len(preview["would_refuse"]) == 1
    assert real["reaped_count"] == preview["would_delete_count"]
    assert len(real["refused"]) == len(preview["would_refuse"])


def test_f23_expired_memo_keys_are_swept_on_write(monkeypatch):
    """Stale keys for scopes never queried again would otherwise persist forever."""
    monkeypatch.setattr(guardrails, "_CEILING_MEMO_SECONDS", 0.0)
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "1")
    for scope in ("org|a", "org|b", "org|c"):
        with pytest.raises(guardrails.GuardrailError):
            guardrails.assert_capacity(1, scope=scope)
    # With a zero-second memo every prior key is expired, so the sweep on each
    # write leaves only the key just stamped.
    assert len(guardrails._ceiling_refusals) == 1


# ── S1: ok() now redacts every successful response ───────────────────────────


def test_s1_successful_responses_are_redacted_by_default():
    """Redaction used to apply only to logs and error context, so any tool
    returning a secret handed it straight to the model. That included read-only
    tools — admin_alerts_get (SMTP password), admin_kmip_get, admin_eventing_get
    (function source, which routinely embeds API keys) — i.e. exactly the set that
    loads in the safe read-only default."""
    from handlers.shared import ok

    payload = json.loads(
        ok({"emailServer": {"user": "svc", "pass": "Sup3rSecret"}})[0].text
    )
    assert payload["emailServer"]["pass"] == "***REDACTED***"
    assert "Sup3rSecret" not in json.dumps(payload)


def test_s1_emailpass_style_field_names_are_caught():
    """`emailPass` does not contain "password", so it slipped the old rule and was
    written to the log in plaintext."""
    from handlers.shared import redact

    masked = redact({"emailHost": "smtp.x", "emailPass": "Sup3rSecret"})
    assert masked["emailPass"] == "***REDACTED***"
    assert masked["emailHost"] == "smtp.x"


def test_s1_only_one_tool_may_emit_credentials():
    """The redaction bypass must stay a single, greppable, justified call site."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    users = []
    for path in root.rglob("*.py"):
        if "test" in path.name or "__pycache__" in str(path):
            continue
        text = path.read_text(encoding="utf-8")
        if "ok_allow_secrets(" in text and "def ok_allow_secrets" not in text:
            users.append(path.name)
    assert users == ["environment.py"], users


def test_s1_env_ensure_can_still_return_the_generated_password():
    """The exception has to actually work, or a provisioned environment is
    unusable."""
    from handlers.shared import ok_allow_secrets

    payload = json.loads(
        ok_allow_secrets({"credential": {"password": "P@ss1"}})[0].text
    )
    assert payload["credential"]["password"] == "P@ss1"


# ── S4: statement chaining in the index DDL parameters ───────────────────────


def test_s4_statement_chaining_is_refused():
    """The validators anchored only at the start, so this passed and was forwarded
    verbatim — relying on the query service's single-statement rule, which this
    server does not own."""
    from handlers.shared import assert_index_create_ddl, assert_index_drop_ddl

    chained = "CREATE INDEX i ON `b`(x); DROP SCOPE `b`.`prod`"
    assert assert_index_create_ddl(chained) is not None
    assert assert_index_drop_ddl("DROP INDEX `b`.`i`; DROP BUCKET `prod`") is not None


def test_s4_comment_tricks_are_refused():
    """A trailing comment silently discards the rest of a generated statement, so
    what executes differs from what was reviewed."""
    from handlers.shared import assert_index_create_ddl

    assert assert_index_create_ddl("CREATE INDEX i ON `b`(x) -- WITH {...}") is not None
    assert assert_index_create_ddl("CREATE INDEX i ON `b`(x) /* WITH */") is not None


def test_s4_legitimate_ddl_still_passes():
    from handlers.shared import assert_index_create_ddl, assert_index_drop_ddl

    assert assert_index_create_ddl("CREATE INDEX i ON `b`(x)") is None
    assert assert_index_create_ddl("BUILD INDEX ON `b`(`i`)") is None
    assert assert_index_drop_ddl("DROP INDEX `b`.`i`") is None
    # A single trailing semicolon is fine — only chaining is refused.
    assert assert_index_create_ddl("CREATE INDEX i ON `b`(x);") is None


# ── S3 / S5: form encoding and retry safety on the self-managed path ─────────


def test_s3_lists_are_json_encoded_not_python_repr():
    """str(list) yields single quotes; on /settings/security's cipherSuites an
    unparseable value means "use defaults" — a silent TLS downgrade."""
    from handlers.shared import form_value

    assert form_value(["TLS_AES_128_GCM_SHA256"]) == '["TLS_AES_128_GCM_SHA256"]'
    assert form_value({"a": 1}) == '{"a": 1}'
    assert form_value(True) == "true"
    assert form_value(False) == "false"
    assert form_value(7) == "7"


def test_s5_admin_request_does_not_retry_mutating_methods_on_5xx():
    """Re-issuing a POST to /controller/failOver because a read timed out is worse
    than reporting the failure."""
    from handlers.shared import _retryable

    assert _retryable(503, "POST") is False
    assert _retryable(500, "POST") is False
    assert _retryable(503, "GET") is True
    assert _retryable(503, "DELETE") is True
    assert _retryable(429, "POST") is True
    assert _retryable(404, "GET") is False


# ── Nothing here may pass vacuously ──────────────────────────────────────────
#
# Every test above asserts inside a `for` over one of these collections, so an
# empty one is a green tick rather than a failure. `test_no_vacuous_coverage.py`
# enforces that this guard exists; the floors below are what it cannot know.

def test_there_is_something_to_test():
    """These four drive every guardrail parametrisation in this file."""
    assert _ALL_OPS, "the Capella operation registry is empty"
    assert CHILD_DESTRUCTIVE, "no destructive child operations to refuse"
    assert CHILD_MUTATING, "no mutating child operations to refuse"
    assert GUARDED_CLUSTER_OPS, (
        "no guarded cluster operations; the unmanaged-cluster and allowlist "
        "refusals are both parametrising over an empty list"
    )
