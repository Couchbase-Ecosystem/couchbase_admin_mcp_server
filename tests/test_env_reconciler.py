"""
`capella_env_ensure`: the reconciler that stands an environment up phase by phase.

WHY A RECONCILER, AND WHY THAT MATTERS FOR TESTS
===============================================
Provisioning a Capella environment takes minutes, and the MCP call that starts it cannot block
for that long. So `capella_env_ensure` is idempotent and phase-returning: each call advances
what it can, reports the phase reached, and is expected to be called again.

That design is what makes the failure modes interesting:

  * **It must adopt what already exists.** A second call that created a second cluster would
    be a billed duplicate — and the reason the Capella client refuses to retry a POST is that
    the reconciler's next pass is the recovery path.
  * **The project must never be guessed.** Defaulting to "the first project the key can see"
    would let a sandbox workflow build in production. It defaults only when the allowlist
    leaves exactly one possibility.
  * **The credential password is returned once.** Capella does not hand it back, so a call
    that creates a credential and swallows the password leaves an unusable environment.

Every Capella call is stubbed at `_invoke`, because what is being tested is the ORDER and the
IDEMPOTENCE, not the client.
"""

from __future__ import annotations

import json

import pytest
from mcp.types import TextContent

from handlers.capella import environment, guardrails

# ── A recording stand-in for the control plane ───────────────────────────────


class _Capella:
    """Answers each v4 operation from an in-memory model of what exists."""

    def __init__(self, **existing):
        self.calls: list[tuple[str, dict]] = []
        self.clusters: list[dict] = existing.get("clusters", [])
        self.buckets: list[dict] = existing.get("buckets", [])
        self.scopes: list[dict] = existing.get("scopes", [])
        self.collections: list[dict] = existing.get("collections", [])
        self.credentials: list[dict] = existing.get("credentials", [])
        self.app_services: list[dict] = existing.get("app_services", [])
        self.cidrs: list[dict] = existing.get("cidrs", [])

    def __call__(self, op_name, base, body=None, **kwargs):
        self.calls.append((op_name, body or {}))
        listings = {
            "capella_clusters_list": self.clusters,
            "capella_buckets_list": self.buckets,
            "capella_scopes_list": self.scopes,
            "capella_collections_list": self.collections,
            "capella_database_credentials_list": self.credentials,
            "capella_app_services_list": self.app_services,
            "capella_allowed_cidrs_list": self.cidrs,
        }
        if op_name in listings:
            return {"data": list(listings[op_name])}
        if op_name == "capella_cluster_get":
            return {"data": self.clusters[0] if self.clusters else {}}
        if op_name.endswith("_create"):
            return {"data": {"id": f"new-{op_name}", **(body or {})}}
        return {"data": {}}

    def created(self) -> list[str]:
        return [name for name, _body in self.calls if name.endswith("_create")]


HEALTHY_CLUSTER = {
    "id": "cluster-1",
    "name": "verify-env",
    "currentState": "healthy",
    "connectionString": "couchbases://cb.example.com",
}


@pytest.fixture
def reconciler(monkeypatch):
    """`environment` with `_invoke` recorded and the guardrail policy permissive."""
    capella = _Capella(clusters=[HEALTHY_CLUSTER])
    monkeypatch.setattr(environment, "_invoke", capella, raising=False)

    monkeypatch.setenv("CAPELLA_ORG_ID", "org-1")
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "proj-1")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "verify-")
    monkeypatch.setenv("CAPELLA_ALLOW_DESTRUCTIVE", "true")
    return capella


def _body(result) -> dict:
    assert isinstance(result, list) and result
    assert isinstance(result[0], TextContent)
    return json.loads(result[0].text)


# ── The project is never guessed ─────────────────────────────────────────────


def test_a_single_allowlisted_project_is_used_as_the_default(reconciler, monkeypatch):
    """Unambiguous: one allowlisted project is the only place this server may operate, so
    defaulting to it cannot pick the wrong target."""
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "only-project")
    monkeypatch.delenv("CAPELLA_DEFAULT_PROJECT_ID", raising=False)

    policy = guardrails.load_policy()
    assert policy.allowed_projects == ("only-project",)
    _org, project, _policy = environment._resolve_context({})
    assert project == "only-project"


def test_several_allowlisted_projects_refuse_to_guess(monkeypatch):
    """THE property. Picking "the first project the key can see" would let a sandbox workflow
    build in production, and the caller would have no indication which was chosen."""
    monkeypatch.setenv("CAPELLA_ORG_ID", "org-1")
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "sandbox-a,sandbox-b")
    monkeypatch.delenv("CAPELLA_DEFAULT_PROJECT_ID", raising=False)

    assert len(guardrails.load_policy().allowed_projects) == 2

    with pytest.raises(guardrails.GuardrailError) as excinfo:
        environment._resolve_context({})
    assert "unambiguous" in str(excinfo.value) or "project_id" in str(excinfo.value)


def test_an_explicit_default_project_is_honoured(monkeypatch):
    monkeypatch.setenv("CAPELLA_ORG_ID", "org-1")
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "a,b")
    monkeypatch.setenv("CAPELLA_DEFAULT_PROJECT_ID", "b")
    _org, project, _policy = environment._resolve_context({})
    assert project == "b"


def test_an_argument_beats_the_default(monkeypatch):
    monkeypatch.setenv("CAPELLA_ORG_ID", "org-1")
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "a,b")
    monkeypatch.setenv("CAPELLA_DEFAULT_PROJECT_ID", "b")
    _org, project, _policy = environment._resolve_context({"project_id": "a"})
    assert project == "a"


def test_a_project_outside_the_allowlist_is_refused(monkeypatch):
    """The allowlist is the sandbox boundary, and an explicit argument must not cross it.

    Asserted on `assert_project_allowed`, which is where the check lives. `_resolve_context`
    only RESOLVES — enforcement happens per operation inside `_invoke`, which is what makes
    it apply to every guarded call rather than only to the ones that resolve context.
    """
    monkeypatch.setenv("CAPELLA_ORG_ID", "org-1")
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "sandbox")

    guardrails.assert_project_allowed("sandbox")  # must not raise
    with pytest.raises(guardrails.GuardrailError):
        guardrails.assert_project_allowed("production")


# ── Idempotence: adopt, do not duplicate ─────────────────────────────────────


def test_an_existing_cluster_is_adopted_rather_than_recreated(reconciler):
    """The recovery path for every failed create. A second cluster would be a billed
    duplicate, and it is why the Capella client deliberately does not retry a POST."""
    _body(
        environment.handle(
            "capella_env_ensure", {"env_name": "verify-env", "project_id": "proj-1"}
        )
    )
    assert "capella_cluster_create" not in reconciler.created()


def test_a_missing_cluster_is_created(reconciler):
    """Guards the adoption test from passing because nothing is ever created."""
    reconciler.clusters = []
    _body(
        environment.handle(
            "capella_env_ensure", {"env_name": "verify-env", "project_id": "proj-1"}
        )
    )
    assert "capella_cluster_create" in reconciler.created()


def test_an_existing_bucket_is_adopted(reconciler):
    reconciler.buckets = [{"id": "b1", "name": "app"}]
    _body(
        environment.handle(
            "capella_env_ensure",
            {"env_name": "verify-env", "project_id": "proj-1", "bucket_name": "app"},
        )
    )
    assert "capella_bucket_create" not in reconciler.created()


def test_a_missing_bucket_is_created(reconciler):
    reconciler.buckets = []
    _body(
        environment.handle(
            "capella_env_ensure",
            {"env_name": "verify-env", "project_id": "proj-1", "bucket_name": "app"},
        )
    )
    assert "capella_bucket_create" in reconciler.created()


def test_a_scope_and_collection_are_created_under_the_bucket(reconciler):
    reconciler.buckets = [{"id": "b1", "name": "app"}]
    _body(
        environment.handle(
            "capella_env_ensure",
            {
                "env_name": "verify-env",
                "project_id": "proj-1",
                "bucket_name": "app",
                "scope_name": "sync",
                "collection_name": "docs",
            },
        )
    )
    created = reconciler.created()
    assert "capella_scope_create" in created
    assert "capella_collection_create" in created


def test_an_existing_scope_is_not_recreated(reconciler):
    reconciler.buckets = [{"id": "b1", "name": "app"}]
    reconciler.scopes = [{"name": "sync"}]
    _body(
        environment.handle(
            "capella_env_ensure",
            {
                "env_name": "verify-env",
                "project_id": "proj-1",
                "bucket_name": "app",
                "scope_name": "sync",
            },
        )
    )
    assert "capella_scope_create" not in reconciler.created()


def test_a_collection_is_only_attempted_when_one_was_asked_for(reconciler):
    """Creating a collection nobody requested would add a keyspace the caller has to clean
    up, and `_default` already exists."""
    reconciler.buckets = [{"id": "b1", "name": "app"}]
    _body(
        environment.handle(
            "capella_env_ensure",
            {
                "env_name": "verify-env",
                "project_id": "proj-1",
                "bucket_name": "app",
                "scope_name": "sync",
            },
        )
    )
    assert "capella_collection_create" not in reconciler.created()


# ── The credential password is returned once ─────────────────────────────────


def test_a_created_credential_returns_its_password_with_a_warning(reconciler):
    """Capella never hands it back. A reconciler that creates a credential and swallows the
    password leaves an environment nothing can connect to."""
    reconciler.credentials = []
    body = _body(
        environment.handle(
            "capella_env_ensure", {"env_name": "verify-env", "project_id": "proj-1"}
        )
    )
    credential = body.get("credential") or {}
    assert credential.get("password"), "the generated password was not returned"
    assert "password_note" in credential
    assert "only on creation" in credential["password_note"]


def test_an_existing_credential_says_the_password_cannot_be_recovered(reconciler):
    """The honest answer. Reporting the credential as ready without a password would send the
    caller looking for a value that does not exist anywhere."""
    reconciler.credentials = [{"id": "u1", "name": "testapp"}]
    body = _body(
        environment.handle(
            "capella_env_ensure", {"env_name": "verify-env", "project_id": "proj-1"}
        )
    )
    credential = body.get("credential") or {}
    assert not credential.get("password")
    assert "delete" in json.dumps(credential).lower()


def test_a_generated_password_is_long_and_random(reconciler):
    reconciler.credentials = []
    seen = set()
    for _ in range(5):
        reconciler.credentials = []
        reconciler.calls.clear()
        body = _body(
            environment.handle(
                "capella_env_ensure", {"env_name": "verify-env", "project_id": "proj-1"}
            )
        )
        seen.add(body["credential"]["password"])
    assert len(seen) == 5, "generated passwords repeat"
    assert all(len(p) >= 16 for p in seen)


# ── Phase reporting ──────────────────────────────────────────────────────────


def test_a_healthy_cluster_reports_a_terminal_phase(reconciler):
    body = _body(
        environment.handle(
            "capella_env_ensure", {"env_name": "verify-env", "project_id": "proj-1"}
        )
    )
    assert body["phase"] in ("ready", "creating_app_service", "waiting_for_app_service")


def test_a_deploying_cluster_reports_that_it_is_waiting(reconciler):
    """The caller polls. Reporting "ready" here would have it connect to a cluster that is
    not accepting connections yet."""
    reconciler.clusters = [{**HEALTHY_CLUSTER, "currentState": "deploying"}]
    body = _body(
        environment.handle(
            "capella_env_ensure", {"env_name": "verify-env", "project_id": "proj-1"}
        )
    )
    assert "wait" in body["phase"] or body["phase"] == "creating_cluster"
    assert body.get("retry_after_s")


def test_a_failed_deployment_is_reported_rather_than_polled_forever(reconciler):
    """`deploymentFailed` is terminal. Treating it as in-flight would poll until the caller
    gave up, with no indication anything was wrong."""
    reconciler.clusters = [{**HEALTHY_CLUSTER, "currentState": "deploymentFailed"}]
    body = _body(
        environment.handle(
            "capella_env_ensure", {"env_name": "verify-env", "project_id": "proj-1"}
        )
    )
    assert "failed" in json.dumps(body).lower()


def test_the_actions_taken_are_reported(reconciler):
    """So a caller polling every 30 seconds can tell progress from a stall."""
    reconciler.clusters = []
    body = _body(
        environment.handle(
            "capella_env_ensure", {"env_name": "verify-env", "project_id": "proj-1"}
        )
    )
    assert body.get("actions")


def test_the_connection_string_is_reported_once_the_cluster_is_healthy(reconciler):
    body = _body(
        environment.handle(
            "capella_env_ensure", {"env_name": "verify-env", "project_id": "proj-1"}
        )
    )
    assert body.get("connection_string") == "couchbases://cb.example.com"


# ── The name prefix is a guardrail, not a convention ─────────────────────────


def test_a_name_outside_the_prefix_is_refused(monkeypatch):
    """The prefix is how the reaper tells this server's ephemeral clusters from everything else
    in the organization. A cluster created outside it would never be cleaned up, and a reaper
    that matched everything would delete things it did not create.

    Asserted on `assert_name_allowed` rather than through `capella_env_ensure`, because the
    check runs INSIDE `_invoke` — which this file stubs. Driving it through the handler
    reported `creating_cluster` for a name called "production-db", and the reason was that my
    own stub had removed the guardrail. Testing a guard through a layer that replaces it is
    worse than not testing it: it looks like coverage of the guard.
    """
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "verify-")

    guardrails.assert_name_allowed("verify-ok")  # must not raise
    with pytest.raises(guardrails.GuardrailError) as excinfo:
        guardrails.assert_name_allowed("production-db")
    assert "verify-" in str(excinfo.value)


def test_the_environment_create_path_goes_through_the_guarded_invoker(reconciler):
    """The corollary. Every mutating call must be made via `_invoke`, because that is where
    the project allowlist and the name prefix are enforced. A handler that called
    `capella_request` directly would bypass both."""
    import inspect

    reconciler.clusters = []
    environment.handle(
        "capella_env_ensure", {"env_name": "verify-ok", "project_id": "proj-1"}
    )
    assert "capella_cluster_create" in reconciler.created()

    # Parsed, and scoped to the FUNCTION each call sits in. `_invoke` itself calls
    # `capella_request` — that is the whole point of it — so a flat "does this string appear"
    # check fails on the correct code, which is what the first version of this did.
    import ast

    tree = ast.parse(inspect.getsource(environment))
    offenders = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if function.name in ("_invoke",):
            continue
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("capella_request", "capella_list")
            ):
                offenders.append(f"{function.name}:{node.lineno}")

    assert not offenders, (
        "these reach the control plane directly instead of going through _invoke, so the "
        f"project allowlist, the name prefix and the hard ceiling do not apply: {offenders}"
    )
