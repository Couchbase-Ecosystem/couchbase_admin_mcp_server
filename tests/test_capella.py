"""
Tests for the Capella control plane: schema integrity, deployment gating,
guardrails, pagination and path construction.

These run offline. Nothing here calls Capella — the client is stubbed — because
the properties worth testing are the ones that would otherwise fail against a
real organization: a malformed schema, a path placeholder with no matching
argument, a destructive call escaping the sandbox, or a list silently truncating
at one page.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from handlers.capella import TOOLS, client, guardrails
from handlers.capella.spec import OPS, OPS_BY_NAME, build_input_schema

# ── Schema integrity ─────────────────────────────────────────────────────────


def test_tool_names_are_unique():
    names = [t.name for t in TOOLS]
    duplicates = {n for n in names if names.count(n) > 1}
    assert not duplicates, f"duplicate tool names: {duplicates}"


def test_every_tool_has_object_schema():
    for tool in TOOLS:
        assert isinstance(tool.inputSchema, dict)
        assert tool.inputSchema.get("type") == "object"
        assert isinstance(tool.inputSchema.get("properties", {}), dict)


def test_required_fields_are_declared_properties():
    """A required field absent from properties is an invalid JSON schema and some
    clients reject the whole tool list because of it."""
    for tool in TOOLS:
        schema = tool.inputSchema
        properties = set(schema.get("properties", {}))
        for field in schema.get("required", []):
            assert field in properties, (
                f"{tool.name}: required {field!r} not in properties"
            )


def test_every_path_placeholder_is_a_tool_argument():
    """The failure this prevents: a path template referencing {cluster_id} while
    the schema never asks for it, so the call dies on a missing-argument error
    that looks like a Capella problem."""
    for op in OPS:
        placeholders = set(client.extract_placeholders(op.path))
        properties = set(build_input_schema(op).get("properties", {}))
        missing = placeholders - properties
        assert not missing, (
            f"{op.name}: placeholders not exposed as arguments: {missing}"
        )


def test_every_op_path_starts_with_v4():
    for op in OPS:
        assert op.path.startswith("/v4/"), f"{op.name}: {op.path}"


def test_read_only_ops_are_get():
    for op in OPS:
        if op.read_only:
            assert op.method == "GET", (
                f"{op.name} is annotated read-only but uses {op.method}"
            )


def test_non_get_ops_are_not_read_only():
    """Classification drives the read-only filter and the scope gate; a mutating
    op annotated read-only would load in read-only mode and be callable by a
    read-scoped token."""
    for op in OPS:
        if op.method != "GET":
            assert not op.read_only, f"{op.name} mutates but is annotated read-only"


def test_destructive_ops_are_guarded():
    """Every destructive operation must pass through the guardrails; an
    unguarded delete is exactly the failure mode the allowlist exists for."""
    for op in OPS:
        if op.destructive:
            assert op.guarded, f"{op.name} is destructive but not guarded"


def test_app_services_are_under_clusters_except_the_org_wide_list():
    """Regression on the ORIGINAL bug, updated for what a live run then proved.

    The previous implementation pathed App Services under /projects/{p}/appservices, which
    does not exist. Everything moved under /clusters/{cluster_id}/appservices — correct for
    every operation EXCEPT the list.

    Probing the real API showed `GET .../clusters/{id}/appservices` returns 405: that path
    accepts POST only. The sole list operation is organization-wide,
    `GET /v4/organizations/{organizationId}/appservices`, confirmed in Couchbase's own
    OpenAPI document. Because a 405 body yields no id, discovery reported "no App Service
    found" exactly as an empty list would — so every App Services operation was silently
    unreachable and nothing in the code hinted at it.
    """
    org_wide = {"capella_app_services_list"}
    for op in OPS:
        if "appservices" not in op.path:
            continue
        if op.name in org_wide:
            assert op.path == "/v4/organizations/{organization_id}/appservices", op.name
            continue
        assert "/clusters/{cluster_id}/appservices" in op.path, op.name
        assert "/projects/{project_id}/appservices" not in op.path, op.name


def test_the_app_service_certificate_segment_is_plural():
    """`/certificate` 404s; the API spells the segment `/certificates` while naming the
    operation in the singular. Found by diffing against the OpenAPI document."""
    op = OPS_BY_NAME["capella_app_service_certificate_get"]
    assert op.path.endswith("/certificates"), op.path


def test_the_access_control_function_is_keyed_on_a_keyspace():
    """v4 keys this on endpoint.scope.collection, not a bare endpoint name. Passing a bare
    name is accepted and silently interpreted as `<name>._default._default`, so on a
    cluster with named scopes it would target the wrong collection."""
    for name in (
        "capella_app_endpoint_access_control_function_get",
        "capella_app_endpoint_access_control_function_set",
    ):
        assert "{app_endpoint_keyspace}" in OPS_BY_NAME[name].path
        assert "{app_endpoint_name}/accessControlFunction" not in OPS_BY_NAME[name].path


def test_credential_ops_redact_their_response():
    assert OPS_BY_NAME["capella_database_credential_create"].sensitive_response


# ── Path construction ────────────────────────────────────────────────────────


def test_build_path_substitutes_and_encodes():
    path = client.build_path(
        "/v4/organizations/{organization_id}/projects/{project_id}",
        {"organization_id": "org-1", "project_id": "proj 2"},
    )
    assert path == "/v4/organizations/org-1/projects/proj%202"


def test_build_path_encodes_slashes_so_a_value_cannot_escape_its_segment():
    path = client.build_path(
        "/v4/organizations/{organization_id}", {"organization_id": "a/../b"}
    )
    assert path == "/v4/organizations/a%2F..%2Fb"


def test_build_path_refuses_missing_argument():
    with pytest.raises(client.CapellaError) as excinfo:
        client.build_path("/v4/organizations/{organization_id}", {})
    assert "organization_id" in str(excinfo.value)


def test_build_path_refuses_empty_string():
    """An empty value would collapse the path to /clusters//buckets, which
    addresses a different resource rather than failing."""
    with pytest.raises(client.CapellaError):
        client.build_path(
            "/v4/organizations/{organization_id}", {"organization_id": ""}
        )


# ── Pagination ───────────────────────────────────────────────────────────────


def test_capella_list_follows_the_cursor_to_the_last_page(monkeypatch):
    pages = {
        1: {
            "data": [{"id": "a"}, {"id": "b"}],
            "cursor": {"pages": {"page": 1, "last": 3, "totalItems": 5}},
        },
        2: {
            "data": [{"id": "c"}, {"id": "d"}],
            "cursor": {"pages": {"page": 2, "last": 3, "totalItems": 5}},
        },
        3: {
            "data": [{"id": "e"}],
            "cursor": {"pages": {"page": 3, "last": 3, "totalItems": 5}},
        },
    }

    def fake_request(method, path, *, params=None, body=None):
        return pages[params["page"]]

    monkeypatch.setattr(client, "capella_request", fake_request)
    result = client.capella_list("/v4/organizations/o/projects/p/clusters")

    assert result["itemCount"] == 5
    assert result["pagesFetched"] == 3
    assert result["truncated"] is False
    assert [item["id"] for item in result["data"]] == ["a", "b", "c", "d", "e"]


def test_capella_list_reports_truncation_rather_than_silently_shortening(monkeypatch):
    def fake_request(method, path, *, params=None, body=None):
        page = params["page"]
        return {
            "data": [{"id": f"{page}-{i}"} for i in range(100)],
            "cursor": {"pages": {"page": page, "last": 50, "totalItems": 5000}},
        }

    monkeypatch.setattr(client, "capella_request", fake_request)
    result = client.capella_list("/v4/x", max_items=150)

    assert result["truncated"] is True
    assert result["itemCount"] == 150
    assert "note" in result


def test_capella_list_passes_through_a_bare_array(monkeypatch):
    monkeypatch.setattr(
        client, "capella_request", lambda *a, **k: [{"id": "x"}, {"id": "y"}]
    )
    result = client.capella_list("/v4/x")
    assert result["itemCount"] == 2
    assert result["truncated"] is False


# ── Guardrails ───────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clear_capella_env(monkeypatch):
    for key in (
        "CAPELLA_ORG_ID",
        "CAPELLA_ALLOWED_PROJECTS",
        "CAPELLA_ENV_NAME_PREFIX",
        "CAPELLA_MAX_ENVIRONMENTS",
        "CAPELLA_ENV_TTL_HOURS",
        "CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE",
        "CAPELLA_PROTECTED_CLUSTERS",
        "CAPELLA_DEFAULT_PROJECT_ID",
    ):
        monkeypatch.delenv(key, raising=False)


def test_destructive_operations_fail_closed_without_an_allowlist():
    """The out-of-box posture: an unconfigured server can create but refuses to
    delete. Defaulting the other way would make 'delete anything in the org' the
    default for a tool an agent can call."""
    with pytest.raises(guardrails.GuardrailError) as excinfo:
        guardrails.assert_project_allowed("any-project")
    assert "CAPELLA_ALLOWED_PROJECTS" in str(excinfo.value)


def test_project_allowlist_admits_listed_and_refuses_unlisted(monkeypatch):
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj-1,test-proj-2")
    guardrails.assert_project_allowed("test-proj-1")  # must not raise
    with pytest.raises(guardrails.GuardrailError):
        guardrails.assert_project_allowed("production-proj")


def test_unscoped_escape_hatch_lifts_the_requirement(monkeypatch):
    monkeypatch.setenv("CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE", "true")
    guardrails.assert_project_allowed("anything")


def test_organization_pin_refuses_a_conflicting_override(monkeypatch):
    monkeypatch.setenv("CAPELLA_ORG_ID", "org-pinned")
    assert guardrails.resolve_org({}) == "org-pinned"
    assert guardrails.resolve_org({"organization_id": "org-pinned"}) == "org-pinned"
    with pytest.raises(guardrails.GuardrailError):
        guardrails.resolve_org({"organization_id": "org-somewhere-else"})


def test_missing_organization_is_an_explicit_error():
    """The message states the problem; the hint carries the remedy, and the hint
    is what the dispatch surfaces to the agent."""
    with pytest.raises(guardrails.GuardrailError) as excinfo:
        guardrails.resolve_org({})
    assert "organization id" in str(excinfo.value)
    assert "CAPELLA_ORG_ID" in excinfo.value.hint


def test_name_prefix_is_enforced_on_create(monkeypatch):
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    guardrails.assert_name_allowed("mcptest-ios-4821")
    with pytest.raises(guardrails.GuardrailError):
        guardrails.assert_name_allowed("prod-cluster")


def test_delete_refused_when_name_lacks_the_prefix(monkeypatch):
    """The guard against a hand-made production cluster sitting inside an
    allowlisted project."""
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    with pytest.raises(guardrails.GuardrailError) as excinfo:
        guardrails.assert_deletable(
            {"id": "c1", "name": "acme-prod-cluster"}, "test-proj"
        )
    assert "does not start with" in str(excinfo.value)


def test_delete_allowed_for_a_properly_prefixed_cluster(monkeypatch):
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    guardrails.assert_deletable({"id": "c1", "name": "mcptest-ios-1"}, "test-proj")


def test_capella_deletion_protection_is_honored(monkeypatch):
    """A Capella-side setting must not be overridable from an MCP call."""
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    with pytest.raises(guardrails.GuardrailError) as excinfo:
        guardrails.assert_deletable(
            {"id": "c1", "name": "mcptest-x", "deletionProtection": True}, "test-proj"
        )
    assert "deletion protection" in str(excinfo.value).lower()


def test_explicitly_protected_cluster_cannot_be_deleted(monkeypatch):
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.setenv("CAPELLA_PROTECTED_CLUSTERS", "c-keep")
    with pytest.raises(guardrails.GuardrailError):
        guardrails.assert_deletable({"id": "c-keep", "name": "anything"}, "test-proj")


def test_environment_ceiling_blocks_runaway_provisioning(monkeypatch):
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "3")
    guardrails.assert_capacity(2)
    with pytest.raises(guardrails.GuardrailError) as excinfo:
        guardrails.assert_capacity(3)
    assert "ceiling" in str(excinfo.value).lower()


# ── Environment marker ───────────────────────────────────────────────────────


def test_marker_roundtrips():
    marker = guardrails.build_marker("ios-pr-4821", ttl_hours=4, owner="ci-pipeline")
    assert marker.startswith(guardrails.ENV_MARKER_PREFIX)
    parsed = guardrails.parse_marker(marker)
    assert parsed["env"] == "ios-pr-4821"
    assert parsed["ttl_h"] == 4
    assert parsed["owner"] == "ci-pipeline"


def test_marker_survives_surrounding_human_text():
    marker = guardrails.build_marker("env-1", ttl_hours=1)
    description = f"Scratch cluster for the phone app.\n{marker}\nAsk Chris."
    assert guardrails.parse_marker(description)["env"] == "env-1"


def test_malformed_marker_is_ignored_not_fatal():
    """A reap sweep must not crash on a description someone hand-edited."""
    assert guardrails.parse_marker("mcp-env:{not valid json") is None
    assert guardrails.parse_marker("no marker here") is None
    assert guardrails.parse_marker(None) is None


def test_unmarked_cluster_is_not_recognized_as_managed():
    assert guardrails.parse_marker("A cluster someone made by hand") is None


def test_expiry_is_computed_from_created_plus_ttl():
    created = datetime(2026, 7, 29, 12, 0, 0, tzinfo=timezone.utc)
    marker = guardrails.build_marker("e", ttl_hours=4, now=created)
    parsed = guardrails.parse_marker(marker)
    assert guardrails.marker_expiry(parsed) == created + timedelta(hours=4)
    assert not guardrails.is_expired(parsed, now=created + timedelta(hours=3))
    assert guardrails.is_expired(parsed, now=created + timedelta(hours=5))


def test_zero_ttl_means_never_expire():
    """A pinned long-lived environment must be immune to the reaper."""
    marker = guardrails.parse_marker(guardrails.build_marker("e", ttl_hours=0))
    assert guardrails.marker_expiry(marker) is None
    assert guardrails.is_expired(marker) is False


# ── Deployment gating ────────────────────────────────────────────────────────


def test_capella_host_detection():
    import deployment

    assert deployment.looks_like_capella_host(
        "couchbases://cb.abc123.cloud.couchbase.com"
    )
    assert not deployment.looks_like_capella_host(
        "couchbases://db.internal.acme.example"
    )


def test_mode_detection(monkeypatch):
    import deployment

    monkeypatch.delenv("CB_DEPLOYMENT", raising=False)
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbases://cb.x.cloud.couchbase.com")
    monkeypatch.delenv("CAPELLA_API_KEY_SECRET", raising=False)
    assert deployment.detect_mode() == deployment.CAPELLA

    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://onprem.local")
    assert deployment.detect_mode() == deployment.SELF_MANAGED

    # Both configured: the operator plainly intends to drive both sides.
    monkeypatch.setenv("CAPELLA_API_KEY_SECRET", "secret")
    assert deployment.detect_mode() == deployment.BOTH

    monkeypatch.setenv("CB_DEPLOYMENT", "capella")
    assert deployment.detect_mode() == deployment.CAPELLA


def test_ns_server_admin_tools_are_unavailable_on_capella():
    import deployment

    assert not deployment.tool_is_available("admin_bucket_create", deployment.CAPELLA)
    assert not deployment.tool_is_available("admin_rebalance_start", deployment.CAPELLA)
    assert not deployment.tool_is_available("admin_stats_bucket", deployment.CAPELLA)


def test_sql_and_capella_tools_are_available_on_capella():
    import deployment

    # SDK / SQL++ diagnostics need no admin REST.
    assert deployment.tool_is_available("cb_index_advisor", deployment.CAPELLA)
    assert deployment.tool_is_available("cb_explain_query", deployment.CAPELLA)
    # Documented as reachable with a database credential.
    assert deployment.tool_is_available("admin_prometheus_targets", deployment.CAPELLA)
    assert deployment.tool_is_available("capella_env_ensure", deployment.CAPELLA)


def test_capella_tools_are_hidden_on_self_managed():
    import deployment

    assert not deployment.tool_is_available(
        "capella_env_ensure", deployment.SELF_MANAGED
    )
    assert deployment.tool_is_available("admin_bucket_create", deployment.SELF_MANAGED)


def test_both_mode_gates_nothing():
    import deployment

    assert deployment.tool_is_available("admin_bucket_create", deployment.BOTH)
    assert deployment.tool_is_available("capella_env_ensure", deployment.BOTH)


def test_unavailable_reason_names_the_alternative():
    import deployment

    reason = deployment.unavailable_reason("admin_bucket_create", deployment.CAPELLA)
    assert "capella_" in reason
    assert "Full Admin" in reason


# ── Guardrail refusals reach the caller as structured errors ──────────────────


def test_guardrail_refusal_is_reported_with_the_policy(monkeypatch):
    """An agent that hits a refusal needs to see what the policy is, or it will
    retry the same call forever."""
    from handlers import capella

    monkeypatch.setenv("CAPELLA_ORG_ID", "org-1")
    monkeypatch.delenv("CAPELLA_ALLOWED_PROJECTS", raising=False)

    result = capella.handle(
        "capella_cluster_delete", {"project_id": "prod", "cluster_id": "c1"}
    )
    payload = json.loads(result[0].text)
    assert payload["guardrail"] is True
    assert "policy" in payload
    assert payload["policy"]["destructive_operations_enabled"] is False


def test_guardrails_status_tool_reports_posture(monkeypatch):
    from handlers import capella

    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "p1")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    payload = json.loads(capella.handle("capella_guardrails_status", {})[0].text)
    assert payload["posture"] == "sandboxed"
    assert payload["allowed_projects"] == ["p1"]
    assert payload["name_prefix"] == "mcptest-"


# ── Diff against Couchbase's own OpenAPI document ────────────────────────────
#
# Every path below was read out of the spec at
# docs.couchbase.com/cloud/management-api-reference (the embedded Redoc state, which is
# the machine-readable OpenAPI document rather than scraped prose) and cross-checked
# against the Terraform provider's Go string literals where one exists.
#
# This table exists because reading the code could not have found these. A live probe
# returned 405 for the App Services list, and only then did diffing against the spec show
# that the cluster-scoped collection is POST-only. Recording the authoritative shape here
# means the next such divergence fails a test instead of failing in a customer's pipeline.

_BASE = (
    "/v4/organizations/{organization_id}/projects/{project_id}"
    "/clusters/{cluster_id}/appservices"
)

#: (operation, expected method, expected path)
AUTHORITATIVE_APP_SERVICE_PATHS = [
    # The list is ORG-WIDE. There is no cluster-scoped list, and no clusterId query
    # parameter — callers filter on each item's clusterId field.
    (
        "capella_app_services_list",
        "GET",
        "/v4/organizations/{organization_id}/appservices",
    ),
    ("capella_app_service_create", "POST", _BASE),
    ("capella_app_service_get", "GET", f"{_BASE}/{{app_service_id}}"),
    ("capella_app_service_delete", "DELETE", f"{_BASE}/{{app_service_id}}"),
    # activationState, with a capital S and no trailing segment. POST resumes, DELETE
    # suspends. Not to be confused with the App ENDPOINT equivalent, which is
    # activationStatus.
    (
        "capella_app_service_turn_on",
        "POST",
        f"{_BASE}/{{app_service_id}}/activationState",
    ),
    (
        "capella_app_service_turn_off",
        "DELETE",
        f"{_BASE}/{{app_service_id}}/activationState",
    ),
    (
        "capella_app_service_admin_users_list",
        "GET",
        f"{_BASE}/{{app_service_id}}/adminUsers",
    ),
    (
        "capella_app_service_admin_user_create",
        "POST",
        f"{_BASE}/{{app_service_id}}/adminUsers",
    ),
    (
        "capella_app_service_admin_user_delete",
        "DELETE",
        f"{_BASE}/{{app_service_id}}/adminUsers/{{admin_user_id}}",
    ),
    # Plural segment, singular operation name — the trap that made this 404.
    (
        "capella_app_service_certificate_get",
        "GET",
        f"{_BASE}/{{app_service_id}}/certificates",
    ),
    # allowedcidrs is all lowercase, unlike its camelCase siblings.
    (
        "capella_app_service_allowed_cidrs_list",
        "GET",
        f"{_BASE}/{{app_service_id}}/allowedcidrs",
    ),
    (
        "capella_app_service_allowed_cidr_create",
        "POST",
        f"{_BASE}/{{app_service_id}}/allowedcidrs",
    ),
    (
        "capella_app_service_allowed_cidr_delete",
        "DELETE",
        f"{_BASE}/{{app_service_id}}/allowedcidrs/{{allowed_cidr_id}}",
    ),
    # App ENDPOINT activation is activationStatus — Status, not State.
    (
        "capella_app_endpoint_online",
        "POST",
        f"{_BASE}/{{app_service_id}}/appEndpoints/{{app_endpoint_name}}/activationStatus",
    ),
    (
        "capella_app_endpoint_offline",
        "DELETE",
        f"{_BASE}/{{app_service_id}}/appEndpoints/{{app_endpoint_name}}/activationStatus",
    ),
    # Resync start and status share one path, distinguished only by method.
    (
        "capella_app_endpoint_resync_start",
        "POST",
        f"{_BASE}/{{app_service_id}}/appEndpoints/{{app_endpoint_name}}/resync",
    ),
    (
        "capella_app_endpoint_resync_status",
        "GET",
        f"{_BASE}/{{app_service_id}}/appEndpoints/{{app_endpoint_name}}/resync",
    ),
]


@pytest.mark.parametrize(
    ("name", "method", "path"),
    AUTHORITATIVE_APP_SERVICE_PATHS,
    ids=lambda v: str(v)[:40],
)
def test_app_service_paths_match_the_openapi_document(name, method, path):
    op = OPS_BY_NAME[name]
    assert op.method == method, f"{name}: method"
    assert op.path == path, f"{name}: path"


def test_the_authoritative_table_covers_every_app_service_operation():
    """Guards the table above from silently going stale.

    A new App Services operation added to spec.py without a line here would otherwise be
    unverified while the suite stayed green — which is exactly how the list path went
    wrong.
    """
    tabled = {name for name, _, _ in AUTHORITATIVE_APP_SERVICE_PATHS}
    in_spec = {
        op.name
        for op in OPS
        if "appservices" in op.path and "appEndpoints" not in op.path
    }
    # App Endpoint operations are a larger subtree; only the ones in the table are pinned.
    missing = in_spec - tabled
    assert not missing, (
        f"App Services operations with no authoritative path pinned: {sorted(missing)}"
    )


# ── App Service node count ───────────────────────────────────────────────────
#
# A live run answered `{"nodes": 1}` with
#
#   422 {"code":422,"message":"The instance desired capacity must be between 2 and 12."}
#
# spec.py stated the opposite ("2 is the documented minimum for HA; 1 suffices for testing"),
# and the same wrong value was hard-coded in capella_env_create's App Service phase — so that
# phase could never have succeeded. Nothing caught it because no test creates an App Service,
# and the docs describe 2 as the HA minimum, which reads like an availability recommendation
# rather than a hard floor.
#
# These pin the corrected value at every site that carries one.


def test_the_app_service_node_floor_is_two():
    """Not 1. The API refuses 1 with a 422, whatever the documentation implies."""
    from handlers.capella import spec

    assert spec.MIN_APP_SERVICE_NODES == 2
    assert spec.MAX_APP_SERVICE_NODES == 12


def test_env_create_requests_at_least_the_minimum_node_count():
    """The regression that mattered: capella_env_create hard-coded 1, so the App Service
    phase of the primary environment tool failed every time it ran."""
    import inspect

    from handlers.capella import environment, spec

    # Comment lines are excluded: the comment that explains this bug quotes the bad literal
    # verbatim, so a naive substring search over the whole source reports the explanation as
    # the violation. Same trap as the mcp_compat field scan.
    code = [
        line
        for line in inspect.getsource(environment).splitlines()
        if not line.lstrip().startswith("#")
    ]
    offenders = [line.strip() for line in code if '"nodes": 1' in line]
    assert not offenders, (
        "capella_env_create is back to requesting a single App Service node, which Capella "
        f"refuses with a 422: {offenders}"
    )
    assert any('"nodes": MIN_APP_SERVICE_NODES' in line for line in code)
    assert spec.MIN_APP_SERVICE_NODES >= 2


def test_the_documented_node_description_does_not_claim_one_works():
    """The description is what the model reads before choosing a value. It previously told
    the model that 1 was fine for testing, which is the value that 422s."""
    from handlers.capella import spec

    description = spec._APP_SERVICE_CREATE_BODY["nodes"]["description"]
    assert "1 suffices" not in description
    assert str(spec.MIN_APP_SERVICE_NODES) in description


def test_the_verifier_and_the_spec_agree_on_the_node_floor():
    """The verify script cannot import spec — it must run with nothing installed, and falls
    back to parsing spec.py with `ast`. So the constant is duplicated, and this is what keeps
    the copy honest."""
    import pathlib
    import re

    from handlers.capella import spec

    script = (
        pathlib.Path(__file__).resolve().parent.parent
        / "scripts"
        / "verify_capella_paths.py"
    ).read_text(encoding="utf-8")

    match = re.search(r"^_MIN_APP_SERVICE_NODES\s*=\s*(\d+)", script, re.MULTILINE)
    assert match, "the verify script no longer declares _MIN_APP_SERVICE_NODES"
    assert int(match.group(1)) == spec.MIN_APP_SERVICE_NODES

    # And it must actually be used in the request body, not merely declared.
    assert '"nodes": _MIN_APP_SERVICE_NODES' in script
