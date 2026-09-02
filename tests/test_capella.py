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
import re
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


# ── The live verification record ─────────────────────────────────────────────


def test_every_operation_has_been_verified_against_a_live_organization():
    """Makes "all 61 paths are verified" a CHECKED property of the source.

    It was previously a claim in a commit message, and the last time such a claim was made
    it was wrong: `--only-pat` reported an all-clear covering ten unverified paths because
    its selector missed the tag form actually in use. An operation added later, or one whose
    verification lapses, now fails here instead of being quietly assumed.
    """
    from handlers.capella import spec

    # SHIPPED_UNVERIFIED is subtracted, not ignored. Those operations ship on a primary
    # source plus a confirmed sibling, and they say so in their own tool description. The
    # register is the thing that keeps this test meaningful: without it the only way to
    # ship one was to invent a LIVE_VERIFIED entry, which is precisely the false claim
    # this test was written to catch.
    declared = {op.name for op in OPS} - set(spec.SHIPPED_UNVERIFIED)
    recorded = set(spec.LIVE_VERIFIED)
    assert recorded == declared, (
        "the live verification record and the operation registry disagree.\n"
        f"  never verified: {sorted(declared - recorded)}\n"
        f"  recorded but no longer an operation: {sorted(recorded - declared)}"
    )


def test_the_recorded_statuses_are_ones_that_prove_a_route_matched():
    """A status the API can only produce AFTER routing. Anything else is not evidence — a
    connection error or a 404 with no domain code would mean the path was never confirmed."""
    from handlers.capella import spec

    for name, status in spec.LIVE_VERIFIED.items():
        assert status in {"200", "400", "404", "405", "422"}, (
            f"{name}: implausible status {status}"
        )


def test_every_read_operation_was_verified_by_a_real_call():
    """A GET is CALLED for real, so it must have answered 200 — or 404 with a Capella domain
    code, which still proves the handler ran. A read recorded as 405 would mean it was
    probed with OPTIONS instead, i.e. never actually exercised."""
    from handlers.capella import spec

    for op in OPS:
        if op.method == "GET" and op.name not in spec.SHIPPED_UNVERIFIED:
            assert spec.LIVE_VERIFIED[op.name] in {"200", "404"}, (
                f"{op.name} is a GET but was only OPTIONS-probed ("
                f"{spec.LIVE_VERIFIED[op.name]}), so its method was never confirmed"
            )


#: Statuses a write may be recorded with, and what each proves.
#:
#:   405  an OPTIONS probe matched the route and was refused for the method. Confirms
#:        the PATH and says nothing about the method. The weakest of the three.
#:   422  the operation's OWN method was sent and the request was refused on its
#:        CONTENTS or on entitlement. Confirms path AND method, and nothing ran.
#:   400  the same, for endpoints that answer 400 where others answer 422.
#:
#: 422 and 400 were added on 2026-09-01. This test previously demanded 405 exactly, on
#: the reasoning that "a write verified by anything other than an OPTIONS probe means
#: something was actually performed" — which predates --method-probe and is not true of
#: it: an empty body that comes back 422 is the proof that nothing was performed. The
#: live case that forced the question was PUT .../auditLog answering
#: "your support package does not include audit logging", which is a real PUT, refused,
#: with the cluster untouched.
#:
#: A 2xx is still absent and must stay absent. That would mean the write happened.
_WRITE_EVIDENCE = frozenset({"400", "405", "422"})


def test_write_operations_are_path_verified_only_and_that_is_deliberate():
    """405 is the expected result for a write: the OPTIONS probe matched the route and was
    refused for the method, mutating nothing.

    This test exists to record that the weaker evidence is a CHOICE, not an oversight — and
    to keep the distinction visible, because it is exactly the gap that let three wrong
    request bodies sit behind verified paths.
    """
    from handlers.capella import spec

    writes = [
        op
        for op in OPS
        if op.method != "GET" and op.name not in spec.SHIPPED_UNVERIFIED
    ]
    assert writes, "expected write operations to exist"
    for op in writes:
        assert spec.LIVE_VERIFIED[op.name] in _WRITE_EVIDENCE, (
            f"{op.name} recorded {spec.LIVE_VERIFIED[op.name]}; the only statuses that "
            "prove a route without performing the operation are "
            f"{sorted(_WRITE_EVIDENCE)}"
        )


def test_the_verification_date_is_recorded():
    """Provenance without a date is not provenance. Capella's control plane is not frozen,
    so a reader needs to know how old this evidence is."""
    import re

    from handlers.capella import spec

    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", spec.LIVE_VERIFIED_ON), (
        spec.LIVE_VERIFIED_ON
    )


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


# ── Request bodies corrected against live 422s and the OpenAPI document ──────
#
# Three bodies in this registry were wrong, and all three were wrong in the same direction:
# a REQUIRED field declared optional, or a field misnamed. None could be caught by a path
# probe, because an OPTIONS probe sends no body at all — so `[LIVE 405]` on these operations
# proved the route and said nothing about the payload.
#
# The corrections come from live rejections plus Capella's published OpenAPI document
# (CreateAppServiceAdminUserRequest, CreateAppEndpointRequest).


def test_a_database_credential_requires_a_permission_grant():
    """Capella refuses a credential with no grant:

        422 "Can not create new dataplane user without at least (1) valid permission
             being specified"

    Declaring `access` optional told the model the minimal call was name-only, which is
    exactly the call that always fails.
    """
    from handlers.capella import spec

    op = spec.OPS_BY_NAME["capella_database_credential_create"]
    assert "access" in op.body_required
    assert "name" in op.body_required
    # `password` stays OPTIONAL on purpose: omitting it works, and Capella then generates one
    # and returns it once, which keeps a secret out of the caller's prompt.
    assert "password" not in op.body_required


def test_an_app_service_admin_user_requires_name_password_and_access():
    """The live 422 said "contains or lacks both ..." — `access` was missing entirely."""
    from handlers.capella import spec

    op = spec.OPS_BY_NAME["capella_app_service_admin_user_create"]
    assert set(op.body_required) == {"name", "password", "access"}
    assert "access" in op.body


def test_the_admin_user_access_field_documents_its_one_of():
    """`access` is a oneOf: EXACTLY one of `accessAllEndpoints` or `endpoints`. Both or
    neither is the 422. The description is what the model reads before constructing the body,
    so the constraint has to live there and not only in a comment."""
    from handlers.capella import spec

    description = spec.OPS_BY_NAME["capella_app_service_admin_user_create"].body[
        "access"
    ]["description"]
    assert "accessAllEndpoints" in description
    assert "endpoints" in description
    assert "both" in description.lower()


def test_the_spec_warns_that_a_false_all_endpoints_flag_is_rejected():
    """The trap that caught me.

    `{'accessAllEndpoints': false}` looks like the least-privilege choice and is in fact
    NEITHER of the two valid shapes: it grants nothing, and Capella rejects it with the same
    422 as omitting `access` entirely —

        "contains or lacks both, list of endpoints and all endpoints flag."

    There is no "no access" form; to restrict a user you list endpoints. A careful reader
    reaching for the safer-looking option gets an error that does not explain itself, so the
    description has to say so.
    """
    from handlers.capella import spec

    description = spec.OPS_BY_NAME["capella_app_service_admin_user_create"].body[
        "access"
    ]["description"]
    # The exact rejected form, spelled out. Asserting merely that the word "false" appears
    # is not enough — an earlier version of this test passed while the sentence tying
    # `false` to "grants nothing, and is rejected" had been deleted, because "never both and
    # never neither" elsewhere still contained the words being matched.
    assert "'accessAllEndpoints': false" in description
    assert "rejects" in description
    assert "no access" in description, (
        "the description should say there is no 'no access' form, since that is the thing a "
        "careful reader will look for"
    )


def test_the_app_endpoint_delta_sync_field_is_named_correctly():
    """`deltaSyncEnabled`, not `deltaSync`.

    The worst kind of wrong name: v4 ignores an unrecognised field rather than rejecting it,
    so `deltaSync: true` returns 201 and delta sync is simply never enabled. There is no
    error to notice.
    """
    from handlers.capella import spec

    body = spec.OPS_BY_NAME["capella_app_endpoint_create"].body
    assert "deltaSyncEnabled" in body
    assert "deltaSync" not in body


def test_the_app_endpoint_requires_only_a_name_and_bucket():
    """`scopes` is optional — omitting it uses the default scope and collection. Marking it
    required would make the simplest valid call impossible to express."""
    from handlers.capella import spec

    op = spec.OPS_BY_NAME["capella_app_endpoint_create"]
    assert set(op.body_required) == {"name", "bucket"}


def test_the_app_endpoint_scopes_description_states_the_one_scope_limit():
    """Capella permits ONLY ONE scope per App Endpoint. A model handed a multi-scope mapping
    shape would produce a body that is rejected, or worse, partially honoured."""
    from handlers.capella import spec

    description = spec.OPS_BY_NAME["capella_app_endpoint_create"].body["scopes"][
        "description"
    ]
    assert "one scope" in description.lower()
    assert "collections" in description


def test_the_app_endpoint_is_addressed_by_name_not_by_id():
    """Creation answers 201 with an EMPTY body, so there is no id to return — and none is
    needed. Every path in the subtree takes {app_endpoint_name}. A path here that expected an
    id would be unusable."""
    from handlers.capella import spec

    subtree = [
        op
        for op in spec.OPS
        if "/appEndpoints/" in op.path and "app_endpoint" in op.path
    ]
    assert subtree, "expected App Endpoint sub-paths to exist"
    for op in subtree:
        assert (
            "{app_endpoint_name}" in op.path or "{app_endpoint_keyspace}" in op.path
        ), f"{op.name} addresses an App Endpoint by something other than its name"


def test_bucket_flush_is_a_put():
    """It shipped as POST. The path was OPTIONS-probed and recorded [LIVE 405], which is
    true and irrelevant: a 405 from OPTIONS confirms the route and says nothing about which
    method the route accepts. The Terraform provider's generated client — generated from
    Couchbase's own API document — issues PUT.

    Pinned because the failure is quiet. A caller asking to flush a bucket got a 405 that
    reads like an entitlement problem, on the one operation whose purpose is a fast reset
    between test runs, so it would be retried rather than investigated.
    """
    from handlers.capella import spec

    flush = spec.OPS_BY_NAME["capella_bucket_flush"]
    assert flush.method == "PUT", (
        "capella_bucket_flush must be PUT; POST returns 405 and looks like a permissions "
        "failure rather than a wrong method"
    )
    assert flush.path.endswith("/buckets/{bucket_id}/flush")


#: Shipped write operations that genuinely take NO request body. Each needs a reason,
#: because "no body" and "we never worked out the body" look identical in the code and
#: only the second is a defect.
#: DELETE is excluded wholesale rather than listed here — a DELETE identifies its target
#: entirely by path, and requiring a body schema for one would be noise.
_WRITES_WITH_NO_BODY = {
    # The provider's NewPostBackupRequest takes no body argument: the bucket in the path
    # is the whole request.
    "capella_backup_create",
    # ACTION endpoints: the path names both the target and the verb, so there is nothing
    # left for a body to say. All of these predate the 2026-09-01 promotion and have
    # shipped this way throughout; they are listed to make the claim explicit rather than
    # implicit, not because anything about them changed.
    "capella_app_endpoint_offline",
    "capella_app_endpoint_online",
    "capella_app_endpoint_resync_start",
    "capella_app_service_turn_off",
    "capella_app_service_turn_on",
    "capella_bucket_flush",
    "capella_cluster_turn_off",
}


def test_no_shipped_write_tool_is_missing_its_body_schema():
    """A write with body={} renders as a TOOL WITH NO WAY TO SEND A BODY.

    This is not cosmetic. capella_query_index_manage shipped that way, and its input
    schema was {organization_id, project_id, cluster_id, confirm} — no `definition`, the
    one field the operation exists to carry. The tool could be called and could not
    possibly work.

    It happened because a promotion was made on PATH verification alone: an OPTIONS probe
    confirms a route and says nothing about what the route wants. The registry's own
    test_write_operations_are_path_verified_only_and_that_is_deliberate says exactly that,
    and names it as "the gap that let three wrong request bodies sit behind verified
    paths". Wrong bodies were the earlier symptom; absent ones are this one.
    """
    from handlers.capella import spec

    missing = [
        op.name
        for op in OPS
        if op.method not in ("GET", "DELETE")
        # body_scalar counts: a body that IS a JSON string is still a declared body. It
        # lives in its own field because almost every v4 endpoint takes an object and
        # exactly one does not.
        and not (op.body or op.body_scalar)
        and op.name not in _WRITES_WITH_NO_BODY
    ]
    assert not missing, (
        "these shipped write operations declare no request body, so their tools expose "
        f"no way to send one: {sorted(missing)}.\n"
        "Either give each a body schema from a primary source, or add it to "
        "_WRITES_WITH_NO_BODY with the evidence that it takes none."
    )

    stale = sorted(_WRITES_WITH_NO_BODY - {op.name for op in spec.OPS})
    assert not stale, f"exempted operations that no longer exist: {stale}"


def test_a_required_body_field_is_actually_in_the_schema():
    """body_required naming a field the schema does not define would make the tool
    unsatisfiable: the caller is told a field is required and given nowhere to put it."""
    for op in OPS:
        undeclared = [f for f in op.body_required if f not in (op.body or {})]
        assert not undeclared, (
            f"{op.name} requires {undeclared}, which its body schema does not define"
        )


def test_no_write_is_recorded_with_a_success_status():
    """The one status a write must never carry. 2xx means the operation RAN — a bucket
    was deleted, a cluster was created, a restore overwrote a target. Recording it as
    evidence would mean the verification run itself did the damage, and the record would
    read as a clean pass.
    """
    from handlers.capella import spec

    performed = {
        op.name: spec.LIVE_VERIFIED[op.name]
        for op in OPS
        if op.method != "GET"
        and op.name not in spec.SHIPPED_UNVERIFIED
        and spec.LIVE_VERIFIED[op.name].startswith("2")
    }
    assert not performed, (
        f"these writes are recorded with a SUCCESS status: {performed}. Either the probe "
        "performed them, or someone recorded a status by hand. Both need investigating "
        "before this is treated as verification."
    )


def test_an_opaque_object_is_not_accepted_as_a_body_schema():
    """A body of {"type": "object"} with no properties passes the "has a body" guard and
    tells a caller nothing — the body={} defect wearing a different hat.

    capella_alert_integration_create shipped that way for config.webhook and a live 422
    named what was missing: "does not provide a valid authentication method". A caller
    could not have known to send one.
    """

    def _opaque(schema, path):
        found = []
        if not isinstance(schema, dict):
            return found
        if schema.get("type") == "object" and not schema.get("properties"):
            # A free-form map (headers, settings, filters) is legitimately shapeless; it
            # says so in its description rather than being silently empty.
            if "description" not in schema:
                found.append(path)
        for key, value in (schema.get("properties") or {}).items():
            found += _opaque(value, f"{path}.{key}")
        return found

    offenders = []
    for op in OPS:
        for field, schema in (op.body or {}).items():
            offenders += _opaque(schema, f"{op.name}.{field}")
    assert not offenders, (
        "these body fields are typed `object` with neither properties nor a description "
        f"saying why they are free-form: {sorted(offenders)}"
    )


def test_the_alert_integration_writes_are_guarded_and_say_why():
    """These three are the only shipped operations where CALLING THE TOOL makes Capella
    open a connection to a host the caller named.

    Observed live: creating an integration pointed at https://example.com produced
    "Received 405 while trying to connect", with the remote page's HTML quoted back inside
    the error. So the create is a synchronous outbound request carrying caller-supplied
    credentials, and its error carries whatever the probed host returned.

    Two consequences this pins: the operations must be `guarded` so the egress allowlist
    runs before the call, and the summary must SAY the request happens at create time —
    a reader who thinks it merely stores config will place the allowlist check in the
    wrong place.
    """
    from handlers.capella.spec import OPS_BY_NAME

    for name in (
        "capella_alert_integration_create",
        "capella_alert_integration_update",
        "capella_alert_integration_test",
    ):
        op = OPS_BY_NAME.get(name)
        if op is None:
            continue  # still parked; nothing shipped, nothing to guard
        assert op.guarded, f"{name} performs egress and must be guarded"

    create = OPS_BY_NAME["capella_alert_integration_create"]
    assert "EGRESS" in create.summary
    assert "SSRF" in create.summary, (
        "the summary must name the shape of the hazard, not just the word 'egress' — "
        "'names an outbound destination' reads as configuration, and it is a request"
    )


# ── The unverified register ──────────────────────────────────────────────────


def test_every_unverified_operation_gives_a_reason_and_exists():
    """A name in this register with no reason is an exemption nobody can review — and the
    register only earns its place by being reviewable. It exists so that shipping without
    live evidence is a recorded decision rather than a faked LIVE_VERIFIED entry.
    """
    from handlers.capella import spec

    names = {op.name for op in OPS}
    for name, reason in spec.SHIPPED_UNVERIFIED.items():
        assert name in names, (
            f"{name} is registered as shipped-unverified but is not in OPS. Either it "
            "was promoted out of this state and the entry was left behind, or it never "
            "shipped."
        )
        assert len(reason) > 80, (
            f"{name}: the reason must say what evidence DOES exist and what is missing, "
            "not just that it is unverified"
        )
        assert re.search(r"\d{4}-\d{2}-\d{2}", reason), (
            f"{name}: the reason must carry the DATE the exception was made. Without one "
            "there is no telling a decision taken today from one nobody has revisited in "
            "a year, and this register is only safe while that is visible."
        )
        assert name not in spec.LIVE_VERIFIED, (
            f"{name} is in both registers. It is either verified or it is not."
        )


def test_the_unverified_register_stays_small():
    """A ceiling, because the pressure on this register is always one more exception.

    It was 4, and moved to 8 on 2026-09-01 — the same day it was written. That is worth
    being uncomfortable about, so here is the distinction being drawn:

      * ONE batch decision, taken once, for one reason: unblock a customer evaluation on
        operations whose paths are sourced and whose siblings are confirmed live, in an
        organization that cannot produce the objects needed to finish the job.
      * NOT accretion — a name added here every few weeks because verifying was
        inconvenient that day.

    A cap that moves once with a reason is still a cap. A cap that moves whenever it fires
    is decoration. If it fires again, read the DATES: entries that have sat here across
    several rounds of verification are the evidence this became a habit.
    """
    from handlers.capella import spec

    assert len(spec.SHIPPED_UNVERIFIED) <= 8, (
        f"{len(spec.SHIPPED_UNVERIFIED)} operations now ship without live verification: "
        f"{sorted(spec.SHIPPED_UNVERIFIED)}"
    )


def test_an_unverified_operation_warns_in_its_own_description():
    """The register is not where a caller looks. A model deciding whether to trust a 404
    from one of these needs to know at the point of use that the path itself is unproven.
    """
    from handlers.capella import spec

    tools = {t.name: t for t in spec.build_tools()}
    for name in spec.SHIPPED_UNVERIFIED:
        assert "UNVERIFIED PATH" in tools[name].description, (
            f"{name} ships unverified and its tool description does not say so"
        )
    verified = next(n for n in spec.LIVE_VERIFIED if n in tools)
    assert "UNVERIFIED PATH" not in tools[verified].description
    # And the notice must not begin "[PAT", which the verifier reads as the inferred-path
    # provenance tag. Two different states; one substring away from being the same one.
    assert not spec._UNVERIFIED_NOTICE.startswith("[PAT")


def test_the_parked_registry_is_allowed_to_be_empty():
    """Reaching zero is the goal, not a broken import.

    spec_pending.py opened the day with 36 records and ended it with none. Several tests
    needed a parked operation to point at, and the honest fix was for them to SKIP rather
    than fail — a suite that goes red when the work is finished teaches people to leave one
    behind.
    """
    from handlers.capella import spec_pending

    assert isinstance(spec_pending.PENDING_OPS, tuple)
    assert all(hasattr(op, "path") for op in spec_pending.PENDING_OPS)


def test_the_only_scalar_body_is_the_one_that_needs_to_be():
    """`body_scalar` exists for PUT .../eventingFunctions/{name}/code, whose request body
    is the JavaScript source as a bare JSON string rather than an object.

    Pinned narrowly because the field is an escape hatch. If a second operation acquires
    one, that is worth a look — either v4 has more non-object bodies than we thought, or
    someone reached for the hatch instead of writing a schema.
    """
    scalar = {op.name for op in OPS if op.body_scalar}
    assert scalar == {"capella_eventing_function_code_set"}, scalar

    op = OPS_BY_NAME["capella_eventing_function_code_set"]
    assert op.body_scalar["type"] == "string"
    assert not op.body, "an operation declares either an object body or a scalar one"

    schema = build_input_schema(op)
    assert schema["properties"]["body"]["type"] == "string"
    assert "body" in schema["required"]


def test_replication_create_records_the_stronger_evidence():
    """It was [LIVE 405] — path only — and became [LIVE+METHOD 422] without a single new
    API call being designed for it.

    --method-probe can only send an operation's real method where the operation declares
    required body fields, because that is what guarantees an empty body is refused. So
    filling in the request-body schema is what made the stronger check possible: the next
    run sent a real POST and got 422, proving the method is accepted and nothing was
    created.

    Worth pinning because the causal direction is easy to get backwards. Schemas are not
    only documentation for callers — they are what lets the verifier do more than knock on
    the door.
    """
    from handlers.capella import spec

    assert spec.LIVE_VERIFIED["capella_replication_create"] == "422"
    op = spec.OPS_BY_NAME["capella_replication_create"]
    assert op.body_required, (
        "the 422 evidence depends on this operation declaring required body fields; "
        "clearing them silently downgrades the check to an OPTIONS probe"
    )
    assert "LIVE+METHOD" in op.summary


def test_the_destructive_exclusion_shows_up_in_the_record():
    """capella_replication_delete sat next to a live replication and was STILL probed with
    OPTIONS, because it is destructive. That is the exclusion added earlier working on a
    real object rather than in a test double — with a real id available, the empty-body
    probe was the one thing that could have deleted it."""
    from handlers.capella import spec

    assert spec.LIVE_VERIFIED["capella_replication_delete"] == "405"
    assert spec.OPS_BY_NAME["capella_replication_delete"].destructive


def test_a_base64_path_id_survives_encoding():
    """XDCR replication ids are not UUIDs. Capella returns them base64-encoded, padding
    included: NTYyNmM0ZTc4...aGFydmVzdGVy== decodes to
    "5626c4e78606fd10b8b61c19197a8218/harvester/harvester" — a value containing BOTH '='
    and, once decoded, '/'.

    An unencoded '=' in a path segment is merely rude; an unencoded '/' would address a
    different resource entirely. quote_segment handles both, and this pins it: the id
    shape was only observed for the first time on 2026-09-02, and every other v4 path
    parameter in the registry is a UUID or a plain name, so nothing else would catch a
    regression here.
    """
    from handlers.capella.client import build_path

    replication_id = (
        "NTYyNmM0ZTc4NjA2ZmQxMGI4YjYxYzE5MTk3YTgyMTgvaGFydmVzdGVyL2hhcnZlc3Rlcg=="
    )
    rendered = build_path(
        OPS_BY_NAME["capella_replication_get"].path,
        {
            "organization_id": "O",
            "project_id": "P",
            "cluster_id": "C",
            "replication_id": replication_id,
        },
    )
    assert rendered.endswith("/replications/" + replication_id.replace("=", "%3D"))
    assert "==" not in rendered

    # And the decoded form, in case Capella ever hands back the un-encoded value.
    decoded = "5626c4e78606fd10b8b61c19197a8218/harvester/harvester"
    rendered = build_path(
        OPS_BY_NAME["capella_replication_get"].path,
        {
            "organization_id": "O",
            "project_id": "P",
            "cluster_id": "C",
            "replication_id": decoded,
        },
    )
    assert rendered.count("/replications/") == 1
    assert "%2F" in rendered, (
        "a decoded replication id contains slashes; leaving them unencoded would address "
        "a different resource"
    )


# ── Mutation anchors ─────────────────────────────────────────────────────────


def test_every_mutation_anchor_still_matches_its_target():
    """A mutation whose anchor no longer matches tests NOTHING, and the guard it was
    written for silently becomes unverified.

    The harness gets this right — it reports ANCHOR-GONE and fails the run rather than
    counting it as a pass. What it cannot do is be quick about it: the anchors are checked
    while applying 173 mutations across a matrix of Python versions, so a one-character
    drift costs a nine-minute CI round trip to discover.

    This is the same check, done in milliseconds, on the same data. It went in after
    `LIVE_VERIFIED_ON = "2026-07-30"` was anchored by its literal value and the date moved
    the moment 36 operations were verified against a live organization — which is to say,
    the anchor broke on exactly the event the mutation exists to protect.
    """
    import importlib.util
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    scripts = sorted(root.glob("scripts/mutation*.py"))
    assert scripts, "no mutation scripts found; this test has gone stale"

    stale: list[str] = []
    checked = 0
    for script in scripts:
        spec = importlib.util.spec_from_file_location(script.stem, script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        mutations = getattr(module, "MUTATIONS", None)
        assert mutations, f"{script.name} defines no MUTATIONS"

        for entry in mutations:
            label, relpath, old = entry[0], entry[1], entry[2]
            text = (root / relpath).read_text(encoding="utf-8")
            for anchor in old if isinstance(old, list) else [old]:
                checked += 1
                if anchor not in text:
                    stale.append(f"{script.name}: {label} — {relpath}")

    assert not stale, (
        f"{len(stale)} mutation anchor(s) no longer match their target file, so those "
        "mutations test nothing:\n  " + "\n  ".join(stale)
    )
    assert checked > 100, f"only {checked} anchors checked; suspiciously few"
