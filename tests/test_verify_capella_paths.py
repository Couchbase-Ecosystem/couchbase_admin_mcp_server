"""
Tests for the Capella path-verification script, against a FAKE Capella.

A verification tool that reports the wrong answer is worse than none: it would either
send someone chasing a path that is fine, or certify one that is broken. So the script's
logic is exercised against a local HTTP server that behaves like v4 — including the
awkward parts (a 404 whose body says the ROUTE matched and the OBJECT was absent, and a
405 from the OPTIONS probe) — before it is ever pointed at a real organization.
"""

from __future__ import annotations

import http.server
import importlib.util
import json
import os
import pathlib
import socket
import threading
from typing import ClassVar

import pytest

SCRIPT = (
    pathlib.Path(__file__).resolve().parent.parent
    / "scripts"
    / "verify_capella_paths.py"
)


def _load(base_url: str):
    """Import the script with its API base pointed at the fake server."""
    os.environ["CB_CAPELLA_API_URL"] = base_url
    spec = importlib.util.spec_from_file_location("verify_capella_paths", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ── A fake Capella ───────────────────────────────────────────────────────────

REAL_ROUTES = {
    "/v4/organizations/ORG/projects": ["GET"],
    "/v4/organizations/ORG/projects/PROJ/clusters": ["GET", "POST"],
    "/v4/organizations/ORG/projects/PROJ/clusters/CL/buckets": ["GET", "POST"],
    "/v4/organizations/ORG/projects/PROJ/clusters/CL/appservices": ["GET"],
    # A route that exists but where the named object does not — the case that must NOT
    # be reported MISSING.
    "/v4/organizations/ORG/projects/PROJ/clusters/CL/buckets/GONE": ["GET"],
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    #: Set by a test to make the key see several organizations.
    orgs: ClassVar[list] = [{"data": {"id": "ORG", "name": "the customer"}}]

    def _route(self):
        path = self.path.split("?")[0]
        if path == "/v4/organizations":
            return self._send(200, {"data": _Handler.orgs})
        if path == "/v4/organizations/ORG/projects":
            return self._send(200, {"data": [{"id": "PROJ"}]})
        if path == "/v4/organizations/ORG/projects/PROJ/clusters":
            if self.command == "GET":
                return self._send(200, {"data": [{"id": "CL"}]})
            return self._send(405, {"message": "method not allowed"})
        if path == "/v4/organizations/ORG/projects/PROJ/clusters/CL/buckets":
            if self.command == "GET":
                # The INTERNAL bucket is listed first, as it was on the real
                # organization. Taking item [0] is what picked N1QL_SYSTEM_BUCKET.
                return self._send(
                    200,
                    {
                        "data": [
                            {"id": "TjFRTF9TWVNURU1fQlVDS0VU"},
                            {"id": "BKT", "name": "travel"},
                        ]
                    },
                )
            if self.command == "POST":
                # What Capella really does with an empty body on a create: the method is
                # accepted and the PAYLOAD is rejected, so nothing is created.
                return self._send(422, {"message": "name is required"})
            return self._send(405, {"message": "method not allowed"})
        if path.endswith("/buckets/BKT/scopes"):
            return self._send(200, {"data": [{"name": "inventory"}]})
        if path.endswith("/scopes/inventory/collections"):
            return self._send(200, {"data": [{"name": "airline"}]})
        if path == "/v4/organizations/ORG/appservices":
            # Org-wide list, as the real API defines it. Empty here, so App Services
            # paths are SKIPPED downstream — which is what a project with no App
            # Service should produce.
            return self._send(200, {"data": []})
        if path == "/v4/organizations/ORG/projects/PROJ/clusters/CL/appservices":
            # POST-only in the real API; a GET here is 405. Kept so a regression that
            # re-points discovery at the cluster path fails loudly.
            return self._send(405, {"message": "method not allowed"})
        if path.endswith("/onOffSchedule"):
            # Verbatim shape of the real response, which the first version of the
            # detector misread as MISSING.
            return self._send(
                404,
                {
                    "code": 11040,
                    "hint": (
                        "Returned from the API when a database does not have an "
                        "existing On/Off schedule."
                    ),
                    "httpStatusCode": 404,
                    "message": "Failed to get On/Off schedule",
                },
            )
        # ── Routes only the PARKED set touches ──────────────────────────────
        #
        # Three of the four are themselves parked list paths, which is why discovery
        # prints their status: an empty list and a wrong URL are indistinguishable from
        # an absent identifier, and only one of them is a finding.
        if path == "/v4/organizations/ORG/projects/PROJ/clusters/CL/backups":
            return self._send(200, {"data": [{"id": "BKP"}]})
        if path == "/v4/organizations/ORG/projects/PROJ/events":
            return self._send(200, {"data": [{"id": "EVT"}]})
        if path == "/v4/organizations/ORG/projects/PROJ/clusters/CL/auditLogExports":
            # 200 with NO items: the path is right, this cluster simply has no export
            # jobs. export_id must stay absent rather than be invented.
            return self._send(200, {"data": []})
        if path == "/v4/organizations/ORG/projects/PROJ/alertIntegrations":
            return self._send(200, {"data": [{"id": "ALERT"}]})
        if path.endswith("/queryService/indexes"):
            return self._send(200, {"data": [{"indexName": "def_primary"}]})
        if path.endswith("/eventingFunctions"):
            return self._send(200, {"data": [{"name": "enrich"}]})
        if path.endswith("/replications"):
            # 404 on a PARKED list path is a FINDING: the record in spec_pending.py is
            # wrong, not the cluster empty.
            return self._send(404, {"message": "route not found"})

        if path.endswith("/buckets/GONE"):
            return self._send(
                404, {"message": "bucket GONE does not exist in cluster CL"}
            )
        return self._send(404, {"message": "route not found"})

    # BaseHTTPRequestHandler dispatches on these exact names, so the casing is the
    # stdlib's contract rather than a style choice.
    do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = _route  # noqa: N815


@pytest.fixture(scope="module")
def fake_capella():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def script(fake_capella, monkeypatch):
    monkeypatch.setenv("CB_CAPELLA_API_KEY", "fake-secret")
    return _load(fake_capella)


class _Args:
    def __init__(self, **kw):
        self.org = "ORG"
        self.project = None
        self.cluster = None
        self.only_pat = False
        self.only = []
        self.write_probe = False
        self.json = False
        self.__dict__.update(kw)


class _Op:
    """A test double for handlers.capella.spec.Op.

    `destructive` defaults to False, matching the real dataclass. It has to be present:
    `_is_destructive` fails CLOSED, so a double that simply omits the attribute is treated
    as destructive — correct for an unknown operation, and wrong for a stand-in whose
    real counterpart declares False. Leaving it off made every double look destructive to
    the --method-probe exclusion, which is a test-double artifact rather than a finding.

    Tests that want the fail-closed path exercise it with their own bare object; see
    test_an_unknown_destructive_flag_fails_closed.
    """

    def __init__(
        self, name, method, path, summary="", group="g", body=None, destructive=False
    ):
        self.name = name
        self.method = method
        self.path = path
        self.summary = summary
        self.group = group
        self.body = body
        self.destructive = destructive


# ── Discovery ────────────────────────────────────────────────────────────────


def test_discovery_finds_real_identifiers(script, capsys):
    """Filling paths with a made-up UUID would make every nested path 404 and report
    MISSING for paths that are correct. So discovery is what keeps the tool honest."""
    ids = script.discover("fake-secret", _Args())
    assert ids["organization_id"] == "ORG"
    assert ids["project_id"] == "PROJ"
    assert ids["cluster_id"] == "CL"
    assert ids["bucket_id"] == "BKT"
    assert ids["scope_name"] == "inventory"
    # No App Service exists, so its id must be ABSENT rather than invented.
    assert "app_service_id" not in ids
    # ...but a collection IS discoverable, which is what turns capella_collection_delete
    # from a permanent SKIPPED into a real verdict. Without this the two collection
    # paths — half the reason this script exists — could never be verified at all.
    assert ids["collection_name"] == "airline"


def test_the_inferred_collection_paths_get_a_real_verdict(script):
    """The point of the deepened discovery: [PAT] paths must be EXERCISED, not skipped.

    A verification tool that reports SKIPPED for the very paths it was written to check
    has told you nothing, and it would do that silently.
    """
    ids = script.discover("fake-secret", _Args())
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella.spec import OPS_BY_NAME

    for name in ("capella_collection_create", "capella_collection_delete"):
        op = OPS_BY_NAME[name]
        path, missing = script.fill(op.path, ids)
        assert path is not None, f"{name} still cannot be filled: missing {missing}"


def test_explicit_ids_win_over_discovery(script):
    ids = script.discover("fake-secret", _Args(project="P2", cluster="C2"))
    assert ids["project_id"] == "P2"
    assert ids["cluster_id"] == "C2"


def test_a_bare_array_response_is_understood(script):
    """v4 is not uniform: some endpoints wrap lists in {"data": ...}, some do not."""
    assert script._first_id('[{"id": "X"}]', "id") == "X"
    assert script._first_id('{"data": [{"id": "Y"}]}', "id") == "Y"
    assert script._first_id('{"data": []}', "id") is None
    assert script._first_id("not json", "id") is None


# ── Verdicts ─────────────────────────────────────────────────────────────────


def test_an_existing_get_route_is_verified(script):
    op = _Op("cb_projects", "GET", "/v4/organizations/{organization_id}/projects")
    result = script.probe(op, {"organization_id": "ORG"}, "k", False)
    assert result.verdict == "VERIFIED", result.detail


def test_a_nonexistent_route_is_missing(script):
    op = _Op("cb_bogus", "GET", "/v4/organizations/{organization_id}/nope")
    result = script.probe(op, {"organization_id": "ORG"}, "k", False)
    assert result.verdict == "MISSING"
    assert result.status == 404


def test_a_write_route_is_verified_without_writing(script):
    """The OPTIONS probe: a 405 proves the route exists, and nothing was mutated."""
    op = _Op(
        "cb_cluster_create",
        "POST",
        "/v4/organizations/{organization_id}/projects/{project_id}/clusters",
    )
    ids = {"organization_id": "ORG", "project_id": "PROJ"}
    result = script.probe(op, ids, "k", False)
    assert result.verdict == "VERIFIED"
    assert result.status == 405


def test_a_missing_write_route_is_still_detected(script):
    op = _Op(
        "cb_bogus_create",
        "POST",
        "/v4/organizations/{organization_id}/projects/{project_id}/widgets",
    )
    result = script.probe(
        op, {"organization_id": "ORG", "project_id": "PROJ"}, "k", False
    )
    assert result.verdict == "MISSING"


def test_a_route_that_matched_with_an_absent_object_is_not_missing(script):
    """The false-positive trap: v4 returns 404 both for an unknown ROUTE and for a known
    route naming an object that does not exist. Reporting the second as MISSING would
    send someone to fix a path that is perfectly correct."""
    op = _Op(
        "cb_bucket_get",
        "GET",
        "/v4/organizations/{organization_id}/projects/{project_id}"
        "/clusters/{cluster_id}/buckets/{bucket_id}",
    )
    ids = {
        "organization_id": "ORG",
        "project_id": "PROJ",
        "cluster_id": "CL",
        "bucket_id": "GONE",
    }
    result = script.probe(op, ids, "k", False)
    assert result.verdict == "VERIFIED", result.detail
    assert "object absent" in result.detail


def test_an_undiscoverable_identifier_yields_skipped_not_missing(script):
    """No App Service exists in the target project, so its sub-paths cannot be
    exercised. That is not evidence the path is wrong."""
    op = _Op(
        "cb_app_service_get",
        "GET",
        "/v4/organizations/{organization_id}/appservices/{app_service_id}",
    )
    result = script.probe(op, {"organization_id": "ORG"}, "k", False)
    assert result.verdict == "SKIPPED"
    assert "app_service_id" in result.detail


def test_path_placeholders_are_url_encoded(script):
    filled, missing = script.fill(
        "/v4/x/{scope_name}/y", {"scope_name": "my scope/with slash"}
    )
    assert missing == []
    assert " " not in filled and "my%20scope%2Fwith%20slash" in filled


# ── The command-line contract ────────────────────────────────────────────────


def test_it_refuses_to_run_with_no_api_key(script, monkeypatch, capsys):
    monkeypatch.delenv("CB_CAPELLA_API_KEY", raising=False)
    monkeypatch.setattr("sys.argv", ["verify", "--org", "ORG"])
    assert script.main() == 2
    assert "CB_CAPELLA_API_KEY" in capsys.readouterr().err


def test_write_probe_requires_an_explicit_operation_list(script, monkeypatch, capsys):
    """A blanket --write-probe across 61 operations would create and delete real
    infrastructure. It must be impossible to trigger by accident."""
    monkeypatch.setattr("sys.argv", ["verify", "--org", "ORG", "--write-probe"])
    assert script.main() == 2
    assert "requires --only" in capsys.readouterr().err


def test_an_unknown_operation_name_is_rejected(script, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv", ["verify", "--org", "ORG", "--only", "capella_not_a_real_tool"]
    )
    assert script.main() == 2
    assert "unknown operation" in capsys.readouterr().err


def test_no_inferred_paths_left_is_a_success_not_an_error(script, monkeypatch, capsys):
    """When every path cites a primary source, --only-pat has nothing to check.

    Exiting non-zero for that would fail a CI step for having succeeded, which is how a
    useful check gets removed from the pipeline.
    """
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella.spec import OPS_BY_NAME

    if any("[PAT]" in (o.summary or "") for o in OPS_BY_NAME.values()):
        pytest.skip("inferred paths still exist; the other test covers that case")

    monkeypatch.setattr("sys.argv", ["verify", "--org", "ORG", "--only-pat"])
    assert script.main() == 0
    assert "No [PAT] paths remain" in capsys.readouterr().out


def test_only_pat_selects_exactly_the_inferred_paths(script, monkeypatch, capsys):
    """The [PAT] operations are the whole reason this script exists, so the selector that
    isolates them is worth pinning.

    The expected count is DERIVED from the registry rather than hard-coded. It was
    hard-coded to 4, and the moment two of those paths were confirmed against a live
    organization and retagged [LIVE], the test failed for a reason that was the opposite
    of a problem. A test that punishes progress gets deleted rather than fixed.
    """
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella.spec import OPS_BY_NAME

    expected = {n for n, o in OPS_BY_NAME.items() if "[PAT]" in (o.summary or "")}
    if not expected:
        pytest.skip("no inferred paths remain; covered by the test above")

    monkeypatch.setattr("sys.argv", ["verify", "--org", "ORG", "--only-pat", "--json"])
    script.main()
    payload = json.loads(_last_json(capsys))
    assert payload["counts"], payload
    assert all(r["inferred"] for r in payload["results"]), [
        r["name"] for r in payload["results"] if not r["inferred"]
    ]
    assert {r["name"] for r in payload["results"]} == expected


def _last_json(capsys):
    out = capsys.readouterr().out
    start = out.index("{")
    return out[start:]


def test_the_real_spec_has_no_unfillable_placeholders():
    """Every placeholder in every real path must be one discovery knows how to supply,
    or the operation can never be verified and would sit at SKIPPED forever."""
    import re

    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella.spec import OPS_BY_NAME

    discoverable = {
        "organization_id",
        "project_id",
        "cluster_id",
        "bucket_id",
        "scope_name",
        "app_service_id",
        # Only exist after a create; SKIPPED for these is correct and expected.
        "collection_name",
        "app_endpoint_keyspace",
        "admin_user_id",
        "credential_id",
        "app_endpoint_name",
        "user_id",
        "api_key_id",
        "allowed_cidr_id",
        "network_peer_id",
        "backup_id",
        "certificate_id",
        "sample_name",
        "event_id",
        # Discovered from the eventing list, which is why the eventing operations could
        # be promoted at all. Added here when they shipped on 2026-09-01 — this guard is
        # what says "a shipped path must be one the verifier can actually reach", and it
        # fired the moment they moved across.
        "function_name",
        # Discovered from the replications list. Registered when the two replication
        # operations shipped on 2026-09-01 under SHIPPED_UNVERIFIED — this guard says "a
        # shipped path must be one the verifier can reach", and that holds whether or not
        # the path has been verified yet. If anything it matters MORE for those.
        "replication_id",
        # From the index sweep, registered when the query-index operations shipped.
        "index_name",
        # From the sampleBuckets list, registered when capella_sample_bucket_get and
        # _delete shipped on 2026-09-14. That list is itself one of the operations
        # being verified, which is the documented pattern in this script: a discovery
        # call doubles as a probe of the list path, because "none exist" and "we asked
        # the wrong URL" are indistinguishable from an empty ids dict.
        "sample_bucket_id",
        # From the per-bucket backup/cycles list. Registered ahead of the operation
        # that needs it: capella_bucket_backup_cycle_get is still PARKED, because the
        # discovery looked for `cycleId` and the rows carry `cycleID`. Fixed the same
        # day; the guard covers the path either way.
        "cycle_id",
        # Registered when the alert-integration trio and the audit-log export getter
        # shipped under SHIPPED_UNVERIFIED on 2026-09-01. Discovery already looks for
        # both; the objects simply do not exist in the test organization.
        "alert_integration_id",
        "export_id",
        "audit_log_id",
        "on_off_schedule_id",
        "free_tier_cluster_id",
    }
    unknown: dict[str, set[str]] = {}
    for op in OPS_BY_NAME.values():
        for placeholder in re.findall(r"\{(\w+)\}", op.path):
            if placeholder not in discoverable:
                unknown.setdefault(placeholder, set()).add(op.name)
    assert not unknown, (
        "paths use placeholders the verification script cannot supply: "
        + str({k: sorted(v) for k, v in unknown.items()})
    )


# ── The zero-dependency fallback ─────────────────────────────────────────────


def test_the_static_parse_matches_the_real_registry(script):
    """The fallback must agree with the authority, or it is worse than not having one.

    spec.py imports mcp.types to build MCP tool objects, so importing the registry needs
    the SDK and a working project install. This script only needs the URL templates, and
    the natural time to run it is on a fresh checkout or in a CI step that has installed
    nothing — so it falls back to reading the Op(...) declarations with `ast`.

    A fallback that disagreed with the registry would verify paths the server does not
    actually use, which is the one failure that would make the whole tool misleading. So
    the two are compared field by field.
    """
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella.spec import OPS_BY_NAME

    root = pathlib.Path(__file__).resolve().parent.parent
    static = script._ops_by_static_parse(str(root / "handlers" / "capella" / "spec.py"))

    assert len(static) == len(OPS_BY_NAME), (
        f"static parse found {len(static)} ops, the registry has {len(OPS_BY_NAME)}"
    )

    by_name = {op.name: op for op in static}
    assert set(by_name) == set(OPS_BY_NAME)
    for name, real in OPS_BY_NAME.items():
        assert by_name[name].path == real.path, f"{name}: path differs"
        assert by_name[name].method == real.method, f"{name}: method differs"


def test_the_static_parse_preserves_the_provenance_tags(script):
    """--only-pat selects on the summary text, so the fallback has to carry it or the
    inferred paths could not be isolated without the SDK installed.

    Compared against the registry rather than a fixed number, so confirming a path and
    retagging it [LIVE] does not break this.
    """
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella.spec import OPS_BY_NAME

    root = pathlib.Path(__file__).resolve().parent.parent
    static = script._ops_by_static_parse(str(root / "handlers" / "capella" / "spec.py"))

    for tag in ("[PAT]", "[LIVE]", "[TF]", "[DOC]"):
        from_static = {op.name for op in static if tag in (op.summary or "")}
        from_registry = {n for n, o in OPS_BY_NAME.items() if tag in (o.summary or "")}
        assert from_static == from_registry, (
            f"{tag} tags differ between parse and registry"
        )


def test_load_ops_prefers_the_real_registry(script):
    """The import is the authority and must be tried first; the parse is only a
    fallback. If this inverted, the tool would stop reflecting what the server runs."""
    ops = script.load_ops()
    from handlers.capella.spec import Op

    assert ops and isinstance(ops[0], Op), (
        "load_ops returned statically-parsed ops even though the registry imports"
    )


# ── Not making the caller supply what the key already knows ──────────────────


def test_the_organization_is_discovered_when_not_supplied(script, monkeypatch, capsys):
    """--org was required, and it is the most error-prone argument: a long opaque UUID
    that has to be found in a browser URL. A Capella API key can only see organizations
    it belongs to, so for the common case of one there is nothing to ask.

    This also removes the failure that prompted the change: pasting a usage line with
    `<organization_id>` still in it.
    """
    _Handler.orgs = [{"data": {"id": "ORG", "name": "the customer"}}]
    monkeypatch.setattr(
        "sys.argv", ["verify", "--only", "capella_projects_list", "--json"]
    )
    script.main()
    out = capsys.readouterr().out
    assert "Discovered organization: ORG" in out
    payload = json.loads(_json_tail(out))
    assert payload["results"], payload


def test_several_visible_organizations_asks_rather_than_guesses(
    script, monkeypatch, capsys
):
    """Picking one silently could point the run at the wrong tenant. It lists them and
    stops."""
    _Handler.orgs = [
        {"data": {"id": "ORG", "name": "the customer"}},
        {"data": {"id": "ORG2", "name": "Other"}},
    ]
    try:
        monkeypatch.setattr("sys.argv", ["verify", "--only-pat"])
        assert script.main() == 2
        err = capsys.readouterr().err
        assert "several organizations" in err
        assert "ORG2" in err
    finally:
        _Handler.orgs = [{"data": {"id": "ORG", "name": "the customer"}}]


def test_an_explicit_org_skips_discovery(script, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["verify", "--org", "ORG", "--only-pat", "--json"])
    script.main()
    assert "Discovered organization" not in capsys.readouterr().out


def test_the_org_can_come_from_the_environment(script, monkeypatch, capsys):
    """So it can be set once in a shell profile or a CI secret."""
    monkeypatch.setenv("CB_CAPELLA_ORG_ID", "ORG")
    monkeypatch.setattr("sys.argv", ["verify", "--only-pat", "--json"])
    script.main()
    assert "Discovered organization" not in capsys.readouterr().out


# ── Placeholders must fail with an explanation, not a confusing error ────────


@pytest.mark.parametrize(
    "value",
    [
        "<organization_id>",
        "<org>",
        "your-org-id",
        "YOUR_ORG_ID",
        "xxx",
        "TODO",
        "replace-me",
    ],
)
def test_a_placeholder_org_is_refused_with_an_explanation(
    script, monkeypatch, capsys, value
):
    """Copying a usage line verbatim is the most common way to run this wrong.

    On PowerShell it is worse than wrong: `<` is a reserved redirection operator, so the
    shell fails to parse the command before Python starts and the error talks about
    redirection rather than this tool. The message therefore says so explicitly.
    """
    monkeypatch.setattr("sys.argv", ["verify", "--org", value, "--only-pat"])
    assert script.main() == 2
    err = capsys.readouterr().err
    assert "placeholder" in err
    assert "PowerShell" in err


def test_a_placeholder_api_key_is_refused(script, monkeypatch, capsys):
    monkeypatch.setenv("CB_CAPELLA_API_KEY", "<the API key SECRET, not its id>")
    monkeypatch.setattr("sys.argv", ["verify", "--org", "ORG", "--only-pat"])
    assert script.main() == 2
    assert "placeholder" in capsys.readouterr().err


def test_a_real_looking_value_is_not_mistaken_for_a_placeholder(script):
    """The guard must not reject legitimate input: Capella ids are UUIDs and key secrets
    are long base64-ish strings."""
    assert not script._looks_like_a_placeholder("6af08c0a-8cab-4c1c-b257-b521575c16d0")
    assert not script._looks_like_a_placeholder("kZ3xQ8vN2pL9wR4tY7uI1oP5aS6dF0gH")
    assert not script._looks_like_a_placeholder("")


def _json_tail(out: str) -> str:
    return out[out.index("{") :]


# ── --method-probe: proving the method without changing anything ─────────────
#
# Found by accident. A --write-probe of capella_collection_create against live Capella
# returned 422 rather than creating a collection, because the probe body was empty and the
# operation requires `name`. That is strictly better than performing the write: it proves
# the route matched AND the method was accepted AND the request was refused on its
# contents. So it is now a mode of its own rather than a lucky side effect.


def test_a_method_probe_proves_the_method_and_changes_nothing(script):
    """422/400 means: route matched, method accepted, payload refused."""
    op = _Op(
        "cb_bucket_create",
        "POST",
        "/v4/organizations/{organization_id}/projects/{project_id}"
        "/clusters/{cluster_id}/buckets",
        body={"name": {"type": "string"}},
    )
    op.body_required = ("name",)
    ids = {"organization_id": "ORG", "project_id": "PROJ", "cluster_id": "CL"}

    result = script.probe(op, ids, "k", mode="method")
    assert result.verdict == "VERIFIED", result.detail
    assert result.status == 422
    assert "nothing changed" in result.detail


def test_a_method_probe_is_skipped_where_it_could_actually_mutate(script):
    """Without required body fields an empty-body probe might SUCCEED, which would
    perform the operation. Skipping is the only safe answer; --write-probe remains the
    deliberate route."""
    op = _Op(
        "cb_bucket_flush",
        "POST",
        "/v4/organizations/{organization_id}/projects/{project_id}"
        "/clusters/{cluster_id}/buckets",
    )
    result = script.probe(
        op,
        {"organization_id": "ORG", "project_id": "PROJ", "cluster_id": "CL"},
        "k",
        mode="method",
    )
    # The SAFETY property, which has not changed: the operation's own method never
    # reaches the wire, so nothing can have been created.
    assert result.method_sent == "OPTIONS"
    assert "METHOD NOT CONFIRMED" in result.detail

    # ...and the PATH is still checked, which is the part that used to be thrown away.
    # This asserted `verdict == "SKIPPED"` until a live run showed what that cost: 22 of
    # 97 operations came back with no verdict at all, because --method-probe refused the
    # empty-body probe AND declined to fall back to the OPTIONS probe the default mode
    # would have run. A flag meaning "confirm more" returned strictly less.
    assert result.verdict == "VERIFIED"
    assert result.status == 405


def test_an_accepted_empty_body_is_reported_as_an_error(script, monkeypatch):
    """If a create ACCEPTS an empty body, the probe just performed the operation. That is
    not a pass — it means body_required in spec.py understates what the API requires, and
    the operator needs to know something may have been created."""
    op = _Op("cb_thing_create", "POST", "/v4/organizations/{organization_id}/projects")
    op.body_required = ("name",)
    monkeypatch.setattr(script, "_request", lambda *a, **k: (201, '{"id":"new"}'))

    result = script.probe(op, {"organization_id": "ORG"}, "k", mode="method")
    assert result.verdict == "ERROR"
    assert "may have just been performed" in result.detail


# ── The destructive-write guard ──────────────────────────────────────────────


def test_a_destructive_write_probe_is_refused_without_the_extra_flag(
    script, monkeypatch, capsys
):
    """The hazard is one keystroke from a safe command.

    `--write-probe --only capella_collection_create` proved a path and changed nothing.
    The same line with `_delete` would have deleted the _default collection out of a real
    bucket, with no extra confirmation and nothing in the output distinguishing the two.
    """
    monkeypatch.setattr(
        "sys.argv",
        [
            "verify",
            "--org",
            "ORG",
            "--write-probe",
            "--only",
            "capella_collection_delete",
        ],
    )
    assert script.main() == 2
    err = capsys.readouterr().err
    assert "--yes-really-mutate" in err
    assert "capella_collection_delete" in err


def test_the_destructive_guard_refuses_before_making_any_api_call(
    script, monkeypatch, capsys
):
    """A refusal must cost nothing and must not print anything implying work happened."""
    calls = []
    monkeypatch.setattr(
        script, "_request", lambda *a, **k: (calls.append(a) or (200, "{}"))
    )
    monkeypatch.setattr(
        "sys.argv",
        ["verify", "--org", "ORG", "--write-probe", "--only", "capella_bucket_delete"],
    )
    assert script.main() == 2
    assert not calls, f"the guard fired only after {len(calls)} API call(s)"
    assert "Discovering identifiers" not in capsys.readouterr().out


def test_a_non_destructive_write_probe_still_needs_no_extra_flag(
    script, monkeypatch, capsys
):
    """The guard must not block the invocation that actually worked."""
    monkeypatch.setattr(
        "sys.argv",
        [
            "verify",
            "--org",
            "ORG",
            "--write-probe",
            "--only",
            "capella_collection_create",
            "--json",
        ],
    )
    assert script.main() in (0, 1)  # a verdict, not a refusal
    assert "yes-really-mutate" not in capsys.readouterr().err


def test_the_two_probe_modes_are_mutually_exclusive(script, monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "verify",
            "--org",
            "ORG",
            "--write-probe",
            "--method-probe",
            "--only",
            "capella_bucket_create",
        ],
    )
    assert script.main() == 2
    assert "mutually exclusive" in capsys.readouterr().err


# ── Two bugs a live run against real Capella exposed ─────────────────────────


def test_a_capella_domain_error_404_is_not_reported_missing(script):
    """The false positive, with the real response body.

    `GET .../onOffSchedule` on a cluster with no schedule returns

        {"code":11040,
         "hint":"Returned from the API when a database does not have an existing On/Off
                 schedule.",
         "httpStatusCode":404, "message":"Failed to get On/Off schedule..."}

    which says the route was reached and the object is absent. The original detector
    matched on phrases like "does not exist" plus a list of object nouns, and this body
    contains neither — so a correct path was reported MISSING. That is the "confidently
    wrong" outcome the script exists to avoid.

    A domain error CODE is the reliable signal: only the API's own handlers emit those,
    and they run after routing.
    """
    op = _Op(
        "cb_onoff_get",
        "GET",
        "/v4/organizations/{organization_id}/projects/{project_id}"
        "/clusters/{cluster_id}/onOffSchedule",
    )
    ids = {"organization_id": "ORG", "project_id": "PROJ", "cluster_id": "CL"}
    result = script.probe(op, ids, "k")
    assert result.verdict == "VERIFIED", result.detail
    assert "11040" in result.detail


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ('{"code":11040,"message":"no schedule"}', 11040),
        ('{"code":4025,"message":"x"}', 4025),
        # An HTTP status in the code field is not a domain code.
        ('{"code":404,"message":"not found"}', None),
        ('{"message":"route not found"}', None),
        ("<html>404</html>", None),
        ('{"code":true}', None),
        ("[]", None),
    ],
)
def test_the_domain_error_detector_is_specific(script, body, expected):
    """It must not classify every 404 as route-matched, or MISSING becomes unreachable
    and the tool can never report a genuinely wrong path."""
    assert script._capella_domain_error(body) == expected


def test_a_genuinely_wrong_path_is_still_missing(script):
    """The other half: the fix must not have made MISSING unreachable."""
    op = _Op("cb_bogus", "GET", "/v4/organizations/{organization_id}/nope")
    result = script.probe(op, {"organization_id": "ORG"}, "k")
    assert result.verdict == "MISSING"


# ── The static fallback must carry the SAFETY fields ────────────────────────


def test_the_static_parse_carries_every_field_the_script_consults(script):
    """The serious bug. The fallback carried six fields and omitted the two that drive
    the safety decisions — `destructive` and `body_required`.

    `getattr(op, "destructive", False)` then defaulted to "not destructive", so with no
    SDK installed the guard against a destructive --write-probe was INERT, and
    --method-probe skipped every write operation while claiming they had no required body
    fields. The control worked when tested with the SDK present and was silently absent in
    the configuration a user without it actually runs.
    """
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella.spec import OPS_BY_NAME

    root = pathlib.Path(__file__).resolve().parent.parent
    static = script._ops_by_static_parse(str(root / "handlers" / "capella" / "spec.py"))
    by_name = {op.name: op for op in static}

    # `body` is compared on TRUTHINESS only, because that is all the script uses it for
    # (`body={} if op.body else None`), and some schemas build their descriptions from
    # f-strings and module constants that ast.literal_eval cannot evaluate. Demanding
    # exact equality there would fail for a reason with no bearing on correctness.
    truthiness_only = {"body"}

    for name, real in OPS_BY_NAME.items():
        parsed = by_name[name]
        for field in script.CONSULTED_FIELDS:
            got, want = getattr(parsed, field), getattr(real, field)
            if field in truthiness_only:
                assert bool(got) == bool(want), (
                    f"{name}.{field}: static parse {'has' if got else 'lacks'} a body, "
                    f"registry {'has' if want else 'lacks'} one"
                )
            else:
                assert got == want, (
                    f"{name}.{field}: static parse has {got!r}, registry has {want!r}"
                )


def test_destructive_detection_agrees_across_both_sources(script):
    """The specific consequence: the set of operations the guard protects must be the same
    whether or not the SDK is importable."""
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella.spec import OPS_BY_NAME

    root = pathlib.Path(__file__).resolve().parent.parent
    static = script._ops_by_static_parse(str(root / "handlers" / "capella" / "spec.py"))

    from_static = {op.name for op in static if script._is_destructive(op)}
    from_registry = {n for n, o in OPS_BY_NAME.items() if script._is_destructive(o)}
    assert from_static == from_registry
    assert from_static, "no destructive operations detected at all — the guard is inert"


def test_method_probe_eligibility_agrees_across_both_sources(script):
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella.spec import OPS_BY_NAME

    root = pathlib.Path(__file__).resolve().parent.parent
    static = script._ops_by_static_parse(str(root / "handlers" / "capella" / "spec.py"))

    from_static = {op.name for op in static if script._has_required_body(op)}
    from_registry = {n for n, o in OPS_BY_NAME.items() if script._has_required_body(o)}
    assert from_static == from_registry
    assert len(from_static) >= 10, (
        f"only {len(from_static)} operations are method-probeable; the fallback is "
        "probably dropping body_required again"
    )


def test_an_unknown_destructive_flag_fails_closed(script):
    """An operation the script knows nothing about is exactly the one to refuse.
    `getattr(..., False)` defaulted the other way, which is how the guard came to be
    inert."""

    class _Bare:
        name = "mystery"
        method = "DELETE"

    assert script._is_destructive(_Bare()) is True
    assert script._has_required_body(_Bare()) is False


def test_static_op_refuses_to_be_built_with_missing_fields(script):
    """Constructing one without every consulted field is how the omission happened. It is
    now a TypeError rather than a silent default."""
    with pytest.raises(TypeError, match="missing"):
        script._StaticOp(name="x", method="GET", path="/p")


# ── Discovery must not leave ids on the table ────────────────────────────────


def test_credential_and_cidr_ids_are_discovered(script, monkeypatch):
    """Three operations reported SKIPPED for want of an identifier that was sitting in a
    list the script already knew how to call.

    In the output that is indistinguishable from an identifier that genuinely does not
    exist, so it read as "cannot be verified" when it meant "did not look".
    """
    calls: list[str] = []
    real = script._request

    def _spy(method, path, token, body=None):
        calls.append(f"{method} {path}")
        if path.endswith("/users"):
            return 200, json.dumps({"data": [{"id": "CRED-1"}]})
        if path.endswith("/allowedcidrs"):
            return 200, json.dumps({"data": [{"id": "CIDR-1"}]})
        return real(method, path, token, body)

    monkeypatch.setattr(script, "_request", _spy)
    ids = script.discover("fake-secret", _Args())

    assert ids["user_id"] == "CRED-1"
    assert ids["allowed_cidr_id"] == "CIDR-1"
    assert any(c.endswith("/users") for c in calls)
    assert any(c.endswith("/allowedcidrs") for c in calls)


def test_an_empty_credential_list_leaves_the_id_absent(script, monkeypatch):
    """Absent means SKIPPED, which is right. It must not invent a placeholder id — that
    would 404 and be reported as MISSING for a correct path."""
    real = script._request

    def _spy(method, path, token, body=None):
        if path.endswith(("/users", "/allowedcidrs")):
            return 200, json.dumps({"data": []})
        return real(method, path, token, body)

    monkeypatch.setattr(script, "_request", _spy)
    ids = script.discover("fake-secret", _Args())
    assert "user_id" not in ids
    assert "allowed_cidr_id" not in ids


def test_skips_are_grouped_by_cause_in_the_summary(script, monkeypatch, capsys):
    """22 operations skipped for one shared reason printed that sentence 22 times, twice
    over, burying the actionable part: which single missing object unlocks the group."""
    monkeypatch.setattr("sys.argv", ["verify", "--org", "ORG"])
    script.main()
    out = capsys.readouterr().out
    assert "Not exercised" in out
    assert "operation(s):" in out, "the skip summary is not grouped by cause"


# ── The App Service bootstrap ────────────────────────────────────────────────
#
# 22 of the 61 operations need an App Service to exist before their paths can be filled in,
# so every run reported them SKIPPED. Creating one by hand in the Capella console and then
# re-running is exactly the sort of manual step that never gets repeated, which is why the
# script now does it — and why that has to be tested, because it CREATES BILLABLE
# INFRASTRUCTURE and deletes it again.
#
# These use a recording double rather than the fake HTTP server, because what matters is the
# ORDER and CONTENT of the calls: create, then poll, then delete, with the delete reached even
# when verification raises.


class _RecordingCapella:
    """Stands in for `_request`, recording calls and replaying scripted states."""

    def __init__(self, states, *, create_status=201, create_id="AS1", marker=True):
        self.calls: list[tuple[str, str]] = []
        self.states = list(states)
        self.create_status = create_status
        self.create_id = create_id
        self.marker = marker
        self.deleted: list[str] = []

    def __call__(self, method, path, token, body=None):
        self.calls.append((method, path))
        if method == "POST" and path.endswith("/appservices"):
            if self.create_status >= 400:
                return self.create_status, '{"message":"quota exceeded"}'
            payload = (
                {"data": {"id": self.create_id}} if self.create_id else {"data": {}}
            )
            return self.create_status, json.dumps(payload)
        if method == "DELETE" and "/appservices/" in path:
            self.deleted.append(path.rsplit("/", 1)[-1])
            return 202, "{}"
        if method == "GET" and "/appservices/" in path and path.endswith("/adminUsers"):
            return 200, json.dumps({"data": [{"id": "ADMIN1"}]})
        if method == "GET" and "/appservices/" in path:
            state = self.states.pop(0) if self.states else "healthy"
            description = (
                "Ephemeral App Service for v4 path verification. "
                "created-by-verify_capella_paths. Safe to delete."
                if self.marker
                else "a customer's production App Service"
            )
            return 200, json.dumps(
                {
                    "data": {
                        "id": self.create_id,
                        "currentState": state,
                        "description": description,
                    }
                }
            )
        return 404, '{"message":"not found"}'


@pytest.fixture
def fast_polls(script, monkeypatch):
    """Collapse the 15-second poll interval so a multi-poll test is not a multi-minute one."""
    monkeypatch.setattr(script, "_BOOTSTRAP_POLL_SECONDS", 0)
    return script


def test_bootstrap_creates_then_waits_for_healthy(fast_polls, monkeypatch):
    script = fast_polls
    fake = _RecordingCapella(states=["deploying", "deploying", "healthy"])
    monkeypatch.setattr(script, "_request", fake)

    app_id = script.bootstrap_app_service("tok", "/base", _Args())

    assert app_id == "AS1"
    assert fake.calls[0] == ("POST", "/base/appservices")
    # It polled rather than assuming the create response meant ready.
    assert sum(1 for m, p in fake.calls if m == "GET") >= 3


def test_the_created_app_service_carries_an_identifying_marker(fast_polls, monkeypatch):
    """So an orphan is recognisable in the Capella console, and so teardown can tell what it
    is allowed to delete."""
    script = fast_polls
    seen = {}

    def _capture(method, path, token, body=None):
        if method == "POST":
            seen["body"] = body
            return 201, json.dumps({"data": {"id": "AS1"}})
        return 200, json.dumps({"data": {"id": "AS1", "currentState": "healthy"}})

    monkeypatch.setattr(script, "_request", _capture)
    script.bootstrap_app_service("tok", "/base", _Args())

    assert script._BOOTSTRAP_MARKER in seen["body"]["description"]
    # The cheapest App Service Capella will actually create — which is TWO nodes, not one.
    # This test asserted 1 until a live run came back with
    #   422 "The instance desired capacity must be between 2 and 12."
    assert seen["body"]["nodes"] == script._MIN_APP_SERVICE_NODES == 2


def test_a_failed_deployment_still_returns_the_id(fast_polls, monkeypatch):
    """A degraded App Service cannot serve traffic but its URLs still resolve, which is all
    the verifier needs — and the id is required for teardown either way. Returning None here
    would silently abandon billable infrastructure."""
    script = fast_polls
    fake = _RecordingCapella(states=["deploying", "deploymentFailed"])
    monkeypatch.setattr(script, "_request", fake)
    assert script.bootstrap_app_service("tok", "/base", _Args()) == "AS1"


def test_a_failed_create_returns_none(fast_polls, monkeypatch):
    script = fast_polls
    fake = _RecordingCapella(states=[], create_status=422)
    monkeypatch.setattr(script, "_request", fake)
    assert script.bootstrap_app_service("tok", "/base", _Args()) is None


def test_a_create_with_no_readable_id_says_so_loudly(fast_polls, monkeypatch, capsys):
    """The dangerous case: the create SUCCEEDED, so something is now billing, but the id is
    not where expected so teardown cannot run. Returning None quietly would abandon it."""
    script = fast_polls
    fake = _RecordingCapella(states=[], create_id="")
    monkeypatch.setattr(script, "_request", fake)

    assert script.bootstrap_app_service("tok", "/base", _Args()) is None
    output = capsys.readouterr().out
    assert "BILL" in output
    assert "console" in output.lower()


def test_teardown_deletes_what_the_script_created(script, monkeypatch):
    fake = _RecordingCapella(states=["healthy"])
    monkeypatch.setattr(script, "_request", fake)
    script.teardown_app_service("tok", "/base", "AS1")
    assert fake.deleted == ["AS1"]


def test_teardown_refuses_an_app_service_it_did_not_create(script, monkeypatch, capsys):
    """The mistake that is not recoverable. Only ever reachable if the caller's assumption
    about what it created is wrong, which is exactly when a second check earns its keep."""
    fake = _RecordingCapella(states=["healthy"], marker=False)
    monkeypatch.setattr(script, "_request", fake)

    script.teardown_app_service("tok", "/base", "SOMEONE_ELSES")

    assert fake.deleted == []
    assert "REFUSING" in capsys.readouterr().out


def test_a_failed_delete_tells_you_it_is_still_billing(script, monkeypatch, capsys):
    fake = _RecordingCapella(states=["healthy"])

    def _delete_fails(method, path, token, body=None):
        if method == "DELETE":
            return 500, '{"message":"internal error"}'
        return fake(method, path, token, body)

    monkeypatch.setattr(script, "_request", _delete_fails)
    script.teardown_app_service("tok", "/base", "AS1")
    assert "BILL" in capsys.readouterr().out


def test_the_timeout_still_returns_the_id_for_teardown(script, monkeypatch, capsys):
    """A run that gives up waiting must not also give up cleaning up."""
    monkeypatch.setattr(script, "_BOOTSTRAP_POLL_SECONDS", 0)
    monkeypatch.setattr(script, "_BOOTSTRAP_TIMEOUT_SECONDS", 0)
    fake = _RecordingCapella(states=["deploying"])
    monkeypatch.setattr(script, "_request", fake)
    assert script.bootstrap_app_service("tok", "/base", _Args()) == "AS1"
    assert "TIMED OUT" in capsys.readouterr().out


def test_teardown_runs_even_when_verification_raises(script, monkeypatch, capsys):
    """THE property that makes creating billable infrastructure acceptable at all.

    Teardown sits in a `finally`, so an exception or a Ctrl-C part-way through the probe loop
    still removes the App Service. If it were merely the next statement after the loop, any
    failure would leave it running and billing — and a verifier is precisely the sort of tool
    people abandon half-way when it starts reporting problems.
    """
    import sys

    fake = _RecordingCapella(states=["healthy"])
    monkeypatch.setattr(script, "_request", fake)
    monkeypatch.setattr(script, "_BOOTSTRAP_POLL_SECONDS", 0)
    monkeypatch.setattr(
        script,
        "discover",
        lambda token, args: {"project_id": "PROJ", "cluster_id": "CL"},
    )
    monkeypatch.setattr(
        script, "load_ops", lambda **_kwargs: [_Op("op", "GET", "/v4/x")]
    )

    def _explode(*_a, **_k):
        raise KeyboardInterrupt("operator gave up")

    monkeypatch.setattr(script, "_run_probes", _explode)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_capella_paths.py",
            "--org",
            "ORG",
            "--bootstrap-app-service",
            "--yes-really-mutate",
        ],
    )

    with pytest.raises(KeyboardInterrupt):
        script.main()

    assert fake.deleted == ["AS1"], (
        "the App Service was left running after an interrupt"
    )


def test_an_existing_app_service_is_reused_rather_than_paid_for_twice(
    script, monkeypatch, capsys
):
    """The bootstrap runs after discovery for this reason. Provisioning a second App Service
    when the project already has one would make the flag expensive enough to avoid."""
    import sys

    created = []
    monkeypatch.setattr(
        script,
        "bootstrap_app_service",
        lambda *a, **k: created.append(1) or "SHOULD_NOT_HAPPEN",
    )
    monkeypatch.setattr(
        script,
        "discover",
        lambda token, args: {
            "project_id": "PROJ",
            "cluster_id": "CL",
            "app_service_id": "PRE_EXISTING",
        },
    )
    monkeypatch.setattr(
        script, "load_ops", lambda **_kwargs: [_Op("op", "GET", "/v4/x")]
    )
    monkeypatch.setattr(script, "_run_probes", lambda *a, **k: 0)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_capella_paths.py",
            "--org",
            "ORG",
            "--bootstrap-app-service",
            "--yes-really-mutate",
        ],
    )

    assert script.main() == 0
    assert created == [], "created a second App Service when one already existed"
    assert "reusing the existing PRE_EXISTING" in capsys.readouterr().out


# ── The inferred-path selector ───────────────────────────────────────────────
#
# `--only-pat` reported "No [PAT] paths remain: every operation now cites a primary source"
# while TEN of the sixty-one were tagged
#
#     [PAT — verify if 404]
#     [PAT — sibling of the confirmed scopes path]
#
# because the selector tested `"[PAT]" in summary` — the CLOSED literal, which none of them
# contain. A check that issues an all-clear it has not earned is worse than no check: it
# closes the question. The literal was duplicated at three call sites, which is how the three
# stayed wrong together.


def test_the_selector_matches_a_tag_with_a_trailing_note(script):
    """THE bug. This is the form spec.py actually uses."""
    assert script._is_inferred(
        _Op("x", "GET", "/v4/x", "summary [PAT — verify if 404]")
    )
    assert script._is_inferred(
        _Op("x", "GET", "/v4/x", "[PAT — sibling of the confirmed scopes path]")
    )


def test_the_selector_still_matches_the_bare_tag(script):
    assert script._is_inferred(_Op("x", "GET", "/v4/x", "summary [PAT]"))


def test_the_selector_does_not_match_a_sourced_path(script):
    """Guards against over-correcting into a selector that matches everything, which would
    make --only-pat a synonym for the full sweep."""
    for summary in (
        "[TF appservice.go]",
        "[DOC]",
        "[LIVE 405]",
        "[LIVE+METHOD 200]",
        "",
    ):
        assert not script._is_inferred(_Op("x", "GET", "/v4/x", summary)), summary
    assert not script._is_inferred(_Op("x", "GET", "/v4/x", None))


def test_the_selector_is_used_at_every_site_rather_than_reinlined():
    """Three independent copies of the literal is why all three were wrong. A fourth copy
    would be a fourth chance to be wrong."""
    import ast
    import pathlib

    source = (
        pathlib.Path(__file__).resolve().parent.parent
        / "scripts"
        / "verify_capella_paths.py"
    ).read_text(encoding="utf-8")

    # PARSED, not grepped. This is the third time in this project a source scan has flagged
    # the COMMENT that explains a bug — here, the docstring of `_is_inferred` quotes the bad
    # expression verbatim in order to say why it is wrong. An `ast.Compare` node cannot
    # appear inside a docstring, so the ambiguity disappears entirely.
    offenders = [
        node.lineno
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Compare)
        and any(isinstance(op, ast.In) for op in node.ops)
        and isinstance(node.left, ast.Constant)
        and node.left.value == "[PAT]"
    ]
    assert not offenders, (
        "the closed-literal membership test is back at line(s) "
        f"{offenders}, and it misses every '[PAT — ...]' tag"
    )


def test_no_operation_in_the_spec_is_still_inferred():
    """The claim `--only-pat` makes, checked with the FIXED selector. It was false before:
    ten paths were inferred and the tool said none were."""
    import pathlib
    import re

    spec_source = (
        pathlib.Path(__file__).resolve().parent.parent
        / "handlers"
        / "capella"
        / "spec.py"
    ).read_text(encoding="utf-8")

    # The module docstring documents the tag, so only look after it.
    body = spec_source.split('"""', 2)[2]
    remaining = re.findall(r"\[PAT[^\]]*\]", body)
    assert not remaining, (
        f"{len(remaining)} operation(s) still carry an inferred path tag: {remaining}. "
        "Verify them with scripts/verify_capella_paths.py --only-pat and promote the tag."
    )


def test_the_promoted_tags_record_the_status_that_was_observed():
    """A bare [LIVE] asserts; [LIVE 405] shows its evidence. The ten promoted tags carry the
    status so a later reader can tell a real GET from an OPTIONS probe without rerunning."""
    import pathlib
    import re

    spec_source = (
        pathlib.Path(__file__).resolve().parent.parent
        / "handlers"
        / "capella"
        / "spec.py"
    ).read_text(encoding="utf-8")
    body = spec_source.split('"""', 2)[2]

    tags = re.findall(r"\[LIVE(?:\+METHOD)?[^\]]*\]", body)
    assert len(tags) >= 10, f"expected the promoted tags to be present, found {tags}"
    with_status = [t for t in tags if re.search(r"\d{3}", t)]
    assert len(with_status) >= 10, (
        f"promoted tags should carry the observed status; these do not: "
        f"{sorted(set(tags) - set(with_status))}"
    )


# ── Child objects: closing the last 14 skips ─────────────────────────────────
#
# After an App Service exists, 14 operations still reported SKIPPED, every one because the
# list endpoint answered 200 with an EMPTY array — no id to put in the path. Nine of them are
# the App Endpoint subtree, which is the surface a Couchbase Lite replicator talks to, so
# leaving those unverified would have meant verifying the easy half.
#
# These are real writes against a real organization, so the safety properties get the same
# treatment as the App Service bootstrap.


class _ChildRecorder:
    """Records creates and deletes, and can be told to reject specific creates."""

    def __init__(self, *, fail: tuple = (), bucket_name="travel"):
        self.creates: list[tuple[str, dict]] = []
        self.deletes: list[str] = []
        self.fail = fail
        self.bucket_name = bucket_name
        self.counter = 0

    def __call__(self, method, path, token, body=None):
        if method == "POST":
            self.creates.append((path, body or {}))
            if any(marker in path for marker in self.fail):
                return 422, '{"code":422,"message":"rejected by the fake"}'
            self.counter += 1
            return 201, json.dumps({"data": {"id": f"NEW{self.counter}"}})
        if method == "DELETE":
            self.deletes.append(path)
            return 204, ""
        if method == "GET" and "/buckets/" in path:
            return 200, json.dumps({"data": {"id": "BKT", "name": self.bucket_name}})
        return 200, json.dumps({"data": []})


BASE_IDS = {
    "organization_id": "ORG",
    "project_id": "PROJ",
    "cluster_id": "CL",
    "bucket_id": "BKT",
    "scope_name": "inventory",
    "collection_name": "airline",
    "app_service_id": "AS1",
}


def test_child_bootstrap_supplies_every_missing_identifier(script, monkeypatch):
    """The whole point: these five ids are what the 14 skips were waiting for."""
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    ids = dict(BASE_IDS)
    overrides: dict = {}

    script.bootstrap_child_objects("tok", "/base", ids, overrides)

    assert ids["user_id"]
    assert ids["allowed_cidr_id"]
    assert ids["admin_user_id"]
    assert ids["app_endpoint_name"]
    assert ids["app_endpoint_keyspace"]
    assert overrides["capella_app_service_allowed_cidr_delete"]["allowed_cidr_id"]


def test_the_two_allowlist_ids_are_kept_apart(script, monkeypatch):
    """Both routes use the placeholder {allowed_cidr_id} but they are DIFFERENT objects. A
    single flat dict can hold one, so whichever op did not own it would be probed with the
    other's id and answer a 404 that has to be argued about instead of a clean verdict."""
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    ids = dict(BASE_IDS)
    overrides: dict = {}

    script.bootstrap_child_objects("tok", "/base", ids, overrides)

    cluster_id = ids["allowed_cidr_id"]
    as_id = overrides["capella_app_service_allowed_cidr_delete"]["allowed_cidr_id"]
    assert cluster_id != as_id


def test_an_override_applies_to_one_operation_only(script):
    """And must not leak into the shared dict, or it would silently redirect the other
    allowlist route to the wrong object."""
    ids = {"organization_id": "ORG", "allowed_cidr_id": "CLUSTER_CIDR"}
    overrides = {"op_b": {"allowed_cidr_id": "AS_CIDR"}}

    op_a = _Op(
        "op_a", "DELETE", "/v4/organizations/{organization_id}/a/{allowed_cidr_id}"
    )
    op_b = _Op(
        "op_b", "DELETE", "/v4/organizations/{organization_id}/b/{allowed_cidr_id}"
    )

    # Assert on the FILLED path, which is what actually gets requested. `probe` would send a
    # real request; `fill` is the part under test.
    filled_a, _ = script.fill(op_a.path, {**ids, **overrides.get("op_a", {})})
    filled_b, _ = script.fill(op_b.path, {**ids, **overrides.get("op_b", {})})
    assert filled_a.endswith("/CLUSTER_CIDR")
    assert filled_b.endswith("/AS_CIDR")
    assert ids["allowed_cidr_id"] == "CLUSTER_CIDR", (
        "the override mutated the shared dict"
    )


def test_probe_actually_applies_the_override_to_the_request(script, monkeypatch):
    """Through `probe`, not `fill`.

    The test above exercises the substitution and passed while `probe` ignored overrides
    entirely — a mutation setting `extra = None` survived it. `fill` being right is worth
    nothing if the value never reaches the request, so this asserts on the URL that was sent.
    """
    requested: list[str] = []

    def _record(method, path, token, body=None):
        requested.append(path)
        return 405, '{"message":"method not allowed"}'

    monkeypatch.setattr(script, "_request", _record)

    op = _Op(
        "capella_app_service_allowed_cidr_delete",
        "DELETE",
        "/v4/organizations/{organization_id}/x/{allowed_cidr_id}",
    )
    result = script.probe(
        op,
        {"organization_id": "ORG", "allowed_cidr_id": "CLUSTER_CIDR"},
        "tok",
        "options",
        {"capella_app_service_allowed_cidr_delete": {"allowed_cidr_id": "AS_CIDR"}},
    )

    assert result.verdict == "VERIFIED"
    assert requested == ["/v4/organizations/ORG/x/AS_CIDR"], (
        "probe sent the shared id instead of the per-operation override"
    )


def test_probe_without_a_matching_override_uses_the_shared_id(script, monkeypatch):
    """Guards the test above from passing because overrides became mandatory, which would
    send every other allowlist route at the wrong object."""
    requested: list[str] = []

    def _record(method, path, token, body=None):
        requested.append(path)
        return 405, "{}"

    monkeypatch.setattr(script, "_request", _record)

    op = _Op(
        "some_other_op",
        "DELETE",
        "/v4/organizations/{organization_id}/x/{allowed_cidr_id}",
    )
    script.probe(
        op,
        {"organization_id": "ORG", "allowed_cidr_id": "CLUSTER_CIDR"},
        "tok",
        "options",
        {"capella_app_service_allowed_cidr_delete": {"allowed_cidr_id": "AS_CIDR"}},
    )

    assert requested == ["/v4/organizations/ORG/x/CLUSTER_CIDR"]


def test_the_allowlist_entries_use_a_documentation_range(script, monkeypatch):
    """THE security property. An allowlist entry is the one object here whose survival would
    WIDEN network exposure. RFC 5737 TEST-NET-1 is reserved for documentation and assigned to
    no real host, so allowlisting it grants access to nothing.

    Explicitly NOT an RFC 1918 range: 10/8 and 192.168/16 are somebody's actual private
    network, and 0.0.0.0/0 would expose the cluster to the internet.
    """
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    cidrs = [body["cidr"] for path, body in rec.creates if "cidr" in body]
    assert len(cidrs) == 2
    for cidr in cidrs:
        assert cidr.startswith("192.0.2."), f"{cidr} is not RFC 5737 TEST-NET-1"
        assert cidr.endswith("/32"), f"{cidr} is wider than a single host"
    assert "0.0.0.0/0" not in cidrs


def test_the_allowlist_entries_expire_on_their_own(script, monkeypatch):
    """Belt and braces for the only object whose survival matters. Teardown runs from a
    `finally`, but a machine that loses power between create and delete would otherwise leave
    an allowlist rule in place indefinitely."""
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    for path, body in rec.creates:
        if "cidr" in body:
            assert body.get("expiresAt"), (
                f"no expiresAt on the allowlist entry at {path}"
            )


def test_no_generated_password_is_ever_printed(script, monkeypatch, capsys):
    """Two of these objects carry credentials. The script prints every id it creates, and a
    password alongside one would land in a terminal and a CI log."""
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    output = capsys.readouterr().out
    passwords = [b["password"] for _p, b in rec.creates if "password" in b]
    assert passwords, "expected the credential objects to set a password"
    for password in passwords:
        assert password not in output


def test_passwords_are_supplied_rather_than_left_to_capella(script, monkeypatch):
    """Capella generates one if the field is omitted — and returns it in the create response,
    which this script parses and reports on. Supplying one keeps the secret out of a body we
    handle at all."""
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    credential_creates = [
        b for p, b in rec.creates if p.endswith(("/users", "/adminUsers"))
    ]
    assert len(credential_creates) == 2
    for body in credential_creates:
        assert body.get("password"), (
            "a credential object was created without a password"
        )
        assert len(body["password"]) >= 16


def test_a_rejection_body_is_printed_far_enough_to_be_useful(
    script, monkeypatch, capsys
):
    """The whole value of a failed create is the reason.

    Capella's 422 bodies open with ~150 characters of boilerplate — a `code`, an
    `httpStatusCode`, and a generic `hint` reading "Please review your request and ensure
    that all required parameters are correctly provided" — before the `message` that actually
    names the problem. Truncating at 220 characters cut the App Services admin user
    rejection off mid-word at "contains or lacks b", which was the part that would have said
    what to fix, and cost a full App Service provisioning cycle to recover.
    """
    boilerplate = json.dumps(
        {
            "code": 422,
            "hint": (
                "Please review your request and ensure that all required parameters "
                "are correctly provided. Consult the Capella Management API reference "
                "for the schema of this request body."
            ),
            "httpStatusCode": 422,
            "message": (
                "Payload for creating or modifying app service admin user "
                "THE ACTUAL REASON APPEARS HERE"
            ),
        }
    )
    # The marker has to sit BEYOND the old 220-character cut, or the fixture would pass
    # against the very truncation this test exists to prevent.
    assert boilerplate.index("THE ACTUAL REASON") > 220, (
        "fixture too short to exercise truncation"
    )

    def _long_rejection(method, path, token, body=None):
        if method == "POST":
            return 422, boilerplate
        if method == "GET" and "/buckets/" in path:
            return 200, json.dumps({"data": {"id": "BKT", "name": "travel"}})
        return 200, json.dumps({"data": []})

    monkeypatch.setattr(script, "_request", _long_rejection)
    script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    assert "THE ACTUAL REASON APPEARS HERE" in capsys.readouterr().out, (
        "the rejection body was truncated before the message that names the problem"
    )


def test_the_credential_is_created_with_a_permission_grant(script, monkeypatch):
    """Capella refuses a credential that grants nothing:

        422 "Can not create new dataplane user without at least (1) valid permission
             being specified"

    A real gap: nothing asserted this, and the mutation that removed the `access` field
    SURVIVED the whole suite. Found by the harness, not by review.
    """
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    body = next(b for p, b in rec.creates if p.endswith("/users"))
    assert body.get("access"), (
        "the database credential was created with no permission grant"
    )
    # Read-only, because the credential exists for minutes and never needs to write.
    privileges = body["access"][0]["privileges"]
    assert privileges == ["data_reader"], privileges


def test_the_admin_user_is_created_with_exactly_one_access_shape(script, monkeypatch):
    """`access` is a oneOf: exactly one of `accessAllEndpoints` or `endpoints`. Supplying
    both, or neither, is the 422 that read "contains or lacks both ...".
    """
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    body = next(b for p, b in rec.creates if p.endswith("/adminUsers"))
    access = body.get("access")
    assert access, "the admin user was created with no access field"
    keys = set(access)
    assert len(keys & {"accessAllEndpoints", "endpoints"}) == 1, (
        f"access must carry exactly one of the two shapes, got {sorted(keys)}"
    )
    # TRUE, not false. `accessAllEndpoints: false` with no `endpoints` list is not the
    # narrow option, it is NEITHER option — the user would be granted nothing, and Capella
    # counts that as failing to specify access:
    #
    #   422 "... contains or lacks both, list of endpoints and all endpoints flag."
    #
    # Trying to be least-privilege produced the same rejection as omitting the field.
    assert access.get("accessAllEndpoints") is True


def test_the_app_endpoint_uses_the_field_name_capella_reads(script, monkeypatch):
    """`deltaSyncEnabled`, not `deltaSync`. v4 ignores an unrecognised field rather than
    rejecting it, so the wrong name returns 201 and the setting is simply never applied —
    there is no error to notice."""
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    body = next(b for p, b in rec.creates if p.endswith("/appEndpoints"))
    assert "deltaSyncEnabled" in body
    assert "deltaSync" not in body


def test_a_create_that_returns_no_body_still_gets_a_teardown_record(
    script, monkeypatch
):
    """App Endpoint creation answers 201 with an EMPTY body.

    Before the name fallback, that produced "created but no id in the response" — the
    endpoint existed, was reported as a failure, and got NO teardown record. It was only
    cleaned up because deleting the App Service takes its endpoints with it, which is luck
    rather than design.
    """

    def _empty_body_create(method, path, token, body=None):
        if method == "POST":
            return 201, ""  # exactly what Capella does here
        if method == "DELETE":
            return 204, ""
        if method == "GET" and "/buckets/" in path:
            return 200, json.dumps({"data": {"id": "BKT", "name": "travel"}})
        return 200, json.dumps({"data": []})

    monkeypatch.setattr(script, "_request", _empty_body_create)
    ids = dict(BASE_IDS)

    created = script.bootstrap_child_objects("tok", "/base", ids, {})

    assert ids.get("app_endpoint_name"), "the endpoint name fallback did not apply"
    endpoint_teardowns = [p for _label, p in created if "/appEndpoints/" in p]
    assert endpoint_teardowns, "the App Endpoint was created with no teardown record"


def test_the_app_endpoint_keyspace_is_spelled_out(script, monkeypatch):
    """A bare endpoint name is ACCEPTED by v4 and read as `<name>._default._default`, so on a
    cluster with named scopes it silently targets the wrong collection. The two
    accessControlFunction paths take a keyspace, so getting this wrong would verify the right
    route against the wrong object.

    The keyspace names the scope and collection this run CREATED, not the ones discovery
    found — see the next test for why.
    """
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    ids = dict(BASE_IDS)
    script.bootstrap_child_objects("tok", "/base", ids, {})

    endpoint = ids["app_endpoint_name"]
    keyspace = ids["app_endpoint_keyspace"]
    assert keyspace.startswith(f"{endpoint}.")
    assert keyspace.count(".") == 2, f"not endpoint.scope.collection: {keyspace}"
    # NOT the discovered inventory.airline — a scope made for this run.
    assert ".inventory.airline" not in keyspace


def test_the_endpoint_binds_a_throwaway_scope_not_the_discovered_one(
    script, monkeypatch
):
    """THE correctness AND safety fix.

    Configuring an App Endpoint over a collection turns on Sync Gateway for it and writes
    sync metadata into the bucket. Binding the DISCOVERED scope and collection meant binding
    `_default._default` of a bucket holding real data — a verification tool must not start
    syncing somebody's data as a side effect of checking a URL.

    It also did not work twice: the metadata outlives the App Service, so a second run got
        409 "App Endpoint config value or collection conflicts with one already in use"
    on a freshly created App Service, conflicting with the first run's leftovers.
    """
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    ids = dict(BASE_IDS)  # scope_name=inventory, collection_name=airline

    script.bootstrap_child_objects("tok", "/base", ids, {})

    endpoint = next(b for p, b in rec.creates if p.endswith("/appEndpoints"))
    scopes = endpoint["scopes"]
    assert "inventory" not in scopes, (
        "the endpoint bound the discovered scope, which syncs real data"
    )
    assert len(scopes) == 1, "Capella permits only one scope per App Endpoint"
    (bound_scope,) = scopes
    assert "airline" not in scopes[bound_scope]["collections"], (
        "the endpoint bound the discovered collection"
    )
    assert [p for p, _b in rec.creates if p.endswith("/scopes")], (
        "no throwaway scope was created"
    )


def test_the_throwaway_scope_and_collection_are_torn_down(script, monkeypatch):
    """They are created in the target bucket, so they must not be left behind. Order matters:
    the endpoint has to go before the collection it syncs."""
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    created = script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    labels = [label for label, _p in created]
    for expected in ("verify scope", "verify collection", "app endpoint"):
        assert expected in labels, f"{expected} has no teardown record"
    # Teardown is reversed, so creating the endpoint LAST means removing it FIRST, then the
    # collection, then the scope.
    assert labels.index("verify scope") < labels.index("verify collection")
    assert labels.index("verify collection") < labels.index("app endpoint")


def test_the_endpoint_is_skipped_rather_than_binding_real_data(
    script, monkeypatch, capsys
):
    """If the throwaway scope cannot be created, falling back to the discovered collection
    would reintroduce exactly the behaviour being fixed. Nine unverified paths is the better
    outcome."""
    rec = _ChildRecorder(fail=("/scopes",))
    monkeypatch.setattr(script, "_request", rec)
    ids = dict(BASE_IDS)

    script.bootstrap_child_objects("tok", "/base", ids, {})

    assert "app_endpoint_name" not in ids
    assert not [p for p, _b in rec.creates if p.endswith("/appEndpoints")], (
        "an App Endpoint was created without a throwaway scope to bind"
    )
    assert "skipped" in capsys.readouterr().out


def test_the_app_endpoint_is_bound_by_bucket_name_not_id(script, monkeypatch):
    """v4 wants the bucket NAME here, while every other path uses the opaque id. Passing the
    id produces a 422 that reads like a schema problem."""
    rec = _ChildRecorder(bucket_name="travel-sample")
    monkeypatch.setattr(script, "_request", rec)
    script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    endpoint = next(b for p, b in rec.creates if p.endswith("/appEndpoints"))
    assert endpoint["bucket"] == "travel-sample"
    assert endpoint["bucket"] != "BKT"


def test_one_failed_create_does_not_abort_the_others(script, monkeypatch, capsys):
    """None of these are prerequisites for one another, and a rejection body names the field
    that is wrong — which is how the App Service node floor was found. Aborting would discard
    that and the remaining verifications with it."""
    rec = _ChildRecorder(fail=("/users",))
    monkeypatch.setattr(script, "_request", rec)
    ids = dict(BASE_IDS)

    created = script.bootstrap_child_objects("tok", "/base", ids, {})

    assert "user_id" not in ids
    assert ids["app_endpoint_name"], (
        "a later create was abandoned after an earlier failure"
    )
    assert len(created) >= 3
    assert "422" in capsys.readouterr().out


def test_a_missing_app_service_skips_only_its_own_children(script, monkeypatch):
    """The database credential and cluster allowlist entry are cluster-level and do not need
    one, so they must still be created."""
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    ids = {k: v for k, v in BASE_IDS.items() if k != "app_service_id"}

    script.bootstrap_child_objects("tok", "/base", ids, {})

    assert ids["user_id"]
    assert ids["allowed_cidr_id"]
    assert "app_endpoint_name" not in ids
    assert "admin_user_id" not in ids


def test_teardown_removes_children_in_reverse_order(script, monkeypatch):
    """The App Endpoint and admin user live UNDER the App Service. Creation order is
    cluster-level first, so deletion has to run backwards."""
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    created = script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    rec.deletes.clear()
    script.teardown_child_objects("tok", created)

    assert len(rec.deletes) == len(created)
    assert rec.deletes == [path for _label, path in reversed(created)]


def test_every_created_child_is_torn_down(script, monkeypatch):
    """A create with no matching delete is an object left behind in a real organization."""
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    created = script.bootstrap_child_objects("tok", "/base", dict(BASE_IDS), {})

    successful_creates = [p for p, _b in rec.creates]
    assert len(created) == len(successful_creates), (
        "a child object was created without a teardown record"
    )


def test_a_failed_child_delete_is_reported_with_its_path(script, monkeypatch, capsys):
    """So it can be removed by hand. A silent failure is an orphan nobody knows about."""

    def _delete_fails(method, path, token, body=None):
        if method == "DELETE":
            return 500, '{"message":"internal error"}'
        return 200, "{}"

    monkeypatch.setattr(script, "_request", _delete_fails)
    script.teardown_child_objects("tok", [("db credential", "/base/users/NEW1")])

    output = capsys.readouterr().out
    assert "/base/users/NEW1" in output
    assert "500" in output


def test_child_teardown_runs_before_the_app_service_is_deleted(script, monkeypatch):
    """Deleting the parent first would orphan the DELETE calls that verify the children, and
    the run would report a teardown failure for objects Capella had already removed."""
    import sys

    order: list[str] = []
    rec = _ChildRecorder()

    def _record(method, path, token, body=None):
        if method == "DELETE":
            order.append("app_service" if path.count("/") == 4 else "child")
        return rec(method, path, token, body)

    monkeypatch.setattr(script, "_request", _record)
    monkeypatch.setattr(script, "_BOOTSTRAP_POLL_SECONDS", 0)
    monkeypatch.setattr(
        script,
        "discover",
        lambda token, args: {"project_id": "PROJ", "cluster_id": "CL"},
    )
    monkeypatch.setattr(
        script, "load_ops", lambda **_kwargs: [_Op("op", "GET", "/v4/x")]
    )
    monkeypatch.setattr(script, "_run_probes", lambda *a, **k: 0)
    monkeypatch.setattr(script, "bootstrap_app_service", lambda *a, **k: "AS1")
    monkeypatch.setattr(
        script,
        "teardown_app_service",
        lambda token, base, app_id: order.append("app_service"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_capella_paths.py",
            "--org",
            "ORG",
            "--bootstrap-app-service",
            "--bootstrap-child-objects",
            "--yes-really-mutate",
        ],
    )

    assert script.main() == 0
    assert order, "nothing was torn down"
    assert order[-1] == "app_service", f"the App Service was not deleted last: {order}"


def test_child_teardown_survives_an_interrupt(script, monkeypatch):
    """Same property as the App Service teardown, for the same reason."""
    import sys

    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    monkeypatch.setattr(
        script,
        "discover",
        lambda token, args: {
            "project_id": "PROJ",
            "cluster_id": "CL",
            "bucket_id": "BKT",
            "app_service_id": "AS1",
        },
    )
    monkeypatch.setattr(
        script, "load_ops", lambda **_kwargs: [_Op("op", "GET", "/v4/x")]
    )

    def _explode(*_a, **_k):
        raise KeyboardInterrupt("operator gave up")

    monkeypatch.setattr(script, "_run_probes", _explode)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_capella_paths.py",
            "--org",
            "ORG",
            "--bootstrap-child-objects",
            "--yes-really-mutate",
        ],
    )

    with pytest.raises(KeyboardInterrupt):
        script.main()

    assert rec.deletes, "child objects were left behind after an interrupt"


# ── main(): argument validation and the discovery paths ──────────────────────
#
# `main` is where an operator's mistake is caught, and every refusal here exists because the
# alternative is worse than an error message: a placeholder sent as a real value, a destructive
# probe run across the whole surface, or a run that reports success having checked nothing.


def _main(script, monkeypatch, *argv, env=None):
    """Run main() with the given argv. Returns (exit_code, stdout, stderr)."""
    import io
    import sys as _sys

    monkeypatch.setenv("CB_CAPELLA_API_KEY", "fake-secret")
    for key, value in (env or {}).items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)

    monkeypatch.setattr(_sys, "argv", ["verify_capella_paths.py", *argv])
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(_sys, "stdout", out)
    monkeypatch.setattr(_sys, "stderr", err)
    try:
        code = script.main()
    except SystemExit as exc:  # argparse errors
        code = exc.code
    return code, out.getvalue(), err.getvalue()


def test_a_missing_api_key_refuses_before_anything_is_contacted(script, monkeypatch):
    """It must name the variable, and say it is the SECRET rather than the key id — that is
    the mistake that produces a 401 looking like a permissions problem."""
    monkeypatch.delenv("CB_CAPELLA_API_KEY", raising=False)
    import io
    import sys as _sys

    monkeypatch.setattr(_sys, "argv", ["verify_capella_paths.py", "--org", "ORG"])
    err = io.StringIO()
    monkeypatch.setattr(_sys, "stderr", err)
    assert script.main() == 2
    assert "CB_CAPELLA_API_KEY" in err.getvalue()
    assert "SECRET" in err.getvalue()


@pytest.mark.parametrize(
    "placeholder",
    ["<your-org-id>", "<ORG>", "your-org-id-here", "paste-the-key-secret-here"],
)
def test_a_placeholder_value_is_refused(script, monkeypatch, placeholder):
    """Copying a usage line verbatim is the single most common way to run this wrong, and on
    PowerShell an angle bracket fails to parse before Python even starts — so the error the
    operator sees says nothing about this script unless we say it."""
    code, _out, err = _main(script, monkeypatch, "--org", placeholder)
    assert code == 2
    assert "placeholder" in err
    assert "PowerShell" in err or "redirection" in err


def test_write_probe_without_only_is_refused(script, monkeypatch):
    """It performs real writes. Running it across the whole surface is not something to
    reach by accident."""
    code, _out, err = _main(script, monkeypatch, "--org", "ORG", "--write-probe")
    assert code == 2
    assert "--only" in err


def test_write_probe_and_method_probe_are_mutually_exclusive(script, monkeypatch):
    """One performs the operation and the other deliberately avoids performing it. Accepting
    both would silently pick one."""
    code, _out, err = _main(
        script,
        monkeypatch,
        "--org",
        "ORG",
        "--write-probe",
        "--method-probe",
        "--only",
        "capella_projects_list",
    )
    assert code == 2
    assert "mutually exclusive" in err


def test_an_unknown_operation_name_is_reported(script, monkeypatch):
    """A typo'd --only would otherwise select nothing and report a clean run."""
    code, _out, err = _main(
        script, monkeypatch, "--org", "ORG", "--only", "capella_nope"
    )
    assert code == 2
    assert "capella_nope" in err


def test_keep_app_service_without_bootstrap_is_refused(script, monkeypatch):
    code, _out, err = _main(script, monkeypatch, "--org", "ORG", "--keep-app-service")
    assert code == 2
    assert "--bootstrap-app-service" in err


def test_only_pat_with_nothing_left_to_verify_succeeds(script, monkeypatch):
    """Exit 0, not 2. Every path now cites a primary source, so there is nothing to infer —
    and failing a CI step for having succeeded is how a check gets removed."""
    code, out, _err = _main(script, monkeypatch, "--org", "ORG", "--only-pat")
    assert code == 0
    assert "No [PAT] paths remain" in out


def test_the_organization_is_discovered_when_one_is_visible(
    script, monkeypatch, capsys
):
    """A Capella API key can only see the organizations it belongs to, so discovery removes
    the most error-prone argument entirely."""
    code, out, _err = _main(script, monkeypatch, "--only", "capella_projects_list")
    assert code == 0
    assert "Discovered organization" in out


def test_several_visible_organizations_refuse_to_guess(script, monkeypatch):
    """Picking one would run the whole sweep against an organization the operator did not
    name — and the write probes against it too."""
    _Handler.orgs = [
        {"data": {"id": "ORG", "name": "first"}},
        {"data": {"id": "OTHER", "name": "second"}},
    ]
    try:
        code, _out, err = _main(script, monkeypatch, "--only", "capella_projects_list")
        assert code == 2
        assert "several organizations" in err
        assert "OTHER" in err
    finally:
        _Handler.orgs = [{"data": {"id": "ORG", "name": "the customer"}}]


def test_no_visible_organization_names_the_likely_cause(script, monkeypatch):
    """The usual cause is the key ID being used instead of the key secret."""
    _Handler.orgs = []
    try:
        code, _out, err = _main(script, monkeypatch, "--only", "capella_projects_list")
        assert code == 2
        assert "--org" in err
        assert "SECRET" in err or "secret" in err
    finally:
        _Handler.orgs = [{"data": {"id": "ORG", "name": "the customer"}}]


def test_json_output_is_machine_readable(script, monkeypatch):
    """CI consumes this. A human-formatted table would make the exit code the only signal."""
    code, out, _err = _main(
        script, monkeypatch, "--org", "ORG", "--only", "capella_projects_list", "--json"
    )
    assert code == 0
    # No slicing. `out[out.index("{"):]` is what this used to do, and it is precisely the
    # workaround that hid the defect: stdout carried the discovery preamble in front of
    # the document, so anything that did NOT know to slice — jq, a CI step, a reader —
    # got a parse error out of a successful run.
    payload = json.loads(out)
    assert payload


def test_a_missing_path_fails_the_run(script, monkeypatch):
    """Exit 1 on MISSING is what makes this usable as a CI gate. Reporting the finding and
    exiting 0 would make the job green while a path was wrong."""
    ops = [
        _Op("capella_fake", "GET", "/v4/organizations/{organization_id}/nonexistent")
    ]
    monkeypatch.setattr(script, "load_ops", lambda **_kwargs: ops)
    code, out, _err = _main(script, monkeypatch, "--org", "ORG")
    assert code == 1
    assert "MISSING" in out


def test_a_clean_sweep_exits_zero(script, monkeypatch):
    """Guards the gate from failing on success, which is how a CI check gets disabled."""
    ops = [
        _Op(
            "capella_projects_list",
            "GET",
            "/v4/organizations/{organization_id}/projects",
        )
    ]
    monkeypatch.setattr(script, "load_ops", lambda **_kwargs: ops)
    code, _out, _err = _main(script, monkeypatch, "--org", "ORG")
    assert code == 0


def test_the_static_parse_fallback_is_used_when_the_registry_cannot_import(
    script, monkeypatch, capsys
):
    """The script must run with NOTHING installed — that is how it ran on the operator's
    machine, where `mcp` was absent. The fallback parses spec.py with `ast`."""
    import builtins

    real_import = builtins.__import__

    def _block(name, *args, **kwargs):
        if name.startswith(("handlers", "mcp")):
            raise ModuleNotFoundError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block)
    ops = script.load_ops()
    monkeypatch.undo()

    assert len(ops) > 50, f"the static fallback found only {len(ops)} operations"
    assert all(op.path.startswith("/v4/") for op in ops)


def test_every_placeholder_in_this_script_s_own_usage_text_is_detected(script):
    """Self-consistency: the examples we hand people must be recognised if pasted verbatim.

    `paste-the-key-secret-here` — the placeholder in this file's own PowerShell example, and so
    the most likely value to arrive unsubstituted — matched none of the hints. Deriving the
    check from the documentation rather than from a hand-written list is what keeps the two
    from drifting again.
    """
    import re

    docstring = script.__doc__ or ""
    quoted = re.findall(r"'([^']{6,60})'", docstring)
    examples = [
        value
        for value in quoted
        if "-" in value and not value.startswith(("/", "http", "couchbase"))
    ]
    assert examples, "no quoted example values found in the usage text"

    undetected = [v for v in examples if not script._looks_like_a_placeholder(v)]
    assert not undetected, (
        "these appear as example values in this script's own usage text but would be "
        f"accepted as real: {undetected}"
    )


def test_a_real_looking_value_is_not_refused(script):
    """Guards the detector from rejecting genuine input — a UUID, or a base64-ish key secret.
    Over-refusing would make the script unusable and is not obviously safer."""
    for real in (
        "42730eb3-53ab-451a-b5eb-8eeb9a92084c",
        "aGFydmVzdGVyLXNlY3JldC12YWx1ZQ==",
        "be388b87-43cb-4e9b-a3f1-0f837609c4af",
    ):
        assert not script._looks_like_a_placeholder(real), real


#: The parked registry is ALLOWED to be empty — that is the goal state, reached on
#: 2026-09-01 when the last record was promoted. Tests that need a parked operation to
#: point at skip rather than fail, because "there are none left" is a success and must not
#: read as a broken suite.
def _a_parked_name() -> str:
    from handlers.capella.spec_pending import PENDING_OPS

    if not PENDING_OPS:
        pytest.skip("the parked registry is empty — nothing left to verify")
    return PENDING_OPS[0].name


# ── The parked set: --include-pending ────────────────────────────────────────
#
# handlers/capella/spec_pending.py holds 36 operations that are written but not shipped,
# because their paths were transcribed from the v4 reference and never confirmed against
# a live control plane. CONTRIBUTING.md documents a promotion procedure that begins "run
# the probe" — and until --include-pending existed, load_ops() read spec.py and nothing
# else, so the probe could not see a single one of them. It re-checked the 61 paths that
# were already verified and reported nothing about the 36 that needed verifying.
#
# These tests pin the two halves of the fix: that the parked records are LOADED, and that
# the report distinguishes a promotion candidate from a re-verification. The second half
# matters as much as the first — a run that verifies a parked path and buries the result
# in a 97-line table has done the work and hidden the answer.


def test_the_parked_operations_are_absent_by_default(script):
    """The default must stay the shipped surface. A probe that silently included parked
    paths would report MISSING for records nobody claimed were verified, and the exit
    status is used in CI."""
    parked = _a_parked_name()
    names = {op.name for op in script.load_ops()}
    assert parked not in names


def test_include_pending_loads_every_parked_operation(script):
    shipped = script.load_ops()
    both = script.load_ops(include_pending=True)

    from handlers.capella.spec_pending import PENDING_OPS

    assert len(both) == len(shipped) + len(PENDING_OPS)
    names = {op.name for op in both}
    assert {op.name for op in PENDING_OPS} <= names
    assert len(names) == len(both), "an operation was loaded twice"


def test_a_parked_operation_is_identifiable_as_parked(script):
    """Op is a frozen dataclass, so "this record is parked" cannot be stamped onto the
    object. If the bookkeeping that replaces it drifts, the report silently starts
    describing promotion candidates as ordinary re-verifications."""
    parked = _a_parked_name()
    ops = {op.name: op for op in script.load_ops(include_pending=True)}
    assert script._is_pending(ops[parked])
    assert not script._is_pending(ops["capella_projects_list"])


def test_the_pending_marks_are_cleared_when_pending_is_not_requested(script):
    """A load WITHOUT the flag must not leave the previous run's marks behind — the report
    would then tag shipped operations [PEND] and invite someone to "promote" a record that
    is already in spec.py."""
    script.load_ops(include_pending=True)
    ops = {op.name: op for op in script.load_ops()}
    assert not script._is_pending(ops["capella_projects_list"])
    assert not script._PENDING_NAMES


def test_an_operation_in_both_registries_is_refused(script, monkeypatch):
    """A half-finished promotion: the record was copied into OPS and never deleted from
    PENDING_OPS. Probing it twice reports one path under one name with two verdicts, so
    the run is stopped rather than allowed to produce a report nobody can act on."""
    from handlers.capella import spec_pending
    from handlers.capella.spec import OPS_BY_NAME

    already_shipped = next(iter(OPS_BY_NAME.values()))
    monkeypatch.setattr(
        spec_pending, "PENDING_OPS", (*spec_pending.PENDING_OPS, already_shipped)
    )
    with pytest.raises(SystemExit) as excinfo:
        script.load_ops(include_pending=True)
    assert already_shipped.name in str(excinfo.value)


def test_the_static_fallback_also_reads_the_parked_registry(script, monkeypatch):
    """The fallback exists so the script runs with nothing installed, which is how it runs
    on the machine that has the Capella key. If it silently dropped the parked set there,
    the promotion procedure would work only in an environment nobody performs it in."""
    parked = _a_parked_name()

    import builtins

    real_import = builtins.__import__

    def _block(name, *args, **kwargs):
        if name.startswith(("handlers", "mcp")):
            raise ModuleNotFoundError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block)
    ops = script.load_ops(include_pending=True)
    monkeypatch.undo()

    names = {op.name for op in ops}
    assert parked in names
    assert script._is_pending(next(o for o in ops if o.name == parked))


def test_naming_a_parked_operation_without_the_flag_says_why(script, monkeypatch):
    """ "unknown operation" is a misleading answer here: the record exists, it is simply not
    in the registry this run loaded. Someone following CONTRIBUTING.md hits this first."""
    code, _out, err = _main(
        script, monkeypatch, "--org", "ORG", "--only", _a_parked_name()
    )
    assert code == 2
    assert "--include-pending" in err
    assert "spec_pending.py" in err


def test_a_typo_is_still_reported_as_unknown(script, monkeypatch):
    """The diagnostic above must not swallow the ordinary case it sits next to."""
    code, _out, err = _main(
        script, monkeypatch, "--org", "ORG", "--only", "capella_nope"
    )
    assert code == 2
    assert "capella_nope" in err
    assert "--include-pending" not in err


# ── Discovery of the identifiers only the parked set needs ───────────────────


def test_the_parked_identifiers_are_discovered_only_when_asked(script):
    """Nothing in the shipped registry consumes these four, so an unconditional walk would
    spend four requests a run buying nothing."""
    plain = script.discover("fake-secret", _Args())
    assert "backup_id" not in plain
    assert "alert_integration_id" not in plain

    with_pending = script.discover("fake-secret", _Args(include_pending=True))
    assert with_pending["backup_id"] == "BKP"
    assert with_pending["event_id"] == "EVT"
    assert with_pending["alert_integration_id"] == "ALERT"


def test_an_empty_list_leaves_the_identifier_absent(script, capsys):
    """200 with no items means the PATH is right and the object does not exist here. The
    affected operations must report SKIPPED — inventing an id would make a correct path
    report MISSING, which is the confidently-wrong outcome this script exists to avoid."""
    ids = script.discover("fake-secret", _Args(include_pending=True))
    assert "export_id" not in ids
    out = capsys.readouterr().out
    assert "genuinely has none" in out


def test_absence_says_which_kind_of_nothing_it_found():
    """ "I could not find one" and "there is not one" are different claims, and this
    script reported the first AS the second three times running.

    A nested data-inside-data response read as an empty list. app_endpoint_name was
    never discovered at all, so twenty operations reported no identifier available.
    The backup-cycle step looked for `cycleId` while the rows carried `cycleID`, and
    printed "this bucket has no cycles" in the same run where the cycles list
    returned rows.

    Every one of those read as a statement about the customer's cluster, and the
    old message even ended by telling the operator to provision the thing they
    already had. The distinction is now explicit, and this pins it.
    """
    import importlib.util
    import pathlib as _pathlib

    spec = importlib.util.spec_from_file_location(
        "_vcp",
        _pathlib.Path(__file__).resolve().parent.parent
        / "scripts"
        / "verify_capella_paths.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Genuinely empty: a fact about the cluster.
    empty = module._absence_detail('{"data":[]}', ("cycleId",))
    assert "genuinely has none" in empty
    assert "LIMITATION" not in empty.upper() or "THIS SCRIPT" not in empty

    # Rows present, key spelled differently: a fact about THIS SCRIPT. The exact
    # case that shipped -- cycleID with a capital ID.
    mismatch = module._absence_detail(
        '{"data":[{"createdAt":"2026-09-14","cycleID":"abc"}]}', ("cycleId", "id")
    )
    assert "ROWS WERE RETURNED" in mismatch
    assert "limitation of THIS SCRIPT" in mismatch
    # It must name what IS there, or the reader cannot fix it.
    assert "cycleID" in mismatch
    # And it must steer AWAY from provisioning. The old message ended with
    # "provision one and re-run", which would have sent the operator off to
    # create a backup schedule they already had.
    assert "rather than provisioning" in mismatch
    assert "provision one and re-run" not in mismatch.lower()

    # A body that is not JSON at all is not rows.
    assert "genuinely has none" in module._absence_detail("<html>", ("id",))


def test_a_404_on_a_parked_list_path_is_reported_as_a_finding(script, capsys):
    """The distinction the whole discovery step turns on: "this cluster has none" and "we
    asked the wrong URL" both leave the id absent, and only the second is a defect."""
    script.discover("fake-secret", _Args(include_pending=True))
    out = capsys.readouterr().out
    assert "PARKED LIST PATH IS WRONG" in out


def test_app_services_failing_does_not_abort_the_rest_of_discovery(script, monkeypatch):
    """This used to `return ids`. One 403 on the org-wide App Services list — a list that
    has nothing to do with eventing, replication or the parked set — silently cost every
    later identifier its verdict, and the output gave no hint that the walk had stopped."""
    real_request = script._request

    def _fail_app_services(method, path, token, *args, **kwargs):
        if "/appservices" in path:
            return 403, '{"message":"forbidden"}'
        return real_request(method, path, token, *args, **kwargs)

    monkeypatch.setattr(script, "_request", _fail_app_services)
    ids = script.discover("fake-secret", _Args(include_pending=True))

    assert "app_service_id" not in ids
    # Everything discovered AFTER the App Services list must still be there.
    assert ids["function_name"] == "enrich"
    assert ids["backup_id"] == "BKP"
    assert ids["alert_integration_id"] == "ALERT"


# ── The promotion report ─────────────────────────────────────────────────────


def _pending_report(script, monkeypatch, ops, pending_names):
    """Run the report over a synthetic op set with chosen records marked parked."""
    monkeypatch.setattr(script, "load_ops", lambda **_kwargs: ops)
    monkeypatch.setattr(script, "_PENDING_NAMES", set(pending_names))
    return _main(script, monkeypatch, "--org", "ORG", "--include-pending")


def test_a_verified_parked_path_is_named_as_ready_to_promote(script, monkeypatch):
    """Working out by hand which of 97 rows now has evidence behind it is the step at which
    this stops getting done, so the script does it."""
    ops = [
        _Op(
            "capella_parked_ok",
            "GET",
            "/v4/organizations/{organization_id}/projects",
            summary="[DOC]",
        )
    ]
    code, out, _err = _pending_report(script, monkeypatch, ops, {"capella_parked_ok"})
    assert code == 0
    assert "READY TO PROMOTE" in out
    assert "capella_parked_ok" in out
    assert "LIVE_VERIFIED" in out


def test_a_parked_path_that_404s_is_reported_as_wrong_not_as_pending(
    script, monkeypatch
):
    """A parked record that came back MISSING is the one result here that says something is
    BROKEN. Folding it in with the ones that merely lacked an identifier loses it."""
    ops = [
        _Op(
            "capella_parked_wrong",
            "GET",
            "/v4/organizations/{organization_id}/nope",
            summary="[DOC]",
        )
    ]
    code, out, _err = _pending_report(
        script, monkeypatch, ops, {"capella_parked_wrong"}
    )
    assert code == 1, "a wrong path must fail the run"
    assert "PATH IS WRONG" in out
    assert "do NOT promote it" in out


def test_an_options_probe_does_not_earn_the_method_tag(script, monkeypatch):
    """A 405 from OPTIONS proves the route exists and proves nothing about whether POST is
    accepted there. Tagging that [LIVE+METHOD] would overstate the exact evidence this
    script exists to keep honest."""

    class _Result:
        def __init__(self, method, status, verdict="VERIFIED"):
            self.op = _Op("x", method, "/v4/x")
            self.status = status
            self.verdict = verdict

    assert not script.mode_confirmed_method(_Result("POST", 405))
    assert script.mode_confirmed_method(_Result("POST", 422))
    assert script.mode_confirmed_method(_Result("GET", 200))
    # A GET "verified" by 403 was never actually performed.
    assert not script.mode_confirmed_method(_Result("GET", 403))


def test_the_json_output_marks_which_records_are_parked(script, monkeypatch):
    """The JSON is what a promotion is driven from, so "shipped" and "parked" has to be
    readable without cross-referencing the source."""
    ops = [
        _Op("capella_parked_ok", "GET", "/v4/organizations/{organization_id}/projects")
    ]
    monkeypatch.setattr(script, "load_ops", lambda **_kwargs: ops)
    monkeypatch.setattr(script, "_PENDING_NAMES", {"capella_parked_ok"})
    code, out, _err = _main(
        script, monkeypatch, "--org", "ORG", "--include-pending", "--json"
    )
    assert code == 0
    payload = json.loads(out[out.index("{") :])
    assert payload["results"][0]["pending"] is True


# ── What the first live run exposed ──────────────────────────────────────────
#
# Three defects, all found by pointing the tool at a real organization rather than by
# reading it. Each cost real information in that run, and each is pinned here.


def test_an_options_fallback_never_earns_the_method_tag(script):
    """The tag is the promotion decision. A 405 from OPTIONS proves the route exists and
    says nothing about POST — and a status-only rule would have to guess, which is exactly
    how a [LIVE+METHOD] gets handed out on evidence that does not support it."""

    class _R:
        def __init__(self, method, status, sent, verdict="VERIFIED"):
            self.op = _Op("x", method, "/v4/x")
            self.status = status
            self.verdict = verdict
            self.method_sent = sent

    # The real method was sent and the payload rejected: confirmed.
    assert script.mode_confirmed_method(_R("POST", 422, "POST"))
    # The same status reached via OPTIONS is NOT.
    assert not script.mode_confirmed_method(_R("POST", 422, "OPTIONS"))
    assert not script.mode_confirmed_method(_R("POST", 405, "OPTIONS"))
    assert script.mode_confirmed_method(_R("GET", 200, "GET"))


def test_json_output_is_only_json(script, monkeypatch):
    """`--json > out.json` produced the discovery preamble followed by the object, which no
    JSON reader parses — the promotion step this flag exists to feed had to be hand-edited
    first. The preamble also names the organization, project and cluster."""
    code, out, err = _main(
        script, monkeypatch, "--org", "ORG", "--only", "capella_projects_list", "--json"
    )
    assert code == 0
    json.loads(out)  # the WHOLE of stdout, with no slicing
    # The human report is still produced — on stderr.
    assert "Discovering identifiers" in err


def test_json_records_which_method_was_actually_sent(script, monkeypatch):
    """A promotion is decided from this file, so "we sent POST" and "we sent OPTIONS at a
    POST route" cannot look the same in it."""
    code, out, _err = _main(
        script, monkeypatch, "--org", "ORG", "--only", "capella_projects_list", "--json"
    )
    assert code == 0
    payload = json.loads(out)
    assert payload["results"][0]["method_sent"] == "GET"


def test_out_writes_utf8_not_whatever_the_shell_would_do(script, monkeypatch, tmp_path):
    """PowerShell 5.1 encodes `>` output as UTF-16LE with a BOM. The first live run
    produced a 76KB file that was unreadable as JSON for that reason alone, and the caller
    had no way to know from the script's own instructions."""
    target = tmp_path / "probe.json"
    code, _out, _err = _main(
        script,
        monkeypatch,
        "--org",
        "ORG",
        "--only",
        "capella_projects_list",
        "--json",
        "--out",
        str(target),
    )
    assert code == 0
    raw = target.read_bytes()
    assert not raw.startswith(b"\xff\xfe") and not raw.startswith(b"\xef\xbb\xbf")
    json.loads(raw.decode("utf-8"))


def test_out_implies_json(script, monkeypatch, tmp_path):
    """`--out` on its own used to exit 2 saying it "only means something with --json".

    There is nothing else the flag could mean, so that guard caught only people using it
    correctly — it cost two live runs and prevented no mistake. The document is written.
    """
    target = tmp_path / "probe.json"
    code, _out, _err = _main(
        script,
        monkeypatch,
        "--org",
        "ORG",
        "--only",
        "capella_projects_list",
        "--out",
        str(target),
    )
    assert code == 0
    assert json.loads(target.read_text(encoding="utf-8"))["results"]


# ── Selector query parameters ────────────────────────────────────────────────


def test_a_required_selector_is_sent(script):
    """/queryService/indexes 400s without `bucket`. A 400 counts as VERIFIED, so the run
    reported the path confirmed while never once seeing the endpoint answer — the weakest
    evidence that still looks like evidence."""
    op = _Op(
        "cb_indexes",
        "GET",
        "/v4/organizations/{organization_id}/projects/{project_id}"
        "/clusters/{cluster_id}/queryService/indexes",
    )
    op.query = ("bucket", "scope", "collection")
    seen = {}

    def _capture(method, path, token, *a, **k):
        seen["path"] = path
        return 200, '{"data":[]}'

    original = script._request
    script._request = _capture
    try:
        script.probe(
            op,
            {
                "organization_id": "ORG",
                "project_id": "PROJ",
                "cluster_id": "CL",
                "bucket_id": "BKT",
                "scope_name": "inventory",
            },
            "k",
        )
    finally:
        script._request = original

    assert "bucket=BKT" in seen["path"]
    assert "scope=inventory" in seen["path"]
    # Absent identifiers are omitted rather than sent empty — an empty selector is a
    # different request from no selector.
    assert "collection=" not in seen["path"]


def test_paging_parameters_are_not_sent_as_selectors(script):
    """An endpoint that needs paging to answer at all is a different finding, and quietly
    supplying page/sortBy would hide it."""
    op = _Op("cb_list", "GET", "/v4/organizations/{organization_id}/projects")
    op.query = ("sortBy", "sortDirection", "page")
    assert script._required_query(op, {"bucket_id": "BKT"}) == ""


def test_a_get_verified_by_a_400_does_not_earn_the_method_tag(script):
    """The route matched and the call was refused. Nobody has watched it return data, so
    the response shape is still a guess — and a read tool's response shape is the tool."""

    class _R:
        def __init__(self, status):
            self.op = _Op("x", "GET", "/v4/x")
            self.status = status
            self.verdict = "VERIFIED"
            self.method_sent = "GET"

    assert script.mode_confirmed_method(_R(200))
    assert not script.mode_confirmed_method(_R(400))
    assert not script.mode_confirmed_method(_R(404))


def test_the_static_parse_resolves_a_shared_query_constant(script):
    """`query=_PAGE_QUERY` is a NAME, and `query=("projectId", *_PAGE_QUERY)` is a tuple
    containing one. literal_eval returns None for both, which is indistinguishable from
    "declared nothing" — and shared tuples are how these specs avoid repetition, so that
    reads as "no query parameters" across most of the file.

    The companion guard is test_the_static_parse_carries_every_field_the_script_consults,
    which compares the two loaders field by field. It was correct and it did not fire,
    because `query` had been added to the script and not to CONSULTED_FIELDS — a field the
    guard does not know about is a field it cannot compare. Registering the field is what
    armed it.
    """
    # A bare NAME. _KEYSPACE_QUERY moved into spec.py with the query-index promotion on
    # 2026-09-01, so both shapes now live in the same file — which is the ordinary case
    # and still the one literal_eval cannot read.
    shipped_ks = {
        o.name: o for o in script._ops_by_static_parse("handlers/capella/spec.py")
    }
    assert shipped_ks["capella_query_index_properties_get"].query == (
        "bucket",
        "scope",
        "collection",
    )
    # A tuple SPLICING one, in spec.py itself — the shape that literal_eval also cannot
    # read, and the one that hid most of the registry's query declarations.
    shipped = {
        o.name: o for o in script._ops_by_static_parse("handlers/capella/spec.py")
    }
    assert shipped["capella_app_services_list"].query == (
        "projectId",
        "sortBy",
        "sortDirection",
    )


# ── Discovery picked the wrong bucket, then misread the consequence ──────────


def test_discovery_prefers_a_user_bucket_over_an_internal_one(script):
    """It took the first item in the buckets list, and on the real organization that was
    N1QL_SYSTEM_BUCKET — Couchbase's own. Not a valid keyspace for the query-index API, so
    /queryService/indexes answered 404 for the BUCKET while looking like a 404 for the
    route, and the run told someone to go and fix a record that was correct.

    Capella bucket ids are base64 of the name, so the name is recoverable even when the
    list omits it — which is how the internal one is recognised here.
    """
    ids = script.discover("fake-secret", _Args())
    assert ids["bucket_id"] == "BKT"


def test_a_cluster_with_only_an_internal_bucket_still_gets_one(script):
    """Preferring a user bucket must not mean refusing to probe at all. Probing the system
    bucket beats probing nothing."""
    body = '{"data":[{"id":"TjFRTF9TWVNURU1fQlVDS0VU"}]}'
    assert script._preferred_bucket(body) == "TjFRTF9TWVNURU1fQlVDS0VU"


def test_an_absent_object_is_not_reported_as_a_wrong_path(script, capsys):
    """probe() has always distinguished "the route matched and the object is absent" from
    "the route does not exist", using the Capella domain code. Discovery did not, and
    printed PARKED LIST PATH IS WRONG at a correct record."""
    real = script._request

    def _domain_404(method, path, token, *a, **k):
        if path.endswith("/auditLogExports"):
            return 404, (
                '{"code":11040,"hint":"Returned when the bucket has no indexes.",'
                '"httpStatusCode":404,"message":"no indexes found"}'
            )
        return real(method, path, token, *a, **k)

    script._request = _domain_404
    try:
        ids = script.discover("fake-secret", _Args(include_pending=True))
    finally:
        script._request = real

    out = capsys.readouterr().out
    line = out.split("audit export")[-1].split("\n")[0]
    assert "PARKED LIST PATH IS WRONG" not in line
    assert "route MATCHED" in line
    assert "Capella error 11040" in line
    assert "export_id" not in ids


def test_a_404_matched_only_by_prose_says_so_and_shows_the_body(script, capsys):
    """The two 404 branches are not equally strong, and the output rendered them
    identically — the weaker one printed "Capella error None", which reads as a missing
    value rather than as "a different test was used".

    This is the branch a reader most needs to second-guess, so it names the test and
    carries the body. Without that, a live 404 on /queryService/indexes was accepted and
    there was no way to tell from the run's own output whether the route had matched: the
    evidence was discarded at the moment of judging it.
    """
    real = script._request

    def _prose_404(method, path, token, *a, **k):
        if path.endswith("/auditLogExports"):
            return 404, '{"message":"export job does not exist on cluster CL"}'
        return real(method, path, token, *a, **k)

    script._request = _prose_404
    try:
        script.discover("fake-secret", _Args(include_pending=True))
    finally:
        script._request = real

    line = capsys.readouterr().out.split("audit export")[-1].split("\n")[0]
    assert "Capella error None" not in line
    assert "weaker evidence" in line
    assert "does not exist on cluster CL" in line


def test_every_probe_verdict_records_the_method_it_sent(script):
    """`method_sent` was stamped on some returns and not others, so a GET judged on the
    404 branch reported None — and None is the value that means "unknown", which the
    promotion tag reader treats as "do not object". A field consulted for a promotion
    decision cannot be absent on some paths through the function.
    """
    ids = {"organization_id": "ORG", "project_id": "PROJ", "cluster_id": "CL"}
    for op, mode in (
        (_Op("g", "GET", "/v4/organizations/{organization_id}/projects"), "options"),
        (_Op("g404", "GET", "/v4/organizations/{organization_id}/nope"), "options"),
        (_Op("w", "POST", "/v4/organizations/{organization_id}/projects"), "options"),
        (_Op("m", "POST", "/v4/organizations/{organization_id}/projects"), "method"),
    ):
        result = script.probe(op, ids, "k", mode=mode)
        assert result.method_sent, f"{op.name} ({mode}) recorded no method_sent"


def test_the_prose_scan_reads_the_message_not_the_hint(script):
    """Capella's error envelope carries a generic `hint` that is not about this request.

    One real hint reads "Returned from the API when a database does not have an existing
    On/Off schedule" — containing both "does not have" and "no existing". Scanning the
    whole body meant a router 404 carrying that boilerplate would read as proof the route
    matched, on the strength of a sentence describing a different endpoint.
    """
    misleading_hint = (
        '{"code":404,"httpStatusCode":404,'
        '"hint":"Returned from the API when a database does not have an existing '
        'On/Off schedule.","message":"route not found"}'
    )
    assert not script._object_absent_prose(misleading_hint)

    # The live body this was built from: `code` is the HTTP status echoed back, not a
    # domain code, so the structural check declines it — but the message names a domain
    # object, which only the query-index handler could have produced.
    real = (
        '{"code":404,"hint":"Please review your request and ensure that all required '
        'parameters are correctly provided.","httpStatusCode":404,'
        '"message":"Index not found in key space"}'
    )
    assert script._capella_domain_error(real) is None
    assert script._object_absent_prose(real)

    # Non-JSON keeps the old whole-body behaviour rather than silently answering False.
    assert script._object_absent_prose("bucket GONE does not exist in cluster CL")


# ── Finding an index ─────────────────────────────────────────────────────────


def test_the_index_sweep_looks_past_the_default_keyspace(script):
    """One guess was not good enough. The first attempt asked the first bucket's
    _default._default, got "Index not found in key space", and three parked operations
    stayed parked on the strength of it — a true answer to a question nobody meant to ask.
    An organization can easily have indexes and none in that one spot.
    """
    real = script._request

    def _only_one_keyspace_has_one(method, path, token, *a, **k):
        if "queryService/indexes" in path:
            if "scope=reporting" in path and "collection=daily" in path:
                return 200, '{"data":[{"indexName":"ix_daily_ts"}]}'
            return 404, '{"message":"Index not found in key space"}'
        if path.endswith("/buckets/BKT/scopes"):
            return 200, '{"data":[{"name":"_default"},{"name":"reporting"}]}'
        if path.endswith("/scopes/reporting/collections"):
            return 200, '{"data":[{"name":"daily"}]}'
        return real(method, path, token, *a, **k)

    script._request = _only_one_keyspace_has_one
    try:
        ids = {"bucket_id": "BKT"}
        script._discover_an_index(
            "k", "/v4/organizations/ORG/projects/PROJ/clusters/CL", ids
        )
    finally:
        script._request = real

    assert ids["index_name"] == "ix_daily_ts"


def test_the_index_sweep_is_bounded(script):
    """A convenience, not a survey. An organization with many buckets must not turn one
    probe run into hundreds of requests."""
    real = script._request
    calls = []

    def _never_any(method, path, token, *a, **k):
        if "queryService/indexes" in path:
            calls.append(path)
            return 404, '{"message":"Index not found in key space"}'
        if "/scopes/" in path and path.endswith("/collections"):
            return 200, '{"data":[{"name":"c1"}]}'
        if path.endswith("/scopes"):
            scopes = ",".join(f'{{"name":"s{i}"}}' for i in range(20))
            return 200, '{"data":[' + scopes + "]}"
        if path.endswith("/buckets"):
            buckets = ",".join(f'{{"id":"b{i}"}}' for i in range(20))
            return 200, '{"data":[' + buckets + "]}"
        return real(method, path, token, *a, **k)

    script._request = _never_any
    try:
        ids = {}
        script._discover_an_index(
            "k", "/v4/organizations/ORG/projects/PROJ/clusters/CL", ids
        )
    finally:
        script._request = real

    assert "index_name" not in ids
    assert len(calls) <= script._INDEX_SWEEP_KEYSPACES, (
        f"the sweep made {len(calls)} calls; the ceiling is "
        f"{script._INDEX_SWEEP_KEYSPACES}"
    )


def test_an_empty_sweep_says_what_it_looked_at(script, capsys):
    """ "this organization has no indexes" and "we looked in one empty corner of it" are
    different conclusions, and only the first is worth acting on."""
    real = script._request

    def _never_any(method, path, token, *a, **k):
        if "queryService/indexes" in path:
            return 404, '{"message":"Index not found in key space"}'
        return real(method, path, token, *a, **k)

    script._request = _never_any
    try:
        script._discover_an_index(
            "k", "/v4/organizations/ORG/projects/PROJ/clusters/CL", {"bucket_id": "BKT"}
        )
    finally:
        script._request = real

    out = capsys.readouterr().out
    assert "keyspace(s) asked" in out
    # It must not generalise from a bounded sweep to the whole organization.
    assert "The route ANSWERS" in out
    # And it must name what it asked. A bare "none found" gives an operator who can SEE
    # indexes in the console nothing to compare against, so "the sweep is wrong somehow"
    # never becomes "it never looked at the one I mean".
    assert "Asked:" in out
    assert "BKT.inventory.airline" in out, out


def test_method_probe_never_sends_the_real_method_of_a_destructive_operation(script):
    """--method-probe rests on "an empty body is guaranteed to be rejected", which is an
    assumption about the server rather than a guarantee — probe() has a branch for when it
    is wrong, reporting that the operation "may have just been performed".

    For capella_backup_restore that sentence means a cluster's data was overwritten. The
    exclusion had to be added: the destructive guard existed only for --write-probe, and
    the only thing stopping a real POST to .../backups/{backup_id}/restore was that the
    record happened to carry body_required=(). Recording its required fields — precisely
    what the promotion procedure asks for once a 422 names them — would have armed it.
    """
    sent = []

    def _capture(method, path, token, *a, **k):
        sent.append(method)
        return 405, "{}"

    op = _Op("cb_restore", "POST", "/v4/organizations/{organization_id}/projects")
    op.body_required = ("sourceClusterId",)
    op.destructive = True

    original = script._request
    script._request = _capture
    try:
        result = script.probe(op, {"organization_id": "ORG"}, "k", mode="method")
    finally:
        script._request = original

    assert sent == ["OPTIONS"], f"a destructive operation was probed with {sent}"
    assert result.method_sent == "OPTIONS"
    assert "DESTRUCTIVE" in result.detail


def test_a_non_destructive_write_still_gets_its_method_confirmed(script):
    """The exclusion must not quietly disable the mode for everything else."""
    sent = []

    def _capture(method, path, token, *a, **k):
        sent.append(method)
        return 422, '{"message":"name is required"}'

    op = _Op("cb_create", "POST", "/v4/organizations/{organization_id}/projects")
    op.body_required = ("name",)
    op.destructive = False

    original = script._request
    script._request = _capture
    try:
        result = script.probe(op, {"organization_id": "ORG"}, "k", mode="method")
    finally:
        script._request = original

    assert sent == ["POST"]
    assert result.verdict == "VERIFIED"
    assert result.method_sent == "POST"


def test_a_first_of_many_pick_says_so(script, monkeypatch, capsys):
    """Discovery takes the first project and the first cluster. On a shared organization
    that is a coin toss, and it was silent — so a run reported "this cluster has no
    eventing functions" about a cluster nobody chose, while the function sat on another.

    A survey of the organization and a look at one corner of it cannot print the same way.
    """
    real = script._request

    def _many(method, path, token, *a, **k):
        if path.endswith("/projects"):
            return 200, '{"data":[{"id":"PROJ"},{"id":"PROJ2"},{"id":"PROJ3"}]}'
        if path.endswith("/clusters") and method == "GET":
            return 200, '{"data":[{"id":"CL"},{"id":"CL2"}]}'
        return real(method, path, token, *a, **k)

    monkeypatch.setattr(script, "_request", _many)
    script.discover("fake-secret", _Args())
    out = capsys.readouterr().out

    assert "1 of 3 projects" in out
    assert "1 of 2 clusters" in out
    assert "--project" in out and "--cluster" in out


def test_a_single_target_is_not_flagged(script, capsys):
    """One project and one cluster is unambiguous; saying "1 of 1" would be noise."""
    script.discover("fake-secret", _Args())
    out = capsys.readouterr().out
    assert "1 of 1" not in out


def test_a_nested_list_item_still_yields_its_id(script):
    """v4 sometimes nests one level deeper: {"data":[{"data":{...}}]}. The App Services
    discovery unwrapped that and this helper did not, so an endpoint using the nested
    shape read as an EMPTY LIST — "the cluster has none" for a cluster that has some."""
    nested = '{"data":[{"data":{"name":"enrich_orders"}}]}'
    assert script._first_id(nested, "name", "id") == "enrich_orders"
    flat = '{"data":[{"name":"enrich_orders"}]}'
    assert script._first_id(flat, "name", "id") == "enrich_orders"


def test_the_scope_and_collection_lists_read_the_nested_shape(script):
    """_first_id learned to unwrap {"data":[{"data":{...}}]}; _names did not, so a scopes
    or collections list in that shape came back EMPTY and the index sweep fell back to
    ["_default"] — one keyspace per bucket. Three lookups then produced "this organization
    simply has no index", in an organization that has plenty."""
    assert script._names('{"data":[{"data":{"name":"reporting"}}]}') == ["reporting"]
    assert script._names('{"data":[{"name":"reporting"}]}') == ["reporting"]
    assert script._names('{"data":[]}') == []


def test_the_alternatives_are_named_not_just_counted(script, monkeypatch, capsys):
    """ "1 of 2 clusters" without saying what the other one IS sends someone to the Capella
    console to copy a UUID out of a URL. The id is already in the response that produced
    the count."""
    real = script._request

    def _two(method, path, token, *a, **k):
        if path.endswith("/clusters") and method == "GET":
            return 200, (
                '{"data":[{"id":"CL","name":"sandbox"},'
                '{"id":"CL2","name":"field-demo"}]}'
            )
        return real(method, path, token, *a, **k)

    monkeypatch.setattr(script, "_request", _two)
    script.discover("fake-secret", _Args())
    out = capsys.readouterr().out

    assert "CL2" in out and "field-demo" in out
    assert "<- probing this one" in out


def test_the_sweep_names_buckets_readably(script):
    """Capella bucket ids are base64 of the name. A sweep report printing only
    aGFydmVzdGVy is unreadable to the person being asked to compare it with their
    console."""
    assert script._bucket_label("aGFydmVzdGVy") == "harvester"
    assert script._bucket_label("TjFRTF9TWVNURU1fQlVDS0VU") == "N1QL_SYSTEM_BUCKET"
    # Not base64, or base64 of something unprintable: fall back to the id itself rather
    # than printing mojibake.
    assert script._bucket_label("not-base64!") == "not-base64!"


def test_the_sweep_flags_an_empty_scope_list(script, capsys):
    """ "1 keyspace per bucket" is the signature of a scopes list that came back empty and
    was silently replaced with ["_default"] — which is exactly how a bucket with indexes
    in a named scope gets reported as having none."""
    real = script._request

    def _no_scopes(method, path, token, *a, **k):
        if path.endswith("/scopes"):
            return 200, '{"data":[]}'
        if "queryService/indexes" in path:
            return 404, '{"message":"Index not found in key space"}'
        return real(method, path, token, *a, **k)

    script._request = _no_scopes
    try:
        script._discover_an_index(
            "k", "/v4/organizations/ORG/projects/PROJ/clusters/CL", {"bucket_id": "BKT"}
        )
    finally:
        script._request = real

    assert "scopes list empty" in capsys.readouterr().out


# ── Response shapes ──────────────────────────────────────────────────────────


def test_a_parked_read_reports_its_response_keys(script):
    """capella_eventing_function_code_set has a confirmed PATH and a request body with no
    source anywhere — the Terraform provider has no /code endpoint at all. GET on the same
    path answers 200, and whatever it returns is what the setter round-trips, so reading
    the getter settles the setter without sending anything."""
    op = _Op("cb_code_get", "GET", "/v4/organizations/{organization_id}/projects")
    script._PENDING_NAMES.add("cb_code_get")
    real = script._request
    script._request = lambda *a, **k: (
        200,
        '{"code":"function OnUpdate(){}","name":"x"}',
    )
    try:
        result = script.probe(op, {"organization_id": "ORG"}, "k")
    finally:
        script._request = real
        script._PENDING_NAMES.discard("cb_code_get")

    assert "response keys: code, name" in result.detail


def test_a_sensitive_response_never_has_its_shape_reported(script):
    """Keys are schema; values are not. But an operation flagged sensitive_response is one
    whose response carries a signed URL or a credential, and key names on those endpoints
    are close enough to the secret's shape that the honest default is silence."""
    op = _Op("cb_export_get", "GET", "/v4/organizations/{organization_id}/projects")
    op.sensitive_response = True
    script._PENDING_NAMES.add("cb_export_get")
    real = script._request
    script._request = lambda *a, **k: (200, '{"downloadURL":"https://signed"}')
    try:
        result = script.probe(op, {"organization_id": "ORG"}, "k")
    finally:
        script._request = real
        script._PENDING_NAMES.discard("cb_export_get")

    assert "response keys" not in result.detail
    assert "downloadURL" not in result.detail


def test_a_shipped_read_is_not_shape_reported(script):
    """Only the parked set needs this. A shipped tool's response contract is already
    written down, and adding a line per operation to every run is noise."""
    op = _Op("cb_shipped", "GET", "/v4/organizations/{organization_id}/projects")
    real = script._request
    script._request = lambda *a, **k: (200, '{"a":1,"b":2}')
    try:
        result = script.probe(op, {"organization_id": "ORG"}, "k")
    finally:
        script._request = real
    assert "response keys" not in result.detail


def test_a_list_envelope_reports_the_element_shape(script):
    """{"data":[...],"cursor":{...}} — the useful shape is one ELEMENT. Reporting
    "data, cursor" would describe the envelope every list endpoint shares."""
    assert script._response_shape('{"data":[{"id":1,"name":"x"}],"cursor":{}}') == [
        "id",
        "name",
    ]
    assert script._response_shape('{"data":[{"data":{"z":1,"a":2}}]}') == ["a", "z"]


def test_the_static_parse_reads_sensitive_response(script):
    """Registered in CONSULTED_FIELDS rather than reached with a bare getattr — that is
    the mistake `query` made. Under the static fallback the attribute would be absent,
    getattr(..., False) would answer "not sensitive", and the guard stopping a signed URL
    reaching the report would be inert on the only configuration anyone runs."""
    static = {
        o.name: o for o in script._ops_by_static_parse("handlers/capella/spec.py")
    }
    assert static["capella_database_credential_create"].sensitive_response is True
    assert static["capella_projects_list"].sensitive_response is False


# ── v4 does not use one list envelope ────────────────────────────────────────


def test_a_non_data_envelope_is_read(script):
    """GET /buckets/{id}/scopes answers {"scopes": [...]}, and a scope answers
    {"collections": [...]}. Both helpers assumed {"data": [...]}, so a scopes list read as
    EMPTY — and the caller had `or "_default"` behind it, turning a parse failure into a
    plausible default nobody questioned.

    Three buckets reporting three empty scope lists was never a fact about the
    organization: every bucket has at least a _default scope.
    """
    assert script._names('{"scopes":[{"name":"reporting"},{"name":"_default"}]}') == [
        "reporting",
        "_default",
    ]
    assert script._names('{"collections":[{"name":"daily"}]}') == ["daily"]
    assert script._first_id('{"scopes":[{"name":"reporting"}]}', "name") == "reporting"
    # The common envelope still wins outright.
    assert script._names('{"data":[{"name":"a"}],"cursor":{}}') == ["a"]


def test_an_ambiguous_envelope_fails_closed(script):
    """Two list-valued keys is a shape this does not understand, and guessing between them
    is how the first version came to assume "data" everywhere."""
    assert script._names('{"scopes":[{"name":"a"}],"other":[{"name":"b"}]}') == []


def test_an_assumed_scope_is_labelled_as_assumed(script, capsys, monkeypatch):
    """`or "_default"` printed "_default" whether the scopes list said so or could not be
    read at all. Only one of those is a discovery."""
    real = script._request

    def _unreadable_scopes(method, path, token, *a, **k):
        if path.endswith("/scopes"):
            return 200, '{"unexpected":{"shape":true}}'
        return real(method, path, token, *a, **k)

    monkeypatch.setattr(script, "_request", _unreadable_scopes)
    ids = script.discover("fake-secret", _Args())
    out = capsys.readouterr().out

    assert ids["scope_name"] == "_default"
    assert "ASSUMED" in out


def test_the_keyspace_selector_uses_the_bucket_name(script):
    """A keyspace is `bucket`.`scope`.`collection` — three NAMES. The scope and collection
    selectors were already names while the bucket was a base64 id, which is not a keyspace
    anything would recognise, and the API duly answered "Index not found in key space".
    That is a true statement about a keyspace that does not exist.
    """
    op = _Op("cb_ix", "GET", "/v4/organizations/{organization_id}/projects")
    op.query = ("bucket", "scope", "collection")
    q = script._required_query(
        op,
        {
            "bucket_id": "aGFydmVzdGVy",
            "bucket_name": "harvester",
            "scope_name": "governance",
            "collection_name": "trial_signals",
        },
    )
    assert "bucket=harvester" in q
    assert "aGFydmVzdGVy" not in q
    assert "scope=governance" in q and "collection=trial_signals" in q


def test_the_selector_falls_back_to_the_id(script):
    """A run that could not resolve the name should still ask, rather than omit the
    required parameter and collect a 400."""
    op = _Op("cb_ix", "GET", "/v4/organizations/{organization_id}/projects")
    op.query = ("bucket",)
    assert "bucket=BKT" in script._required_query(op, {"bucket_id": "BKT"})


def test_the_sweep_skips_internal_buckets(script, capsys):
    """Four of twelve keyspaces in a live run went to N1QL_SYSTEM_BUCKET, whose scopes are
    Couchbase's own bookkeeping. Nobody looking for a user index wants that budget."""
    real = script._request

    def _many(method, path, token, *a, **k):
        if path.endswith("/buckets"):
            return 200, (
                '{"data":[{"id":"TjFRTF9TWVNURU1fQlVDS0VU"},{"id":"aGFydmVzdGVy"}]}'
            )
        if "queryService/indexes" in path:
            return 404, '{"message":"Index not found in key space"}'
        return real(method, path, token, *a, **k)

    script._request = _many
    try:
        script._discover_an_index(
            "k", "/v4/organizations/ORG/projects/PROJ/clusters/CL", {}
        )
    finally:
        script._request = real

    out = capsys.readouterr().out
    assert "N1QL_SYSTEM_BUCKET" not in out
    assert "harvester" in out


def test_the_sweep_budget_is_shared_across_buckets(script, capsys):
    """Depth-first spent the whole ceiling inside one bucket's scopes and never reached the
    third bucket at all — so "we looked everywhere" was false in a way the report could not
    show."""
    real = script._request

    def _deep_first_bucket(method, path, token, *a, **k):
        if path.endswith("/buckets"):
            return 200, '{"data":[{"id":"YQ=="},{"id":"Yg=="},{"id":"Yw=="}]}'
        if path.endswith("/scopes"):
            scopes = ",".join(f'{{"name":"s{i}"}}' for i in range(30))
            return 200, '{"scopes":[' + scopes + "]}"
        if path.endswith("/collections"):
            return 200, '{"collections":[{"name":"c1"}]}'
        if "queryService/indexes" in path:
            return 404, '{"message":"Index not found in key space"}'
        return real(method, path, token, *a, **k)

    script._request = _deep_first_bucket
    try:
        script._discover_an_index(
            "k", "/v4/organizations/ORG/projects/PROJ/clusters/CL", {}
        )
    finally:
        script._request = real

    out = capsys.readouterr().out
    # Every bucket must get a look, not just the first.
    for name in ("a.", "b.", "c."):
        assert name in out, f"bucket {name!r} was never asked:\n{out}"


def test_the_sweep_asks_for_exactly_what_it_reports(script):
    """The report printed the decoded bucket NAME while the request carried the base64 ID.

    So a run said it had asked "harvester.governance.trial_signals" and had actually asked
    "aGFydmVzdGVy.governance.trial_signals" — a keyspace that does not exist, answered
    accurately with "Index not found in key space". Twelve of those read as twelve empty
    collections.

    A report that does not print the request it made is worse than no report: it is the
    only thing a reader has to check the tool against, and this one quietly agreed with
    itself.
    """
    asked = []
    real = script._request

    def _capture(method, path, token, *a, **k):
        if "queryService/indexes" in path:
            asked.append(path)
            return 404, '{"message":"Index not found in key space"}'
        if path.endswith("/buckets"):
            return 200, '{"data":[{"id":"aGFydmVzdGVy"}]}'
        if path.endswith("/scopes"):
            return 200, '{"scopes":[{"name":"governance"}]}'
        if path.endswith("/collections"):
            return 200, '{"collections":[{"name":"trial_signals"}]}'
        return real(method, path, token, *a, **k)

    script._request = _capture
    try:
        script._discover_an_index("k", "/v4/organizations/O/projects/P/clusters/C", {})
    finally:
        script._request = real

    assert asked, "the sweep made no query-index request at all"
    assert "bucket=harvester" in asked[0], asked[0]
    assert "aGFydmVzdGVy" not in asked[0], (
        "the sweep sent the base64 id while reporting the name"
    )


def test_a_known_accepted_empty_body_is_never_sent(script):
    """The failure this exists for HAPPENED, on a live object.

    `body_required` says what a CALLER must send. It is not a promise about what the
    SERVER refuses, and _has_required_body treated the two as one claim.
    capella_alert_integration_update declares `config` required — correctly, the
    provider's UpdateAlertRequest has it non-optional — and the live API answered 200 to a
    PUT with {}. The probe had already sent it, so a verification run modified the
    integration it was verifying.

    `empty_body_accepted` records the observation and overrides the inference.
    """
    sent = []

    def _capture(method, path, token, *a, **k):
        sent.append(method)
        return 405, "{}"

    op = _Op("cb_update", "PUT", "/v4/organizations/{organization_id}/projects")
    op.body_required = ("config",)
    op.empty_body_accepted = True

    original = script._request
    script._request = _capture
    try:
        result = script.probe(op, {"organization_id": "ORG"}, "k", mode="method")
    finally:
        script._request = original

    assert sent == ["OPTIONS"], f"the real method was sent anyway: {sent}"
    assert "accept an empty body" in result.detail
    assert not script._has_required_body(op)


def test_the_static_parse_reads_the_empty_body_flag(script):
    """A guard that only works with the SDK installed is the mistake `query` made — and
    this one's absence lets the probe perform a write on the configuration everyone runs.
    """
    static = {
        o.name: o for o in script._ops_by_static_parse("handlers/capella/spec.py")
    }
    assert static["capella_alert_integration_update"].empty_body_accepted is True
    assert static["capella_alert_integration_create"].empty_body_accepted is False


def test_an_accepted_empty_body_is_still_reported_loudly(script):
    """The ERROR branch is what caught this in the first place, and it must stay. Silence
    here would have meant a write with no record of it."""
    op = _Op("cb_thing", "POST", "/v4/organizations/{organization_id}/projects")
    op.body_required = ("name",)
    original = script._request
    script._request = lambda *a, **k: (200, "{}")
    try:
        result = script.probe(op, {"organization_id": "ORG"}, "k", mode="method")
    finally:
        script._request = original
    assert result.verdict == "ERROR"
    assert "may have just been performed" in result.detail


# ── Edge rejections are not evidence ─────────────────────────────────────────


def test_a_proxy_403_is_not_treated_as_proof_of_a_route(script):
    """_PATH_EXISTS admits 403 on the reasoning that a 403 "requires authentication to
    have succeeded first, which requires routing". True of a 403 the API emits. False of
    one the EDGE emits.

    Found live on 2026-09-02: a POST to .../cloudsnapshotbackups/{id}/clone came back as
    an nginx HTML error page — no Capella envelope, no domain code, no JSON. That request
    never reached the API, and this set would have recorded it VERIFIED.
    """
    op = _Op("cb_clone", "POST", "/v4/organizations/{organization_id}/projects")
    original = script._request
    script._request = lambda *a, **k: (
        403,
        "<html>\r\n<head><title>403 Forbidden</title></head>\r\n"
        "<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n"
        "<hr><center>nginx</center>\r\n</body>\r\n</html>",
    )
    try:
        result = script.probe(op, {"organization_id": "ORG"}, "k")
    finally:
        script._request = original

    assert result.verdict == "ERROR", (
        "an edge rejection is inconclusive; recording it VERIFIED claims a route exists "
        "on the strength of a response the API never saw"
    )
    assert "PROXY" in result.detail
    assert "nginx" in result.detail


def test_an_api_403_is_still_proof(script):
    """The narrowing must not throw away the case the rule was written for: Capella's own
    403 does require routing, and remains evidence."""
    op = _Op("cb_thing", "GET", "/v4/organizations/{organization_id}/projects")
    original = script._request
    script._request = lambda *a, **k: (
        403,
        '{"code":4025,"hint":"Check your role.","httpStatusCode":403,'
        '"message":"Access Denied."}',
    )
    try:
        result = script.probe(op, {"organization_id": "ORG"}, "k")
    finally:
        script._request = original
    assert result.verdict == "VERIFIED"


def test_the_edge_detector_is_narrow(script):
    """ "Not JSON" would be far too broad — an empty body on a 204 is normal and proves
    plenty. Only the shape of a proxy error page counts."""
    assert script._looks_like_an_edge_rejection("<html><body>403</body></html>")
    assert script._looks_like_an_edge_rejection(
        "<!DOCTYPE html><title>Forbidden</title>"
    )
    assert script._looks_like_an_edge_rejection("403 Forbidden\nnginx\n")
    # Not edge rejections:
    assert not script._looks_like_an_edge_rejection("")
    assert not script._looks_like_an_edge_rejection('{"code":403,"message":"denied"}')
    assert not script._looks_like_an_edge_rejection('[{"id":"x"}]')
    assert not script._looks_like_an_edge_rejection("Index not found in key space")
