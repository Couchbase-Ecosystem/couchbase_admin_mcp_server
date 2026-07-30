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
    orgs: ClassVar[list] = [{"data": {"id": "ORG", "name": "the deployment"}}]

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
                return self._send(200, {"data": [{"id": "BKT", "name": "travel"}]})
            return self._send(405, {"message": "method not allowed"})
        if path.endswith("/buckets/BKT/scopes"):
            return self._send(200, {"data": [{"name": "inventory"}]})
        if path.endswith("/scopes/inventory/collections"):
            return self._send(200, {"data": [{"name": "airline"}]})
        if path == "/v4/organizations/ORG/projects/PROJ/clusters/CL/appservices":
            return self._send(200, {"data": []})  # none exist -> SKIPPED downstream
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
    def __init__(self, name, method, path, summary="", group="g", body=None):
        self.name = name
        self.method = method
        self.path = path
        self.summary = summary
        self.group = group
        self.body = body


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
    _Handler.orgs = [{"data": {"id": "ORG", "name": "the deployment"}}]
    monkeypatch.setattr("sys.argv", ["verify", "--only-pat", "--json"])
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
        {"data": {"id": "ORG", "name": "the deployment"}},
        {"data": {"id": "ORG2", "name": "Other"}},
    ]
    try:
        monkeypatch.setattr("sys.argv", ["verify", "--only-pat"])
        assert script.main() == 2
        err = capsys.readouterr().err
        assert "several organizations" in err
        assert "ORG2" in err
    finally:
        _Handler.orgs = [{"data": {"id": "ORG", "name": "the deployment"}}]


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
