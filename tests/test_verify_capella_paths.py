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
                return self._send(200, {"data": [{"id": "BKT", "name": "travel"}]})
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
    assert result.verdict == "SKIPPED"
    assert "could SUCCEED and mutate" in result.detail


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
    monkeypatch.setattr(script, "load_ops", lambda: [_Op("op", "GET", "/v4/x")])

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
    monkeypatch.setattr(script, "load_ops", lambda: [_Op("op", "GET", "/v4/x")])
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


def test_the_app_endpoint_keyspace_is_spelled_out(script, monkeypatch):
    """A bare endpoint name is ACCEPTED by v4 and read as `<name>._default._default`, so on a
    cluster with named scopes it silently targets the wrong collection. The two
    accessControlFunction paths take a keyspace, so getting this wrong would verify the right
    route against the wrong object."""
    rec = _ChildRecorder()
    monkeypatch.setattr(script, "_request", rec)
    ids = dict(BASE_IDS)
    script.bootstrap_child_objects("tok", "/base", ids, {})

    assert (
        ids["app_endpoint_keyspace"] == f"{ids['app_endpoint_name']}.inventory.airline"
    )


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
    monkeypatch.setattr(script, "load_ops", lambda: [_Op("op", "GET", "/v4/x")])
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
    monkeypatch.setattr(script, "load_ops", lambda: [_Op("op", "GET", "/v4/x")])

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
