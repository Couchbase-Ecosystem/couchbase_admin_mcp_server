"""Tests for controls that had NO test behind them.

Every test here closes a mutation that survived the full suite. A control with no
test is a control that can be deleted, inverted or short-circuited by a refactor and
CI will still be green -- and this repo's own history shows that happening twice, with
two "completed" fixes turning out to be absent from the source entirely.

The mutation each test kills is named in its docstring, because the useful question
about a test is not "what does it assert" but "what breakage would it catch".
"""

from __future__ import annotations

import importlib
import json
import sys

import pytest


def _reload_server():
    """Re-execute the shared policy modules and `server` against the current env.

    RELOAD, never sys.modules.pop. Popping rebinds the module to a new object and
    test_transport_edge.py's own importlib.reload(server) then dies with "module server
    not in sys.modules" -- the identical order dependence this file's siblings were just
    fixed for. Writing it the wrong way here reintroduced it immediately, which is a
    fair indication of how easy that mistake is.
    """
    for name in ("profile_config", "handlers.shared"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    if "server" in sys.modules:
        return importlib.reload(sys.modules["server"])
    return importlib.import_module("server")


@pytest.fixture
def _restore_server_module():
    """Put `server` back in step with the ambient environment after a test moved it."""
    yield
    if "server" in sys.modules:
        importlib.reload(sys.modules["server"])


# ── The read-only tool filter (mutation: `if READ_ONLY_MODE:` -> `if False:`) ──


def test_read_only_mode_loads_no_write_tools(monkeypatch, _restore_server_module):
    """Kills: `if READ_ONLY_MODE:` -> `if False:` in server._filter_tools.

    This is the default posture in the Dockerfile and the coarsest write control in
    the product, and it was verified by nothing: with the filter disabled the suite
    stayed at 3014 passed while the server loaded 134 tools including 70 writes,
    instead of 64 tools and zero writes.
    """
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "true")
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://localhost")
    monkeypatch.setenv("CB_USERNAME", "u")
    monkeypatch.setenv("CB_PASSWORD", "p")

    server = _reload_server()

    offenders = [
        t.name
        for t in server._TOOLS
        if not server._is_read_only(t)
        and t.name not in server._ALWAYS_LOADED_IN_READ_ONLY
    ]
    assert not offenders, (
        f"{len(offenders)} write tools loaded in read-only mode: {offenders[:5]}"
    )
    assert server._TOOLS, "no tools loaded at all, so this proves nothing"
    assert len(server._TOOLS) < len(server._RAW_TOOLS), (
        "read-only mode filtered nothing; the filter is not running"
    )


def test_writes_load_when_read_only_is_off(monkeypatch, _restore_server_module):
    """The other polarity, so the test above cannot pass by loading nothing."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "false")
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://localhost")
    monkeypatch.setenv("CB_USERNAME", "u")
    monkeypatch.setenv("CB_PASSWORD", "p")

    server = _reload_server()
    writes = [t for t in server._TOOLS if not server._is_read_only(t)]
    assert writes, "no write tools loaded with read-only mode off"


# ── The console's unauthenticated-API refusal (mutation: guard -> `if False:`) ──


def test_the_console_refuses_the_admin_api_without_auth(monkeypatch):
    """Kills: the `not _INSECURE_NO_AUTH_ACKNOWLEDGED and path.startswith("/api/")`
    guard in gui_server.global_auth_check -> `if False:`.

    That guard is the fix for "every route, including /api/call, was open to any client
    that could reach the port". With it disabled the suite stayed green while
    GET /api/tools answered 200 to an unauthenticated caller.
    """
    pytest.importorskip("flask")
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "0")
    monkeypatch.setenv("GUI_HOST", "127.0.0.1")
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://localhost")
    monkeypatch.setenv("CB_USERNAME", "u")
    monkeypatch.setenv("CB_PASSWORD", "p")

    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    sys.modules.pop("gui.gui_server", None)
    gui = importlib.import_module("gui.gui_server")
    try:
        gui.app.config["TESTING"] = True
        client = gui.app.test_client()
        for path in ("/api/tools", "/api/config"):
            assert client.get(path).status_code == 403, (
                f"{path} served without authentication and without the "
                "CB_GUI_INSECURE_NO_AUTH acknowledgement"
            )
        assert (
            client.post(
                "/api/call",
                json={"tool": "admin_bucket_list", "arguments": {}},
                headers={"Origin": "http://127.0.0.1"},
            ).status_code
            == 403
        )
    finally:
        sys.modules.pop("gui.gui_server", None)


# ── The absolute egress denials (mutation: name/plausibility checks -> `if False:`) ──


@pytest.mark.parametrize(
    "denied_name",
    [
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "localhost",
        "localhost.localdomain",
    ],
)
def test_always_denied_names_hold_even_under_allow_any(monkeypatch, denied_name):
    """Kills: `if host in _ALWAYS_DENIED_NAMES:` -> `if False:`.

    These are documented as denials that "cannot be configured away", and nothing
    tested them: with the check disabled, CB_ADMIN_EGRESS_ALLOW_ANY=true made
    metadata.google.internal an allowed destination for a cluster-originated request.
    """
    from handlers import egress

    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("CB_ADMIN_EGRESS_EXEMPT_FIELDS", "")

    with pytest.raises(egress.EgressDeniedError) as excinfo:
        egress.assert_egress_allowed(denied_name, field="hostname", tool="t")

    # Assert the denial came from the NAME LIST specifically, not from some other
    # layer. Asserting only "it raised" made this test pass against the mutation: in
    # this environment these names fail DNS resolution, or resolve into a denied
    # range, so they are refused either way. That is defence in depth working, but it
    # is not evidence about the layer under test -- and in a cloud environment where
    # metadata.google.internal DOES resolve, the name list is what has to hold.
    assert "loopback or metadata hostname" in str(excinfo.value), (
        f"{denied_name} was denied, but not by _ALWAYS_DENIED_NAMES -- the name-list "
        f"layer may have stopped contributing. Got: {excinfo.value}"
    )


def test_the_always_denied_set_is_not_empty():
    """A parametrised test over an empty set asserts nothing."""
    from handlers import egress

    assert len(egress._ALWAYS_DENIED_NAMES) >= 5


@pytest.mark.parametrize(
    "smuggled",
    [
        "169.254.169.254\x00.corp.example",
        "evil.tld\x00.corp.example",
        "evil.tld\n.corp.example",
        "a" * 300 + ".corp.example",
        "..corp.example",
    ],
)
def test_implausible_hosts_are_refused_against_a_suffix_allowlist(
    monkeypatch, smuggled
):
    """Kills: `if not _is_plausible_host(host):` -> `if False:`.

    This is the control that stops a value this server parses differently from the
    cluster. Untested, and with it disabled a NUL-truncated host smuggled past a
    suffix allowlist: `169.254.169.254\\x00.corp.example` was returned as allowed.
    """
    from handlers import egress

    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", ".corp.example")
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOW_ANY", raising=False)
    monkeypatch.setenv("CB_ADMIN_EGRESS_EXEMPT_FIELDS", "")

    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed(smuggled, field="hostname", tool="t")


def test_a_legitimate_suffix_match_still_passes(monkeypatch):
    """Over-guarding is an outage, so the allowed case is pinned alongside."""
    from handlers import egress

    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", ".corp.example")
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOW_ANY", raising=False)
    monkeypatch.setenv("CB_ADMIN_EGRESS_EXEMPT_FIELDS", "")
    egress.assert_egress_allowed("backup.corp.example", field="hostname", tool="t")


# ── The enterprise profile's https requirement (two surviving mutations) ──


@pytest.mark.parametrize(
    ("issuer", "should_refuse"),
    [
        ("http://idp.example.com/realms/mcp", True),
        ("http://10.0.0.5:8080/realms/mcp", True),
        ("https://idp.example.com/realms/mcp", False),
        ("http://127.0.0.1:8080/realms/mcp", False),
        ("http://localhost:8080/realms/mcp", False),
    ],
)
def test_enterprise_refuses_a_plaintext_oidc_issuer(monkeypatch, issuer, should_refuse):
    """Kills TWO mutations that both survived: disabling the scheme check outright,
    and widening the loopback exemption to any http host.

    The JWKS fetched from this origin is the only thing establishing that a token came
    from the operator's IdP. Over cleartext, a substituted key set mints a token
    carrying the automation scope -- verified accepted -- which is full unattended
    administrator access.
    """
    import profile_config

    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", "/tmp/audit-test.log")
    monkeypatch.setenv("OAUTH_ISSUER", issuer)
    monkeypatch.setenv("OAUTH_AUDIENCE", "aud")
    monkeypatch.delenv("OAUTH_JWKS_URI", raising=False)
    importlib.reload(profile_config)

    https_errors = [e for e in profile_config.validate("enterprise") if "https" in e]
    if should_refuse:
        assert https_errors, f"{issuer} was accepted in the enterprise profile"
    else:
        assert not https_errors, f"{issuer} was wrongly refused: {https_errors}"


def test_enterprise_refuses_a_plaintext_jwks_uri(monkeypatch):
    """The JWKS URI is the same trust anchor by another name."""
    import profile_config

    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", "/tmp/audit-test.log")
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("OAUTH_AUDIENCE", "aud")
    monkeypatch.setenv("OAUTH_JWKS_URI", "http://idp.example.com/certs")
    importlib.reload(profile_config)

    assert [e for e in profile_config.validate("enterprise") if "https" in e]


def test_enterprise_refuses_oauth_skip_verify(monkeypatch):
    """Kills: the enterprise `OAUTH_SKIP_VERIFY` refusal -> `if False:`.

    "The one control the unattended model rests on entirely", per its own error text,
    and the enterprise-profile branch had no test. auth/oidc.py refuses the
    SKIP_VERIFY + REQUIRE_AUTH combination independently, so this is defence in depth
    -- but a defence with no test is one a refactor removes silently.
    """
    import profile_config

    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", "/tmp/audit-test.log")
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("OAUTH_AUDIENCE", "aud")
    monkeypatch.setenv("OAUTH_SKIP_VERIFY", "true")
    importlib.reload(profile_config)

    errors = profile_config.validate("enterprise")
    assert any("OAUTH_SKIP_VERIFY" in e for e in errors)


@pytest.mark.parametrize("spelling", ["true", "yes", "on", "1", "y", "t"])
def test_enterprise_refuses_tls_insecure_in_every_spelling(monkeypatch, spelling):
    """The profile validator and the TLS context builder must agree on truth.

    They did not: this module used {1,true,yes,on} while handlers.shared accepted
    {...,y,t} too, so CB_ADMIN_TLS_INSECURE=y was NOT refused here and WAS honoured
    there -- the server started and then sent cluster administrator credentials with
    certificate and hostname verification disabled.
    """
    import profile_config

    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", "/tmp/audit-test.log")
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("OAUTH_AUDIENCE", "aud")
    monkeypatch.setenv("CB_ADMIN_TLS_INSECURE", spelling)
    importlib.reload(profile_config)

    errors = profile_config.validate("enterprise")
    assert any("CB_ADMIN_TLS_INSECURE" in e for e in errors), (
        f"CB_ADMIN_TLS_INSECURE={spelling!r} accepted in the enterprise profile"
    )


# ── The scope gate's fail-closed path (mutation: return real scopes) ──


def test_current_claims_fails_closed_when_resolution_raises(monkeypatch):
    """Kills: `except Exception: return None` -> returning read+write scopes.

    "Authorization must never be granted because a lookup blew up." With the mutation
    the suite stayed green while check_scope authorized every tool.
    """
    from auth import request_auth, scope_gate

    def boom(*_args, **_kwargs):
        raise RuntimeError("resolution exploded")

    monkeypatch.setattr(request_auth, "resolve_claims", boom, raising=False)
    monkeypatch.setenv("CB_ADMIN_HTTP_REQUIRE_AUTH", "true")
    scope_gate.clear_token_claims()

    assert scope_gate.current_claims() is None, (
        "a failed claims lookup must not produce claims"
    )


# ── Forced logout from a cross-site page (no Origin, no Referer) ──


def _console_client(monkeypatch):
    pytest.importorskip("flask")
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("GUI_HOST", "127.0.0.1")
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://localhost")
    monkeypatch.setenv("CB_USERNAME", "u")
    monkeypatch.setenv("CB_PASSWORD", "p")
    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    sys.modules.pop("gui.gui_server", None)
    gui = importlib.import_module("gui.gui_server")
    gui.app.config["TESTING"] = True
    return gui


def test_a_cross_site_logout_is_refused_without_any_origin_header(monkeypatch):
    """An attacker page with `Referrer-Policy: no-referrer` sends neither Origin nor
    Referer, so the origin allowlist never fired and a cross-site <img> tag pointed at
    /auth/logout cleared the operator's session.

    Sec-Fetch-Site is what distinguishes that from someone typing the URL. It is a
    forbidden header, so page script cannot set or strip it.
    """
    gui = _console_client(monkeypatch)
    try:
        response = gui.app.test_client().get(
            "/auth/logout", headers={"Sec-Fetch-Site": "cross-site"}
        )
        assert response.status_code == 403, (
            "a cross-site-initiated logout was accepted; a forced logout is still a "
            "state change driven by another site"
        )
    finally:
        sys.modules.pop("gui.gui_server", None)


@pytest.mark.parametrize("fetch_site", ["none", "same-origin"])
def test_a_legitimate_logout_still_works(monkeypatch, fetch_site):
    """Direct navigation (`none`) and the console's own UI (`same-origin`) must keep
    working -- requiring Origin/Referer instead of this would break both."""
    gui = _console_client(monkeypatch)
    try:
        response = gui.app.test_client().get(
            "/auth/logout", headers={"Sec-Fetch-Site": fetch_site}
        )
        assert response.status_code != 403, (
            f"Sec-Fetch-Site: {fetch_site} is not cross-site and must not be refused"
        )
    finally:
        sys.modules.pop("gui.gui_server", None)


# ── The verifier script's safety guards and exit code ──


def _run_verifier(args, env=None):
    """Run the path verifier as a program and return (exit_code, output)."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "scripts/verify_capella_paths.py", *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env={**__import__("os").environ, **(env or {})},
        cwd=str(__import__("pathlib").Path(__file__).resolve().parent.parent),
    )
    return result.returncode, result.stdout + result.stderr


@pytest.mark.parametrize(
    "flag", ["--bootstrap-app-service", "--bootstrap-child-objects"]
)
def test_bootstrapping_requires_the_mutate_acknowledgement(flag):
    """Kills: `if False and ...` on each of these two guards.

    Both create billable infrastructure in a real Capella organization, and both
    mutations survived the full suite -- while the sibling guards (--write-probe needs
    --only, destructive write-probe needs --yes-really-mutate, --keep-app-service needs
    --bootstrap-app-service) were all killed. The omission was specific to the two that
    spend money.
    """
    # A credential must be present, or the script exits on the missing-key path before
    # it ever reaches the guard under test -- which would make this pass for the wrong
    # reason. The value is never used: the guard refuses before any request is made.
    code, output = _run_verifier(
        [flag, "--org", "org-1"], env={"CB_CAPELLA_API_KEY": "not-a-real-key"}
    )
    assert code == 2, (
        f"{flag} was accepted without --yes-really-mutate (exit {code}): "
        f"{output[-300:]}"
    )
    assert "yes-really-mutate" in output
    # No results table, which is what proves the refusal came before any work. Checked
    # as the summary LINE rather than the words "VERIFIED"/"SKIPPED", which appear in
    # the refusal message as ordinary prose.
    assert "SKIPPED=" not in output and "VERIFIED=" not in output


def test_the_path_exists_set_excludes_statuses_that_prove_nothing():
    """Kills: adding 5xx (or re-adding 429/401) to _PATH_EXISTS.

    Widening this set raises the VERIFIED count without verifying anything, and adding
    500/502/503 survived the whole suite. 429 and 401 are excluded deliberately: a
    rate-limited run reported every path VERIFIED, and Capella answers 401 BEFORE
    routing -- established live -- so a dead credential did the same.
    """
    import importlib.util
    import pathlib

    spec = importlib.util.spec_from_file_location(
        "_verifier",
        pathlib.Path(__file__).resolve().parent.parent
        / "scripts"
        / "verify_capella_paths.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert {200, 201, 202, 204, 400, 403, 405, 409, 422} == module._PATH_EXISTS
    for proves_nothing in (429, 401, 500, 502, 503, 504):
        assert proves_nothing not in module._PATH_EXISTS, (
            f"{proves_nothing} does not prove a route exists; counting it lets a run "
            "report the whole surface as verified having verified nothing"
        )


# ── Redaction and statement guards must be BOUNDED, not just correct ──


def test_redaction_is_bounded_on_a_large_unbroken_token():
    """A CPU budget, because no functional test can catch this.

    Three separate super-linear patterns shipped in this file, and every one produced
    byte-identical OUTPUT to its bounded replacement -- so correctness tests pass either
    way and only a timing assertion notices a revert.

    The worst was `redact_text`, reachable with NO authentication: an MCP client sending
    a 20 000-character tool NAME stalled the event-loop thread for 25 s (and every other
    client with it), because err() runs redaction over both the message and the `tool=`
    context before the unknown name is refused. A cluster error body reaches the same
    path through each handler's except block. 200 KB extrapolated to roughly 50 minutes.
    """
    import time

    from handlers import shared

    payload = "Z" * 200_000
    for label, call in (
        ("redact_text", lambda: shared.redact_text(payload)),
        ("redact_uri_credentials", lambda: shared.redact_uri_credentials(payload)),
        ("redact (string leaf)", lambda: shared.redact({"cert": payload})),
    ):
        started = time.perf_counter()
        call()
        elapsed = time.perf_counter() - started
        assert elapsed < 1.0, (
            f"{label} took {elapsed:.1f}s on a 200KB unbroken token. This is a denial "
            "of service, not a slow path: it runs on the event-loop thread inside err() "
            "with caller-controlled input. Bound the pattern's quantifiers or cap the "
            "input before scanning."
        )


def test_redaction_still_masks_after_the_bound():
    """The budget above must not have been bought by masking less."""
    from handlers import shared

    for value, expected_masked in (
        ("password: s3cret", True),
        ("CB_PASSWORD=hunter2", True),
        ("couchbase://admin:pw@host", True),
        ("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.abc.def", True),
        ("bearer eyJhbGciOiJSUzI1NiJ9.abc.def", True),
        ("read-only mode", False),
        ("admin_bucket_create", False),
        # A credential as free text under a HARMLESS key. Real shape:
        # admin_eventing_get returns an Eventing function's own source, and a password
        # inside `appcode` was written to the audit log and returned to the model in
        # the clear. That tool is annotated read-only, so it loads in the safest profile.
        ('var x = { "password": "s3cret" };', True),
        ("bearer eyJhbGciOiJSUzI1NiJ9.abc.def", True),
    ):
        out = shared.redact({"m": value})["m"]
        masked = "REDACTED" in out
        assert masked is expected_masked, f"{value!r} -> {out!r}"


def test_an_oversized_statement_is_refused_not_parsed():
    """The SQL++ guards are super-linear and `statement` is caller-supplied.

    200KB of unclosed `/*+` openers took 60 s in the optimizer-hint strip alone --
    a strip that this session ADDED to stop over-guarding legitimate hints. Both the
    length and the opener count are now bounded, and a legitimate hint still passes.
    """
    import time

    from handlers import shared

    started = time.perf_counter()
    refusal = shared.assert_single_statement("SELECT 1 " + "/*+" * 66_669)
    elapsed = time.perf_counter() - started
    assert refusal, "an oversized statement must be refused"
    assert elapsed < 1.0, f"took {elapsed:.1f}s to refuse; the cap is not being applied"

    started = time.perf_counter()
    refusal = shared.assert_single_statement("SELECT 1 " + "/*+" * 5_000)
    elapsed = time.perf_counter() - started
    assert refusal and "optimizer-hint" in refusal, (
        "a statement under the length cap but full of hint openers must be refused by "
        f"the opener-count bound; got {refusal!r}"
    )
    assert elapsed < 1.0, f"took {elapsed:.1f}s"

    # And the legitimate forms still work, or this is just over-guarding.
    assert (
        shared.assert_single_statement("SELECT /*+ INDEX(t idx_a) */ * FROM `b` t")
        is None
    )
    assert shared.assert_single_statement("SELECT * FROM `b` WHERE a = 1") is None


# ── A gap mutation testing found and the suite did not ──
#
# The companion to this one -- an unknown PKCE state accepted when the login cookie
# agrees -- lives in tests/test_gui_oauth_routes.py rather than here, because that is
# the file the round-5 harness runs for the console mutations. A test in this file
# would have proved the control and still let the mutation report itself uncaught.


def test_status_never_reports_the_connection_string_verbatim(monkeypatch):
    """Kills: breaking redact_uri_credentials, which is what actually enforces this.

    Not "kills: dropping redact_uri_credentials from mcp_status" -- that was the round-5
    entry, and it is now a no-op, because redact() masks credentials in every string leaf
    and that path runs redact_uri_credentials too. The entry has been withdrawn with the
    reasoning recorded in scripts/mutation_round_5.py; this test asserts the observable
    behaviour rather than either layer, so it holds whichever one is doing the work.

    Worth asserting at all because cb_mcp_status is annotated read-only, so it loads in
    the safest deployment and an agent calls it freely -- and CB_CONNECTION_STRING carries
    the cluster password in the `couchbase://user:pw@host` form, which is the documented
    way to set it.
    """
    from handlers import mcp_status

    monkeypatch.setenv(
        "CB_CONNECTION_STRING", "couchbases://admin:sup3rs3cret@cb.example.com"
    )
    payload = json.loads(mcp_status.handle("cb_mcp_status", {})[0].text)
    rendered = json.dumps(payload)
    assert "sup3rs3cret" not in rendered, (
        "cb_mcp_status returned the cluster password in clear; the connection string "
        "must go through redact_uri_credentials"
    )
    assert "cb.example.com" in rendered, (
        "the host was masked too, which makes the tool useless for diagnosing "
        "connectivity -- only the credential should be removed"
    )
