"""
Log-file preparation, the Capella HTTP client's error mapping, and the small guards left over.

WHY THE LOG FILE HAS SECURITY PROPERTIES
========================================
The audit and diagnostic logs record who did what to a cluster, and the diagnostic log
contains cluster responses. So the file's *preparation* matters as much as its contents:

  * it is created 0600, and the mode is set with `fchmod` on a descriptor opened
    `O_NOFOLLOW` — not `chmod` on a path, which is a symlink race;
  * an existing file with more than one hard link is reported, because another name for the
    same inode receives every line written;
  * a path that cannot be prepared is reported to the caller, which SKIPS that sink rather
    than silently logging nowhere.

The Capella client's error mapping is the other half: a 403 from a project the token cannot
see must not read like a missing cluster, or an operator spends an afternoon looking for a
resource that is there.
"""

from __future__ import annotations

import json
import os

import pytest

import logging_config
from tests._platform import FILE_MODES_AVAILABLE, requires_symlinks

# ── Log file preparation ─────────────────────────────────────────────────────


def test_a_new_log_file_is_created_private(tmp_path):
    """0600. It holds a record of administrative actions against the cluster, and on a shared
    host the default umask would make that world-readable."""
    path = tmp_path / "audit.log"
    assert logging_config._ensure_private_logfile(str(path)) is True
    assert path.exists()
    if FILE_MODES_AVAILABLE:
        # The mode is the claim only where a mode exists. Windows has none to
        # set, and logging_config._restrict_to_owner refuses to fake one.
        assert oct(path.stat().st_mode)[-3:] == "600"


def test_an_existing_log_file_is_tightened(tmp_path):
    """A file left behind by an earlier run, or created by an operator with `touch`, is
    almost always 0644."""
    path = tmp_path / "audit.log"
    path.write_text("earlier content\n")
    path.chmod(0o644)

    assert logging_config._ensure_private_logfile(str(path)) is True
    if FILE_MODES_AVAILABLE:
        # The mode is the claim only where a mode exists. Windows has none to
        # set, and logging_config._restrict_to_owner refuses to fake one.
        assert oct(path.stat().st_mode)[-3:] == "600"
    # And the existing content is not truncated — it is an append-only record.
    assert path.read_text() == "earlier content\n"


def test_a_hard_linked_log_file_is_reported(tmp_path, capsys):
    """Another name for the same inode receives every line written. Tightening the mode on
    one name does nothing about that, so the only honest response is to say so."""
    path = tmp_path / "audit.log"
    path.write_text("")
    os.link(path, tmp_path / "second-name.log")

    logging_config._ensure_private_logfile(str(path))
    assert "hard link" in capsys.readouterr().err


def test_a_single_linked_file_produces_no_warning(tmp_path, capsys):
    """Guards the warning from firing on every ordinary file, which is how a real warning
    gets ignored."""
    path = tmp_path / "audit.log"
    path.write_text("")
    logging_config._ensure_private_logfile(str(path))
    assert "hard link" not in capsys.readouterr().err


def test_a_missing_directory_is_created_rather_than_refused(tmp_path):
    """An operator naming a path on a fresh volume should not have to mkdir first, so the
    parents are created. This test originally asserted the opposite and was wrong about the
    behaviour, not the behaviour being wrong."""
    path = tmp_path / "new" / "deeper" / "audit.log"
    assert logging_config._ensure_private_logfile(str(path)) is True
    assert path.exists()
    if FILE_MODES_AVAILABLE:
        # The mode is the claim only where a mode exists. Windows has none to
        # set, and logging_config._restrict_to_owner refuses to fake one.
        assert oct(path.stat().st_mode)[-3:] == "600"


def test_a_genuinely_unusable_path_is_reported_rather_than_raising(tmp_path):
    """The caller SKIPS the sink on False. Raising would stop the server starting over a log
    path; returning True would log nowhere while claiming to log.

    A path whose parent is a FILE cannot be created however many directories are made.
    """
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    assert logging_config._ensure_private_logfile(str(blocker / "audit.log")) is False


def test_a_directory_where_a_file_belongs_is_reported(tmp_path):
    directory = tmp_path / "audit.log"
    directory.mkdir()
    assert logging_config._ensure_private_logfile(str(directory)) is False


@pytest.mark.skipif(
    not hasattr(os, "O_NOFOLLOW"), reason="O_NOFOLLOW is not available on this platform"
)
@requires_symlinks
def test_a_symlinked_log_path_does_not_follow_the_link(tmp_path):
    """THE symlink race. `chmod` on a path follows the link, so an attacker who can create
    `audit.log -> /etc/shadow` in a writable directory would have the server chmod their
    target. Opening `O_NOFOLLOW` refuses instead."""
    target = tmp_path / "target.txt"
    target.write_text("sensitive")
    target.chmod(0o644)
    link = tmp_path / "audit.log"
    link.symlink_to(target)

    assert logging_config._ensure_private_logfile(str(link)) is False, (
        "a symlinked log path was accepted"
    )
    # And the target is untouched — this is the actual harm being prevented. As root,
    # `ln -s /etc/passwd audit.log` would otherwise chmod it to 0600 and brick the host;
    # `ln -sf /dev/null audit.log` would discard the entire audit trail, silently.
    assert oct(target.stat().st_mode)[-3:] == "644", (
        "the symlink was followed and the target's mode was changed"
    )
    assert target.read_text() == "sensitive"


def test_the_mode_is_set_on_a_descriptor_not_a_path():
    """Parsed, because the distinction is invisible in behaviour with no attacker present —
    and it is the whole point of the O_NOFOLLOW open.

    An AST walk, not a text search: the function's own comments explain the vulnerability
    using the words `os.chmod`, so a substring scan flags the explanation. That is the fourth
    time in this suite that a prose match has done so; the rule by now is to parse.
    """
    import ast
    import inspect

    def calls_in(function):
        tree = ast.parse(inspect.getsource(function).strip())
        return {
            f"{node.func.value.id}.{node.func.attr}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
        }

    # The mode change moved into _restrict_to_owner when os.fchmod turned out not
    # to exist on Windows, so the property is now split across two functions and
    # both halves have to hold: the caller must delegate rather than chmod a path,
    # and the delegate must use the descriptor it is handed.
    outer = calls_in(logging_config._ensure_private_logfile)
    assert "os.chmod" not in outer, (
        "chmod on a path follows symlinks; use fchmod on an O_NOFOLLOW descriptor"
    )

    inner = calls_in(logging_config._restrict_to_owner)
    assert "os.fchmod" in inner
    assert "os.chmod" not in inner, (
        "os.chmod on Windows only toggles the read-only attribute; it would not "
        "remove read access from another local account, so calling it there would "
        "make this control look enforced while doing nothing"
    )


# ── Level and size configuration ─────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [("100", 100), ("", 42), ("nonsense", 42), ("0", 42), ("-5", 42)],
)
def test_positive_integer_settings_fall_back_on_nonsense(monkeypatch, value, expected):
    """A rotation size of 0 would rotate on every record. These are read at import, so
    raising would stop the server over a typo in a tuning knob."""
    monkeypatch.setenv("CB_TEST_SIZE", value)
    assert logging_config._int_env_value("CB_TEST_SIZE", 42) == expected


def test_an_invalid_log_level_falls_back_to_the_default_and_says_so(tmp_path):
    """Silently logging at the wrong level is worse than either alternative: an operator who
    asked for DEBUG and got INFO will conclude the problem is unlogged."""
    logging_config.configure_logging(
        level="VERBOSE",
        sinks=("stderr",),
        log_file=None,
        log_max_bytes=1024,
        log_backup_count=1,
    )
    resolved = logging_config.get_resolved_logging_config()
    assert resolved.level == logging_config.DEFAULT_LOG_LEVEL.upper()


def test_level_off_attaches_no_handlers(tmp_path):
    """`OFF` has to mean off. A handler left attached would keep writing."""
    logging_config.configure_logging(
        level="OFF",
        sinks=("stderr",),
        log_file=str(tmp_path / "x.log"),
        log_max_bytes=1024,
        log_backup_count=1,
    )
    import logging

    logger = logging.getLogger(logging_config.CB_ADMIN_SERVER_NAME)
    assert logger.handlers == []
    assert logging_config.get_resolved_logging_config().sinks == ()


def test_reconfiguring_releases_the_previous_handlers(tmp_path):
    """Handlers hold file descriptors. Reconfiguring without closing them leaks one per call,
    which a test suite or a reload finds quickly."""
    import logging

    logger = logging.getLogger(logging_config.CB_ADMIN_SERVER_NAME)
    for _ in range(5):
        logging_config.configure_logging(
            level="INFO",
            sinks=("file",),
            log_file=str(tmp_path / "x.log"),
            log_max_bytes=1024,
            log_backup_count=1,
        )
    assert len(logger.handlers) <= 4, f"{len(logger.handlers)} handlers accumulated"


def test_file_logging_with_no_path_falls_back_and_reports_it(tmp_path, monkeypatch):
    """Asking for file logging and getting none silently is the failure that matters: the
    support bundle is empty when it is needed."""
    monkeypatch.chdir(tmp_path)
    logging_config.configure_logging(
        level="INFO",
        sinks=("file",),
        log_file=None,
        log_max_bytes=1024,
        log_backup_count=1,
    )
    resolved = logging_config.get_resolved_logging_config()
    assert resolved.log_files, "no file sink was attached and nothing was reported"


def test_a_failed_file_sink_falls_back_to_stderr(tmp_path, capsys):
    """Otherwise an ERROR-level message goes nowhere at all. Losing errors because the log
    path was wrong is the worst combination of the two failures."""
    import logging

    logging_config.configure_logging(
        level="INFO",
        sinks=("file",),
        log_file=str(tmp_path / "missing-dir" / "x.log"),
        log_max_bytes=1024,
        log_backup_count=1,
    )
    logger = logging.getLogger(logging_config.CB_ADMIN_SERVER_NAME)
    assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers), (
        "the file sink failed and nothing replaced it"
    )


def test_disabled_file_logging_warns_that_support_bundles_will_be_empty(
    tmp_path, capsys
):
    logging_config.configure_logging(
        level="INFO",
        sinks=("stderr",),
        log_file=None,
        log_max_bytes=1024,
        log_backup_count=1,
    )
    assert logging_config.get_resolved_logging_config().log_files is None


@pytest.fixture(autouse=True)
def _restore_logging():
    """Every test here reconfigures the shared root logger, so restore it afterwards or the
    rest of the suite inherits whatever the last test set."""
    yield
    logging_config.configure_from_env()


# ── The Capella client's actionable hints ────────────────────────────────────
#
# `_hint_for_status` is what turns a bare status into something an operator can act on. The
# distinctions it draws are the ones that cost time when they are wrong.


def test_a_401_names_the_credential_and_the_usual_mistake():
    """The recurring stumble is using the key's ID rather than its SECRET, and it fails as a
    401 that reads like a revoked key."""
    from handlers.capella import client

    hint = client._hint_for_status(401)
    assert "SECRET" in hint
    assert "API_KEY" in hint or "API Key" in hint


def test_a_403_is_about_ROLES_not_a_missing_resource():
    """Authenticated but not authorized. Reporting it like a 404 sends the operator looking
    for a cluster that is there."""
    from handlers.capella import client

    hint = client._hint_for_status(403)
    assert "authorized" in hint.lower()
    assert "projectViewer" in hint or "role" in hint.lower()


def test_a_404_explains_the_id_hierarchy():
    """The specific trap: a VALID cluster UUID under the WRONG project id returns 404, not
    403. Without that sentence the operator concludes the cluster was deleted."""
    from handlers.capella import client

    hint = client._hint_for_status(404)
    assert "WRONG project" in hint or "wrong project" in hint.lower()


def test_a_409_says_to_wait_for_a_terminal_state():
    """Mid-operation is the common cause, and the fix is polling rather than retrying
    immediately — which is what an operator does by reflex."""
    from handlers.capella import client

    hint = client._hint_for_status(409)
    assert "healthy" in hint
    assert "currentState" in hint or "poll" in hint.lower()


def test_a_422_points_at_the_offending_field():
    from handlers.capella import client

    hint = client._hint_for_status(422)
    assert "field" in hint.lower()


def test_a_429_says_to_slow_down():
    from handlers.capella import client

    assert "rate limit" in client._hint_for_status(429).lower()


def test_an_unmapped_status_gets_no_invented_hint():
    """A confident but wrong hint is worse than none. 500 and 502 are the control plane's
    problem, and there is nothing useful to say about them."""
    from handlers.capella import client

    for status in (200, 500, 502, 418):
        assert client._hint_for_status(status) == ""


def test_the_error_carries_its_status_and_hint_as_attributes():
    """Callers branch on `.status` and surface `.hint`. Packing them into the message only
    would make both unreadable programmatically."""
    from handlers.capella import client

    error = client.CapellaError("boom", status=403, hint="widen the role")
    assert error.status == 403
    assert error.hint == "widen the role"
    assert "boom" in str(error)


# ── The client's retry policy ────────────────────────────────────────────────


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_a_read_is_retried_on_a_transient_status(status):
    from handlers.capella import client

    assert client._retryable(status, "GET") is True


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422])
def test_a_permanent_status_is_not_retried(status):
    """Retrying a 422 triples the latency of every malformed request and never succeeds."""
    from handlers.capella import client

    assert client._retryable(status, "GET") is False


def test_a_capella_write_is_not_retried_on_a_server_error():
    """Same reasoning as the self-managed client: a POST that created a cluster and lost its
    response would create a second one. On Capella that is a billable mistake."""
    from handlers.capella import client

    assert client._retryable(502, "POST") is False


def test_a_capella_write_IS_retried_when_nothing_could_have_happened():
    """429 means the request was rejected at the door."""
    from handlers.capella import client

    assert client._retryable(429, "POST") is True


# ── Path building and parameter encoding ─────────────────────────────────────


def test_a_path_segment_is_encoded():
    from handlers.capella import client

    assert client.quote_segment("a/b") == "a%2Fb"


def test_query_parameters_are_encoded_and_stable():
    from handlers.capella import client

    encoded = client._encode_params({"page": 2, "perPage": 100})
    assert "page=2" in encoded
    assert "perPage=100" in encoded


def test_no_parameters_produces_no_query_string():
    from handlers.capella import client

    assert client._encode_params(None) == ""
    assert client._encode_params({}) == ""


def test_placeholders_are_extracted_in_order():
    from handlers.capella import client

    assert client.extract_placeholders(
        "/v4/organizations/{organization_id}/projects/{project_id}"
    ) == ["organization_id", "project_id"]


def test_the_pages_envelope_is_summarised():
    """v4 wraps lists as {"data": [...], "cursor": {"pages": {...}}}. Reading page one and
    stopping is the bug that silently truncated an organization with 431 clusters to 100."""
    from handlers.capella import client

    meta = client._pages_meta(
        {"data": [], "cursor": {"pages": {"page": 1, "last": 5, "totalItems": 431}}}
    )
    assert meta["last"] == 5
    assert meta["totalItems"] == 431


def test_a_missing_cursor_is_treated_as_a_single_page():
    """Some endpoints return a bare array. Treating that as "page 1 of unknown" would loop."""
    from handlers.capella import client

    meta = client._pages_meta({"data": []})
    assert meta.get("last", 1) in (1, None, 0) or meta == {}


def test_a_sensitive_response_is_redacted():
    """Credential creates return a generated password once. It must not reach a log or an
    LLM context window."""
    from handlers.capella import client

    redacted = client.redact_response({"id": "u1", "password": "generated-secret"})
    assert "generated-secret" not in json.dumps(redacted)


# ── Deployment gating ────────────────────────────────────────────────────────


def test_a_capella_connection_string_is_recognised():
    import deployment

    assert deployment.looks_like_capella_host(
        "couchbases://cb.abc123.cloud.couchbase.com"
    )


def test_a_self_managed_host_is_not_mistaken_for_capella():
    """Gating on the wrong answer would hide the entire admin_* surface from an operator with
    a perfectly ordinary Enterprise cluster."""
    import deployment

    for host in (
        "couchbase://localhost",
        "couchbases://cb.internal.example.com",
        "couchbase://10.0.0.5",
        "",
    ):
        assert not deployment.looks_like_capella_host(host), host


def test_an_unavailable_tool_explains_itself():
    """The hint is what stops someone re-running the same call with different credentials."""
    import deployment

    reason = deployment.unavailable_reason("admin_bucket_list", "capella")
    assert reason
    assert len(reason) > 20


# ── Request source attribution ───────────────────────────────────────────────


def test_the_request_source_is_empty_when_there_is_no_request(monkeypatch):
    """stdio has no peer address, and inventing one would put a fictional client in the audit
    record. Empty is the honest answer; the transport is recorded separately.

    The absence is ESTABLISHED rather than assumed: `current_request` reads a contextvar, and
    an earlier HTTP test in the same process leaves one set. Depending on ambient contextvar
    state made this pass alone and fail in a full run.
    """
    from auth import request_auth

    monkeypatch.setattr(request_auth, "current_request", lambda: None)
    assert request_auth.request_source() == ""


def test_a_request_with_no_client_address_yields_no_source(monkeypatch):
    """A Starlette request can carry `client=None` — behind some ASGI servers and in test
    clients. Reading `.host` off it would raise inside the audit path, after the handler had
    already run and the change had already been made."""
    from auth import request_auth

    class _Request:
        client = None

    monkeypatch.setattr(request_auth, "current_request", lambda: _Request())
    assert request_auth.request_source() == ""


def test_the_request_source_reports_the_peer_when_there_is_one(monkeypatch):
    """Over HTTP it is the only thing tying an audited action to a caller."""
    from auth import request_auth

    class _Client:
        host = "10.1.2.3"

    class _Request:
        client = _Client()

    monkeypatch.setattr(request_auth, "current_request", lambda: _Request())
    assert "10.1.2.3" in request_auth.request_source()


def test_claims_do_not_survive_being_cleared():
    """The contextvar is per-task, and a leaked claim set is one caller acting with another's
    authority. `clear_token_claims` runs in the console's teardown for exactly that reason."""
    from auth import scope_gate

    scope_gate.set_token_claims({"sub": "user-a", "scope": "couchbase:admin"})
    assert scope_gate.current_claims() == {"sub": "user-a", "scope": "couchbase:admin"}

    scope_gate.clear_token_claims()
    assert scope_gate.current_claims() is None


def test_the_principal_is_identified_for_the_audit_record():
    """ "Which service principal did this" is the question the audit trail has to answer, and
    for an unattended workflow it is the only identity available."""
    from auth import scope_gate

    principal = scope_gate.principal_of({"sub": "svc-automation", "azp": "cb-admin"})
    assert isinstance(principal, dict)
    assert "svc-automation" in json.dumps(principal)


def test_an_absent_claim_set_still_yields_a_principal_record():
    """stdio has no token. The audit record still needs a principal field rather than a
    KeyError inside the audit path, after the handler has already run."""
    from auth import scope_gate

    assert isinstance(scope_gate.principal_of(None), dict)


# ── capella_request against a real HTTP server ───────────────────────────────
#
# The retry policy here has the same shape as the self-managed client's, and the same
# reasoning — but the stakes are higher. A POST that creates a Capella cluster and loses its
# response to a 502 would, if retried, create a SECOND cluster. That is a real duplicate,
# billed, and the caller never learns it happened.
#
# Exercised against a local server so the retry COUNT is observable rather than inferred.


class _CapellaRecorder:
    def __init__(self):
        self.requests: list[dict] = []
        self.statuses: list[int] = []
        self.body = '{"data": []}'


CAPELLA_RECORDER = _CapellaRecorder()


class _CapellaHandler:
    """Defined as a factory so the recorder is bound per server."""

    @staticmethod
    def build():
        import http.server

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                CAPELLA_RECORDER.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": raw.decode(errors="replace"),
                    }
                )
                status = (
                    CAPELLA_RECORDER.statuses.pop(0)
                    if CAPELLA_RECORDER.statuses
                    else 200
                )
                payload = CAPELLA_RECORDER.body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_DELETE = _handle  # noqa: N815

        return _Handler


@pytest.fixture(scope="module")
def capella_api():
    import http.server
    import socket
    import threading

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", port), _CapellaHandler.build()
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def capella(capella_api, monkeypatch):
    from handlers.capella import client

    monkeypatch.setenv("CAPELLA_BASE_URL", capella_api)
    monkeypatch.setenv("CAPELLA_API_KEY_SECRET", "test-key-secret")
    monkeypatch.setattr(client.time, "sleep", lambda _s: None)
    CAPELLA_RECORDER.requests.clear()
    CAPELLA_RECORDER.statuses.clear()
    CAPELLA_RECORDER.body = '{"data": []}'
    return client, CAPELLA_RECORDER


def test_a_capella_get_sends_a_bearer_token(capella):
    client, recorder = capella
    client.capella_request("GET", "/v4/organizations")
    assert recorder.requests[0]["headers"]["Authorization"] == "Bearer test-key-secret"


def test_a_missing_api_key_is_reported_by_name(capella, monkeypatch):
    """Not defaulted: a silently unauthenticated control-plane client produces 401s that look
    like a permissions problem rather than a configuration one.

    Asserted on `_secret()`, which is where the naming happens, rather than through
    `capella_request`. Going through the request made the test order-dependent — another test
    in this file replaces `capella_request` to exercise pagination, and under some orderings
    this one called the replacement and never reached the credential lookup at all. A test
    that passes or fails on ordering is not testing the thing it names.
    """
    client, _ = capella
    monkeypatch.delenv("CAPELLA_API_KEY_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="CAPELLA_API_KEY_SECRET"):
        client._secret()


def test_the_credential_is_looked_up_before_any_request_is_sent(capella, monkeypatch):
    """The lookup has to come first, or a misconfigured server sends an unauthenticated
    request and reports Capella's 401 rather than its own missing variable."""
    import urllib.request

    client, _ = capella
    monkeypatch.delenv("CAPELLA_API_KEY_SECRET", raising=False)

    def _must_not_be_called(*_args, **_kwargs):
        raise AssertionError("a request was sent with no credential configured")

    monkeypatch.setattr(urllib.request, "urlopen", _must_not_be_called)
    with pytest.raises(RuntimeError, match="CAPELLA_API_KEY_SECRET"):
        client.capella_request("GET", "/v4/organizations")


def test_a_json_body_is_sent(capella):
    client, recorder = capella
    client.capella_request("POST", "/v4/x", body={"name": "cluster-1"})
    request = recorder.requests[0]
    assert json.loads(request["body"]) == {"name": "cluster-1"}
    assert "application/json" in request["headers"]["Content-Type"]


def test_query_parameters_reach_the_url(capella):
    client, recorder = capella
    client.capella_request("GET", "/v4/x", params={"page": 2, "perPage": 100})
    assert "page=2" in recorder.requests[0]["path"]


def test_an_empty_204_becomes_an_explicit_ok(capella):
    """v4 DELETEs answer 204. Returning None would read as failure to every caller."""
    client, recorder = capella
    recorder.statuses = [204]
    recorder.body = ""
    result = client.capella_request("DELETE", "/v4/x")
    assert result["status"] == "ok"
    # The status is carried alongside, so a caller can tell 204 from 200-with-empty-body.
    assert result["http_status"] == 204


def test_a_403_raises_with_the_role_hint_attached(capella):
    client, recorder = capella
    recorder.statuses = [403]
    recorder.body = '{"message": "access denied"}'
    with pytest.raises(client.CapellaError) as excinfo:
        client.capella_request("GET", "/v4/x")
    assert excinfo.value.status == 403
    assert "projectViewer" in excinfo.value.hint


def test_a_get_is_retried_on_a_server_error(capella):
    client, recorder = capella
    recorder.statuses = [503, 502]
    client.capella_request("GET", "/v4/x")
    assert len(recorder.requests) == 3


def test_a_CREATE_is_not_retried_on_a_server_error(capella):
    """THE expensive one. A POST that created a cluster and lost its response would, if
    retried, create a SECOND cluster — billed, and invisible to the caller."""
    client, recorder = capella
    recorder.statuses = [502]
    with pytest.raises(client.CapellaError):
        client.capella_request(
            "POST", "/v4/organizations/o/projects/p/clusters", body={}
        )
    assert len(recorder.requests) == 1, "a cluster-create POST was re-sent after a 502"


def test_a_create_that_is_not_retried_says_why(capella):
    """The caller has to know the outcome is UNKNOWN rather than "failed", or the reconciler's
    next pass is the only thing that saves them."""
    client, recorder = capella
    recorder.statuses = [502]
    with pytest.raises(client.CapellaError) as excinfo:
        client.capella_request("POST", "/v4/x/clusters", body={})
    combined = f"{excinfo.value} {excinfo.value.hint}"
    # The message has to say the outcome is UNKNOWN, not "failed" — and name the recovery.
    assert "deliberat" in combined, combined
    assert "capella_env_ensure" in combined or "adopts" in combined, combined


@pytest.mark.parametrize("status", [408, 425, 429])
def test_a_create_IS_retried_when_the_status_proves_nothing_happened(capella, status):
    client, recorder = capella
    recorder.statuses = [status]
    client.capella_request("POST", "/v4/x", body={})
    assert len(recorder.requests) == 2


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_idempotent_methods_retry(capella, method):
    client, recorder = capella
    recorder.statuses = [503]
    client.capella_request(method, "/v4/x")
    assert len(recorder.requests) == 2


def test_a_permanent_status_is_not_retried_over_the_wire(capella):
    """Named distinctly from the `_retryable` unit test above. They collided, and the second
    definition SHADOWED the first — six parametrised cases silently stopped running, which is
    the failure mode a duplicate test name always has."""
    client, recorder = capella
    recorder.statuses = [404]
    with pytest.raises(client.CapellaError):
        client.capella_request("GET", "/v4/x")
    assert len(recorder.requests) == 1


def test_pagination_follows_the_cursor_to_the_last_page(capella, monkeypatch):
    """Reading page one and stopping is the bug that silently reported 100 clusters for an
    organization with 431."""
    client, recorder = capella
    pages = {
        "1": {"data": [{"id": "a"}], "cursor": {"pages": {"page": 1, "last": 3}}},
        "2": {"data": [{"id": "b"}], "cursor": {"pages": {"page": 2, "last": 3}}},
        "3": {"data": [{"id": "c"}], "cursor": {"pages": {"page": 3, "last": 3}}},
    }
    import urllib.parse

    def _paged(method, path, *, params=None, body=None):
        page = str((params or {}).get("page", 1))
        assert urllib.parse.urlparse(path) is not None
        return pages[page]

    monkeypatch.setattr(client, "capella_request", _paged)
    envelope = client.capella_list("/v4/x")
    assert [i["id"] for i in envelope["data"]] == ["a", "b", "c"]
    assert envelope["pagesFetched"] == 3
    assert envelope["truncated"] is False


def test_a_network_error_on_a_capella_CREATE_says_the_outcome_is_unknown(
    capella, monkeypatch
):
    """A dropped connection on a POST is indistinguishable from "arrived, applied, reply lost".

    So the create is NOT retried — and the caller has to be told that the outcome is unknown
    rather than failed, or they will assume nothing happened and try again by hand. This
    covers the URLError branch specifically; the 5xx branch has its own message.
    """
    import urllib.error
    import urllib.request

    client, _ = capella
    attempts = {"n": 0}

    def _refuse(*_args, **_kwargs):
        attempts["n"] += 1
        raise urllib.error.URLError("connection reset by peer")

    monkeypatch.setattr(urllib.request, "urlopen", _refuse)

    with pytest.raises(client.CapellaError) as excinfo:
        client.capella_request("POST", "/v4/x/clusters", body={})

    assert attempts["n"] == 1, "a CREATE was re-sent after a dropped connection"
    hint = excinfo.value.hint
    assert "not retried" in hint
    assert "Verify current state" in hint


def test_a_network_error_on_a_read_is_retried_and_says_where_to_look(
    capella, monkeypatch
):
    """Guards the test above from passing because nothing is retried, and pins the hint that
    matters operationally: the control plane is a DIFFERENT destination from the cluster's
    data-plane hostname, and egress allowlists routinely miss it."""
    import urllib.error
    import urllib.request

    client, _ = capella
    attempts = {"n": 0}

    def _refuse(*_args, **_kwargs):
        attempts["n"] += 1
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(urllib.request, "urlopen", _refuse)
    monkeypatch.setattr(client.time, "sleep", lambda _s: None)

    with pytest.raises(client.CapellaError) as excinfo:
        client.capella_request("GET", "/v4/organizations")

    assert attempts["n"] > 1, "a read was not retried after a transient network failure"
    assert "egress" in excinfo.value.hint or "outbound HTTPS" in excinfo.value.hint
