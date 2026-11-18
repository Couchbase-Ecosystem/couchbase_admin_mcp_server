"""
Regression tests for the security fixes in `handlers/shared.py`.

Component: regression suite; see tests/README.md.
Spec: none; these pin four audit findings (redirect credential leak, redaction past
the scan cap, dot-segment path encoding, read-only mode failing open).
Main items: redirect refusal, redaction cap, quote_path dot-segments, fail-closed flag.
Callers: collected by pytest
Callees: `handlers.shared`
"""

from __future__ import annotations

import http.server
import json
import threading
import time

import pytest

from handlers import shared


def _serve(handler_cls):
    """Start a local HTTP server on a free port and return it."""
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_admin_request_refuses_a_redirect_and_never_resends_credentials(
    monkeypatch, status
):
    """A redirect must not carry the Authorization header to another URL."""
    seen: dict[str, str | None] = {}

    class Target(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen["auth"] = self.headers.get("Authorization")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_a):
            pass

    target = _serve(Target)

    class Cluster(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.send_header("Location", f"http://127.0.0.1:{target.server_port}/x")
            self.end_headers()

        def log_message(self, *_a):
            pass

    cluster = _serve(Cluster)
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://127.0.0.1")
    monkeypatch.setenv("CB_MGMT_PORT", str(cluster.server_port))
    monkeypatch.setenv("CB_USERNAME", "Administrator")
    monkeypatch.setenv("CB_PASSWORD", "s3cretpw")
    monkeypatch.delenv("CB_CLIENT_CERT_PATH", raising=False)
    try:
        with pytest.raises(RuntimeError, match=f"{status}.*refused"):
            shared.admin_request("GET", "/pools")
    finally:
        cluster.shutdown()
        target.shutdown()
    assert "auth" not in seen, "the redirect target must never be contacted"


def test_redaction_masks_every_secret_in_a_long_value_and_keeps_the_rest():
    """A long value is returned in full, with a secret anywhere in it masked."""
    late = "password=lateSecret99 "
    body = "x " * 10 + "password=hunter2 " + "y" * 5000 + " " + late + "tail-marker"
    for out in (
        shared.err("HTTP 400: " + body)[0].text,
        shared.redact_text(body),
    ):
        assert "hunter2" not in out
        assert "lateSecret99" not in out
        # Nothing is dropped: the end of the value is still there.
        assert "tail-marker" in out
        assert "truncated" not in out


def test_redaction_masks_a_secret_straddling_a_window_boundary():
    """A token on a window edge is masked, not cut where its key no longer shows."""
    pad = "a " * (shared._REDACT_CHUNK // 2 - 6)
    text = pad + "Bearer abcdefghijklmnopqrstuvwxyz0123456789 and more text"
    out = shared.redact_text(text)
    assert "abcdefgh" not in out
    assert out.endswith("and more text")


def test_redaction_still_caps_an_absurd_value():
    out = shared.redact_text("a " * shared._REDACT_MAX_TEXT)
    assert "truncated at" in out
    assert len(out) < shared._REDACT_MAX_TEXT + 400


def test_a_long_function_source_round_trips_through_ok():
    code = "function OnUpdate(doc, meta) {\n" + "  log(doc);\n" * 2000 + "}\n"
    out = json.loads(shared.ok({"appcode": code})[0].text)
    assert out["appcode"] == code


def test_uri_password_with_reserved_characters_is_masked():
    for uri in (
        "couchbase://admin:p/ss@host",
        "couchbase://admin:p?ss@host",
        "couchbase://admin:p#ss@host",
    ):
        out = shared.redact_uri_credentials(uri)
        assert "ss" not in out.split("@")[0].split(":", 2)[-1]
        assert out.endswith("@host")
    # A bare port is not a password.
    assert (
        shared.redact_uri_credentials("http://host:8080/a@b") == "http://host:8080/a@b"
    )


@pytest.mark.parametrize(
    "key", ["X-API-Key", "api-key", "otpCookie", "clientKey", "spKey"]
)
def test_header_and_cookie_spellings_are_masked(key):
    assert "s3cr3tvalue" not in shared.redact_text(f'{{"{key}": "s3cr3tvalue"}}')
    assert shared.redact({key: "s3cr3tvalue"})[key] == shared.REDACTED


def test_ok_masks_a_secret_inside_a_long_string_value():
    code = 'var cfg = {"password": "hunter2"}; ' + "x" * 5000
    out = shared.ok({"appcode": code})[0].text
    assert "hunter2" not in out
    assert "hunter2" not in json.loads(out)["appcode"]


def test_redaction_of_long_hostile_input_stays_fast():
    start = time.monotonic()
    shared.redact_text("a-" * 50_000)
    shared.redact_text("scheme://" + "u" * 100_000)
    assert time.monotonic() - start < 2.0


def test_short_text_is_unchanged_in_shape():
    assert shared.redact_text("password=hunter2 ok") == "password=***REDACTED*** ok"
    assert "truncated" not in shared.redact_text("plain text")


@pytest.mark.parametrize("segment", [".", ".."])
def test_quote_path_encodes_dot_segments(segment):
    quoted = shared.quote_path(segment)
    assert quoted not in (".", "..")
    assert quoted == segment.replace(".", "%2E")


def test_quote_path_keeps_other_values():
    assert shared.quote_path("a.b") == "a.b"
    assert shared.quote_path("...") == "..."
    assert shared.quote_path("travel-sample") == "travel-sample"
    assert shared.quote_path("") == ""


@pytest.mark.parametrize("raw", ["flase", "maybe", "2", "tru"])
def test_unrecognised_read_only_value_fails_closed(monkeypatch, raw, caplog):
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", raw)
    assert (
        shared.get_env_bool("CB_ADMIN_READ_ONLY_MODE", True, fail_closed=True) is True
    )


@pytest.mark.parametrize("raw", ["false", "FALSE", " no ", "0", "off"])
def test_explicit_false_still_turns_read_only_off(monkeypatch, raw):
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", raw)
    assert (
        shared.get_env_bool("CB_ADMIN_READ_ONLY_MODE", True, fail_closed=True) is False
    )


def test_plain_get_env_bool_is_unchanged_for_other_callers(monkeypatch):
    monkeypatch.setenv("SOME_FLAG", "flase")
    assert shared.get_env_bool("SOME_FLAG", True) is False
    assert shared.get_env_bool("SOME_UNSET_FLAG", True) is True


def test_a_quote_inside_an_optimizer_hint_does_not_hide_a_second_statement():
    stmt = 'CREATE INDEX i ON `b`(x) /*+ " */ ; DROP SCOPE `b`.`prod` /*" */'
    assert shared.assert_single_statement(stmt) is not None


def test_a_plain_optimizer_hint_is_still_accepted():
    stmt = "SELECT /*+ INDEX(t idx_a) */ * FROM `b` t WHERE a = 1"
    assert shared.assert_single_statement(stmt) is None


def test_a_tool_list_path_that_does_not_exist_is_warned_about(monkeypatch):
    seen = []
    monkeypatch.setattr(
        shared._log, "warning", lambda msg, *a, **k: seen.append(msg % a)
    )
    names = shared._parse_tool_list("/no/such/dir/disabled.txt")
    assert names == {"/no/such/dir/disabled.txt"}
    assert any("looks like a file path" in m for m in seen)
