"""Regression tests for the audit fixes in server, console login, logging, OIDC, probe and profile.

Component: regression suite; see tests/README.md.
Spec: docs/spec.md S3 (dispatch), S4 (audit), S5 (profiles), S6 (transports).
Main items: `test_a_cancelled_call_is_audited_and_reraised`, `test_login_next_*`,
    `test_traceback_*`, `test_server_wide_dry_run_*`, `test_discovery_*`,
    `test_healthcheck_*`, `test_enterprise_warns_*`.
Callers: none; collected by pytest
Callees: `auth.oidc`, `dryrun`, `handlers.shared`, `healthcheck`, `logging_config`,
    `profile_config`, `server`, `tests.test_gui_oauth_routes`

Each test fails on the code as it was before the fix: a cancelled call left no audit
record, `next=/\\evil.com` was stored, a traceback bypassed redaction and flattening, a
caller's `dry_run: false` beat the operator's preview mode for `capella_env_reap`, OIDC
discovery accepted any issuer and never expired, the probe ignored TLS, and the enterprise
profile stayed silent about missing confinement.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.test_gui_oauth_routes import client, gui  # noqa: F401  (fixtures)


def test_a_cancelled_call_is_audited_and_reraised(monkeypatch):
    """Cancelling the call task writes an `error` audit record and still raises CancelledError."""
    import server
    from handlers import shared

    records: list[dict] = []
    monkeypatch.setattr(server.audit, "emit_tool_call", lambda **kw: records.append(kw))
    started, release = threading.Event(), threading.Event()

    class Slow:
        def handle(self, name, args):
            started.set()
            release.wait(5)
            return shared.ok({"x": 1})

    name = "admin_xdcr_conflict_log_query"
    # Hermetic: whether this tool is exposed depends on the ambient deployment mode
    # (CB_DEPLOYMENT, the Capella variables a developer shell carries). When it was not
    # exposed the dispatch refused at once, so there was nothing in flight to cancel and the
    # test failed for a reason unrelated to cancellation. Expose it explicitly.
    from mcp.types import Tool, ToolAnnotations

    if name not in {t.name for t in server._TOOLS}:
        stub = Tool(
            name=name,
            description="stub",
            inputSchema={
                "type": "object",
                "properties": {"bucket_name": {"type": "string"}},
            },
            annotations=ToolAnnotations(readOnlyHint=True),
        )
        monkeypatch.setattr(server, "_TOOLS", [*server._TOOLS, stub])
    # This test is about cancellation, not authorization: an enterprise-profile shell would
    # otherwise refuse the call for want of a token before any handler is in flight.
    monkeypatch.setattr(server, "check_scope", lambda _tool: None)
    monkeypatch.setitem(server._HANDLERS, name, Slow())

    async def main():
        task = asyncio.create_task(server.call_tool(name, {"bucket_name": "b"}))
        for _ in range(200):
            if started.is_set():
                break
            await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()

    asyncio.run(main())
    assert [r["decision"] for r in records] == ["error"], records
    assert "CancelledError" in records[0]["reason"]


@pytest.mark.parametrize(
    "value",
    [
        "/%5Cevil.com",
        "//evil.com",
        "/%0d%0aSet-Cookie:x",
        "https://evil.com",
        "evil.com",
    ],
)
def test_login_next_hostile_values_fall_back_to_root(client, gui, value):  # noqa: F811
    """A backslash, a protocol-relative form, a control character or an absolute URL becomes '/'."""
    gui._pkce_store.clear()
    client.get(f"/auth/login?next={value}")
    (entry,) = gui._pkce_store.values()
    assert entry["next"] == "/"


def test_login_next_plain_path_is_kept(client, gui):  # noqa: F811
    """A normal same-origin path with a query still survives."""
    gui._pkce_store.clear()
    client.get("/auth/login?next=/tools?x=1")
    (entry,) = gui._pkce_store.values()
    assert entry["next"] == "/tools?x=1"


def _logged(exc: BaseException) -> str:
    """Run a record carrying `exc` through `SafeRecordFilter` and the stock formatter."""
    import logging_config

    try:
        raise exc
    except BaseException:
        record = logging.getLogger("t").makeRecord(
            "t", logging.ERROR, __file__, 1, "failed", (), sys.exc_info()
        )
    logging_config.SafeRecordFilter().filter(record)
    return logging.Formatter("%(message)s").format(record)


def test_traceback_cannot_forge_lines():
    """CR, LF, NEL, U+2028 and ESC inside an exception message are escaped in the output."""
    out = _logged(ValueError("a\nFAKE audit line\r\x85\u2028\x1b[31m"))
    assert "\n" not in out and "\r" not in out
    assert "\u2028" not in out and "\x85" not in out and "\x1b" not in out
    assert "FAKE audit line" in out


def test_traceback_is_redacted():
    """A credential-looking assignment in an exception message is masked."""
    out = _logged(RuntimeError("connect failed password=hunter2hunter2 to host"))
    assert "hunter2hunter2" not in out


def test_server_wide_dry_run_forces_handler_owned_tool(monkeypatch):
    """CB_ADMIN_DRY_RUN=true overrides a caller's dry_run=false for a handler-owned tool."""
    import dryrun

    class Tool:
        name = "capella_env_reap"

    monkeypatch.setattr(dryrun, "_HANDLER_OWNED", {"capella_env_reap"})
    monkeypatch.setenv("CB_ADMIN_DRY_RUN", "true")
    args = {"dry_run": False}
    assert dryrun.force_handler_owned(args, Tool()) is True
    assert args["dry_run"] is True
    monkeypatch.setenv("CB_ADMIN_DRY_RUN", "false")
    args = {"dry_run": False}
    assert dryrun.force_handler_owned(args, Tool()) is False
    assert args["dry_run"] is False


def test_discovery_requires_https_and_matching_issuer(monkeypatch):
    """Plain http (non-loopback), an issuer mismatch and an oversized body are refused."""
    from auth import oidc

    oidc._discovery_cache.clear()
    monkeypatch.setenv("OAUTH_ISSUER", "http://idp.example.com")
    with pytest.raises(RuntimeError, match="https"):
        oidc._discover()

    class Resp:
        def __init__(self, body: bytes):
            self._body = body

        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size=0):
            yield self._body

        def close(self):
            pass

    seen: dict = {}

    def fake_get(url, **kwargs):
        seen.update(kwargs)
        return Resp(fake_get.body)

    monkeypatch.setattr(oidc._requests, "get", fake_get)
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example.com")

    fake_get.body = b'{"issuer": "https://evil.example", "token_endpoint": "x"}'
    with pytest.raises(RuntimeError, match="does not match"):
        oidc._discover()

    fake_get.body = b" " * (oidc._DISCOVERY_MAX_BYTES + 1)
    with pytest.raises(RuntimeError, match="too large"):
        oidc._discover()

    fake_get.body = (
        b'{"issuer": "https://idp.example.com/",'
        b' "token_endpoint": "http://idp.example.com/token"}'
    )
    with pytest.raises(RuntimeError, match="https"):
        oidc._discover()

    fake_get.body = (
        b'{"issuer": "https://idp.example.com/",'
        b' "token_endpoint": "https://idp.example.com/token"}'
    )
    assert oidc._discover()["token_endpoint"] == "https://idp.example.com/token"
    assert seen["allow_redirects"] is False


def test_discovery_cache_expires(monkeypatch):
    """A cached document older than the TTL is fetched again."""
    from auth import oidc

    oidc._discovery_cache.clear()
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example.com")
    calls: list[int] = []

    class Resp:
        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size=0):
            yield b'{"issuer": "https://idp.example.com"}'

        def close(self):
            pass

    monkeypatch.setattr(
        oidc._requests, "get", lambda *a, **k: calls.append(1) or Resp()
    )
    oidc._discover()
    oidc._discover()
    assert len(calls) == 1
    key = "https://idp.example.com"
    stamp, doc = oidc._discovery_cache[key]
    oidc._discovery_cache[key] = (stamp - oidc._DISCOVERY_TTL - 1, doc)
    oidc._discover()
    assert len(calls) == 2


def test_healthcheck_probes_https_when_tls_is_direct(monkeypatch):
    """With a cert and key configured the endpoint is https."""
    import healthcheck

    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "http")
    monkeypatch.setenv("CB_ADMIN_TLS_CERT_FILE", "/x.crt")
    monkeypatch.setenv("CB_ADMIN_TLS_KEY_FILE", "/x.key")
    monkeypatch.delenv("CB_ADMIN_TLS_CLIENT_CA_FILE", raising=False)
    assert healthcheck._endpoint().startswith("https://")


@pytest.mark.parametrize(
    "alias", ["streamable_http", "streamablehttp", "streamable-http"]
)
def test_healthcheck_recognises_transport_aliases(monkeypatch, alias):
    """The probe runs (and fails here, nothing listening) for every alias the server accepts."""
    import healthcheck

    monkeypatch.setenv("CB_ADMIN_TRANSPORT", alias)
    monkeypatch.setenv("CB_ADMIN_PORT", "1")
    monkeypatch.delenv("CB_ADMIN_TLS_CERT_FILE", raising=False)
    code, _ = healthcheck.check(timeout=0.5)
    assert code == 1


def test_enterprise_warns_about_missing_confinement(monkeypatch):
    """Empty ceiling and unset fixture/catalog roots give warnings, not errors."""
    import profile_config

    for var in (
        "CB_ADMIN_ALWAYS_CONFIRM",
        "CB_ADMIN_FIXTURE_ROOT",
        "CB_ADMIN_CATALOG_ROOT",
    ):
        monkeypatch.delenv(var, raising=False)
    found = profile_config.warnings_for(profile_config.ENTERPRISE)
    text = " ".join(found)
    assert "CB_ADMIN_ALWAYS_CONFIRM" in text
    assert "CB_ADMIN_FIXTURE_ROOT" in text and "CB_ADMIN_CATALOG_ROOT" in text
    assert profile_config.warnings_for(profile_config.WORKSTATION) == []
    monkeypatch.setenv("CB_ADMIN_ALWAYS_CONFIRM", "capella_cluster_delete")
    monkeypatch.setenv("CB_ADMIN_FIXTURE_ROOT", "/f")
    monkeypatch.setenv("CB_ADMIN_CATALOG_ROOT", "/c")
    assert profile_config.warnings_for(profile_config.ENTERPRISE) == []
