"""
The audit sink's last-resort paths, the profile validator's remaining refusals, and the
diagnostic probes' row handling.

WHY THE AUDIT FALLBACKS MATTER
==============================
`emit_tool_call` catches `BaseException` twice, nested. That looks excessive until you notice
what it is protecting: the audit record is written AFTER the handler has run, so an exception
in the recording path means the action happened and nothing says so. A record that cannot be
serialised in full must still produce a line naming the tool and the decision, and if even
that fails, a bare line — because "something happened here" is still evidence.

That is the one place in this codebase where swallowing an exception is the correct behaviour,
and it is worth having tests that say so.
"""

from __future__ import annotations

import json

import pytest

import audit
import profile_config


@pytest.fixture(autouse=True)
def _audit_records_reach_caplog():
    """Let caplog see audit records regardless of what configured logging earlier.

    logging_config.configure_logging sets `propagate = False` on the `couchbase-admin`
    logger -- correct in production, since the tree has its own handlers and
    propagation would duplicate every line onto the root. But caplog captures by
    attaching to the ROOT logger, so once ANY earlier test in the session has
    configured logging, these assertions saw an empty caplog and failed for a reason
    that has nothing to do with the audit fallbacks they exist to test.

    Restoring propagation for the duration of each test in this file makes them
    independent of collection order, which is the property that was missing.
    """
    import logging

    tree = logging.getLogger("couchbase-admin")
    previous = tree.propagate
    previous_level = tree.level
    tree.propagate = True
    if tree.level > logging.INFO:
        tree.setLevel(logging.INFO)
    try:
        yield
    finally:
        tree.propagate = previous
        tree.setLevel(previous_level)


# ── The audit sink degrades rather than losing the record ─────────────────────


@pytest.fixture(autouse=True)
def _reset_audit():
    audit.reset_audit_sink()
    yield
    audit.reset_audit_sink()


def test_a_record_is_written_to_the_file_sink(tmp_path, monkeypatch):
    path = tmp_path / "audit.log"
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(path))
    audit.reset_audit_sink()

    audit.emit_tool_call(
        tool="admin_bucket_delete",
        arguments={"bucket_name": "b"},
        decision="allowed",
        principal={"sub": "u"},
    )
    assert "admin_bucket_delete" in path.read_text()


def test_an_unopenable_audit_file_is_reported_as_a_startup_error(tmp_path, monkeypatch):
    """A requested-but-unusable sink is fatal at startup, because the alternative is a server
    that believes it is auditing and is not."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(blocker / "audit.log"))
    audit.reset_audit_sink()

    problem = audit.audit_sink_error()
    assert problem
    assert "CB_ADMIN_AUDIT_FILE" in problem


def test_no_audit_file_configured_is_not_an_error(monkeypatch):
    """Guards the check above from making the default configuration unstartable."""
    monkeypatch.delenv("CB_ADMIN_AUDIT_FILE", raising=False)
    audit.reset_audit_sink()
    assert audit.audit_sink_error() is None


def test_an_unserialisable_argument_still_produces_a_record(
    tmp_path, monkeypatch, caplog
):
    """THE property. The record is written after the handler has already run, so a
    serialisation failure here means the action happened and nothing says so.

    The fallback drops the arguments and keeps the tool, the decision and the principal —
    which is what an audit trail is actually for.
    """

    class _Unserialisable:
        def __repr__(self):
            raise RuntimeError("even repr fails")

    monkeypatch.delenv("CB_ADMIN_AUDIT_FILE", raising=False)
    audit.reset_audit_sink()

    with caplog.at_level("INFO"):
        audit.emit_tool_call(
            tool="admin_bucket_delete",
            arguments={"payload": _Unserialisable()},
            decision="allowed",
            principal={"sub": "u"},
        )

    text = caplog.text
    assert "AUDIT" in text
    assert "admin_bucket_delete" in text
    assert "allowed" in text


def test_the_degraded_record_says_it_is_degraded(tmp_path, monkeypatch, caplog):
    """Otherwise a record missing its arguments looks like a call that had none."""

    class _Unserialisable:
        def __repr__(self):
            raise RuntimeError("no")

    monkeypatch.delenv("CB_ADMIN_AUDIT_FILE", raising=False)
    audit.reset_audit_sink()
    with caplog.at_level("INFO"):
        audit.emit_tool_call(
            tool="t",
            arguments={"x": _Unserialisable()},
            decision="allowed",
            principal={"sub": "u"},
        )
    assert "record_error" in caplog.text or "could not be serialised" in caplog.text


def test_emitting_survives_a_base_exception_during_serialisation(monkeypatch, caplog):
    """`emit_tool_call` catches BaseException, not Exception, and that is deliberate: a Ctrl-C
    arriving while the record is being serialised would otherwise lose the record of an action
    that has ALREADY happened.

    Induced by making the serialiser raise, NOT by passing an object whose `__repr__` raises.
    The first version of this test did the latter, and pytest calls `repr()` on test arguments
    when formatting output — so the KeyboardInterrupt escaped the test and aborted the whole
    session. A test that makes the runner unusable is worse than no test.
    """
    import json as json_module

    monkeypatch.delenv("CB_ADMIN_AUDIT_FILE", raising=False)
    audit.reset_audit_sink()

    calls = {"n": 0}
    real_dumps = json_module.dumps

    def _first_call_is_interrupted(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise KeyboardInterrupt
        return real_dumps(*args, **kwargs)

    monkeypatch.setattr(audit.json, "dumps", _first_call_is_interrupted)

    with caplog.at_level("INFO"):
        # Must not raise, and must still leave evidence.
        audit.emit_tool_call(
            tool="admin_bucket_delete",
            arguments={"bucket_name": "prod"},
            decision="allowed",
            principal={"sub": "u"},
        )

    assert calls["n"] >= 2, "the fallback serialisation was never attempted"
    assert "admin_bucket_delete" in caplog.text


def test_emitting_survives_even_the_fallback_failing(monkeypatch, caplog):
    """The innermost guard. If the degraded record cannot be serialised either, a bare line is
    still evidence that something happened — which is the whole point of an audit trail."""
    monkeypatch.delenv("CB_ADMIN_AUDIT_FILE", raising=False)
    audit.reset_audit_sink()

    def _always_interrupted(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(audit.json, "dumps", _always_interrupted)

    with caplog.at_level("ERROR"):
        audit.emit_tool_call(
            tool="admin_bucket_delete",
            arguments={},
            decision="allowed",
            principal={"sub": "u"},
        )

    assert caplog.text.strip(), "nothing at all was recorded"


def test_an_auth_failure_is_recorded(tmp_path, monkeypatch):
    path = tmp_path / "audit.log"
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(path))
    audit.reset_audit_sink()

    audit.emit_auth_failure(reason="missing bearer token", source="10.1.2.3:5555")
    written = path.read_text()
    assert "missing bearer token" in written
    assert "10.1.2.3" in written


# ── Correlation ids are bounded ──────────────────────────────────────────────


def test_a_correlation_id_is_normalised():
    """It reaches a log line, so embedded newlines would let a caller forge a second record."""
    assert audit.sanitize_correlation("  run \n 42  ") == "run 42"


def test_an_empty_correlation_id_becomes_none():
    for value in ("", "   ", "\n\t", None):
        assert audit.sanitize_correlation(value) is None


def test_an_over_long_correlation_id_is_truncated_visibly():
    """Unbounded, it is a way to make each audit line arbitrarily large — and to push earlier
    records out of a rotation. Truncation has to be visible or the value looks complete."""
    cleaned = audit.sanitize_correlation("x" * 5000)
    assert len(cleaned) < 5000
    assert "truncated" in cleaned


# ── The profile validator's remaining refusals ───────────────────────────────


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("::1", True),
        ("127.0.0.5", True),
        ("0.0.0.0", False),
        ("10.1.2.3", False),
        ("cb-admin.internal", False),
        ("", False),
    ],
)
def test_loopback_detection(host, expected):
    """The workstation profile's whole premise is that a human is at the client, which only
    holds on loopback. A hostname that resolves to 127.0.0.1 is NOT loopback for this purpose:
    it means somebody else can reach the port."""
    assert profile_config._is_loopback_host(host) is expected


def test_the_enterprise_profile_refuses_a_missing_audience(monkeypatch):
    """Without it, any validly-signed token from the tenant is accepted — including one minted
    for an unrelated application in the same corporate IdP."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.setenv("OAUTH_ISSUER", "https://idp.example.com")
    monkeypatch.delenv("OAUTH_AUDIENCE", raising=False)

    import importlib

    reloaded = importlib.reload(profile_config)
    try:
        assert any("OAUTH_AUDIENCE" in e for e in reloaded.PROFILE_ERRORS)
    finally:
        monkeypatch.undo()
        importlib.reload(profile_config)


def test_the_enterprise_profile_refuses_unrestricted_egress(monkeypatch):
    """The cluster could be pointed at any public host — including as the destination for a
    full diagnostic log bundle, which is the exfiltration path this project spent a round
    closing."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")

    import importlib

    reloaded = importlib.reload(profile_config)
    try:
        assert any("EGRESS_ALLOW_ANY" in e for e in reloaded.PROFILE_ERRORS)
    finally:
        monkeypatch.undo()
        importlib.reload(profile_config)


@pytest.mark.parametrize("name", ["workstation", "enterprise", None, "nonsense"])
def test_every_profile_describes_itself(name):
    """The banner prints this, and an operator's only confirmation of which posture is active.
    An unset profile has to say that the posture is accidental rather than reporting a default.
    """
    description = profile_config.describe(name)
    assert description
    if name in ("workstation", "enterprise"):
        assert name in description
    else:
        assert "UNSET" in description or "no profile" in description


def test_the_workstation_description_states_its_premise():
    """That a human is present. Everything the profile permits rests on it."""
    text = profile_config.describe("workstation")
    assert "human" in text
    assert "stdio" in text
    assert "loopback" in text


def test_the_enterprise_description_states_that_confirmation_is_not_the_control():
    """The distinction the whole authorization model turns on: unattended chains are
    authorised by token scopes, not by a per-call confirmation nobody sees."""
    text = profile_config.describe("enterprise")
    assert "unattended" in text
    assert "scope" in text


# ── The audited principal ────────────────────────────────────────────────────


def test_the_local_identity_is_recorded_for_a_stdio_call():
    """stdio has no token, so the OS user and host are the only identity available — and an
    audit record with no principal at all is not an audit record."""
    identity = profile_config.local_identity()
    assert identity["os_user"]
    assert identity["host"]


def test_the_local_identity_never_raises(monkeypatch):
    """It is called on the audit path. A container with no passwd entry makes `getpass.getuser`
    raise, and an exception here would lose the record of an action that already happened."""
    import getpass
    import socket

    monkeypatch.setattr(
        getpass, "getuser", lambda: (_ for _ in ()).throw(OSError("no passwd entry"))
    )
    monkeypatch.setattr(
        socket, "gethostname", lambda: (_ for _ in ()).throw(OSError("no hostname"))
    )
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.delenv("USERNAME", raising=False)

    identity = profile_config.local_identity()
    assert identity["os_user"] == "unknown"
    assert identity["host"] == "unknown"


def test_the_local_identity_falls_back_to_the_environment(monkeypatch):
    """A container without a passwd entry still usually has USER set, and a real username is
    worth more in the record than "unknown"."""
    import getpass

    monkeypatch.setattr(
        getpass, "getuser", lambda: (_ for _ in ()).throw(OSError("no passwd entry"))
    )
    monkeypatch.setenv("USER", "ada")
    assert profile_config.local_identity()["os_user"] == "ada"


# ── Encryption / KMIP settings ───────────────────────────────────────────────


def test_kmip_settings_are_returned_without_the_key(monkeypatch):
    """`admin_kmip_get` returns the KMIP configuration, and it is annotated read-only — so it
    loads in the safest deployment. It must not carry key material."""
    from handlers import encryption

    monkeypatch.setattr(
        encryption,
        "admin_request",
        lambda *a, **k: {
            "keyId": "k1",
            "kmipHost": "kmip.internal",
            "kmipPassword": "should-not-appear",
        },
        raising=False,
    )
    result = encryption.handle("admin_kmip_get", {})
    text = result[0].text
    assert "kmip.internal" in text
    assert "should-not-appear" not in text, "a KMIP credential reached the response"


def test_an_unknown_encryption_tool_is_refused(monkeypatch):
    from handlers import encryption
    from handlers.shared import ERROR_MARKER

    monkeypatch.setattr(encryption, "admin_request", lambda *a, **k: {}, raising=False)
    body = json.loads(encryption.handle("admin_not_a_real_tool", {})[0].text)
    assert body[ERROR_MARKER] is True


def test_a_later_audit_file_is_honoured_after_an_earlier_emit(tmp_path, monkeypatch):
    """The sink memo must be keyed on the PATH, not on "have we looked before".

    Found by the randomised-order CI run, not by file order: an emit with
    CB_ADMIN_AUDIT_FILE unset memoised "no sink", and because the memo recorded no
    path, a CB_ADMIN_AUDIT_FILE set afterwards was never read. audit_sink_error() then
    reported a perfectly writable file as unusable -- and both _enforce_gui_posture()
    and server._enforce_profile() treat that as fatal, so the process refused to start
    over a sink that was fine.

    Not test-only: profile_config applies the enterprise profile's env defaults at
    IMPORT time, so whether the variable is set before or after the first audit emit is
    decided by import order.
    """
    import audit

    monkeypatch.delenv("CB_ADMIN_AUDIT_FILE", raising=False)
    audit.reset_audit_sink()
    try:
        # An audit record with no dedicated sink configured. This is what sets the memo.
        audit.emit({"ts": "t", "event": "probe", "decision": "allowed"})
        assert audit.audit_sink_error() is None, "no sink requested, so no error"

        # Now configure one, in a directory that exists and is writable.
        target = tmp_path / "audit.log"
        monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(target))
        assert audit.audit_sink_error() is None, (
            "a writable audit file was reported unusable because the memo from the "
            "earlier emit was never invalidated; this refusal is fatal at startup"
        )

        # And it is genuinely attached, not merely un-refused.
        audit.emit({"ts": "t", "event": "probe2", "decision": "allowed"})
        assert target.exists() and "probe2" in target.read_text(encoding="utf-8"), (
            "the sink reported itself usable but wrote nothing"
        )
    finally:
        audit.reset_audit_sink()


def test_switching_the_audit_file_does_not_keep_writing_to_the_old_one(
    tmp_path, monkeypatch
):
    """The other half: rebuilding on a path change must release the previous handler
    and start writing to the new file, or a reconfigure silently keeps appending to a
    file nobody is reading any more."""
    import audit

    first, second = tmp_path / "one.log", tmp_path / "two.log"
    audit.reset_audit_sink()
    try:
        monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(first))
        audit.emit({"ts": "t", "event": "to_first", "decision": "allowed"})
        monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(second))
        audit.emit({"ts": "t", "event": "to_second", "decision": "allowed"})

        assert "to_first" in first.read_text(encoding="utf-8")
        assert "to_second" in second.read_text(encoding="utf-8")
        assert "to_second" not in first.read_text(encoding="utf-8"), (
            "records kept going to the previous audit file after it was reconfigured"
        )
    finally:
        audit.reset_audit_sink()
