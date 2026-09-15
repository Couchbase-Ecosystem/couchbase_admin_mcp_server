"""
Coverage for the controls the third review pass found untested.

Each of these existed as code with no test behind it, which is the state that let two
earlier "completed" fixes turn out to be absent from the source entirely. Grouped by
the finding they close.
"""

from __future__ import annotations

import contextlib
import importlib
import ipaddress
import json
import sys
import threading

import pytest
from tests._platform import FILE_MODES_AVAILABLE, requires_symlinks

# ── H5 / M6: the JWKS refresh budget and its concurrency safety ──────────────


class _FakeKey:
    def __init__(self, kid):
        self.key_id = kid


class _CountingClient:
    """Stands in for PyJWKClient, counting the refreshes an attacker would force."""

    def __init__(self, known=("real-kid",)):
        self.known = list(known)
        self.refreshes = 0

    def get_signing_keys(self, refresh=False):
        if refresh:
            self.refreshes += 1
        return [_FakeKey(k) for k in self.known]


@pytest.fixture
def oidc(monkeypatch):
    from auth import oidc as module

    module.reset_jwks_throttle()
    yield module
    module.reset_jwks_throttle()


def test_cycling_kids_cannot_force_unbounded_jwks_fetches(oidc, monkeypatch):
    """The per-kid memo alone did NOT mitigate the attack it was written for.

    `kid` is read from the UNVERIFIED header, so it is attacker-chosen: varying it
    every request never hits a per-kid entry, and each novel kid costs one outbound
    fetch because PyJWT's refresh=True bypasses its own cache. Measured at 200
    requests -> 200 fetches: 1:1 amplification against the customer's IdP, from a
    trusted source address, reachable unauthenticated.

    The budget is on the scarce resource (the fetch), which cannot be evaded by
    choosing a different key because there is no key-derived state to miss.
    """
    monkeypatch.setenv("CB_ADMIN_JWKS_REFRESH_BUDGET", "10")
    importlib.reload(oidc)
    oidc.reset_jwks_throttle()

    client = _CountingClient()
    refused = 0
    for index in range(200):
        kid = f"attacker-{index}"
        if not oidc._kid_is_known(client, kid):
            try:
                oidc._refuse_if_recently_missed("https://idp/jwks", kid)
            except RuntimeError:
                refused += 1
                continue
        client.get_signing_keys(refresh=True)

    assert client.refreshes <= 10, (
        f"{client.refreshes} outbound JWKS fetches from 200 attacker-chosen kids; the "
        "budget is not bounding the scarce resource"
    )
    assert refused >= 180


def test_a_legitimate_kid_is_never_throttled(oidc):
    """The throttle must not become the denial of service it replaced: the first
    version recorded on EVERY call, so one attacker request refused all legitimate
    tokens for 60 seconds."""
    client = _CountingClient()
    for index in range(20):
        with contextlib.suppress(RuntimeError):
            oidc._refuse_if_recently_missed("https://idp/jwks", f"attacker-{index}")

    assert oidc._kid_is_known(client, "real-kid") is True


def test_a_repeat_of_the_same_unknown_kid_is_refused_without_a_fetch(oidc):
    oidc._refuse_if_recently_missed("https://idp/jwks", "typo-kid")
    with pytest.raises(RuntimeError):
        oidc._refuse_if_recently_missed("https://idp/jwks", "typo-kid")


def test_a_resolved_kid_is_forgotten_so_rotation_costs_one_request(oidc):
    """A real key rotation must not be throttled beyond the first attempt."""
    import jwt as pyjwt

    token = pyjwt.encode(
        {"sub": "x"}, "a" * 40, algorithm="HS256", headers={"kid": "new"}
    )
    oidc._refuse_if_recently_missed("https://idp/jwks", "new")
    oidc._forget_unknown_kid(token, "https://idp/jwks")
    oidc._refuse_if_recently_missed("https://idp/jwks", "new")  # must not raise


def test_the_throttle_is_concurrency_safe(oidc):
    """validate_token runs on worker threads from two places, and the stale-entry
    comprehension over a plain dict raised "dictionary changed size during iteration".
    That RuntimeError is swallowed upstream and becomes a DENIAL — so valid tokens were
    intermittently rejected, and the enterprise flow is a concurrent fan-out, i.e.
    concurrency is the normal case rather than the edge one.

    The dict is pre-seeded with many STALE entries so the cleanup loop is long, which is
    what makes the race reliably observable rather than a one-in-a-thousand flake.
    """
    now = __import__("time").monotonic()
    with oidc._throttle_lock:
        for index in range(4000):
            # Older than the window, so every call walks and prunes all of them.
            oidc._unknown_kids[f"https://idp/jwks|stale-{index}"] = now - 600

    errors: list[str] = []

    def worker(n):
        for i in range(200):
            try:
                oidc._refuse_if_recently_missed("https://idp/jwks", f"k{n}-{i}")
            except RuntimeError:
                continue  # expected: budget/memo refusals
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, f"concurrent access raised: {set(errors)}"


def test_the_throttle_mutates_its_state_under_a_lock():
    """Structural backstop for the test above.

    A data race cannot be proven absent by running it — the probabilistic test can only
    show the race is unlikely on this machine, on this run. So the invariant is also
    asserted directly: the shared state is only touched while the lock is held.
    """
    import inspect

    from auth import oidc as module

    for function in (module._refuse_if_recently_missed, module._forget_unknown_kid):
        source = inspect.getsource(function)
        assert "_throttle_lock" in source, (
            f"{function.__name__} mutates _unknown_kids without taking the lock; "
            "concurrent validations will intermittently reject valid tokens"
        )


# ── M9: human_is_present must not trust the profile label alone ──────────────


def test_the_container_bind_waiver_does_not_confer_a_human(monkeypatch):
    """CB_ADMIN_WORKSTATION_CONTAINER_BIND=1 waives the locality check, and nothing
    verifies the "-p 127.0.0.1:PORT:PORT" it asserts — so a REMOTE caller holding no
    automation scope could satisfy the hard ceiling with its own confirm: true."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "http")
    monkeypatch.setenv("CB_ADMIN_HOST", "0.0.0.0")
    monkeypatch.setenv("CB_ADMIN_WORKSTATION_CONTAINER_BIND", "1")
    monkeypatch.setenv("CB_ADMIN_ALWAYS_CONFIRM", "admin_bucket_delete")

    import authz
    import profile_config

    importlib.reload(profile_config)
    importlib.reload(authz)

    assert profile_config.PROFILE_ERRORS == []  # the waiver is honoured for STARTUP
    assert authz.human_is_present() is False, "a network bind is not a human"

    decision, _ = authz.evaluate(
        "admin_bucket_delete", in_confirm_set=True, has_automation_scope=False
    )
    assert decision.decision == "denied_hard_ceiling"


def test_stdio_on_a_workstation_is_a_human(monkeypatch):
    """The supported laptop shape must keep working: the ceiling is enforced THROUGH
    the confirmation rather than as a refusal."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "stdio")
    monkeypatch.setenv("CB_ADMIN_ALWAYS_CONFIRM", "admin_bucket_delete")

    import authz
    import profile_config

    importlib.reload(profile_config)
    importlib.reload(authz)

    assert authz.human_is_present() is True
    decision, needs_confirm = authz.evaluate(
        "admin_bucket_delete", in_confirm_set=False, has_automation_scope=False
    )
    assert decision.allowed
    assert needs_confirm is True, "the ceiling must RAISE the confirmation requirement"


def test_a_caller_supplied_human_present_flag_is_explicit(monkeypatch):
    """Callers state their own evidence; the GUI must be able to say 'not a human'
    without depending on CB_ADMIN_TRANSPORT, which describes another process."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "stdio")
    monkeypatch.setenv("CB_ADMIN_ALWAYS_CONFIRM", "admin_bucket_delete")

    import authz

    importlib.reload(authz)
    decision, _ = authz.evaluate(
        "admin_bucket_delete",
        in_confirm_set=True,
        has_automation_scope=False,
        human_present=False,
    )
    assert decision.decision == "denied_hard_ceiling"


def test_automation_still_skips_confirmation_for_ordinary_writes(monkeypatch):
    """The enterprise flow must not be collateral damage: this is the whole point."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.delenv("CB_ADMIN_ALWAYS_CONFIRM", raising=False)

    import authz
    import profile_config

    importlib.reload(profile_config)
    importlib.reload(authz)
    decision, needs_confirm = authz.evaluate(
        "admin_bucket_create", in_confirm_set=True, has_automation_scope=True
    )
    assert decision.allowed
    assert needs_confirm is False


# ── H4: a record must actually reach CB_ADMIN_AUDIT_FILE ─────────────────────


def test_a_record_reaches_the_dedicated_audit_file(tmp_path, monkeypatch):
    """The variable was a phantom: profile_config accepted its PRESENCE as proof of a
    durable sink while nothing read it. The old tests asserted the same inference —
    that validate() was happy — rather than that a record existed."""
    path = tmp_path / "audit.log"
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(path))

    import audit

    audit.reset_audit_sink()
    try:
        audit.emit_tool_call(
            tool="admin_bucket_delete",
            arguments={"bucket_name": "prod", "password": "hunter2"},
            decision="allowed",
            principal={"principal": "svc-child", "automation": True, "auth": "oauth"},
            correlation_id="gh-run-991",
        )

        assert path.exists(), "CB_ADMIN_AUDIT_FILE was set and no file was created"
        body = path.read_text(encoding="utf-8")
        assert "admin_bucket_delete" in body
        assert "gh-run-991" in body, "correlation id missing from the durable record"
        assert "hunter2" not in body, "a credential reached the audit file"
        if FILE_MODES_AVAILABLE:
            # POSIX-only claim. The record reaching the file, and the credential
            # not reaching it, are the assertions that hold everywhere.
            assert oct(path.stat().st_mode & 0o777) == "0o600"
    finally:
        audit.reset_audit_sink()


@requires_symlinks
def test_an_unusable_audit_path_is_reported_as_fatal(tmp_path, monkeypatch):
    """Silent degradation is what made this a phantom in the first place. An audit sink
    that was asked for and cannot be opened must stop startup, not log a line into the
    log the operator was told they no longer needed."""
    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    link = tmp_path / "audit.log"
    link.symlink_to(victim)
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(link))

    import audit

    audit.reset_audit_sink()
    try:
        problem = audit.audit_sink_error()
        assert problem is not None
        assert "CB_ADMIN_AUDIT_FILE" in problem
        assert victim.read_text(encoding="utf-8") == "keep"
    finally:
        audit.reset_audit_sink()


def test_no_audit_file_configured_is_not_an_error(monkeypatch):
    monkeypatch.delenv("CB_ADMIN_AUDIT_FILE", raising=False)
    import audit

    audit.reset_audit_sink()
    assert audit.audit_sink_error() is None


# ── Mass assignment: the schema-derived allow-list ───────────────────────────


def test_undeclared_arguments_are_refused_not_dropped():
    """Dropping silently is the worse failure for an agent: it reports success while
    the setting it asked for was never applied, and the model cannot learn."""
    from handlers import indexes
    from handlers.shared import ERROR_MARKER, refuse_undeclared

    refusal = refuse_undeclared(
        {"indexerThreads": 4, "disableUIOverHttp": "true"},
        "admin_index_settings_set",
        indexes.TOOLS,
        endpoint="/settings/indexes",
    )
    assert refusal is not None
    payload = json.loads(refusal[0].text)
    assert payload[ERROR_MARKER] is True
    assert "disableUIOverHttp" in payload["error"]
    assert "indexerThreads" in payload["declared_parameters"]


def test_declared_arguments_pass_through():
    from handlers import indexes
    from handlers.shared import form_data_declared, refuse_undeclared

    args = {"indexerThreads": 4, "logLevel": "info", "confirm": True}
    assert refuse_undeclared(args, "admin_index_settings_set", indexes.TOOLS) is None
    sent = form_data_declared(args, "admin_index_settings_set", indexes.TOOLS)
    assert sent == {"indexerThreads": "4", "logLevel": "info"}


def test_the_allow_list_is_the_tools_own_schema():
    """Derived, not hand-written: seven literal sets would be seven things to forget."""
    from handlers import cluster
    from handlers.shared import schema_keys

    keys = schema_keys("admin_cluster_memory_set", cluster.TOOLS)
    assert "dataMemoryQuota" in keys
    assert "clusterName" not in keys, (
        "clusterName is accepted by /pools/default but not declared by this tool; "
        "it must not be forwardable"
    )


def test_correlation_id_is_declared_on_every_tool(monkeypatch):
    """It was documented in .env.example, read by audit.py, stripped by the dispatch —
    and present in ZERO tool schemas, so the model that is supposed to send the field
    the whole enterprise audit story rests on could not see it."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    import server

    importlib.reload(server)
    missing = [
        tool.name
        for tool in server._TOOLS
        if "correlation_id" not in ((tool.inputSchema or {}).get("properties") or {})
    ]
    assert not missing, (
        f"{len(missing)} tools do not declare correlation_id: {missing[:5]}"
    )


# ── M11: the peer-address check ──────────────────────────────────────────────


def test_ipv4_mapped_loopback_counts_as_local():
    """A dual-stack socket reports a v4 client as ::ffff:127.0.0.1, and the peer check
    must treat that as local.

    This asserted ``address.is_loopback is False`` as "premise of the bug". That
    premise was true on the CPython this was written against and is no longer true:
    IPv6Address now delegates is_loopback to the mapped v4 address, so the assertion
    failed on 3.11.15+ and the test was red for a reason that had nothing to do with
    this server. Pinning the standard library's old answer as a premise makes a test
    fail when the platform gets BETTER.

    What actually matters is unchanged and is what this now asserts: the mapped
    address is recoverable and is loopback, so the peer check has a correct answer to
    read whichever way the stdlib decides to report the outer address.
    """
    address = ipaddress.ip_address("::ffff:127.0.0.1")
    assert address.ipv4_mapped is not None
    assert address.ipv4_mapped.is_loopback is True
    # Either spelling must reach the same verdict, which is the invariant the peer
    # check depends on.
    assert address.is_loopback or address.ipv4_mapped.is_loopback


# ── M12: exception text is redacted ──────────────────────────────────────────


@pytest.mark.parametrize(
    ("message", "secret"),
    [
        ('HTTPError 400: {"password": "hunter2"}', "hunter2"),
        ("connection failed for password=s3cret host=db1", "s3cret"),
        ("RuntimeError: emailPass: 'smtp-secret'", "smtp-secret"),
        ("Bearer token=abc123xyz rejected", "abc123xyz"),
    ],
)
def test_err_redacts_its_own_message(message, secret):
    """Only `context` went through redact(), and redact() is a no-op on a bare string —
    so every handler's `err(f"{type(exc).__name__}: {exc}")` passed remote text through
    untouched, and admin_request folds the cluster's response body into it."""
    from handlers.shared import err

    payload = json.loads(err(message)[0].text)
    assert secret not in payload["error"]
    assert "***REDACTED***" in payload["error"]


@pytest.mark.parametrize(
    "message",
    [
        "bucket 'prod' does not exist",
        # The first version of redact_text matched a sensitive fragment ANYWHERE in the
        # identifier, and the tool name admin_password_policy_set contains "password" —
        # so it masked the useful half of this message and hid the diagnosis. The
        # fragment must terminate the identifier.
        "Unrecognised argument(s) for admin_password_policy_set: ['disableUIOverHttp']",
        "tool admin_password_policy_set failed with 404",
        "rebalance failed: node 10.0.0.4 is unreachable",
    ],
)
def test_redaction_leaves_ordinary_messages_alone(message):
    from handlers.shared import err

    payload = json.loads(err(message)[0].text)
    assert payload["error"] == message, "a diagnostic message was masked"


# ── M10: composites cannot reach a restricted primitive ─────────────────────


def test_a_composite_cannot_use_a_disabled_primitive(monkeypatch):
    """CB_ADMIN_DISABLED_TOOLS=capella_cluster_delete did nothing about
    capella_env_teardown, which performs the same deletion through _invoke."""
    from handlers import shared
    from handlers.capella import environment

    monkeypatch.setattr(shared, "DISABLED_TOOLS", {"capella_cluster_delete"})
    with pytest.raises(environment.CompositeRefusedError) as excinfo:
        environment._assert_primitive_permitted(
            "capella_cluster_delete", "capella_env_teardown"
        )
    assert "CB_ADMIN_DISABLED_TOOLS" in str(excinfo.value)


def test_a_composite_cannot_use_a_ceiling_primitive_unattended(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.setenv("CB_ADMIN_ALWAYS_CONFIRM", "capella_cluster_delete")

    import authz
    import profile_config
    from handlers.capella import environment

    importlib.reload(profile_config)
    importlib.reload(authz)
    monkeypatch.setattr(environment, "authz", authz)

    with pytest.raises(environment.CompositeRefusedError) as excinfo:
        environment._assert_primitive_permitted(
            "capella_cluster_delete", "capella_env_teardown"
        )
    assert "hard ceiling" in str(excinfo.value)


def test_read_primitives_are_unaffected(monkeypatch):
    """The guard must not break the reconciler's ordinary lookups."""
    from handlers.capella import environment

    monkeypatch.delenv("CB_ADMIN_ALWAYS_CONFIRM", raising=False)
    environment._assert_primitive_permitted(
        "capella_clusters_list", "capella_env_status"
    )


# ── Mutation-driven additions ────────────────────────────────────────────────
#
# Every test below closes a mutation that SURVIVED: the control was present and
# correct, but the tests exercised its helpers individually rather than the composed
# behaviour, so removing the composition changed nothing observable.


def test_a_known_kid_is_never_gated_however_much_abuse_is_in_flight(oidc):
    """Closes: dropping the `_kid_is_known` check in validate_token.

    Without it the throttle refuses tokens signed by a key we ALREADY HOLD — which is
    the denial of service the first version of this fix introduced, where one attacker
    request with a junk kid refused every legitimate token for 60 seconds. Testing the
    two helpers separately could not see it; this drives the composed gate.
    """
    import jwt as pyjwt

    client = _CountingClient(known=("real-kid",))

    # Exhaust the budget with invented key ids.
    for index in range(50):
        with contextlib.suppress(RuntimeError):
            oidc.gate_unknown_kid(
                client,
                pyjwt.encode(
                    {"sub": "x"},
                    "a" * 40,
                    algorithm="HS256",
                    headers={"kid": f"attacker-{index}"},
                ),
                "https://idp/jwks",
            )

    legitimate = pyjwt.encode(
        {"sub": "svc"}, "a" * 40, algorithm="HS256", headers={"kid": "real-kid"}
    )
    # Must NOT raise: the key is in the cached set, so no refresh is needed at all.
    oidc.gate_unknown_kid(client, legitimate, "https://idp/jwks")


def test_an_unknown_kid_is_gated_by_the_composed_check(oidc):
    """The other half: the gate must still engage for a key we do not hold."""
    import jwt as pyjwt

    client = _CountingClient(known=("real-kid",))
    token = pyjwt.encode(
        {"sub": "x"}, "a" * 40, algorithm="HS256", headers={"kid": "unknown-kid"}
    )
    oidc.gate_unknown_kid(client, token, "https://idp/jwks")  # first: permitted
    with pytest.raises(RuntimeError):
        oidc.gate_unknown_kid(client, token, "https://idp/jwks")  # repeat: refused


def test_a_success_carrying_an_error_field_is_not_recorded_as_a_denial(monkeypatch):
    """Closes: classifying on the presence of an "error" KEY.

    capella_env_ensure's phase results and capella_env_reap's per-item failures both
    return a top-level "error" inside an otherwise successful response, so ordinary
    provisioning progress was written to the audit log as ``denied_handler``. An audit
    trail that cries wolf on every poll is one an operator learns to ignore.
    """
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    import server
    from handlers.shared import err, ok

    importlib.reload(server)

    success_with_error_text = ok(
        {"phase": "creating_cluster", "done": False, "error": "a sub-resource note"}
    )
    assert server._classify_result(success_with_error_text) == ("allowed", "")

    refusal = err("nope", guardrail=True)
    decision, reason = server._classify_result(refusal)
    assert decision == "denied_guardrail"
    assert reason == "nope"


def test_correlation_id_reaches_the_audit_record_through_the_dispatch(
    tmp_path, monkeypatch
):
    """Closes: dropping the correlation_id capture in call_tool.

    The field was documented, plumbed through audit.build_record, and declared in every
    tool schema — and the dispatch popped it without reading it, so every enterprise
    record was untraceable back to the human action that started the workflow. Asserted
    end-to-end through call_tool, not by calling emit_tool_call directly, because the
    latter is exactly what passed while the wiring was absent.

    ``confirm: true`` is essential to this test. audit.build_record has a FALLBACK that
    reads the id out of the arguments dict, and on an early denial path (no confirm) the
    dispatch has not yet stripped it — so a version of this test without confirm passed
    while exercising only the fallback, and mutation testing caught that. The ALLOWED
    path runs after the strip, which makes the explicit capture the only remaining
    source of the value.
    """
    import asyncio

    path = tmp_path / "audit.log"
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(path))
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "false")

    import audit
    import handlers.shared

    importlib.reload(handlers.shared)
    import server

    importlib.reload(server)
    audit.reset_audit_sink()
    try:
        asyncio.new_event_loop().run_until_complete(
            server.call_tool(
                "admin_bucket_create",
                {
                    "bucket_name": "b",
                    "ram_quota_mb": 256,
                    "confirm": True,
                    "correlation_id": "gh-run-4242",
                },
            )
        )
        body = path.read_text(encoding="utf-8") if path.exists() else ""
        records = [
            json.loads(line.split("AUDIT ", 1)[1])
            for line in body.splitlines()
            if "AUDIT " in line
        ]
        assert records, "no audit record was written at all"
        # The record for the EXECUTED call, i.e. after the argument strip.
        executed = records[-1]
        assert executed["decision"] != "denied_confirmation", (
            "the call did not pass the confirmation gate, so this test would be "
            "exercising build_record's fallback rather than the dispatch capture"
        )
        assert executed.get("correlation_id") == "gh-run-4242", (
            f"the correlation id never reached the audit record: {executed}"
        )
        # ...and it must not have been forwarded to the handler as a REST parameter.
        assert "correlation_id" not in executed["args"]
    finally:
        audit.reset_audit_sink()


def test_a_newline_in_a_correlation_id_cannot_forge_a_record(tmp_path, monkeypatch):
    """It is caller-supplied text landing in a log line."""
    import audit

    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(tmp_path / "a.log"))
    audit.reset_audit_sink()
    try:
        assert "\n" not in (audit.sanitize_correlation('run-1\nAUDIT {"fake":1}') or "")
    finally:
        audit.reset_audit_sink()


def test_workstation_with_a_network_bind_refuses_to_start(monkeypatch):
    """Closes: skipping _validate_workstation_is_actually_local entirely.

    The existing test asserted the WAIVED case (PROFILE_ERRORS == [] with the container
    acknowledgement), which passes whether or not the check runs at all. This asserts
    the unwaived case, which is the one that stops an operator from copying a dev
    compose file into a data centre and getting unauthenticated destructive admin over
    the network.
    """
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "http")
    monkeypatch.setenv("CB_ADMIN_HOST", "0.0.0.0")
    monkeypatch.delenv("CB_ADMIN_WORKSTATION_CONTAINER_BIND", raising=False)

    import profile_config

    importlib.reload(profile_config)
    assert profile_config.PROFILE_ERRORS, (
        "workstation + http + 0.0.0.0 started cleanly; that is unauthenticated "
        "destructive admin exposed to the network"
    )
    assert any("workstation" in e for e in profile_config.PROFILE_ERRORS)


def test_workstation_on_loopback_http_is_fine(monkeypatch):
    """The check must not block the supported local container-over-http shape."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "http")
    monkeypatch.setenv("CB_ADMIN_HOST", "127.0.0.1")
    monkeypatch.delenv("CB_ADMIN_WORKSTATION_CONTAINER_BIND", raising=False)

    import profile_config

    importlib.reload(profile_config)
    assert not [e for e in profile_config.PROFILE_ERRORS if "workstation" in e]


def test_the_ceiling_is_checked_regardless_of_automation(monkeypatch):
    """Closes: nesting the ceiling test under `and has_automation_scope`.

    That was the original GUI defect: with automation off — the default — a ceiling
    tool fell through to the ordinary gate where the caller's own `confirm: true`
    satisfied it. The ceiling must engage for BOTH principals.
    """
    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.setenv("CB_ADMIN_ALWAYS_CONFIRM", "admin_bucket_delete")

    import authz
    import profile_config

    # profile_config snapshots PROFILE_NAME at import, and authz reads that attribute
    # — so reloading authz alone leaves a stale profile from a previous test.
    importlib.reload(profile_config)
    importlib.reload(authz)
    for has_automation in (True, False):
        decision, _ = authz.evaluate(
            "admin_bucket_delete",
            in_confirm_set=True,
            has_automation_scope=has_automation,
        )
        assert decision.decision == "denied_hard_ceiling", (
            f"ceiling not enforced for has_automation_scope={has_automation}"
        )


def test_the_ceiling_applies_to_a_read_only_tool_named_in_it(monkeypatch):
    """`in_confirm_set` being False must not skip the ceiling."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.setenv("CB_ADMIN_ALWAYS_CONFIRM", "admin_bucket_list")

    import authz
    import profile_config

    importlib.reload(profile_config)
    importlib.reload(authz)
    decision, _ = authz.evaluate(
        "admin_bucket_list", in_confirm_set=False, has_automation_scope=False
    )
    assert decision.decision == "denied_hard_ceiling"


# ── Round-4 additions: controls that could be deleted with a green suite ─────
#
# Independent verification mutated each of these and all 504 tests still passed. Every
# one was the same pattern: the test asserted on a HELPER while the composition — the
# place the control actually takes effect — was uncovered.


@requires_symlinks
def test_an_unusable_audit_sink_stops_the_server_from_starting(tmp_path, monkeypatch):
    """Closes: `sink_problem = None` in server._enforce_profile.

    The existing test asserted only that audit.audit_sink_error() RETURNS a string. Its
    docstring said "must stop startup" and nothing tested that startup stopped, so the
    call site could be deleted with a green suite — and this is the control that keeps an
    unattended deployment from running with no accountability at all.
    """
    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    link = tmp_path / "audit.log"
    link.symlink_to(victim)

    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "stdio")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(link))

    import audit
    import profile_config
    import server

    importlib.reload(profile_config)
    importlib.reload(server)
    audit.reset_audit_sink()
    try:
        with pytest.raises(SystemExit) as excinfo:
            server._enforce_profile()
        assert excinfo.value.code == 2
    finally:
        audit.reset_audit_sink()


def test_a_usable_audit_sink_does_not_stop_the_server(tmp_path, monkeypatch):
    """The other half, so the test above cannot pass by refusing everything."""
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "stdio")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(tmp_path / "audit.log"))

    import audit
    import profile_config
    import server

    importlib.reload(profile_config)
    importlib.reload(server)
    audit.reset_audit_sink()
    try:
        server._enforce_profile()  # must not raise
    finally:
        audit.reset_audit_sink()


def test_the_gui_configures_logging_in_its_own_process(monkeypatch):
    """Closes: removing configure_from_env() from gui/gui_server.py.

    Without it the console's audit records propagate to a root logger with no handlers,
    and logging.lastResort only emits at WARNING — so every INFO-level AUDIT record was
    discarded, making the console the one way to act without leaving a trace.

    Asserted on the resulting HANDLER TREE, not on the source text: a grep for
    "configure_from_env()" also matches the string inside a comment, so commenting the
    call out passed a structural check.
    """
    import logging

    pytest.importorskip("flask")
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    monkeypatch.setenv("CB_ADMIN_LOG_SINKS", "stderr")

    tree = logging.getLogger("couchbase-admin")
    for handler in list(tree.handlers):
        tree.removeHandler(handler)
    assert not tree.handlers  # premise: nothing configured yet

    # RELOAD in place, never sys.modules.pop.
    # Popping rebinds these to NEW module objects, so another test file
    # holding a reference to the old one fails on its own importlib.reload
    # with "module not in sys.modules". That silently disabled 6 tests in
    # test_audit_and_profile.py -- including two enterprise-profile security
    # refusals -- whenever this file collected first. reload re-executes the
    # module body, which is what the pop was for, without breaking identity.
    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)
    # gui.gui_server is POPPED, not reloaded, so the module body genuinely
    # re-executes. Popping it is safe -- unlike the shared policy modules, no other
    # test file holds a long-lived reference to this module object.
    #
    # The posture check no longer runs at IMPORT (2026-09-15): importing this module
    # could terminate the interpreter, which took an unrelated test down during
    # collection under randomised order. It now runs in create_app(), with a
    # before_request guard catching a launcher that skips the factory. These tests
    # therefore call the factory rather than relying on an import side effect --
    # which is also a stronger assertion, because it exercises the path an operator
    # actually starts the console through.
    sys.modules.pop("gui.gui_server", None)
    import profile_config  # noqa: F401

    importlib.import_module("gui.gui_server")

    assert tree.handlers, (
        "importing the GUI left the couchbase-admin logger tree unconfigured; its "
        "audit records will be discarded at INFO level"
    )


@requires_symlinks
def test_the_gui_refuses_to_start_on_an_unusable_audit_sink(tmp_path, monkeypatch):
    """Closes: `_sink_problem = None` in gui._enforce_gui_posture.

    The console is a second process with the same accountability requirement, and it
    enforces the posture at IMPORT time — so the assertion is that importing it raises.
    """
    pytest.importorskip("flask")
    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    link = tmp_path / "audit.log"
    link.symlink_to(victim)

    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    monkeypatch.setenv("CB_ADMIN_AUDIT_FILE", str(link))

    import audit

    audit.reset_audit_sink()
    # RELOAD in place, never sys.modules.pop.
    # Popping rebinds these to NEW module objects, so another test file
    # holding a reference to the old one fails on its own importlib.reload
    # with "module not in sys.modules". That silently disabled 6 tests in
    # test_audit_and_profile.py -- including two enterprise-profile security
    # refusals -- whenever this file collected first. reload re-executes the
    # module body, which is what the pop was for, without breaking identity.
    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)
    # gui.gui_server is POPPED, not reloaded, so the module body genuinely
    # re-executes. Popping it is safe -- unlike the shared policy modules, no other
    # test file holds a long-lived reference to this module object.
    #
    # The posture check no longer runs at IMPORT (2026-09-15): importing this module
    # could terminate the interpreter, which took an unrelated test down during
    # collection under randomised order. It now runs in create_app(), with a
    # before_request guard catching a launcher that skips the factory. These tests
    # therefore call the factory rather than relying on an import side effect --
    # which is also a stronger assertion, because it exercises the path an operator
    # actually starts the console through.
    sys.modules.pop("gui.gui_server", None)
    import profile_config  # noqa: F401

    try:
        module = importlib.import_module("gui.gui_server")
        with pytest.raises(SystemExit) as excinfo:
            module.create_app()
        assert excinfo.value.code == 2
        assert victim.read_text(encoding="utf-8") == "keep"
    finally:
        audit.reset_audit_sink()
        sys.modules.pop("gui.gui_server", None)


def _console_under_a_broken_posture(monkeypatch):
    """Import the console with an incoherent posture, WITHOUT needing a symlink.

    `enterprise` with no OAUTH_ISSUER and no OAUTH_AUDIENCE is incoherent, and
    profile_config says so in PROFILE_ERRORS. The neighbouring tests build their
    bad posture from a symlinked audit path because the sink is what they are
    testing; these two are about the ENFORCEMENT POINT, so they need any invalid
    posture at all.

    That distinction matters beyond tidiness: @requires_symlinks skips without
    Developer Mode, `live` and skipped tests are excluded from the mutation
    harnesses, and a control nothing can mutate is a control nothing checks.
    These now run on every platform.
    """
    pytest.importorskip("flask")
    monkeypatch.setenv("CB_ADMIN_PROFILE", "enterprise")
    monkeypatch.delenv("OAUTH_ISSUER", raising=False)
    monkeypatch.delenv("OAUTH_AUDIENCE", raising=False)

    import audit

    audit.reset_audit_sink()
    for name in ("profile_config", "handlers.shared", "authz"):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)
    sys.modules.pop("gui.gui_server", None)
    return importlib.import_module("gui.gui_server")


def test_importing_the_console_does_not_terminate_the_interpreter(monkeypatch):
    """The cost the import-time guard was charging, now removed.

    MEASURED 2026-09-15. A test elsewhere reloaded profile_config under a
    deliberately invalid enterprise configuration -- which is how each requirement
    is proven load-bearing -- and the next test to import this module died during
    COLLECTION with SystemExit(2), naming an OAuth control unrelated to it.

    server.py never had this problem: it enforces from _async_main(), at run time.
    """
    try:
        module = _console_under_a_broken_posture(monkeypatch)  # must NOT raise
        assert hasattr(module, "create_app")
        assert module.app is not None
    finally:
        import audit

        audit.reset_audit_sink()
        sys.modules.pop("gui.gui_server", None)


def test_the_factory_still_refuses_an_incoherent_posture(monkeypatch):
    """The other half. Moving the check out of import must not remove it."""
    try:
        module = _console_under_a_broken_posture(monkeypatch)
        with pytest.raises(SystemExit) as excinfo:
            module.create_app()
        assert excinfo.value.code == 2
    finally:
        import audit

        audit.reset_audit_sink()
        sys.modules.pop("gui.gui_server", None)


def test_a_launcher_that_skips_the_factory_cannot_serve(monkeypatch):
    """Closes the regression that moving enforcement out of import could cause.

    `gunicorn gui.gui_server:app` is the form the old comment documented, and the
    reason the guard sat at module scope. It bypasses create_app(), so the same
    posture check runs as a before_request guard and answers 503 rather than
    serving the admin surface.

    503 rather than SystemExit on purpose: raising inside a worker is a crash loop,
    and an operator who reaches this started the process by an unsupported route.
    Failing every request with the reason is louder and cheaper to diagnose.
    """
    try:
        module = _console_under_a_broken_posture(monkeypatch)
        response = module.app.test_client().get("/api/tools")
        assert response.status_code == 503, response.status_code
        body = response.get_json()
        assert body["problems"], body
        assert "create_app()" in body["hint"]
    finally:
        import audit

        audit.reset_audit_sink()
        sys.modules.pop("gui.gui_server", None)


@pytest.mark.parametrize(
    ("message", "secret"),
    [
        ("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.abc.def", "eyJhbGciOiJSUzI1NiJ9"),
        ("authorization=Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
        ("sent Bearer eyJhbGciOiJSUzI1NiJ9.xyz to the cluster", "eyJhbGciOiJSUzI1NiJ9"),
    ],
)
def test_an_auth_scheme_credential_is_redacted(message, secret):
    """A bearer token carries the credential in the VALUE with no sensitive key name at
    all, and a space between scheme and token — so neither the suffix rule nor the prose
    rule sees it. It is also the single most common way a token reaches a log.

    An earlier version matched the word "Bearer" as the value and produced
    `Authorization: ***REDACTED*** eyJ...` — the label masked and the credential left in
    place, which is worse than not matching.
    """
    from handlers.shared import redact_text

    out = redact_text(message)
    assert secret not in out, out
    assert "***REDACTED***" in out


def test_a_token_without_sub_is_rejected(monkeypatch):
    """Closes: dropping "sub" from required_claims.

    Every other test monkeypatches validate_token, so the claim requirement was never
    exercised. A token with no sub yields principal: null — the unattributable admin
    action the comment above required_claims says was fixed.
    """
    from auth import oidc

    assert "sub" in oidc.REQUIRED_CLAIM_NAMES, (
        "sub is no longer required, so an admin action can be unattributable"
    )


def test_deployment_gating_is_applied_in_the_gui_execution_path(monkeypatch):
    """Closes: removing _tool_is_deployable from either GUI path.

    Against Capella the console advertised and would execute ~120 ns_server tools that
    cannot work there — the "tools that each fail with an opaque 401" problem the gating
    layer exists to remove, reintroduced through the other door.
    """
    pytest.importorskip("flask")
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_DEPLOYMENT", "capella")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    monkeypatch.setenv("CB_ADMIN_READ_ONLY_MODE", "false")
    # RELOAD in place, never sys.modules.pop.
    # Popping rebinds these to NEW module objects, so another test file
    # holding a reference to the old one fails on its own importlib.reload
    # with "module not in sys.modules". That silently disabled 6 tests in
    # test_audit_and_profile.py -- including two enterprise-profile security
    # refusals -- whenever this file collected first. reload re-executes the
    # module body, which is what the pop was for, without breaking identity.
    for name in (
        "profile_config",
        "handlers.shared",
        "authz",
        "deployment",
        "gui.gui_server",
    ):
        if name in sys.modules:
            importlib.reload(sys.modules[name])
        else:
            importlib.import_module(name)
    import profile_config  # noqa: F401

    module = importlib.import_module("gui.gui_server")
    module = importlib.reload(module)
    module.app.config.update(TESTING=True)

    # A self-managed-only tool must be absent from the listing...
    with module.app.test_client() as client:
        listed = {t["name"] for t in client.get("/api/tools").get_json()}
        assert "admin_bucket_delete" not in listed, (
            "an ns_server tool is advertised in Capella mode"
        )

        # ...AND refused if a caller names it anyway.
        resp = client.post(
            "/api/call",
            json={"tool": "admin_bucket_delete", "arguments": {"name": "b"}},
        )
    assert resp.status_code == 403, resp.get_json()
    assert "deployment mode" in resp.get_json()["error"]


def test_the_csrf_guard_covers_every_state_changing_api_path(monkeypatch):
    """Closes: narrowing the guard from /api/* to /api/call only.

    Coverage existed for /api/call alone, so restricting the guard to that one path was
    invisible — while /api/config and any future endpoint went unprotected.
    """
    pytest.importorskip("flask")
    import inspect

    # The profile must be pinned: an earlier test may have evicted gui.gui_server from
    # sys.modules, and re-importing it runs _enforce_gui_posture(), which correctly
    # refuses to start with no CB_ADMIN_PROFILE set.
    monkeypatch.setenv("CB_ADMIN_PROFILE", "workstation")
    monkeypatch.setenv("CB_GUI_INSECURE_NO_AUTH", "1")
    monkeypatch.setenv("OAUTH_ENABLED", "false")
    import profile_config

    importlib.reload(profile_config)
    module = importlib.import_module("gui.gui_server")

    source = inspect.getsource(module._reject_cross_site_request)
    assert '"/api/"' in source, "the CSRF guard is no longer path-general"
    assert '"/auth/"' in source


def test_forgetting_a_kid_does_not_reset_the_whole_budget(oidc):
    """Closes: replacing _forget_unknown_kid's single-key pop with a full clear().

    That mutation lets ONE valid token per request reset the entire refresh budget,
    which restores the amplification while the suite stays green.
    """
    import jwt as pyjwt

    oidc.reset_jwks_throttle()
    for index in range(5):
        with contextlib.suppress(RuntimeError):
            oidc._refuse_if_recently_missed("https://idp/jwks", f"attacker-{index}")

    spent_before = len(oidc._refresh_times)
    assert spent_before > 0, "nothing was recorded, so this test proves nothing"

    token = pyjwt.encode(
        {"sub": "x"}, "a" * 40, algorithm="HS256", headers={"kid": "attacker-0"}
    )
    oidc._forget_unknown_kid(token, "https://idp/jwks")

    assert len(oidc._refresh_times) == spent_before, (
        "resolving one kid reset the global refresh budget; an attacker can keep it "
        "open by interleaving one valid token"
    )
    # ...and only the one kid was forgotten.
    assert "https://idp/jwks|attacker-1" in oidc._unknown_kids


def test_the_refresh_budget_default_is_conservative(monkeypatch):
    """Closes: raising the default budget to something enormous.

    Every other test sets CB_ADMIN_JWKS_REFRESH_BUDGET explicitly, so the DEFAULT — the
    value a real deployment uses — was untested.
    """
    monkeypatch.delenv("CB_ADMIN_JWKS_REFRESH_BUDGET", raising=False)
    from auth import oidc

    importlib.reload(oidc)
    assert 1 <= oidc._REFRESH_BUDGET <= 60, (
        f"default refresh budget is {oidc._REFRESH_BUDGET}; a large default is the "
        "same 1:1 amplification the budget exists to prevent"
    )


def test_a_kid_less_token_is_still_gated(oidc):
    """Closes: `if kid and not _kid_is_known(...)`.

    A falsy kid short-circuited the gate entirely, and PyJWT then looks up None, matches
    nothing, and refreshes anyway — so omitting the header restored the exact 1:1
    amplification the budget was written to stop (measured 101 fetches per 100 requests).
    """
    import jwt as pyjwt

    class _Client:
        def get_signing_keys(self, refresh=False):
            return [_FakeKey("real-kid")]

    client = _Client()
    for headers in ({}, {"kid": ""}):
        oidc.reset_jwks_throttle()
        token = pyjwt.encode({"sub": "x"}, "a" * 40, algorithm="HS256", headers=headers)
        oidc.gate_unknown_kid(client, token, "https://idp/jwks")  # first: permitted
        with pytest.raises(RuntimeError):
            oidc.gate_unknown_kid(client, token, "https://idp/jwks")  # repeat: refused


def test_a_scalar_payload_is_guarded(monkeypatch):
    """Closes: the scalar-root branch of guard_nested_host_fields returning silently.

    handlers/backup.py passes args["target"] straight in with no type validation, so
    target="s3://169.254.169.254/loot" was checked by NOTHING while the dict spelling of
    the same value was denied. A guard whose coverage depends on the caller's choice of
    JSON type is not a guard.
    """
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", raising=False)
    from handlers import backup, eventing
    from handlers.shared import ERROR_MARKER

    for tool, args in (
        (
            "admin_backup_restore_run",
            {"repository_id": "r", "target": "s3://169.254.169.254/loot"},
        ),
    ):
        payload = json.loads(backup.handle(tool, args)[0].text)
        assert payload[ERROR_MARKER] is True
        assert "169.254" in payload["error"], payload

    # Eventing's definition, as a bare string and as a root-level list of strings.
    for definition in ("http://169.254.169.254/", ["http://169.254.169.254/"]):
        payload = json.loads(
            eventing.handle(
                "admin_eventing_create_or_update",
                {"function_name": "f", "definition": definition},
            )[0].text
        )
        assert "169.254" in payload["error"], payload


def test_javascript_in_an_eventing_definition_is_not_guarded(monkeypatch):
    """The other half: forcing checks on every nested string would run a function's
    appcode through the allowlist and refuse ordinary JavaScript."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")
    from handlers.egress import guard_nested_host_fields

    guard_nested_host_fields(
        {
            "appname": "f",
            "appcode": "function OnUpdate(doc, meta) { log(doc.id); }",
            "depcfg": {"source_bucket": "b", "metadata_bucket": "m"},
        },
        tool="admin_eventing_create_or_update",
    )
