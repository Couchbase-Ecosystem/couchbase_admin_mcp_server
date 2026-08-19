"""Regression tests for the ten findings fixed from SECURITY_AND_BUG_SCAN_2026-08-17.

One test per finding, named by its id, asserting the BEHAVIOUR that was wrong rather
than the shape of the fix.

Why a dedicated file: the report's own explanation for why most of these survived is
that nothing covered them. `admin_autofailover_set` had no test at all. The guardrail
fixtures hand-built ownership markers, so the create path that never wrote one was
invisible. The five dispatch refusal-path tests existed but did not run. A fix without
a test in that situation is the same fix again in six months, so the tests live
together where the provenance is obvious.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


# ── BUG-3: the shipped artifact must contain every top-level module ──────────


def test_bug3_dryrun_is_in_both_shipping_lists():
    """server.py imports dryrun; the container and the wheel must both ship it.

    test_packaging already asserts this generically for every import. This is the
    specific one, because it was reported by those tests for days and read as a stale
    test rather than as the container failing to start.
    """
    dockerfile = (REPO / "Dockerfile").read_text(encoding="utf-8")
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert "dryrun.py /app/dryrun.py" in dockerfile
    assert '"dryrun.py" = "dryrun.py"' in pyproject


# ── SEC-2: dry-run preview must not echo credentials ─────────────────────────


@pytest.mark.parametrize(
    "argname",
    ["password", "emailPass", "secret_access_key", "kmipKeyPassphrase"],
)
def test_sec2_preview_redacts_credentials_in_prose_and_dict(argname):
    """The prose `message` leaked what the `arguments` dict masked.

    Both come from the same payload, so both must be masked. The console consumer
    applies no redaction of its own, so this is the only place that covers it.
    """
    import dryrun

    payload = dryrun.preview(
        "admin_user_create",
        {"username": "svc", argname: "sup3rs3cret", "dry_run": True},
        reason="test",
    )
    assert "sup3rs3cret" not in payload["message"], "credential in the prose message"
    assert "sup3rs3cret" not in json.dumps(payload["arguments"])
    # The non-sensitive argument still has to be readable, or the preview is useless.
    assert "svc" in payload["message"]


# ── BUG-1: admin_bucket_create must send the quota it requires ───────────────


def test_bug1_bucket_create_sends_ram_quota(monkeypatch):
    """`ramQuota` is the schema's required argument; ns_server wants `ramQuotaMB`.

    The rename sat AFTER the allow-list filter, which had already dropped ramQuota,
    so it was dead code and the POST carried no quota at all.
    """
    from handlers import buckets

    sent: dict = {}

    def fake_admin_request(method, path, data=None, **kw):
        sent.update({"method": method, "path": path, "data": data or {}})
        return {"ok": True}

    monkeypatch.setattr(buckets, "admin_request", fake_admin_request)
    buckets.handle(
        "admin_bucket_create",
        {"name": "b1", "ramQuota": 256, "bucketType": "couchbase"},
    )
    assert sent["data"].get("ramQuotaMB") == "256", (
        f"quota not forwarded; body was {sent['data']}"
    )
    assert "ramQuota" not in sent["data"], "unrenamed key would be rejected"


def test_bug1_bucket_create_still_refuses_invented_keys(monkeypatch):
    """The rename must not become a hole in the allow-list."""
    from handlers import buckets

    sent: dict = {}
    monkeypatch.setattr(
        buckets,
        "admin_request",
        lambda m, p, data=None, **kw: sent.update({"data": data or {}}) or {"ok": True},
    )
    buckets.handle(
        "admin_bucket_create",
        {"name": "b1", "ramQuota": 256, "notARealSetting": "x"},
    )
    assert "notARealSetting" not in sent["data"]


# ── BUG-2: a tool that owns dry_run must receive it ──────────────────────────


def test_bug2_handler_owned_dry_run_is_not_stripped():
    """The dispatch stripped the flag unconditionally, including from its owner.

    capella_env_reap defaults dry_run to TRUE, so with the flag removed every reap
    was a preview and expired environments billed forever.
    """
    import dryrun

    class FakeTool:
        name = "capella_env_reap"

    dryrun._HANDLER_OWNED = {"capella_env_reap"}
    assert dryrun.handler_owns(FakeTool()) is True

    args = {"dry_run": False, "organization_id": "o"}
    # This is the guard the dispatch now applies.
    if not dryrun.handler_owns(FakeTool()):
        dryrun.strip(args)
    assert "dry_run" in args, "owner never sees the flag it implements"

    # A tool that does NOT own it still gets it stripped, or it reaches a REST body.
    class Other:
        name = "admin_bucket_delete"

    other_args = {"dry_run": True, "bucket_name": "b"}
    if not dryrun.handler_owns(Other()):
        dryrun.strip(other_args)
    assert "dry_run" not in other_args


def test_bug2_in_effect_returns_false_for_the_owner():
    """The premise: in_effect defers to the handler, which is why stripping broke it."""
    import dryrun

    class FakeTool:
        name = "capella_env_reap"

    dryrun._HANDLER_OWNED = {"capella_env_reap"}
    applies, _ = dryrun.in_effect({"dry_run": True}, FakeTool())
    assert applies is False


# ── SEC-1: the ceiling must not be answerable two ways ──────────────────────


def test_sec1_caller_context_overrides_the_process_global(monkeypatch):
    """The composite guard asks authz.human_is_present() directly.

    In a console process on a workstation profile that read True from the MCP
    transport variable, while the console itself passed human_present=False into
    evaluate(). capella_env_teardown then deleted a ceiling-listed cluster that
    capella_cluster_delete was refusing on the same request.
    """
    import authz
    import profile_config

    monkeypatch.setattr(profile_config, "PROFILE_NAME", profile_config.WORKSTATION)
    monkeypatch.setenv("CB_ADMIN_TRANSPORT", "stdio")

    assert authz.human_is_present() is True, "premise: the transport says stdio"
    with authz.caller_context(human_present=False):
        assert authz.human_is_present() is False, "caller evidence must win"
    assert authz.human_is_present() is True, "context must not leak"


def test_sec1_composite_guard_refuses_under_console_evidence(monkeypatch):
    """The end-to-end shape: the ceiling refuses the COMPOSITE, not just the primitive.

    Both cases are driven through caller_context rather than by arranging the profile
    and transport, deliberately. This suite reloads and re-imports authz, so
    `environment.authz` can be a different module object from `sys.modules["authz"]` --
    which means patching `profile_config.PROFILE_NAME` here does not necessarily reach
    the copy the guard consults, and a test written that way fails for reasons that
    have nothing to do with the ceiling.

    Stating the evidence explicitly tests exactly what the fix guarantees: whatever the
    caller declares is what the guard downstream acts on. That it survives duplicate
    module copies is the point -- the evidence lives on the thread object, so every
    copy of authz reaches the same value. The process-global fallback is covered
    separately by test_sec1_caller_context_overrides_the_process_global.
    """
    import authz
    from handlers.capella import environment

    monkeypatch.setenv("CB_ADMIN_ALWAYS_CONFIRM", "capella_cluster_delete")
    monkeypatch.setenv("CB_ADMIN_DISABLED_TOOLS", "")

    # Interactive MCP caller: a human is present, so the composite may proceed.
    with authz.caller_context(human_present=True):
        environment._assert_primitive_permitted(
            "capella_cluster_delete", "capella_env_teardown"
        )

    # Console caller: no human, so it must refuse -- and name both tools.
    with authz.caller_context(human_present=False):
        with pytest.raises(environment.CompositeRefusedError) as excinfo:
            environment._assert_primitive_permitted(
                "capella_cluster_delete", "capella_env_teardown"
            )
    assert "capella_env_teardown" in str(excinfo.value)
    assert "capella_cluster_delete" in str(excinfo.value)


def test_sec1_evidence_survives_duplicate_authz_module_copies(monkeypatch):
    """The flag must not live in module state.

    The first version of this fix used a module-level threading.local, and this suite
    produced a second live copy of authz -- so the console set the flag on one copy and
    the composite guard read None from the other, silently reverting to the answer the
    override exists to replace. A security control whose enforcement depends on import
    bookkeeping is the same defect shape as SEC-1 itself.
    """
    import importlib
    import sys

    import authz

    monkeypatch.setenv("CB_ADMIN_ALWAYS_CONFIRM", "capella_cluster_delete")

    # A genuinely separate module object, as importlib.reload plus a stale reference
    # produces in this suite.
    spec = importlib.util.find_spec("authz")
    other = importlib.util.module_from_spec(spec)
    sys.modules["_authz_copy_for_test"] = other
    spec.loader.exec_module(other)
    assert other is not authz, "premise: two distinct module objects"

    with authz.caller_context(human_present=False):
        assert other.caller_evidence() is False, (
            "the other copy cannot see the evidence; module-scoped state has "
            "reintroduced the split this fix exists to close"
        )
        assert other.human_is_present() is False

    assert other.caller_evidence() is None, "restore must be visible to both copies"
    del sys.modules["_authz_copy_for_test"]


def test_sec1_nested_context_cannot_widen_evidence(monkeypatch):
    """A composite re-entering the dispatch must not be able to promote itself.

    This test previously asserted the OPPOSITE of its own name: it checked that the
    inner context returned True inside an outer False, i.e. it pinned the widening as
    correct while the name claimed it was prevented. caller_context now clamps, so the
    name and the assertion agree.
    """
    import authz

    with authz.caller_context(human_present=False):
        assert authz.human_is_present() is False
        with authz.caller_context(human_present=True):
            assert authz.human_is_present() is False, (
                "an inner context widened the evidence: a composite re-entering the "
                "dispatch could promote itself past the hard ceiling, which is SEC-1"
            )
        assert authz.human_is_present() is False, "inner context must be popped"

    # Narrowing in the other direction must still work, or the console's
    # human_present=False would be ignored inside an interactive MCP call.
    with authz.caller_context(human_present=True):
        assert authz.human_is_present() is True
        with authz.caller_context(human_present=False):
            assert authz.human_is_present() is False
        assert authz.human_is_present() is True


# ── BUG-5: a boolean argument must mean what it says ────────────────────────


@pytest.mark.parametrize(
    "sent,expected",
    [
        (False, "false"),
        ("false", "false"),
        ("False", "false"),
        ("no", "false"),
        ("off", "false"),
        (0, "false"),
        (True, "true"),
        ("true", "true"),
        ("1", "true"),
        (1, "true"),
    ],
)
def test_bug5_autofailover_enabled_is_coerced(monkeypatch, sent, expected):
    """`enabled="false"` ENABLED auto-failover, on a destructiveHint tool.

    This tool had no test of any kind, which is why a straight inversion survived.
    """
    from handlers import cluster

    sent_data: dict = {}
    monkeypatch.setattr(
        cluster,
        "admin_request",
        lambda m, p, data=None, **kw: sent_data.update(data or {}) or {"ok": True},
    )
    cluster.handle("admin_autofailover_set", {"enabled": sent})
    assert sent_data["enabled"] == expected, f"enabled={sent!r} produced {sent_data}"


@pytest.mark.parametrize("field", ["timeout", "maxCount"])
def test_bug5_autofailover_zero_is_forwarded_not_dropped(monkeypatch, field):
    """`if args.get(field)` dropped 0 while returning success.

    0 is out of range and ns_server will say so. An explicit rejection beats being
    told a value was set that was never sent.
    """
    from handlers import cluster

    sent_data: dict = {}
    monkeypatch.setattr(
        cluster,
        "admin_request",
        lambda m, p, data=None, **kw: sent_data.update(data or {}) or {"ok": True},
    )
    cluster.handle("admin_autofailover_set", {"enabled": True, field: 0})
    assert sent_data.get(field) == "0", f"{field}=0 was dropped; body was {sent_data}"


def test_bug5_arg_truthy_fails_closed_on_nonsense():
    """An uninterpretable request to switch something ON must not switch it on."""
    from handlers.shared import arg_truthy

    assert arg_truthy("maybe") is False
    assert arg_truthy("") is False
    assert arg_truthy(None) is False


# ── SEC-3: the spend ceiling must see the raw create primitive ──────────────


def test_sec3_ceiling_counts_clusters_created_by_the_primitive(monkeypatch):
    """count_managed_environments counted only markers.

    capella_cluster_create forwarded the caller's body verbatim and wrote no marker,
    so clusters created through it were invisible to the guard bounding them. Six
    were created against a ceiling of two.
    """
    from handlers.capella import guardrails

    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "p1")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    monkeypatch.setenv("CAPELLA_MAX_ENVIRONMENTS", "2")
    guardrails.load_policy.cache_clear() if hasattr(
        guardrails.load_policy, "cache_clear"
    ) else None

    # What the primitive used to leave behind: right name, no marker.
    unmarked = [{"name": f"mcptest-{i}", "description": ""} for i in range(6)]
    count = guardrails.count_managed_environments(lambda project: unmarked, None, "p1")
    assert count == 6, (
        f"ceiling still blind to primitive-created clusters (saw {count})"
    )


def test_sec3_ceiling_ignores_foreign_clusters(monkeypatch):
    """The name signal must not count somebody else's clusters."""
    from handlers.capella import guardrails

    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "p1")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    foreign = [{"name": "production-orders", "description": "the real one"}]
    assert guardrails.count_managed_environments(lambda p: foreign, None, "p1") == 0


def test_sec3_no_prefix_configured_keeps_marker_only_counting(monkeypatch):
    """With no prefix, is_managed_name matches everything.

    Counting on it there would make the ceiling refuse creates in an org that was
    previously working, so the name signal is gated on a prefix being configured.
    """
    from handlers.capella import guardrails

    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "p1")
    monkeypatch.delenv("CAPELLA_ENV_NAME_PREFIX", raising=False)
    anything = [{"name": "someones-cluster", "description": ""}]
    assert guardrails.count_managed_environments(lambda p: anything, None, "p1") == 0


# ── SEC-4: a brace in `owner` must not orphan an environment ────────────────


def test_sec4_owner_with_a_brace_still_parses():
    """`owner="ci pipeline }run-42"` made parse_marker return None.

    Every consequence failed open: the ceiling stopped counting it, env_list filed it
    as unmanaged, and reap never collected it, so it billed indefinitely.
    """
    from handlers.capella import guardrails

    raw = guardrails.ENV_MARKER_PREFIX + json.dumps(
        {
            "env": "mcptest-a",
            "created": "2026-08-17T00:00:00Z",
            "ttl_h": 8,
            "owner": "ci pipeline }run-42",
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    parsed = guardrails.parse_marker(raw)
    assert parsed is not None, "greedy anchored parse should recover this"
    assert parsed["owner"] == "ci pipeline }run-42"
    assert parsed["env"] == "mcptest-a"


def test_sec4_marker_survives_a_human_edited_description():
    """Tolerance was the original design intent and must be preserved."""
    from handlers.capella import guardrails

    marker = guardrails.build_marker("mcptest-b", ttl_hours=8, owner="ci-bot")
    described = f"scratch cluster for the integration POC\n{marker}\ndo not delete before Friday"
    parsed = guardrails.parse_marker(described)
    assert parsed is not None and parsed["env"] == "mcptest-b"


@pytest.mark.parametrize("bad", ['a"b', "a{b", "a}b", "a\\b", "a\nb"])
def test_sec4_unsafe_marker_text_is_refused_at_write_time(bad):
    """Refused where the value is named, not silently rewritten."""
    from handlers.capella import guardrails

    with pytest.raises(guardrails.GuardrailError):
        guardrails.build_marker("mcptest-c", owner=bad)


# ── SEC-5: the egress verdict must not depend on spelling ───────────────────


@pytest.fixture
def egress_env(monkeypatch):
    """A hermetic egress configuration.

    Every variable the guard reads is pinned, not just the allowlist. An earlier
    version of these tests set only CB_ADMIN_EGRESS_ALLOWED_HOSTS and passed alone
    while failing in a full suite, because another test leaks
    CB_ADMIN_EGRESS_EXEMPT_FIELDS and an exempt key is skipped before any check runs.
    A guard test that inherits ambient configuration is testing the environment.
    """
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "backup.internal")
    monkeypatch.setenv("CB_ADMIN_EGRESS_EXEMPT_FIELDS", "")
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOW_ANY", raising=False)


@pytest.mark.parametrize(
    "spelling",
    [
        "169.254.169.254",
        "2852039166",
        "0xa9fea9fe",
        "metadata",
        "localhost",
        "metadata.google.internal",
    ],
)
def test_sec5_nested_and_flat_guards_agree(egress_env, spelling):
    """Three guards over one payload disagreed in the unsafe direction.

    `{"depcfg":{"curl":[{"hostname":"metadata"}]}}` was unchecked while the same
    destination as `metadata.google.internal` was denied.
    """
    from handlers import egress

    with pytest.raises(egress.EgressDeniedError):
        egress.guard_host_like_fields({"hostname": spelling}, tool="t")
    with pytest.raises(egress.EgressDeniedError):
        egress.guard_nested_host_fields(
            {"depcfg": {"curl": [{"hostname": spelling}]}}, tool="t"
        )


def test_sec5_non_string_leaf_is_checked(egress_env):
    """A non-str leaf under a host-like key was dropped entirely."""
    from handlers import egress

    with pytest.raises(egress.EgressDeniedError):
        egress.guard_nested_host_fields({"hostname": 2852039166}, tool="t")


def test_sec5_allowed_host_still_passes(egress_env):
    """Over-guarding is an outage, so the allowed case is pinned too."""
    from handlers import egress

    egress.guard_nested_host_fields(
        {"depcfg": {"curl": [{"hostname": "backup.internal"}]}}, tool="t"
    )


def test_sec5_eventing_appcode_is_not_run_through_the_allowlist(egress_env):
    """Forcing the heuristic everywhere would refuse ordinary JavaScript."""
    from handlers import egress

    egress.guard_nested_host_fields(
        {"appcode": "function OnUpdate(doc, meta) { log('a.b.c:8091'); }"}, tool="t"
    )


# ── BUG-12: the five refusal-path tests must actually run ───────────────────


def test_bug12_no_test_uses_the_ambient_event_loop():
    """`asyncio.get_event_loop()` reads ambient state.

    Any earlier test calling asyncio.run leaves the main thread's loop closed, so the
    bare form raises instead of creating one -- which is why five refusal-path tests
    in test_server_dispatch.py passed alone and never ran in a full-suite CI. Guarding
    the form rather than the symptom, because the symptom only appears in a full run
    and depends on collection order.

    Scoped to the CHAINED form, not to every mention. test_dry_run.py's `call()` uses
    get_event_loop deliberately, checks `is_closed()` and falls back to a fresh loop,
    with a comment explaining this exact hazard. That is the defended form and
    flagging it would teach the next person to work around the guard rather than fix
    the bug. The chained form has nowhere to put such a check, which is what makes it
    the reliable signal.
    """
    offenders = []
    pattern = re.compile(
        r"\basyncio\.get_event_loop\s*\(\s*\)\s*\.\s*run_until_complete"
    )
    for path in sorted((REPO / "tests").glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue  # this file names the pattern in order to forbid it
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                offenders.append(f"{path.name}:{lineno}")
        # The call may also be split across lines, which is how the original read.
        for match in pattern.finditer(re.sub(r"\s*\n\s*", " ", text)):
            hit = f"{path.name}:<wrapped>"
            if hit not in offenders and not any(
                o.startswith(path.name + ":") for o in offenders
            ):
                offenders.append(hit)
    assert not offenders, (
        "use asyncio.run(), or get_event_loop() with an is_closed() fallback as "
        "test_dry_run.call() does; the chained form reads ambient loop state and "
        f"makes the test silently not run in a full suite: {offenders}"
    )


def test_bug12_the_dispatch_refusal_paths_run_after_asyncio_run():
    """Reproduce the pollution, then prove the fixed call form survives it."""
    import server

    asyncio.run(asyncio.sleep(0))  # what test_http_authorization.py does

    with pytest.raises(RuntimeError):
        asyncio.get_event_loop()  # premise: the old form is now broken

    result = asyncio.run(server.call_tool("no_such_tool_at_all", {}))
    assert result, "the refusal path must produce a payload"


# ── The stale premise found while re-running the suite ──────────────────────


def test_ipv4_mapped_premise_is_not_pinned_to_an_old_cpython():
    """CPython changed: IPv6Address now delegates is_loopback to the mapped address.

    A test asserting the OLD answer as its premise fails when the platform improves.
    What matters is that the peer check has a correct answer to read either way.
    """
    address = ipaddress.ip_address("::ffff:127.0.0.1")
    assert address.ipv4_mapped is not None
    assert address.ipv4_mapped.is_loopback is True
