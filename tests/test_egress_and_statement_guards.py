"""
Tests for the cluster-egress allowlist, mass-assignment allow-lists, and the
statement guards on the self-managed surface.

Three classes of finding are covered:

  SSRF        Five tools take a hostname from the caller and make COUCHBASE open
              the connection — including admin_logs_collect_start, whose
              uploadHost receives a full diagnostic bundle from every node. Those
              destinations could also be internal addresses the agent itself
              cannot reach; 169.254.169.254 returns cloud IAM credentials.
  MASS ASSIGN Six handlers forwarded every caller-supplied key to sensitive
              endpoints, /settings/security among them.
  STATEMENTS  block_dml_if_readonly had zero callers anywhere — it read as a
              control while enforcing nothing.
"""

from __future__ import annotations

import ipaddress
import json

import pytest

from handlers import egress, shared


@pytest.fixture(autouse=True)
def _clean_egress_env(monkeypatch):
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOW_ANY", raising=False)


# ── Absolute denials ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "host",
    [
        "169.254.169.254",  # AWS/GCP instance metadata -> IAM credentials
        "169.254.170.2",  # ECS task metadata
        "127.0.0.1",
        "localhost",
        "metadata.google.internal",
        "metadata",
        "[::1]",
        "0.0.0.0",
    ],
)
def test_metadata_and_loopback_are_always_denied(host, monkeypatch):
    """These stay denied even with the allowlist lifted. There is no legitimate
    reason to ask a Couchbase node to upload its logs to the metadata service, and
    the cost of being wrong is cloud IAM credentials."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed(host, field="uploadHost", tool="t")


def test_metadata_denied_even_when_explicitly_allowlisted(monkeypatch):
    """An operator cannot configure their way into the metadata service."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "169.254.169.254")
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed("169.254.169.254", field="h", tool="t")


def test_metadata_denied_with_a_port_attached(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed("169.254.169.254:80", field="h", tool="t")


def test_metadata_denied_when_dressed_as_a_url(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed(
            "http://169.254.169.254/latest/meta-data/", field="h", tool="t"
        )


# ── Fail closed, then allowlist behaviour ────────────────────────────────────


def test_no_allowlist_means_no_destination_permitted():
    with pytest.raises(egress.EgressDeniedError) as excinfo:
        egress.assert_egress_allowed("backup.example.com", field="uploadHost", tool="t")
    assert "CB_ADMIN_EGRESS_ALLOWED_HOSTS" in str(excinfo.value)


def test_exact_host_allowlist(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "backup.example.com")
    assert (
        egress.assert_egress_allowed("backup.example.com", field="h", tool="t")
        == "backup.example.com"
    )
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed("evil.example.com", field="h", tool="t")


def test_domain_suffix_allowlist(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", ".corp.example")
    egress.assert_egress_allowed("smtp.corp.example", field="h", tool="t")
    egress.assert_egress_allowed("corp.example", field="h", tool="t")
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed("corp.example.evil.tld", field="h", tool="t")


def test_suffix_entry_does_not_match_a_lookalike_domain(monkeypatch):
    """'.corp.example' must not admit 'notcorp.example'."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", ".corp.example")
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed("notcorp.example", field="h", tool="t")


def test_cidr_allowlist(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "10.20.0.0/16")
    egress.assert_egress_allowed("10.20.5.7", field="h", tool="t")
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed("10.21.5.7", field="h", tool="t")


def test_port_and_scheme_are_stripped_before_the_decision(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "vault.example.com")
    for value in (
        "vault.example.com",
        "vault.example.com:5696",
        "https://vault.example.com",
        "https://vault.example.com/v1/keys",
    ):
        assert egress.assert_egress_allowed(value, field="h", tool="t") == (
            "vault.example.com"
        )


def test_empty_host_is_refused():
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed("", field="h", tool="t")


def test_hint_is_part_of_the_message(monkeypatch):
    """The handlers catch broad exceptions, so the remediation guidance has to
    travel in the message or it is lost."""
    with pytest.raises(egress.EgressDeniedError) as excinfo:
        egress.assert_egress_allowed("x.example.com", field="h", tool="t")
    assert "CB_ADMIN_EGRESS_ALLOWED_HOSTS" in str(excinfo.value)


def test_describe_policy_reports_fail_closed():
    assert "fail-closed" in egress.describe_policy()["posture"]


# ── The five sinks actually consult it ───────────────────────────────────────

#: Every tool that makes the CLUSTER dial a caller-supplied destination. The
#: eventing entry is the sixth, and was missing from the original inventory — an
#: Eventing definition carries depcfg.curl[] bindings, which is the same hazard one
#: level down inside a nested object.
SINK_CALLS = [
    (
        "xdcr",
        "admin_xdcr_reference_create",
        "hostname",
        {"name": "r", "username": "u", "password": "p"},
    ),
    ("cluster", "admin_node_add", "hostname", {"user": "u", "password": "p"}),
    ("cluster", "admin_logs_collect_start", "uploadHost", {}),
    ("cluster", "admin_alerts_set", "emailHost", {"enabled": True}),
    ("encryption", "admin_kmip_set", "kmipHost", {}),
]

SINKS = SINK_CALLS


def test_the_sink_inventory_is_not_empty():
    """Guards the parametrised sweep below from silently matching nothing.

    Five flat-argument sinks here; the sixth (Eventing's depcfg.curl bindings) has
    its own test because the destination is nested inside a definition object rather
    than being a top-level argument.
    """
    assert len(SINK_CALLS) == 5


@pytest.mark.parametrize(("module", "tool", "field", "extra"), SINK_CALLS)
def test_each_sink_refuses_an_unallowlisted_destination(module, tool, field, extra):
    """One END-TO-END test per sink, through the real handler.

    This replaces a structural test that grepped the file for the string
    "assert_egress_allowed". That was decorative: three of the sinks live in
    handlers/cluster.py, so deleting the guard from admin_logs_collect_start left the
    string present via admin_node_add and the test still passed. Mutation testing
    confirmed it missed the removal of the guard from admin_alerts_set,
    admin_kmip_set AND admin_node_add — i.e. it protected one of the four sinks it
    claimed to cover.
    """
    import importlib

    handler = importlib.import_module(f"handlers.{module}")
    payload = json.loads(
        handler.handle(tool, {**extra, field: "169.254.169.254", "confirm": True})[
            0
        ].text
    )
    assert "error" in payload, f"{tool} did not refuse a metadata-service {field}"
    blob = json.dumps(payload)
    assert (
        "never an acceptable destination" in blob
        or "CB_ADMIN_EGRESS_ALLOWED_HOSTS" in blob
    ), f"{tool} failed for some reason other than the egress guard: {blob[:200]}"


def test_logs_collect_refuses_an_unallowlisted_upload_host():
    """End to end through the handler: the diagnostic bundle must not be sent."""
    from handlers import cluster

    result = cluster.handle(
        "admin_logs_collect_start",
        {"uploadHost": "attacker.example.com", "confirm": True},
    )
    payload = json.loads(result[0].text)
    assert "error" in payload
    assert "CB_ADMIN_EGRESS_ALLOWED_HOSTS" in json.dumps(payload)


def test_xdcr_reference_refuses_an_unallowlisted_host():
    from handlers import xdcr

    result = xdcr.handle(
        "admin_xdcr_reference_create",
        {
            "name": "r",
            "hostname": "169.254.169.254",
            "username": "u",
            "password": "p",
            "confirm": True,
        },
    )
    payload = json.loads(result[0].text)
    assert "error" in payload
    # And the supplied password must not be echoed back.
    assert "p" not in payload.get("args", {}).get("password", "")


# ── Mass assignment ──────────────────────────────────────────────────────────


def test_security_settings_rejects_unknown_keys():
    """/settings/security governs TLS posture; an invented key must not reach it."""
    from handlers import security

    payload = json.loads(
        security.handle(
            "admin_security_settings_set",
            {"confirm": True, "someInventedField": "x"},
        )[0].text
    )
    assert "Unrecognised setting" in payload["error"]


def test_query_settings_rejects_unknown_keys():
    from handlers import stats

    payload = json.loads(
        stats.handle(
            "admin_query_settings_set", {"confirm": True, "notARealSetting": 1}
        )[0].text
    )
    assert "Unrecognised query setting" in payload["error"]


def test_internal_settings_requires_an_explicit_settings_object():
    from handlers import stats

    payload = json.loads(
        stats.handle("admin_internal_settings_set", {"confirm": True, "foo": "bar"})[
            0
        ].text
    )
    assert "explicit `settings` object" in payload["error"]


# ── Statement guards ─────────────────────────────────────────────────────────


def test_dml_detection_catches_a_cte_prefixed_mutation():
    """WITH is not a write keyword, but this statement is a write."""
    assert shared.is_dml_statement("WITH t AS (SELECT 1) DELETE FROM `b` WHERE k IN t")


def test_dml_detection_fails_safe_on_an_unterminated_comment():
    """The comment-skipping group matched zero times and the keyword match then
    failed, so a mutation classified as read-only."""
    assert shared.is_dml_statement("/* DELETE FROM `b`")


def test_dml_detection_fails_safe_on_a_bom():
    assert shared.is_dml_statement("﻿DELETE FROM `b`")


@pytest.mark.parametrize(
    "stmt",
    [
        "INSERT INTO b VALUES (1,2)",
        "UPSERT INTO b VALUES (1,2)",
        "UPDATE b SET x=1",
        "DELETE FROM b",
        "MERGE INTO b USING c ON x",
        "DROP INDEX b.i",
        "CREATE INDEX i ON b(x)",
        "GRANT admin TO u",
        "EXECUTE FUNCTION f()",
    ],
)
def test_known_mutations_are_classified_as_dml(stmt):
    assert shared.is_dml_statement(stmt)


@pytest.mark.parametrize(
    "stmt", ["SELECT 1", "  SELECT * FROM b", "-- c\nSELECT 1", "/* c */ SELECT 1"]
)
def test_reads_are_not_classified_as_dml(stmt):
    assert not shared.is_dml_statement(stmt)


def test_block_dml_if_readonly_blocks_in_readonly_mode(monkeypatch):
    monkeypatch.setattr(shared, "READ_ONLY_MODE", True)
    assert shared.block_dml_if_readonly("DELETE FROM b") is not None
    assert shared.block_dml_if_readonly("SELECT 1") is None


def test_block_dml_if_readonly_is_inert_when_writes_are_enabled(monkeypatch):
    monkeypatch.setattr(shared, "READ_ONLY_MODE", False)
    assert shared.block_dml_if_readonly("DELETE FROM b") is None


def test_the_guard_now_has_real_callers():
    """It previously had none, which made it a control in name only."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    callers = {
        p.name
        for p in (root / "handlers").glob("*.py")
        if (
            "block_dml_if_readonly(" in p.read_text(encoding="utf-8")
            or "assert_read_only_statement(" in p.read_text(encoding="utf-8")
        )
        and p.name != "shared.py"
    }
    assert {"diagnostics.py", "indexes.py"} <= callers, callers


def test_vector_index_where_clause_refuses_comments_and_subqueries():
    """A trailing '--' comments out the WITH clause carrying the index's dimension
    and similarity, so the index built is not the one that was reviewed."""
    from handlers import eight_x

    for probe in (
        "1=1 --",
        "META().id IN (SELECT RAW k FROM `other` k)",
        "a=1;b=2",
        "y=2 /* c */",
    ):
        assert eight_x._WHERE_FORBID.search(probe), probe
    assert not eight_x._WHERE_FORBID.search("type = 'doc' AND active = true")


# ── No reverse proxy into the network (private ranges need naming) ────────────


@pytest.mark.parametrize(
    "host", ["10.1.2.3", "192.168.1.5", "172.20.0.9", "100.64.3.4"]
)
def test_private_ranges_are_not_admitted_by_allow_any(host, monkeypatch):
    """CB_ADMIN_EGRESS_ALLOW_ANY means "any PUBLIC destination". If it also opened
    RFC1918, reaching for it out of convenience would turn the cluster into a
    reverse proxy into the internal network."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    with pytest.raises(egress.EgressDeniedError) as excinfo:
        egress.assert_egress_allowed(host, field="uploadHost", tool="t")
    assert "private range" in str(excinfo.value)


def test_private_host_is_permitted_when_explicitly_named(monkeypatch):
    """The legitimate case: a customer's backup target and SMTP relay are on
    RFC1918. They must be reachable — by being named, individually."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "10.20.30.40")
    assert egress.assert_egress_allowed("10.20.30.40", field="h", tool="t")


def test_private_cidr_can_be_allowlisted(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "10.20.0.0/16")
    assert egress.assert_egress_allowed("10.20.5.6", field="h", tool="t")
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed("10.21.5.6", field="h", tool="t")


def test_public_host_still_works_under_allow_any(monkeypatch):
    """Resolution is stubbed rather than live.

    This test used real DNS, so it asserted a property of the test environment as much
    as of the code — and it failed in any sandbox without a resolver, for a reason
    unrelated to what it checks.
    """
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    monkeypatch.setattr(
        egress, "_resolve_all", lambda host: [ipaddress.ip_address("203.0.113.10")]
    )
    assert egress.assert_egress_allowed("uploads.couchbase.com", field="h", tool="t")


def test_allow_any_refuses_a_name_it_cannot_resolve(monkeypatch):
    """ALLOW_ANY is documented as keeping the metadata/loopback denial. For a NAME that
    promise rests entirely on resolution succeeding: with an empty result the denial
    loop ran zero times and the name was admitted unchecked, then re-resolved
    independently by the cluster — possibly to 169.254.169.254."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", raising=False)
    monkeypatch.setattr(egress, "_resolve_all", lambda host: [])
    with pytest.raises(egress.EgressDeniedError) as excinfo:
        egress.assert_egress_allowed("who-knows.example", field="h", tool="t")
    assert "could not be resolved" in str(excinfo.value)


def test_an_explicitly_listed_name_may_be_unresolvable(monkeypatch):
    """An operator who names a destination has made the decision; a name that only
    resolves inside the cluster's own network is an ordinary case and must still work."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "internal-only.example")
    monkeypatch.setattr(egress, "_resolve_all", lambda host: [])
    assert egress.assert_egress_allowed("internal-only.example", field="h", tool="t")


def test_skip_dns_remains_an_escape_hatch(monkeypatch):
    """Where resolution is unavailable or too slow in-path, the operator can opt out
    and keep the string-level denials."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", raising=False)
    assert egress.assert_egress_allowed("who-knows.example", field="h", tool="t")
    # ...but a literal metadata address is still refused.
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed("169.254.169.254", field="h", tool="t")


# ── Debug tools are read-only, unconditionally ───────────────────────────────


def test_debug_tools_refuse_mutations_even_when_writes_are_enabled(monkeypatch):
    """Not read-only-mode dependent. A statement parameter on a diagnostic tool is
    not a sanctioned route for changing data under ANY configuration."""
    monkeypatch.setattr(shared, "READ_ONLY_MODE", False)
    for stmt in (
        "DELETE FROM `b`",
        "UPDATE `b` SET x=1",
        "UPSERT INTO `b` VALUES (1,2)",
        "WITH t AS (SELECT 1) DELETE FROM `b` WHERE k IN t",
    ):
        assert shared.assert_read_only_statement(stmt, tool="cb_explain_query"), stmt


def test_debug_tools_allow_reads_when_writes_are_enabled(monkeypatch):
    monkeypatch.setattr(shared, "READ_ONLY_MODE", False)
    assert shared.assert_read_only_statement("SELECT 1", tool="t") is None


def test_debug_tools_refuse_chained_statements(monkeypatch):
    monkeypatch.setattr(shared, "READ_ONLY_MODE", False)
    assert shared.assert_read_only_statement(
        "SELECT 1; DELETE FROM `b`", tool="cb_explain_query"
    )


def test_explain_of_a_mutation_is_refused():
    """EXPLAIN of a DELETE does not execute it, but per the design rule the debug
    tools do not accept mutating statements at all."""
    from handlers import diagnostics

    payload = json.loads(
        diagnostics.handle("cb_explain_query", {"statement": "DELETE FROM `b`"})[0].text
    )
    assert "read-only diagnostic tool" in payload["error"]


def test_index_advisor_rejects_non_string_elements():
    """ADVISOR() also accepts a session-control object, so a dict element was a
    control command reaching a read-only-annotated tool."""
    from handlers import diagnostics

    payload = json.loads(
        diagnostics.handle("cb_index_advisor", {"statements": [{"action": "purge"}]})[
            0
        ].text
    )
    assert "only SQL++ strings" in payload["error"]


def test_index_advisor_rejects_mutating_statements():
    from handlers import diagnostics

    payload = json.loads(
        diagnostics.handle("cb_index_advisor", {"statements": ["DELETE FROM `b`"]})[
            0
        ].text
    )
    assert "read-only diagnostic tool" in payload["error"]


def test_eventing_curl_bindings_are_guarded():
    """The sixth sink, and the most powerful one — it had no guard at all.

    An Eventing definition carries depcfg.curl[] bindings: cluster-originated
    outbound HTTP with a caller-chosen hostname and its own credentials. Same hazard
    as the other five, one level down inside a nested object, which is why an
    argument-level check missed it.
    """
    from handlers import eventing

    payload = json.loads(
        eventing.handle(
            "admin_eventing_create_or_update",
            {
                "function_name": "x",
                "confirm": True,
                "definition": {
                    "appname": "x",
                    "appcode": "function OnUpdate(d,m){}",
                    "depcfg": {"curl": [{"hostname": "http://169.254.169.254"}]},
                    "settings": {},
                },
            },
        )[0].text
    )
    assert "error" in payload
    assert "never an acceptable destination" in json.dumps(payload)


def test_kmip_additional_fields_cannot_smuggle_a_host():
    """additional_fields is an allow-list escape hatch by construction, so the guard
    has to run on the MERGED payload. Checking args["kmipHost"] meant
    additional_fields={"kmipHost": ...} skipped it entirely — on the tool that
    decides where the cluster fetches its master encryption key."""
    from handlers import encryption

    payload = json.loads(
        encryption.handle(
            "admin_kmip_set",
            {"confirm": True, "additional_fields": {"kmipHost": "169.254.169.254"}},
        )[0].text
    )
    assert "error" in payload
    assert "never an acceptable destination" in json.dumps(payload)


@pytest.mark.parametrize(
    "host",
    [
        "::ffff:169.254.169.254",  # IPv4-mapped IPv6 — dialled as IPv4 by every stack
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "2130706433",  # bare integer -> 127.0.0.1
        "0x7f000001",  # hex
        "0177.0.0.1",  # dotted octal
        "169.254.169.254.",  # trailing dot defeats both name list and IP parse
        "metadata.google.internal.",
        "0.0.0.1",  # 0.0.0.0/8 routes locally; only /32 was denied
        "smtp.corp.example:25@169.254.169.254",  # userinfo: real target is after the @
    ],
)
def test_denial_cannot_be_dodged_by_address_spelling(host, monkeypatch):
    """Each of these reached the metadata service with the allowlist LIFTED."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "smtp.corp.example")
    with pytest.raises(egress.EgressDeniedError):
        egress.assert_egress_allowed(host, field="uploadHost", tool="t")


def test_query_and_fragment_cannot_forge_a_suffix_match(monkeypatch):
    """`https://evil.tld?x=.corp.example` matched a `.corp.example` suffix entry,
    because the query string was still part of the compared value."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", ".corp.example")
    for value in (
        "https://evil.tld?x=.corp.example",
        "https://evil.tld#.corp.example",
    ):
        with pytest.raises(egress.EgressDeniedError):
            egress.assert_egress_allowed(value, field="h", tool="t")


def test_a_name_resolving_to_the_metadata_service_is_refused(monkeypatch):
    """The check was on the STRING, so DNS decided the destination."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    monkeypatch.setattr(
        egress,
        "_resolve_all",
        lambda host: [__import__("ipaddress").ip_address("169.254.169.254")],
    )
    with pytest.raises(egress.EgressDeniedError) as excinfo:
        egress.assert_egress_allowed(
            "imds.attacker.example", field="uploadHost", tool="t"
        )
    assert "resolves to" in str(excinfo.value)


def test_read_only_ctes_are_not_mistaken_for_writes():
    """Treating every WITH as a write disabled the diagnostic tools for exactly the
    queries an operator brings to an index advisor."""
    assert not shared.is_dml_statement("WITH t AS (SELECT 1) SELECT * FROM t")
    assert shared.is_dml_statement("WITH t AS (SELECT 1) DELETE FROM `b` WHERE k IN t")


@pytest.mark.parametrize(
    "stmt",
    [
        "SELECT * FROM `b` WHERE code = 'A;B'",
        "SELECT * FROM `b` WHERE note = 'x--y'",
        "SELECT * FROM `orders;archive`",
        "SELECT * FROM `b` WHERE c = 'a/*b'",
    ],
)
def test_quoted_spans_do_not_trip_the_chaining_guard(stmt):
    """A statement from system:completed_requests plausibly contains all of these,
    and the refusal message ("Remove everything after the first ';'") actively
    misled."""
    assert shared.assert_single_statement(stmt) is None


def test_response_fields_that_merely_look_sensitive_survive():
    """ok() redacts every response, so a bare-substring rule corrupted data an agent
    reads and writes back — an FTS analysis section round-tripped
    "tokenizer": "***REDACTED***" into the cluster."""
    masked = shared.redact(
        {
            "tokenizer": "unicode",
            "token_filters": ["lower"],
            "author": "chris",
            "authType": "sasl",
            "bypass": True,
            "password": "s3cret",
            "emailPass": "s3cret",
            "bearer_key": "k",
        }
    )
    assert masked["tokenizer"] == "unicode"
    assert masked["token_filters"] == ["lower"]
    assert masked["author"] == "chris"
    assert masked["authType"] == "sasl"
    assert masked["bypass"] is True
    for secret in ("password", "emailPass", "bearer_key"):
        assert masked[secret] == shared.REDACTED, secret


def test_deeply_nested_arguments_cannot_destroy_the_audit_record():
    """A ~500-deep nested argument raised RecursionError inside record construction —
    which runs AFTER the handler — so the bucket was deleted and the audit trail
    contained nothing."""
    import audit as audit_mod

    deep = {"a": None}
    cursor = deep
    for _ in range(800):
        cursor["a"] = {"a": None}
        cursor = cursor["a"]

    emitted = []
    original = audit_mod.emit
    audit_mod.emit = emitted.append
    try:
        audit_mod.emit_tool_call(
            tool="admin_bucket_delete",
            arguments={"bucket_name": "prod", "junk": deep},
            decision="allowed",
        )
    finally:
        audit_mod.emit = original
    assert emitted and emitted[0]["tool"] == "admin_bucket_delete"


def test_audit_settings_reject_unknown_keys():
    """/settings/audit was the one settings endpoint left with full mass assignment —
    the anti-forensics one."""
    from handlers import security

    payload = json.loads(
        security.handle("admin_audit_set", {"confirm": True, "notAThing": 1})[0].text
    )
    assert "Unrecognised audit setting" in payload["error"]


# ── The recursive walk: the shapes the old guard failed open on ───────────────
#
# The previous guard read exactly definition["depcfg"]["curl"][i]["hostname"] and
# returned SILENTLY on any other shape. Its test covered only that one shape — the one
# the old code already handled — so all four bypasses survived. Mutation testing then
# showed a fifth, introduced by the first version of the walk itself.

_METADATA = "169.254.169.254"

_BYPASS_SHAPES = {
    "a top-level LIST of definitions (the endpoint accepts one)": [
        {"depcfg": {"curl": [{"hostname": _METADATA}]}}
    ],
    "depcfg as a list": {"depcfg": [{"curl": [{"hostname": _METADATA}]}]},
    "curl as a single object, not a list": {
        "depcfg": {"curl": {"hostname": _METADATA}}
    },
    "an alternate key spelling": {"depcfg": {"curl": [{"Hostname": _METADATA}]}},
    "a url instead of a hostname": {
        "depcfg": {"curl": [{"url": f"http://{_METADATA}/latest/meta-data/"}]}
    },
    "a LIST OF SCALARS under a host key": {"hostname": [_METADATA]},
    "a tuple of scalars": {"hostname": (_METADATA,)},
    "a list of url strings": {"depcfg": {"curl": [f"http://{_METADATA}/"]}},
    "buried somewhere else entirely": {
        "settings": {"deployment": {"remoteEndpoint": _METADATA}}
    },
    "the canonical shape (a regression check)": {
        "depcfg": {"curl": [{"hostname": _METADATA}]}
    },
}


@pytest.mark.parametrize(("label", "payload"), list(_BYPASS_SHAPES.items()))
def test_the_walk_finds_a_metadata_address_in_any_shape(label, payload, monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")
    with pytest.raises(egress.EgressDeniedError):
        egress.guard_nested_host_fields(payload, tool="admin_eventing_create_or_update")


def test_the_walk_reaches_the_eventing_handler(monkeypatch):
    """End-to-end through the real handler, not just the helper."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")
    from handlers import eventing

    result = eventing.handle(
        "admin_eventing_create_or_update",
        {
            "function_name": "f",
            "definition": {"depcfg": {"curl": [{"hostname": [_METADATA]}]}},
        },
    )
    payload = json.loads(result[0].text)
    assert payload[shared.ERROR_MARKER] is True
    assert "169.254" in payload["error"]


def test_an_allowlisted_destination_still_passes_the_walk(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "curl.corp.example")
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")
    egress.guard_nested_host_fields(
        {"depcfg": {"curl": [{"hostname": "curl.corp.example"}]}}, tool="t"
    )


def test_fields_that_merely_look_like_addresses_are_not_guarded(monkeypatch):
    """Over-guarding is the safe direction but still an operator-facing outage: a
    contact emailAddress or a macAddress inside a definition is not a destination."""
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", raising=False)
    egress.guard_nested_host_fields(
        {"emailAddress": "ops@corp.example", "macAddress": "00:11:22:33:44:55"},
        tool="t",
    )


def test_an_operator_can_exempt_a_field_name(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_EXEMPT_FIELDS", "siteUrl")
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", raising=False)
    egress.guard_nested_host_fields({"siteUrl": "https://anything.example"}, tool="t")
    # ...and a field that is NOT exempted is still guarded.
    with pytest.raises(egress.EgressDeniedError):
        egress.guard_nested_host_fields(
            {"otherUrl": "https://anything.example"}, tool="t"
        )


def test_the_walk_has_a_leaf_budget(monkeypatch):
    """Depth was capped; BREADTH was not. Every name-valued leaf costs a blocking
    getaddrinfo, so one call with thousands of leaves was thousands of resolver round
    trips on a single worker thread — and, under a suffix allowlist, a DNS side
    channel out of the server."""
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", ".corp.example")
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")
    payload = {"hosts": [f"h{i}.corp.example" for i in range(5000)]}
    with pytest.raises(egress.EgressDeniedError) as excinfo:
        egress.guard_nested_host_fields(payload, tool="t")
    assert "destination-shaped values" in str(excinfo.value)


def test_a_reasonable_payload_is_within_the_budget(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", ".corp.example")
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")
    payload = {
        "depcfg": {"curl": [{"hostname": f"h{i}.corp.example"} for i in range(20)]}
    }
    egress.guard_nested_host_fields(payload, tool="t")


def test_a_depth_bomb_is_refused_rather_than_raising_recursionerror():
    deep: dict = {}
    cursor = deep
    for _ in range(200):
        cursor["a"] = {}
        cursor = cursor["a"]
    with pytest.raises(egress.EgressDeniedError):
        egress.guard_nested_host_fields(deep, tool="t")


# ── Mass assignment, through the real handlers ───────────────────────────────


@pytest.mark.parametrize(
    ("module_name", "tool", "good", "undeclared"),
    [
        (
            "indexes",
            "admin_index_settings_set",
            {"indexerThreads": 4},
            "disableUIOverHttp",
        ),
        (
            "cluster",
            "admin_cluster_memory_set",
            {"dataMemoryQuota": 1024},
            "clusterName",
        ),
        (
            "security",
            "admin_password_policy_set",
            {"minLength": 8},
            "disableUIOverHttp",
        ),
        (
            "xdcr",
            "admin_xdcr_settings_set",
            {"compressionType": "Auto"},
            "sourceNozzlePerNode",
        ),
    ],
)
def test_an_undeclared_key_is_refused_by_the_handler(
    module_name, tool, good, undeclared
):
    """Through handle(), not through the helper.

    A mutation that removed the refusal but kept the filtering survived a test that
    called refuse_undeclared() directly: the key was silently dropped, which is the
    behaviour the refusal exists to prevent — an agent told the operation succeeded
    while the setting it asked for was never applied.
    """
    import importlib

    module = importlib.import_module(f"handlers.{module_name}")
    args = dict(good)
    args[undeclared] = "true"
    args["confirm"] = True

    result = module.handle(tool, args)
    payload = json.loads(result[0].text)
    assert payload[shared.ERROR_MARKER] is True, payload
    assert undeclared in payload["error"], payload
    assert "declared_parameters" in payload
