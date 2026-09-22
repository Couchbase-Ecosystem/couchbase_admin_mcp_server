"""Branches in the cluster and security handlers that no other suite reaches.

Both modules sat in the seventies while the modules around them were above
ninety, and the uncovered lines were not obscure -- they were the argument
combinations that translate a friendly parameter into the one ns_server actually
accepts. Every one of them is a place where a call can be accepted, report
success, and apply nothing:

  * `dataMemoryQuota` is the readable name next to indexMemoryQuota and
    ftsMemoryQuota. ns_server calls it `memoryQuota`, and an untranslated one is
    silently never applied.
  * `/settings/alerts` is a FULL REPLACE, so a call that sets one field clears
    every other. The handler reads first and merges.
  * `alerts` and `pop_up_alerts` are comma-separated tokens, not JSON. A JSON
    array on that endpoint means "no alert types".
  * `disabledUsers` on /settings/audit is the same shape of bug, and it took the
    `auditdEnabled` in the same call down with it.
  * A role's scoping parts are positional. A trailing component may be absent; an
    INNER one cannot be skipped, or the result is a malformed `travel::orders`.

These are all decidable without a cluster: the handler either puts the right
thing on the wire or it does not. What is on the wire is what these assert.
"""

from __future__ import annotations

import json

import pytest

from handlers import cluster as cluster_mod
from handlers import security as security_mod
from handlers.shared import ERROR_MARKER


def payload(result) -> dict:
    return json.loads(result[0].text)


def is_error(result) -> bool:
    return payload(result).get(ERROR_MARKER) is True


class _Wire:
    """Records every admin_request the handler makes, and can answer GETs."""

    def __init__(self, responses=None):
        self.calls: list[tuple] = []
        self.responses = responses or {}

    def __call__(self, method="GET", path="/", data=None, **kwargs):
        self.calls.append((method, path, data))
        if (method, path) in self.responses:
            return self.responses[(method, path)]
        return {"ok": True}

    def last(self):
        return self.calls[-1]

    def sent(self):
        return self.calls[-1][2]


@pytest.fixture
def wire(monkeypatch):
    def _install(module, responses=None):
        w = _Wire(responses)
        monkeypatch.setattr(module, "admin_request", w)
        return w

    return _install


# ═══ cluster ═════════════════════════════════════════════════════════════════


def test_the_readable_quota_name_is_translated_on_the_way_out(wire):
    """`dataMemoryQuota` reads unambiguously next to indexMemoryQuota and
    ftsMemoryQuota, and ns_server has never heard of it."""
    w = wire(cluster_mod)
    cluster_mod.handle(
        "admin_cluster_memory_set", {"dataMemoryQuota": 1024, "confirm": True}
    )
    sent = w.sent()
    assert "dataMemoryQuota" not in sent
    assert sent["memoryQuota"] == "1024", (
        "form values, not JSON: ns_server's settings endpoints take strings"
    )


@pytest.mark.parametrize(
    ("tool", "method", "path"),
    [
        ("admin_node_list", "GET", "/pools/nodes"),
        ("admin_node_services_list", "GET", "/pools/default/nodeServices"),
    ],
)
def test_the_node_listings_reach_their_endpoints(wire, tool, method, path):
    w = wire(cluster_mod)
    assert not is_error(cluster_mod.handle(tool, {}))
    assert w.last()[:2] == (method, path)


def test_adding_a_node_checks_the_hostname_against_the_egress_allowlist(wire):
    """The cluster dials out to this host, and a node that joins receives replica
    data."""
    w = wire(cluster_mod)
    seen: list[str] = []
    import handlers.cluster as mod

    original = mod.assert_egress_allowed
    try:
        mod.assert_egress_allowed = lambda value, field=None, tool=None: seen.append(
            value
        )
        cluster_mod.handle(
            "admin_node_add",
            {
                "hostname": "node2.internal",
                "user": "u",
                "password": "p",
                "confirm": True,
            },
        )
    finally:
        mod.assert_egress_allowed = original

    assert seen == ["node2.internal"]
    assert w.last()[:2] == ("POST", "/controller/addNode")
    assert w.sent()["services"] == "kv", "the documented default"


def test_a_rebalance_sends_only_the_node_lists_it_was_given(wire):
    w = wire(cluster_mod)
    cluster_mod.handle(
        "admin_rebalance_start",
        {"knownNodes": "n1,n2", "ejectedNodes": "n2", "confirm": True},
    )
    assert w.sent() == {"ejectedNodes": "n2", "knownNodes": "n1,n2"}

    cluster_mod.handle("admin_rebalance_start", {"confirm": True})
    assert w.sent() == {}, "nothing supplied means nothing sent"


@pytest.mark.parametrize("given", [True, "true", 1])
def test_autofailover_booleans_reach_the_wire_as_strings(wire, given):
    """ns_server's settings endpoints take form values. A Python bool serialised
    verbatim is not one, and before refuse_undeclared these were dropped in
    silence."""
    w = wire(cluster_mod)
    cluster_mod.handle(
        "admin_autofailover_set",
        {
            "enabled": True,
            "failoverOnDataDiskIssues[enabled]": given,
            "confirm": True,
        },
    )
    assert w.sent()["failoverOnDataDiskIssues[enabled]"] == "true"


def test_an_autofailover_time_period_is_stringified(wire):
    w = wire(cluster_mod)
    cluster_mod.handle(
        "admin_autofailover_set",
        {
            "enabled": True,
            "failoverOnDataDiskIssues[timePeriod]": 120,
            "confirm": True,
        },
    )
    assert w.sent()["failoverOnDataDiskIssues[timePeriod]"] == "120"


def test_a_log_upload_host_is_checked_against_the_egress_allowlist(wire):
    wire(cluster_mod)
    import handlers.cluster as mod

    seen: list[str] = []
    original = mod.assert_egress_allowed
    try:
        mod.assert_egress_allowed = lambda value, field=None, tool=None: seen.append(
            value
        )
        cluster_mod.handle(
            "admin_logs_collect_start",
            {"uploadHost": "uploads.example.com", "ticket": "T1", "confirm": True},
        )
    finally:
        mod.assert_egress_allowed = original
    assert seen == ["uploads.example.com"]


def test_an_undeclared_argument_to_a_settings_endpoint_is_refused(wire):
    """Mass assignment on a settings endpoint is how an unrelated cluster
    parameter comes to be applied verbatim."""
    wire(cluster_mod)
    result = cluster_mod.handle(
        "admin_alerts_set", {"notARealSetting": "x", "confirm": True}
    )
    assert is_error(result)


# ── /settings/alerts is a full replace, so the handler reads first ───────────


def _alerts_wire(wire, current):
    return wire(cluster_mod, {("GET", "/settings/alerts"): current})


def test_setting_one_alert_field_preserves_the_others(wire):
    """POST /settings/alerts is a full replace. Writing one field without the
    rest clears every other -- including the recipients."""
    w = _alerts_wire(
        wire,
        {
            "enabled": True,
            "recipients": "ops@example.com",
            "sender": "cb@example.com",
            "alerts": ["auto_failover_node", "ip_address_changed"],
        },
    )
    cluster_mod.handle("admin_alerts_set", {"enabled": True, "confirm": True})
    sent = w.sent()
    assert sent["recipients"] == "ops@example.com"
    assert sent["sender"] == "cb@example.com"


def test_alert_type_lists_reach_the_wire_comma_separated_not_as_json(wire):
    """form_value JSON-encodes a list, and /settings/alerts parses these two as
    comma-separated tokens -- a JSON array is unparseable, which on this endpoint
    means "no alert types"."""
    w = _alerts_wire(wire, {"enabled": False})
    cluster_mod.handle(
        "admin_alerts_set",
        {"alerts": ["auto_failover_node", "disk_usage"], "confirm": True},
    )
    assert w.sent()["alerts"] == "auto_failover_node,disk_usage"


def test_an_existing_alert_list_is_merged_back_comma_separated(wire):
    w = _alerts_wire(wire, {"alerts": ["auto_failover_node", "disk_usage"]})
    cluster_mod.handle("admin_alerts_set", {"enabled": True, "confirm": True})
    assert w.sent()["alerts"] == "auto_failover_node,disk_usage"


def test_the_smtp_sub_document_is_flattened_back_into_parameters(wire):
    """The SMTP host/port/user live in an `emailServer` sub-document on the way
    out but are flat parameters on the way in."""
    w = _alerts_wire(
        wire,
        {
            "emailServer": {
                "host": "smtp.example.com",
                "port": 25,
                "encrypt": False,
                "user": "mailer",
            }
        },
    )
    cluster_mod.handle("admin_alerts_set", {"enabled": True, "confirm": True})
    sent = w.sent()
    assert sent["emailHost"] == "smtp.example.com"
    assert sent["emailPort"] == "25"
    assert sent["emailUser"] == "mailer"


def test_a_supplied_value_wins_over_the_one_already_on_the_cluster(wire):
    w = _alerts_wire(wire, {"recipients": "old@example.com"})
    cluster_mod.handle(
        "admin_alerts_set", {"recipients": "new@example.com", "confirm": True}
    )
    assert w.sent()["recipients"] == "new@example.com"


# ═══ security ════════════════════════════════════════════════════════════════


@pytest.mark.parametrize(
    ("roles", "expected"),
    [
        ([{"role": "admin"}], "admin"),
        ([{"role": "bucket_admin", "bucket_name": "travel"}], "bucket_admin[travel]"),
        (
            [{"role": "data_reader", "bucket_name": "travel", "scope_name": "inv"}],
            "data_reader[travel:inv]",
        ),
        (
            [
                {
                    "role": "data_reader",
                    "bucket_name": "travel",
                    "scope_name": "inv",
                    "collection_name": "airline",
                }
            ],
            "data_reader[travel:inv:airline]",
        ),
        # A wildcard bucket is the unscoped form, not a literal '*'.
        ([{"role": "data_reader", "bucket_name": "*"}], "data_reader"),
        # An INNER gap stops the encoding rather than emitting travel::orders.
        (
            [
                {
                    "role": "data_reader",
                    "bucket_name": "travel",
                    "scope_name": "",
                    "collection_name": "orders",
                }
            ],
            "data_reader[travel]",
        ),
        ([{"role": ""}, "not-a-dict", {"no": "role"}], ""),
        ([{"role": "a"}, {"role": "b"}], "a,b"),
    ],
)
def test_role_scoping_is_positional_and_stops_at_the_first_gap(roles, expected):
    assert security_mod._roles_to_form({"roles": roles}) == expected


def test_creating_a_user_in_an_external_domain_is_refused_not_quietly_localised(
    wire,
):
    """The sibling user tools all honour `domain`, which is exactly why a model
    passes it here. Accepting it created a local, password-backed account where an
    LDAP/SAML identity was requested -- reported as success."""
    wire(security_mod)
    result = security_mod.handle(
        "admin_user_create",
        {
            "username": "alice",
            "password": "p",
            "roles": "admin",
            "domain": "external",
            "confirm": True,
        },
    )
    assert is_error(result)
    assert "LOCAL users only" in payload(result)["error"]
    assert "identity provider" in payload(result)["hint"]


def test_creating_a_local_user_sends_the_optional_fields_only_when_given(wire):
    w = wire(security_mod)
    security_mod.handle(
        "admin_user_create",
        {"username": "alice", "password": "p", "roles": "admin", "confirm": True},
    )
    assert w.last()[:2] == ("PUT", "/settings/rbac/users/local/alice")
    assert set(w.sent()) == {"password", "roles"}

    security_mod.handle(
        "admin_user_create",
        {
            "username": "bob",
            "password": "p",
            "roles": "admin",
            "name": "Bob",
            "groups": "ops",
            "confirm": True,
        },
    )
    assert w.sent()["name"] == "Bob"
    assert w.sent()["groups"] == "ops"


def test_deleting_a_user_honours_the_domain(wire):
    w = wire(security_mod)
    security_mod.handle(
        "admin_user_delete",
        {"username": "alice", "domain": "external", "confirm": True},
    )
    assert w.last()[1] == "/settings/rbac/users/external/alice"


def test_an_unknown_domain_is_refused(wire):
    wire(security_mod)
    result = security_mod.handle(
        "admin_user_delete",
        {"username": "alice", "domain": "wishful", "confirm": True},
    )
    assert is_error(result)


def test_audit_exemptions_reach_the_wire_comma_separated(wire):
    """Declared as an array, `disabledUsers` reached the wire as a JSON literal,
    which ns_server rejects -- so the whole POST failed and the auditdEnabled in
    the same call was not applied either."""
    w = wire(security_mod)
    security_mod.handle(
        "admin_audit_set",
        {
            "auditdEnabled": True,
            "disabledUsers": ["alice/local", "bob/local", "  "],
            "confirm": True,
        },
    )
    sent = w.sent()
    assert sent["disabledUsers"] == "alice/local,bob/local"
    assert "[" not in sent["disabledUsers"], "a JSON array here means no exemptions"


def test_reading_the_audit_settings_hits_the_documented_endpoint(wire):
    w = wire(security_mod)
    assert not is_error(security_mod.handle("admin_audit_get", {}))
    assert w.last()[:2] == ("GET", "/settings/audit")


def test_alerts_refuses_when_the_current_settings_cannot_be_read(wire):
    """Read-modify-write means the READ is load-bearing. Merging against nothing
    would write a settings document with every unnamed field cleared, which on
    this endpoint silently drops the recipients."""
    wire(cluster_mod, {("GET", "/settings/alerts"): {}})
    result = cluster_mod.handle("admin_alerts_set", {"enabled": True, "confirm": True})
    assert is_error(result)
    assert "was not attempted" in payload(result)["error"]
    assert "REPLACE" in payload(result)["hint"].upper()
