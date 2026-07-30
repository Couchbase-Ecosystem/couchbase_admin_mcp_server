"""
The rest of `handlers/shared.py`: SDK connection, env parsing, DDL guards, form encoding.

The HTTP client is in `test_shared_http.py`. This covers the surface around it, and two parts
of it carry real consequences rather than just uncovered lines:

  * `get_sdk_connection` chooses between mTLS and password authentication. Picking password
    when certificates are configured sends a credential that the operator believes they have
    stopped using.
  * `form_value` encodes values for the ns_server REST API. Python's `str(True)` is `"True"`,
    which that API does not accept — and on `/settings/security` an unparseable `cipherSuites`
    means "use the defaults", i.e. a silent TLS downgrade rather than an error.
"""

from __future__ import annotations

import json
import sys
import types
from typing import ClassVar

import pytest

from handlers import shared

# ── The Couchbase SDK connection ─────────────────────────────────────────────
#
# `couchbase` is a declared dependency but a C extension, frequently absent from a test
# environment — which is why these 48 lines had never run. The stub below records what the
# handler asked for; nothing here asserts anything about the SDK's own behaviour.


class _FakeAuthenticator:
    def __init__(self, kind, **kwargs):
        self.kind = kind
        self.kwargs = kwargs


class _FakeCluster:
    instances: ClassVar[list] = []

    def __init__(self, connection_string, options):
        self.connection_string = connection_string
        self.options = options
        self.ready_timeout = None
        _FakeCluster.instances.append(self)

    def wait_until_ready(self, timeout):
        self.ready_timeout = timeout

    def bucket(self, name):
        return _FakeBucket(name)


class _FakeBucket:
    def __init__(self, name):
        self.name = name

    def scope(self, scope_name):
        return _FakeScope(scope_name)


class _FakeScope:
    def __init__(self, name):
        self.name = name

    def collection(self, collection_name):
        return f"{self.name}.{collection_name}"


class _FakeOptions:
    def __init__(self, authenticator):
        self.authenticator = authenticator
        self.profile = None

    def apply_profile(self, name):
        self.profile = name


@pytest.fixture
def sdk(monkeypatch):
    """A stubbed `couchbase` package, and `shared`'s connection cache cleared."""
    package = types.ModuleType("couchbase")
    auth_module = types.ModuleType("couchbase.auth")
    cluster_module = types.ModuleType("couchbase.cluster")
    options_module = types.ModuleType("couchbase.options")

    auth_module.CertificateAuthenticator = lambda **kw: _FakeAuthenticator("cert", **kw)
    auth_module.PasswordAuthenticator = lambda *a, **kw: _FakeAuthenticator(
        "password", args=a, **kw
    )
    cluster_module.Cluster = _FakeCluster
    options_module.ClusterOptions = _FakeOptions

    for name, module in (
        ("couchbase", package),
        ("couchbase.auth", auth_module),
        ("couchbase.cluster", cluster_module),
        ("couchbase.options", options_module),
    ):
        monkeypatch.setitem(sys.modules, name, module)

    _FakeCluster.instances.clear()
    monkeypatch.setattr(shared, "_cluster", None, raising=False)
    monkeypatch.setattr(shared, "_bucket", None, raising=False)
    monkeypatch.setattr(shared, "_collection", None, raising=False)

    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://cb.example.com")
    monkeypatch.setenv("CB_USERNAME", "Administrator")
    monkeypatch.setenv("CB_PASSWORD", "password")
    for key in ("CB_CLIENT_CERT_PATH", "CB_CLIENT_KEY_PATH", "CB_CA_CERT_PATH"):
        monkeypatch.delenv(key, raising=False)
    for key in ("CB_BUCKET", "CB_SCOPE", "CB_COLLECTION"):
        monkeypatch.delenv(key, raising=False)
    return shared


def test_a_connection_is_established_and_waited_for(sdk):
    """`wait_until_ready` is what turns a wrong connection string into an error here rather
    than a confusing timeout inside the first query."""
    cluster, bucket, collection = sdk.get_sdk_connection()
    assert cluster.connection_string == "couchbase://cb.example.com"
    assert cluster.ready_timeout is not None
    assert bucket.name == "default"
    assert collection == "_default._default"


def test_the_connection_is_cached(sdk):
    """A fresh Cluster per call would open a new connection pool for every tool invocation."""
    first, _, _ = sdk.get_sdk_connection()
    second, _, _ = sdk.get_sdk_connection()
    assert first is second
    assert len(_FakeCluster.instances) == 1


def test_password_authentication_is_used_by_default(sdk):
    cluster, _, _ = sdk.get_sdk_connection()
    assert cluster.options.authenticator.kind == "password"


def test_client_certificates_select_mtls(sdk, monkeypatch):
    """THE consequence. With certificates configured the operator believes authentication
    happens at the TLS layer; falling back to a password would send a credential they think
    is no longer in use."""
    monkeypatch.setenv("CB_CLIENT_CERT_PATH", "/certs/client.pem")
    monkeypatch.setenv("CB_CLIENT_KEY_PATH", "/certs/client.key")

    cluster, _, _ = sdk.get_sdk_connection()
    authenticator = cluster.options.authenticator
    assert authenticator.kind == "cert"
    assert authenticator.kwargs["cert_path"] == "/certs/client.pem"
    assert authenticator.kwargs["key_path"] == "/certs/client.key"
    # And no password anywhere in what was handed to the SDK.
    assert "password" not in json.dumps(authenticator.kwargs, default=str)


def test_a_half_configured_certificate_pair_falls_back_to_a_password(sdk, monkeypatch):
    """A cert with no key cannot authenticate. Choosing mTLS anyway would fail with a TLS
    handshake error rather than working with the credentials that are configured."""
    monkeypatch.setenv("CB_CLIENT_CERT_PATH", "/certs/client.pem")
    monkeypatch.delenv("CB_CLIENT_KEY_PATH", raising=False)

    cluster, _, _ = sdk.get_sdk_connection()
    assert cluster.options.authenticator.kind == "password"


def test_a_custom_ca_is_passed_through_on_both_auth_paths(sdk, monkeypatch):
    """A private CA is the normal enterprise case, and it applies regardless of how the
    client authenticates."""
    monkeypatch.setenv("CB_CA_CERT_PATH", "/certs/ca.pem")

    cluster, _, _ = sdk.get_sdk_connection()
    assert cluster.options.authenticator.kwargs["cert_path"] == "/certs/ca.pem"

    monkeypatch.setattr(shared, "_cluster", None)
    monkeypatch.setenv("CB_CLIENT_CERT_PATH", "/certs/c.pem")
    monkeypatch.setenv("CB_CLIENT_KEY_PATH", "/certs/k.pem")
    cluster, _, _ = sdk.get_sdk_connection()
    assert cluster.options.authenticator.kwargs["trust_store_path"] == "/certs/ca.pem"


def test_the_wan_profile_is_applied(sdk):
    """Capella is remote by definition. Without the relaxed timeouts, ordinary latency looks
    like an unavailable cluster."""
    cluster, _, _ = sdk.get_sdk_connection()
    assert cluster.options.profile == "wan_development"


def test_the_configured_keyspace_is_used(sdk, monkeypatch):
    monkeypatch.setenv("CB_BUCKET", "travel-sample")
    monkeypatch.setenv("CB_SCOPE", "inventory")
    monkeypatch.setenv("CB_COLLECTION", "airline")

    _cluster, bucket, collection = sdk.get_sdk_connection()
    assert bucket.name == "travel-sample"
    assert collection == "inventory.airline"


def test_missing_credentials_are_reported_by_name(sdk, monkeypatch):
    """`get_env` raises for a required variable. A silent default would connect as the wrong
    principal, or anonymously."""
    monkeypatch.delenv("CB_PASSWORD", raising=False)
    with pytest.raises(RuntimeError, match="CB_PASSWORD"):
        sdk.get_sdk_connection()


def test_a_missing_sdk_says_what_to_install(monkeypatch):
    """`couchbase` is a C extension, so a slim image is exactly how it goes missing. The
    error has to name the package rather than surfacing a bare ImportError."""
    monkeypatch.setattr(shared, "_cluster", None, raising=False)

    class _Blocker:
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] == "couchbase":
                raise ModuleNotFoundError(fullname)

    for name in [n for n in list(sys.modules) if n.split(".")[0] == "couchbase"]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setattr(sys, "meta_path", [_Blocker(), *sys.meta_path])

    with pytest.raises(RuntimeError, match="couchbase"):
        shared.get_sdk_connection()


# ── Environment parsing ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value", ["1", "true", "TRUE", "yes", "on", "y", "t", " True "]
)
def test_every_accepted_spelling_of_true(monkeypatch, value):
    """One notion of truth, because five call sites accepted "on" and one did not — which
    made CB_ADMIN_HTTP_REQUIRE_AUTH=on stop the edge middleware rejecting a missing token
    while the scope check still denied. Tool calls failed closed, but the handshake and
    list_tools succeeded unauthenticated, disclosing the whole admin surface."""
    monkeypatch.setenv("CB_TEST_FLAG", value)
    assert shared.env_truthy("CB_TEST_FLAG") is True
    assert shared.get_env_bool("CB_TEST_FLAG", False) is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "n", "f", "maybe", "2"])
def test_anything_else_is_false(monkeypatch, value):
    """Fail closed: an unrecognised value must not enable a control the operator did not
    ask for. Note "off" and "2" are simply not true rather than errors."""
    monkeypatch.setenv("CB_TEST_FLAG", value)
    assert shared.env_truthy("CB_TEST_FLAG", default=True) is False


def test_an_unset_or_empty_flag_takes_the_default(monkeypatch):
    """Docker Compose passes `KEY=` for an unset variable, so empty must mean unset."""
    monkeypatch.delenv("CB_TEST_FLAG", raising=False)
    assert shared.env_truthy("CB_TEST_FLAG", default=True) is True
    monkeypatch.setenv("CB_TEST_FLAG", "")
    assert shared.env_truthy("CB_TEST_FLAG", default=True) is True
    assert shared.get_env_bool("CB_TEST_FLAG", True) is True


@pytest.mark.parametrize(
    ("value", "expected"),
    [("42", 42), ("", 7), ("not-a-number", 7), ("  13  ", 13), ("-1", -1)],
)
def test_integer_parsing_falls_back_rather_than_raising(monkeypatch, value, expected):
    """These are read at import. A ValueError here would stop the server starting because
    of a typo in a tuning knob."""
    monkeypatch.setenv("CB_TEST_INT", value)
    assert shared.get_env_int("CB_TEST_INT", 7) == expected


def test_an_unset_integer_takes_the_default(monkeypatch):
    monkeypatch.delenv("CB_TEST_INT", raising=False)
    assert shared.get_env_int("CB_TEST_INT", 7) == 7


# ── Tool lists: inline or from a file ────────────────────────────────────────


def test_a_tool_list_can_be_given_inline(monkeypatch):
    assert shared._parse_tool_list("a, b ,c") == {"a", "b", "c"}


def test_an_empty_tool_list_is_empty_not_a_set_containing_nothing_useful():
    assert shared._parse_tool_list("") == set()
    assert shared._parse_tool_list(None) == set()
    assert shared._parse_tool_list(",,, ,") == set()


def test_a_tool_list_can_be_a_file(tmp_path):
    """A deployment disabling forty tools cannot put them in an environment variable
    readably, and a file is reviewable in version control."""
    listing = tmp_path / "disabled.txt"
    listing.write_text(
        "# tools we do not allow\nadmin_bucket_delete\n\nadmin_cluster_failover\n   \n"
    )
    assert shared._parse_tool_list(str(listing)) == {
        "admin_bucket_delete",
        "admin_cluster_failover",
    }


def test_comments_and_blank_lines_in_a_tool_list_file_are_ignored(tmp_path):
    """Without this a `#` comment becomes a tool name that matches nothing, so the operator
    believes a tool is disabled when it is not."""
    listing = tmp_path / "d.txt"
    listing.write_text("#comment\n# another\nadmin_x\n")
    assert shared._parse_tool_list(str(listing)) == {"admin_x"}


def test_a_path_that_does_not_exist_is_treated_as_an_inline_name(tmp_path):
    """A typo'd path must not silently disable nothing. It becomes a name that matches no
    tool, which `test_disabled_tools_must_exist` elsewhere is what catches."""
    assert shared._parse_tool_list("/no/such/file.txt") == {"/no/such/file.txt"}


# ── Index DDL guards ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "statement",
    [
        "CREATE INDEX ix1 ON `b`(x)",
        "create primary index on `b`",
        "BUILD INDEX ON `b`(ix1)",
        "CREATE VECTOR INDEX v1 ON `b`(vec VECTOR)",
        "CREATE HYPERSCALE VECTOR INDEX v1 ON `b`(vec VECTOR)",
        "CREATE COMPOSITE VECTOR INDEX v1 ON `b`(a, vec VECTOR)",
    ],
)
def test_real_index_ddl_is_accepted(statement):
    assert shared.assert_index_create_ddl(statement) is None


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT * FROM `b`",
        "DELETE FROM `b` WHERE 1=1",
        "UPDATE `b` SET x = 1",
        "INSERT INTO `b` VALUES ('k', {})",
        "DROP BUCKET `b`",
        "CREATE SCOPE `b`.s",
        "GRANT ROLE admin TO u",
    ],
)
def test_arbitrary_sql_is_refused_by_the_index_create_guard(statement):
    """`admin_index_create` takes a raw statement. Without this guard it is an
    execute-anything tool wearing an index-shaped name — and it is annotated as a write
    rather than as destructive."""
    error = shared.assert_index_create_ddl(statement)
    assert error is not None
    assert "index DDL" in error


def test_a_chained_statement_is_refused_by_the_ddl_guard():
    """The bypass that makes the pattern match worthless: a legitimate CREATE INDEX followed
    by anything at all."""
    error = shared.assert_index_create_ddl("CREATE INDEX ix ON `b`(x); DROP BUCKET `b`")
    assert error is not None
    assert "chaining" in error


def test_a_commented_statement_is_refused_by_the_ddl_guard():
    """A trailing comment silently discards part of what was reviewed."""
    error = shared.assert_index_create_ddl(
        "CREATE INDEX ix ON `b`(x) -- WITH {'nodes':[]}"
    )
    assert error is not None
    assert "comments" in error


@pytest.mark.parametrize(
    "statement",
    ["DROP INDEX `b`.ix", "drop primary index on `b`", "DROP VECTOR INDEX v1 ON `b`"],
)
def test_real_drop_ddl_is_accepted(statement):
    assert shared.assert_index_drop_ddl(statement) is None


@pytest.mark.parametrize(
    "statement", ["DROP BUCKET `b`", "DROP SCOPE `b`.s", "DELETE FROM `b`", "SELECT 1"]
)
def test_the_drop_guard_refuses_anything_but_an_index_drop(statement):
    assert shared.assert_index_drop_ddl(statement) is not None


def test_an_unterminated_quote_is_refused_rather_than_guessed(monkeypatch):
    """The parser could not read the statement, so the chaining and comment checks cannot be
    applied to it. Forwarding a statement this server was unable to parse would mean the
    guards silently did not run."""
    error = shared.assert_single_statement("CREATE INDEX ix ON `b`(x) WITH {'a: 1}")
    assert error is not None
    assert "Unterminated" in error


def test_semicolons_and_comment_markers_inside_literals_are_fine():
    """Over-refusing is its own failure: a legitimate index with a `--` in a string literal
    would become impossible to create."""
    assert (
        shared.assert_single_statement(
            "CREATE INDEX ix ON `b`(x) WITH {'note':'a;b--c'}"
        )
        is None
    )


# ── The confirmation gate ────────────────────────────────────────────────────


def test_a_tool_outside_the_confirmation_set_passes_straight_through():
    assert shared.require_confirmation("admin_bucket_list", {}, False) is None


def test_a_confirmation_tool_without_the_flag_is_refused():
    error = shared.require_confirmation("admin_bucket_delete", {}, True)
    assert error is not None
    assert "admin_bucket_delete" in error


def test_confirmation_must_be_the_boolean_true():
    """The string "true" arriving from a JSON-ish client must not satisfy a destructive
    gate — that is a type coercion deciding whether data is deleted."""
    for value in ("true", "yes", 1, "confirm"):
        assert shared.require_confirmation(
            "admin_bucket_delete", {"confirm": value}, True
        )


def test_confirmation_with_the_flag_proceeds():
    assert (
        shared.require_confirmation("admin_bucket_delete", {"confirm": True}, True)
        is None
    )


# ── Form encoding ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, "true"), (False, "false"), (1, "1"), (2.5, "2.5"), ("x", "x")],
)
def test_booleans_are_encoded_the_way_ns_server_expects(value, expected):
    """Python's `str(True)` is "True", which the management API does not accept."""
    assert shared.form_value(value) == expected


@pytest.mark.parametrize("value", [["a", "b"], ("a", "b"), {"a": 1}])
def test_collections_are_encoded_as_json_not_a_python_repr(value):
    """A Python repr uses single quotes, which the cluster cannot parse. On
    `/settings/security` an unparseable `cipherSuites` means "use the defaults" — a SILENT
    TLS DOWNGRADE rather than an error — and on audit `disabledUsers` it means the
    exemption never applies."""
    encoded = shared.form_value(value)
    assert "'" not in encoded
    assert json.loads(encoded) == (list(value) if isinstance(value, tuple) else value)


def test_a_path_segment_cannot_escape_itself():
    """A bucket name containing a slash would otherwise address a different resource
    entirely rather than failing."""
    assert shared.quote_path("a/b") == "a%2Fb"
    assert shared.quote_path("../../admin") == "..%2F..%2Fadmin"


def test_a_normal_path_segment_survives_unchanged():
    assert shared.quote_path("travel-sample") == "travel-sample"


# ── Schema keys ──────────────────────────────────────────────────────────────


def test_schema_keys_reads_the_declared_properties():
    from mcp.types import Tool

    tools = [
        Tool(
            name="admin_thing",
            description="d",
            inputSchema={"type": "object", "properties": {"a": {}, "b": {}}},
        )
    ]
    assert shared.schema_keys("admin_thing", tools) == frozenset({"a", "b"})


def test_schema_keys_for_an_unknown_tool_is_empty():
    """Empty rather than raising, because `refuse_undeclared` then refuses everything for
    that tool — fail closed, not open."""
    assert shared.schema_keys("no_such_tool", []) == frozenset()


# ── Read-only mode default ───────────────────────────────────────────────────


def test_read_only_mode_defaults_to_on():
    """The default posture: an operator who sets nothing gets a server that cannot change
    their cluster.

    Asserted on `get_env_bool`'s default argument as the module uses it, NOT by reloading
    `handlers.shared`. Reloading it rebinds the module object that fourteen handlers, the
    console and `server.py` all imported names from — which broke an unrelated test in
    another file, and only in a full-suite run. The reload was more dangerous than the line
    it covered.
    """
    import inspect

    source = inspect.getsource(shared)
    assert (
        'READ_ONLY_MODE: bool = get_env_bool("CB_ADMIN_READ_ONLY_MODE", True)' in source
    ), "read-only mode no longer defaults to on"
    # And the parser it relies on genuinely returns the default when unset.
    import os

    snapshot = os.environ.pop("CB_ADMIN_READ_ONLY_MODE", None)
    try:
        assert shared.get_env_bool("CB_ADMIN_READ_ONLY_MODE", True) is True
    finally:
        if snapshot is not None:
            os.environ["CB_ADMIN_READ_ONLY_MODE"] = snapshot


# ── The required-variable marker survives a module reload ────────────────────


def test_a_missing_required_variable_raises_rather_than_returning_a_sentinel(
    monkeypatch,
):
    monkeypatch.delenv("CB_TEST_REQUIRED", raising=False)
    with pytest.raises(RuntimeError, match="CB_TEST_REQUIRED"):
        shared.get_env("CB_TEST_REQUIRED")


def test_the_required_marker_still_works_after_the_module_is_reloaded(monkeypatch):
    """THE BUG this pins.

    `_REQUIRED = object()` with an `is` check compares a default bound at DEFINITION time
    against the CURRENT module global. Reload the module and they are two different objects,
    the identity check fails, and `get_env` returns THE SENTINEL rather than raising.

    That is the worst failure available to this function: a missing credential comes back as a
    truthy object and is passed onward. It showed up as
    `handlers.capella.client._secret()` returning `<object object at 0x...>` for an unset
    CAPELLA_API_KEY_SECRET — which would have been sent as a Bearer token.

    Found because another test reloads `handlers.shared`, so the failure was real and already
    reachable in this suite rather than hypothetical.
    """
    import importlib
    import sys

    monkeypatch.delenv("CB_TEST_REQUIRED", raising=False)

    # Reload WHATEVER is currently registered under the name, not the object this file
    # imported at collection time. `importlib.reload` requires
    # `sys.modules[m.__name__] is m`, and the console's OAuth fixture pops
    # `handlers.shared` to force a fresh import — so by the time this runs, the registered
    # module can be a different object, or absent entirely. Depending on which was true made
    # this fail only in a full-suite run.
    registered = sys.modules.get("handlers.shared", shared)
    monkeypatch.setitem(sys.modules, "handlers.shared", registered)

    # The PRE-reload function object. This is the reference that actually breaks, and the one
    # every handler holds: `from .shared import get_env` binds the function, so a later reload
    # leaves fourteen modules calling this object while the module global it compares against
    # has been replaced. Asserting only on the reloaded module's own `get_env` would pass
    # either way — that version of this test let the identity-check mutation survive.
    before_reload = registered.get_env

    importlib.reload(registered)

    with pytest.raises(RuntimeError, match="CB_TEST_REQUIRED"):
        before_reload("CB_TEST_REQUIRED")

    # And a required variable that IS set must still come back rather than raise.
    monkeypatch.setenv("CB_TEST_REQUIRED", "value")
    assert before_reload("CB_TEST_REQUIRED") == "value"


def test_an_explicit_default_is_not_mistaken_for_the_required_marker(monkeypatch):
    """Guards the fix from over-reaching: a real default must still be returned."""
    monkeypatch.delenv("CB_TEST_OPTIONAL", raising=False)
    assert shared.get_env("CB_TEST_OPTIONAL", "fallback") == "fallback"
    assert shared.get_env("CB_TEST_OPTIONAL", None) is None
    assert shared.get_env("CB_TEST_OPTIONAL", "") == ""
