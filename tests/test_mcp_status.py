"""
The introspection tools — cb_mcp_status, cb_mcp_list_tools, cb_mcp_get_tool_info.

WHY THESE MATTER MORE THAN THEY LOOK
====================================
Three reasons this module is worth real tests rather than a smoke check:

1. It is where twelve of the nineteen `mcp_compat` conversions live. If the read-only and
   destructive flags are read wrongly, this module reports the wrong safety posture — and
   an operator asking "is this server in read-only mode?" is asking precisely because they
   are about to trust the answer.

2. It reports configuration, which means it is a deliberate disclosure surface. Writing
   these tests found that `cb_mcp_status` returned CB_CONNECTION_STRING verbatim, so a
   password in the URI's userinfo went to any caller with a read-only token.

3. Every tool here is annotated read-only, so all three load in the safest deployment and
   under a read-only token. There is no gate in front of them.
"""

from __future__ import annotations

import json

import pytest
from mcp.types import Tool, ToolAnnotations

from handlers import mcp_status


def _payload(result) -> dict:
    """The JSON body of a handler response."""
    assert len(result) == 1
    return json.loads(result[0].text)


def _tool(name, *, read_only=False, destructive=False, idempotent=False, schema=None):
    return Tool(
        name=name,
        description=f"{name} description",
        inputSchema=schema or {"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=read_only,
            destructiveHint=destructive,
            idempotentHint=idempotent,
        ),
    )


READ_TOOL = _tool("cb_read_thing", read_only=True, idempotent=True)
WRITE_TOOL = _tool("cb_write_thing")
DESTRUCTIVE_TOOL = _tool("cb_drop_thing", destructive=True)
UNANNOTATED_TOOL = Tool(
    name="cb_unannotated", description="d", inputSchema={"type": "object"}
)


@pytest.fixture
def fake_server(monkeypatch):
    """Stand in for the `server` module that `handle()` imports lazily.

    A stub rather than the real module because the real one's tool list depends on profile,
    read-only mode and CB_ADMIN_DISABLED_TOOLS — so assertions against it would be really
    assertions about the current default configuration, and would move whenever a tool was
    added.
    """
    import sys
    import types

    module = types.ModuleType("server")
    module._RAW_TOOLS = [READ_TOOL, WRITE_TOOL, DESTRUCTIVE_TOOL, UNANNOTATED_TOOL]
    module._TOOLS = [READ_TOOL, WRITE_TOOL, DESTRUCTIVE_TOOL]
    module._CONFIRMATION_REQUIRED = {"cb_drop_thing"}

    real = sys.modules.get("server")
    sys.modules["server"] = module
    yield module
    if real is not None:
        sys.modules["server"] = real
    else:
        sys.modules.pop("server", None)


# ── The connection string must not carry a password out (the defect) ─────────


def test_a_password_in_the_connection_string_is_not_returned(fake_server, monkeypatch):
    """THE DEFECT. `redact()` masks by key name, and `connection_string` contains no
    credential-looking word, so the whole URI went out verbatim from a read-only tool."""
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbases://admin:sup3rs3cret@cb.host")
    body = _payload(mcp_status.handle("cb_mcp_status", {}))
    assert "sup3rs3cret" not in json.dumps(body)


def test_the_username_and_host_are_still_reported(fake_server, monkeypatch):
    """Masking the whole URI would be safe and useless. "Which account is this server
    using, against which cluster?" is the reason to read this field at all."""
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbases://admin:sup3rs3cret@cb.host")
    reported = _payload(mcp_status.handle("cb_mcp_status", {}))["connection"][
        "connection_string"
    ]
    assert "admin" in reported
    assert "cb.host" in reported
    assert "couchbases://" in reported


def test_a_connection_string_without_credentials_is_untouched(fake_server, monkeypatch):
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://node1,node2?kv_timeout=5s")
    assert (
        _payload(mcp_status.handle("cb_mcp_status", {}))["connection"][
            "connection_string"
        ]
        == "couchbase://node1,node2?kv_timeout=5s"
    )


def test_no_credential_paths_or_passwords_appear_anywhere_in_the_status(
    fake_server, monkeypatch
):
    """A sweep rather than a field-by-field check, so a field added later is covered by
    default instead of being covered only if someone remembers to extend a test."""
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbases://admin:pw-in-uri@cb.host")
    monkeypatch.setenv("CB_PASSWORD", "pw-in-env")
    monkeypatch.setenv("CB_USERNAME", "admin")
    monkeypatch.setenv("CB_CLIENT_KEY_PATH", "/secrets/client-key-path.pem")
    monkeypatch.setenv("CB_CLIENT_CERT_PATH", "/secrets/client-cert-path.pem")
    monkeypatch.setenv("CB_CA_CERT_PATH", "/secrets/ca-path.pem")

    text = json.dumps(_payload(mcp_status.handle("cb_mcp_status", {})))
    for leaked in (
        "pw-in-uri",
        "pw-in-env",
        "client-key-path",
        "client-cert-path",
        "ca-path",
    ):
        assert leaked not in text, f"{leaked!r} reached the status payload"


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (
            "couchbases://admin:sup3r@cb.host",
            "couchbases://admin:***REDACTED***@cb.host",
        ),
        # A raw "@" in the password. RFC 3986 says percent-encode it; people paste it
        # anyway. Matching only to the FIRST "@" left the tail of the password in clear.
        (
            "couchbases://admin:p@ssword@cb.host",
            "couchbases://admin:***REDACTED***@cb.host",
        ),
        # Reaches logs far more often than the status payload does.
        (
            "failed to connect to couchbase://admin:pw@h:11210 after 3 tries",
            "failed to connect to couchbase://admin:***REDACTED***@h:11210 after 3 tries",
        ),
        # Nothing to mask — these must survive byte for byte, or an agent reading a
        # config value and writing it back would corrupt it.
        (
            "couchbase://node1,node2?kv_timeout=5s",
            "couchbase://node1,node2?kv_timeout=5s",
        ),
        ("couchbase://user@host", "couchbase://user@host"),
        ("http://host:8080/path", "http://host:8080/path"),
        # An "@" after the authority is not userinfo.
        (
            "https://api.example.com/v4/x?filter=a@b.com",
            "https://api.example.com/v4/x?filter=a@b.com",
        ),
        ("http://host:8080/a@b", "http://host:8080/a@b"),
        ("no uri here at all", "no uri here at all"),
        ("", ""),
    ],
)
def test_uri_credential_masking(given, expected):
    from handlers.shared import redact_uri_credentials

    assert redact_uri_credentials(given) == expected


def test_the_rule_also_applies_to_free_text_error_messages():
    """Connection strings appear in exception text constantly, and that path goes to both
    the response and the audit log."""
    from handlers.shared import redact_text

    assert "pw" not in redact_text("dsn = couchbase://admin:pw@h")


def test_the_auth_method_is_named_without_revealing_the_credential(
    fake_server, monkeypatch
):
    monkeypatch.setenv("CB_CLIENT_CERT_PATH", "/secrets/c.pem")
    monkeypatch.setenv("CB_CLIENT_KEY_PATH", "/secrets/k.pem")
    body = _payload(mcp_status.handle("cb_mcp_status", {}))
    assert body["connection"]["auth_method"] == "mTLS (client certificate)"


def test_password_auth_is_reported_when_only_a_username_and_password_are_set(
    fake_server, monkeypatch
):
    for key in ("CB_CLIENT_CERT_PATH", "CB_CLIENT_KEY_PATH"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CB_USERNAME", "admin")
    monkeypatch.setenv("CB_PASSWORD", "pw")
    body = _payload(mcp_status.handle("cb_mcp_status", {}))
    assert body["connection"]["auth_method"] == "Password (username/password)"


def test_missing_credentials_are_reported_rather_than_guessed(fake_server, monkeypatch):
    for key in (
        "CB_CLIENT_CERT_PATH",
        "CB_CLIENT_KEY_PATH",
        "CB_USERNAME",
        "CB_PASSWORD",
    ):
        monkeypatch.delenv(key, raising=False)
    body = _payload(mcp_status.handle("cb_mcp_status", {}))
    assert body["connection"]["auth_method"] == "Not configured"


def test_a_half_configured_client_certificate_is_not_reported_as_mtls(
    fake_server, monkeypatch
):
    """Cert without key cannot authenticate. Reporting mTLS would send someone debugging a
    connection failure in exactly the wrong direction."""
    monkeypatch.setenv("CB_CLIENT_CERT_PATH", "/secrets/c.pem")
    monkeypatch.delenv("CB_CLIENT_KEY_PATH", raising=False)
    monkeypatch.setenv("CB_USERNAME", "admin")
    monkeypatch.setenv("CB_PASSWORD", "pw")
    body = _payload(mcp_status.handle("cb_mcp_status", {}))
    assert body["connection"]["auth_method"] == "Password (username/password)"
    assert body["connection"]["tls"]["client_cert_configured"] is False


def test_tls_verification_being_disabled_is_reported(fake_server, monkeypatch):
    """An operator who believes TLS is verified when it is not has no way to find out
    except by asking this tool."""
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbases://cb.host")
    monkeypatch.setenv("CB_ADMIN_TLS_INSECURE", "true")
    tls = _payload(mcp_status.handle("cb_mcp_status", {}))["connection"]["tls"]
    assert tls["tls_enabled"] is True
    assert tls["tls_verify_disabled"] is True


def test_plain_couchbase_is_not_reported_as_tls_enabled(fake_server, monkeypatch):
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://cb.host")
    monkeypatch.delenv("CB_ADMIN_TLS_INSECURE", raising=False)
    tls = _payload(mcp_status.handle("cb_mcp_status", {}))["connection"]["tls"]
    assert tls["tls_enabled"] is False
    assert tls["tls_verify_disabled"] is False


# ── Tool counts and categories come from the compat accessors ───────────────


def test_tool_counts_by_category_are_correct(fake_server):
    """These come from `mcp_compat.is_read_only` / `is_destructive`. If those read the
    wrong field name every tool counts as a write, and the reported posture is wrong."""
    tools = _payload(mcp_status.handle("cb_mcp_status", {}))["tools"]
    assert tools["by_category"] == {"read": 1, "write": 2, "destructive": 1}


def test_filtered_out_tools_are_reported(fake_server):
    """The whole point of the tool: "why is admin_bucket_delete missing?"."""
    tools = _payload(mcp_status.handle("cb_mcp_status", {}))["tools"]
    assert tools["registered"] == 4
    assert tools["loaded"] == 3
    assert tools["filtered_out"] == 1


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        ("read", ["cb_read_thing"]),
        ("write", ["cb_write_thing"]),
        ("destructive", ["cb_drop_thing"]),
        ("all", ["cb_read_thing", "cb_write_thing", "cb_drop_thing"]),
    ],
)
def test_list_tools_filters_by_category(fake_server, category, expected):
    body = _payload(mcp_status.handle("cb_mcp_list_tools", {"category": category}))
    assert [row["name"] for row in body["tools"]] == expected
    assert body["count"] == len(expected)
    assert body["filter"] == category


def test_list_tools_defaults_to_all(fake_server):
    body = _payload(mcp_status.handle("cb_mcp_list_tools", {}))
    assert body["count"] == 3


def test_a_destructive_tool_is_categorised_destructive_not_write(fake_server):
    """`_category_of` checks destructive BEFORE read-only, so the ordering is load-bearing:
    a destructive tool must never be reported as an ordinary write."""
    assert mcp_status._category_of(DESTRUCTIVE_TOOL) == "destructive"


def test_an_unannotated_tool_is_treated_as_a_write(fake_server):
    """Absent annotations must fail towards caution. Defaulting to "read" would let an
    unannotated tool appear in the read-only catalog."""
    assert mcp_status._category_of(UNANNOTATED_TOOL) == "write"


def test_every_row_reports_all_three_annotation_flags(fake_server):
    row = next(
        r
        for r in _payload(mcp_status.handle("cb_mcp_list_tools", {}))["tools"]
        if r["name"] == "cb_read_thing"
    )
    assert row == {
        "name": "cb_read_thing",
        "category": "read",
        "read_only": True,
        "destructive": False,
        "idempotent": True,
    }


def test_list_tools_reports_loaded_tools_not_registered_ones(fake_server):
    """A filtered-out tool appearing here would tell an operator a tool is available when
    calling it will be refused."""
    names = [
        r["name"] for r in _payload(mcp_status.handle("cb_mcp_list_tools", {}))["tools"]
    ]
    assert "cb_unannotated" not in names


# ── Single-tool info ─────────────────────────────────────────────────────────


def test_tool_info_returns_the_schema_and_annotations(fake_server):
    body = _payload(
        mcp_status.handle("cb_mcp_get_tool_info", {"tool_name": "cb_drop_thing"})
    )
    assert body["name"] == "cb_drop_thing"
    assert body["input_schema"] == {"type": "object", "properties": {}}
    assert body["annotations"] == {
        "read_only": False,
        "destructive": True,
        "idempotent": False,
    }


def test_tool_info_works_for_a_registered_but_filtered_out_tool(fake_server):
    """The diagnostic case this tool exists for. Looking up a tool that is NOT loaded has to
    work, and has to say so — otherwise "no such tool" is indistinguishable from
    "filtered out by read-only mode"."""
    body = _payload(
        mcp_status.handle("cb_mcp_get_tool_info", {"tool_name": "cb_unannotated"})
    )
    assert body["currently_loaded"] is False


def test_tool_info_marks_a_loaded_tool_as_loaded(fake_server):
    body = _payload(
        mcp_status.handle("cb_mcp_get_tool_info", {"tool_name": "cb_read_thing"})
    )
    assert body["currently_loaded"] is True


def test_tool_info_for_an_unknown_tool_is_an_error_with_a_hint(fake_server):
    from handlers.shared import ERROR_MARKER

    body = _payload(
        mcp_status.handle("cb_mcp_get_tool_info", {"tool_name": "cb_no_such_tool"})
    )
    assert body[ERROR_MARKER] is True
    assert "cb_no_such_tool" in body["error"]
    assert "cb_mcp_list_tools" in body["hint"]


def test_tool_info_without_a_tool_name_is_an_error_not_a_crash(fake_server):
    """`args["tool_name"]` raises KeyError; the handler's except turns it into a response.
    A raise here would propagate as a transport-level failure instead of something the
    model can read and correct."""
    from handlers.shared import ERROR_MARKER

    body = _payload(mcp_status.handle("cb_mcp_get_tool_info", {}))
    assert body[ERROR_MARKER] is True
    assert "KeyError" in body["error"]


def test_an_unknown_tool_name_is_refused(fake_server):
    from handlers.shared import ERROR_MARKER

    body = _payload(mcp_status.handle("cb_mcp_not_a_tool", {}))
    assert body[ERROR_MARKER] is True


def test_a_malformed_port_becomes_an_error_response(fake_server, monkeypatch):
    """`int(CB_ADMIN_PORT)` raises. Reaching the model as a readable error beats a
    traceback out of the transport."""
    from handlers.shared import ERROR_MARKER

    monkeypatch.setenv("CB_ADMIN_PORT", "not-a-port")
    body = _payload(mcp_status.handle("cb_mcp_status", {}))
    assert body[ERROR_MARKER] is True


# ── The module's own declarations ────────────────────────────────────────────


def test_every_tool_here_is_annotated_read_only():
    """The module docstring promises it, and these tools answer from in-process state with
    no cluster call. An accidental write annotation would drop them from the read-only
    catalog and break introspection in the safest deployment."""
    import mcp_compat

    for tool in mcp_status.TOOLS:
        assert mcp_compat.is_read_only(tool) is True, tool.name
        assert mcp_compat.is_destructive(tool) is False, tool.name


def test_every_declared_tool_is_actually_handled(fake_server):
    """A tool advertised in TOOLS but missing from `handle()` falls through to
    "Unknown mcp_status tool" — discoverable only by calling it."""
    from handlers.shared import ERROR_MARKER

    for tool in mcp_status.TOOLS:
        args = {"tool_name": "cb_read_thing"} if "tool_info" in tool.name else {}
        body = _payload(mcp_status.handle(tool.name, args))
        assert "Unknown mcp_status tool" not in str(body.get("error", "")), tool.name
        assert body.get(ERROR_MARKER) is not True, tool.name


def test_every_tool_schema_is_valid_json_schema():
    import jsonschema

    import mcp_compat

    for tool in mcp_status.TOOLS:
        jsonschema.Draft7Validator.check_schema(mcp_compat.input_schema(tool))
