"""handlers/encryption.py — Phase 5 deferred: DARE + KMIP.

Couchbase 8.x adds first-class Data-at-Rest Encryption (DARE) with optional
KMIP key-management integration. The cluster-level configuration is exposed
via REST endpoints under /settings/security/encryptionAtRest and
/settings/security/kmip on the cluster manager.

REST PATH ASSUMPTION
====================
The endpoints below match Couchbase 8.0 documentation. Earlier 7.x releases
had partial DARE support with a different (less stable) endpoint shape. On
clusters without DARE configured (or without the Enterprise license), the
read tools return whatever the cluster reports (typically `enabled: false`)
and the write tools return the cluster's permission error.

If a tool returns 404, the path may be different on your cluster's Couchbase
version. The handlers add a `hint` field to the error to flag this — same
pattern as the Eventing tools.

Tools (4):
  admin_encryption_get          read     current DARE configuration
  admin_encryption_set          destructive  enable/disable DARE, rotate keys
  admin_kmip_get                read     KMIP server configuration
  admin_kmip_set                destructive  configure KMIP server connection
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .egress import guard_host_like_fields
from .shared import admin_request, err, form_value, ok, schema_keys

TOOLS: list[Tool] = [
    Tool(
        name="admin_encryption_get",
        description=(
            "Get the current Data-at-Rest Encryption (DARE) configuration. "
            "Returns enabled state, encryption algorithm, key source (master "
            "key file or KMIP), and rotation status. Couchbase 7.x has partial "
            "DARE support; 8.x has first-class configuration."
        ),
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_encryption_set",
        description=(
            "Configure Data-at-Rest Encryption. Misconfiguration can render "
            "data unreadable. Requires confirm:true. Common fields: "
            "`encryptionEnabled` (bool), `keySource` (master_password | kmip), "
            "`rotateInterval` (seconds), `algorithm` (e.g. AES-256-GCM). "
            "Specific field names vary by Couchbase version — see your "
            "cluster's `/settings/security/encryptionAtRest` GET response."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "encryptionEnabled": {"type": "boolean"},
                "keySource": {
                    "type": "string",
                    "enum": ["master_password", "kmip"],
                },
                "rotateInterval": {
                    "type": "integer",
                    "description": "Key rotation interval in seconds",
                },
                "algorithm": {"type": "string"},
                "additional_fields": {
                    "type": "object",
                    "description": (
                        "Any other fields the cluster expects. Pass-through to "
                        "the REST endpoint. Useful when Couchbase adds new "
                        "options that this MCP doesn't list explicitly."
                    ),
                },
                "confirm": {"type": "boolean"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_kmip_get",
        description=(
            "Get the current KMIP (Key Management Interoperability Protocol) "
            "server configuration used to source the master encryption key. "
            "Returns hostname, port, certificate paths, and connection status."
        ),
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_kmip_set",
        description=(
            "Configure the KMIP server connection. Misconfiguration can prevent "
            "the cluster from starting after restart (the master key becomes "
            "unreachable). Requires confirm:true. Common fields: `kmipHost`, "
            "`kmipPort`, `clientCertPath`, `clientKeyPath`, `caCertPath`, "
            "`uid` (key UID on the KMIP server)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "kmipHost": {"type": "string"},
                "kmipPort": {"type": "integer"},
                "clientCertPath": {"type": "string"},
                "clientKeyPath": {"type": "string"},
                "caCertPath": {"type": "string"},
                "uid": {
                    "type": "string",
                    "description": "Key Unique Identifier on the KMIP server",
                },
                "additional_fields": {
                    "type": "object",
                    "description": "Pass-through for fields not listed here",
                },
                "confirm": {"type": "boolean"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
]


def _path_hint(msg: str) -> str | None:
    """If the error is a 404, hint at the path-assumption caveat."""
    if "404" in msg:
        return (
            "404 may indicate the encryption / KMIP REST path differs on this "
            "Couchbase version. See handlers/encryption.py module docstring."
        )
    return None


def _build_form_data(
    args: dict, exclude: set[str], *, tool_name: str = "", tools: list | None = None
) -> dict:
    """Flatten DECLARED fields plus additional_fields into one form-data dict.

    Two defects this replaces.

    Every key in ``args`` used to be forwarded, so these two security endpoints --
    /settings/security/kmip and /settings/security/encryptionAtRest -- had an
    allow-list wider than their own schemas and no refuse_undeclared, unlike every
    other settings tool in this repo. A hallucinated key became a real change to
    encryption-at-rest configuration and was reported as success. Declared keys are
    now the allow-list, and ``additional_fields`` is the single explicit escape hatch
    for a version-specific parameter -- which is what it was added for.

    And ``str(v)`` produced a Python repr for a list or dict: cipherSuites=["TLS_A",
    "TLS_B"] went on the wire as "['TLS_A', 'TLS_B']", which the cluster cannot parse
    -- and on cipherSuites an unparseable value means "use defaults", i.e. a silent
    TLS downgrade reported as success. form_value is the one encoder that gets this
    right, and it exists precisely for this.
    """
    declared = schema_keys(tool_name, tools or []) if tool_name else set()
    data = {}
    for k, v in args.items():
        if k in exclude or v is None:
            continue
        if declared and k not in declared:
            continue
        data[k] = form_value(v)
    extra = args.get("additional_fields") or {}
    for k, v in extra.items():
        if v is None:
            continue
        data[k] = form_value(v)
    return data


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        if name == "admin_encryption_get":
            return ok(admin_request("GET", "/settings/security/encryptionAtRest"))

        if name == "admin_encryption_set":
            data = _build_form_data(
                args,
                exclude={"confirm", "additional_fields"},
                tool_name=name,
                tools=TOOLS,
            )
            # This tool had NO egress guard, while admin_kmip_set — the same class of
            # operation — had one. /settings/security/encryptionAtRest also accepts
            # key-source configuration, and additional_fields is free-form, so the
            # master-encryption-key source could be redirected through this tool
            # while the guard on the neighbouring one looked like the control was
            # covered.
            guard_host_like_fields(data, tool=name)
            return ok(
                admin_request("POST", "/settings/security/encryptionAtRest", data=data)
            )

        if name == "admin_kmip_get":
            return ok(admin_request("GET", "/settings/security/kmip"))

        if name == "admin_kmip_set":
            # Build the payload FIRST, then guard what is actually being sent.
            #
            # Checking args["kmipHost"] let `additional_fields={"kmipHost": ...}`
            # walk straight past the guard: the key was absent from args, so no check
            # ran, and _build_form_data then merged it into the request verbatim.
            # additional_fields is an allow-list escape hatch by construction, so any
            # guard has to run on the merged result, not the declared arguments.
            data = _build_form_data(
                args,
                exclude={"confirm", "additional_fields"},
                tool_name=name,
                tools=TOOLS,
            )
            # kmipHost decides where the cluster fetches its MASTER ENCRYPTION KEY.
            # Pointed elsewhere, the cluster cannot decrypt its own data after a
            # restart.
            #
            # This was a two-spelling denylist (`kmipHost`, `kmiphost`), so
            # `KmipHost` in additional_fields walked past it. Guarding by key shape
            # covers every casing and every other host-bearing field the endpoint
            # accepts.
            guard_host_like_fields(data, tool=name)
            return ok(admin_request("POST", "/settings/security/kmip", data=data))

        return err(f"Unknown encryption tool: {name}", tool=name)

    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc}"
        hint = _path_hint(str(exc))
        if hint:
            return err(msg, tool=name, args=args, hint=hint)
        return err(msg, tool=name, args=args)
