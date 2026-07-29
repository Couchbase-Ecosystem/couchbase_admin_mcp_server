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

from .shared import admin_request, err, ok

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


def _build_form_data(args: dict, exclude: set[str]) -> dict:
    """Flatten explicit fields + additional_fields into a single form-data dict.
    Convert booleans to 'true'/'false' for form encoding."""
    data = {}
    for k, v in args.items():
        if k in exclude or v is None:
            continue
        if isinstance(v, bool):
            data[k] = "true" if v else "false"
        else:
            data[k] = str(v)
    extra = args.get("additional_fields") or {}
    for k, v in extra.items():
        if v is None:
            continue
        if isinstance(v, bool):
            data[k] = "true" if v else "false"
        else:
            data[k] = str(v)
    return data


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        if name == "admin_encryption_get":
            return ok(admin_request("GET", "/settings/security/encryptionAtRest"))

        if name == "admin_encryption_set":
            data = _build_form_data(args, exclude={"confirm", "additional_fields"})
            return ok(
                admin_request("POST", "/settings/security/encryptionAtRest", data=data)
            )

        if name == "admin_kmip_get":
            return ok(admin_request("GET", "/settings/security/kmip"))

        if name == "admin_kmip_set":
            data = _build_form_data(args, exclude={"confirm", "additional_fields"})
            return ok(admin_request("POST", "/settings/security/kmip", data=data))

        return err(f"Unknown encryption tool: {name}", tool=name)

    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc}"
        hint = _path_hint(str(exc))
        if hint:
            return err(msg, tool=name, args=args, hint=hint)
        return err(msg, tool=name, args=args)
