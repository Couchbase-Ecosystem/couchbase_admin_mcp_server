"""handlers/security.py — Users, groups, roles, RBAC, audit, certs, password policy.

Changes from upstream:
- Phase 1: ToolAnnotations. User/group deletes, password changes, and
  security-settings writes marked destructive.
- Phase 2: Structured err() returns.
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .shared import (
    admin_request,
    err,
    form_data,
    form_data_declared,
    ok,
    quote_path,
    refuse_undeclared,
)

#: Keys /settings/audit accepts. `auditdEnabled=false` disables cluster auditing
#: outright, so this list is the difference between a reviewable change and silent
#: anti-forensics.
#: Every key here is also declared in admin_audit_set's schema. Keeping the two in
#: step matters: a key that is allow-listed but undeclared is reachable through the
#: console while being invisible to a model reading the schema, which is how
#: `disabled` -- selective audit suppression -- became settable without being
#: documented. `uid` is deliberately absent: it is server-generated, not settable.
_AUDIT_SETTINGS_KEYS: frozenset[str] = frozenset(
    {
        "auditdEnabled",
        "logPath",
        "rotateInterval",
        "rotateSize",
        "disabledUsers",
        "disabled",
        "enabledEvents",
    }
)

#: Keys /settings/security accepts. This endpoint governs TLS posture and UI
#: exposure, so it is the last place mass assignment is acceptable: forwarding
#: every caller-supplied key let a model set fields nobody reviewed — an
#: unparseable cipherSuites value, for instance, means "use the defaults", which
#: is a silent TLS downgrade.
_SECURITY_SETTINGS_KEYS: frozenset[str] = frozenset(
    {
        "clusterEncryptionLevel",
        "disableUIOverHttp",
        "disableUIOverHttps",
        "tlsMinVersion",
        "cipherSuites",
        "honorCipherOrder",
        "hstsMaxAge",
        "hstsIncludeSubDomains",
        "hstsPreload",
        "responseHeaders",
        "allowNonLocalCACertUpload",
    }
)

TOOLS: list[Tool] = [
    # ── Users ────────────────────────────────────────────────────────────
    Tool(
        name="admin_user_list",
        description="List all local or external users.",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "enum": ["local", "external"],
                    "description": "Default: local",
                }
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_user_get",
        description="Get details for a specific user.",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "enum": ["local", "external"]},
                "username": {"type": "string"},
            },
            "required": ["username"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_user_create",
        description=(
            "Create or update a local user. roles is a comma-separated string, "
            "e.g. 'admin' or 'bucket_admin[travel-sample]'."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "password": {"type": "string"},
                "name": {"type": "string", "description": "Display name"},
                "roles": {
                    "type": "string",
                    "description": "Comma-separated role list",
                },
                "groups": {
                    "type": "string",
                    "description": "Comma-separated group list",
                },
            },
            "required": ["username", "password", "roles"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_user_delete",
        description="Delete a local or external user. IRREVERSIBLE. Requires confirm:true.",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "enum": ["local", "external"]},
                "username": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["username"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_user_change_password",
        description="Change the password for a local user. Requires confirm:true.",
        inputSchema={
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "password": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["username", "password"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    # ── Groups ───────────────────────────────────────────────────────────
    Tool(
        name="admin_group_list",
        description="List all user groups.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_group_get",
        description="Get details for a specific user group.",
        inputSchema={
            "type": "object",
            "properties": {"group_name": {"type": "string"}},
            "required": ["group_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_group_create",
        description="Create or update a user group.",
        inputSchema={
            "type": "object",
            "properties": {
                "group_name": {"type": "string"},
                "description": {"type": "string"},
                "roles": {"type": "string"},
                "ldap_group_ref": {"type": "string"},
            },
            "required": ["group_name", "roles"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_group_delete",
        description="Delete a user group. IRREVERSIBLE. Requires confirm:true.",
        inputSchema={
            "type": "object",
            "properties": {
                "group_name": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["group_name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    # ── Roles ────────────────────────────────────────────────────────────
    Tool(
        name="admin_role_list",
        description="List all available RBAC roles in the cluster.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    # ── Who am I ─────────────────────────────────────────────────────────
    Tool(
        name="admin_whoami",
        description="Return the identity and roles of the currently authenticated user.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    # ── Audit ────────────────────────────────────────────────────────────
    Tool(
        name="admin_audit_get",
        description="Retrieve current audit configuration.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_audit_set",
        description="Configure audit settings (enabled, log_path, rotate_interval, etc.).",
        inputSchema={
            "type": "object",
            "properties": {
                "auditdEnabled": {"type": "boolean"},
                "logPath": {"type": "string"},
                "rotateInterval": {
                    "type": "integer",
                    "description": "Rotation interval in seconds",
                },
                "rotateSize": {
                    "type": "integer",
                    "description": "Max log size in bytes",
                },
                "disabledUsers": {
                    "type": "string",
                    "description": (
                        "Comma-separated user/domain tokens exempted from auditing, "
                        "e.g. 'svc/local,@eventing/local'. A list is accepted and "
                        "joined, because /settings/audit parses commas, not JSON."
                    ),
                },
                # DECLARED, not merely allow-listed. These three were in the
                # allow-list and absent from this schema, so the model could not
                # discover them while the console path could still send them -- and
                # `disabled` selectively switches OFF audit events, which is the
                # first thing someone does after acting destructively. A
                # security-relevant parameter that is reachable must be visible.
                "disabled": {
                    "type": "string",
                    "description": (
                        "Comma-separated audit EVENT IDs to disable, e.g. "
                        "'8243,8255'. Disabling events removes them from the "
                        "cluster's forensic record -- state why in correlation_id."
                    ),
                },
                "enabledEvents": {
                    "type": "string",
                    "description": "Comma-separated audit event IDs to enable.",
                },
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    # ── Password policy ───────────────────────────────────────────────────
    Tool(
        name="admin_password_policy_get",
        description="Retrieve the current password policy.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_password_policy_set",
        description=(
            "Set password policy (minLength, enforceUppercase, enforceLowercase, "
            "enforceDigits, enforceSpecialChars)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "minLength": {"type": "integer"},
                "enforceUppercase": {"type": "boolean"},
                "enforceLowercase": {"type": "boolean"},
                "enforceDigits": {"type": "boolean"},
                "enforceSpecialChars": {"type": "boolean"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
        ),
    ),
    # ── Security settings ─────────────────────────────────────────────────
    Tool(
        name="admin_security_settings_get",
        description="Get global security / TLS settings.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
        ),
    ),
    Tool(
        name="admin_security_settings_set",
        description=(
            "Update global security settings (tlsMinVersion, honorCipherOrder, "
            "cipherSuites, etc.). Changes can lock you out of the cluster if "
            "misconfigured. Requires confirm:true."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "tlsMinVersion": {
                    "type": "string",
                    "enum": ["tlsv1", "tlsv1.1", "tlsv1.2", "tlsv1.3"],
                },
                "honorCipherOrder": {"type": "boolean"},
                "cipherSuites": {"type": "array", "items": {"type": "string"}},
                # DECLARED rather than only allow-listed, for the same reason as
                # admin_audit_set: these were reachable through the console while
                # invisible to a model, and two of them can cut off every client or
                # the admin UI. Reachable and dangerous must mean documented.
                "clusterEncryptionLevel": {
                    "type": "string",
                    "enum": ["control", "all", "strict"],
                    "description": (
                        "Node-to-node encryption level. 'strict' disables all "
                        "non-TLS ports and can cut off clients that are not "
                        "configured for TLS. Verify client readiness first."
                    ),
                },
                "disableUIOverHttp": {
                    "type": "boolean",
                    "description": "Disable the admin UI on the plain HTTP port.",
                },
                "disableUIOverHttps": {
                    "type": "boolean",
                    "description": (
                        "Disable the admin UI on the HTTPS port. Setting both "
                        "disableUIOverHttp and this locks the UI out entirely."
                    ),
                },
                "allowNonLocalCACertUpload": {"type": "boolean"},
                "hstsMaxAge": {"type": "integer"},
                "hstsIncludeSubDomains": {"type": "boolean"},
                "hstsPreload": {"type": "boolean"},
                "responseHeaders": {
                    "type": "string",
                    "description": "JSON object of extra HTTP response headers.",
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


def _roles_to_form(user: dict) -> str:
    """Re-encode a GET's `roles` array into the comma-separated form a PUT expects.

    ns_server ANSWERS with objects
      [{"role": "bucket_admin", "bucket_name": "travel", "scope_name": "inventory"}]
    but ACCEPTS the compact spelling
      bucket_admin[travel:inventory]
    so a role list read back from a GET cannot be posted verbatim. Needed because
    changing a password is a read-modify-write: the roles have to be written back or
    the PUT clears them.
    """
    encoded: list[str] = []
    for entry in user.get("roles") or []:
        if not isinstance(entry, dict):
            continue
        role = str(entry.get("role") or "").strip()
        if not role:
            continue
        # Only the scoping parts, in ns_server's positional order. A trailing
        # component may be absent; an INNER one cannot be skipped, so stop at the
        # first gap rather than emitting a malformed [travel::orders].
        parts: list[str] = []
        for key in ("bucket_name", "scope_name", "collection_name"):
            value = entry.get(key)
            if value in (None, "", "*") and key == "bucket_name":
                break
            if value in (None, ""):
                break
            parts.append(str(value))
        encoded.append(f"{role}[{':'.join(parts)}]" if parts else role)
    return ",".join(encoded)


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        # Validate domain against allowed values — defense-in-depth, since schema
        # enums are advisory and not server-enforced.
        raw_domain = args.get("domain", "local")
        if raw_domain not in ("local", "external"):
            return err(
                f"Invalid domain {raw_domain!r}; must be 'local' or 'external'.",
                tool=name,
            )
        domain = raw_domain  # safe to interpolate; validated against allow-list

        if name == "admin_user_list":
            return ok(admin_request("GET", f"/settings/rbac/users/{domain}"))

        if name == "admin_user_get":
            u = quote_path(args["username"])
            return ok(admin_request("GET", f"/settings/rbac/users/{domain}/{u}"))

        if name == "admin_user_create":
            # `domain` is validated at the top of handle() and was then IGNORED here,
            # with the path hardcoded to /local/. So admin_user_create(domain="external")
            # passed validation and created a local, password-backed account where an
            # LDAP/SAML identity was requested -- reported as success. The sibling user
            # tools all honour `domain`, which is exactly why a model passes it here.
            if raw_domain != "local":
                return err(
                    f"admin_user_create creates LOCAL users only; domain={raw_domain!r} "
                    "is not supported by this tool.",
                    tool=name,
                    hint=(
                        "An external (LDAP/SAML) identity has no password for this "
                        "server to set, so creating one is a different operation. "
                        "Create it in the identity provider, then grant roles with "
                        "admin_user_roles_set, or omit `domain` to create a local user."
                    ),
                )
            u = quote_path(args["username"])
            data = {"password": args["password"], "roles": args["roles"]}
            if args.get("name"):
                data["name"] = args["name"]
            if args.get("groups"):
                data["groups"] = args["groups"]
            return ok(
                admin_request("PUT", f"/settings/rbac/users/local/{u}", data=data)
            )

        if name == "admin_user_delete":
            u = quote_path(args["username"])
            return ok(admin_request("DELETE", f"/settings/rbac/users/{domain}/{u}"))

        if name == "admin_user_change_password":
            # /controller/changePassword changes the password of the AUTHENTICATED
            # user and has no `username` parameter at all. Posting one there did not
            # change the named user: it rotated the credential this server itself
            # authenticates with (CB_USERNAME, typically Administrator), locking the
            # MCP server -- and every other consumer of that credential -- out on the
            # next call, while reporting success. On builds that reject unknown
            # parameters it 400s instead, i.e. the tool never worked either way.
            #
            # The original comment was right that a bare PUT wipes roles, so the fix
            # is read-modify-write: GET the user, then PUT the new password back
            # alongside the roles and groups it already had.
            u = quote_path(args["username"])
            current = admin_request("GET", f"/settings/rbac/users/{domain}/{u}")
            if not isinstance(current, dict):
                return err(
                    f"Could not read user {args['username']!r} before changing the "
                    "password, so the change was not attempted.",
                    tool=name,
                    hint=(
                        "The password must be written back together with the user's "
                        "existing roles, or the PUT would clear them. Confirm the "
                        "user exists with admin_user_get."
                    ),
                )
            data = {"password": args["password"], "roles": _roles_to_form(current)}
            groups = current.get("groups")
            if groups:
                data["groups"] = ",".join(str(g) for g in groups)
            if current.get("name"):
                data["name"] = current["name"]
            return ok(
                admin_request("PUT", f"/settings/rbac/users/{domain}/{u}", data=data)
            )

        if name == "admin_group_list":
            return ok(admin_request("GET", "/settings/rbac/groups"))

        if name == "admin_group_get":
            g = quote_path(args["group_name"])
            return ok(admin_request("GET", f"/settings/rbac/groups/{g}"))

        if name == "admin_group_create":
            g = quote_path(args["group_name"])
            data = {"roles": args["roles"]}
            if args.get("description"):
                data["description"] = args["description"]
            if args.get("ldap_group_ref"):
                data["ldap_group_ref"] = args["ldap_group_ref"]
            return ok(admin_request("PUT", f"/settings/rbac/groups/{g}", data=data))

        if name == "admin_group_delete":
            g = quote_path(args["group_name"])
            return ok(admin_request("DELETE", f"/settings/rbac/groups/{g}"))

        if name == "admin_role_list":
            return ok(admin_request("GET", "/settings/rbac/roles"))

        if name == "admin_whoami":
            return ok(admin_request("GET", "/whoami"))

        if name == "admin_audit_get":
            return ok(admin_request("GET", "/settings/audit"))

        if name == "admin_audit_set":
            # /settings/audit parses `disabledUsers` as comma-separated
            # `user/domain` tokens. Declared as an array, it reached the wire as a
            # JSON literal, which ns_server rejects -- so the whole POST failed and
            # the auditdEnabled in the same call was not applied either. Where a
            # build tolerates the token, the exemption silently never matched.
            if isinstance(args.get("disabledUsers"), (list, tuple)):
                args = dict(args)
                args["disabledUsers"] = ",".join(
                    str(u) for u in args["disabledUsers"] if str(u).strip()
                )
            # Key allow-list, fail closed. This was the ONE settings endpoint left
            # with full mass assignment — and it configures the cluster's own audit
            # log, which is the first thing someone disables after doing something
            # destructive. Every neighbouring endpoint got an allow-list; this one
            # needed it most.
            unknown = sorted(
                k for k in args if k not in _AUDIT_SETTINGS_KEYS and k != "confirm"
            )
            if unknown:
                return err(
                    f"Unrecognised audit setting(s): {unknown}.",
                    tool=name,
                    hint=(
                        "This endpoint controls the cluster's audit log. Only known "
                        f"keys are forwarded. Permitted: {sorted(_AUDIT_SETTINGS_KEYS)}."
                    ),
                )
            data = form_data(
                {k: v for k, v in args.items() if k in _AUDIT_SETTINGS_KEYS}
            )
            return ok(admin_request("POST", "/settings/audit", data=data))

        if name == "admin_password_policy_get":
            return ok(admin_request("GET", "/settings/passwordPolicy"))

        if name == "admin_password_policy_set":
            refusal = refuse_undeclared(
                args, name, TOOLS, endpoint="/settings/passwordPolicy"
            )
            if refusal is not None:
                return refusal
            data = form_data_declared(args, name, TOOLS)
            return ok(admin_request("POST", "/settings/passwordPolicy", data=data))

        if name == "admin_security_settings_get":
            return ok(admin_request("GET", "/settings/security"))

        if name == "admin_security_settings_set":
            unknown = sorted(
                k for k in args if k not in _SECURITY_SETTINGS_KEYS and k != "confirm"
            )
            if unknown:
                return err(
                    f"Unrecognised setting(s) for /settings/security: {unknown}.",
                    tool=name,
                    hint=(
                        "This endpoint controls TLS posture and UI exposure, so "
                        "only known keys are forwarded. Permitted: "
                        f"{sorted(_SECURITY_SETTINGS_KEYS)}."
                    ),
                )
            data = form_data(
                {k: v for k, v in args.items() if k in _SECURITY_SETTINGS_KEYS}
            )
            return ok(admin_request("POST", "/settings/security", data=data))

        return err(f"Unknown security tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
