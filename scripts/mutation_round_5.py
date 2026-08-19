"""Mutation-check the session-cookie fixes and the mcp version-compat accessors.

Same contract as rounds 1-4: break one guard, run the suite that is supposed to notice, and
report anything that stays green. A guard whose deletion nothing detects is decoration.

These cover the three defects found by writing tests for `auth/session.py`, which had 0%
coverage, plus `mcp_compat.py`, which was written to survive the mcp 2.x field renaming and
would otherwise be tested only by the version that is not installed.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile


class MutationTimeoutError(RuntimeError):
    """A mutation run that neither passed nor failed. Never counted as caught."""


ROOT = pathlib.Path(__file__).resolve().parent.parent
SESSION = "tests/test_session.py"
COMPAT = "tests/test_mcp_compat.py"
STATUS = "tests/test_mcp_status.py"
CONTRACT = "tests/test_handler_contract.py"
CAPELLA = "tests/test_capella.py tests/test_verify_capella_paths.py"
TOKEN = "tests/test_token_validation.py"
SHARED = "tests/test_shared_http.py tests/test_shared_helpers.py"
GUI_OAUTH = "tests/test_gui_oauth_routes.py"
GUI_AUTHZ = "tests/test_gui_authorization.py"
SQLB = "tests/test_sql_builders.py"
DISPATCH = "tests/test_server_dispatch.py"
PLAN = "tests/test_plan_analysis.py"
INFRA = "tests/test_logging_and_client.py"
EDGE = "tests/test_transport_edge.py"
AUDITP = "tests/test_audit_and_profile.py"
ENVREC = "tests/test_env_reconciler.py"

MUTATIONS = [
    # ── Defect 1: the Secure flag behind a TLS-terminating proxy ────────────
    (
        "session cookie: Secure decided from the request scheme again",
        "gui/gui_server.py",
        "        secure=_session.cookie_is_secure(),",
        "        secure=request.is_secure,",
        SESSION,
    ),
    (
        "session cookie: external TLS termination no longer implies Secure",
        "auth/session.py",
        "    if settings.cert_file or settings.terminated_externally:",
        "    if settings.cert_file:",
        SESSION,
    ),
    (
        "session cookie: Secure dropped entirely",
        "auth/session.py",
        # Anchor updated: the code it pointed at was edited during the security pass.
        "    if settings.cert_file or settings.terminated_externally:\n"
        "        return True",
        "    if False:\n        return True",
        SESSION,
    ),
    (
        "session cookie: Secure always on, breaking http://127.0.0.1 login",
        "auth/session.py",
        # Anchor updated: the code it pointed at was edited during the security pass.
        "    # Loopback development over http://. Secure here would stop the browser sending the\n"
        "    # cookie back to http://127.0.0.1 and break local login outright.\n"
        "    return False",
        "    return True",
        SESSION,
    ),
    # ── Defect 2: OAUTH_SESSION_SECRET unchecked at startup ─────────────────
    (
        "startup: a missing session signing secret is no longer fatal",
        "auth/session.py",
        '    if not os.environ.get("OAUTH_SESSION_SECRET", "").strip():',
        "    if False:",
        SESSION,
    ),
    (
        "startup: the session check is never called by the console",
        "gui/gui_server.py",
        "        problems.extend(_session_mod.validate_startup())",
        "        _session_mod.validate_startup()",
        SESSION,
    ),
    (
        "startup: a whitespace-only secret passes",
        "auth/session.py",
        '    if not os.environ.get("OAUTH_SESSION_SECRET", "").strip():',
        '    if os.environ.get("OAUTH_SESSION_SECRET") is None:',
        SESSION,
    ),
    # ── Defect 3: one source of truth for the lifetime ──────────────────────
    (
        "cookie lifetime: diverges from the server-side session lifetime",
        "auth/session.py",
        "def cookie_max_age() -> int:",
        "def cookie_max_age(_unused: int = 0) -> int:\n    return 28800\n\n\ndef _dead_cookie_max_age() -> int:",
        SESSION,
    ),
    (
        "startup: an unparseable TTL is accepted",
        "auth/session.py",
        "        except (ValueError, TypeError):\n            errors.append(",
        "        except (ValueError, TypeError):\n            pass\n        if False:\n            errors.append(",
        SESSION,
    ),
    (
        "startup: a zero TTL that locks everyone out is accepted",
        "auth/session.py",
        "            if ttl <= 0:",
        "            if ttl < 0:",
        SESSION,
    ),
    # ── Session integrity, which had no tests at all ────────────────────────
    (
        "session: cookie signature no longer verified",
        "auth/session.py",
        "    if not hmac.compare_digest(expected, provided):\n        return None",
        "    if False:\n        return None",
        SESSION,
    ),
    (
        "session: expiry no longer checked on read",
        "auth/session.py",
        '    if time.time() - entry["created"] > _session_ttl():',
        "    if False:",
        SESSION,
    ),
    (
        "session: an unset signing secret signs with an empty key",
        "auth/session.py",
        "    if not secret:\n        raise RuntimeError(",
        "    if False:\n        raise RuntimeError(",
        SESSION,
    ),
    (
        "session: update accepts a forged cookie",
        "auth/session.py",
        "    if session_id is None or session_id not in _store:\n        return False",
        "    if session_id is None and session_id not in _store:\n        return False",
        SESSION,
    ),
    (
        "session: expired sessions are never purged",
        "auth/session.py",
        '    stale = [sid for sid, entry in _store.items() if now - entry["created"] > ttl]',
        "    stale = []",
        SESSION,
    ),
    # ── mcp 2.x compatibility ───────────────────────────────────────────────
    (
        "mcp_compat: only the 1.x schema spelling is tried",
        "mcp_compat.py",
        '    schema = _first_attr(tool, "inputSchema", "input_schema")',
        '    schema = _first_attr(tool, "inputSchema")',
        COMPAT,
    ),
    (
        "mcp_compat: an unreadable schema becomes {} instead of raising",
        "mcp_compat.py",
        '    schema = _first_attr(tool, "inputSchema", "input_schema")',
        '    schema = _first_attr(tool, "inputSchema", "input_schema", default=None)',
        COMPAT,
    ),
    (
        "mcp_compat: the camelCase-to-snake derivation is broken",
        "mcp_compat.py",
        '    snake = "".join(f"_{ch.lower()}" if ch.isupper() else ch for ch in name)',
        "    snake = name.lower()",
        COMPAT,
    ),
    (
        "mcp_compat: only the 2.x annotation spelling is tried",
        "mcp_compat.py",
        "    return bool(_first_attr(annotations, name, snake, default=False))",
        "    return bool(_first_attr(annotations, snake, default=False))",
        COMPAT,
    ),
    (
        "mcp_compat: a write tool reports itself read-only",
        "mcp_compat.py",
        '    return annotation(tool, "readOnlyHint")',
        "    return True",
        COMPAT,
    ),
    (
        "mcp_compat: destructive tools stop reporting as destructive",
        "mcp_compat.py",
        '    return annotation(tool, "destructiveHint")',
        "    return False",
        COMPAT,
    ),
    # The scan that stops a twentieth direct field read appearing. The mutation has to be a
    # real direct read, not just any edit at the call site — an undefined name would be a
    # NameError caught by whatever tests mcp_status, which is a different guard.
    (
        "mcp_compat: a direct .readOnlyHint read is reintroduced at a call site",
        "handlers/mcp_status.py",
        "    if mcp_compat.is_read_only(t):",
        "    if t.annotations.readOnlyHint:",
        COMPAT,
    ),
    (
        "mcp_compat: a direct .inputSchema read is reintroduced at a call site",
        "handlers/mcp_status.py",
        # Anchor updated: the code it pointed at was edited during the security pass.
        '        "read": _categories.count("read"),',
        '        "read": sum(1 for t in loaded_tools if t.inputSchema),',
        COMPAT,
    ),
    # ── The connection-string password disclosure ───────────────────────────
    #
    # WITHDRAWN, and the reason matters more than the entry did.
    #
    # This slot used to remove `redact_uri_credentials` from cb_mcp_status's
    # connection_string field, and round 5 reported "no test caught it". Writing a test
    # for it showed why: nothing catches it because it is no longer a defect. redact()
    # gained content masking on every string LEAF during the security pass, and that path
    # runs redact_text -> redact_uri_credentials, so the password is masked whether or not
    # mcp_status asks for it. The mutated build returns
    # `couchbases://admin:***REDACTED***@cb.example.com` -- the same output as the
    # unmutated one.
    #
    # Deleting one of two layers that both hold is not a mutation, and a test written to
    # "catch" it would have had to assert on the layer rather than the behaviour. The
    # property itself IS still enforced by mutation: the entry immediately below breaks
    # redact_uri_credentials at the source, which takes out BOTH layers at once, and it is
    # caught. tests/test_unguarded_controls.py::
    # test_status_never_reports_the_connection_string_verbatim asserts the observable
    # behaviour alongside it.
    (
        "redaction: URI userinfo masking is a no-op",
        "handlers/shared.py",
        "    return _URI_CREDENTIAL_RE.sub(",
        "    return text or _URI_CREDENTIAL_RE.sub(",
        STATUS,
    ),
    (
        "redaction: a raw @ in the password truncates the mask",
        "handlers/shared.py",
        r'    r":(?P<password>[^/?#\s]*)"',
        r'    r":(?P<password>[^/?#@\s]*)"',
        STATUS,
    ),
    (
        "redaction: the mask swallows the host as well as the password",
        "handlers/shared.py",
        "        lambda m: f\"{m.group('scheme')}{m.group('user')}:{REDACTED}\", text",
        "        lambda m: REDACTED, text",
        STATUS,
    ),
    (
        "redaction: error messages no longer get the URI pass",
        "handlers/shared.py",
        "    text = redact_uri_credentials(text)",
        "    pass",
        STATUS,
    ),
    # ── mcp_status reads the right safety flags ─────────────────────────────
    (
        "status: destructive tools are categorised as ordinary writes",
        "handlers/mcp_status.py",
        '    if mcp_compat.is_destructive(t):\n        return "destructive"',
        '    if False:\n        return "destructive"',
        STATUS,
    ),
    (
        "status: an unannotated tool is reported as read-only",
        "handlers/mcp_status.py",
        '    if not t.annotations:\n        return "write"',
        '    if not t.annotations:\n        return "read"',
        STATUS,
    ),
    (
        "status: list_tools reports registered tools instead of loaded ones",
        "handlers/mcp_status.py",
        '            loaded_tools = getattr(server_module, "_TOOLS", [])\n            rows = []',
        '            loaded_tools = getattr(server_module, "_RAW_TOOLS", [])\n            rows = []',
        STATUS,
    ),
    (
        "status: a half-configured client certificate is reported as mTLS",
        "handlers/mcp_status.py",
        "    if cert and key:",
        "    if cert or key:",
        STATUS,
    ),
    (
        "status: disabled TLS verification is reported as verified",
        "handlers/mcp_status.py",
        '        "tls_verify_disabled": insecure,',
        '        "tls_verify_disabled": False,',
        STATUS,
    ),
    # ── The cross-handler contract harness ──────────────────────────────────
    (
        "contract: a declared tool loses its route in handle()",
        "handlers/buckets.py",
        '        if name == "admin_bucket_list":',
        '        if name == "admin_bucket_list_RENAMED":',
        CONTRACT,
    ),
    (
        "contract: a tool is annotated both read-only and destructive",
        "handlers/mcp_status.py",
        "        annotations=ToolAnnotations(\n"
        "            readOnlyHint=True,\n"
        "            destructiveHint=False,\n"
        "            idempotentHint=True,\n"
        "        ),",
        "        annotations=ToolAnnotations(\n"
        "            readOnlyHint=True,\n"
        "            destructiveHint=True,\n"
        "            idempotentHint=True,\n"
        "        ),",
        CONTRACT,
    ),
    (
        "contract: two handler groups declare the same tool name",
        "handlers/collections.py",
        "TOOLS: list[Tool] = [",
        'TOOLS: list[Tool] = [\n    Tool(\n        name="admin_bucket_list",\n'
        '        description="a shadowing duplicate",\n'
        '        inputSchema={"type": "object", "properties": {}},\n'
        "        annotations=ToolAnnotations(readOnlyHint=True),\n    ),",
        CONTRACT,
    ),
    (
        "contract: a schema requires a property it never defines",
        "handlers/backup.py",
        "        inputSchema={",
        '        inputSchema={\n            "required": ["undefined_property"],',
        CONTRACT,
    ),
    (
        "contract: the SDK import escapes handle() uncaught again",
        "handlers/diagnostics.py",
        "    try:\n        # Inside the try.",
        "    from couchbase.options import QueryOptions as _Early\n\n    try:\n        # Inside the try.",
        CONTRACT,
    ),
    # Mutating the harness itself: proves the anti-vacuity guard works. If the fixture goes
    # back to refusing the SDK seam, the three SQL++ modules stop being exercised at all —
    # which is the state this file was in when it was first written and passing.
    (
        "contract: the fixture short-circuits the SQL++ handlers again",
        "tests/test_handler_contract.py",
        "    def _fake_sdk_connection():\n        return cluster, object(), object()",
        "    def _fake_sdk_connection():\n        raise AssertionError('no cluster')",
        CONTRACT,
    ),
    # ── The App Service node count, found by a live 422 ─────────────────────
    (
        "capella: env_create asks for a single App Service node again",
        "handlers/capella/environment.py",
        '                "nodes": MIN_APP_SERVICE_NODES,',
        '                "nodes": 1,',
        CAPELLA,
    ),
    (
        "capella: the node floor drops below what Capella accepts",
        "handlers/capella/spec.py",
        "MIN_APP_SERVICE_NODES = 2",
        "MIN_APP_SERVICE_NODES = 1",
        CAPELLA,
    ),
    (
        "capella: the tool description tells the model 1 node is fine",
        "handlers/capella/spec.py",
        '            f"Node count. Capella requires {MIN_APP_SERVICE_NODES}-"',
        '            f"Node count. 1 suffices for testing. {MIN_APP_SERVICE_NODES}-"',
        CAPELLA,
    ),
    (
        "capella: the verifier's node count drifts from the spec",
        "scripts/verify_capella_paths.py",
        "_MIN_APP_SERVICE_NODES = 2",
        "_MIN_APP_SERVICE_NODES = 1",
        CAPELLA,
    ),
    # ── The false all-clear from --only-pat ─────────────────────────────────
    (
        "capella: the inferred-path selector goes back to the closed literal",
        "scripts/verify_capella_paths.py",
        '    return "[PAT" in (getattr(op, "summary", "") or "")',
        '    return "[PAT]" in (getattr(op, "summary", "") or "")',
        CAPELLA,
    ),
    (
        "capella: --only-pat re-inlines its own copy of the test",
        "scripts/verify_capella_paths.py",
        "        ops = [o for o in ops if _is_inferred(o)]",
        '        ops = [o for o in ops if "[PAT]" in (o.summary or "")]',
        CAPELLA,
    ),
    (
        "capella: the selector matches everything, making --only-pat the full sweep",
        "scripts/verify_capella_paths.py",
        '    return "[PAT" in (getattr(op, "summary", "") or "")',
        "    return True",
        CAPELLA,
    ),
    (
        "capella: an unverified inferred path reappears in the spec",
        "handlers/capella/spec.py",
        'summary="List collections in a scope. [LIVE+METHOD 200]",',
        'summary="List collections in a scope. [PAT — sibling of the scopes path]",',
        CAPELLA,
    ),
    # ── The child-object bootstrap ──────────────────────────────────────────
    (
        "capella: an allowlist entry on a real private range instead of TEST-NET",
        "scripts/verify_capella_paths.py",
        '_DOC_CIDR_CLUSTER = "192.0.2.10/32"',
        '_DOC_CIDR_CLUSTER = "10.0.0.10/32"',
        CAPELLA,
    ),
    (
        "capella: an allowlist entry open to the whole internet",
        "scripts/verify_capella_paths.py",
        '_DOC_CIDR_APP_SERVICE = "192.0.2.11/32"',
        '_DOC_CIDR_APP_SERVICE = "0.0.0.0/0"',
        CAPELLA,
    ),
    (
        "capella: allowlist entries no longer self-expire",
        "scripts/verify_capella_paths.py",
        '            "expiresAt": expires,\n        },\n    )\n    if cidr_id:',
        "        },\n    )\n    if cidr_id:",
        CAPELLA,
    ),
    (
        "capella: the two allowlist ids collapse into one",
        "scripts/verify_capella_paths.py",
        '        overrides["capella_app_service_allowed_cidr_delete"] = {\n'
        '            "allowed_cidr_id": as_cidr_id\n'
        "        }",
        '        ids["allowed_cidr_id"] = as_cidr_id',
        CAPELLA,
    ),
    (
        "capella: per-op overrides are ignored, so one route probes the wrong object",
        "scripts/verify_capella_paths.py",
        "    extra = (overrides or {}).get(op.name)",
        "    extra = None",
        CAPELLA,
    ),
    (
        "capella: the throwaway password is omitted, so Capella returns a generated one",
        "scripts/verify_capella_paths.py",
        '            "password": _throwaway_password(),',
        '            "password": "",',
        CAPELLA,
    ),
    (
        "capella: a created child object gets no teardown record",
        "scripts/verify_capella_paths.py",
        "        created.append((label, f\"{path}/{urllib.parse.quote(new_id, safe='')}\"))",
        "        pass",
        CAPELLA,
    ),
    (
        "capella: children are torn down in creation order, orphaning the nested ones",
        "scripts/verify_capella_paths.py",
        "    for label, path in reversed(created):",
        "    for label, path in created:",
        CAPELLA,
    ),
    (
        "capella: the App Endpoint is bound by bucket id instead of name",
        "scripts/verify_capella_paths.py",
        '            "bucket": bucket,',
        '            "bucket": bucket_id,',
        CAPELLA,
    ),
    (
        "capella: the keyspace collapses to a bare endpoint name",
        "scripts/verify_capella_paths.py",
        '            f"{endpoint_id}.{verify_scope}.{verify_collection}"',
        "            endpoint_id",
        CAPELLA,
    ),
    (
        "capella: one failed create aborts the rest of the bootstrap",
        "scripts/verify_capella_paths.py",
        '            print(f"  {label:14s}: create failed HTTP {status} — {body[:500]}")\n'
        "            return None",
        '            print(f"  {label:14s}: create failed HTTP {status} — {body[:500]}")\n'
        "            raise SystemExit(3)",
        CAPELLA,
    ),
    (
        "capella: child teardown does not run when verification raises",
        "scripts/verify_capella_paths.py",
        "        if created_children:\n"
        "            print()\n"
        '            print("Tearing down child objects:")\n'
        "            teardown_child_objects(token, created_children)",
        "        if False:\n"
        "            print()\n"
        '            print("Tearing down child objects:")\n'
        "            teardown_child_objects(token, created_children)",
        CAPELLA,
    ),
    # ── Request bodies corrected by live 422s + the OpenAPI document ────────
    (
        "capella: a database credential no longer requires a permission grant",
        "handlers/capella/spec.py",
        'body_required=("name", "access"),',
        'body_required=("name",),',
        CAPELLA,
    ),
    (
        "capella: an admin user no longer requires its access oneOf",
        "handlers/capella/spec.py",
        'body_required=("name", "password", "access"),',
        'body_required=("name",),',
        CAPELLA,
    ),
    (
        # The description is replaced WHOLESALE, not edited.
        #
        # Two narrower versions of this mutation survived, both correctly: the description
        # states the oneOf twice ("never both and never neither", then "Supplying both or
        # neither is a 422"), so deleting either mention leaves it still true. A mutation that
        # leaves the code correct tests nothing, and padding the harness with one would be
        # exactly the decoration this file exists to find.
        #
        # Removing the whole description is unambiguous: the model is then told a required
        # field exists and nothing about the only two shapes it accepts.
        "capella: the admin user access field loses its shape guidance entirely",
        "handlers/capella/spec.py",
        '            "access": {\n                "type": "object",\n                "description": (',
        # `"" and (...)` short-circuits to "". `"" or (...)` would have yielded the original
        # string — a mutation that changes nothing, which is how the first attempt at this
        # "survived".
        '            "access": {\n                "type": "object",\n                "description": "" and (',
        CAPELLA,
    ),
    (
        "capella: deltaSyncEnabled reverts to the silently-ignored deltaSync",
        "handlers/capella/spec.py",
        '            "deltaSyncEnabled": {',
        '            "deltaSync": {',
        CAPELLA,
    ),
    (
        # Targets the phrase that CARRIES the limit. An earlier version edited a neighbouring
        # sentence and survived, correctly — "ONLY ONE scope is allowed" was still there.
        "capella: the one-scope-per-endpoint limit is dropped from the description",
        "handlers/capella/spec.py",
        '                    "Optional. Keys are SCOPE names, and ONLY ONE scope is allowed per App "',
        '                    "Optional. Keys are SCOPE names, per App "',
        CAPELLA,
    ),
    (
        "capella: the bootstrap stops sending the credential grant",
        "scripts/verify_capella_paths.py",
        '            "access": [{"privileges": ["data_reader"]}],',
        "",
        CAPELLA,
    ),
    (
        "capella: the bootstrap stops sending the admin user access oneOf",
        "scripts/verify_capella_paths.py",
        '            "access": {"accessAllEndpoints": True},',
        "",
        CAPELLA,
    ),
    (
        "capella: a create with no readable id gets no teardown record again",
        "scripts/verify_capella_paths.py",
        '        new_id = str(data.get("id") or data.get("name") or "") or (fallback_id or "")',
        '        new_id = str(data.get("id") or data.get("name") or "")',
        CAPELLA,
    ),
    (
        "capella: the App Endpoint loses its name fallback, so it leaks",
        "scripts/verify_capella_paths.py",
        "        fallback_id=endpoint_name,",
        "        fallback_id=None,",
        CAPELLA,
    ),
    (
        "capella: a rejection body is truncated below the useful part again",
        "scripts/verify_capella_paths.py",
        'print(f"  {label:14s}: create failed HTTP {status} — {body[:500]}")',
        'print(f"  {label:14s}: create failed HTTP {status} — {body[:60]}")',
        CAPELLA,
    ),
    # ── App Endpoint must not bind real data (409 + a safety problem) ───────
    (
        "capella: the endpoint binds the discovered scope, syncing real data",
        "scripts/verify_capella_paths.py",
        '            "scopes": {verify_scope: {"collections": {verify_collection: {}}}},',
        '            "scopes": {scope: {"collections": {collection: {}}}},',
        CAPELLA,
    ),
    (
        "capella: no throwaway scope is created for the endpoint to bind",
        "scripts/verify_capella_paths.py",
        '        {"name": verify_scope},\n        fallback_id=verify_scope,',
        '        {"name": verify_scope},\n        fallback_id=None,',
        CAPELLA,
    ),
    (
        "capella: the keyspace names the discovered scope instead of the created one",
        "scripts/verify_capella_paths.py",
        '            f"{endpoint_id}.{verify_scope}.{verify_collection}"',
        '            f"{endpoint_id}.{scope}.{collection}"',
        CAPELLA,
    ),
    (
        "capella: the admin user grant reverts to the rejected false form",
        "scripts/verify_capella_paths.py",
        '            "access": {"accessAllEndpoints": True},',
        '            "access": {"accessAllEndpoints": False},',
        CAPELLA,
    ),
    (
        "capella: the spec stops warning that accessAllEndpoints false is rejected",
        "handlers/capella/spec.py",
        "                    \"{'accessAllEndpoints': false} is NEITHER — it grants nothing, and \"",
        '                    "false disables it. "',
        CAPELLA,
    ),
    # ── The live verification record ────────────────────────────────────────
    (
        "capella: an operation drops out of the live verification record",
        "handlers/capella/spec.py",
        '    "capella_app_endpoint_get": "200",\n',
        "",
        CAPELLA,
    ),
    (
        "capella: a GET is recorded as OPTIONS-probed, so its method was never confirmed",
        "handlers/capella/spec.py",
        '    "capella_app_endpoint_get": "200",',
        '    "capella_app_endpoint_get": "405",',
        CAPELLA,
    ),
    (
        "capella: a write is recorded as a real call, meaning something was performed",
        "handlers/capella/spec.py",
        '    "capella_bucket_delete": "405",',
        '    "capella_bucket_delete": "200",',
        CAPELLA,
    ),
    (
        "capella: a status the API cannot produce after routing is accepted",
        "handlers/capella/spec.py",
        '    "capella_bucket_delete": "405",',
        '    "capella_bucket_delete": "000",',
        CAPELLA,
    ),
    (
        "capella: the verification date is dropped",
        "handlers/capella/spec.py",
        'LIVE_VERIFIED_ON = "2026-07-30"',
        'LIVE_VERIFIED_ON = "recently"',
        CAPELLA,
    ),
    # ── The authorization decision itself ───────────────────────────────────
    #
    # `validate_token` had NEVER been executed by a test — every test that touched it
    # monkeypatched it away. These break each control inside it in turn.
    (
        "auth: skip-verify no longer refuses to combine with required auth",
        "auth/oidc.py",
        '        if _env("CB_ADMIN_HTTP_REQUIRE_AUTH", "").lower() in ("1", "true", "yes", "on"):',
        "        if False:",
        TOKEN,
    ),
    (
        "auth: skip-verify no longer refuses a network bind",
        "auth/oidc.py",
        '        if host not in ("127.0.0.1", "localhost", "::1", ""):',
        "        if False:",
        TOKEN,
    ),
    (
        "auth: a symmetric signing algorithm is accepted, enabling forgery",
        "auth/oidc.py",
        "    if unsafe:\n        raise RuntimeError(",
        "    if False:\n        raise RuntimeError(",
        TOKEN,
    ),
    (
        "auth: the asymmetric-only check misses HS256",
        "auth/oidc.py",
        '        a for a in algorithms if not a.upper().startswith(("RS", "PS", "ES", "ED"))',
        '        a for a in algorithms if a.upper() == "NONE"',
        TOKEN,
    ),
    (
        "auth: any token from the issuer is accepted with no audience configured",
        "auth/oidc.py",
        '        raise RuntimeError(\n            "OAUTH_AUDIENCE must be set when CB_ADMIN_HTTP_REQUIRE_AUTH=true. "',
        '        pass\n    if False:\n        raise RuntimeError(\n            "OAUTH_AUDIENCE must be set when CB_ADMIN_HTTP_REQUIRE_AUTH=true. "',
        TOKEN,
    ),
    (
        "auth: exp is no longer required, so a token without one never expires",
        "auth/oidc.py",
        'REQUIRED_CLAIM_NAMES: tuple[str, ...] = ("exp", "iss", "sub")',
        'REQUIRED_CLAIM_NAMES: tuple[str, ...] = ("iss", "sub")',
        TOKEN,
    ),
    (
        "auth: sub is no longer required, so an admin action is unattributable",
        "auth/oidc.py",
        'REQUIRED_CLAIM_NAMES: tuple[str, ...] = ("exp", "iss", "sub")',
        'REQUIRED_CLAIM_NAMES: tuple[str, ...] = ("exp", "iss")',
        TOKEN,
    ),
    (
        "auth: the required-claims list is not passed to the decoder",
        "auth/oidc.py",
        '        "options": {"require": required_claims, "verify_exp": True},',
        '        "options": {"verify_exp": True},',
        TOKEN,
    ),
    (
        "auth: expiry checking is switched off",
        "auth/oidc.py",
        '        "options": {"require": required_claims, "verify_exp": True},',
        '        "options": {"require": required_claims, "verify_exp": False},',
        TOKEN,
    ),
    (
        "auth: the audience is never verified, even when configured",
        "auth/oidc.py",
        "    if not audience:\n        # Some providers (Keycloak) put the client_id as the audience;",
        "    if True:\n        # Some providers (Keycloak) put the client_id as the audience;",
        TOKEN,
    ),
    (
        "auth: the issuer is not checked, so any signer of a known key is trusted",
        "auth/oidc.py",
        "        issuer=issuer,",
        "        issuer=None,",
        TOKEN,
    ),
    (
        "auth: the signature is verified against no key at all",
        "auth/oidc.py",
        "        signing_key.key,",
        '        signing_key.key,\n        options={"verify_signature": False},',
        TOKEN,
    ),
    # ── The browser login flow: PKCE and state are CSRF controls ────────────
    (
        "auth: PKCE downgraded to the plain method, so nothing binds the code",
        "auth/oidc.py",
        "    digest = hashlib.sha256(verifier.encode()).digest()",
        "    digest = verifier.encode()",
        TOKEN,
    ),
    (
        "auth: the challenge method claims S256 while the value is not hashed",
        "auth/oidc.py",
        '        "code_challenge_method": "S256",',
        '        "code_challenge_method": "plain",',
        TOKEN,
    ),
    (
        "auth: the state parameter is dropped from the authorization URL",
        "auth/oidc.py",
        '        "state": state,',
        '        "state": "",',
        TOKEN,
    ),
    (
        "auth: the client secret leaks into the browser redirect",
        "auth/oidc.py",
        '        "code_challenge_method": "S256",\n    }',
        '        "code_challenge_method": "S256",\n        "client_secret": _env("OAUTH_CLIENT_SECRET"),\n    }',
        TOKEN,
    ),
    (
        "auth: the PKCE verifier is not sent in the code exchange",
        "auth/oidc.py",
        '        "code_verifier": code_verifier,',
        "",
        TOKEN,
    ),
    (
        "auth: a failed token exchange returns quietly instead of raising",
        "auth/oidc.py",
        "    resp = _requests.post(token_ep, data=payload, timeout=15)\n"
        "    resp.raise_for_status()\n"
        "    return resp.json()\n\n\ndef refresh_access_token",
        "    resp = _requests.post(token_ep, data=payload, timeout=15)\n"
        "    return resp.json()\n\n\ndef refresh_access_token",
        TOKEN,
    ),
    (
        "auth: human-only scopes are sent on the machine-to-machine request",
        "auth/oidc.py",
        '                if s not in ("openid", "profile", "email", "address", "phone")',
        "                if s",
        TOKEN,
    ),
    (
        "auth: the dedicated automation identity is ignored",
        "auth/oidc.py",
        '    client_id = _env("OAUTH_CC_CLIENT_ID") or _env_required("OAUTH_CLIENT_ID")',
        '    client_id = _env_required("OAUTH_CLIENT_ID")',
        TOKEN,
    ),
    # ── admin_request retry safety ──────────────────────────────────────────
    (
        "shared: a POST is retried on a 5xx, so a failover may run twice",
        "handlers/shared.py",
        "    if status in (500, 502, 503, 504):\n        return method.upper() in _IDEMPOTENT_METHODS",
        "    if status in (500, 502, 503, 504):\n        return True",
        SHARED,
    ),
    (
        "shared: POST joins the idempotent set",
        "handlers/shared.py",
        '_IDEMPOTENT_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "PUT", "DELETE"})',
        '_IDEMPOTENT_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "PUT", "DELETE", "POST"})',
        SHARED,
    ),
    (
        "shared: a network error on a POST is retried",
        "handlers/shared.py",
        "            if method.upper() in _IDEMPOTENT_METHODS and attempt < _MAX_ATTEMPTS:",
        "            if attempt < _MAX_ATTEMPTS:",
        SHARED,
    ),
    (
        "shared: a client error is retried, tripling the latency of every mistake",
        "handlers/shared.py",
        "    if status in _UNPROCESSED_STATUSES:\n        return True",
        "    if status >= 400:\n        return True",
        SHARED,
    ),
    (
        "shared: the retry backoff becomes a tight loop",
        "handlers/shared.py",
        "_BASE_BACKOFF = 0.5",
        "_BASE_BACKOFF = 0.0",
        SHARED,
    ),
    (
        "shared: mTLS also sends the password it was meant to replace",
        "handlers/shared.py",
        "    if cert_path and key_path:\n        return {}",
        "    if False:\n        return {}",
        SHARED,
    ),
    (
        "shared: a half-configured certificate pair selects mTLS and cannot authenticate",
        "handlers/shared.py",
        "    if cert_path and key_path:\n        auth = CertificateAuthenticator(",
        "    if cert_path or key_path:\n        auth = CertificateAuthenticator(",
        SHARED,
    ),
    (
        "shared: TLS verification is disabled without the opt-in",
        "handlers/shared.py",
        '    if get_env_bool("CB_ADMIN_TLS_INSECURE", False):',
        "    if True:",
        SHARED,
    ),
    (
        "shared: booleans reach the REST API as Python reprs",
        "handlers/shared.py",
        '    if isinstance(v, bool):\n        return "true" if v else "false"',
        "    if False:\n        return str(v)",
        SHARED,
    ),
    (
        "shared: a list is sent as a Python repr, silently downgrading TLS ciphers",
        "handlers/shared.py",
        "    if isinstance(v, (list, tuple, dict)):",
        "    if False:",
        SHARED,
    ),
    (
        "shared: a path segment can escape itself",
        "handlers/shared.py",
        "def quote_path(segment: str) -> str:",
        "def quote_path(segment: str) -> str:\n    return segment",
        SHARED,
    ),
    (
        "shared: the index-create guard accepts arbitrary SQL++",
        "handlers/shared.py",
        '    if not _INDEX_DDL_RE.match(stmt or ""):',
        "    if False:",
        SHARED,
    ),
    (
        "shared: an unterminated quote is forwarded unparsed",
        "handlers/shared.py",
        "    if unterminated:\n        return (",
        "    if False:\n        return (",
        SHARED,
    ),
    (
        "shared: a truthy string satisfies the destructive confirmation gate",
        "handlers/shared.py",
        '    if args.get("confirm") is True:',
        '    if args.get("confirm"):',
        SHARED,
    ),
    (
        "shared: read-only mode defaults to off",
        "handlers/shared.py",
        'READ_ONLY_MODE: bool = get_env_bool("CB_ADMIN_READ_ONLY_MODE", True)',
        'READ_ONLY_MODE: bool = get_env_bool("CB_ADMIN_READ_ONLY_MODE", False)',
        SHARED,
    ),
    # ── The console's browser login flow ────────────────────────────────────
    (
        "console: /api/config hands the connection-string password to the browser",
        "gui/gui_server.py",
        "    return _shared_redact_uri_credentials(value)",
        "    return value",
        GUI_OAUTH,
    ),
    (
        "console: the callback no longer checks state, so login CSRF works",
        "gui/gui_server.py",
        "    pkce = _pkce_store.pop(state, None)",
        # created_at is part of the substitute entry ON PURPOSE. The obvious form of this
        # mutation -- `or {"verifier": "", "next": "/"}` -- is not a real hole: the
        # substitute has no created_at, so the TTL check three lines down computes an
        # infinite age and refuses anyway. A test that only asserted "400" therefore
        # passed against the mutated build, for the wrong reason. With a fresh created_at
        # the fabricated state clears BOTH checks and reaches exchange_code, which is the
        # actual vulnerability this entry is meant to describe.
        "    pkce = _pkce_store.pop(state, None) or {\n"
        '        "verifier": "",\n'
        '        "next": "/",\n'
        '        "created_at": str(time.time()),\n'
        "    }",
        GUI_OAUTH,
    ),
    (
        "console: state is reusable, so a captured callback URL is a reusable login",
        "gui/gui_server.py",
        "    pkce = _pkce_store.pop(state, None)",
        "    pkce = _pkce_store.get(state, None)",
        GUI_OAUTH,
    ),
    (
        "console: next becomes an open redirect on an authenticated endpoint",
        "gui/gui_server.py",
        '    next_url = raw_next if (not parsed.scheme and not parsed.netloc) else "/"',
        "    next_url = raw_next",
        GUI_OAUTH,
    ),
    (
        "console: a failed token refresh leaves the dead session alive",
        "gui/gui_server.py",
        "        except Exception:\n            # Refresh or re-validation failed — session is dead\n            _session.delete_session(cookie)\n            return None",
        '        except Exception:\n            return sess.get("claims")',
        GUI_OAUTH,
    ),
    (
        "console: a session with no refresh token stays authenticated after expiry",
        "gui/gui_server.py",
        "        if not refresh_token:\n            # No way to refresh an expired session — treat as logged out\n            _session.delete_session(cookie)\n            return None",
        '        if not refresh_token:\n            return sess.get("claims")',
        GUI_OAUTH,
    ),
    (
        "console: refreshed tokens keep the pre-refresh claims, so a revoked role persists",
        "gui/gui_server.py",
        "            new_claims = _oidc.validate_token(new_token)",
        '            new_claims = sess.get("claims") or {}',
        GUI_OAUTH,
    ),
    # ── SQL++ identifier quoting: the injection boundary ────────────────────
    (
        "sql: identifier quoting stops doubling backticks, so a name can escape",
        "handlers/indexes.py",
        '    return "`" + (s or "").replace("`", "``") + "`"',
        '    return "`" + (s or "") + "`"',
        SQLB,
    ),
    (
        "sql: identifiers are interpolated unquoted",
        "handlers/indexes.py",
        '    return "`" + (s or "").replace("`", "``") + "`"',
        '    return s or ""',
        SQLB,
    ),
    (
        "sql: the replica count is interpolated without coercion",
        "handlers/indexes.py",
        '                withs.append(f\'"num_replica": {int(args["num_replica"])}\')',
        '                withs.append(f\'"num_replica": {args["num_replica"]}\')',
        SQLB,
    ),
    (
        "sql: the index list interpolates its filters instead of binding them",
        "handlers/indexes.py",
        # Anchor updated: the code it pointed at was edited during the security pass.
        '                    "(bucket_id = $bucket OR (bucket_id IS MISSING "',
        "                    f\"bucket_id = '{args['bucket_name']}' OR (\"",
        SQLB,
    ),
    (
        "sql: a raw index drop skips the read-only guard",
        "handlers/indexes.py",
        '                blocked = block_dml_if_readonly(args["statement"])\n                if blocked:\n                    return err(blocked, tool=name)\n                return _run_n1ql(args["statement"])\n\n            if not args.get("bucket_name"):\n                return err(\n                    "bucket_name is required when statement is not provided", tool=name\n                )',
        '                return _run_n1ql(args["statement"])\n\n            if not args.get("bucket_name"):\n                return err(\n                    "bucket_name is required when statement is not provided", tool=name\n                )',
        SQLB,
    ),
    # ── Audit classification ────────────────────────────────────────────────
    (
        # Anchor updated: the code it pointed at was edited during the security pass.
        "audit: a successful non-JSON response is recorded as a denial",
        "audit.py",
        '        if not isinstance(text, str):\n            return "allowed", ""',
        '        if not isinstance(text, str):\n            return "denied_handler", "unreadable"',
        DISPATCH,
    ),
    (
        # Anchor RETARGETED: _classify_result moved out of server.py into
        # audit.classify_result so BOTH dispatch paths share one refusal
        # vocabulary -- the console was collapsing every refusal to
        # denied_handler. The harness correctly reported ANCHOR-GONE when the
        # code moved, which is the whole point of it.
        "audit: a guardrail refusal is indistinguishable from a cluster error",
        "audit.py",
        '            if payload.get("guardrail"):',
        "            if False:",
        DISPATCH,
    ),
    (
        "audit: an egress refusal is indistinguishable from a cluster error",
        "audit.py",
        '            if "EgressDenied" in reason or "EGRESS_ALLOWED_HOSTS" in reason:',
        "            if False:",
        DISPATCH,
    ),
    (
        "audit: the reason is no longer truncated",
        "audit.py",
        '            reason = str(payload.get("error"))[:400]',
        '            reason = str(payload.get("error"))',
        DISPATCH,
    ),
    (
        "audit: an unparseable result is invented as a denial",
        "audit.py",
        '    except Exception:\n        # Not JSON, or an unexpected shape. Treat as success rather than inventing a\n        # denial; the handler returned normally.\n        return "allowed", ""',
        '    except Exception:\n        return "denied_handler", "unparseable"',
        DISPATCH,
    ),
    # ── DNS-rebinding allowlist ─────────────────────────────────────────────
    (
        "transport: a configured hostname is allowed only without its port",
        "server.py",
        '        if ":" not in entry:\n            extra.append(f"{entry}:{port}")',
        '        if False:\n            extra.append(f"{entry}:{port}")',
        DISPATCH,
    ),
    (
        "transport: the wildcard-bind warning is silent",
        "server.py",
        '    if host in ("0.0.0.0", "::", "") and not extra:',
        "    if False:",
        DISPATCH,
    ),
    # ── Dispatch refusals name the right cause ──────────────────────────────
    (
        "dispatch: an unknown tool is not audited",
        "server.py",
        '        _audit("denied_unknown_tool", reason="no handler registered")',
        "        pass",
        DISPATCH,
    ),
    (
        "dispatch: a deployment-gated tool is reported as read-only filtered",
        "server.py",
        "        if _GATING and not deployment.tool_is_available(name, _DEPLOYMENT_MODE):",
        "        if False:",
        DISPATCH,
    ),
    # ── Query-plan analysis: the advice an operator acts on ─────────────────
    (
        "plan: only the newest PrimaryScan spelling is recognised",
        "handlers/diagnostics.py",
        '_PRIMARY_SCAN_OPS = {"PrimaryScan", "PrimaryScan2", "PrimaryScan3"}',
        '_PRIMARY_SCAN_OPS = {"PrimaryScan3"}',
        PLAN,
    ),
    (
        "plan: only the newest IndexScan spelling is recognised",
        "handlers/diagnostics.py",
        '_INDEX_SCAN_OPS = {"IndexScan", "IndexScan2", "IndexScan3"}',
        '_INDEX_SCAN_OPS = {"IndexScan3"}',
        PLAN,
    ),
    (
        "plan: the walker stops descending, so nested operators are missed",
        "handlers/diagnostics.py",
        "            if isinstance(v, (dict, list)):\n                yield from _walk_plan(v)",
        "            if False:\n                yield from _walk_plan(v)",
        PLAN,
    ),
    (
        "plan: a filter before any scan is reported as a missed pushdown",
        "handlers/diagnostics.py",
        '        if op == "Filter" and saw_scan:',
        '        if op == "Filter":',
        PLAN,
    ),
    (
        "plan: an unreadable plan reports no problems, which reads as no problems",
        "handlers/diagnostics.py",
        '    if not summary["operators"]:',
        "    if False:",
        PLAN,
    ),
    (
        "plan: index names are not deduplicated in the finding",
        "handlers/diagnostics.py",
        '        f.append("Indexes used: " + ", ".join(sorted(set(summary["indexes_used"]))))',
        '        f.append("Indexes used: " + ", ".join(summary["indexes_used"]))',
        PLAN,
    ),
    (
        "plan: the EXPLAIN fallback keeps going past the limit",
        "handlers/diagnostics.py",
        "            if len(flagged) >= limit:\n                break",
        "            if False:\n                break",
        PLAN,
    ),
    (
        "plan: one unexplainable statement aborts the whole probe",
        "handlers/diagnostics.py",
        '            _log.debug("skipping un-explainable statement: %s", e)\n            continue',
        "            raise",
        PLAN,
    ),
    # ── Log file preparation ────────────────────────────────────────────────
    (
        # Targeted at the EXISTING-FILE branch, where fchmod is the only thing tightening
        # the mode. In the create branch `os.open` already passes 0o600, so removing fchmod
        # there is a no-op — and that version of this mutation "survived" for that reason.
        "logging: an existing log file is left at whatever mode it had",
        "logging_config.py",
        "            # fchmod on an fd we opened without following links, not chmod on a path.\n"
        '            fd = os.open(path, os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))\n'
        "            try:\n"
        "                os.fchmod(fd, 0o600)",
        '            fd = os.open(path, os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))\n'
        "            try:\n"
        "                pass",
        INFRA,
    ),
    (
        # BOTH symlink defences at once. Removing only the `islink` check survives, and
        # correctly: `O_NOFOLLOW` on the open refuses the link independently, so the outcome
        # is unchanged. That is what defence in depth means, and a mutation that leaves
        # behaviour identical tests nothing. Removing both is the mutation that matters.
        "logging: both symlink defences removed, so an arbitrary file is chmodded",
        "logging_config.py",
        # O_NOFOLLOW appears at THREE sites (the shared opener, the create branch, the
        # existing-file branch) and each edit replaces the first remaining occurrence, so it
        # is listed three times. A symlink pointing at an existing file takes the last of
        # them, which is why leaving any single one in place changes nothing.
        [
            "        if os.path.islink(path):",
            'getattr(os, "O_NOFOLLOW", 0)',
            'getattr(os, "O_NOFOLLOW", 0)',
            'getattr(os, "O_NOFOLLOW", 0)',
        ],
        ["        if False:", "0", "0", "0"],
        INFRA,
    ),
    (
        "logging: a hard-linked log file is no longer reported",
        "logging_config.py",
        "            if info.st_nlink > 1:",
        "            if False:",
        INFRA,
    ),
    (
        "logging: an unusable path claims success, so the sink logs nowhere",
        "logging_config.py",
        "    except OSError:",
        "    except OSError if False else ():",
        INFRA,
    ),
    # ── The Capella client ──────────────────────────────────────────────────
    (
        "capella: a CREATE is retried on a 5xx, so a second cluster is billed",
        "handlers/capella/client.py",
        "    if status in _SERVER_ERROR:\n        return method.upper() in _IDEMPOTENT_METHODS",
        "    if status in _SERVER_ERROR:\n        return True",
        INFRA,
    ),
    (
        "capella: POST joins the idempotent set",
        "handlers/capella/client.py",
        '_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "PUT", "DELETE"})',
        '_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "PUT", "DELETE", "POST"})',
        INFRA,
    ),
    (
        "capella: a 403 loses the role hint and reads like a missing resource",
        "handlers/capella/client.py",
        "    if status == 403:",
        "    if False:",
        INFRA,
    ),
    (
        "capella: a 404 no longer explains the project-id trap",
        "handlers/capella/client.py",
        "    if status == 404:",
        "    if False:",
        INFRA,
    ),
    (
        "capella: an unretried CREATE no longer says the outcome is unknown",
        "handlers/capella/client.py",
        "            if not safe_to_repeat:",
        "            if False:",
        INFRA,
    ),
    (
        "capella: the API key secret is defaulted instead of demanded",
        "handlers/capella/client.py",
        '    return get_env("CAPELLA_API_KEY_SECRET")',
        '    return os.environ.get("CAPELLA_API_KEY_SECRET", "")',
        INFRA,
    ),
    (
        "capella: pagination stops after the first page",
        "handlers/capella/client.py",
        "def capella_list(",
        "def _dead_capella_list(",
        INFRA,
    ),
    # ── The required-variable marker across a module reload ─────────────────
    (
        "shared: the required marker reverts to identity, so a missing credential "
        "returns a sentinel object instead of raising",
        "handlers/shared.py",
        '    return type(default).__name__ == "_RequiredSentinel"',
        "    return default is _REQUIRED",
        SHARED,
    ),
    (
        "shared: a missing required variable is no longer fatal at all",
        "handlers/shared.py",
        "        if _is_required(default):",
        "        if False:",
        SHARED,
    ),
    # ── The ASGI auth edge ──────────────────────────────────────────────────
    (
        "edge: a presented token that fails validation is discarded, not rejected",
        "server.py",
        '                await _send_401(send, f"Invalid token: {type(exc).__name__}")\n                return',
        "                pass",
        EDGE,
    ),
    (
        "edge: token validation moves back onto the event loop",
        "server.py",
        "                await asyncio.to_thread(_oidc.validate_token, token)",
        "                _oidc.validate_token(token)",
        EDGE,
    ),
    (
        "edge: a missing token is allowed even when auth is required",
        "server.py",
        "        elif self._require:",
        "        elif False:",
        EDGE,
    ),
    (
        "edge: the bearer scheme is matched case-sensitively",
        "server.py",
        'if val.lower().startswith("bearer "):',
        'if val.startswith("Bearer "):',
        EDGE,
    ),
    (
        "banner: an issuer with no enforcement is no longer warned about",
        "server.py",
        '    if os.environ.get("OAUTH_ISSUER", "").strip() and not env_truthy(',
        "    if False and env_truthy(",
        EDGE,
    ),
    (
        "banner: skip-verify is no longer announced",
        "server.py",
        '    if env_truthy("OAUTH_SKIP_VERIFY"):',
        "    if False:",
        EDGE,
    ),
    (
        "banner: a ceiling entry matching no tool is no longer reported",
        "server.py",
        "    if _CEILING_UNKNOWN:",
        "    if False:",
        EDGE,
    ),
    # ── The audit record of last resort ─────────────────────────────────────
    (
        "audit: a serialisation failure loses the record entirely",
        "audit.py",
        "    except BaseException:\n        try:\n            _log.info(",
        "    except BaseException:\n        return\n        try:\n            _log.info(",
        AUDITP,
    ),
    (
        # Targets the CHECK in audit_sink_error, not the log line beside it in the opener —
        # removing the log changes nothing observable, and that version of this mutation
        # survived for that reason.
        "audit: an unusable audit file is no longer fatal at startup",
        "audit.py",
        "    if _audit_file_logger() is not None:\n        return None",
        "    if True:\n        return None",
        AUDITP,
    ),
    (
        "audit: a correlation id is no longer bounded",
        "audit.py",
        "    if len(text) > _MAX_CORRELATION_LEN:",
        "    if False:",
        AUDITP,
    ),
    (
        "audit: newlines survive in a correlation id, so a record can be forged",
        "audit.py",
        '    text = " ".join(text.split())',
        "    text = text",
        AUDITP,
    ),
    (
        "profile: a hostname is treated as loopback",
        "profile_config.py",
        "        return ipaddress.ip_address(host).is_loopback\n    except ValueError:\n        return False",
        "        return ipaddress.ip_address(host).is_loopback\n    except ValueError:\n        return True",
        AUDITP,
    ),
    (
        "profile: the enterprise profile stops requiring an audience",
        "profile_config.py",
        '            "OAUTH_AUDIENCE is unset in the enterprise profile. Without it, any "',
        '            "note: "',
        AUDITP,
    ),
    # ── The environment reconciler ──────────────────────────────────────────
    (
        "reconciler: a second cluster is created instead of adopting the existing one",
        "handlers/capella/environment.py",
        "    if cluster is None:",
        "    if True:",
        ENVREC,
    ),
    (
        # The RESULT's password, not the request body's. `"password": password` appears at
        # both sites and the harness replaces the first — which is the body, so the credential
        # was still created correctly and the mutation changed nothing the caller sees.
        "reconciler: the generated credential password is not returned to the caller",
        "handlers/capella/environment.py",
        '        result["credential"] = {\n            "name": cred_name,\n            "password": password,',
        '        result["credential"] = {\n            "name": cred_name,\n            "password": "",',
        ENVREC,
    ),
    # ── The protocol-level isError flag, and the console's half of it ───────
    (
        "console: a refused call is reported to the browser as a success again",
        "gui/gui_server.py",
        'return jsonify({"ok": decision == "allowed", "result": parsed})',
        'return jsonify({"ok": True, "result": parsed})',
        GUI_AUTHZ,
    ),
    # ── The protocol-level isError flag ─────────────────────────────────────
    (
        "dispatch: a refusal is reported to the client as a successful call again",
        "server.py",
        '    if not _carries_error_marker(getattr(result, "content", None)):\n        return server_result',
        '    if _carries_error_marker(getattr(result, "content", None)):\n        return server_result',
        DISPATCH,
    ),
    (
        "dispatch: every call is flagged as an error, so the flag means nothing",
        "server.py",
        "        if isinstance(payload, dict) and payload.get(shared.ERROR_MARKER) is True:\n            return True\n    return False",
        "        if isinstance(payload, dict):\n            return True\n    return False",
        DISPATCH,
    ),
]


def run(target: str, cwd: pathlib.Path) -> bool:
    """True when the suite passes, i.e. the mutation SURVIVED."""
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-x",
                "-q",
                "-p",
                "no:randomly",
                "-m",
                "not live",
                *target.split(),
            ],
            check=False,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=150,
        )
    except subprocess.TimeoutExpired:
        # A TIMEOUT IS NOT A KILL. `return False` here means "tests failed", which this
        # harness reports as the mutation being CAUGHT -- with no assertion having failed
        # anywhere. So any mutation that merely made the target slow enough to exceed the
        # timeout was recorded as covered by a test. That is the harness telling the
        # comfortable story, in the one tool whose entire job is to say which controls
        # are untested. Raised so the run fails loudly instead.
        raise MutationTimeoutError(
            f"pytest timed out on {target}; this mutation is NOT proven caught. "
            "Re-run with a longer timeout before trusting the result."
        ) from None
    return result.returncode == 0


def main() -> int:
    survivors = []
    for label, relpath, old, new, target in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp) / "cb"
            shutil.copytree(
                ROOT,
                work,
                ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".git"),
            )
            # `old`/`new` may each be a LIST, applying several edits as ONE mutation.
            #
            # Needed for LAYERED guards. The symlink protection in logging_config is both an
            # `islink` check and `O_NOFOLLOW` on the open; removing either alone leaves the
            # outcome identical, because the other still refuses. A single-edit mutation
            # therefore "survives" while the guard is perfectly well tested — the mutation is
            # the thing at fault, not the test. Removing both together is the edit that
            # actually changes behaviour, and it is caught.
            edits = (
                list(zip(old, new, strict=False))
                if isinstance(old, list)
                else [(old, new)]
            )
            path = work / relpath
            text = path.read_text()
            missing = [o for o, _ in edits if o not in text]
            if missing:
                # Not a pass. An anchor that no longer matches means this mutation tested
                # nothing, and the guard it was written for is now unverified.
                print(f"  ANCHOR-GONE  {label} ({relpath})", flush=True)
                survivors.append((label, "anchor not found"))
                continue
            for one_old, one_new in edits:
                text = text.replace(one_old, one_new, 1)
            path.write_text(text)
            if run(target, work):
                print(f"  SURVIVED     {label}", flush=True)
                survivors.append((label, "no test caught it"))
            else:
                print(f"  caught       {label}", flush=True)

    print(flush=True)
    if survivors:
        print(f"{len(survivors)} of {len(MUTATIONS)} NOT CAUGHT:")
        for label, why in survivors:
            print(f"  - {label}  [{why}]")
        return 1
    print(f"All {len(MUTATIONS)} mutations caught.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
