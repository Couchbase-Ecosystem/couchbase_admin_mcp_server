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

ROOT = pathlib.Path(__file__).resolve().parent.parent
SESSION = "tests/test_session.py"
COMPAT = "tests/test_mcp_compat.py"
STATUS = "tests/test_mcp_status.py"
CONTRACT = "tests/test_handler_contract.py"
CAPELLA = "tests/test_capella.py tests/test_verify_capella_paths.py"

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
        "    if settings.cert_file or settings.terminated_externally:  # noqa: SIM103\n"
        "        return True",
        "    if False:\n        return True",
        SESSION,
    ),
    (
        "session cookie: Secure always on, breaking http://127.0.0.1 login",
        "auth/session.py",
        "    # No TLS configured at all. `tls_config.validate()` already refuses to start in this\n"
        "    # state on a non-loopback bind, so reaching here means local development over http://.\n"
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
        '        "read": sum(1 for t in loaded_tools if mcp_compat.is_read_only(t)),',
        '        "read": sum(1 for t in loaded_tools if t.inputSchema),',
        COMPAT,
    ),
    # ── The connection-string password disclosure ───────────────────────────
    (
        "status: the connection string is reported verbatim again",
        "handlers/mcp_status.py",
        '            "connection_string": redact_uri_credentials(\n'
        '                os.environ.get("CB_CONNECTION_STRING", "couchbase://localhost")\n'
        "            ),",
        '            "connection_string": os.environ.get(\n'
        '                "CB_CONNECTION_STRING", "couchbase://localhost"\n'
        "            ),",
        STATUS,
    ),
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
        return False
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
            path = work / relpath
            text = path.read_text()
            if old not in text:
                # Not a pass. An anchor that no longer matches means this mutation tested
                # nothing, and the guard it was written for is now unverified.
                print(f"  ANCHOR-GONE  {label} ({relpath})", flush=True)
                survivors.append((label, "anchor not found"))
                continue
            path.write_text(text.replace(old, new, 1))
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
