"""
shared.py — connection pool, HTTP admin client, response helpers, safety primitives.

Changes from upstream:
- Phase 1 (safety):
  * Read-only mode (CB_ADMIN_READ_ONLY_MODE) with classification helpers
  * Disabled-tools list (CB_ADMIN_DISABLED_TOOLS, comma list or file path)
  * Confirmation-required list (CB_ADMIN_CONFIRMATION_REQUIRED_TOOLS)
  * Removal of hardcoded "Administrator"/"password" defaults — fail loudly at startup
  * SQL++ DML detection (block_dml_if_readonly)
  * Index DDL validators (assert_index_ddl_only)
- Phase 2 (engineering):
  * Retries with exponential backoff in admin_request / admin_request_json
  * JSON-body support unified in admin_request (no separate _json variant inconsistencies)
  * Standardized URL encoding (handled inside admin_request — callers never URL-encode)
  * Structured err() with diagnostic context
  * Cluster version detection cached on first call
- Phase 3 (auth & transport):
  * mTLS via CB_CLIENT_CERT_PATH, CB_CLIENT_KEY_PATH
  * CA cert path via CB_CA_CERT_PATH (for self-signed self-managed clusters)
  * Cert auth on SDK connection when cert paths are set

All tool names from upstream are preserved unchanged. New env vars are additive.
"""

from __future__ import annotations

import base64
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any

from mcp.types import TextContent

from logging_config import get_logger

_log = get_logger("handlers.shared")

# ── Sentinels for "must be set" environment variables ────────────────────────

_REQUIRED = object()


def get_env(key: str, default: Any = _REQUIRED) -> str | None:
    """Get an env var. If default is _REQUIRED and unset, raise at call time."""
    val = os.environ.get(key)
    if val is None or val == "":
        if default is _REQUIRED:
            raise RuntimeError(
                f"Required environment variable {key} is not set. "
                f"Set it before starting the MCP server."
            )
        return default
    return val


def get_env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def get_env_int(key: str, default: int) -> int:
    raw = os.environ.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# ── Safety mode configuration (read once at import) ──────────────────────────


def _parse_tool_list(raw: str | None) -> set[str]:
    """Parse a tool list from either a comma-separated string or a file path."""
    if not raw:
        return set()
    # If it looks like a file path and the file exists, read it
    if os.path.isfile(raw):
        names: set[str] = set()
        with open(raw, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                names.add(line)
        return names
    return {n.strip() for n in raw.split(",") if n.strip()}


READ_ONLY_MODE: bool = get_env_bool("CB_ADMIN_READ_ONLY_MODE", True)
DISABLED_TOOLS: set[str] = _parse_tool_list(os.environ.get("CB_ADMIN_DISABLED_TOOLS"))
_CUSTOM_CONFIRMATION_TOOLS: set[str] = _parse_tool_list(
    os.environ.get("CB_ADMIN_CONFIRMATION_REQUIRED_TOOLS")
)
# Whether to use elicitation hint in error responses (informational only;
# actual confirmation is enforced via the `confirm` argument pattern).
ELICITATION_HINTS: bool = get_env_bool("CB_ADMIN_ELICITATION_HINTS", True)


def get_confirmation_required(default_destructive: Iterable[str]) -> set[str]:
    """
    Return the effective set of tools that require explicit `confirm: true`.
    Always includes the supplied default set (tools annotated destructiveHint=true)
    plus any user additions from CB_ADMIN_CONFIRMATION_REQUIRED_TOOLS.
    """
    return set(default_destructive) | _CUSTOM_CONFIRMATION_TOOLS


# ── SDK connection (lazy) ────────────────────────────────────────────────────

_cluster = None
_bucket = None
_collection = None


def get_sdk_connection():
    """Return (cluster, bucket, collection) — lazily initialised."""
    global _cluster, _bucket, _collection
    if _cluster is not None:
        return _cluster, _bucket, _collection

    try:
        from datetime import timedelta

        from couchbase.auth import CertificateAuthenticator, PasswordAuthenticator
        from couchbase.cluster import Cluster
        from couchbase.options import ClusterOptions
    except ImportError as exc:
        raise RuntimeError("pip install couchbase>=4.2.0") from exc

    conn_str = get_env("CB_CONNECTION_STRING", "couchbase://localhost")
    cert_path = os.environ.get("CB_CLIENT_CERT_PATH")
    key_path = os.environ.get("CB_CLIENT_KEY_PATH")
    ca_path = os.environ.get("CB_CA_CERT_PATH")

    # Auth selection: mTLS if both client cert + key are provided; otherwise basic.
    if cert_path and key_path:
        auth = CertificateAuthenticator(
            cert_path=cert_path,
            key_path=key_path,
            trust_store_path=ca_path,
        )
    else:
        # Basic auth requires both username and password — no silent defaults.
        username = get_env("CB_USERNAME")
        password = get_env("CB_PASSWORD")
        auth = PasswordAuthenticator(
            username,
            password,
            cert_path=ca_path,
        )

    opts = ClusterOptions(auth)
    # WAN profile relaxes timeouts for remote / Capella connections.
    opts.apply_profile("wan_development")

    _cluster = Cluster(conn_str, opts)
    _cluster.wait_until_ready(timedelta(seconds=10))

    bucket_name = get_env("CB_BUCKET", "default")
    scope_name = get_env("CB_SCOPE", "_default")
    coll_name = get_env("CB_COLLECTION", "_default")

    _bucket = _cluster.bucket(bucket_name)
    _collection = _bucket.scope(scope_name).collection(coll_name)
    return _cluster, _bucket, _collection


# ── HTTP admin client ────────────────────────────────────────────────────────


def _admin_url() -> str:
    """Derive the HTTP management URL from CB_CONNECTION_STRING."""
    raw = get_env("CB_CONNECTION_STRING", "couchbase://localhost")
    # Strip scheme to get host
    host = raw.replace("couchbases://", "").replace("couchbase://", "")
    # Drop any path or query
    host = host.split("/")[0]
    # Drop SDK port if user specified one
    host = host.split(":")[0]
    is_tls = "couchbases://" in raw
    default_port = "18091" if is_tls else "8091"
    port = get_env("CB_MGMT_PORT", default_port)
    scheme = "https" if is_tls else "http"
    return f"{scheme}://{host}:{port}"


def _build_ssl_context() -> ssl.SSLContext | None:
    """Build an SSL context honoring CB_CLIENT_CERT_PATH / CB_CLIENT_KEY_PATH /
    CB_CA_CERT_PATH. Returns None if no TLS configuration is needed (HTTP only).
    """
    raw = get_env("CB_CONNECTION_STRING", "couchbase://localhost")
    if "couchbases://" not in raw:
        return None

    ctx = ssl.create_default_context()
    ca_path = os.environ.get("CB_CA_CERT_PATH")
    if ca_path:
        ctx.load_verify_locations(cafile=ca_path)

    cert_path = os.environ.get("CB_CLIENT_CERT_PATH")
    key_path = os.environ.get("CB_CLIENT_KEY_PATH")
    if cert_path and key_path:
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    # Allow disabling hostname verification only via an opt-in env var
    if get_env_bool("CB_ADMIN_TLS_INSECURE", False):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _auth_header() -> dict[str, str]:
    """Return Authorization header. If client certs are set, basic auth is omitted
    (mTLS does authentication at the TLS layer)."""
    cert_path = os.environ.get("CB_CLIENT_CERT_PATH")
    key_path = os.environ.get("CB_CLIENT_KEY_PATH")
    if cert_path and key_path:
        return {}
    username = get_env("CB_USERNAME")
    password = get_env("CB_PASSWORD")
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


# Retry config
_MAX_ATTEMPTS = get_env_int("CB_ADMIN_HTTP_RETRIES", 3)
_BASE_BACKOFF = 0.5  # seconds; doubles each attempt
_HTTP_TIMEOUT = get_env_int("CB_ADMIN_HTTP_TIMEOUT", 30)


def _retryable(status: int) -> bool:
    """Whether a given HTTP status code should be retried."""
    return status in (408, 425, 429, 500, 502, 503, 504)


def admin_request(
    method: str,
    path: str,
    data: dict | list | None = None,
    params: dict | None = None,
    json_body: bool = False,
) -> Any:
    """
    Execute a Couchbase Management REST API call.

    method:    HTTP verb
    path:      path component including leading slash (e.g. /pools/default/buckets)
    data:      dict (form or JSON) or list (JSON only)
    params:    query string parameters; URL-encoded by this function
    json_body: if True, send `data` as JSON (Content-Type: application/json).
               Otherwise send as application/x-www-form-urlencoded (default).

    Retries on transient 5xx and 429 with exponential backoff.
    Returns parsed JSON, or {"status": "ok"} for empty responses.
    Raises RuntimeError with diagnostic context on permanent failure.
    """
    base = _admin_url()
    url = f"{base}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)

    body: bytes | None = None
    headers = {"Accept": "application/json"}
    headers.update(_auth_header())

    if data is not None:
        if json_body or isinstance(data, list):
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode()
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            # Filter Nones to avoid sending empty values
            cleaned = {k: v for k, v in data.items() if v is not None}
            body = urllib.parse.urlencode(cleaned).encode()

    context = _build_ssl_context()

    last_error: str | None = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(
                req, timeout=_HTTP_TIMEOUT, context=context
            ) as resp:
                raw = resp.read()
                if not raw:
                    return {"status": "ok"}
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    # Some endpoints (e.g. /api/cfg) return text/plain
                    return {"status": "ok", "body": raw.decode(errors="replace")}
        except urllib.error.HTTPError as exc:
            body_bytes = exc.read() if hasattr(exc, "read") else b""
            try:
                detail = json.loads(body_bytes)
            except Exception:
                detail = body_bytes.decode(errors="replace")
            last_error = f"HTTP {exc.code} on {method} {path}: {detail}"
            if _retryable(exc.code) and attempt < _MAX_ATTEMPTS:
                time.sleep(_BASE_BACKOFF * (2 ** (attempt - 1)))
                continue
            raise RuntimeError(last_error) from exc
        except urllib.error.URLError as exc:
            last_error = f"Network error on {method} {path}: {exc.reason}"
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_BASE_BACKOFF * (2 ** (attempt - 1)))
                continue
            raise RuntimeError(last_error) from exc

    raise RuntimeError(last_error or "Unknown error after retries")


def admin_request_json(method: str, path: str, payload: Any | None = None) -> Any:
    """Compatibility shim: send a JSON body. Equivalent to admin_request(json_body=True)."""
    return admin_request(method, path, data=payload, json_body=True)


# ── Cluster version detection ────────────────────────────────────────────────

_cluster_version: str | None = None


def get_cluster_version() -> str | None:
    """Return the cluster implementationVersion string, or None if unreachable.
    Cached after first successful call.
    """
    global _cluster_version
    if _cluster_version is not None:
        return _cluster_version
    try:
        info = admin_request("GET", "/pools")
        ver = info.get("implementationVersion") if isinstance(info, dict) else None
        if isinstance(ver, str):
            _cluster_version = ver
    except Exception as e:
        # Version detection is best-effort; degrade gracefully but leave a trace.
        _log.debug("cluster version detection failed: %s", e)
    return _cluster_version


def is_version_at_least(major: int, minor: int = 0) -> bool:
    """Return True if the cluster version is >= the given major.minor.
    Returns False if version is unknown (conservative default)."""
    v = get_cluster_version()
    if not v:
        return False
    m = re.match(r"(\d+)\.(\d+)", v)
    if not m:
        return False
    vm, vn = int(m.group(1)), int(m.group(2))
    if vm != major:
        return vm > major
    return vn >= minor


def is_8x() -> bool:
    return is_version_at_least(8, 0)


def is_7x() -> bool:
    v = get_cluster_version()
    if not v:
        return False
    m = re.match(r"(\d+)\.", v)
    return bool(m and int(m.group(1)) == 7)


# ── SQL++ DML detection ──────────────────────────────────────────────────────

# Matches DML keywords at the start of a statement, allowing for leading
# whitespace and `--` or `/* */` comments.
_DML_RE = re.compile(
    r"""
    ^\s*                           # leading whitespace
    (?:--[^\n]*\n\s*|/\*.*?\*/\s*)*  # optional line / block comments
    (?P<kw>INSERT|UPSERT|UPDATE|DELETE|MERGE|CREATE|DROP|BUILD|ALTER|GRANT|REVOKE|EXECUTE)
    \b
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)


def is_dml_statement(stmt: str) -> bool:
    """Return True if the SQL++ statement is a write/DDL/DCL operation."""
    return bool(_DML_RE.match(stmt or ""))


def block_dml_if_readonly(stmt: str) -> str | None:
    """If read-only mode is on and stmt is DML, return an error message.
    Otherwise return None (caller proceeds)."""
    if READ_ONLY_MODE and is_dml_statement(stmt):
        return (
            "Read-only mode is enabled (CB_ADMIN_READ_ONLY_MODE=true). "
            "SQL++ statements that modify data or schema are blocked. "
            "To allow writes, restart the server with CB_ADMIN_READ_ONLY_MODE=false."
        )
    return None


# ── Index DDL validation ─────────────────────────────────────────────────────

_INDEX_DDL_RE = re.compile(
    r"""^\s*
    (CREATE\s+(PRIMARY\s+)?INDEX|BUILD\s+INDEX|CREATE\s+(?:HYPERSCALE\s+|COMPOSITE\s+)?VECTOR\s+INDEX)
    \b
    """,
    re.IGNORECASE | re.VERBOSE,
)

_INDEX_DROP_RE = re.compile(
    r"""^\s*DROP\s+(PRIMARY\s+)?(?:VECTOR\s+)?INDEX\b""",
    re.IGNORECASE | re.VERBOSE,
)


def assert_index_create_ddl(stmt: str) -> str | None:
    """Validate that a raw statement is index-creation DDL.
    Returns error message if not, else None.
    Prevents `admin_index_create` from being used to execute arbitrary SQL++."""
    if not _INDEX_DDL_RE.match(stmt or ""):
        return (
            "admin_index_create's `statement` parameter only accepts index DDL "
            "(CREATE INDEX, CREATE PRIMARY INDEX, BUILD INDEX, "
            "or CREATE [HYPERSCALE|COMPOSITE] VECTOR INDEX). "
            "Use the helper fields (index_name, bucket_name, fields, etc.) for "
            "structured creation, or run other SQL++ via cb_query."
        )
    return None


def assert_index_drop_ddl(stmt: str) -> str | None:
    if not _INDEX_DROP_RE.match(stmt or ""):
        return (
            "admin_index_drop's `statement` parameter only accepts DROP INDEX / "
            "DROP PRIMARY INDEX / DROP VECTOR INDEX. "
            "Use the helper fields for structured drops, or cb_query for other SQL++."
        )
    return None


# ── Confirmation gate for destructive tools ──────────────────────────────────


def require_confirmation(
    tool_name: str, args: dict, in_confirm_set: bool
) -> str | None:
    """
    If the tool is in the confirmation set and args doesn't include `confirm: true`,
    return an error message. Otherwise return None.

    The `confirm` argument is stripped from args before tool execution (callers
    should pop it). This is universal — works on any MCP client without
    requiring elicitation protocol support.
    """
    if not in_confirm_set:
        return None
    if args.get("confirm") is True:
        return None
    hint = ""
    if ELICITATION_HINTS:
        hint = (
            " To proceed, re-call this tool with the same arguments plus "
            "`confirm: true`. This server treats destructive operations as "
            "two-step to prevent accidental data loss."
        )
    return f"Confirmation required for `{tool_name}`.{hint}"


# ── Response helpers ─────────────────────────────────────────────────────────


def form_value(v: Any) -> str:
    """Convert a value to its REST form-encoding string representation.

    Couchbase REST endpoints expect lowercase 'true'/'false' for boolean fields,
    not Python's str(True)='True'. This helper produces the correct encoding for
    booleans while passing through ints/floats/strings via str().
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def quote_path(segment: str) -> str:
    """URL-encode a single path segment for use in a REST URL.

    Encodes every reserved character including '/' so a user-supplied identifier
    containing slashes, spaces, '@', '#', etc. can never escape its segment or
    inject extra path components. Use this for every user-supplied value that
    is interpolated into an admin_request path.
    """
    return urllib.parse.quote(segment or "", safe="")


def form_data(args: dict, exclude: Iterable[str] = ("confirm",)) -> dict:
    """Build a form-encodable dict from tool args.

    - Drops None values
    - Drops keys in `exclude` (default: 'confirm')
    - Converts booleans to lowercase 'true'/'false' (Couchbase REST API requirement)
    - Converts all other values via str()
    """
    excluded = set(exclude)
    return {
        k: form_value(v) for k, v in args.items() if v is not None and k not in excluded
    }


# ── Redaction ────────────────────────────────────────────────────────────────

# Substrings (case-insensitive) that mark a field as sensitive. A key is
# redacted if it CONTAINS any of these — so "password", "new_password", and
# "adminPassword" all match. Kept as substrings rather than exact names because
# the admin surface spans many services with inconsistent field naming.
_SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "password",
    "passphrase",
    "secret",
    "token",
    "credential",
    "private_key",
    "privatekey",
    "apikey",
    "api_key",
    "access_key",
    "accesskey",
    "auth",
)

# Keys that look sensitive by the rule above but are safe to keep — otherwise
# useful diagnostic fields would be needlessly masked.
_SENSITIVE_KEY_ALLOW: frozenset[str] = frozenset(
    {
        "auth_method",  # names the mechanism, not a credential
        "authentication_type",
    }
)

REDACTED = "***REDACTED***"


def _is_sensitive_key(key: str) -> bool:
    k = key.lower()
    if k in _SENSITIVE_KEY_ALLOW:
        return False
    return any(part in k for part in _SENSITIVE_KEY_PARTS)


def redact(value: Any) -> Any:
    """Return a deep copy of ``value`` with sensitive fields masked.

    Recurses through dicts and lists. Any dict key whose name indicates a
    credential (see ``_SENSITIVE_KEY_PARTS``) has its value replaced with
    ``REDACTED`` regardless of the value's type. Non-container values pass
    through unchanged. Used on both logged call arguments and the ``args``
    echoed back in error context, so a failed ``admin_user_create`` never
    surfaces the plaintext password to the agent or the logs.
    """
    if isinstance(value, dict):
        return {
            k: (REDACTED if _is_sensitive_key(k) else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def ok(data: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


def err(msg: str, **context) -> list[TextContent]:
    """Structured error response. `context` adds diagnostic fields like
    `tool`, `args`, `hint` that help the LLM recover.

    Any ``args`` (or other dict/list) passed in ``context`` is redacted before
    serialization so credentials in the failing call are never echoed back.
    """
    payload = {"error": msg}
    if context:
        payload.update({k: redact(v) for k, v in context.items()})
    return [TextContent(type="text", text=json.dumps(payload, indent=2, default=str))]
