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


class _RequiredSentinel:
    """Marks a variable as REQUIRED, recognised by type name rather than by identity.

    `_REQUIRED = object()` looked fine and had a sharp edge. A function's default argument is
    bound once, at definition time, while the `is _REQUIRED` check inside reads the CURRENT
    module global. Reload this module — a test does, and so does any tooling that reloads —
    and those become two different objects. The identity check then fails, and `get_env`
    returns THE SENTINEL OBJECT instead of raising.

    That is the worst possible failure for this function: a missing required credential comes
    back as a truthy object and is passed onward. It surfaced as
    `handlers.capella.client._secret()` quietly returning `<object object at 0x...>` for an
    unset CAPELLA_API_KEY_SECRET, which would then be sent as a Bearer token.

    Comparing the TYPE NAME survives a reload, because the name is what is stable across
    re-execution of the module.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return "<required>"


_REQUIRED = _RequiredSentinel()


def _is_required(default: Any) -> bool:
    """Whether `default` is the required-marker, across module reloads."""
    return type(default).__name__ == "_RequiredSentinel"


def get_env(key: str, default: Any = _REQUIRED) -> str | None:
    """Get an env var. If no default is given and it is unset, raise at call time."""
    val = os.environ.get(key)
    if val is None or val == "":
        if _is_required(default):
            raise RuntimeError(
                f"Required environment variable {key} is not set. "
                f"Set it before starting the MCP server."
            )
        return default
    return val


#: The single accepted spelling set for boolean environment variables.
#:
#: Five call sites accepted "on" and one did not, so CB_ADMIN_HTTP_REQUIRE_AUTH=on
#: made the edge middleware stop rejecting a missing token while check_scope still
#: denied. Tool calls failed closed, but the MCP handshake and list_tools succeeded
#: unauthenticated — disclosing the whole admin surface and the deployment mode.
TRUTHY_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on", "y", "t"})


def env_truthy(key: str, default: bool = False) -> bool:
    """Read a boolean env var with ONE consistent notion of truth."""
    raw = (os.environ.get(key) or "").strip().lower()
    if not raw:
        return default
    return raw in TRUTHY_VALUES


def get_env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in TRUTHY_VALUES


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
_MAX_ATTEMPTS = max(1, get_env_int("CB_ADMIN_HTTP_RETRIES", 3))
_BASE_BACKOFF = 0.5  # seconds; doubles each attempt
# A timeout of 0 reaches urlopen as a non-blocking socket and fails
# instantly; clamp rather than let a stray 0 look like "no timeout".
_HTTP_TIMEOUT = max(1, get_env_int("CB_ADMIN_HTTP_TIMEOUT", 30))


#: Safe to repeat: repeating cannot create a second resource or re-run an action.
_IDEMPOTENT_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "PUT", "DELETE"})

#: The server rejected or never began the request, so nothing was applied.
_UNPROCESSED_STATUSES: frozenset[int] = frozenset({408, 425, 429})


def _retryable(status: int, method: str = "GET") -> bool:
    """Whether to retry, accounting for whether the method is safe to repeat.

    A POST whose response is lost to a timeout or a 502 may already have been
    applied. Retrying it re-runs the action — and on this API the actions include
    ``/controller/failOver``, ``/controller/doFlush`` and rebalance. Re-issuing a
    failover because a read timed out is worse than reporting the failure, so
    non-idempotent methods retry only on statuses that prove nothing happened.
    """
    if status in _UNPROCESSED_STATUSES:
        return True
    if status in (500, 502, 503, 504):
        return method.upper() in _IDEMPOTENT_METHODS
    return False


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
            if _retryable(exc.code, method) and attempt < _MAX_ATTEMPTS:
                time.sleep(_BASE_BACKOFF * (2 ** (attempt - 1)))
                continue
            raise RuntimeError(last_error) from exc
        except urllib.error.URLError as exc:
            last_error = f"Network error on {method} {path}: {exc.reason}"
            # A dropped connection on a mutating call cannot be distinguished
            # from "applied, reply lost", so it is not retried.
            if method.upper() in _IDEMPOTENT_METHODS and attempt < _MAX_ATTEMPTS:
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
    (?P<kw>INSERT|UPSERT|UPDATE|DELETE|MERGE|CREATE|DROP|BUILD|ALTER|GRANT|REVOKE|EXECUTE|INFER)
    \b
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)


def _lex_sql_literals(text: str) -> tuple[str, bool]:
    """Blank out quoted spans, and report whether the text ended inside a literal.

    Without this, `;`, `--` and `/*` matched anywhere in the string, so ordinary
    statements were refused with a misleading message:

        SELECT * FROM `b` WHERE code = 'A;B'    -> "statement chaining"
        SELECT * FROM `b` WHERE note = 'x--y'   -> "comments not permitted"
        SELECT * FROM `orders;archive`          -> "statement chaining"

    A statement pulled from system:completed_requests and handed to the index
    advisor plausibly contains all three.

    The second return value matters. An UNTERMINATED quote blanks everything from the
    quote to the end of the string, so the chaining and comment scans saw an empty
    tail and PASSED a statement this function could not actually lex — a trailing
    unclosed quote followed by a second statement sailed through the chaining check.
    Refusing is the only honest answer there: the guard cannot say what the query
    service will make of it, and "I could not parse this, so I allowed it" is the
    wrong direction for a control.
    """
    out: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and quote in ("'", '"'):
                out.append(" ")
                i += 2
                continue
            if ch == quote:
                # A doubled quote is an escaped quote: still inside the literal.
                if i + 1 < len(text) and text[i + 1] == quote:
                    out.append(" ")
                    i += 2
                    continue
                quote = None
            out.append(" ")
        elif ch in ("'", '"', "`"):
            quote = ch
            out.append(" ")
        else:
            out.append(ch)
        i += 1
    return "".join(out), quote is not None


def _strip_sql_literals(text: str) -> str:
    """The blanked text only, for callers that do not care about termination."""
    stripped, _unterminated = _lex_sql_literals(text)
    return stripped


def is_dml_statement(stmt: str) -> bool:
    """Return True if the SQL++ statement writes.

    Conservative on genuine ambiguity — an unterminated block comment or a BOM
    counts as DML, because guessing "read-only" on an unparseable statement is the
    expensive direction to be wrong in.

    NOT conservative about ``WITH``, though. Treating every WITH-prefixed statement
    as a write refused legitimate read-only CTEs
    (``WITH t AS (SELECT 1) SELECT * FROM t``), which disabled the diagnostic tools
    for exactly the queries an operator brings to an index advisor. A CTE writes only
    if it contains a write keyword, so that is what is tested.
    """
    text = stmt or ""
    if not text.strip():
        return False
    if "\ufeff" in text[:4]:  # a BOM defeats \s in the pattern
        return True
    # Opened-but-unclosed block comment: the comment-skipping group matches zero
    # times, the keyword match then fails, and a mutation reads as read-only.
    if text.count("/*") != text.count("*/"):
        return True

    stripped = _strip_sql_literals(text)
    if re.match(r"^\s*WITH\b", stripped, re.IGNORECASE):
        return bool(
            re.search(
                r"\b(INSERT|UPSERT|UPDATE|DELETE|MERGE|CREATE|DROP|ALTER|GRANT"
                r"|REVOKE|EXECUTE)\b",
                stripped,
                re.IGNORECASE,
            )
        )
    return bool(_DML_RE.match(text))


def assert_read_only_statement(stmt: str, *, tool: str) -> str | None:
    """Refuse a data-modifying SQL++ statement UNCONDITIONALLY.

    Distinct from block_dml_if_readonly, which only refuses while
    CB_ADMIN_READ_ONLY_MODE is on. The diagnostic tools — EXPLAIN, the index
    advisor, schema inference, the completed-requests advisors — exist to inspect a
    workload. There is no configuration under which they should modify data, so they
    do not consult read-only mode at all: a mutation handed to a debug tool is
    refused whether or not writes are enabled elsewhere.

    Writes still happen, of course — through the purpose-built admin_* tools, which
    are annotated, gated and audited as writes. A statement parameter on a read tool
    is simply not one of those routes.
    """
    chained = assert_single_statement(stmt)
    if chained:
        return chained
    if is_dml_statement(stmt):
        return (
            f"`{tool}` is a read-only diagnostic tool and will not execute a "
            "statement that modifies data or schema. Use the purpose-built "
            "admin_* tool for the change you intend — those are annotated, gated "
            "and audited as writes."
        )
    return None


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


def assert_single_statement(stmt: str) -> str | None:
    """Reject statement chaining and comment tricks in a caller-supplied SQL++.

    The DDL validators below anchor at the START of the string only, so
    ``CREATE INDEX i ON `b`(x); DROP SCOPE `b`.`prod``` satisfied them and was
    forwarded verbatim. The only thing that stopped the second statement running
    was the query service's own single-statement rule — an undocumented server
    behaviour this server does not own and must not depend on.

    Comments are refused for the same reason: a trailing ``--`` silently discards
    the rest of a generated statement (for example the WITH clause carrying an
    index's dimension and similarity), so what executes differs from what the
    operator confirmed.
    """
    text, unterminated = _lex_sql_literals(stmt or "")
    if unterminated:
        return (
            "Unterminated quote in the statement, so it could not be parsed and the "
            "chaining and comment checks cannot be applied to it. Refusing rather "
            "than forwarding a statement this server was unable to read. Close the "
            "quote, or double it if a literal quote was intended."
        )
    if re.search(r";\s*\S", text):
        return (
            "Statement chaining is not permitted: this parameter accepts exactly "
            "one statement. Remove everything after the first ';' (semicolons "
            "inside string literals and quoted identifiers are fine)."
        )
    if "--" in text or "/*" in text:
        return (
            "SQL++ comments are not permitted in this parameter, because a "
            "trailing comment can silently discard part of the statement that "
            "was reviewed. Remove '--' and '/*' (occurrences inside string "
            "literals and quoted identifiers are fine)."
        )
    return None


def assert_index_create_ddl(stmt: str) -> str | None:
    """Validate that a raw statement is index-creation DDL.
    Returns error message if not, else None.
    Prevents `admin_index_create` from being used to execute arbitrary SQL++."""
    chained = assert_single_statement(stmt)
    if chained:
        return chained
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
    chained = assert_single_statement(stmt)
    if chained:
        return chained
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
    if isinstance(v, (list, tuple, dict)):
        # str() on a list yields a Python repr with single quotes, which the
        # cluster cannot parse. On /settings/security's cipherSuites an
        # unparseable value means "use defaults" — a silent TLS downgrade — and
        # on audit disabledUsers it means the exemption never applies.
        return json.dumps(v)
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


def schema_keys(tool_name: str, tools: Iterable[Any]) -> frozenset[str]:
    """The argument names a tool's own inputSchema declares.

    Memo-free and cheap; the tool lists are small and built once at import.
    """
    for tool in tools:
        if getattr(tool, "name", None) == tool_name:
            schema = getattr(tool, "inputSchema", None) or {}
            props = schema.get("properties") or {}
            return frozenset(props)
    return frozenset()


def form_data_declared(
    args: dict,
    tool_name: str,
    tools: Iterable[Any],
    *,
    exclude: Iterable[str] = ("confirm",),
    extra_allowed: Iterable[str] = (),
) -> dict:
    """form_data(), restricted to keys the tool actually declares.

    MASS ASSIGNMENT. Several settings tools did ``form_data(args)`` and POSTed the
    result to a Couchbase settings endpoint, which meant every key the caller
    supplied was forwarded verbatim — including ones the tool never advertised and
    the model simply invented. ``/settings/security``, ``/settings/indexes`` and
    ``/pools/default`` all accept fields well beyond what these tools expose, so a
    hallucinated or hostile key became a real configuration change to a security
    endpoint.

    Deriving the allow-list from the tool's OWN schema rather than a hand-written set
    is deliberate: seven separate literal sets would be seven things to forget when a
    parameter is added, and the previous per-tool sets had already drifted. If it is
    not in the schema the model was shown, it does not go on the wire.

    Unknown keys are DROPPED here, but every caller pairs this with
    ``refuse_undeclared()`` so the caller is told. Silently dropping is the worse
    failure for an agent: it reports success while the setting it asked for was never
    applied, and the model has no way to learn that the parameter does not exist.
    """
    allowed = schema_keys(tool_name, tools) | frozenset(extra_allowed)
    filtered = {k: v for k, v in args.items() if k in allowed}
    return form_data(filtered, exclude=exclude)


def refuse_undeclared(
    args: dict,
    tool_name: str,
    tools: Iterable[Any],
    *,
    exclude: Iterable[str] = ("confirm",),
    extra_allowed: Iterable[str] = (),
    endpoint: str = "",
) -> list[TextContent] | None:
    """err() naming any argument the tool does not declare, or None if all are known.

    Refusing beats dropping: the caller finds out that `checkpointInterval` is not a
    parameter of this tool instead of believing a no-op succeeded.
    """
    unknown = rejected_keys(
        args, tool_name, tools, exclude=exclude, extra_allowed=extra_allowed
    )
    if not unknown:
        return None
    declared = sorted(schema_keys(tool_name, tools))
    target = endpoint or "a Couchbase settings endpoint"
    return err(
        f"Unrecognised argument(s) for {tool_name}: {unknown}.",
        tool=tool_name,
        hint=(
            f"This tool forwards its arguments to {target}, which accepts more fields "
            "than the tool exposes — so an undeclared key would become a real "
            "configuration change that was never reviewed. Refusing rather than "
            "silently dropping it, because a dropped key looks like success. "
            f"Declared parameters: {declared}."
        ),
        declared_parameters=declared,
    )


def rejected_keys(
    args: dict,
    tool_name: str,
    tools: Iterable[Any],
    *,
    exclude: Iterable[str] = ("confirm",),
    extra_allowed: Iterable[str] = (),
) -> list[str]:
    """Keys that form_data_declared() would silently drop. For a clear refusal."""
    allowed = schema_keys(tool_name, tools) | frozenset(extra_allowed) | set(exclude)
    return sorted(k for k in args if k not in allowed)


# ── Redaction ────────────────────────────────────────────────────────────────

# Substrings (case-insensitive) that mark a field as sensitive. A key is
# redacted if it CONTAINS any of these — so "password", "new_password", and
# "adminPassword" all match. Kept as substrings rather than exact names because
# the admin surface spans many services with inconsistent field naming.
_SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "password",
    # "pass"/"pwd"/"passwd" matter on their own: Couchbase's alerts endpoint
    # names its SMTP password field `emailPass`, which does NOT contain
    # "password", so it was logged and echoed in plaintext.
    "pass",
    "pwd",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "credential",
    "private_key",
    "privatekey",
    "apikey",
    "api_key",
    "bearer",
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
        # ok() now redacts EVERY response, so a bare-substring rule on
        # "pass"/"auth"/"token" actively corrupts data an agent reads and writes
        # back. The concrete case: an FTS index definition's analysis section, where
        # masking `tokenizer` and `token_filters` makes an
        # admin_fts_index_get -> admin_fts_index_create round-trip write
        # "***REDACTED***" into the cluster.
        "tokenizer",
        "tokenizers",
        "token_filters",
        "token_maps",
        "author",
        "authtype",
        "auth_type",
        "authentication",
        "oauth_enabled",
        "bypass",
        "compass",
        "passive",
        "passthrough",
    }
)

REDACTED = "***REDACTED***"


def _is_sensitive_key(key: str) -> bool:
    k = key.lower()
    if k in _SENSITIVE_KEY_ALLOW:
        return False
    return any(part in k for part in _SENSITIVE_KEY_PARTS)


#: Depth beyond which redact() stops recursing. A caller-supplied argument nested
#: ~500 deep raised RecursionError inside the audit path — after the handler had
#: already executed — so the bucket was gone and the record was never written.
_REDACT_MAX_DEPTH = 24


def redact(value: Any, _depth: int = 0) -> Any:
    """Return a deep copy of ``value`` with sensitive fields masked.

    Recurses through dicts and lists. Any dict key whose name indicates a
    credential (see ``_SENSITIVE_KEY_PARTS``) has its value replaced with
    ``REDACTED`` regardless of the value's type. Non-container values pass
    through unchanged. Used on both logged call arguments and the ``args``
    echoed back in error context, so a failed ``admin_user_create`` never
    surfaces the plaintext password to the agent or the logs.
    """
    if _depth > _REDACT_MAX_DEPTH:
        return "...(nesting depth capped)"
    if isinstance(value, dict):
        return {
            k: (REDACTED if _is_sensitive_key(k) else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth + 1) for v in value]
    return value


def ok(data: Any) -> list[TextContent]:
    """Successful tool response, with credential material masked.

    Redaction used to apply only to logs and to err() context, so every
    SUCCESSFUL response was dumped verbatim into the model's context. That leaked
    real secrets from tools that are annotated read-only and therefore load in
    the "safe" default deployment: admin_alerts_get returns the SMTP password,
    admin_kmip_get the KMIP key configuration, admin_eventing_get the function
    source (which routinely embeds API keys), admin_xdcr_references_list the
    remote-cluster credentials.

    A read tool returning a secret is still a credential disclosure. Responses
    are now masked on the same rules as logs.
    """
    return [
        TextContent(type="text", text=json.dumps(redact(data), indent=2, default=str))
    ]


def ok_allow_secrets(data: Any) -> list[TextContent]:
    """Successful response that is permitted to carry credential material.

    THE ONLY SANCTIONED EXCEPTION to ok()'s redaction, and deliberately named so
    that every use is greppable and has to be justified in review.

    It exists for exactly one case: Capella returns a generated database-credential
    password once, at creation, and never again. A test client cannot connect
    without it, and masking it would leave the caller holding an unusable
    environment with no way to recover the password except deleting and recreating
    the credential. So capella_env_ensure surfaces it a single time, at the moment
    of creation, and says so in the payload.

    Anything else returning a secret is a bug — use ok().
    """
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


#: Key stamped into every err() payload so the audit classifier can distinguish a
#: refusal from a success that happens to mention an error. Underscore-prefixed to
#: make collision with a Couchbase REST field impossible.
ERROR_MARKER = "_is_error"


#: Identifier endings that mark a name as STRUCTURAL rather than a secret, even though
#: it contains a sensitive fragment. `admin_password_policy_set` is a tool name;
#: `passwordMinLength` is a policy field. Without this the masking swallowed the useful
#: half of ordinary diagnostics.
_NON_SECRET_ENDINGS: tuple[str, ...] = (
    "set",
    "get",
    "list",
    "policy",
    "date",
    "hash",
    "length",
    "expiry",
    "expiration",
    "enabled",
    "disabled",
    "required",
    "type",
    "format",
    "count",
    "age",
    "min",
    "max",
    "name",
    "id",
)
# NOTE: "field" is deliberately NOT here. `password_field=s3cret` names a credential
# despite sounding structural, and treating it as structural left the secret in the
# clear.


def _is_secret_identifier(name: str) -> bool:
    """Whether a key name in free text denotes a credential VALUE.

    Two rules, because one alone was wrong in each direction:

      * ends with a sensitive fragment -> yes (``password``, ``adminPassword``,
        ``emailPass``, ``token``, ``clientSecret``).
      * merely CONTAINS one -> yes only if it does not end in a structural word.
        Pure substring matching masked ``admin_password_policy_set: [...]``; pure
        suffix matching missed ``passwordValue=`` and ``user_password_new=``.
    """
    bare = name.strip("\"'").lower()
    if not bare or bare in _SENSITIVE_KEY_ALLOW:
        return False
    if bare.endswith(tuple(_SENSITIVE_KEY_PARTS)):
        return True
    if any(fragment in bare for fragment in _SENSITIVE_KEY_PARTS):
        return not bare.endswith(_NON_SECRET_ENDINGS)
    return False


def _value_is_prose(value: str) -> bool:
    """Whether a value reads as an explanation rather than a credential.

    A cluster that REJECTS a password echoes the reason back in the same field:

        {"errors":{"password":"The password must be at least 6 characters long"}}

    Masking that leaves an autonomous agent with ``***REDACTED***`` and no way to
    self-correct — it retries the same invalid password forever. Credentials are single
    tokens; validation messages are sentences. So a multi-word value is treated as
    prose and preserved.

    The residual risk is a genuine passphrase containing spaces being echoed back by an
    endpoint. That is narrow, and blinding the automation is the larger harm here.
    """
    inner = value.strip().strip("\"'")
    # An auth scheme plus its credential is two "words" and is never prose.
    if re.match(r"^(?:Bearer|Basic|Digest)\s", inner, re.IGNORECASE):
        return False
    return len(inner.split()) >= 3


#: A password inside a URI's userinfo component: scheme://user:PASSWORD@host.
#:
#: "/", "?", "#" and whitespace end the authority, so excluding them is what stops this
#: matching an "@" that appears later in a path or query — `?filter=a@b.com` and
#: `http://host:8080/a@b` both correctly fail to match.
#:
#: The password class deliberately ALLOWS "@" and is greedy, so it runs to the LAST "@"
#: before the host. RFC 3986 requires a literal "@" in a password to be percent-encoded, but
#: people do paste raw ones, and with "@" excluded the match stopped at the first one and
#: left the rest of the password in the clear — `admin:p@ssword@host` masked as
#: `admin:***REDACTED***@ssword@host`. Over-masking a host is harmless; under-masking a
#: password is the whole bug.
_URI_CREDENTIAL_RE = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)"
    r"(?P<user>[^/?#@\s:]+)"
    r":(?P<password>[^/?#\s]*)"
    r"(?=@)"
)


def redact_uri_credentials(text: str) -> str:
    """Mask the password in any `scheme://user:password@host` URI inside `text`.

    None of the other rules catch this. `redact()` masks by KEY NAME, and the key here is
    `connection_string`, which contains no credential-looking word. `redact_text()` masks
    `key: value` assignments, and a URI is one value. So `cb_mcp_status` — annotated
    read-only, and therefore loaded in the safest deployment — returned
    CB_CONNECTION_STRING verbatim, handing the cluster password to any caller holding a
    read-only token.

    The username is deliberately KEPT. It is not the secret, and "which account is this
    server using?" is the main reason someone reads this field.
    """
    if not isinstance(text, str) or not text:
        return text
    return _URI_CREDENTIAL_RE.sub(
        lambda m: f"{m.group('scheme')}{m.group('user')}:{REDACTED}", text
    )


def redact_text(text: str) -> str:
    """Mask credential-looking assignments inside a free-form string.

    redact() walks dicts and lists; a bare string was returned unchanged. Exception
    messages are the one place attacker- and cluster-influenced text enters a response
    and a log line without passing through a dict, so they need their own pass.
    """
    if not isinstance(text, str) or not text:
        return text

    # Connection strings reach logs and error messages constantly — "failed to connect to
    # couchbase://admin:pw@host" is the single most likely place this leaks.
    text = redact_uri_credentials(text)

    fragments = "|".join(re.escape(part) for part in _SENSITIVE_KEY_PARTS)
    pattern = re.compile(
        r"(?P<key>[\"\']?[\w.-]*?(?:" + fragments + r")[\w.-]*[\"\']?)"
        r"(?P<sep>\s*[:=]+\s*)"
        # A scheme-prefixed value is ONE value. Without this alternative the value
        # matched only the word "Bearer", so `Authorization: Bearer <jwt>` became
        # `Authorization: ***REDACTED*** <jwt>` — the label masked and the credential
        # left in place, which is worse than not matching at all.
        r"(?P<val>(?:Bearer|Basic|Digest)\s+[A-Za-z0-9._~+/=-]+"
        r"|\"[^\"]*\"|\'[^\']*\'|[^\s,;&}\)\]]+)",
        re.IGNORECASE,
    )

    def _mask(match: re.Match) -> str:
        if not _is_secret_identifier(match.group("key")):
            return match.group(0)
        if _value_is_prose(match.group("val")):
            return match.group(0)
        return f"{match.group('key')}{match.group('sep')}{REDACTED}"

    text = pattern.sub(_mask, text)

    # `Authorization: Bearer <jwt>` carries the credential in the VALUE with no
    # sensitive key name at all, and a space between scheme and token — so neither rule
    # above sees it. It is the single most common way a token reaches a log.
    return re.sub(
        r"\b(Bearer|Basic|Digest)\s+([A-Za-z0-9._~+/=-]{8,})",
        lambda m: f"{m.group(1)} {REDACTED}",
        text,
        flags=re.IGNORECASE,
    )


def err(msg: str, **context) -> list[TextContent]:
    """Structured error response. `context` adds diagnostic fields like
    `tool`, `args`, `hint` that help the LLM recover.

    Any ``args`` (or other dict/list) passed in ``context`` is redacted before
    serialization so credentials in the failing call are never echoed back.
    """
    # The MESSAGE is redacted too, not just the context.
    #
    # Only `context` values went through redact(), and redact() is a no-op on a bare
    # string — so `err(f"{type(exc).__name__}: {exc}")` in every handler's except
    # block passed the exception text through untouched, and admin_request folds the
    # cluster's raw response body into that text. Any endpoint that echoes a submitted
    # field back on error would put it in the response and the log.
    payload = {"error": redact_text(msg)}
    if context:
        payload.update({k: redact(v) for k, v in context.items()})
    # Machine-readable discriminator for the audit classifier. Reading back the
    # presence of an "error" KEY was wrong: several handlers return a SUCCESS payload
    # that carries a top-level "error" describing a sub-resource problem (a phase
    # result, a per-item failure in a batch), and those were being recorded as
    # denials — which corrupts exactly the record an auditor relies on. Only err()
    # sets this, so only err() can be classified as a refusal.
    payload[ERROR_MARKER] = True
    return [TextContent(type="text", text=json.dumps(payload, indent=2, default=str))]
