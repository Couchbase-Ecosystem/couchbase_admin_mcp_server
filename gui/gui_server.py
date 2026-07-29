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
        POST /auth/token with { "grant_type": "client_credentials" } returns a
        short-lived access token that callers supply as  Authorization: Bearer <token>
        on /api/* requests.

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
from functools import wraps
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
    stats,
    xdcr,
)
from handlers.shared import (  # noqa: E402
    _CUSTOM_CONFIRMATION_TOOLS,
    DISABLED_TOOLS,
    READ_ONLY_MODE,
    require_confirmation,
)

# ---------------------------------------------------------------------------
# OAuth feature flag
# ---------------------------------------------------------------------------
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
app = Flask(__name__, static_folder="static")

CORS(
    app,
    origins=[
        re.compile(r"^https?://localhost(:[0-9]+)?$"),
        re.compile(r"^https?://127\.0\.0\.1(:[0-9]+)?$"),
        re.compile(r"^https?://\[::1\](:[0-9]+)?$"),
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


# ---------------------------------------------------------------------------
# Safety helpers (unchanged from original)
# ---------------------------------------------------------------------------
def _is_destructive(tool) -> bool:
    return bool(tool and tool.annotations and tool.annotations.destructiveHint)


def _is_read_only(tool) -> bool:
    return bool(tool and tool.annotations and tool.annotations.readOnlyHint)


def _visible_tools():
    # Admin server has no internally-DML-gated tools, so nothing is force-loaded
    # in read-only mode beyond the annotated read-only tools.
    always_loaded_in_ro: set[str] = set()
    out = []
    for t in ALL_TOOLS:
        if t.name in DISABLED_TOOLS:
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
    if not value:
        return ""
    return "********" if key in _REDACTED_FIELDS else value


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
    "/auth/token",
    "/auth/status",
}


def _is_public(path: str) -> bool:
    return path in _PUBLIC_PATHS or path.startswith("/static/")


def require_auth(f):
    """
    Decorator that enforces authentication when OAUTH_ENABLED=true.
    - API routes: returns 401 JSON on failure.
    - Browser routes: handled by the frontend (which checks /auth/status).
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _OAUTH_ENABLED:
            return f(*args, **kwargs)
        if _is_public(request.path):
            return f(*args, **kwargs)
        claims = _resolve_claims()
        if claims is None:
            return jsonify({"error": "Unauthorized", "auth_required": True}), 401
        # Attach claims to request context for downstream use
        request.oauth_claims = claims  # type: ignore[attr-defined]
        return f(*args, **kwargs)

    return wrapper


# Apply auth check to all routes via before_request
@app.before_request
def global_auth_check():
    if not _OAUTH_ENABLED:
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
            return jsonify({"error": "Unauthorized", "auth_required": True}), 401
        # Non-API routes serve the SPA which handles the redirect
        return None
    request.oauth_claims = claims  # type: ignore[attr-defined]
    return None


# ---------------------------------------------------------------------------
# OAuth endpoints  (/auth/*)
# ---------------------------------------------------------------------------

# Temporary PKCE state store: { state: { verifier, next, created_at } }
# Entries are cleaned up on each new login attempt (max 10-minute lifetime).
_pkce_store: dict[str, dict[str, str]] = {}
_PKCE_TTL = 600  # 10 minutes — enough to complete a browser login


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

    _pkce_purge()
    state = secrets.token_urlsafe(32)
    verifier, challenge = _oidc.generate_pkce_pair()
    _pkce_store[state] = {
        "verifier": verifier,
        "next": next_url,
        "created_at": str(time.time()),
    }

    try:
        url = _oidc.build_authorization_url(state=state, code_challenge=challenge)
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500

    return redirect(url)


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

    pkce = _pkce_store.pop(state, None)
    if pkce is None:
        return jsonify(
            {
                "error": "Invalid or expired state parameter. Please try logging in again."
            }
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
        secure=request.is_secure,  # Secure flag when served over HTTPS
        samesite="Lax",
        max_age=int(os.environ.get("OAUTH_SESSION_TTL_SECONDS", "28800")),
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


@app.route("/auth/token", methods=["POST"])
def auth_token():
    """
    Client Credentials token endpoint.

    POST body (JSON):
      { "grant_type": "client_credentials" }

    Returns:
      { "access_token": "...", "token_type": "Bearer", "expires_in": N }

    The caller supplies the returned token as  Authorization: Bearer <token>
    on subsequent /api/* requests.
    """
    if not _OAUTH_ENABLED:
        return jsonify({"error": "OAuth not enabled"}), 400

    body = request.get_json(force=True) or {}
    if body.get("grant_type") != "client_credentials":
        return jsonify(
            {"error": "Only grant_type=client_credentials is supported here"}
        ), 400

    try:
        tokens = _oidc.client_credentials_token()
    except Exception as exc:
        return jsonify({"error": f"Client credentials request failed: {exc}"}), 502

    return jsonify(
        {
            "access_token": tokens.get("access_token", ""),
            "token_type": tokens.get("token_type", "Bearer"),
            "expires_in": tokens.get("expires_in", 3600),
            "scope": tokens.get("scope", ""),
        }
    )


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
                "inputSchema": tool.inputSchema,
                "readOnly": _is_read_only(tool),
                "destructive": _is_destructive(tool),
            }
        )
    return jsonify(result)


@app.route("/api/call", methods=["POST"])
def call_tool():
    body = request.get_json(force=True)
    tool_name = body.get("tool")
    arguments = body.get("arguments", {}) or {}

    if not tool_name:
        return jsonify({"error": "Missing 'tool' field"}), 400
    if tool_name in DISABLED_TOOLS:
        return jsonify(
            {"error": f"Tool '{tool_name}' is disabled by configuration"}
        ), 403

    tool = TOOL_INDEX.get(tool_name)
    if tool is None:
        return jsonify({"error": f"Unknown tool: {tool_name}"}), 404

    if (
        READ_ONLY_MODE
        and not _is_read_only(tool)
        and True  # admin server has no internally-DML-gated tools
    ):
        return jsonify(
            {
                "error": (
                    f"Tool '{tool_name}' is a write operation and "
                    "CB_ADMIN_READ_ONLY_MODE=true. Set false to enable."
                )
            }
        ), 403

    # Confirmation / automation model — mirrors server.py so the GUI exercises
    # the real trust logic. A write tool is gated unless:
    #   * the caller supplied confirm:true (interactive human), OR
    #   * the GUI session is in "automation" mode (simulating an automation-
    #     scoped principal) AND the tool is not in the hard ceiling.
    # The hard ceiling (CB_ADMIN_ALWAYS_CONFIRM) always requires confirm, even
    # in automation mode — exactly as the server enforces it.
    is_write = not (
        tool.annotations and getattr(tool.annotations, "readOnlyHint", False)
    )
    in_confirm_set = is_write or tool_name in _CUSTOM_CONFIRMATION_TOOLS

    automation_mode = bool(body.get("automation")) or (
        os.environ.get("CB_ADMIN_GUI_AUTOMATION", "").lower() in ("1", "true", "yes")
    )
    hard_ceiling = {
        n.strip()
        for n in os.environ.get("CB_ADMIN_ALWAYS_CONFIRM", "").split(",")
        if n.strip()
    }

    if in_confirm_set and automation_mode:
        if tool_name in hard_ceiling:
            # A ceiling tool under automation must not be satisfiable by a
            # self-supplied confirm:true — that is the agent rubber-stamping
            # itself. Refuse; a human must approve via a non-automation session.
            return jsonify(
                {
                    "ok": False,
                    "error": (
                        f"'{tool_name}' is in the automation hard ceiling "
                        "(CB_ADMIN_ALWAYS_CONFIRM) and cannot run under automation "
                        "mode, even with confirm:true. A human must approve it."
                    ),
                    "requires_confirmation": True,
                    "hard_ceiling": True,
                }
            ), 403
        # Authorized automation: skip the per-call human confirmation.
        in_confirm_set = False

    confirm_err = require_confirmation(tool_name, arguments, in_confirm_set)
    if confirm_err is not None:
        return jsonify(
            {
                "ok": False,
                "error": confirm_err,
                "requires_confirmation": True,
                "hard_ceiling": tool_name in hard_ceiling,
            }
        ), 403

    arguments = {k: v for k, v in arguments.items() if k != "confirm"}

    handler = HANDLERS.get(tool_name)
    if handler is None:
        return jsonify({"error": f"No handler for tool: {tool_name}"}), 500

    try:
        result = handler.handle(tool_name, arguments)
        text = result[0].text if result else "{}"
        parsed = json.loads(text)
        return jsonify({"ok": True, "result": parsed})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 200


@app.route("/api/config", methods=["GET", "POST"])
def config():
    if request.method == "POST":
        body = request.get_json(force=True) or {}
        rejected = []
        applied = []
        for key, val in body.items():
            if key not in _CONFIG_ALLOWLIST:
                rejected.append(key)
                continue
            if val is None or val == "":
                os.environ.pop(key, None)
            else:
                os.environ[key] = str(val)
            applied.append(key)

        import handlers.shared as sh

        sh._cluster = sh._bucket = sh._collection = None
        return jsonify({"ok": True, "applied": applied, "rejected": rejected})

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

    if host == "0.0.0.0" and os.environ.get("CB_GUI_ALLOW_REMOTE", "").lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        print(
            "[gui] Refusing to bind to 0.0.0.0 without CB_GUI_ALLOW_REMOTE=1.",
            file=sys.stderr,
        )
        host = "127.0.0.1"

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
