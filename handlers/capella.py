"""handlers/capella.py — Phase 7: Couchbase Capella v4 control plane (read-only).

DIFFERENT FROM THE REST OF THIS MCP
====================================
The Capella v4 API is the Couchbase Capella *organization-level* control
plane — it manages orgs, projects, clusters, users, allowlists, and API keys
at the SaaS layer. It is NOT the per-cluster management API (port 8091/18091)
that the other admin_* tools in this MCP use.

  Capella v4 base URL:   https://cloudapi.cloud.couchbase.com
  Auth:                  Bearer <CAPELLA_API_KEY_SECRET>
  Resource hierarchy:    /v4/organizations/{orgId}/projects/{projectId}/clusters/{clusterId}/...

This module has its OWN request helper (`_capella_request`) because:
  - Different base URL (env var, not derived from CB_CONNECTION_STRING)
  - Different auth header (Bearer token, not Basic)
  - Different TLS handling (Capella uses a publicly-trusted cert — no
    CB_CA_CERT_PATH or mTLS plumbing applies)

ENV VARS
========
  CAPELLA_API_KEY_SECRET    Required. The API key secret created in the
                            Capella UI under "Settings → API Keys → Create
                            API Key". This is the *secret* part of the key
                            pair, used as the Bearer token directly.
  CAPELLA_BASE_URL          Optional. Defaults to https://cloudapi.cloud.couchbase.com.
                            Override only if you're testing against a
                            non-production Capella endpoint.
  CAPELLA_HTTP_TIMEOUT      Optional. Per-request timeout (default 30s).
  CAPELLA_HTTP_RETRIES      Optional. Retry count for transient failures
                            (default 3).

SCOPE
=====
This phase delivers READ-ONLY tools (list + get) across the full resource
hierarchy. Write operations (project/cluster create/delete, user management,
API-key rotation) are explicitly out of scope — the cost of an LLM-driven
write to a production Capella org outweighs the convenience.

To enable writes later, extend each affected handler with POST/PUT/DELETE
variants behind a confirm:true gate.

Tools (16, all read-only):
  capella_organizations_list, capella_organization_get
  capella_projects_list, capella_project_get
  capella_clusters_list, capella_cluster_get
  capella_database_users_list, capella_database_user_get
  capella_allowed_cidrs_list, capella_allowed_cidr_get
  capella_org_users_list, capella_org_user_get
  capella_api_keys_list, capella_api_key_get
  capella_app_services_list, capella_app_service_get
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

from .shared import err, get_env, get_env_int, ok

_DEFAULT_CAPELLA_BASE = "https://cloudapi.cloud.couchbase.com"


def _capella_base_url() -> str:
    """Resolve the Capella API base URL, with sensible default."""
    return os.environ.get("CAPELLA_BASE_URL", _DEFAULT_CAPELLA_BASE).rstrip("/")


def _capella_secret() -> str:
    """Read the Capella API key secret. Raises if unset (same fail-loud pattern
    as the rest of the MCP)."""
    return get_env("CAPELLA_API_KEY_SECRET")


def _retryable(status: int) -> bool:
    return status in (408, 425, 429, 500, 502, 503, 504)


def _capella_request(
    method: str,
    path: str,
    params: dict | None = None,
) -> Any:
    """GET-only Capella v4 request (this module is read-only).

    Retries on transient failures with exponential backoff, like admin_request.
    Returns parsed JSON; raises RuntimeError with diagnostic context on
    permanent failure.
    """
    secret = _capella_secret()
    base = _capella_base_url()
    if not path.startswith("/"):
        path = "/" + path
    url = base + path
    if params:
        # Filter Nones and serialize.
        cleaned = {k: v for k, v in params.items() if v is not None}
        if cleaned:
            url += "?" + urllib.parse.urlencode(cleaned)

    headers = {
        "Authorization": f"Bearer {secret}",
        "Accept": "application/json",
    }

    timeout = get_env_int("CAPELLA_HTTP_TIMEOUT", 30)
    max_attempts = get_env_int("CAPELLA_HTTP_RETRIES", 3)
    base_backoff = 0.5

    # Capella uses a publicly-trusted cert; default SSL context is correct.
    context = ssl.create_default_context()

    last_error: str | None = None
    for attempt in range(1, max_attempts + 1):
        req = urllib.request.Request(url, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                raw = resp.read()
                if not raw:
                    return {"status": "ok"}
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return {"status": "ok", "body": raw.decode(errors="replace")}
        except urllib.error.HTTPError as exc:
            body_bytes = exc.read() if hasattr(exc, "read") else b""
            try:
                detail = json.loads(body_bytes)
            except Exception:
                detail = body_bytes.decode(errors="replace")
            last_error = f"HTTP {exc.code} on {method} {path}: {detail}"
            if _retryable(exc.code) and attempt < max_attempts:
                time.sleep(base_backoff * (2 ** (attempt - 1)))
                continue
            raise RuntimeError(last_error) from exc
        except urllib.error.URLError as exc:
            last_error = f"Network error on {method} {path}: {exc.reason}"
            if attempt < max_attempts:
                time.sleep(base_backoff * (2 ** (attempt - 1)))
                continue
            raise RuntimeError(last_error) from exc

    raise RuntimeError(last_error or "Unknown error after retries")


# ── Tool definitions ─────────────────────────────────────────────────────────


def _org_id_schema() -> dict:
    return {"type": "string", "description": "Capella organization UUID"}


def _project_id_schema() -> dict:
    return {"type": "string", "description": "Capella project UUID"}


def _cluster_id_schema() -> dict:
    return {"type": "string", "description": "Capella cluster UUID"}


_RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)


TOOLS: list[Tool] = [
    Tool(
        name="capella_organizations_list",
        description=(
            "List organizations the configured API key has access to. "
            "Typically returns one organization. Use this as a connectivity "
            "check after configuring CAPELLA_API_KEY_SECRET."
        ),
        inputSchema={"type": "object", "properties": {}},
        annotations=_RO,
    ),
    Tool(
        name="capella_organization_get",
        description="Get details of a specific Capella organization.",
        inputSchema={
            "type": "object",
            "properties": {"organization_id": _org_id_schema()},
            "required": ["organization_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_projects_list",
        description="List all projects in an organization.",
        inputSchema={
            "type": "object",
            "properties": {"organization_id": _org_id_schema()},
            "required": ["organization_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_project_get",
        description="Get details of a specific project.",
        inputSchema={
            "type": "object",
            "properties": {
                "organization_id": _org_id_schema(),
                "project_id": _project_id_schema(),
            },
            "required": ["organization_id", "project_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_clusters_list",
        description="List clusters in a project (Capella operational deployments).",
        inputSchema={
            "type": "object",
            "properties": {
                "organization_id": _org_id_schema(),
                "project_id": _project_id_schema(),
            },
            "required": ["organization_id", "project_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_cluster_get",
        description=(
            "Get details of a specific cluster: cloud provider, region, "
            "service groups, support plan, current state."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "organization_id": _org_id_schema(),
                "project_id": _project_id_schema(),
                "cluster_id": _cluster_id_schema(),
            },
            "required": ["organization_id", "project_id", "cluster_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_database_users_list",
        description=(
            "List database credentials (cluster-scoped users for the Couchbase "
            "data plane) on a specific cluster. Different from "
            "capella_org_users_list which is org-level Capella access."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "organization_id": _org_id_schema(),
                "project_id": _project_id_schema(),
                "cluster_id": _cluster_id_schema(),
            },
            "required": ["organization_id", "project_id", "cluster_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_database_user_get",
        description="Get a specific database credential's details.",
        inputSchema={
            "type": "object",
            "properties": {
                "organization_id": _org_id_schema(),
                "project_id": _project_id_schema(),
                "cluster_id": _cluster_id_schema(),
                "user_id": {"type": "string"},
            },
            "required": ["organization_id", "project_id", "cluster_id", "user_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_allowed_cidrs_list",
        description=(
            "List the IP allowlist (CIDR blocks) for a cluster. Capella only "
            "accepts client connections from allowed CIDRs."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "organization_id": _org_id_schema(),
                "project_id": _project_id_schema(),
                "cluster_id": _cluster_id_schema(),
            },
            "required": ["organization_id", "project_id", "cluster_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_allowed_cidr_get",
        description="Get details of a specific allowlist entry.",
        inputSchema={
            "type": "object",
            "properties": {
                "organization_id": _org_id_schema(),
                "project_id": _project_id_schema(),
                "cluster_id": _cluster_id_schema(),
                "allowed_cidr_id": {"type": "string"},
            },
            "required": [
                "organization_id",
                "project_id",
                "cluster_id",
                "allowed_cidr_id",
            ],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_org_users_list",
        description=(
            "List Capella users at the organization level (people with "
            "Capella UI / API access, distinct from per-cluster database "
            "users). Each user has an org-level role and per-project roles."
        ),
        inputSchema={
            "type": "object",
            "properties": {"organization_id": _org_id_schema()},
            "required": ["organization_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_org_user_get",
        description="Get details of a specific organization user.",
        inputSchema={
            "type": "object",
            "properties": {
                "organization_id": _org_id_schema(),
                "user_id": {"type": "string"},
            },
            "required": ["organization_id", "user_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_api_keys_list",
        description=(
            "List API keys in an organization. Returns metadata only "
            "(the secret part of each key is not retrievable post-creation)."
        ),
        inputSchema={
            "type": "object",
            "properties": {"organization_id": _org_id_schema()},
            "required": ["organization_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_api_key_get",
        description="Get metadata for a specific API key.",
        inputSchema={
            "type": "object",
            "properties": {
                "organization_id": _org_id_schema(),
                "api_key_id": {"type": "string"},
            },
            "required": ["organization_id", "api_key_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_app_services_list",
        description=(
            "List App Services (Couchbase Mobile / Sync Gateway managed "
            "endpoints) attached to a cluster."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "organization_id": _org_id_schema(),
                "project_id": _project_id_schema(),
            },
            "required": ["organization_id", "project_id"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_app_service_get",
        description="Get details of a specific App Service.",
        inputSchema={
            "type": "object",
            "properties": {
                "organization_id": _org_id_schema(),
                "project_id": _project_id_schema(),
                "app_service_id": {"type": "string"},
            },
            "required": ["organization_id", "project_id", "app_service_id"],
        },
        annotations=_RO,
    ),
]


# ── Handler ──────────────────────────────────────────────────────────────────


def _path(*segments: str) -> str:
    """Build a URL-encoded path. Each segment is encoded individually."""
    parts = []
    for s in segments:
        if s.startswith("/"):
            s = s[1:]
        parts.append(urllib.parse.quote(s, safe=""))
    return "/v4/" + "/".join(parts)


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        org = args.get("organization_id", "")
        proj = args.get("project_id", "")
        cl = args.get("cluster_id", "")

        if name == "capella_organizations_list":
            return ok(_capella_request("GET", "/v4/organizations"))

        if name == "capella_organization_get":
            return ok(_capella_request("GET", _path("organizations", org)))

        if name == "capella_projects_list":
            return ok(_capella_request("GET", _path("organizations", org, "projects")))

        if name == "capella_project_get":
            return ok(
                _capella_request("GET", _path("organizations", org, "projects", proj))
            )

        if name == "capella_clusters_list":
            return ok(
                _capella_request(
                    "GET", _path("organizations", org, "projects", proj, "clusters")
                )
            )

        if name == "capella_cluster_get":
            return ok(
                _capella_request(
                    "GET", _path("organizations", org, "projects", proj, "clusters", cl)
                )
            )

        if name == "capella_database_users_list":
            return ok(
                _capella_request(
                    "GET",
                    _path(
                        "organizations", org, "projects", proj, "clusters", cl, "users"
                    ),
                )
            )

        if name == "capella_database_user_get":
            return ok(
                _capella_request(
                    "GET",
                    _path(
                        "organizations",
                        org,
                        "projects",
                        proj,
                        "clusters",
                        cl,
                        "users",
                        args["user_id"],
                    ),
                )
            )

        if name == "capella_allowed_cidrs_list":
            return ok(
                _capella_request(
                    "GET",
                    _path(
                        "organizations",
                        org,
                        "projects",
                        proj,
                        "clusters",
                        cl,
                        "allowedcidrs",
                    ),
                )
            )

        if name == "capella_allowed_cidr_get":
            return ok(
                _capella_request(
                    "GET",
                    _path(
                        "organizations",
                        org,
                        "projects",
                        proj,
                        "clusters",
                        cl,
                        "allowedcidrs",
                        args["allowed_cidr_id"],
                    ),
                )
            )

        if name == "capella_org_users_list":
            return ok(_capella_request("GET", _path("organizations", org, "users")))

        if name == "capella_org_user_get":
            return ok(
                _capella_request(
                    "GET", _path("organizations", org, "users", args["user_id"])
                )
            )

        if name == "capella_api_keys_list":
            return ok(_capella_request("GET", _path("organizations", org, "apikeys")))

        if name == "capella_api_key_get":
            return ok(
                _capella_request(
                    "GET", _path("organizations", org, "apikeys", args["api_key_id"])
                )
            )

        if name == "capella_app_services_list":
            return ok(
                _capella_request(
                    "GET", _path("organizations", org, "projects", proj, "appservices")
                )
            )

        if name == "capella_app_service_get":
            return ok(
                _capella_request(
                    "GET",
                    _path(
                        "organizations",
                        org,
                        "projects",
                        proj,
                        "appservices",
                        args["app_service_id"],
                    ),
                )
            )

        return err(f"Unknown Capella tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
