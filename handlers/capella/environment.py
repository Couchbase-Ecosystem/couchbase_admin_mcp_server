"""
handlers/capella/environment.py — ephemeral test-environment orchestration.

THE PROBLEM
===========
"Stand up a Capella cluster, point a mobile app at it, tear it down" is not one
API call. It is: create project (or reuse), create cluster, wait 5-15 minutes,
allowlist the client, create a bucket, create a database credential, create an
App Service, wait another 5-10 minutes, create an App Endpoint, bring it online,
and hand back a connection string plus a sync URL. Teardown is the same list
backwards, with ordering constraints (an App Service must go before its cluster).

Two properties make that awkward for an agent, and both shape this module:

  1. IT IS LONGER THAN A TOOL CALL. Nothing can block for fifteen minutes. So
     this is written as a RECONCILER, not a script: ``capella_env_ensure`` looks
     at what exists, does whatever it can right now, and returns a phase plus a
     retry hint. Call it repeatedly — from a poll loop, a scheduled task, or an
     agent that waits — and it converges. Each call is safe to repeat.

  2. THERE IS NO LOCAL STATE. Everything is derived from Capella itself, keyed
     by naming convention and the ``mcp-env:`` marker in the description field.
     A CI job that dies mid-provision leaves no orphaned bookkeeping, and a
     later ``capella_env_ensure`` or ``capella_env_reap`` picks the environment
     up exactly where it was. State files are the usual source of "Terraform
     thinks it exists but it doesn't" — avoided entirely.

THE ONE THING THAT CANNOT BE RECONCILED
=======================================
A database credential's password is returned once, at creation, and is not
retrievable afterwards. So on the call that creates it, the password is in the
result; on a later reconcile of the same environment, it is not, and cannot be.
This module says so explicitly rather than returning a plausible-looking blank,
and offers the only real remedy: rotate the credential (delete and recreate) to
obtain a new one. Guessing or silently omitting it would send a CI job into a
confusing authentication failure.
"""

from __future__ import annotations

import contextlib
import json
import secrets
import string
from datetime import datetime, timezone
from typing import Any

from mcp.types import TextContent, Tool, ToolAnnotations

import authz
from handlers.shared import err, ok, ok_allow_secrets
from logging_config import get_logger

from . import guardrails as g
from .client import CapellaError, build_path, capella_list, capella_request
from .spec import (
    IN_FLIGHT_CLUSTER_STATES,
    OPS_BY_NAME,
    TERMINAL_APP_SERVICE_STATES,
)

_log = get_logger("handlers.capella.environment")

_RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)
_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True)
_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True
)

# Recommended poll interval. Cluster deployment is minutes, so a tight loop only
# burns API quota against the organization rate limit.
RETRY_AFTER_SECONDS = 30


# ── Low-level helpers ────────────────────────────────────────────────────────


#: Cap for the reconciler's own existence lookups. Far above CAPELLA_MAX_ITEMS on
#: purpose: every list call here answers "does this already exist?", and a
#: truncated page answers "no" for something that does exist — which would make
#: the reconciler create a duplicate cluster instead of adopting the real one.
#: Silent truncation breaking idempotency is the worst available failure here.
_INTERNAL_LOOKUP_MAX = 10_000


class CompositeRefusedError(RuntimeError):
    """A composite tool tried to use a primitive the operator has restricted."""


def _assert_primitive_permitted(op_name: str, composite: str) -> None:
    """Honour CB_ADMIN_DISABLED_TOOLS and the hard ceiling for the PRIMITIVE.

    The composite environment tools reach the v4 ops directly through _invoke, so both
    name-keyed controls were bypassed by construction: an operator who set

        CB_ADMIN_ALWAYS_CONFIRM=capella_cluster_delete
        CB_ADMIN_DISABLED_TOOLS=capella_cluster_delete

    still had capella_env_teardown and capella_env_reap delete clusters, unattended.
    Those controls are documented as the thing an automated caller "provably cannot
    bypass", and the operator's mental model — "cluster deletion is behind a human" —
    was simply wrong.

    Note this can make teardown fail, which is the correct outcome: if a human must
    approve a cluster deletion, then an unattended reaper must not perform one. The
    error names both the composite and the primitive so the cause is obvious rather
    than looking like a Capella API failure.
    """
    from handlers.shared import DISABLED_TOOLS

    if op_name in DISABLED_TOOLS:
        raise CompositeRefusedError(
            f"{composite} needs `{op_name}`, which is listed in "
            f"CB_ADMIN_DISABLED_TOOLS. Refusing: reaching a disabled primitive "
            f"through a composite tool would make that list advisory. Remove "
            f"`{op_name}` from CB_ADMIN_DISABLED_TOOLS, or do not use {composite}."
        )

    if op_name in authz.hard_ceiling_tools() and not authz.human_is_present():
        raise CompositeRefusedError(
            f"{composite} needs `{op_name}`, which is in the hard ceiling "
            f"(CB_ADMIN_ALWAYS_CONFIRM), and no human is present at the client. "
            f"Refusing: an unattended composite must not perform an operation the "
            f"operator has said requires a person. Perform it through an "
            f"interactive session, or remove `{op_name}` from CB_ADMIN_ALWAYS_CONFIRM "
            f"if {composite} is meant to run unattended."
        )


def _invoke(
    op_name: str,
    args: dict,
    *,
    body: Any | None = None,
    composite: str = "a composite tool",
) -> Any:
    """Call a registered v4 op by name, using its declared method and path."""
    _assert_primitive_permitted(op_name, composite)
    op = OPS_BY_NAME[op_name]
    path = build_path(op.path, args)
    if op.paginated:
        return capella_list(path, max_items=_INTERNAL_LOOKUP_MAX)
    return capella_request(op.method, path, body=body)


def _items(envelope: Any) -> list[dict]:
    """Extract the item list from either a normalized envelope or a bare array."""
    if isinstance(envelope, dict):
        data = envelope.get("data")
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        return []
    if isinstance(envelope, list):
        return [d for d in envelope if isinstance(d, dict)]
    return []


def _find_by_name(collection: list[dict], name: str) -> dict | None:
    for item in collection:
        if str(item.get("name")) == name:
            return item
    return None


_PASSWORD_SYMBOLS = "!@#$%^&*-_=+"


def _generate_password(length: int = 24) -> str:
    """Generate a Capella-acceptable password from a CSPRNG.

    Capella requires length >= 8 with at least one upper, lower, digit and
    symbol. Rather than bolting a fixed 'Aa1!' onto the front — which satisfies
    the rule but hands an attacker four known characters and concentrates all the
    entropy in the remainder — this draws one character from each required class,
    fills the rest from the full alphabet, and shuffles with ``secrets``. Every
    position is then unpredictable.
    """
    alphabet = string.ascii_letters + string.digits + _PASSWORD_SYMBOLS
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(_PASSWORD_SYMBOLS),
    ]
    filler = [secrets.choice(alphabet) for _ in range(max(0, length - len(required)))]
    chars = required + filler
    # secrets-backed Fisher-Yates; random.shuffle is not cryptographically secure.
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def _cluster_name(env_name: str) -> str:
    policy = g.load_policy()
    if policy.name_prefix and not env_name.startswith(policy.name_prefix):
        return f"{policy.name_prefix}{env_name}"
    return env_name


def _connection_string(cluster: dict) -> str | None:
    """Pull the SDK connection string out of a cluster object.

    v4 has used more than one field name for this across revisions, so check the
    known spellings rather than assuming one.
    """
    for key in ("connectionString", "connectionstring", "hostname", "endpoint"):
        value = cluster.get(key)
        if isinstance(value, str) and value:
            return value if "://" in value else f"couchbases://{value}"
    return None


# ── Tool definitions ─────────────────────────────────────────────────────────

_ENV_NAME_SCHEMA = {
    "type": "string",
    "description": (
        "Logical environment name, e.g. 'ios-pr-4821'. Used to derive the "
        "cluster name (with CAPELLA_ENV_NAME_PREFIX prepended if configured) and "
        "to find the environment again on later calls. Keep it stable across the "
        "life of one test run — it is the only key linking the calls together."
    ),
}

TOOLS: list[Tool] = [
    Tool(
        name="capella_env_ensure",
        description=(
            "Idempotently converge a Capella test environment toward the "
            "requested spec, and report how far it got. THE PRIMARY TOOL for "
            "standing up a test target.\n\n"
            "Because a cluster takes 5-15 minutes and an App Service another "
            "5-10, this does NOT block to completion. It performs every step "
            "that can be done now and returns {phase, done, retry_after_s}. Call "
            "it again on that interval until phase is 'ready'. Repeat calls are "
            "safe: existing resources are reused, never duplicated.\n\n"
            "Phases: creating_cluster -> waiting_for_cluster -> configuring -> "
            "creating_app_service -> waiting_for_app_service -> "
            "configuring_app_endpoint -> ready.\n\n"
            "When phase is 'ready' the result carries the connection string, the "
            "App Services endpoint (if requested), and the bucket/scope/"
            "collection layout. The database credential password appears ONLY in "
            "the call that created it — capture it then."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "env_name": _ENV_NAME_SCHEMA,
                "project_id": {
                    "type": "string",
                    "description": (
                        "Target project UUID. Must be in CAPELLA_ALLOWED_PROJECTS. "
                        "Defaults to CAPELLA_DEFAULT_PROJECT_ID when set."
                    ),
                },
                "organization_id": {
                    "type": "string",
                    "description": "Defaults to CAPELLA_ORG_ID.",
                },
                "app_services": {
                    "type": "boolean",
                    "description": (
                        "Provision an App Service and App Endpoint for Couchbase "
                        "Lite sync. Set true for a mobile app that replicates; "
                        "false for one that talks to the cluster directly via SDK "
                        "or the Data API. Roughly doubles provisioning time."
                    ),
                },
                "cloud_provider": {"type": "string", "enum": ["aws", "gcp", "azure"]},
                "region": {
                    "type": "string",
                    "description": "e.g. us-east-1. Match your CI runners.",
                },
                "server_version": {
                    "type": "string",
                    "description": "Couchbase Server version, e.g. 7.6.",
                },
                "bucket_name": {
                    "type": "string",
                    "description": "Bucket to create. Defaults to 'testdata'.",
                },
                "scope_name": {
                    "type": "string",
                    "description": "Optional scope to create in the bucket.",
                },
                "collection_name": {
                    "type": "string",
                    "description": "Optional collection to create in that scope.",
                },
                "sample_bucket": {
                    "type": "string",
                    "description": (
                        "Load a Couchbase sample dataset instead of an empty "
                        "bucket, e.g. 'travel-sample'. Deterministic seed data "
                        "with no fixture loader to maintain."
                    ),
                },
                "credential_name": {
                    "type": "string",
                    "description": "Database credential username. Defaults to 'testapp'.",
                },
                "allowed_cidrs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "CIDRs permitted to reach the cluster, e.g. "
                        "['203.0.113.4/32']. Without at least one, the cluster "
                        "deploys successfully and refuses every connection — the "
                        "single most common cause of 'it provisioned but I can't "
                        "connect'."
                    ),
                },
                "app_service_cidrs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "CIDRs permitted to reach the App Service sync endpoint. "
                        "SEPARATE from the cluster allowlist — a phone or device "
                        "farm needs an entry here."
                    ),
                },
                "ttl_hours": {
                    "type": "integer",
                    "description": (
                        "Hours before capella_env_reap considers this environment "
                        "expired. 0 means never expire. Defaults to "
                        "CAPELLA_ENV_TTL_HOURS."
                    ),
                },
                "owner": {
                    "type": "string",
                    "description": "Free text recorded in the marker, e.g. a pipeline name or build URL.",
                },
                "confirm": {
                    "type": "boolean",
                    "description": "Required for the write steps unless the caller is automation-scoped.",
                },
            },
            "required": ["env_name"],
        },
        annotations=_WRITE,
    ),
    Tool(
        name="capella_env_status",
        description=(
            "Read-only view of one environment: cluster state, App Service state, "
            "buckets, allowlist entries, marker metadata and time remaining "
            "before expiry. Use this to poll without risking any write."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "env_name": _ENV_NAME_SCHEMA,
                "project_id": {"type": "string"},
                "organization_id": {"type": "string"},
            },
            "required": ["env_name"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_env_list",
        description=(
            "List every environment this server owns across the allowlisted "
            "projects, with age, TTL, expiry and current state. Clusters carrying "
            "no mcp-env marker are reported separately as 'unmanaged' — visible, "
            "but explicitly not reapable."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "project_id": {
                    "type": "string",
                    "description": "Limit to one project. Defaults to all allowlisted projects.",
                },
                "organization_id": {"type": "string"},
                "include_unmanaged": {
                    "type": "boolean",
                    "description": "Also list clusters without a marker. Default true.",
                },
            },
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_env_connection_info",
        description=(
            "Everything a test client needs to connect: SDK connection string, "
            "App Services public endpoint and websocket URL, bucket/scope/"
            "collection names, credential username, and the current allowlist. "
            "Reports plainly that the credential password is unavailable if this "
            "server did not create it in the current call."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "env_name": _ENV_NAME_SCHEMA,
                "project_id": {"type": "string"},
                "organization_id": {"type": "string"},
            },
            "required": ["env_name"],
        },
        annotations=_RO,
    ),
    Tool(
        name="capella_env_park",
        description=(
            "Turn an environment off without destroying it — stops the spend, "
            "keeps the data and configuration, and avoids paying the 5-15 minute "
            "provisioning cost again. The right move between test runs on a "
            "long-lived environment. The linked App Service is turned off with "
            "the cluster."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "env_name": _ENV_NAME_SCHEMA,
                "project_id": {"type": "string"},
                "organization_id": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["env_name"],
        },
        annotations=_WRITE,
    ),
    Tool(
        name="capella_env_resume",
        description=(
            "Turn a parked environment back on, including its App Service, and "
            "report readiness. Asynchronous — poll capella_env_status until the "
            "cluster is healthy."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "env_name": _ENV_NAME_SCHEMA,
                "project_id": {"type": "string"},
                "organization_id": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["env_name"],
        },
        annotations=_WRITE,
    ),
    Tool(
        name="capella_env_teardown",
        description=(
            "Destroy an environment: App Service first (required ordering), then "
            "the cluster. IRREVERSIBLE — all data is lost. Refused unless the "
            "environment is in an allowlisted project, its name carries the "
            "configured prefix, and Capella deletion protection is off.\n\n"
            "Asynchronous: returns once deletion is accepted. Poll "
            "capella_env_status until the resources are gone."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "env_name": _ENV_NAME_SCHEMA,
                "project_id": {"type": "string"},
                "organization_id": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["env_name"],
        },
        annotations=_DESTRUCTIVE,
    ),
    Tool(
        name="capella_env_reap",
        description=(
            "Find environments whose TTL has expired and tear them down. The "
            "backstop for the CI job that crashed before its teardown step — "
            "without it, orphaned test clusters bill indefinitely.\n\n"
            "DEFAULTS TO A DRY RUN: it reports what it would delete and deletes "
            "nothing until dry_run is explicitly false. Only clusters carrying a "
            "valid mcp-env marker with an elapsed TTL are ever eligible, and each "
            "one is still checked against the full guardrail set individually."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "project_id": {
                    "type": "string",
                    "description": "Limit to one project. Defaults to all allowlisted projects.",
                },
                "organization_id": {"type": "string"},
                "dry_run": {
                    "type": "boolean",
                    "description": "Default TRUE. Set false to actually delete.",
                },
                "confirm": {"type": "boolean"},
            },
        },
        annotations=_DESTRUCTIVE,
    ),
    Tool(
        name="capella_guardrails_status",
        description=(
            "Report this server's effective Capella blast radius: pinned "
            "organization, allowlisted projects, required name prefix, "
            "environment ceiling, default TTL and whether destructive operations "
            "are enabled at all. Answered by the same code that enforces the "
            "policy, so it cannot drift from documentation. Check this first when "
            "a write is unexpectedly refused."
        ),
        inputSchema={"type": "object", "properties": {}},
        annotations=_RO,
    ),
]


# ── Resolution ───────────────────────────────────────────────────────────────


def _resolve_context(args: dict) -> tuple[str, str, g.Policy]:
    """Resolve (organization_id, project_id, policy), applying the guardrails."""
    policy = g.load_policy()
    org = g.resolve_org(args, policy)

    project = (args.get("project_id") or "").strip()
    if not project:
        import os

        project = (os.environ.get("CAPELLA_DEFAULT_PROJECT_ID") or "").strip()
    if not project:
        if len(policy.allowed_projects) == 1:
            # Unambiguous: one allowlisted project is the only place this server
            # may operate, so defaulting to it cannot pick the wrong target.
            project = policy.allowed_projects[0]
        else:
            raise g.GuardrailError(
                "No project_id supplied and no unambiguous default.",
                hint=(
                    "Pass project_id, or set CAPELLA_DEFAULT_PROJECT_ID. "
                    "capella_projects_list shows the available projects; only "
                    "those in CAPELLA_ALLOWED_PROJECTS may be modified."
                ),
            )
    return org, project, policy


def _get_cluster(org: str, project: str, env_name: str) -> dict | None:
    clusters = _items(
        _invoke(
            "capella_clusters_list", {"organization_id": org, "project_id": project}
        )
    )
    return _find_by_name(clusters, _cluster_name(env_name))


def _get_cluster_for_destructive(org: str, project: str, env_name: str) -> dict | None:
    """Cluster lookup for destructive operations, matching the literal name too.

    ``_get_cluster`` deliberately only matches the PREFIXED name, so a reconcile
    can never adopt a cluster this server did not create. But that strictness
    makes destructive operations lie: asked to tear down 'acme-prod' with a
    prefix configured, the prefixed lookup misses and teardown reports
    "nothing_to_do" — while the cluster sits there, live.

    "I did nothing because there is nothing" and "I did nothing because I refuse"
    are different answers, and an operator acting on the first one would conclude
    the cluster was already gone. So destructive paths also match the literal
    name, purely so the guardrail can then refuse it out loud with the reason.
    """
    clusters = _items(
        _invoke(
            "capella_clusters_list", {"organization_id": org, "project_id": project}
        )
    )
    return _find_by_name(clusters, _cluster_name(env_name)) or _find_by_name(
        clusters, env_name
    )


def _refetch_cluster(org: str, project: str, cluster: dict) -> dict:
    """Re-read a cluster individually before making a guardrail decision on it.

    Cluster objects reached via ``_get_cluster*`` come from the paginated LIST
    endpoint, and cloud list endpoints routinely return SUMMARY objects that omit
    fields present only on the per-resource GET. ``deletionProtection`` is exactly
    such a field: if the list response omits it, ``assert_deletable`` sees None,
    concludes "not protected", and tears down a cluster that Capella has marked
    protected — while the equivalent raw primitive, which does its own GET,
    correctly refuses. Two code paths disagreeing about whether a cluster may be
    destroyed is the kind of inconsistency that only shows up in production.

    FAILS CLOSED. An earlier version fell back to the LIST object when the GET
    yielded nothing usable, which quietly reintroduced the very weakness it was
    added to remove: the guardrail would then evaluate deletionProtection against a
    summary object that may not carry the field. Same principle as
    ``__init__._fetch_cluster`` — a guard that disappears when the world looks
    strange is not a guard.
    """
    cluster_id = str(cluster.get("id") or "")
    if not cluster_id:
        raise g.GuardrailError(
            f"Cannot verify ownership of cluster {cluster.get('name')!r}: the "
            "listing returned no cluster id.",
            hint=(
                "The guardrails need the full cluster object to decide, so the "
                "operation is refused rather than attempted. Re-check with "
                "capella_clusters_list."
            ),
        )
    fetched = _invoke(
        "capella_cluster_get",
        {"organization_id": org, "project_id": project, "cluster_id": cluster_id},
    )
    if not isinstance(fetched, dict) or not fetched.get("name"):
        raise g.GuardrailError(
            f"Cannot verify ownership of cluster {cluster_id!r}: Capella did not "
            "return a usable cluster object.",
            hint=(
                "Deciding from the summarised list entry instead would risk acting "
                "on a cluster whose deletion-protection state is unknown, so the "
                "operation is refused."
            ),
        )
    return fetched


def _count_managed_environments(
    org: str, policy: g.Policy, fallback_project: str
) -> int:
    """Managed-environment count across the whole sandbox.

    Thin adapter over guardrails.count_managed_environments so the reconciler and
    the raw-primitive dispatch share one definition of the ceiling.
    """

    def list_for_project(project: str) -> list[dict]:
        return _items(
            _invoke(
                "capella_clusters_list",
                {"organization_id": org, "project_id": project},
            )
        )

    return g.count_managed_environments(list_for_project, policy, fallback_project)


def _get_app_service(org: str, project: str, cluster_id: str) -> dict | None:
    """The App Service attached to this cluster, or None.

    The list endpoint is ORGANIZATION-WIDE. There is no cluster-scoped list — the
    cluster-level ``/appservices`` path accepts POST only, which is why a GET against it
    returned 405 and this function previously found nothing at all.

    So the filter on ``clusterId`` is load-bearing, not a tidy-up. Taking ``services[0]``
    from an org-wide list would attach the reconciler to whichever App Service happened to
    be first in the organization — quite possibly one belonging to a different cluster,
    and then park, resume or tear it down on the strength of that.
    """
    services = _items(
        _invoke(
            "capella_app_services_list",
            {"organization_id": org, "projectId": project},
        )
    )
    for service in services:
        if str(service.get("clusterId") or "") == str(cluster_id):
            return service
    return None


def _state_of(resource: dict) -> str:
    for key in ("currentState", "state", "status"):
        value = resource.get(key)
        if isinstance(value, str) and value:
            return value
    return "unknown"


def _phase_result(phase: str, **extra: Any) -> dict:
    done = phase == "ready"
    payload: dict[str, Any] = {"phase": phase, "done": done}
    if not done:
        payload["retry_after_s"] = RETRY_AFTER_SECONDS
        payload["next_step"] = (
            f"Call capella_env_ensure again with the same arguments in about "
            f"{RETRY_AFTER_SECONDS}s. This is expected — provisioning is "
            f"asynchronous, not stuck."
        )
    payload.update(extra)

    # "ready" with no allowlist entries is a trap: the environment is genuinely
    # provisioned, and every client connection to it will still be refused. Say so
    # here rather than letting the caller discover it as a connection timeout that
    # looks like a credential or DNS problem.
    if done and not payload.get("_allowlist_present", True):
        payload["warning_allowlist"] = (
            "Environment is ready BUT the cluster IP allowlist is empty, so "
            "Capella will refuse every client connection regardless of "
            "credentials. Pass allowed_cidrs to capella_env_ensure, or add an "
            "entry with capella_allowed_cidr_create."
        )
    payload.pop("_allowlist_present", None)
    return payload


# ── capella_env_ensure ───────────────────────────────────────────────────────


def _ensure(args: dict) -> dict:
    org, project, policy = _resolve_context(args)
    g.assert_project_allowed(project, policy)

    env_name = str(args["env_name"]).strip()
    cluster_name = _cluster_name(env_name)
    g.assert_name_allowed(cluster_name, policy)

    want_app_services = bool(args.get("app_services"))
    actions: list[str] = []

    # ── Cluster ──────────────────────────────────────────────────────────────
    cluster = _get_cluster(org, project, env_name)

    if cluster is None:
        # Skip the multi-project count if THIS SCOPE was just refused.
        scope = g.ceiling_scope_key(policy, org, project)
        if g.ceiling_refusal_active(scope):
            g.raise_ceiling_refusal(policy)
        g.assert_capacity(
            _count_managed_environments(org, policy, project), policy, scope=scope
        )

        marker = g.build_marker(
            env_name,
            ttl_hours=args.get("ttl_hours"),
            owner=str(args.get("owner") or ""),
            extra={"app_services": want_app_services},
        )
        body = {
            "name": cluster_name,
            "description": marker,
            "cloudProvider": {
                "type": args.get("cloud_provider") or "aws",
                "region": args.get("region") or "us-east-1",
                "cidr": args.get("cluster_cidr") or "10.0.1.0/23",
            },
            "couchbaseServer": {"version": args.get("server_version") or "7.6"},
            "serviceGroups": [
                {
                    "node": {
                        "compute": {"cpu": 4, "ram": 16},
                        "disk": {"storage": 50, "type": "gp3", "iops": 3000},
                    },
                    "numOfNodes": 3,
                    "services": ["data", "query", "index"],
                }
            ],
            "availability": {"type": "single"},
            "support": {"plan": "basic", "timezone": "ET"},
        }
        _invoke(
            "capella_cluster_create",
            {"organization_id": org, "project_id": project},
            body=body,
        )
        actions.append(f"created cluster {cluster_name}")
        return _phase_result(
            "creating_cluster",
            environment=env_name,
            cluster_name=cluster_name,
            actions=actions,
            note=(
                "Cluster deployment started. Typically 5-15 minutes. Service "
                "group defaults were applied; pass explicit values to "
                "capella_cluster_create instead if this shape is wrong for the "
                "test workload."
            ),
        )

    # An EXISTING cluster is about to be adopted and configured — new credentials,
    # new allowlist entries, new buckets, possibly an App Service. That is a
    # mutation, so the same ownership check every other mutating path performs
    # applies here too. Without it, a cluster whose name happens to match the
    # prefix — including one an operator explicitly listed in
    # CAPELLA_PROTECTED_CLUSTERS — was freely reconfigurable through this tool,
    # and the protected-cluster guarantee held only against deletion.
    g.assert_managed(cluster, project, kind="cluster", policy=policy, verb="configure")

    cluster_id = str(cluster.get("id") or "")
    state = _state_of(cluster)

    if state in IN_FLIGHT_CLUSTER_STATES:
        return _phase_result(
            "waiting_for_cluster",
            environment=env_name,
            cluster_id=cluster_id,
            cluster_state=state,
            actions=actions,
        )

    if state not in ("healthy",):
        return _phase_result(
            "cluster_not_healthy",
            environment=env_name,
            cluster_id=cluster_id,
            cluster_state=state,
            actions=actions,
            note=(
                f"Cluster is in state {state!r}, which is terminal but not "
                "healthy. Check capella_project_events_list for the failure "
                "reason — the create call itself will not have reported it. If "
                "the cluster is turnedOff, use capella_env_resume."
            ),
        )

    # ── Cluster is healthy: configure it ─────────────────────────────────────
    base = {"organization_id": org, "project_id": project, "cluster_id": cluster_id}
    result: dict[str, Any] = {"environment": env_name, "cluster_id": cluster_id}

    # Allowlist. Without an entry the cluster deploys fine and refuses every
    # connection, so this comes first and its outcome is tracked for the warning
    # attached to a "ready" result.
    wanted_cidrs = list(args.get("allowed_cidrs") or [])
    current = {
        str(entry.get("cidr"))
        for entry in _items(_invoke("capella_allowed_cidrs_list", base))
    }
    for cidr in wanted_cidrs:
        if cidr not in current:
            _invoke(
                "capella_allowed_cidr_create",
                base,
                body={"cidr": cidr, "comment": f"mcp-env {env_name}"},
            )
            actions.append(f"allowlisted {cidr}")
            current.add(cidr)
    result["_allowlist_present"] = bool(current)

    # Bucket, or a sample dataset.
    sample = args.get("sample_bucket")
    bucket_name = args.get("bucket_name") or "testdata"
    buckets = _items(_invoke("capella_buckets_list", base))

    if sample:
        if not _find_by_name(buckets, str(sample)):
            _invoke("capella_sample_bucket_load", base, body={"name": sample})
            actions.append(f"loaded sample bucket {sample}")
        bucket_name = str(sample)
        bucket = _find_by_name(
            _items(_invoke("capella_buckets_list", base)), bucket_name
        )
    else:
        bucket = _find_by_name(buckets, bucket_name)
        if bucket is None:
            _invoke(
                "capella_bucket_create",
                base,
                body={
                    "name": bucket_name,
                    "memoryAllocationInMb": 256,
                    "replicas": 0,
                    "flush": True,
                },
            )
            actions.append(f"created bucket {bucket_name}")
            bucket = _find_by_name(
                _items(_invoke("capella_buckets_list", base)), bucket_name
            )

    result["bucket"] = bucket_name
    bucket_id = str((bucket or {}).get("id") or "")

    # A scope/collection request that cannot be satisfied must not pass silently:
    # returning "ready" while the requested layout is absent sends the test suite
    # into a confusing "keyspace not found" instead of naming the real problem.
    scope_name = args.get("scope_name")
    if scope_name and not bucket_id:
        return _phase_result(
            "configuring",
            actions=actions,
            error=(
                f"Requested scope {scope_name!r} could not be created: bucket "
                f"{bucket_name!r} has no id yet. A sample-bucket import is still "
                "in progress, or the bucket create did not take effect."
            ),
            next_step=(
                "Call capella_env_ensure again shortly. If it persists, check "
                "capella_buckets_list and capella_project_events_list."
            ),
            **result,
        )

    # Scope and collection, when asked for.
    if scope_name and bucket_id:
        scope_base = {**base, "bucket_id": bucket_id}
        scopes = _items(_invoke("capella_scopes_list", scope_base))
        if not _find_by_name(scopes, str(scope_name)):
            _invoke("capella_scope_create", scope_base, body={"name": scope_name})
            actions.append(f"created scope {scope_name}")
        result["scope"] = scope_name

        collection_name = args.get("collection_name")
        if collection_name:
            coll_base = {**scope_base, "scope_name": scope_name}
            colls = _items(_invoke("capella_collections_list", coll_base))
            if not _find_by_name(colls, str(collection_name)):
                _invoke(
                    "capella_collection_create",
                    coll_base,
                    body={"name": collection_name},
                )
                actions.append(f"created collection {collection_name}")
            result["collection"] = collection_name

    # Database credential. Password is returned once, here, and never again.
    cred_name = str(args.get("credential_name") or "testapp")
    creds = _items(_invoke("capella_database_credentials_list", base))
    if _find_by_name(creds, cred_name):
        result["credential"] = {
            "name": cred_name,
            "password": None,
            "password_note": (
                "Credential already exists and Capella does not allow reading a "
                "password back. If the password was not captured when it was "
                "created, delete this credential and let capella_env_ensure "
                "recreate it — that is the only way to obtain a usable one."
            ),
        }
    else:
        password = _generate_password()
        _invoke(
            "capella_database_credential_create",
            base,
            body={
                "name": cred_name,
                "password": password,
                "access": [{"privileges": ["data_reader", "data_writer"]}],
            },
        )
        actions.append(f"created database credential {cred_name}")
        result["credential"] = {
            "name": cred_name,
            "password": password,
            "password_note": (
                "Capture this now — it is returned only on creation and cannot be "
                "retrieved later."
            ),
        }

    result["connection_string"] = _connection_string(cluster)

    # ── App Services ─────────────────────────────────────────────────────────
    if not want_app_services:
        return _phase_result("ready", actions=actions, **result)

    app_service = _get_app_service(org, project, cluster_id)
    if app_service is None:
        as_name = f"{cluster_name}-sync"
        _invoke(
            "capella_app_service_create",
            base,
            body={
                "name": as_name,
                "description": g.build_marker(
                    env_name,
                    ttl_hours=args.get("ttl_hours"),
                    owner=str(args.get("owner") or ""),
                ),
                "nodes": 1,
                "compute": {"cpu": 2, "ram": 4},
            },
        )
        actions.append(f"created app service {as_name}")
        return _phase_result("creating_app_service", actions=actions, **result)

    as_id = str(app_service.get("id") or "")
    as_state = _state_of(app_service)
    result["app_service_id"] = as_id
    result["app_service_state"] = as_state

    if as_state not in TERMINAL_APP_SERVICE_STATES:
        return _phase_result("waiting_for_app_service", actions=actions, **result)
    if as_state != "healthy":
        return _phase_result(
            "app_service_not_healthy",
            actions=actions,
            note=(
                f"App Service is {as_state!r}. Check "
                "capella_project_events_list; if it is turnedOff, use "
                "capella_env_resume."
            ),
            **result,
        )

    # App Service allowlist — separate from the cluster's.
    as_base = {**base, "app_service_id": as_id}
    as_cidrs = list(args.get("app_service_cidrs") or [])
    if as_cidrs:
        current = {
            str(e.get("cidr"))
            for e in _items(_invoke("capella_app_service_allowed_cidrs_list", as_base))
        }
        for cidr in as_cidrs:
            if cidr not in current:
                _invoke(
                    "capella_app_service_allowed_cidr_create",
                    as_base,
                    body={"cidr": cidr, "comment": f"mcp-env {env_name}"},
                )
                actions.append(f"allowlisted {cidr} on app service")

    # App Endpoint — what the mobile client actually replicates against.
    endpoint_name = f"{env_name}-endpoint"
    endpoints = _items(_invoke("capella_app_endpoints_list", as_base))
    endpoint = _find_by_name(endpoints, endpoint_name)
    if endpoint is None:
        _invoke(
            "capella_app_endpoint_create",
            as_base,
            body={"name": endpoint_name, "bucket": bucket_name},
        )
        actions.append(f"created app endpoint {endpoint_name}")
        endpoint = {"name": endpoint_name}

    # A newly created endpoint is offline; bring it online or nothing syncs.
    ep_base = {**as_base, "app_endpoint_name": endpoint_name}
    try:
        _invoke("capella_app_endpoint_online", ep_base)
        actions.append(f"brought app endpoint {endpoint_name} online")
    except CapellaError as exc:
        # Already online is a success, not a failure, in a reconciler.
        if exc.status not in (400, 409):
            raise

    result["app_endpoint"] = endpoint_name
    result["app_service_hostname"] = app_service.get("hostname") or app_service.get(
        "dns"
    )
    if result["app_service_hostname"]:
        result["couchbase_lite_url"] = (
            f"wss://{result['app_service_hostname']}/{endpoint_name}"
        )

    return _phase_result("ready", actions=actions, **result)


# ── Read-only reporting ──────────────────────────────────────────────────────


def _status(args: dict) -> dict:
    org, project, _ = _resolve_context(args)
    env_name = str(args["env_name"]).strip()
    cluster = _get_cluster(org, project, env_name)
    if cluster is None:
        return {
            "environment": env_name,
            "exists": False,
            "note": (
                f"No cluster named {_cluster_name(env_name)!r} in project "
                f"{project}. It was never created, or teardown has completed."
            ),
        }

    cluster_id = str(cluster.get("id") or "")
    marker = g.parse_marker(cluster.get("description"))
    base = {"organization_id": org, "project_id": project, "cluster_id": cluster_id}

    out: dict[str, Any] = {
        "environment": env_name,
        "exists": True,
        "cluster_id": cluster_id,
        "cluster_name": cluster.get("name"),
        "cluster_state": _state_of(cluster),
        "connection_string": _connection_string(cluster),
        "managed_by_this_server": marker is not None,
        "marker": marker,
    }
    if marker:
        expiry = g.marker_expiry(marker)
        out["expires_at"] = expiry.isoformat() if expiry else None
        out["expired"] = g.is_expired(marker)

    try:
        out["buckets"] = [
            b.get("name") for b in _items(_invoke("capella_buckets_list", base))
        ]
        out["allowed_cidrs"] = [
            e.get("cidr") for e in _items(_invoke("capella_allowed_cidrs_list", base))
        ]
    except CapellaError as exc:
        # A cluster that is turnedOff or mid-delete answers 404/409 on children.
        out["detail_unavailable"] = str(exc)

    app_service = None
    # A cluster that is turnedOff or mid-delete answers 404/409 on its children;
    # an App Service we cannot read is simply omitted from the status report.
    with contextlib.suppress(CapellaError):
        app_service = _get_app_service(org, project, cluster_id)
    if app_service:
        out["app_service"] = {
            "id": app_service.get("id"),
            "name": app_service.get("name"),
            "state": _state_of(app_service),
            "hostname": app_service.get("hostname") or app_service.get("dns"),
        }
    return out


def _list_envs(args: dict) -> dict:
    policy = g.load_policy()
    org = g.resolve_org(args, policy)
    include_unmanaged = args.get("include_unmanaged", True)

    projects = (
        [args["project_id"]]
        if args.get("project_id")
        else list(policy.allowed_projects)
    )
    if not projects:
        raise g.GuardrailError(
            "No projects to list.",
            hint=(
                "Set CAPELLA_ALLOWED_PROJECTS, or pass project_id. Listing every "
                "project in the organization is deliberately not the default."
            ),
        )

    managed: list[dict] = []
    unmanaged: list[dict] = []
    now = datetime.now(timezone.utc)

    for project in projects:
        for cluster in _items(
            _invoke(
                "capella_clusters_list", {"organization_id": org, "project_id": project}
            )
        ):
            marker = g.parse_marker(cluster.get("description"))
            entry = {
                "project_id": project,
                "cluster_id": cluster.get("id"),
                "name": cluster.get("name"),
                "state": _state_of(cluster),
            }
            if marker is None:
                entry["reapable"] = False
                entry["reason"] = "no mcp-env marker — not created by this server"
                unmanaged.append(entry)
                continue
            expiry = g.marker_expiry(marker)
            entry.update(
                {
                    "environment": marker.get("env"),
                    "owner": marker.get("owner"),
                    "created": marker.get("created"),
                    "ttl_hours": marker.get("ttl_h"),
                    "expires_at": expiry.isoformat() if expiry else None,
                    "expired": g.is_expired(marker, now=now),
                    "reapable": True,
                }
            )
            managed.append(entry)

    return {
        "managed": managed,
        "managed_count": len(managed),
        "expired_count": sum(1 for e in managed if e.get("expired")),
        "unmanaged": unmanaged if include_unmanaged else [],
        "unmanaged_count": len(unmanaged),
        "ceiling": policy.max_environments,
    }


def _connection_info(args: dict) -> dict:
    status = _status(args)
    if not status.get("exists"):
        return status

    out = {
        "environment": status["environment"],
        "cluster_state": status["cluster_state"],
        "connection_string": status.get("connection_string"),
        "buckets": status.get("buckets"),
        "allowed_cidrs": status.get("allowed_cidrs"),
    }
    app_service = status.get("app_service")
    if app_service:
        out["app_service"] = app_service
        hostname = app_service.get("hostname")
        if hostname:
            out["app_services_admin_url"] = f"https://{hostname}:4985"
            out["couchbase_lite_url_pattern"] = f"wss://{hostname}/<appEndpointName>"

    if status["cluster_state"] != "healthy":
        out["warning"] = (
            f"Cluster state is {status['cluster_state']!r}; clients will not "
            "connect until it is 'healthy'."
        )
    if not status.get("allowed_cidrs"):
        out["warning_allowlist"] = (
            "The cluster allowlist is EMPTY. Capella will refuse every client "
            "connection regardless of credentials. Add the test client's CIDR "
            "with capella_allowed_cidr_create."
        )
    out["credential_note"] = (
        "Database credential passwords cannot be read back from Capella. Use the "
        "value captured when the credential was created, or recreate it."
    )
    return out


# ── Lifecycle writes ─────────────────────────────────────────────────────────


def _park(args: dict) -> dict:
    org, project, policy = _resolve_context(args)
    env_name = str(args["env_name"]).strip()
    cluster = _get_cluster_for_destructive(org, project, env_name)
    if cluster is None:
        raise g.GuardrailError(f"No cluster found for environment {env_name!r}.")
    # Re-read the cluster individually: the guardrail decision must be made on the
    # full object, not on a possibly-summarised LIST entry.
    cluster = _refetch_cluster(org, project, cluster)
    # assert_managed, NOT assert_deletable: parking is the cost-saving operation,
    # and refusing it because the cluster is protected from DELETION would push an
    # operator toward switching protection off to get ordinary work done.
    g.assert_managed(cluster, project, kind="cluster", policy=policy, verb="park")

    base = {
        "organization_id": org,
        "project_id": project,
        "cluster_id": str(cluster.get("id")),
    }
    try:
        _invoke("capella_cluster_turn_off", base)
    except CapellaError as exc:
        # 7011: already off. Idempotent success.
        if "7011" not in str(exc):
            raise
        return {"environment": env_name, "state": "already_off", "billing": "stopped"}

    return {
        "environment": env_name,
        "state": "turning_off",
        "note": (
            "Turn-off accepted. The linked App Service is turned off with the "
            "cluster. Data and configuration are retained; compute billing "
            "stops. Use capella_env_resume to bring it back — much faster than "
            "reprovisioning."
        ),
    }


def _resume(args: dict) -> dict:
    org, project, policy = _resolve_context(args)
    env_name = str(args["env_name"]).strip()
    cluster = _get_cluster_for_destructive(org, project, env_name)
    if cluster is None:
        raise g.GuardrailError(f"No cluster found for environment {env_name!r}.")
    cluster = _refetch_cluster(org, project, cluster)
    # Resuming an unmanaged cluster starts billing on infrastructure this server
    # does not own, so it gets the same ownership check as any other mutation.
    g.assert_managed(cluster, project, kind="cluster", policy=policy, verb="resume")

    base = {
        "organization_id": org,
        "project_id": project,
        "cluster_id": str(cluster.get("id")),
    }
    try:
        _invoke("capella_cluster_turn_on", base, body={"turnOnLinkedAppService": True})
    except CapellaError as exc:
        # 7010: already on.
        if "7010" not in str(exc):
            raise
        return {"environment": env_name, "state": "already_on"}

    return {
        "environment": env_name,
        "state": "turning_on",
        "retry_after_s": RETRY_AFTER_SECONDS,
        "note": (
            "Turn-on accepted, including the linked App Service. Poll "
            "capella_env_status until cluster_state is 'healthy'."
        ),
    }


def _teardown(args: dict) -> dict:
    org, project, policy = _resolve_context(args)
    env_name = str(args["env_name"]).strip()
    cluster = _get_cluster_for_destructive(org, project, env_name)

    # The caller may pin the exact resource it means. The reaper does, because it
    # has already resolved a concrete cluster_id while listing, and re-deriving the
    # target from the marker's env NAME would let a tampered or stale marker point
    # teardown at a DIFFERENT, non-expired cluster — every guardrail would still
    # pass, because that other cluster is also inside the sandbox. The checks would
    # simply be applied to the wrong resource.
    expected_id = str(args.get("expected_cluster_id") or "").strip()
    if expected_id and cluster is not None:
        actual_id = str(cluster.get("id") or "")
        if actual_id != expected_id:
            raise g.GuardrailError(
                f"Identity mismatch for environment {env_name!r}: expected cluster "
                f"{expected_id!r} but the name resolved to {actual_id!r}.",
                hint=(
                    "The environment marker and the cluster name disagree, so the "
                    "intended target is ambiguous and nothing was deleted. This "
                    "usually means a cluster description was edited by hand. "
                    "Reconcile the marker, or delete the cluster explicitly with "
                    "capella_cluster_delete."
                ),
            )
    if cluster is None:
        return {
            "environment": env_name,
            "result": "nothing_to_do",
            "note": "No matching cluster; already torn down.",
        }

    cluster_id = str(cluster.get("id"))
    # Re-read individually before the destructive decision. A LIST response may
    # omit deletionProtection, in which case a list-sourced object would look
    # unprotected and this teardown would delete a cluster that the equivalent
    # raw primitive — which does its own GET — correctly refuses.
    cluster = _refetch_cluster(org, project, cluster)
    g.assert_deletable(cluster, project, kind="cluster", policy=policy)

    base = {"organization_id": org, "project_id": project, "cluster_id": cluster_id}
    actions: list[str] = []

    # App Service must go first — the cluster delete fails while one is attached.
    # If the App Service cannot be read (cluster off, or already partly deleted)
    # treat it as absent and proceed to the cluster; the cluster delete will
    # itself refuse if one is in fact still attached.
    app_service = None
    with contextlib.suppress(CapellaError):
        app_service = _get_app_service(org, project, cluster_id)

    if app_service:
        as_state = _state_of(app_service)
        if as_state in ("destroying",):
            return {
                "environment": env_name,
                "result": "waiting",
                "retry_after_s": RETRY_AFTER_SECONDS,
                "note": "App Service deletion already in progress. Call again once it completes.",
            }
        _invoke(
            "capella_app_service_delete",
            {**base, "app_service_id": str(app_service.get("id"))},
        )
        actions.append(f"deleting app service {app_service.get('name')}")
        return {
            "environment": env_name,
            "result": "app_service_deleting",
            "actions": actions,
            "retry_after_s": RETRY_AFTER_SECONDS,
            "note": (
                "App Service deletion accepted. The cluster cannot be deleted "
                "until it finishes — call capella_env_teardown again in about "
                f"{RETRY_AFTER_SECONDS}s to continue."
            ),
        }

    _invoke("capella_cluster_delete", base)
    actions.append(f"deleting cluster {cluster.get('name')}")
    return {
        "environment": env_name,
        "result": "cluster_deleting",
        "actions": actions,
        "note": (
            "Cluster deletion accepted. Asynchronous; poll capella_env_status "
            "until it reports the environment no longer exists."
        ),
    }


def _classify_expired(entries: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split expired environments into reapable and un-pinnable.

    Used by BOTH the dry run and the real run so their answers cannot disagree.
    Previously the dry run reported every expired entry as "would delete" while
    the real run separately refused those lacking a cluster id — so an operator
    sizing a sweep from the preview got a number the real run would not match.
    """
    reapable: list[dict] = []
    unpinnable: list[dict] = []
    for entry in entries:
        if entry.get("environment") and entry.get("cluster_id"):
            reapable.append(entry)
        elif entry.get("environment"):
            unpinnable.append(
                {
                    "environment": entry.get("environment"),
                    "error": (
                        "listing returned no cluster id, so the reap target cannot "
                        "be pinned; skipped rather than resolved by name"
                    ),
                }
            )
    return reapable, unpinnable


def _reap(args: dict) -> dict:
    dry_run = args.get("dry_run", True)
    listing = _list_envs({**args, "include_unmanaged": False})
    expired = [e for e in listing["managed"] if e.get("expired")]
    reapable, unpinnable = _classify_expired(expired)

    if dry_run:
        return {
            "dry_run": True,
            "would_delete": reapable,
            "would_delete_count": len(reapable),
            "would_refuse": unpinnable,
            "note": (
                "Nothing was deleted. Re-call with dry_run=false to tear these "
                "down. Each will still be checked against the guardrails "
                "individually at that point."
            ),
        }

    reaped: list[dict] = []
    refused: list[dict] = list(unpinnable)
    for entry in reapable:
        # _classify_expired has already guaranteed both fields are present.
        env_name = entry["environment"]
        pinned_id = entry["cluster_id"]
        try:
            outcome = _teardown(
                {
                    "env_name": env_name,
                    "project_id": entry["project_id"],
                    "organization_id": args.get("organization_id"),
                    # Pin the resource whose expiry actually triggered this sweep.
                    "expected_cluster_id": pinned_id,
                }
            )
            reaped.append({"environment": env_name, "outcome": outcome.get("result")})
        except (g.GuardrailError, CapellaError) as exc:
            # One environment refusing must not abort the whole sweep.
            refused.append({"environment": env_name, "error": str(exc)})
            _log.warning("reap skipped %s: %s", env_name, exc)

    return {
        "dry_run": False,
        "reaped": reaped,
        "reaped_count": len(reaped),
        "refused": refused,
        "note": (
            "Teardown is asynchronous and multi-step: environments with an App "
            "Service need a second reap pass once the App Service deletion "
            "completes."
        ),
    }


# ── Dispatch ─────────────────────────────────────────────────────────────────

_HANDLERS = {
    "capella_env_ensure": _ensure,
    "capella_env_status": _status,
    "capella_env_list": _list_envs,
    "capella_env_connection_info": _connection_info,
    "capella_env_park": _park,
    "capella_env_resume": _resume,
    "capella_env_teardown": _teardown,
    "capella_env_reap": _reap,
}


def handle(name: str, args: dict) -> list[TextContent]:
    if name == "capella_guardrails_status":
        return ok(g.describe_policy())

    handler = _HANDLERS.get(name)
    if handler is None:
        return err(f"Unknown environment tool: {name}", tool=name)

    try:
        payload = handler(args)
        if name == "capella_env_ensure":
            # The single sanctioned credential-surfacing path: a freshly created
            # database-credential password is returned once, because Capella will
            # never return it again and the test client cannot connect without it.
            return ok_allow_secrets(payload)
        return ok(payload)
    except g.GuardrailError as exc:
        # Policy refusal: nothing was sent to Capella. Say so, and say why.
        return err(
            f"Refused by guardrail policy: {exc}",
            tool=name,
            hint=exc.hint,
            guardrail=True,
            policy=g.describe_policy(),
        )
    except CapellaError as exc:
        return err(str(exc), tool=name, hint=exc.hint, status=exc.status)
    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)


__all__ = ["TOOLS", "handle"]


# Kept for the status tool's convenience: a compact JSON rendering of the policy
# suitable for the startup banner.
def policy_banner() -> str:
    return json.dumps(g.describe_policy(), separators=(",", ":"), sort_keys=True)
