"""
handlers/capella — Couchbase Capella control plane.

Two layers, deliberately separated:

  PRIMITIVES (spec.py)      One tool per Capella v4 operation. Thin, predictable,
                            no orchestration. Use when you know exactly which
                            call you want.

  ORCHESTRATION (environment.py)
                            Composite tools that drive a whole ephemeral test
                            environment — capella_env_ensure, _status, _park,
                            _resume, _teardown, _reap. These sequence the
                            primitives, handle the asynchronous waits, and
                            enforce ordering constraints (an App Service must be
                            deleted before its cluster).

An agent asked to "spin up a test cluster for the phone app" should reach for
capella_env_ensure, not assemble fifteen primitive calls itself — every step it
has to remember is a step it can get wrong, and the ordering constraints are not
discoverable from the individual tool descriptions.

Both layers share guardrails.py, which confines destructive operations to
allowlisted projects and prefixed resource names.

This package replaces the former single-module handlers/capella.py, which had
App Services pathed under /projects/{p}/appservices (the real path is under
/clusters/{c}) and did not paginate list responses.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.types import TextContent, Tool

from handlers.shared import err, ok
from logging_config import get_logger

from . import environment, fixture, guardrails
from .client import (
    CapellaError,
    build_path,
    capella_list,
    capella_request,
    extract_placeholders,
    redact_response,
)
from .spec import OPS_BY_NAME, RECOMMENDED_HARD_CEILING, build_tools

_log = get_logger("handlers.capella")

#: Cap for list calls made internally by the guardrails and the orchestrator.
#: Deliberately far above CAPELLA_MAX_ITEMS: these lookups decide "does this
#: resource already exist?", and a truncated page would answer "no" for
#: something that does exist — creating a duplicate cluster or evading the
#: spend ceiling. Correctness of a lookup matters more than its response size.
_INTERNAL_LOOKUP_MAX = 10_000

#: Every Capella tool: primitives, the environment orchestration layer, and
#: the fixture layer. Order matters only for display.
TOOLS: list[Tool] = build_tools() + environment.TOOLS + fixture.TOOLS

_ENV_TOOL_NAMES = {t.name for t in environment.TOOLS}


def _query_params(op, args: dict) -> dict:
    params = {key: args[key] for key in op.query if args.get(key) is not None}
    return params


#: Ops that create a top-level resource whose name must satisfy the prefix
#: convention. The prefix is load-bearing — a resource created without it can
#: never be torn down or reaped by this server.
_NAME_CHECKED_CREATES = frozenset({"capella_cluster_create", "capella_project_create"})

#: Ops whose body carries a `name` that must satisfy the prefix rule. A RENAME is as
#: capable of moving a resource out of the sandbox as a create is of putting one
#: outside it, and only the creates were covered.
_NAME_CHECKED_RENAMES = _NAME_CHECKED_CREATES | frozenset({"capella_cluster_update"})

#: Ops whose body can erase the ownership marker held in `description`.
_MARKER_PRESERVING_UPDATES = frozenset({"capella_cluster_update"})


def _preserve_ownership_marker(name: str, args: dict, body_in: dict) -> None:
    """Carry an existing ownership marker across an update that would drop it.

    The marker lives in a free-text field a caller legitimately edits, so this
    preserves the marker line and leaves the caller's prose alone. When the body
    supplies no description at all, nothing is done: the field is absent from the PUT
    and Capella leaves the stored value untouched.
    """
    if "description" not in body_in:
        return
    supplied = str(body_in.get("description") or "")
    if guardrails.parse_marker(supplied):
        return  # caller kept a valid marker; leave it exactly as written
    try:
        current = _fetch_cluster(args)
    except guardrails.GuardrailError:
        raise
    existing_marker = guardrails.parse_marker(current.get("description"))
    if not existing_marker:
        return  # nothing to preserve
    marker_line = guardrails.ENV_MARKER_PREFIX + json.dumps(
        existing_marker, separators=(",", ":"), sort_keys=True
    )
    prose = supplied.rstrip()
    body_in["description"] = f"{prose}\n{marker_line}" if prose else marker_line
    _log.info(
        "%s: re-attached the ownership marker the update would have dropped "
        "(env=%r). Without it the cluster becomes invisible to the environment "
        "ceiling and to capella_env_reap.",
        name,
        existing_marker.get("env"),
    )


def _fetch_cluster(args: dict) -> dict:
    """Fetch the cluster a guarded call targets, or fail closed.

    Any non-dict response is treated as a failure rather than as "no cluster to
    check". An earlier version wrapped the guard in ``if isinstance(cluster,
    dict)``, which meant an unexpected response shape SKIPPED the ownership check
    and let the operation proceed — a guard that disappears when the world looks
    strange is not a guard.
    """
    cluster = capella_request(
        "GET", build_path(OPS_BY_NAME["capella_cluster_get"].path, args)
    )
    if not isinstance(cluster, dict) or not cluster.get("name"):
        raise guardrails.GuardrailError(
            "Could not establish ownership of the target cluster: Capella did not "
            "return a usable cluster object.",
            hint=(
                "The guardrails need the live cluster's name to decide whether it "
                "is inside this server's sandbox, so the operation is refused "
                "rather than attempted. Verify the ids with capella_clusters_list."
            ),
        )
    return cluster


def _apply_guardrails(name: str, op, args: dict, policy: guardrails.Policy) -> None:
    """Enforce the sandbox for one mutating operation.

    Ordering matters: cheap local checks first, then the one network round-trip
    needed to inspect the live target. Everything raises GuardrailError, so a
    refusal never reaches Capella.
    """
    placeholders = set(extract_placeholders(op.path))

    # 1. Project allowlist. A guarded op that addresses a project MUST have one —
    #    a falsy project_id previously skipped enforcement silently.
    if "project_id" in placeholders:
        project_id = str(args.get("project_id") or "").strip()
        if not project_id:
            raise guardrails.GuardrailError(
                f"`{name}` requires project_id, and the guardrails cannot be "
                "evaluated without it.",
                hint="Supply project_id. See capella_projects_list.",
            )
        guardrails.assert_project_allowed(project_id, policy)

    # 2. Ownership of the live target cluster. This covers every mutating call on
    #    a cluster's CHILDREN — buckets, scopes, collections, credentials,
    #    allowlists, App Services, App Endpoints — not just the cluster delete.
    #
    #    Without this, an allowlisted project was enough: capella_bucket_flush or
    #    capella_bucket_delete could be aimed at an unmanaged (unprefixed)
    #    cluster that happened to live in that project, and the name-prefix
    #    guard — the whole defense against a hand-made production cluster inside
    #    a test project — protected nothing but capella_cluster_delete.
    if "cluster_id" in placeholders:
        cluster = _fetch_cluster(args)
        project_id = str(args.get("project_id") or "")
        if name == "capella_cluster_delete":
            # Deleting the cluster itself additionally honors Capella's own
            # deletion-protection flag.
            guardrails.assert_deletable(
                cluster, project_id, kind="cluster", policy=policy
            )
        else:
            verb = "delete resources on" if op.destructive else "modify"
            guardrails.assert_managed(
                cluster, project_id, kind="cluster", policy=policy, verb=verb
            )

    # 2b. Deleting a PROJECT is an indirect route to its clusters — no cluster
    #     tool is involved, so the ownership check above never fires. Capella is
    #     documented to refuse a project delete while it still holds clusters, but
    #     relying on that leaves the containment guarantee in someone else's hands
    #     and dependent on a behaviour that could change. Check locally: if the
    #     project contains any cluster this server does not own, refuse.
    if name == "capella_project_delete":
        listed = capella_list(
            build_path(OPS_BY_NAME["capella_clusters_list"].path, args),
            max_items=_INTERNAL_LOOKUP_MAX,
        )
        clusters = listed.get("data", []) if isinstance(listed, dict) else []
        unmanaged = [
            str(c.get("name") or c.get("id"))
            for c in clusters
            if isinstance(c, dict)
            and not guardrails.is_managed_name(str(c.get("name") or ""), policy)
        ]
        # CAPELLA_PROTECTED_CLUSTERS, on the one operation that can take a cluster
        # with the project. The containment check refused only clusters failing the
        # NAME rule, so a protected cluster sitting alone in an allowlisted project
        # passed -- while capella_cluster_delete on the same cluster was refused, and
        # the hint says "No override exists."
        protected_names = {
            p.strip().casefold() for p in policy.protected_clusters if p.strip()
        }
        if protected_names:
            contained_protected = [
                str(c.get("name") or c.get("id"))
                for c in clusters
                if isinstance(c, dict)
                and (
                    str(c.get("name") or "").casefold() in protected_names
                    or str(c.get("id") or "").casefold() in protected_names
                )
            ]
            if contained_protected:
                raise guardrails.GuardrailError(
                    f"Refusing to delete project {args.get('project_id')!r}: it "
                    f"contains {len(contained_protected)} cluster(s) listed in "
                    f"CAPELLA_PROTECTED_CLUSTERS "
                    f"({', '.join(contained_protected[:5])}).",
                    hint=(
                        "Deleting the project would delete these clusters with it, "
                        "reaching resources capella_cluster_delete refuses outright. "
                        "Remove them from CAPELLA_PROTECTED_CLUSTERS if that is "
                        "genuinely intended, or delete the project from the Capella UI."
                    ),
                )

        if unmanaged:
            raise guardrails.GuardrailError(
                f"Refusing to delete project {args.get('project_id')!r}: it contains "
                f"{len(unmanaged)} cluster(s) this server does not own "
                f"({', '.join(unmanaged[:5])}).",
                hint=(
                    "Deleting a project would take its clusters with it, which is a "
                    "way to reach clusters the name-prefix guard would otherwise "
                    "protect. Remove or relocate those clusters first, or delete "
                    "the project from the Capella UI if that is genuinely intended."
                ),
            )

    # 3. Naming convention on the creates that establish a new managed resource, and
    #    on any RENAME. `and body_in.get("name")` used to guard this: a body whose
    #    name was "" skipped assert_name_allowed entirely instead of being refused,
    #    so the check was absent on exactly the branch it exists to cover. A blank
    #    name on one of these ops is now a refusal.
    body_in = args.get("body")
    if (
        name in _NAME_CHECKED_RENAMES
        and isinstance(body_in, dict)
        and "name" in body_in
    ):
        guardrails.assert_name_allowed(str(body_in.get("name") or ""), policy)

    # 3a. An UPDATE must not be able to launder a resource out of the sandbox.
    #
    #     capella_cluster_update checked that the CURRENT cluster was owned, then
    #     forwarded the caller's body verbatim. Both of the sandbox's identifying
    #     marks live in that body, so one PUT could erase both: rename the cluster
    #     off the prefix and blank the description holding the ownership marker.
    #     Afterwards the ceiling counted it as 0, capella_env_list filed it as
    #     unmanaged and not reapable, capella_env_teardown answered "already torn
    #     down", and capella_cluster_delete refused it forever for lacking the
    #     prefix. Every removal path this server has was closed, and the cluster
    #     billed indefinitely. Verified: 6 live clusters against a ceiling of 2.
    #
    #     capella_cluster_update is also destructive=False, so an automation
    #     principal reaches it with no confirmation.
    #
    #     So: the new name is prefix-checked above, and an existing marker is carried
    #     across rather than dropped. A caller may edit the prose around it.
    if name in _MARKER_PRESERVING_UPDATES and isinstance(body_in, dict):
        _preserve_ownership_marker(name, args, body_in)

    # 3b. Stamp the ownership marker on the raw create primitive.
    #
    #     capella_cluster_create forwarded the caller's body verbatim, so a cluster
    #     created through it carried no marker -- and the ceiling, capella_env_list
    #     and the reaper are all built on that marker. The cluster was therefore
    #     invisible to the guard meant to bound it and to the reaper meant to collect
    #     it: created by this server, owned by nothing.
    #
    #     A caller-supplied description is preserved and the marker appended on its
    #     own line, because parse_marker is anchored per line and a human may want to
    #     write a note next to it.
    #     ttl_hours=0 is load-bearing and NOT the default. build_marker's default is
    #     CAPELLA_ENV_TTL_HOURS (8), and stamping that here would enrol every
    #     primitive-created cluster into the unattended reaper's delete list -- a tool
    #     with no ttl_hours argument and no mention of expiry in its description would
    #     silently arm capella_env_reap to DELETE the cluster eight hours later. A
    #     caller who writes "long-lived perf baseline, do not delete" in the
    #     description would lose it overnight. 0 means pinned: counted by the ceiling,
    #     never auto-reaped. Deliberate lifecycle stays with capella_env_ensure, which
    #     takes ttl_hours explicitly and says so.
    if name == "capella_cluster_create" and isinstance(body_in, dict):
        if not guardrails.parse_marker(body_in.get("description")):
            marker = guardrails.build_marker(
                str(body_in.get("name") or ""), ttl_hours=0
            )
            existing = str(body_in.get("description") or "").rstrip()
            body_in["description"] = f"{existing}\n{marker}" if existing else marker

    # 4. Spend ceiling. Previously enforced only inside capella_env_ensure, so an
    #    agent looping on the raw create primitive could provision without bound.
    if name == "capella_cluster_create":
        scope = guardrails.ceiling_scope_key(
            policy,
            str(args.get("organization_id") or ""),
            str(args.get("project_id") or ""),
        )
        if guardrails.ceiling_refusal_active(scope):
            guardrails.raise_ceiling_refusal(policy)

        def list_for_project(project: str) -> list[dict]:
            listed = capella_list(
                build_path(
                    OPS_BY_NAME["capella_clusters_list"].path,
                    {**args, "project_id": project},
                ),
                max_items=_INTERNAL_LOOKUP_MAX,
            )
            data = listed.get("data", []) if isinstance(listed, dict) else []
            return [c for c in data if isinstance(c, dict)]

        # Counted across every allowlisted project, matching capella_env_ensure.
        # Counting only this call's project let an agent round-robin project_id and
        # provision (projects x ceiling) clusters.
        guardrails.assert_capacity(
            guardrails.count_managed_environments(
                list_for_project, policy, str(args.get("project_id") or "")
            ),
            policy,
            scope=scope,
        )


def _handle_primitive(name: str, args: dict) -> list[TextContent]:
    op = OPS_BY_NAME[name]
    policy = guardrails.load_policy()

    # Resolve the organization, refusing a mismatched caller override.
    args = dict(args)
    args["organization_id"] = guardrails.resolve_org(args, policy)

    if op.guarded:
        _apply_guardrails(name, op, args, policy)

    path = build_path(op.path, args)
    body = args.get("body")

    if op.paginated:
        result: Any = capella_list(
            path,
            params=_query_params(op, args),
            max_items=args.get("max_items"),
        )
    else:
        result = capella_request(
            op.method, path, params=_query_params(op, args) or None, body=body
        )

    if op.sensitive_response:
        # The response carries a generated password or API token. Redact before
        # it reaches the model's context or the server log. The environment
        # orchestrator is the sanctioned path for surfacing a new credential,
        # and it does so once, at the point of use.
        result = redact_response(result)
        if isinstance(result, dict):
            result["_note"] = (
                "Credential material in this response was redacted. Use "
                "capella_env_ensure to provision a credential and receive its "
                "password once, at creation."
            )

    return ok(result)


def handle(name: str, args: dict) -> list[TextContent]:
    """Dispatch a Capella tool call."""
    if name in _ENV_TOOL_NAMES or name == "capella_guardrails_status":
        return environment.handle(name, args)

    if name in fixture.TOOL_NAMES:
        return fixture.handle(name, args)

    if name not in OPS_BY_NAME:
        return err(f"Unknown Capella tool: {name}", tool=name)

    try:
        return _handle_primitive(name, args)
    except guardrails.GuardrailError as exc:
        return err(
            f"Refused by guardrail policy: {exc}",
            tool=name,
            hint=exc.hint,
            guardrail=True,
            policy=guardrails.describe_policy(),
        )
    except CapellaError as exc:
        return err(str(exc), tool=name, hint=exc.hint, status=exc.status)
    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)


__all__ = ["TOOLS", "handle", "RECOMMENDED_HARD_CEILING"]
