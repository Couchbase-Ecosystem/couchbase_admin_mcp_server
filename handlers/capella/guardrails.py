"""
handlers/capella/guardrails.py — blast-radius controls for unattended Capella writes.

THE PROBLEM THIS SOLVES
=======================
The ephemeral-environment workflow is inherently destructive and runs with no
human in the loop: a CI job creates a cluster, tests a mobile app against it,
and deletes it. ``capella_cluster_delete`` is therefore a tool an automation
principal must be able to call without confirmation — which is exactly the tool
you least want pointed at a production cluster by a mistaken or manipulated
argument.

The server's existing controls are necessary but not sufficient here:

  * read-only mode      — off by definition; this workflow writes.
  * confirm:true gate   — bypassed by design for automation principals.
  * CB_ADMIN_ALWAYS_CONFIRM — would stop teardown dead, defeating the purpose.

None of them can express "delete freely, but only inside the sandbox." That is
what this module adds, and it is the control that makes unattended teardown
safe to offer at all.

FOUR INDEPENDENT LIMITS
=======================
  1. ORGANIZATION PIN     — CAPELLA_ORG_ID. Every path is built against this
                            org. A caller-supplied organization_id that differs
                            is refused rather than honored.
  2. PROJECT ALLOWLIST    — CAPELLA_ALLOWED_PROJECTS. Destructive operations are
                            confined to these project UUIDs. Production lives in
                            a project not on the list, so it is unreachable.
  3. NAME PREFIX          — CAPELLA_ENV_NAME_PREFIX. Resources created by this
                            server carry the prefix, and destructive operations
                            refuse anything lacking it. Defends the case where a
                            hand-made production cluster sits in an allowlisted
                            project.
  4. ENVIRONMENT CEILING  — CAPELLA_MAX_ENVIRONMENTS. A runaway loop cannot bill
                            the organization for fifty clusters.

Every limit is read from server-side configuration at deploy time by a human.
None can be relaxed by a tool argument, a token scope, or an LLM's assertion
that it is fine. A caller provably cannot self-promote out of the sandbox.

Configured with no allowlist, the module FAILS CLOSED for destructive
operations: an unconfigured server can create, but refuses to delete. The
alternative default — delete anything — is not a defensible out-of-box posture
for a tool an agent can call.

METADATA / OWNERSHIP MARKER
===========================
Capella has no tags or labels on clusters, so there is nowhere native to record
"this is a test environment, owned by pipeline X, safe to reap after 4 hours."
This module encodes that in the cluster's free-text ``description`` field as a
single machine-readable line:

    mcp-env:{"env":"ios-pr-4821","ttl_h":4,"created":"2026-07-29T14:02:11Z", ...}

Written by the environment orchestrator, parsed by the lister and the reaper. It
makes ownership self-describing: a reaper never has to consult external state to
know what it may destroy, and a human reading the Capella UI can see what a
stray cluster was for and who to ask.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from logging_config import get_logger

_log = get_logger("handlers.capella.guardrails")

# The marker that identifies a cluster/app-service as owned by this server.
# Deliberately verbose and unlikely to collide with a human-written description.
ENV_MARKER_PREFIX = "mcp-env:"

_ISO = "%Y-%m-%dT%H:%M:%SZ"


class GuardrailError(RuntimeError):
    """A destructive operation refused by policy.

    Distinct from CapellaError: nothing was sent to Capella. The call was
    stopped locally, before it could do harm.
    """

    def __init__(self, message: str, *, hint: str = ""):
        super().__init__(message)
        self.hint = hint


def _env(key: str, default: str = "") -> str:
    return (os.environ.get(key) or default).strip()


def _env_list(key: str) -> tuple[str, ...]:
    raw = _env(key)
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _env_int(key: str, default: int) -> int:
    raw = _env(key)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        _log.warning("%s=%r is not an integer; using default %d", key, raw, default)
        return default


# ── Policy snapshot ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Policy:
    """The effective guardrail configuration.

    Read fresh on each access rather than cached at import, so a long-running
    HTTP-transport server picks up a corrected env var on restart of the process
    only — but tests can monkeypatch the environment without fighting a cache.
    """

    organization_id: str = ""
    allowed_projects: tuple[str, ...] = ()
    name_prefix: str = ""
    max_environments: int = 10
    default_ttl_hours: int = 8
    allow_unscoped_destructive: bool = False
    protected_clusters: tuple[str, ...] = field(default=())

    @property
    def destructive_allowed(self) -> bool:
        """Whether destructive operations are permitted at all.

        False when no project allowlist is configured — fail closed. The escape
        hatch (CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE=true) exists for a throwaway
        personal org and is named so that enabling it in a customer org is an
        obviously deliberate act.
        """
        return bool(self.allowed_projects) or self.allow_unscoped_destructive


def load_policy() -> Policy:
    return Policy(
        organization_id=_env("CAPELLA_ORG_ID"),
        allowed_projects=_env_list("CAPELLA_ALLOWED_PROJECTS"),
        name_prefix=_env("CAPELLA_ENV_NAME_PREFIX"),
        max_environments=_env_int("CAPELLA_MAX_ENVIRONMENTS", 10),
        default_ttl_hours=_env_int("CAPELLA_ENV_TTL_HOURS", 8),
        allow_unscoped_destructive=_env("CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE").lower()
        in ("1", "true", "yes", "on"),
        protected_clusters=_env_list("CAPELLA_PROTECTED_CLUSTERS"),
    )


# ── Assertions ───────────────────────────────────────────────────────────────


def resolve_org(args: dict, policy: Policy | None = None) -> str:
    """Return the organization id to use, refusing a mismatched override.

    When CAPELLA_ORG_ID is pinned, a caller-supplied organization_id that
    differs is an error rather than a silent override — an agent that has
    hallucinated or been fed a different org UUID should fail loudly, not
    quietly operate somewhere unexpected.
    """
    policy = policy or load_policy()
    supplied = (args.get("organization_id") or "").strip()
    pinned = policy.organization_id

    if pinned and supplied and supplied != pinned:
        raise GuardrailError(
            f"organization_id {supplied!r} does not match the server's pinned "
            f"CAPELLA_ORG_ID {pinned!r}.",
            hint=(
                "This server is bound to one Capella organization. Omit "
                "organization_id to use the pinned value, or deploy a second "
                "server instance for the other organization."
            ),
        )
    org = pinned or supplied
    if not org:
        raise GuardrailError(
            "No Capella organization id available.",
            hint=(
                "Set CAPELLA_ORG_ID (recommended — it also pins the guardrails), "
                "or pass organization_id explicitly. capella_organizations_list "
                "will show which organizations the API key can see."
            ),
        )
    return org


def assert_project_allowed(project_id: str, policy: Policy | None = None) -> None:
    """Refuse a destructive operation outside the allowlisted test projects."""
    policy = policy or load_policy()

    if not policy.destructive_allowed:
        raise GuardrailError(
            "Destructive Capella operations are disabled: CAPELLA_ALLOWED_PROJECTS "
            "is not set, so this server has no defined sandbox.",
            hint=(
                "Set CAPELLA_ALLOWED_PROJECTS to the project UUID(s) that hold "
                "throwaway test environments. Production projects must be left "
                "off that list — that omission is what makes them unreachable. "
                "For a personal throwaway organization only, "
                "CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE=true lifts the requirement."
            ),
        )

    if policy.allowed_projects and project_id not in policy.allowed_projects:
        raise GuardrailError(
            f"Project {project_id!r} is not in CAPELLA_ALLOWED_PROJECTS.",
            hint=(
                "Destructive operations are confined to the configured test "
                "projects. If this project genuinely should be reapable, a human "
                "must add it to the server's configuration and restart — it "
                "cannot be authorized from the client side."
            ),
        )


def assert_name_allowed(name: str, policy: Policy | None = None) -> None:
    """Refuse to create a resource whose name breaks the prefix convention.

    The prefix is what lets the reaper and the destructive guard distinguish
    "created by this server" from "created by a human", so a resource created
    without it would be un-reapable and un-deletable later.
    """
    policy = policy or load_policy()
    if policy.name_prefix and not name.startswith(policy.name_prefix):
        raise GuardrailError(
            f"Resource name {name!r} must start with CAPELLA_ENV_NAME_PREFIX "
            f"{policy.name_prefix!r}.",
            hint=(
                "The prefix is load-bearing: destructive operations refuse any "
                "resource lacking it, so a name without the prefix could never "
                "be torn down by this server."
            ),
        )


def is_managed_name(name: str, policy: Policy | None = None) -> bool:
    """Whether a resource name marks it as created by this server.

    Predicate form of the name-prefix rule, for callers that need to classify a
    list of resources rather than assert on one. With no prefix configured every
    name qualifies — consistent with the prefix being optional, and the reason a
    prefix is strongly recommended in any shared organization.
    """
    policy = policy or load_policy()
    if not policy.name_prefix:
        return True
    return name.startswith(policy.name_prefix)


def assert_managed(
    resource: dict,
    project_id: str,
    *,
    kind: str = "cluster",
    policy: Policy | None = None,
    verb: str = "modify",
) -> None:
    """Assert that a fetched resource is inside this server's sandbox.

    Takes the resource as returned by v4 — not just its id — so the decision is
    made on Capella's own view of the object rather than on caller-supplied
    claims about it. An agent cannot assert that a cluster is a test cluster; the
    name on the live object decides.

    This is the check that applies to EVERY mutating operation, not only deletes.
    Adding an IP allowlist entry, rewriting an access-control function or flushing
    a bucket on a production cluster is just as far out of scope as deleting it,
    and an operation that only checked the project would let all of those through
    on any unmanaged cluster that happened to sit in an allowlisted project.
    """
    policy = policy or load_policy()
    assert_project_allowed(project_id, policy)

    name = str(resource.get("name") or "")
    rid = str(resource.get("id") or "")

    # Match on id OR name. Operators overwhelmingly know clusters by name, so a
    # protected-list that only matched UUIDs would silently protect nothing —
    # worse than no protection at all, because it reads as configured.
    # Case-INSENSITIVE, matching every other spelling-tolerant comparison in this
    # file. An exact match failed OPEN: CAPELLA_PROTECTED_CLUSTERS=MCPTEST-KeepMe
    # against cluster mcptest-keepme was reported as protected by
    # capella_guardrails_status and deleted anyway. A protection that reads as
    # configured but does not hold is worse than none, which is the same argument
    # the name-match comment above makes.
    protected = {p.strip().casefold() for p in policy.protected_clusters if p.strip()}
    if (rid and rid.casefold() in protected) or (name and name.casefold() in protected):
        raise GuardrailError(
            f"{kind} {name or rid!r} appears in CAPELLA_PROTECTED_CLUSTERS.",
            hint="Explicitly protected by server configuration. No override exists.",
        )

    if policy.name_prefix and not name.startswith(policy.name_prefix):
        raise GuardrailError(
            f"Refusing to {verb} {kind} {name!r}: its name does not start with "
            f"CAPELLA_ENV_NAME_PREFIX {policy.name_prefix!r}, so this server did "
            f"not create it.",
            hint=(
                "This is the guard against a hand-made production cluster that "
                "happens to sit in an allowlisted project. Operate on it from the "
                "Capella UI if that is genuinely intended."
            ),
        )


#: Values Capella has used for an enabled deletion-protection flag. Compared
#: case-insensitively; the JSON boolean and several string spellings are all
#: treated as "protected" because guessing wrong here fails open.
_PROTECTION_ENABLED = frozenset({"true", "enabled", "on", "yes"})


def assert_deletable(
    resource: dict,
    project_id: str,
    *,
    kind: str = "cluster",
    policy: Policy | None = None,
) -> None:
    """Full destructive-operation check: sandbox membership plus Capella's own
    deletion-protection flag.

    Deletion protection is deliberately checked HERE and not in assert_managed:
    the flag means "do not destroy this", not "do not touch this". Refusing to
    park or reconfigure a protected cluster would push an operator toward turning
    protection off to get ordinary work done, which is exactly backwards.
    """
    policy = policy or load_policy()
    assert_managed(resource, project_id, kind=kind, policy=policy, verb="delete")

    name = str(resource.get("name") or resource.get("id") or "")
    for flag in (
        "deletionProtection",
        "deletion_protection",
        "deletionProtectionEnabled",
    ):
        value = resource.get(flag)
        if value is True or (
            isinstance(value, str) and value.strip().lower() in _PROTECTION_ENABLED
        ):
            raise GuardrailError(
                f"{kind} {name!r} has Capella deletion protection enabled.",
                hint=(
                    "Disable protection deliberately in Capella before teardown. "
                    "The flag exists precisely to require that extra step, and "
                    "this server will not override it."
                ),
            )


def count_managed_environments(
    list_clusters_for_project: Callable[[str], list[dict]],
    policy: Policy | None = None,
    fallback_project: str = "",
) -> int:
    """Count managed environments across the WHOLE sandbox.

    Takes a callable so this module stays free of any HTTP dependency, and so the
    orchestrator and the raw-primitive dispatch share ONE definition of "how many
    environments exist". They previously had two: the reconciler counted across
    every allowlisted project while the primitive counted only the project named
    in the call, which meant an agent calling capella_cluster_create directly and
    round-robining project_id could provision (projects x ceiling) clusters — the
    exact bypass the reconciler's version had been written to close, left open one
    layer down. A spend ceiling has to mean the same thing on every path that can
    spend.
    """
    policy = policy or load_policy()
    projects = list(policy.allowed_projects) or (
        [fallback_project] if fallback_project else []
    )
    total = 0
    for project in projects:
        for cluster in list_clusters_for_project(project):
            if not isinstance(cluster, dict):
                continue
            # Count by marker OR by managed name. Marker-only meant the ceiling could
            # not see anything created through capella_cluster_create, because the
            # primitive forwards the caller's body verbatim and never wrote a marker
            # -- so the guard bounding spend was blind to the cheapest way to spend.
            # Demonstrated with CAPELLA_MAX_ENVIRONMENTS=2: six clusters created,
            # count observed as 0, ceiling never tripped. The name-prefix guard DOES
            # fire on that path, which is what makes the name a sound second signal:
            # anything created through this server carries the prefix.
            #
            # Gated on a prefix BEING configured. is_managed_name returns True for
            # every name when there is no prefix, which would make the ceiling count
            # every pre-existing cluster in an allowlisted project and refuse creates
            # in an org that was previously working. So with no prefix the behaviour
            # is unchanged and marker-only -- one more reason the prefix is not
            # optional in practice.
            if parse_marker(cluster.get("description")) or (
                policy.name_prefix
                and is_managed_name(str(cluster.get("name") or ""), policy)
            ):
                total += 1
    return total


# ── Ceiling-refusal memo ─────────────────────────────────────────────────────
#
# Counting environments means listing clusters in every allowlisted project, with
# pagination. An agent that retries a create in a tight loop after being refused
# re-triggers that whole sweep on every attempt, amplifying read traffic against
# the organization's rate limit for calls that were never going to succeed.
#
# So once the ceiling is observed to be hit, that REFUSAL is remembered briefly
# and re-served locally without re-listing. Note the direction: caching a refusal
# is fail-safe (the worst case is refusing a create that has just become
# permissible, for a few seconds). Caching an ALLOWANCE would be fail-open and is
# deliberately not done — the count is always re-taken before anything is created.
_CEILING_MEMO_SECONDS = 15.0

#: Keyed by SCOPE, not global. A single process-global timestamp was the first
#: attempt and it was wrong: on the HTTP transport one process serves many
#: callers, so one project hitting its ceiling refused every other project's
#: creates for 15s — and re-polling the saturated project re-stamped the memo,
#: sustaining an org-wide block indefinitely. A performance optimisation that
#: converts "this project is full" into "nothing may be created anywhere" is a
#: denial of service, so the memo is scoped to exactly the set of projects the
#: count summed over.
_ceiling_refusals: dict[str, float] = {}


def ceiling_scope_key(policy: Policy, organization_id: str, project_id: str) -> str:
    """Identify the scope a ceiling decision applies to.

    With an allowlist, the count sums across every allowlisted project, so a
    refusal genuinely applies to that whole set. Unscoped, the count is
    per-project, so the refusal must be too.
    """
    if policy.allowed_projects:
        return f"{organization_id}|" + ",".join(sorted(policy.allowed_projects))
    return f"{organization_id}|{project_id}"


def ceiling_refusal_active(scope: str) -> bool:
    """True if this scope was refused very recently, so a re-count can be skipped."""
    stamped = _ceiling_refusals.get(scope)
    if stamped is None:
        return False
    if (time.monotonic() - stamped) >= _CEILING_MEMO_SECONDS:
        _ceiling_refusals.pop(scope, None)
        return False
    return True


def reset_ceiling_memo() -> None:
    """Clear all memoised refusals. Used by tests; safe to call at any time."""
    _ceiling_refusals.clear()


def raise_ceiling_refusal(policy: Policy | None = None) -> None:
    """Re-serve a recent ceiling refusal for this scope without re-counting."""
    policy = policy or load_policy()
    raise GuardrailError(
        f"Environment ceiling of {policy.max_environments} "
        "(CAPELLA_MAX_ENVIRONMENTS) was reached moments ago; refusing without "
        "re-checking to avoid hammering the Capella API in a retry loop.",
        hint=(
            "Tear down or reap finished environments (capella_env_list shows what "
            f"exists). The check is re-taken after {int(_CEILING_MEMO_SECONDS)}s. "
            "This refusal applies only to the projects the ceiling counts across."
        ),
    )


def assert_capacity(
    current_count: int, policy: Policy | None = None, scope: str = ""
) -> None:
    """Refuse to exceed the configured environment ceiling."""
    policy = policy or load_policy()
    if current_count >= policy.max_environments:
        if scope:
            now = time.monotonic()
            # Sweep expired keys on write so the dict cannot accumulate stale
            # entries for scopes that are never queried again.
            for key in [
                k
                for k, stamped in _ceiling_refusals.items()
                if (now - stamped) >= _CEILING_MEMO_SECONDS
            ]:
                _ceiling_refusals.pop(key, None)
            _ceiling_refusals[scope] = now
        raise GuardrailError(
            f"Environment ceiling reached: {current_count} of "
            f"{policy.max_environments} (CAPELLA_MAX_ENVIRONMENTS).",
            hint=(
                "Tear down or reap finished environments first "
                "(capella_env_list shows what exists, capella_env_reap removes "
                "expired ones). The ceiling is a spend guard against a retry "
                "loop provisioning clusters without bound."
            ),
        )


# ── Environment metadata marker ──────────────────────────────────────────────


def build_marker(
    env_name: str,
    *,
    ttl_hours: int | None = None,
    owner: str = "",
    extra: dict | None = None,
    now: datetime | None = None,
) -> str:
    """Build the ``mcp-env:{...}`` description line for a created resource."""
    # Checked at WRITE time as well as parse time. The greedy anchored parse now
    # survives a `}` in owner, but refusing it here means a marker never becomes
    # ambiguous in the first place, and the caller finds out at the call that named
    # the value rather than at a reap weeks later that quietly collected nothing.
    assert_marker_text_safe("env_name", env_name)
    assert_marker_text_safe("owner", owner)
    # Coerce and clamp the TTL at WRITE time. The schema declares an integer and
    # nothing enforced it, so `ttl_hours="4"` was written through verbatim and then
    # read back as non-numeric, which marker_expiry treated as "never expires" -- the
    # caller asked for four hours and got forever. An absurd value is refused rather
    # than clamped silently, because a caller who asked for a billion hours has made
    # a mistake worth hearing about.
    if ttl_hours is not None:
        try:
            ttl_hours = int(float(str(ttl_hours).strip()))
        except (TypeError, ValueError, OverflowError):
            raise GuardrailError(
                f"ttl_hours={ttl_hours!r} is not a number.",
                hint=(
                    "TTL drives whether capella_env_reap ever collects this "
                    "environment. A value it cannot read means 'never', so it is "
                    "refused here rather than quietly pinning a billable resource."
                ),
            ) from None
        if ttl_hours > _MAX_TTL_HOURS:
            raise GuardrailError(
                f"ttl_hours={ttl_hours} exceeds the maximum of {_MAX_TTL_HOURS} "
                f"({_MAX_TTL_HOURS // 24} days).",
                hint=(
                    "A TTL beyond this is indistinguishable from 'never expires' and "
                    "overflowed the expiry arithmetic, which broke every listing and "
                    "reap for the whole sandbox. Use ttl_hours=0 to pin an "
                    "environment deliberately."
                ),
            )
    policy = load_policy()
    created = (now or datetime.now(timezone.utc)).strftime(_ISO)
    payload: dict[str, Any] = {
        "env": env_name,
        "created": created,
        "ttl_h": ttl_hours if ttl_hours is not None else policy.default_ttl_hours,
    }
    if owner:
        payload["owner"] = owner
    if extra:
        payload.update(extra)
    return ENV_MARKER_PREFIX + json.dumps(
        payload, separators=(",", ":"), sort_keys=True
    )


_MARKER_RE = re.compile(re.escape(ENV_MARKER_PREFIX) + r"\s*(?=\{)")


def _extract_marker_json(description: str) -> str | None:
    """Return the marker's JSON object text, or None.

    Brace-COUNTING rather than a regex, because both regex forms tried here were
    wrong in opposite directions and each failed open -- an unparsed marker means
    "not ours", so the ceiling stops counting the cluster and the reaper stops
    collecting it, and it bills until a human notices.

      * `\\{.*?\\}` (non-greedy) stopped at the first `}`, including one inside a
        JSON string value. `owner="ci pipeline }run-42"` truncated the marker to
        invalid JSON. A plausible CI value, no adversary needed.
      * `\\{.*\\}\\s*$` (greedy, anchored) fixed that but required the closing brace
        to be the last thing on the line, so `mcp-env:{...} keep until Friday`
        stopped parsing -- and this module's own caller promises a human may write a
        note next to the marker.

    Counting braces while tracking JSON string state satisfies both: it survives a
    brace inside a value AND ignores anything after the object ends.
    """
    match = _MARKER_RE.search(description)
    if not match:
        return None
    text = description[match.end() :]
    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[: index + 1]
        elif char in "\n\r" and depth == 0:
            return None
    return None  # unbalanced: no closing brace for the object we opened


#: Characters refused in caller-supplied marker text. Defence in depth alongside the
#: greedy parse: the parse now survives them, and refusing them keeps a description a
#: human can read and re-parse by eye.
#: Upper bound on a marker TTL. 365 days: long enough for any legitimate
#: long-lived sandbox, short enough that the expiry arithmetic cannot overflow.
_MAX_TTL_HOURS = 24 * 365

_MARKER_UNSAFE_CHARS = ('"', "{", "}", "\\", "\n", "\r")


def assert_marker_text_safe(field: str, value: str | None) -> None:
    """Refuse marker text that could corrupt the ownership record.

    Raised rather than sanitised: silently rewriting an operator's `owner` would make
    the audit trail disagree with what they typed, and the value is free text they can
    trivially adjust.
    """
    if not value:
        return
    found = [c for c in _MARKER_UNSAFE_CHARS if c in value]
    if found:
        raise GuardrailError(
            f"{field}={value!r} contains {', '.join(repr(c) for c in found)}, which "
            f"cannot appear in the ownership marker this server writes into the "
            f"resource description.",
            hint=(
                "The marker is one line of JSON in a field humans also edit. Quotes, "
                "braces, backslashes and newlines make it ambiguous to re-parse, and "
                "a marker that fails to parse is treated as 'not ours' — which means "
                "the environment ceiling stops counting it and the reaper stops "
                "collecting it, so it bills until someone notices. Use plain text."
            ),
        )


def parse_marker(description: str | None) -> dict | None:
    """Extract the environment marker from a description, or None.

    Tolerant by design: a human may have edited the description around the
    marker line, and a malformed marker must not crash a list or reap call — it
    simply means "not recognizably ours", which the caller treats as
    not-reapable.
    """
    if not description:
        return None
    raw = _extract_marker_json(description)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        _log.debug("malformed mcp-env marker ignored: %r", description[:120])
        return None
    return data if isinstance(data, dict) else None


def marker_expiry(marker: dict) -> datetime | None:
    """Absolute expiry time for a marker, or None if it never expires.

    ``ttl_h`` of 0 or a negative value means "no TTL" — an explicitly pinned
    environment the reaper must leave alone.
    """
    created_raw = marker.get("created")
    ttl = marker.get("ttl_h")
    # A str/bool ttl_h used to fall through this isinstance check and mean "never
    # expires", so `ttl_hours="4"` -- which nothing validated, despite the schema
    # declaring an integer -- silently pinned the environment forever. Coerce
    # numeric strings instead, and treat an uncoercible value as pinned only after
    # saying so, because "never reaped" is the expensive direction.
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
        try:
            ttl = float(str(ttl).strip())
        except (TypeError, ValueError):
            _log.warning(
                "mcp-env marker has a non-numeric ttl_h=%r; treating as pinned "
                "(it will never be auto-reaped). Fix the marker or the caller.",
                marker.get("ttl_h"),
            )
            return None
    if not created_raw or ttl <= 0:
        return None
    try:
        created = datetime.strptime(str(created_raw), _ISO).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    # OverflowError/OSError, not just ValueError. A large ttl_h or a far-future
    # `created` made this arithmetic raise, and because every caller reaches it
    # through a list, that ONE poisoned description broke capella_env_list,
    # capella_env_status and BOTH reap modes for the entire sandbox -- so no
    # genuinely expired environment anywhere got collected until a human found it.
    # One bad marker must degrade to "not recognizably ours", never to an outage.
    try:
        return created + timedelta(hours=float(ttl))
    except (OverflowError, OSError, ValueError):
        _log.warning(
            "mcp-env marker ttl_h=%r overflows a representable date; treating as "
            "pinned rather than failing the whole listing.",
            ttl,
        )
        return None


def is_expired(marker: dict, *, now: datetime | None = None) -> bool:
    expiry = marker_expiry(marker)
    if expiry is None:
        return False
    return (now or datetime.now(timezone.utc)) >= expiry


def policy_warnings(policy: Policy | None = None) -> list[str]:
    """Configuration weaknesses worth stating out loud.

    A control that silently does nothing is worse than an absent one, because the
    config file reads as though it is protecting you. Each entry here names a
    guardrail that is present in principle but inert as configured.
    """
    policy = policy or load_policy()
    warnings: list[str] = []

    if policy.destructive_allowed and not policy.name_prefix:
        warnings.append(
            "CAPELLA_ENV_NAME_PREFIX is not set, so the per-resource ownership "
            "check is INERT: every cluster in an allowlisted project counts as "
            "this server's, and destructive operations are confined only by the "
            "project list. Set a prefix in any organization where an allowlisted "
            "project might also hold clusters created by hand."
        )

    if policy.allow_unscoped_destructive:
        warnings.append(
            "CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE is enabled: destructive "
            "operations are permitted anywhere in the organization. Intended only "
            "for a personal throwaway organization."
        )
        warnings.append(
            "In unscoped mode CAPELLA_MAX_ENVIRONMENTS is enforced PER PROJECT, "
            "not organization-wide: with no allowlist there is no set of projects "
            "to sum across, so a caller varying project_id gets a fresh ceiling "
            "in each one. Set CAPELLA_ALLOWED_PROJECTS to make the ceiling global."
        )

    if policy.destructive_allowed and not policy.organization_id:
        warnings.append(
            "CAPELLA_ORG_ID is not pinned, so the organization is taken from "
            "whatever the caller supplies. Pin it to bind this server to one "
            "organization."
        )

    if policy.default_ttl_hours <= 0:
        warnings.append(
            "CAPELLA_ENV_TTL_HOURS is 0 or negative, so new environments never "
            "expire and capella_env_reap will not collect them. An abandoned CI "
            "job will bill indefinitely."
        )

    return warnings


def describe_policy() -> dict:
    """Policy summary for the status tool and the startup banner.

    Surfacing this is part of the control: an operator should be able to ask the
    server what its blast radius is, and get an answer from the same code path
    that enforces it rather than from documentation that may have drifted.
    """
    policy = load_policy()
    return {
        "organization_pinned": bool(policy.organization_id),
        "allowed_projects": list(policy.allowed_projects),
        "name_prefix": policy.name_prefix or None,
        "max_environments": policy.max_environments,
        "default_ttl_hours": policy.default_ttl_hours,
        "protected_clusters": list(policy.protected_clusters),
        "destructive_operations_enabled": policy.destructive_allowed,
        "warnings": policy_warnings(policy),
        "posture": (
            "sandboxed"
            if policy.allowed_projects
            else (
                "UNSCOPED — destructive ops allowed org-wide"
                if policy.allow_unscoped_destructive
                else "fail-closed — destructive ops refused"
            )
        ),
    }
