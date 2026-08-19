"""dryrun.py — preview a write without performing it, in ONE place.

WHY THIS EXISTS
===============
The architecture document claimed "every Admin MCP tool takes a dry-run flag". That was
false when it was written: exactly one tool had one, ``capella_env_reap``, whose
``dry_run`` argument defaults to true because reaping clusters is the operation you least
want to fire by accident. Every other one of the 200-odd tools acted immediately.

A dry run is worth more here than in most servers, because the intended caller is an
agent. The cheapest review of a plan an agent produced is the plan itself: the tool it
picked, the target it resolved, and the payload it assembled, in front of a person before
anything runs. That artifact is also what you attach to a change request.

WHERE THE DECISION LIVES
========================
In this module, not in the handlers, for the same reason ``authz.py`` exists: there are
two dispatch paths into the handlers -- the MCP tool dispatch in ``server.py`` and
``POST /api/call`` in ``gui/gui_server.py`` -- and a policy expressed twice diverges. Both
ask here.

THE POLICY
==========
1. A tool that declares ``dry_run`` in its own input schema OWNS the flag. The dispatch
   does not intercept it. ``capella_env_reap`` needs a real dry run that lists which
   clusters it would reap, which means reading Capella -- something only the handler can
   do. Intercepting it centrally would have replaced a useful preview with a stub, and
   silently changed its default from true to false.

2. Otherwise a dry run is requested by ``dry_run: true`` on the call, or demanded for
   every call by ``CB_ADMIN_DRY_RUN=true`` in the environment. The environment wins: a
   caller cannot pass ``dry_run: false`` to escape a server-wide preview mode. That
   asymmetry is the point -- preview mode is an operator control, in the same family as
   ``CB_ADMIN_READ_ONLY_MODE``, and a control a caller can turn off is not a control.

3. Read-side tools execute normally even under a dry run. A read changes nothing, so
   refusing it would remove the very information a plan is checked against -- and an
   agent that cannot read while previewing cannot produce a plan worth reviewing.

4. A write is not executed. The call returns what WOULD have happened: the tool, the
   arguments as resolved after gating, the deployment mode, and the reason the dry run
   was in effect. It returns as a normal success payload, so a client that does not know
   about dry runs still gets a readable answer rather than an error.

WHAT A DRY RUN IS NOT
=====================
It is not authorization. The scope gate, the hard ceiling and the confirmation gate all
run BEFORE this, so a dry run of a tool you may not call is still a refusal -- previewing
is not a way to find out what a privileged tool would do. And it is not validation: the
payload is not sent, so nothing checks it against the cluster. A dry run tells you what
the agent decided to do. Whether the cluster would accept it is a different question.
"""

from __future__ import annotations

import os
from typing import Any

ARG = "dry_run"
ENV = "CB_ADMIN_DRY_RUN"

_TRUE = ("1", "true", "yes", "on")

#: What the flag says in a tool schema, so the model sending it knows what it gets back.
SCHEMA_PROPERTY = {
    "type": "boolean",
    "description": (
        "Preview only. When true the call is authorized and audited but NOT performed: "
        "the response says which tool would have run, against which target, with which "
        "arguments. Use it to put an agent's plan in front of a person before the first "
        "real run, and keep the output as the record of what was proposed. Reads ignore "
        "it, because a read changes nothing. CB_ADMIN_DRY_RUN=true forces it for every "
        "call and cannot be overridden from here."
    ),
}


def server_wide() -> bool:
    """Whether the operator has put the whole server in preview mode.

    Read from the environment on every call rather than snapshotted at import, so an
    operator can turn preview mode on in a running deployment the way the hard ceiling
    is read fresh -- the emergency-stop path depends on that property.
    """
    return (os.environ.get(ENV, "") or "").strip().lower() in _TRUE


#: Tools whose own handler implements ``dry_run``. Recorded by name at startup rather than
#: inferred from the schema on every call, because the schema is not a safe signal once the
#: dispatch starts ADVERTISING ``dry_run`` on write tools: "declares dry_run" would then be
#: true of everything, `handler_owns` would return True everywhere, and the interception
#: would silently stop happening for all 200 tools. Registration runs against the raw
#: schemas, before injection.
_HANDLER_OWNED: set[str] = set()


def register_handler_owned(tools: Any) -> set[str]:
    """Record which of `tools` declare their own ``dry_run``. Call once, on the RAW tools."""
    for tool in tools:
        # Through mcp_compat, not a bare getattr with a default. The getattr form
        # returns the DEFAULT under mcp 2.x field naming instead of failing, so
        # _HANDLER_OWNED would come back empty and capella_env_reap would silently
        # lose the dry_run flag it implements. mcp_compat.input_schema raises on an
        # unrecognised shape, which is the whole reason it exists -- and the AST guard
        # in test_mcp_compat cannot see a getattr-by-string, which is why this survived.
        import mcp_compat

        schema = mcp_compat.input_schema(tool)
        if not isinstance(schema, dict):
            continue
        properties = schema.get("properties")
        if isinstance(properties, dict) and ARG in properties:
            name = getattr(tool, "name", None)
            if name:
                _HANDLER_OWNED.add(name)
    return set(_HANDLER_OWNED)


def handler_owned_tools() -> set[str]:
    return set(_HANDLER_OWNED)


def handler_owns(tool: Any) -> bool:
    """True when the tool implements ``dry_run`` itself, so the dispatch keeps its hands off."""
    return getattr(tool, "name", None) in _HANDLER_OWNED


def requested(arguments: dict[str, Any] | None) -> bool:
    """Whether this call asked for a dry run. Tolerant of the string forms a client may send."""
    if not arguments:
        return False
    value = arguments.get(ARG)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in _TRUE
    return False


def in_effect(arguments: dict[str, Any] | None, tool: Any) -> tuple[bool, str]:
    """Return (dry_run_applies, why).

    ``why`` is written into the payload and the audit record so a reader can tell an
    operator-wide preview from a caller asking for one -- they mean different things when
    the question later is "why did nothing happen?".
    """
    if handler_owns(tool):
        return False, ""
    if server_wide():
        return True, f"{ENV}=true (server-wide preview mode)"
    if requested(arguments):
        return True, f"{ARG}=true on this call"
    return False, ""


def strip(arguments: dict[str, Any]) -> None:
    """Remove the control field so it cannot reach a REST or SDK call as a stray parameter.

    The same hazard as ``confirm`` and ``correlation_id``: a Capella v4 request body with
    an unexpected member is a 400 at best, and at worst a member the API quietly honours.
    """
    arguments.pop(ARG, None)


def preview(
    name: str,
    arguments: dict[str, Any],
    *,
    reason: str,
    deployment_mode: str = "",
    read_side: bool = False,
) -> dict[str, Any]:
    """The payload returned instead of performing the write.

    A plain dict with both a human ``message`` and structured fields, because the two
    callers wrap it differently: the MCP dispatch hands it to ``shared.ok()``, which
    serialises it into a text block like every other tool result, and the console returns
    it as JSON. An earlier version built its own ``content`` list here, which then got
    nested inside ok()'s -- one payload carrying two different shapes of the same thing.
    """
    # Redact BEFORE formatting, which is the whole point. ``ok()`` masks the dict on
    # the way out, but ``redact()`` is a documented no-op on a string, so a password
    # formatted into ``message`` below survived every downstream masking step and
    # reached the model's context in clear -- while the SAME value in ``arguments``
    # was masked, which is what made it look handled. Reachable on
    # admin_user_create, admin_user_change_password, admin_user_create_temporary,
    # admin_node_add, admin_xdcr_reference_create, admin_alerts_set (emailPass) and
    # admin_kmip_set. And the console consumer applies no redaction at all, so there
    # both the prose and the dict leaked. Doing it here closes both consumers at
    # once, because both read this one payload.
    #
    # Imported inside the function, not at module scope: profile_config writes into
    # the environment at import time, so every top-level module server.py imports is
    # order-sensitive, and dryrun has no other reason to depend on handlers.
    from handlers.shared import redact

    shown = redact({k: v for k, v in arguments.items() if k != ARG})
    lines = [
        f"DRY RUN — {name} was NOT executed.",
        f"Why: {reason}.",
    ]
    if deployment_mode:
        lines.append(f"Target: {deployment_mode}.")
    lines.append(
        "Arguments as resolved: "
        + (", ".join(f"{k}={v!r}" for k, v in sorted(shown.items())) or "(none)")
    )
    lines.append(
        "Nothing was changed. Re-call without the dry run to perform it, "
        "and keep this output as the record of what was proposed."
    )
    return {
        "message": "\n".join(lines),
        "dry_run": True,
        "executed": False,
        "tool": name,
        "arguments": shown,
        "reason": reason,
        "deployment_mode": deployment_mode or None,
        "read_side": read_side,
    }
