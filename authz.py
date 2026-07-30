"""
authz.py — the confirmation/ceiling decision, in ONE place.

WHY THIS MODULE EXISTS
======================
There are two dispatch paths into the handlers: the MCP tool dispatch in server.py
and ``POST /api/call`` in gui/gui_server.py. Both re-implemented the same
authorization reasoning, and both times the GUI copy drifted:

  * ``bool(body.get("automation"))`` let a caller self-promote out of the
    confirmation gate with one JSON field — fixed in the GUI only.

  * The hard-ceiling check sat INSIDE ``if in_confirm_set and automation_mode``, so
    with automation mode off, a ceiling tool fell through to the ordinary
    confirmation gate and a caller-supplied ``confirm: true`` satisfied it. A
    read-only tool named in the ceiling skipped the check altogether, because
    ``in_confirm_set`` was false.

  * No audit record was emitted for ANY GUI operation, so the console was the one
    way to perform a privileged action that left no trace — while server.py had
    grown a full record on every decision path.

  * ``check_scope`` was never called, so any authenticated user in the tenant had
    the entire tool surface regardless of the scopes in their token.

Divergence is the predictable outcome of expressing one policy twice. So the policy
lives here, both callers ask this module, and a fix lands in both by construction.

WHAT THE POLICY IS
==================
1. Scope. If a token is present, its scopes must satisfy the tool's requirement.
   Fails closed when authentication is required.

2. The hard ceiling (``CB_ADMIN_ALWAYS_CONFIRM``). Evaluated FIRST, for every tool,
   regardless of read-only-ness, automation, or the confirmation set. Where no human
   is present at the client it is a refusal — ``confirm: true`` is a value the
   caller supplies, so an unattended agent using it to satisfy a ceiling is
   rubber-stamping itself. Where a human IS present it forces the confirmation even
   for a tool that would not otherwise be gated.

3. Automation. A principal holding the automation scope skips the per-call human
   confirmation for ordinary gated writes: the human authorization happened once,
   when the IdP issued that service principal its credential. This is the enterprise
   flow working as designed, not a bypass.

4. Otherwise the ordinary confirmation gate applies.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import profile_config


@dataclass(frozen=True)
class Decision:
    """The outcome of the policy for one call."""

    #: Audit decision label. "allowed" means proceed.
    decision: str
    #: Human-readable refusal reason; empty when allowed.
    reason: str = ""
    #: Extra fields the caller should surface in its error payload.
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision == "allowed"


def hard_ceiling_tools() -> frozenset[str]:
    """Tools that require a human even for an authorized automation principal.

    Read from the environment on each call rather than snapshotted at import, so a
    test (and an operator restarting with a new value) sees the current setting.
    """
    return frozenset(
        n.strip()
        for n in os.environ.get("CB_ADMIN_ALWAYS_CONFIRM", "").split(",")
        if n.strip()
    )


def human_is_present() -> bool:
    """Whether `confirm: true` can be believed as a human's second look.

    The profile NAME is not sufficient evidence, which is what this used to test.
    ``_validate_workstation_is_actually_local()`` exists precisely to check the
    premise — but it accepts ``CB_ADMIN_WORKSTATION_CONTAINER_BIND=1`` as a waiver for
    the container shape, and nothing verifies the "-p 127.0.0.1:PORT:PORT" claim that
    waiver asserts. So with the waiver set, a REMOTE authenticated caller holding no
    automation scope could satisfy the hard ceiling with its own ``confirm: true`` —
    the one value this module says must never be believed when no human is present.

    So the test is on the TRANSPORT, not the label:

      * stdio — a human is at the MCP client by construction. There is no socket; the
        process is spoken to over its own stdin by the program that launched it.
      * anything else — a request arrived over a network socket, and this code cannot
        tell whether a person authorised it. The ceiling refuses.

    That makes the workstation console (loopback HTTP, peer-checked) subject to the
    ceiling too, which is correct: a browser request is not a human confirmation, and
    the CSRF finding showed exactly how a page could supply one.
    """
    if profile_config.PROFILE_NAME != profile_config.WORKSTATION:
        return False
    transport = (os.environ.get("CB_ADMIN_TRANSPORT") or "stdio").strip().lower()
    return transport == "stdio"


def evaluate(
    tool_name: str,
    *,
    in_confirm_set: bool,
    has_automation_scope: bool,
    human_present: bool | None = None,
) -> tuple[Decision, bool]:
    """Apply the ceiling and automation policy.

    Returns ``(decision, in_confirm_set)``. When the decision is allowed, the second
    element is the confirmation requirement the caller must still enforce — the
    ceiling can RAISE it (workstation) and automation can clear it.

    ``human_present`` lets a caller state its OWN evidence rather than inheriting the
    MCP transport's. This matters because CB_ADMIN_TRANSPORT describes the MCP server
    and says nothing about the console: an unset value means "stdio", so the GUI would
    otherwise inherit "a human is present" from a variable about a different process.
    Each caller documents what its evidence actually is.
    """
    if human_present is None:
        human_present = human_is_present()

    if tool_name in hard_ceiling_tools():
        if not human_present:
            return (
                Decision(
                    "denied_hard_ceiling",
                    reason=(
                        f"`{tool_name}` is in the hard ceiling "
                        "(CB_ADMIN_ALWAYS_CONFIRM) and cannot be executed in a "
                        "deployment where no human is present at the client. "
                        "`confirm: true` does not satisfy it — that value is "
                        "supplied by the caller. Perform this operation through an "
                        "interactive, human-driven session."
                    ),
                    detail={"requires_confirmation": True, "hard_ceiling": True},
                ),
                in_confirm_set,
            )
        # A human is present: force the confirmation even for a tool that would not
        # otherwise be gated (a read-only tool named in the ceiling, or one loosened
        # via CB_ADMIN_CONFIRMATION_REQUIRED_TOOLS).
        return Decision("allowed"), True

    if in_confirm_set and has_automation_scope:
        # Authorized automation: the credential carries the authorization.
        return Decision("allowed"), False

    return Decision("allowed"), in_confirm_set
