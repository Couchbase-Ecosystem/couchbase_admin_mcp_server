# Authorization: who may do what, and who is present

**Source:** `authz.py` (the policy), `server.py` `call_tool` (the MCP path),
`gui/gui_server.py` `call_tool` (the console path), `auth/scope_gate.py` (token scopes).
**Spec:** `docs/spec.md` S3 steps 3 to 5, S5. **Open questions:** Q-003 (the audit decision
vocabulary).

## What it decides

For every tool call, three things, in this order:

1. **Scope.** If a token is present, its scopes must cover the tool. With no token (stdio),
   this step does nothing. Refusal: `denied_scope`.
2. **The hard ceiling.** The tools named in `CB_ADMIN_ALWAYS_CONFIRM`. Where no human is
   present, a ceiling tool is refused outright. Where a human is present, the call is
   forced to need confirmation even if the tool would not normally. Refusal:
   `denied_hard_ceiling`.
3. **Confirmation and automation.** A tool in the confirmation set needs `confirm: true`.
   A principal whose token carries the automation scope skips that per-call confirmation
   for ordinary gated writes. Refusal: `denied_confirmation`.

`authz.evaluate` makes steps 2 and 3 and returns a `Decision`. Step 1 is
`auth.scope_gate.check_scope`.

## Why it is built this way

**The ceiling is evaluated first and for every tool.** It was once evaluated only when the
caller held the automation scope. That inverted the privilege model: a principal with write
but not automation skipped the ceiling, so removing a scope from a token granted
capability and the most privileged principal was the only one refused. The comment in
`server.py` above the `authz.evaluate` call records this.

**`confirm: true` is never evidence of a human.** The model supplies it. On a workstation a
person sees the call and can say no, so it is a real second look. Over the network, nobody
can tell, so `human_is_present()` answers False and the ceiling refuses. The authorization
for unattended work happened once, when the identity provider issued the service principal
a token with the automation scope. That is the enterprise flow working as designed.

**Human presence is tested on the transport, not the profile name.** The workstation
profile can be waived into a container shape with `CB_ADMIN_WORKSTATION_CONTAINER_BIND=1`,
and nothing verifies the loopback claim that waiver makes. So with the label as the test, a
remote authenticated caller with no automation scope could satisfy the ceiling with its own
`confirm: true`. The rule now is: workstation profile and stdio means a human is at the
client; anything else means no human. That makes the workstation console (loopback HTTP)
subject to the ceiling too, which is intended, because a browser request is not a human
confirmation.

**The console states its own evidence.** `CB_ADMIN_TRANSPORT` describes the MCP server and
says nothing about the console, and an unset value means stdio, so the console would
inherit "a human is present" from a variable about a different entry point. The console
passes `human_present=False` to `evaluate` and to `caller_context`. The two dispatch paths
ask the same module, so a fix lands in both. They once each had their own copy, and the
console's drifted (see the history below).

## The caller evidence

`authz.caller_context(human_present=...)` wraps the handler call. Anything below the
dispatch that asks `human_is_present()` gets this call's answer, not the process-wide one.
Three choices in it are easy to undo by accident:

- **It is stored on the thread object, not in a `threading.local()` and not in a
  `ContextVar`.** A module-level `threading.local()` failed a test: the suite re-imports
  `authz`, and `handlers.capella.environment.authz` was observed to be a different module
  object from `sys.modules["authz"]`. Two copies mean two thread-locals, so the console set
  the flag on one and the composite guard read nothing from the other. The thread object is
  the same however many copies of the module exist. A `ContextVar` does not work because
  `run_in_executor` does not carry context across to the worker thread, so the value is set
  inside the thread that runs the handler (`_run_handler` in `server.py`).
- **Nesting only narrows.** An inner context may say "no human" inside an outer "human
  present", never the reverse (`effective = human_present if previous is not False else
  False`). No composite tool re-enters the dispatch today, so this is not a live hole. It is
  there so the property holds by construction and not by accident.
- **The attribute is removed on the outermost exit.** Executor threads are pooled. A value
  left behind would answer for the next call to land on that worker.

## What went wrong before

| Finding | What happened | Held by |
| --- | --- | --- |
| Console copy of the policy drifted | A caller could promote itself out of the confirmation gate with one JSON field. The ceiling sat inside `if in_confirm_set and automation_mode`, so with automation off a caller's `confirm: true` satisfied it. The console wrote no audit record and never called `check_scope`. | `tests/test_dispatch_parity.py`, `tests/test_gui_authorization.py` |
| SEC-1: the ceiling answered two ways | In a console process on a workstation profile, `capella_env_teardown` deleted a cluster named in `CB_ADMIN_ALWAYS_CONFIRM` that `capella_cluster_delete` refused on the same request. Verified against live Capella with a real DELETE. | `tests/test_scan_20260817_regressions.py` (`test_sec1_*`) |
| Ceiling gated on the automation scope | See "The ceiling is evaluated first" above. | `tests/test_automation_model.py` (`test_hard_ceiling_not_bypassable_by_automation*`) |
| Entra tokens | Entra client-credentials tokens carry app permissions in `roles`, not `scp`. Reading only `scope`, `scp` and `scopes` hid an automation grant and downgraded an authorized caller to per-call confirmation. All present claims are now unioned. | `tests/test_scope_claim_shapes.py` |

## Check before changing it

- Change policy only in `authz.py`. If a branch of the policy appears in `server.py` or
  `gui/gui_server.py`, move it, or the paths will drift again.
- Run `tests/test_dispatch_parity.py`, `tests/test_automation_model.py`,
  `tests/test_scan_20260817_regressions.py` and `tests/test_gui_authorization.py`. They
  fail when the two paths decide differently.
- The correlation id and `confirm` are control fields. Neither may influence a decision
  beyond what is described here, and both are removed before the handler runs.
- The audit decision names are listed in `docs/spec.md` S4. `Decision.decision` uses them
  as labels, so a new refusal needs a new name there (see Q-003).

## What this note does not cover

How a token is validated (`auth/oidc.py`), and how the console signs a person in
(`auth/session.py`). The Capella guardrails, which add a second ceiling for Capella writes
(`handlers/capella/guardrails.py`), are for a later note.
