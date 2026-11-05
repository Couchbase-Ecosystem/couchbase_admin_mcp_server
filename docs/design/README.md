# Design notes

One note per hard subsystem: the parts where the code is short but the reasons are long.
Each note says what the subsystem decides, why it is built that way, what went wrong
before, which tests hold each property in place, and what to check before changing it.

A note explains reasons. `docs/spec.md` states today's behavior and `docs/questions.md`
holds the open decisions. Chris Ahrendt decides the architecture, so a note records a
decision he made or one that is open in `questions.md`. It does not make one.

| Note | Subsystem | Source |
| --- | --- | --- |
| [authorization.md](authorization.md) | Scope, hard ceiling, automation and confirmation, and the evidence that a human is present | `authz.py`, `server.py`, `gui/gui_server.py`, `auth/scope_gate.py` |

Planned, in this order: the Capella client and guardrails, fixtures, the egress allowlist,
the transports.
