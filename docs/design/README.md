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
| [capella-client-and-guardrails.md](capella-client-and-guardrails.md) | The Capella v4 client, retries, and the sandbox that confines unattended writes | `handlers/capella/client.py`, `handlers/capella/guardrails.py`, `handlers/capella/__init__.py` |
| [egress-allowlist.md](egress-allowlist.md) | Where the cluster may be told to connect | `handlers/egress.py` |
| [fixtures.md](fixtures.md) | Named, hash-verified datasets on both planes | `handlers/fixture_core.py`, `handlers/fixture.py`, `handlers/capella/fixture.py` |
| [transports.md](transports.md) | stdio, streamable HTTP, caller identity and TLS | `server.py`, `auth/request_auth.py`, `tls_config.py` |

Where writing a note found a gap (an untested guard, an unchecked claim), the note says so under
"Before you change it", with the date it was checked. A gap is a fact about the repository on that
date, not a decision. A question that needs Chris is in `docs/questions.md`.
