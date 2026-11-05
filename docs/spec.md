# Specification of today's behavior

Version 0.1, 2026-11-02. **Change in this version:** first numbered draft, written from
the code at the commit named in `CHANGELOG.md`. It describes what the server does now,
so source headers can cite section numbers (decision Q1, `docs/questions.md`).

Status: [DESIGN] until Chris Ahrendt approves it as the specification of record. Where I
could not confirm a point from the code, the section says [VERIFY]. Where the document
points to another file instead of restating, that file is the source and was not re-read
for this draft.

Each section has a number, `S<n>`. Headers cite them as, for example, "spec S3".

## S1. Purpose and surface

The server exposes Couchbase administration as MCP tools. Tools have three prefixes,
because they reach three different systems with three different credentials:

| Prefix | Reaches | Credential |
| --- | --- | --- |
| `admin_*` | Self-managed cluster, ns_server REST | HTTP Basic (`CB_USERNAME`, `CB_PASSWORD`) |
| `capella_*` | Capella v4 control plane | Bearer API key secret |
| `cb_*` | Query service and server introspection | Cluster credentials, or none |

Counts are in `docs/tools.json` and in `docs/ARCHITECTURE.md`, each with its date. Do not
quote a count here without one.

## S2. One container, one control plane

A container or process drives one control plane: Capella or self-managed. It loads only
the tools that can work there. `deployment.py` detects the mode, and
`CB_ADMIN_REQUIRE_DEPLOYMENT` makes start-up refuse when the mode cannot be resolved.
Source: `deployment.py`, `docs/CONTAINER_DEPLOYMENT.md`, rule 2.1 in `AGENTS.md`.

## S3. How a tool call is decided

`call_tool` in `server.py` applies these steps in this order. A refusal at any step is a
normal, structured return value, not an exception, and each one writes an audit record
(S4).

1. **Unknown tool.** No handler is registered: refused (`denied_unknown_tool`).
2. **Not loaded.** The tool is registered but not in the current tool list. The reason
   is deployment mode (`denied_deployment`), or read-only mode or the disabled list
   (`denied_read_only`). The console reports a tool in the disabled list as
   `denied_disabled` instead (`gui/gui_server.py`).
3. **Scope.** If a token is present, its scopes must satisfy the tool (`denied_scope`).
   With no token (stdio), this step does nothing.
4. **Hard ceiling and automation.** `authz.evaluate` decides first, for every tool,
   whether the hard ceiling (`CB_ADMIN_ALWAYS_CONFIRM`) applies. Where no human is
   present, a ceiling tool is refused. `confirm: true` cannot satisfy it, because the
   caller supplies that value (`denied_hard_ceiling`).
5. **Confirmation.** A tool in the confirmation set needs `confirm: true`, unless the
   principal holds the automation scope for an ordinary gated write
   (`denied_confirmation`).
6. **Control fields are removed.** `confirm` and the correlation id are removed so
   neither reaches a REST or SDK call. The correlation id is provenance only and never
   influences a decision.
7. **Dry run.** After every gate, a write with `dry_run` is withheld and a preview is
   returned (`dry_run`). Reads still run. A tool that implements `dry_run` itself keeps the
   argument.
8. **Handler.** Runs on a worker thread (`docs/THREADING_MODEL.md`). A handler may refuse
   (egress allowlist, Capella guardrail, validation). The audit decision is taken from its
   result (`denied_egress`, `denied_guardrail`, `denied_handler`, `allowed`), or `error`
   when it raises.

The console (`POST /api/call` in `gui/gui_server.py`) asks the same `authz` module, so the
policy is expressed once.

## S4. Audit record

One structured JSON line per decision, written through the logging module with the prefix
`AUDIT ` and, when configured, to a separate audit file. A record never raises: if a record
cannot be built in full, a reduced record is written (`audit.emit`).

The decision vocabulary is `audit.DECISIONS` (decided 2026-11-05, Q-003). It has fourteen
names, each with its meaning in that table:

`allowed`, `dry_run`, `error`, `denied_authentication`, `denied_confirmation`,
`denied_deployment`, `denied_disabled`, `denied_egress`, `denied_guardrail`,
`denied_handler`, `denied_hard_ceiling`, `denied_read_only`, `denied_scope`,
`denied_unknown_tool`.

Where the less obvious ones come from: `denied_authentication` is written by
`audit.emit_auth_failure` as an `auth_failure` event when a credential is rejected.
`denied_guardrail`, `denied_egress` and `denied_handler` are taken from a handler's
result by `audit.classify_result`: a guardrail marker, an egress-denial message, or any
other refusal.

The docstring of `audit.build_record`, this section and `audit.DECISIONS` list the same
names, and `tests/test_audit_vocabulary.py` fails when they disagree with each other or
with the denials the code emits.

## S5. Profiles

`CB_ADMIN_PROFILE` is `workstation` or `enterprise`. It has no default, and the server
refuses to start without it (`profile_config.py`).

- **workstation:** a person is present at the client, identity is the operating-system
  user, nothing is exposed to the network, and `confirm: true` is a real second look.
- **enterprise:** no person is present by design. Authorization happens when the identity
  provider issues the service principal a token with the automation scope. `confirm: true`
  means nothing, because the model supplies it. `CB_ADMIN_HTTP_REQUIRE_AUTH` must be true,
  and start-up refuses without a durable audit sink and without an OAuth issuer
  (`profile_config.validate`).

Explicit environment variables override profile defaults. An incoherent combination is
refused at start-up.

## S6. Transports

- **stdio** (default): no token. Used by local clients.
- **streamable HTTP** (`CB_ADMIN_TRANSPORT=http`): a session manager gives each client
  its own session. The caller's authorization is resolved from the request inside the
  dispatch task (`auth/request_auth.py`). Origin and host validation are on, and TLS is
  set up by `tls_config.py`. [VERIFY] The exact defaults for allowed origins and hosts:
  read `_allowed_origins` and `_allowed_hosts` in `server.py`.

## S7. Protocol error flag

Every refusal is reported to the client with `isError: true`. The server wraps the
registered call handler and sets the flag when the result carries the shared error marker
(`server.py`, `_call_tool_with_is_error`). The marker is the one `audit.classify_result`
uses, so the flag and the audit record agree about whether a call was refused.

## S8. Capella operations

Operations are a declarative registry (`handlers/capella/spec.py`). Nothing is shipped
without a status recorded from an observed call. Blast-radius controls for unattended
writes are in `handlers/capella/guardrails.py`. The first source for request and response
shapes is the public Terraform provider's client (`docs/PROVIDER_SOURCE.md`, decision Q3).
Counts and the verification status per operation are in `docs/CAPELLA_SURFACE_TODO.md`,
dated. [VERIFY] Not re-read for this draft.

## S9. Fixtures and the backup catalogue

A fixture is a portable export of data, indexes and functions that can be imported again
(`handlers/fixture.py`, `handlers/capella/fixture.py`, `handlers/fixture_core.py`). The
backup catalogue records user-defined metadata about backups on both control planes
(`handlers/backup_catalog.py`). Behavior and file formats are in `docs/FIXTURE_DESIGN.md`.
[VERIFY] Not re-read for this draft.

## S10. Egress allowlist

Tools that ask the cluster to contact a destination are checked against an allowlist
(`handlers/egress.py`) and refused with `denied_egress`. [VERIFY] The configuration names
and the default: read the module header.
