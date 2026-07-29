# Couchbase Admin MCP Server

An MCP server exposing Couchbase **cluster administration and operations** as
tools for agents — buckets, collections, users and security, XDCR, indexes,
FTS administration, eventing, backup/restore, statistics, diagnostics, and
Capella management.

It is the administrative counterpart to the data-plane
[MCP-Couchbase](https://github.com/celticht32/MCP-Couchbase) server: that one
does CRUD and query against your data; this one manages the cluster around it.
The two are deliberately separate servers — different audiences, different risk
profiles, different release cadences.

> **Safety-first defaults.** Out of the box this server is **read-only**, and
> when writes are enabled **every** mutating operation is gated. You have to opt
> in to danger deliberately. See [Trust models](#trust-models).

---

## What's here

~150 tools across these areas:

| Area | Examples |
|---|---|
| Buckets | create, update, delete, flush, compact, sample install |
| Collections & scopes | create/drop scope, create/drop/update collection |
| Security | users, groups, roles, password policy, audit, LDAP/SAML |
| Cluster | nodes, rebalance, failover, auto-failover, server groups, logs |
| XDCR | remote references, replications, settings, conflict log |
| Indexes | GSI create/drop/build, settings, advisor |
| Search (FTS) | index CRUD, ingest control, analysis |
| Eventing | function create/deploy/pause/resume |
| Backup | repository list/get, backup list/run, restore |
| Encryption | DARE / KMIP configuration |
| Statistics | cluster, bucket, index, query, and node stats |
| Diagnostics | schema inference, explain, query-performance advisors |
| Capella | Capella control-plane operations |

Every tool is annotated `readOnlyHint` / `destructiveHint` so the read-only
filter and the confirmation gate classify it correctly.

---

## Quick start

```bash
# 1. Install
pip install -e .

# 2. Configure
cp .env.example .env
#    edit .env — at minimum CB_CONNECTION_STRING / CB_USERNAME / CB_PASSWORD

# 3. Run (stdio transport, read-only by default)
couchbase-admin-mcp-server
```

To enable writes, set `CB_ADMIN_READ_ONLY_MODE=false` — but read
[Trust models](#trust-models) first.

---

## Trust models

This is the important part. Administrative operations can reshape a cluster, so
the server has two independent, layered controls.

### Layer 1 — read-only mode (default ON)

`CB_ADMIN_READ_ONLY_MODE=true` (the default) loads only the read tools. Every
mutating tool is **unloaded entirely** — not merely gated, but absent from the
tool list, so it cannot be called at all. This is the outermost guard. Turn it
off only when you actually need writes.

### Layer 2 — confirmation, and the two ways to satisfy it

When writes are enabled, **every write tool is gated by default.** There are two
distinct trust models for getting past the gate, and they are not the same
thing:

#### Interactive — a human approves each call

The default. A gated call is withheld until the caller supplies `confirm: true`
in the arguments (or answers an elicitation prompt on clients that support one).
This is confirmation-by-argument, so it works on **any** MCP client without
requiring elicitation protocol support. It is the right model when a person is
driving.

#### Automation — an authorized principal runs unattended

For CI/CD and workflow agents where **no human is present per call.** A workflow
that seeds an environment, runs a migration, or promotes a build from dev → CIT
cannot stop to ask a human to approve each bucket create.

The wrong way to solve this — and the only way most servers allow — is to have
the agent *impersonate* a human by auto-answering the prompt, or to switch
confirmation off entirely. Both destroy the gate.

This server instead binds an **automation mode** to the authenticated principal:

- A workflow's service principal is issued a token by your IdP carrying the
  automation scope (`couchbase-mcp:automation`) **in addition to** the write
  scope.
- A session on that token executes gated writes **without** a per-call prompt —
  because the human decision already happened, once, when the credential was
  issued. That is the auditable authorization.
- The automation scope **never substitutes** for the write scope. An automation
  token with no write scope still cannot write.
- The scope is bound to the token, issued by your IdP — **a caller cannot
  self-promote** by putting a value in tool arguments.

### Layer 3 — the hard ceiling (what makes automation safe)

Some operations should never run unattended, even inside an authorized pipeline.
`CB_ADMIN_ALWAYS_CONFIRM` is a server-configured list of tools that **always**
require a per-call human confirmation, **even for an automation-scoped
principal**.

> **This is the control that makes automation mode safe to offer.** The list is
> set on the **server**, at deploy time, by a human. No token scope, no tool
> argument, no client-supplied value can remove a tool from it. A workflow agent
> can create buckets and deploy functions unattended, but a failover or a
> production bucket delete still stops for a person — and the agent provably
> cannot change that.

It ships **empty** (friction-free for a developer's own cluster). For a
production admin server, set a strict list, for example:

```bash
CB_ADMIN_ALWAYS_CONFIRM=admin_bucket_delete,admin_bucket_flush,admin_node_remove,\
admin_failover_hard,admin_failover_graceful,admin_rebalance_start,\
admin_user_delete,admin_xdcr_replication_delete,admin_cluster_leave
```

### Per-environment policy

Because the ceiling is server configuration, the same binary enforces different
policy per environment: the dev cluster's server runs permissive automation with
an empty ceiling; the prod cluster's server keeps promotion-to-prod operations
behind the hard gate. Deploy the same image, change the config.

### Audit

Every gated call is logged with the tool name, redacted arguments, outcome, and
duration. When an OAuth token is present, the principal and the mode it ran under
(interactive vs automation) are recorded — so "a pipeline did this unattended" is
accountable rather than opaque.

---

## Logging

Logs use a per-module hierarchy under `couchbase-admin.*` and are configurable
via `CB_ADMIN_LOG_*` (see `.env.example`). With the file sink enabled, the
server writes **one rotating file per level** — `cb_admin_mcp.info.log`,
`.warning.log`, `.error.log` — so support can request exactly the error log
without wading through everything else.

Sensitive fields (passwords, tokens, secrets, KMIP passphrases) are **redacted**
from both logs and error responses. A failed `admin_user_create` never echoes
the plaintext password back to the agent or into a log file.

---

## Transports

- **stdio** (default) — for local MCP clients.
- **http** — set `CB_ADMIN_TRANSPORT=http`. With `OAUTH_ISSUER` configured and
  `CB_ADMIN_HTTP_REQUIRE_AUTH=true`, bearer tokens are validated and per-tool
  scope enforcement (including automation mode) applies. Without auth, deploy
  behind a trusted proxy.

---

## Development

```bash
pip install -e '.[dev]'
ruff check .
pytest
```

---

## License

MIT © 2026 Chris Ahrendt
