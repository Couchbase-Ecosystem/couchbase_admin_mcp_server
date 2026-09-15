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

**284 tools** as of 2026-09-14 — 138 `capella_*`, 127 `admin_*`, 19 `cb_*`.
A deployment loads ONE control plane's half, never both, so a running server
advertises far fewer than that; see "One container, one control plane" below.

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
#    edit .env — at minimum:
#      CB_ADMIN_PROFILE          workstation | enterprise   (NO DEFAULT — see below)
#      CB_CONNECTION_STRING
#      CB_USERNAME / CB_PASSWORD

# 3. Run (stdio transport, read-only by default)
couchbase-admin-mcp-server
```

**`CB_ADMIN_PROFILE` has no default and the server refuses to start without it.**
That is deliberate, and it is the first thing to know:

```
[couchbase-admin-mcp] REFUSING TO START: CB_ADMIN_PROFILE is not set.
```

The two supported deployments have opposite security postures, and guessing between
them is how you end up with an unauthenticated administration API on a network
interface. Use `workstation` for local work; see
[Deployment profiles](#deployment-profiles).

To enable writes, set `CB_ADMIN_READ_ONLY_MODE=false` — but read
[Trust models](#trust-models) first.

---

> **Running ephemeral Capella environments for app testing?** See
> **[RUNBOOK.md](RUNBOOK.md)** — the operator guide for both deployment shapes, the
> environment lifecycle, a worked CI pipeline, and a troubleshooting table.

---

## Deployment profiles

There are two ways this server runs, and they are not variations of one thing — they
have different trust models, so the deployment states which it is, once:

| | `workstation` | `enterprise` |
|---|---|---|
| Shape | Laptop or local container, driven by Claude Desktop over stdio | A workflow-manager agent instructs child agents, which act unattended |
| Human present at the moment of action? | **Yes** — the MCP client surfaces each call | **No, by design** |
| `confirm: true` means | A person really looked | Nothing — the model supplies it |
| What authorizes a write | That confirmation | The automation scope in the caller's OAuth token |
| Identity in the audit record | OS user and host | The token's service principal |
| HTTP auth | Off (there is no IdP on a laptop) | **Required** |
| Admin console | Loopback only, peer-address checked | Behind SSO |

`profile_config.py` derives the posture from that single variable and **refuses
incoherent combinations at startup** rather than at 3am. For example
`CB_ADMIN_PROFILE=workstation` with `CB_ADMIN_TRANSPORT=http` on a non-loopback
address is fatal: every relaxation the workstation profile makes is justified by
nothing being network-reachable. If that is a container publishing its port to
loopback on the host, say so with
`CB_ADMIN_WORKSTATION_CONTAINER_BIND=1`.

The hard ceiling (`CB_ADMIN_ALWAYS_CONFIRM`) is only satisfiable over **stdio**, where a
person answers the client's prompt. It ships empty; see [Trust models](#trust-models).

---

## Trust models

This is the important part. Administrative operations can reshape a cluster, so
the server has two independent, layered controls.

### Layer 1 — read-only mode (default ON)

`CB_ADMIN_READ_ONLY_MODE=true` (the default) loads only the read tools. Every
mutating tool is **unloaded entirely** — not merely gated, but absent from the
tool list, so it cannot be called at all. This is the outermost guard. Turn it
off only when you actually need writes.

### Layer 1a — dry run (preview a write without performing it)

Every write tool accepts `dry_run: true`, and `CB_ADMIN_DRY_RUN=true` forces it
for every call. The call is authorized and audited normally and then **not
performed**; the response says which tool would have run, against which target,
with which arguments. Reads still execute, because a read changes nothing and a
plan cannot be checked without one.

The environment variable wins over the argument: `dry_run: false` cannot escape a
server-wide preview mode. Audit records these as `dry_run` rather than `allowed`,
so a preview never counts as a privileged write.

Use it for the first unattended run against a new organization, and keep the
output as the artifact attached to the change request. Note that a dry run is not
authorization and not validation — the gates all run first, and the payload is
never sent, so it tells you what the agent decided to do, not whether the cluster
would accept it. `capella_env_reap` keeps its own `dry_run`, which defaults to
**true** and really does list what it would reap.

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
  automation scope (`couchbase-admin-mcp:automation`) **in addition to** the write
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

### Which claim your IdP must put the scopes in

The automation model rests on one question — does this token carry the automation
scope — and identity providers disagree about which claim a grant lands in. This
server reads **all** of the shapes below, and a token needs to satisfy only one of
them. Grants from several claims are **combined**, not shadowed, so a provider that
issues delegated scopes and application roles at the same time works.

| Claim | Shape | Emitted by |
|---|---|---|
| `scope` | space-delimited string | Keycloak scopes, Auth0, anything RFC-compliant |
| `scp` | string or list | Entra delegated permissions, Okta |
| `scopes` | string or list | assorted |
| `roles` | list | **Entra application permissions — this is what a client-credentials token carries** |
| `permissions` | list | Auth0 RBAC |
| `realm_access.roles` | list, nested | **Keycloak realm roles** |
| `resource_access.<client>.roles` | list, nested | **Keycloak client roles**, any client id |

The three in bold are the ones that have actually caused trouble. An Entra
client-credentials token puts app permissions in `roles` and nothing in `scp`, so a
server reading only `scope`/`scp` sees an automation-scoped service principal as
unprivileged. Keycloak puts *scopes* at the top level but *roles* one or two levels
down, and granting the permission as a role is the more natural choice in its UI.

**Both failures point the safe way** — the grant is not seen, so the write is gated
and the pipeline stops rather than over-reaching. That is the correct direction and
it is still a bad afternoon, because the symptom is "this write needs confirmation"
and the cause is an IdP mapper three systems away. So when a token validates and
carries no grant this server recognises, the denial says so explicitly and lists the
claims it read, instead of reporting a generic missing scope.

`tests/test_scope_claim_shapes.py` pins every row of that table, asserts the shapes
combine, and asserts the reverse — that a value appearing in an unrelated claim
(`aud`, `groups`, a custom entitlement) grants nothing. Three entries in
`scripts/mutation_round_4.py` prove those tests fail when the extraction is removed.

**What this does not establish.** Those are synthetic claim dictionaries in the
layouts the providers document: they prove the extraction, not the integration. No
signature, no JWKS, no clock, no live issuer. An installation with a custom mapper,
or a provider that changes its layout, is outside what they can see. For the
integration, see the next section.

### Verified against a real identity provider

On **2026-09-15** the authorization model was driven end to end by a real Keycloak
26.7.3, over the HTTP transport, with tokens minted by client-credentials service
accounts — not by the test suite. The realm is in `deploy/keycloak/`; the driver is
`scripts/idp_lab_assertions.py`; `deploy/keycloak/README.md` has the setup.

| Case | Principal | Result |
|---|---|---|
| no token | — | 401 before routing, `denied_authentication` audited |
| `aud` claim absent | `stranger` | 401, `MissingRequiredClaimError` |
| `aud` present but for another app, **holding the write role** | `otherapp` | 401, `InvalidAudienceError` |
| read tool | `reader` | executed |
| write tool | `reader` | denied, naming the scopes the token holds |
| tool listing | `reader` | 70 read tools (was 146, all of them) |
| write tool | `writer` | confirmation required, nothing created |
| write tool | `automation` | executed unattended, scope created |
| cleanup delete | `automation` | executed, no residue |

Every one of those decisions produced an audit record naming the principal. The
three that reached dispatch:

| Decision | `principal` | `client_id` | `automation` |
|---|---|---|---|
| `denied_scope` | service account sub | `cb-admin-mcp-reader` | `false` |
| `denied_confirmation` | service account sub | `cb-admin-mcp-writer` | `false` |
| `allowed` | service account sub | `cb-admin-mcp-automation` | `true` |

Each also carries `issuer`, the full `scopes` list as extracted, the tool name,
the arguments, the source address, and — on the allowed call — `duration_ms`.
An unattended write is therefore attributable to the credential the IdP issued,
which is the property the whole audit layer exists for and the one that had never
been observed against a real token.

Two of those are worth reading twice.

**The Keycloak grant lives only in `realm_access.roles`.** The top-level `scope`
claim on that token is `profile email` — nothing else. A server reading only
`scope`/`scp`/`scopes` would have resolved a fully-authorized automation principal
to *zero grants*: every write denied, automation silently off. The bolded rows in
the claim table above are not defensive coding; against Keycloak the nested path is
the only path.

**`otherapp` is the case that matters in a shared tenant.** Its token is correctly
signed by the right issuer, unexpired, carries `sub`, and holds
`couchbase-admin-mcp:write`. It is refused solely because it was minted for a
different application. A missing-`aud` refusal proves the claim is *required*; only
this one proves the value is *compared*, and every token an unrelated app in the
same tenant issues will have an `aud`.

**What this run found.** The tool listing was authenticated but not authorized: a
validated reader token was offered all 146 loaded tools with their argument schemas,
then refused at call time. Nothing escalated — the gate held — but the deployment's
posture was readable by the weakest credential in the tenant. Fixed by routing the
listing through `auth.scope_gate.denial_for()`, the same function the call path
uses, so the two cannot drift; `tests/test_tool_listing_is_scoped.py` and four
entries in `scripts/mutation_round_4.py` hold it in place.

**What this still does not establish.** The server under test ran from the working
tree on the host, not from the shipped container image, and the listener was
cleartext on loopback. Container-plus-IdP over the docker network needs TLS on the
IdP (`profile_config.py` refuses a non-loopback `http://` issuer, correctly) and is
covered by `deploy/docker-compose.keycloak.yml` and
`deploy/docker-compose.ee.idp-lab.yml`, which have **not** been run. Keycloak is
also one provider: these results say nothing about where Entra, Okta or Auth0 put a
grant in any particular tenant's configuration. The check for that is a decoded
sample token from the tenant in question, not another synthetic realm.

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

## Connecting from Claude Desktop

Claude Desktop speaks **stdio** natively and does not connect directly to a
private HTTP MCP endpoint: its "custom connector" feature routes the URL through
Anthropic's cloud, which cannot reach a server on a private work network (and you
should not expose a cluster-admin server to the public internet to make it
reach). Two setups work; pick by how you're running the container.

### Option A — stdio (simplest for Claude Desktop)

Let Claude Desktop launch the container per session and talk stdio directly. The
container still reaches the Couchbase container over the Docker network for the
*cluster* connection; only the MCP channel is stdio. In
`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "couchbase-admin": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--network", "your_docker_network",
        "-e", "CB_ADMIN_PROFILE=workstation",
        "-e", "CB_ADMIN_TRANSPORT=stdio",
        "-e", "CB_CONNECTION_STRING=couchbase://couchbase",
        "-e", "CB_USERNAME=Administrator",
        "-e", "CB_PASSWORD=password",
        "-e", "CB_ADMIN_READ_ONLY_MODE=false",
        "couchbase-admin-mcp:latest"
      ]
    }
  }
}
```

`--network your_docker_network` is what lets the launched container resolve the
`couchbase` service name. stdio is the image default, so no transport env is
needed — it's shown in the config above only for clarity.

### Option B — HTTP + mcp-remote bridge (for a long-running container)

If the admin server runs as a persistent service (the image default: http on
`0.0.0.0:8000`, port published to your host), bridge it into Claude Desktop with
`mcp-remote`. The bridge runs on your machine, reaches the container locally, and
presents stdio to Claude Desktop — nothing needs public exposure.

```json
{
  "mcpServers": {
    "couchbase-admin": {
      "command": "npx",
      "args": ["mcp-remote", "http://localhost:8000/mcp", "--allow-http"]
    }
  }
}
```

`--allow-http` is required because the container serves plain HTTP on localhost
(mcp-remote expects HTTPS otherwise). If you enable OAuth, add
`--header "Authorization:Bearer <token>"`.

> Restart Claude Desktop after editing `claude_desktop_config.json`, and verify
> the server shows **Connected** in Settings → Developer. If it doesn't, run the
> exact command from the config manually in a terminal — the error it prints is
> far more useful than the status line.

---

## Running in Docker

> **Deploying this for real — on a laptop, on AWS, or on GCP — is
> [`docs/CONTAINER_DEPLOYMENT.md`](docs/CONTAINER_DEPLOYMENT.md).** It covers the
> one-container-one-control-plane rule, secrets handling, TLS termination and
> what has and has not actually been exercised. The section below is the short
> local version.

Build the image:

```bash
docker build -t couchbase-admin-mcp:latest .
```

**Connecting to a Couchbase cluster in another container.** Put both on the same
Docker network and point `CB_CONNECTION_STRING` at the cluster container's
service name. For a long-running networked service you **opt in to HTTP** with
`CB_ADMIN_TRANSPORT=http` and `CB_ADMIN_HOST=0.0.0.0` (stdio, the default,
cannot cross a container boundary).

```yaml
# docker-compose.yml
services:
  couchbase:
    image: couchbase:enterprise
    ports: ["8091-8096:8091-8096", "11210:11210"]
    # ... your cluster provisioning ...

  admin-mcp:
    build: .
    depends_on: [couchbase]
    ports: ["8000:8000"]
    environment:
      CB_ADMIN_PROFILE: workstation     # no default; the server refuses to start without it
      CB_CONNECTION_STRING: couchbase://couchbase   # the service name above
      CB_USERNAME: Administrator
      CB_PASSWORD: password
      CB_ADMIN_READ_ONLY_MODE: "false"  # opt in to writes (default is true/read-only)
      CB_ADMIN_TRANSPORT: http          # opt in to HTTP for a networked service
      CB_ADMIN_HOST: 0.0.0.0            # accept connections from other containers/host

      # The two acknowledgements this combination requires. Both are deliberately
      # awkward: `workstation` + HTTP + a non-loopback bind is exactly the shape that
      # produces unauthenticated admin over a network, so the server will not start
      # unless you state that you know what you are doing and why.
      #
      #   ...CONTAINER_BIND: inside a container the process MUST bind 0.0.0.0; the
      #      isolation comes from publishing the port narrowly, not from the bind
      #      address. Publish it as 127.0.0.1:8000:8000 if the host should be the only
      #      client.
      #   ...TLS_TERMINATED_EXTERNALLY: this listener is cleartext. Acceptable on a
      #      private Docker network you control; NOT acceptable anywhere a bearer token
      #      could be observed. Set CB_ADMIN_TLS_CERT_FILE / _KEY_FILE instead to
      #      terminate TLS here.
      CB_ADMIN_WORKSTATION_CONTAINER_BIND: "1"
      CB_ADMIN_TLS_TERMINATED_EXTERNALLY: "1"

      # For unattended automation on a shared cluster use CB_ADMIN_PROFILE=enterprise
      # instead, which requires OAuth and refuses hard-ceiling tools outright.
      # See "Deployment profiles" and "Trust models" above.
```

Your MCP client (or agent) then connects to `http://<host>:8000/mcp`. To run
stdio instead (only meaningful when a supervisor in the same container drives
the server), set `CB_ADMIN_TRANSPORT=stdio`.

Notes:
- The image runs as a non-root user and ships **read-only by default** — set
  `CB_ADMIN_READ_ONLY_MODE=false` to enable writes.
- `CB_BUCKET` is optional here — admin operations act at the cluster level; it
  only affects the SDK warm-up used by a few diagnostics tools.
- Use `couchbase://` (not `couchbases://`) for a non-TLS in-network connection,
  or supply certs and keep `couchbases://` for TLS. See the TLS vars in
  `.env.example`.
- On HTTP with no OAuth configured, the server performs no request auth — keep
  it on a trusted internal network or put a proxy in front. With `OAUTH_ISSUER`
  + `CB_ADMIN_HTTP_REQUIRE_AUTH=true`, bearer-token scope enforcement (including
  automation mode) applies.

---

## Transports

- **stdio** (default, code and Docker image alike) — for local MCP clients
  (including Claude Desktop) that launch the server as a subprocess and speak
  over stdin/stdout.
- **http** — opt in with `CB_ADMIN_TRANSPORT=http` for a long-running networked
  service; stdio cannot cross a container boundary.
  With `OAUTH_ISSUER` configured and
  `CB_ADMIN_HTTP_REQUIRE_AUTH=true`, bearer tokens are validated and per-tool
  scope enforcement (including automation mode) applies. Without auth, deploy
  behind a trusted proxy.

> **⚠ Never set `OAUTH_SKIP_VERIFY=true` in production.** It disables JWT
> signature, issuer, audience, and expiry verification — any token is accepted
> and any caller can self-grant write and automation scope, making the entire
> trust model meaningless. It exists only for local development and defaults to
> off. Leave it unset in any shared or production deployment.

---

## Development

```bash
pip install -e '.[dev]'
ruff check .
pytest
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE) for
attribution — Apache 2.0 section 4(d) requires NOTICE to travel with redistributions, so
both files ship in the wheel.

Copyright 2026 Couchbase, Inc.

---

## Couchbase Capella

Capella does **not** expose the ns_server Management REST API on 8091/18091 to
tenants. A Capella *database credential* carries bucket-scoped data roles and
never Full Admin, so the `admin_*` tools in this server cannot work against a
Capella cluster — they are an authorization boundary away, not a network hop.

Point this server at a Capella connection string and it detects that, then
**unloads the tools that cannot work** rather than offering the 123 `admin_*`
tools (count as of 2026-09-14) that would each fail with an opaque 401 on first
use. An agent cannot misroute to a tool it never
sees.

### What is reachable on Capella

| Surface | Auth | Covered by |
|---|---|---|
| Management API v4 (`cloudapi.cloud.couchbase.com`) | Organization API key secret, Bearer | `capella_*` tools |
| Prometheus scrape on `:18091` | Database credential with read on all buckets | `admin_prometheus_targets` |
| SQL++ / query service | Database credential | `cb_*` diagnostics, index advisor, EXPLAIN |
| Data API (once enabled via v4) | Database credential | out of scope here |

What is genuinely unavailable — rebalance, failover, node add/remove, server
groups, `/internalSettings`, log collection, DARE/KMIP, LDAP/SAML — is mostly not
withheld but *reassigned*: those are operations Couchbase performs as the
operator. DARE/KMIP becomes CMEK; LDAP/SAML becomes organization SSO. The one
real gap is FTS index administration, which has no v4 equivalent.

### Ephemeral test environments

The headline use case: stand up a throwaway Capella cluster, point a mobile app
at it, tear it down. That is not one API call — it is create cluster, wait 5-15
minutes, allowlist the client, create a bucket and credential, create an App
Service, wait another 5-10 minutes, create an App Endpoint, bring it online. And
teardown is the same list backwards, with ordering constraints.

`capella_env_ensure` does all of it as a **reconciler**. Nothing can block for
fifteen minutes, so each call does whatever can be done now and returns a phase
plus a retry interval:

```
capella_env_ensure(env_name="ios-pr-4821", app_services=true,
                   allowed_cidrs=["203.0.113.4/32"], ttl_hours=4)
  -> {"phase": "creating_cluster", "done": false, "retry_after_s": 30}
  -> {"phase": "waiting_for_cluster", ...}          # call again
  -> {"phase": "creating_app_service", ...}
  -> {"phase": "ready", "connection_string": "couchbases://...",
      "couchbase_lite_url": "wss://.../ios-pr-4821-endpoint", ...}
```

Repeat calls are safe — existing resources are reused, never duplicated. There is
**no local state file**: everything is derived from Capella itself via a naming
convention plus an `mcp-env:{...}` marker written into the cluster description.
A CI job that dies mid-provision leaves no orphaned bookkeeping, and the next
`capella_env_ensure` picks up exactly where it left off.

| Tool | Purpose |
|---|---|
| `capella_env_ensure` | Converge an environment; call until `phase == "ready"` |
| `capella_env_status` | Read-only poll: cluster and App Service state, TTL remaining |
| `capella_env_connection_info` | Connection string, sync URL, allowlist, warnings |
| `capella_env_list` | Every managed environment, with age and expiry; unmanaged clusters flagged separately |
| `capella_env_park` / `_resume` | Turn off / on without destroying — stops spend, keeps the environment |
| `capella_env_teardown` | Destroy: App Service first, then cluster |
| `capella_env_reap` | Tear down expired environments. **Dry run by default** |
| `capella_guardrails_status` | What this server's blast radius actually is |

Alongside these sit ~60 thin `capella_*` primitives, one per v4 operation, for
when you know exactly which call you want.

### Guardrails

Unattended teardown needs `capella_cluster_delete` callable without
confirmation — which is exactly the operation you least want pointed at
production. Read-only mode is off by definition here, the `confirm:true` gate is
bypassed for automation principals by design, and `CB_ADMIN_ALWAYS_CONFIRM` would
stop teardown dead. None of them can express *"delete freely, but only inside the
sandbox."*

Four independent server-side limits do:

- **`CAPELLA_ORG_ID`** — pins the organization; a conflicting caller override is refused.
- **`CAPELLA_ALLOWED_PROJECTS`** — destructive operations are confined to these projects. Production is unreachable because it is not on the list. **Unset means fail closed**: the server will create but refuse to delete.
- **`CAPELLA_ENV_NAME_PREFIX`** — destructive operations refuse any resource whose name lacks the prefix, covering the hand-made production cluster that happens to sit in an allowlisted project.
- **`CAPELLA_MAX_ENVIRONMENTS`** — a spend ceiling, so a retry loop cannot provision without bound.

Plus `CAPELLA_PROTECTED_CLUSTERS` for named exceptions, and Capella's own
deletion-protection flag, which this server honors and cannot override.

None of these can be relaxed by a tool argument, a token scope, or a model
asserting that it is fine. Ask the running server what its posture is with
`capella_guardrails_status`.

### Risks Associated with LLMs

- The use of large language models and similar technology involves risks, including the potential for inaccurate or harmful outputs.
- Couchbase does not review or evaluate the quality or accuracy of such outputs, and such outputs may not reflect Couchbase's views.
- You are solely responsible for determining whether to use large language models and related technology, and for complying with any license terms, terms of use, and your organization's policies governing your use of the same.

---

## 📢 Support Policy

We truly appreciate your interest in this project!  
This project is **community-maintained**, which means it's **not officially supported** by our support team.

If you need help, have found a bug, or want to contribute improvements, the best place to do that is right here — by [opening a GitHub issue](https://github.com/Couchbase-Ecosystem/couchbase_admin_mcp_server/issues).  
Our support portal is unable to assist with requests related to this project, so we kindly ask that all inquiries stay within GitHub.

Your collaboration helps us all move forward together — thank you!
