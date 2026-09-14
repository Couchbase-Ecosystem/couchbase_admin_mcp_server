# Operator runbook — ephemeral Capella environments for mobile app testing

The task this exists for: **stand up a Capella environment, point a phone app at it, tear it
down** — repeatedly, from CI, with nobody watching.

This is the operator document. `README.md` describes the server, `CONTRIBUTING.md` describes
the code, and `docs/ARCHITECTURE.md` plus the architecture document under `docs/` record the
controls and the reasoning behind them. Everything here has been run.

---

## 1. Which shape are you running?

There are two, and they are not variations of one thing. Pick before configuring anything.

| | **A — Developer laptop** | **B — Unattended agent chain** |
|---|---|---|
| `CB_ADMIN_PROFILE` | `workstation` | `enterprise` |
| Transport | stdio (Claude Desktop, or a container over stdio) | Streamable HTTP |
| Who authorises a write | A person answering the client's prompt | The `automation` scope in the caller's OAuth token |
| `confirm: true` means | A person really looked | **Nothing** — the model supplies it |
| Audit identity | OS user + host | The token's service principal |
| Hard-ceiling tools | Reachable | **Refused outright** |

The server **refuses to start** if the profile is unset, or if the combination is
incoherent. That is the design: the failure is at startup, not at 3am.

---

## 2. Shape A — developer laptop

```bash
export CB_ADMIN_PROFILE=workstation
export CB_ADMIN_READ_ONLY_MODE=false          # opt in to writes

# Capella control plane
# The SERVER reads CAPELLA_API_KEY_SECRET. Note the name: it is the API key's
# secret, not its id — supplying the id gives a 401 that reads like a permissions
# problem. (scripts/verify_capella_paths.py reads CB_CAPELLA_API_KEY instead; the
# two are separate on purpose, so a read-only verification key need not be the key
# the server runs with.)
export CAPELLA_API_KEY_SECRET='<the API key SECRET, not its id>'
export CAPELLA_ORG_ID=00000000-0000-...            # pin the organization

# Guardrails — see section 4. Set these even on a laptop.
export CAPELLA_ALLOWED_PROJECTS=00000000-0000-...
export CAPELLA_ENV_NAME_PREFIX=mcp-test-
export CAPELLA_MAX_ENVIRONMENTS=3
export CAPELLA_ENV_TTL_HOURS=8

couchbase-admin-mcp-server
```

Claude Desktop config — note `CB_ADMIN_PROFILE`, without which the container exits
immediately:

```json
{
  "mcpServers": {
    "couchbase-admin": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
        "-e", "CB_ADMIN_PROFILE=workstation",
        "-e", "CB_ADMIN_TRANSPORT=stdio",
        "-e", "CB_ADMIN_READ_ONLY_MODE=false",
        "-e", "CAPELLA_API_KEY_SECRET",
        "-e", "CAPELLA_ORG_ID",
        "-e", "CAPELLA_ALLOWED_PROJECTS",
        "-e", "CAPELLA_ENV_NAME_PREFIX",
        "couchbase-admin-mcp:latest"],
      "env": {
        "CAPELLA_API_KEY_SECRET": "...",
        "CAPELLA_ORG_ID": "...",
        "CAPELLA_ALLOWED_PROJECTS": "...",
        "CAPELLA_ENV_NAME_PREFIX": "mcp-test-"
      }
    }
  }
}
```

Sanity check before doing anything destructive:

```
capella_guardrails_status
```

It reports the org pin, the project allowlist, the name prefix, the ceiling and the TTL as
the server actually resolved them. If a guardrail you thought you set is absent, this is
where you find out — not from a deleted cluster.

---

## 3. Shape B — the unattended chain

The flow: a human pushes a commit → a workflow-manager agent notices → it instructs a child
agent → the child calls this server → the environment appears. **Nobody approves anything at
the moment of action**, and that is correct: the authorisation happened when the IdP issued
that child a credential carrying the `automation` scope.

```bash
export CB_ADMIN_PROFILE=enterprise
export CB_ADMIN_TRANSPORT=http
export CB_ADMIN_HOST=0.0.0.0
export CB_ADMIN_PORT=8000

# Authentication is MANDATORY in this profile and the server checks it at startup.
export OAUTH_ISSUER=https://idp.corp.example/realms/mcp
export OAUTH_AUDIENCE=api://couchbase-admin-mcp
export CB_ADMIN_HTTP_REQUIRE_AUTH=true

# Scopes. A child agent's token needs write; write + automation lets it act with no
# per-call confirmation. Automation alone grants nothing.
export CB_ADMIN_SCOPE_READ=couchbase-admin-mcp:read
export CB_ADMIN_SCOPE_WRITE=couchbase-admin-mcp:write
export CB_ADMIN_SCOPE_AUTOMATION=couchbase-admin-mcp:automation

# TRANSPORT ENCRYPTION. Pick one; a non-loopback bind with neither is fatal.
export CB_ADMIN_TLS_CERT_FILE=/etc/tls/server.crt
export CB_ADMIN_TLS_KEY_FILE=/etc/tls/server.key
#   ...or, if an ingress or service mesh terminates TLS in front:
# export CB_ADMIN_TLS_TERMINATED_EXTERNALLY=1

# Optional and recommended here: mutual TLS, so a stolen bearer token alone is not enough.
# export CB_ADMIN_TLS_CLIENT_CA_FILE=/etc/tls/client-ca.crt

# The audit log is the ONLY accountability when nobody is watching. An unwritable path
# is fatal at startup rather than a warning nobody reads.
export CB_ADMIN_AUDIT_FILE=/var/log/couchbase-admin-mcp/audit.log

# Where the cluster may be told to send things. Fails closed.
export CB_ADMIN_EGRESS_ALLOWED_HOSTS=.corp.example
```

The image already creates `/var/log/couchbase-admin-mcp` owned by the runtime user.

### The one variable to get right

`CB_ADMIN_SCOPE_AUTOMATION` is what lets a child agent write without a human. It is bound to
the **token**, so a caller cannot grant it to itself by putting a value in tool arguments —
that was tried and closed. Issue it only to service principals that should act unattended.

### Correlation — how a cluster change traces back to a person

Pass `correlation_id` on every call: a commit SHA, a workflow run URL, anything that
identifies the human action that started the chain.

```json
{"tool": "capella_env_ensure",
 "arguments": {"env_name": "mcp-test-pr-1421", "correlation_id": "gh-run-8891234"}}
```

It is recorded in the audit record and **never** consulted for authorisation. It is declared
on every tool's schema, so the model can see it. Without it, the audit trail stops at
"service principal X created a cluster" and cannot reach the push that caused it.

---

## 4. Guardrails — what makes unattended teardown safe

Five independent limits. Set them **before** granting the automation scope to anything.

| Variable | Default | What it prevents |
|---|---|---|
| `CAPELLA_ORG_ID` | none | Acting in the wrong organization |
| `CAPELLA_ALLOWED_PROJECTS` | none | Touching production projects |
| `CAPELLA_ENV_NAME_PREFIX` | none | Adopting or reaping clusters this server did not create |
| `CAPELLA_MAX_ENVIRONMENTS` | `10` | A retry loop provisioning fifty clusters |
| `CAPELLA_ENV_TTL_HOURS` | `8` | Forgotten environments billing forever |
| `CAPELLA_PROTECTED_CLUSTERS` | none | Naming specific clusters that must never be touched |

**`CAPELLA_ENV_NAME_PREFIX` is the one that matters most.** The reaper only considers
clusters whose name carries the prefix *and* whose description carries this server's
ownership marker. Without a prefix there is nothing distinguishing "an environment I created
and may delete" from "a cluster somebody depends on".

`CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE` exists and defaults to off. Leaving it off is the point.

---

## 5. The environment lifecycle

Nine tools. `capella_env_ensure` is a **reconciler**: it converges toward the shape you
declare, holds no local state, and is safe to call repeatedly — which is what makes it usable
from a pipeline that retries.

```
capella_env_ensure            create or converge (cluster, buckets, scopes,
                              collections, credential, allowlist, App Services)
capella_env_status            where it is in provisioning
capella_env_connection_info   what the phone app needs to connect
capella_env_park              turn OFF an idle environment (keeps data, stops compute)
capella_env_resume            turn it back on
capella_env_teardown          DELETE it
capella_env_reap              delete everything past its TTL
capella_env_list              what this server owns
capella_guardrails_status     the limits as actually resolved
```

### Provisioning is asynchronous — this is not an error

`capella_env_ensure` returns a **phase**, not a finished cluster:

```json
{"phase": "creating_cluster", "done": false, "retry_after_s": 30,
 "next_step": "Call capella_env_ensure again with the same arguments in about 30s."}
```

Call it again with the same arguments. Cluster creation typically takes 5–15 minutes. The
phase reaches `ready` when the cluster is healthy and every declared object exists.

### Park versus teardown

- **Park** (`capella_env_park`) turns the cluster off. Data survives, compute billing stops,
  `capella_env_resume` brings it back. Use it between test runs on the same branch.
- **Teardown** (`capella_env_teardown`) deletes. Use it when the branch merges or closes.

---

## 6. Connecting the phone app

```
capella_env_connection_info  { "env_name": "mcp-test-pr-1421" }
```

```json
{
  "environment": "mcp-test-pr-1421",
  "cluster_state": "healthy",
  "connection_string": "couchbases://cb.xxxx.cloud.couchbase.com",
  "buckets": ["testdata"],
  "allowed_cidrs": ["203.0.113.0/24"],
  "couchbase_lite_url_pattern": "wss://xxxx.apps.cloud.couchbase.com/<appEndpointName>",
  "app_services_admin_url": "https://xxxx.apps.cloud.couchbase.com:4985"
}
```

`couchbase_lite_url_pattern` is the value Couchbase Lite needs — substitute your App
Endpoint name.

### The two things that will actually stop you connecting

1. **An empty allowlist.** Capella refuses *every* client connection when the allowlist is
   empty, regardless of credentials, and the error looks like a network timeout rather than
   an authorisation failure. `capella_env_connection_info` warns explicitly when it sees
   this. Pass `allowed_cidrs` to `capella_env_ensure`, or add the CI runner's egress CIDR
   with `capella_allowed_cidr_create`.

2. **The credential password.** Capella will not return it after creation. `capella_env_ensure`
   surfaces it **once**, in the response that creates it. Capture it then — from a later call
   it is unrecoverable and the credential must be recreated.

---

## 7. A worked CI pipeline

GitHub Actions, but the shape is the same anywhere. Assumes the server is reachable per
shape B and the runner holds a token with `write` + `automation`.

```yaml
name: Mobile app integration tests

on: [pull_request]

jobs:
  test-against-ephemeral-capella:
    runs-on: ubuntu-latest
    env:
      MCP: https://cb-admin-mcp.corp.example/mcp
      ENV_NAME: mcp-test-pr-${{ github.event.pull_request.number }}
    steps:
      - uses: actions/checkout@v4

      - name: Get a token for this job
        id: token
        run: |
          # Client-credentials grant, straight from the IdP. This server validates
          # tokens; it never issues them.
          TOKEN=$(curl -sS -X POST "$OAUTH_TOKEN_URL" \
            -d grant_type=client_credentials \
            -d client_id="$OAUTH_CLIENT_ID" \
            -d client_secret="$OAUTH_CLIENT_SECRET" \
            -d scope="couchbase-admin-mcp:write couchbase-admin-mcp:automation" \
            | jq -r .access_token)
          echo "::add-mask::$TOKEN"
          echo "token=$TOKEN" >> "$GITHUB_OUTPUT"

      - name: Stand up the environment
        run: |
          # Poll until the reconciler reports ready. It is idempotent, so re-calling with
          # the same arguments is the intended way to wait.
          for attempt in $(seq 1 40); do
            PHASE=$(curl -sS "$MCP" \
              -H "Authorization: Bearer ${{ steps.token.outputs.token }}" \
              -H 'Content-Type: application/json' \
              -d '{"tool":"capella_env_ensure","arguments":{
                     "env_name":"'"$ENV_NAME"'",
                     "app_services": true,
                     "bucket_name":"testdata",
                     "allowed_cidrs":["'"$(curl -sS https://api.ipify.org)"'/32"],
                     "ttl_hours": 4,
                     "owner":"ci",
                     "correlation_id":"gh-run-${{ github.run_id }}"}}' \
              | jq -r '.phase')
            echo "attempt $attempt: $PHASE"
            [ "$PHASE" = "ready" ] && break
            sleep 30
          done
          [ "$PHASE" = "ready" ] || { echo "environment not ready"; exit 1; }

      - name: Point the app at it and run the tests
        run: |
          INFO=$(curl -sS "$MCP" \
            -H "Authorization: Bearer ${{ steps.token.outputs.token }}" \
            -H 'Content-Type: application/json' \
            -d '{"tool":"capella_env_connection_info","arguments":{"env_name":"'"$ENV_NAME"'"}}')
          export CB_URL=$(echo "$INFO" | jq -r .connection_string)
          export SYNC_URL=$(echo "$INFO" | jq -r .couchbase_lite_url_pattern)
          ./gradlew connectedAndroidTest      # or your mobile test runner

      - name: Tear it down
        if: always()          # ALWAYS — a failed test must not leak a cluster
        run: |
          curl -sS "$MCP" \
            -H "Authorization: Bearer ${{ steps.token.outputs.token }}" \
            -H 'Content-Type: application/json' \
            -d '{"tool":"capella_env_teardown","arguments":{
                   "env_name":"'"$ENV_NAME"'",
                   "correlation_id":"gh-run-${{ github.run_id }}"}}'
```

### Two things this pipeline gets right on purpose

- **`if: always()` on teardown.** Without it a failing test leaves a cluster billing
  indefinitely. The TTL reaper is the backstop, not the plan.
- **A scheduled reaper**, because a cancelled job never reaches its cleanup step at all:

```yaml
  reap-expired:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # Dry run first in a new pipeline — it reports what it WOULD delete.
          curl -sS "$MCP" -H "Authorization: Bearer $TOKEN" \
            -H 'Content-Type: application/json' \
            -d '{"tool":"capella_env_reap","arguments":{"dry_run": true}}'
```

Run it hourly. `capella_env_reap` only ever considers clusters carrying both the name prefix
and this server's ownership marker.

---

## 8. When something goes wrong

| Symptom | Cause |
|---|---|
| `REFUSING TO START: CB_ADMIN_PROFILE is not set` | Working as designed. Set `workstation` or `enterprise`. |
| `REFUSING TO START — incoherent security posture` | The combination cannot be secure. The message names each problem and how to resolve it; read it rather than guessing. |
| `CB_ADMIN_AUDIT_FILE ... cannot be used` | The path is unwritable or a symlink. Fatal on purpose: in shape B the log is the only accountability. |
| `Access denied: tool ... requires scope` | The token lacks `write`. Automation alone grants nothing. |
| `is in the hard ceiling ... cannot be executed` | A ceiling tool over HTTP. `confirm: true` cannot satisfy it — the caller supplies that value. Use an interactive stdio session. |
| Tools missing in Capella mode | Deployment gating. ~120 ns_server tools cannot work against Capella (a Capella credential is never cluster-admin), so they are unloaded rather than failing at 401. `cb_mcp_status` lists what is loaded and why, and `cb_mcp_list_tools` enumerates the surface. |
| Phone app times out | The allowlist is almost certainly empty. See section 6. |
| `EgressDenied` | A tool asked the cluster to contact a host outside `CB_ADMIN_EGRESS_ALLOWED_HOSTS`. Add it deliberately; the metadata/loopback denial cannot be configured away. |
| Capella 404 on a specific tool | Verify the path: `python scripts/verify_capella_paths.py`. |

### What the audit log answers

```bash
grep AUDIT /var/log/couchbase-admin-mcp/audit.log | jq 'select(.decision != "allowed")'
```

Each record carries the tool, the decision, the principal, whether automation applied, the
scopes held, the source address and the correlation id. Refusals are recorded as well as
successes — a refused call is the more interesting half.

---

## 9. Before you trust this in production

- [ ] `capella_guardrails_status` shows the org pin, project allowlist and name prefix you expect
- [ ] `CAPELLA_ENV_NAME_PREFIX` is set — without it the reaper cannot tell your clusters apart
- [ ] `capella_env_reap` with `dry_run: true` lists only what you expect
- [ ] TLS is configured, or external termination explicitly acknowledged
- [ ] `CB_ADMIN_AUDIT_FILE` points somewhere durable, and a record appears after one call
- [ ] The automation scope is issued only to principals that should act unattended
- [ ] `python scripts/verify_capella_paths.py` reports `MISSING=0`
- [ ] `uv run python scripts/verify_mcp_surface.py` reports no PROTOCOL failures — see section 10.
      A verified path is not a callable tool; this is the check that a client can reach it.
- [ ] Optional, but this is how the 61/61 result was produced. Re-run it if Capella's control
      plane has changed since `spec.LIVE_VERIFIED_ON`:
      `python scripts/verify_capella_paths.py --bootstrap-app-service --bootstrap-child-objects --yes-really-mutate`.
      Without an App Service, the App Services and App Endpoint operations
      report `SKIPPED` — 22 of them as of 2026-09-14; with one but no App Endpoint,
      14 still do. Their paths are real but had never been watched returning a response.

      It creates a two-node App Service (Capella's minimum — it refuses 1), then a database
      credential, two allowlist entries, an App Services admin user, and a throwaway scope,
      collection and App Endpoint; verifies everything; then deletes it all from a `finally`,
      children before the parent.

      Nothing it creates touches data you care about. The allowlist entries use
      `192.0.2.x/32` — RFC 5737 TEST-NET-1, reserved for documentation and assigned to no
      real host, so neither grants access to anything — and carry a one-hour `expiresAt` so a
      failed teardown still lapses. The App Endpoint binds a scope created for the run, never
      `_default._default`: configuring an endpoint over a collection turns on Sync Gateway for
      it and writes sync metadata into the bucket, which a verification tool must not do to
      real data.

      The App Service is the only billable part; budget several minutes for it to provision.
- [ ] A teardown step runs with `if: always()`, and a scheduled reaper exists
- [ ] One environment has been created and torn down by hand before CI is pointed at it

---

## 10. Proving the surface from an MCP client

`scripts/verify_capella_paths.py` speaks HTTP to Capella directly. It answers
"does this path exist", and it answers it well — but it never starts this server,
never loads a tool, and never passes through a line of dispatch. Ninety-seven
verified paths say nothing about whether a client can call them.

`scripts/verify_mcp_surface.py` drives the server over stdio with the official
`mcp` client — the same library Claude Desktop and Claude Code use — and reports
which tools answered. It covers everything the path checker cannot see: startup
under a profile, the advertised tool list, deployment gating, the read-only
filter, the scope gate, the hard ceiling, the confirmation gate, dry-run
interception, argument marshalling, response redaction, and the audit record each
call emits.

```powershell
cd C:\Work\Development\CB-Admin-MCP
uv run python scripts\verify_mcp_surface.py --verbose
```

Reads only. Nothing is created and nothing is modified.

### The write surface, without writing

```powershell
uv run python scripts\verify_mcp_surface.py --write-preview --verbose
```

This starts a second server with writes loaded and `CB_ADMIN_DRY_RUN=true`, then
calls every write tool twice: once without `confirm`, which must be refused, and
once with it, which must come back as a preview. It is safe because of where the
dry-run interception sits — after every gate, before the handler — and because
`CB_ADMIN_DRY_RUN` is an operator control a caller cannot override.

One exception, and the phase refuses to run rather than guess at it: a tool that
implements `dry_run` in its own handler is deliberately *not* intercepted.
`capella_env_reap` is one of those, and it reaps clusters. The set cannot be read
off the advertised schemas — `dry_run` is injected into nearly every write tool's
schema — so it is read from `cb_mcp_status`, and a server that does not report it
gets no write phase at all.

### Capturing it as evidence

```powershell
powershell -File scripts\run-mcp-evidence.ps1 -IncludeWrites
```

Writes `evidence-mcp-read-<date>.txt` and `evidence-mcp-write-<date>.txt`:
PowerShell transcripts carrying the commit, the posture and the timestamps, which
is what makes them attachable to a ticket. The same pattern
`mcp-crud-couchbase\run-capella-evidence2.ps1` uses for the KV pull requests.

### Reading the result

| Outcome | Meaning |
|---|---|
| `ok` / `ok (empty)` | The handler ran. An empty listing is a real answer, not a gap. |
| `gated` | Refused for want of `confirm: true`. The confirmation gate working. |
| `guarded` | Refused by Capella guardrail policy. Also a pass. |
| `preview` | A write withheld by the dry run, as intended. |
| `UPSTREAM` | The handler ran and the API refused it. Often environmental — `capella_cluster_audit_log_export_get` needs an Enterprise plan. Fails the run only under `--strict`. |
| `skipped` | Arguments could not be resolved; nothing was sent. **Never counted as a pass.** |
| `TIMEOUT` | The call never came back. Only the `cb_*` SDK tools do this. The detail line names the cluster the server is pointed at — check that before reading anything into it. Says nothing about the surface; fails only under `--strict`. |
| `PROTOCOL FAILURE` | The MCP layer itself failed — an advertised tool that will not dispatch. Always a defect. |
| `*** PERFORMED ***` | A write ran in a phase where nothing should have. Reported first, fails the run. |

Exit 0 is clean, 1 is a defect in the surface, and 2 and 3 are reachable only
with `--strict` (upstream errors or timeouts, unresolvable arguments).

The `cb_*` diagnostics tools are the only ones here that touch the data plane —
they run SQL++ over the SDK rather than going to the control plane over 443. They
are also the only ones that can hang rather than fail, and the read phase stops
after three consecutive timeouts and names the cluster the server is pointed at.

Read that line before concluding anything about the network. `CB_CONNECTION_STRING`
defaults to `couchbase://localhost`, so with it unset these tools block trying to
reach a cluster that is not there — which is indistinguishable from a firewalled
one, and has twice been mistaken for one. `--only capella_` skips them outright
when you want the control-plane surface on its own.

### Where the network fits

The Capella tools here reach the v4 control plane at `cloudapi.cloud.couchbase.com`
over 443 with the organization API key. That is **not** gated by the per-cluster
IP allowlist, so this run works with the VPN up and a failure is a credential or a
server problem rather than a network one. The allowlist gates the data plane —
the SDK's 11207 connection and the Data API, and therefore the fixture tools.
`CAPELLA-CONNECTIVITY.md` has the full account of the data-plane side, including
which parts of it are measured and which are still hypothesis.

---

## 11. Proving a fixture family — the round trip

This is the only check in this repository that compares a fixture against
something **other than itself**, and it is the difference between a fixture
family that is carefully written and one that is verified.

### Why nothing cheaper is enough

On 2026-09-14 the Capella exporter recorded the wrong document key for 187 of
188 documents. The export query read

    SELECT META().id AS id, META().expiration AS exp, d.*

and `d.*` comes last, so any document carrying its own `id` field overwrote the
metadata alias. `travel-sample`'s airline documents are `{"id": 10, ...}` keyed
`airline_10`; the fixture recorded `10`.

Every check in place at the time passed:

| Check | Why it passed anyway |
|---|---|
| per-file `sha256` | the hash of a wrong file matches the hash recorded for that wrong file |
| line counts | 188 wrong documents are still 188 lines |
| `*_fixture_verify --check_cluster` | `COUNT(*)` on the cluster was 188, correctly |

Each one compares a fixture against its own record. Only a round trip compares
it against a second, independent capture.

### Running it

```powershell
# Capella
uv run python scripts\fixture_round_trip.py --plane capella `
    --keyspace travel-sample.inventory.airline `
    --scratch  travel-sample.roundtrip.airline `
    --work     C:\Work\Development\roundtrip `
    --perform

# Enterprise Edition
uv run python scripts\fixture_round_trip.py --plane ee `
    --keyspace travel-sample.inventory.airline `
    --scratch  travel-sample.roundtrip.airline `
    --work     C:\Work\Development\roundtrip-ee `
    --perform
```

Drop `--perform` to print the three calls it would make and exit. The two
exports are reads; the import is the only write, and it creates the scratch
scope and collection.

Pick a source keyspace **with documents in it**. A round trip over an empty
collection compares nothing with nothing; the script refuses rather than
reporting a clean result that establishes nothing.

### Reading the result

`identical: true` with a non-zero `first_documents` is the strongest statement
available about a fixture family on that plane.

Otherwise the report separates **keys** from **bodies**, because the repairs are
different:

- **keys differ, bodies do not** — the export is recording something other than
  the document key. The script says so in `signature` and names
  `META_ID_ALIAS`. This is the 2026-09-14 failure.
- **bodies differ, keys do not** — the payload is being altered in transit.
  Look at the import's write path, not the export's query.
- **keys missing from the second export** — the import wrote some and not all.
  Its per-keyspace `failures` list says which.

### Afterwards

**The scratch keyspace is not removed.** A verification tool that deletes things
can destroy the evidence of the failure it just found, so the script prints what
it created and leaves it. Drop the scope yourself once you have read the result:

```powershell
uv run python scripts\dump_tool.py admin_scope_delete `
    -a bucket_name=travel-sample -a scope_name=roundtrip `
    --write --perform --allow-destructive
```

### Current status, 2026-09-14

| Plane | Round trip run? |
|---|---|
| Capella | **Yes** — and it is what found the key bug. The fix is in; a confirming re-run is outstanding. |
| Enterprise Edition | **No.** `handlers/fixture.py` has never been run against a live EE cluster. |

Until the EE row says yes, treat `admin_fixture_export`, `admin_fixture_import`,
`admin_fixture_list` and `admin_fixture_verify` as written rather than verified — `tests/test_ee_fixture.py` asserts that the module keeps saying so.
