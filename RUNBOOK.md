# Operator runbook — ephemeral Capella environments for mobile app testing

The task this exists for: **stand up a Capella environment, point a phone app at it, tear it
down** — repeatedly, from CI, with nobody watching.

This is the operator document. `README.md` describes the server, `CONTRIBUTING.md` describes
the code, and `CAPELLA_HANDOFF.md` records the security review and the reasoning behind the
controls. Everything here has been run.

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
- [ ] If you will use App Services (Couchbase Lite sync), close the last 22 paths once:
      `python scripts/verify_capella_paths.py --bootstrap-app-service --yes-really-mutate`.
      It creates a single-node App Service, verifies those paths, and deletes it again from a
      `finally`. Without an App Service in the project those 22 report `SKIPPED` — their
      paths come from Couchbase's published API document but have never been watched
      returning a response.
- [ ] A teardown step runs with `if: always()`, and a scheduled reaper exists
- [ ] One environment has been created and torn down by hand before CI is pointed at it
