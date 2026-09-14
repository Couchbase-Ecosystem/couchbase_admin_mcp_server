# Capella surface: what is missing, and what we are deliberately not adding

Written 2026-09-14, from an operation-by-operation diff of
`handlers/capella/spec.py` (102 shipped operations) against the Terraform
provider's generated client, `internal/generated/api/openapi.gen.go`
(289 operations), plus its hand-written `internal/api/**` structs and the
call sites in `internal/resources/*.go`.

**We cover 92 of the 289 v4 operations the provider knows about.** The other
197 are listed below, grouped by whether they should be added and why. A "no"
here is a decision with a reason, not a gap nobody noticed — the point of
writing it down is that the next person does not re-derive it.

## The rule this document exists to enforce

> When a v4 request body, path or status is in question, **read the provider
> source first**. Probe only for behaviour the source cannot state.

`spec_pending.py` already said the generated client is the stronger source and
that 19 parked paths had been wrong for trusting a rendered docs page instead.
On 2026-09-14 that lesson cost another 43 live requests: the App Endpoint access
control function was refused every time with `JavaScript source does not
evaluate to a function`, which reads as a verdict on the JavaScript. It is not.
The body is raw JavaScript sent as `Content-Type: application/javascript`, and
`internal/api/client.go:72` says so in four lines. No amount of probing from
outside would have produced that answer, because the error message is emitted
before anything is compiled — a discriminator (sending text that is not
JavaScript at all, and getting the identical message) is what finally proved it.

Probes remain the right instrument for: whether a route exists, entitlement
refusals, server defects (the on/off schedule 500), and anything where the
question is "what does this deployment actually do" rather than "what does the
API accept".

---

## P0 — reach zero SKIPPED — **CLOSED 2026-09-14**

Four tools, all OURS, all unimplemented code rather than unknowns. They were the
entire remaining gap between the surface run and a clean one.

**All four are now implemented and verified against a live cluster.** The surface
run reports 0 SKIPPED. `capella_fixture_export` exports structure, GSI
definitions, eventing functions and documents (the last over the Data API);
`capella_fixture_verify` verifies a fixture alone from the filesystem and, given
a `cluster_id`, verifies a live cluster against it — per-keyspace `COUNT(*)` and
index existence plus online state. Measured on 2026-09-14 against
`fixtures/mcptest-data-1`: 188 documents exported, 188 counted on the cluster,
both recorded indexes online, `verified: true` on both halves.

`capella_fixture_import` remains unimplemented and still refuses. It is the one
member of the family that writes to somebody's cluster, and a half-implemented
importer is worse than none.

The original blocking table, kept for the record:

| Tool | Blocking | Note |
|---|---|---|
| `capella_env_status` | needs `env_name` | no environment exists to name |
| `capella_env_connection_info` | needs `env_name` | same |
| `capella_fixture_export` | needs `fixture_id`, `fixture_path` | `capella_fixture_*` is declared and not implemented |
| `capella_fixture_verify` | needs `fixture_path` | same |

`capella_fixture_list` also reports UPSTREAM for the same reason. Both v4
questions this family was waiting on were settled on 2026-09-01; nothing
external blocks it.

**Also at P0, because they are one call each away from closing:**

- `capella_cluster_onoff_schedule_update` — in `SHIPPED_UNVERIFIED` because its
  only observed status is 404. `scripts/probe_onoff_schedule.py` now sends an
  invalid body at a cluster that has a schedule and prints the 400/422 to
  record.
- `capella_cluster_audit_log_export_get` — stays unverified. The 200 body cannot
  be produced by this organization: enabling audit logging is refused by
  ENTITLEMENT (422, "your support package does not include audit logging"). An
  Enterprise-plan org closes it in one run. Not our defect and not our fix.

---

## P1 — add these next

Ranked by how likely someone is to need them and be unable to proceed.

### 1. App Endpoint import filter (3 ops)

`GET|PUT|DELETE .../appEndpoints/{keyspace}/importFilter`
(`openapi.gen.go:24098/24160/24036`)

The exact twin of the access control function: same keyspace segment, same raw
`application/javascript` body, same 204. We ship one half of a matched pair, and
the half we ship is the one that was broken until today. The client support this
needs already exists (`Op.body_content_type`), so this is an hour's work.

**Why:** an App Endpoint with no import filter imports every document in the
collection. On a shared bucket that is both a correctness problem and a cost
problem, and there is currently no way to narrow it through this server.

### 2. `capella_app_service_update` (PUT `.../appservices/{id}`)

`UpdateAppServiceRequest` is `{compute: {cpu, ram}, nodes}` — nothing else
(`openapi.gen.go:5811`). 204. Optional `If-Match` header for optimistic
concurrency (`internal/resources/appservice.go:316`).

**Why:** we can create and delete an App Service but not resize one. Note what
this does NOT do: there is **no `version` field**, so PUT cannot upgrade an App
Service. Upgrading means delete and recreate at the new version, which destroys
its App Endpoints — so anyone planning an upgrade needs `capella_app_endpoint_create`
and `_update` (both shipped) as part of the procedure, not as an afterthought.
Worth stating plainly in the tool summary, because "update" implies otherwise.

### 3. In-place updates we do not have (4 ops)

| Operation | Path | Why |
|---|---|---|
| `PUT .../buckets/{id}` | `openapi.gen.go:28401` | resize a bucket without delete+recreate (`durabilityLevel, memoryAllocationInMb, replicas, timeToLiveInSeconds, flush`) |
| `PUT .../collections/{name}` | `:29516` | change `maxTTL` |
| `PUT .../users/{id}` | `:33681` | rotate a credential's password/access in place |
| `PUT .../projects/{id}` | `:18127` | rename a project |

**Why:** every one of these is currently a delete-and-recreate, which on a
bucket means destroying data to change a setting.

### 4. `GET .../replications/jobs/{jobId}` (`:33004`)

**Why:** `capella_replication_create` returns a `jobId`, not a replication id —
a gap `spec.py` already records and works around by listing. This closes it
directly.

### 5. App Endpoint completeness (6 ops)

`GET .../appEndpoints/{name}/cors` (`:24978`) — we can set CORS and not read it.
`DELETE .../appEndpoints/{name}/resync` (`:25738`) — we can start a resync and
not cancel one. `DELETE .../accessControlFunction` (`:23848`, 202).
`GET .../appEndpoints/{name}/collections` (`:24862`),
`.../adminUsers` (`:24547`), `GET|PUT .../auditLog` (`:24663/24736`).

### 6. Bucket backup schedules (4 ops)

`GET|POST|PUT|DELETE .../buckets/{id}/backup/schedules` (`:28613-28802`),
plus `GET .../backup/cycles[/{id}]` (`:28458/28558`).

**Why:** we ship on-demand backup and no scheduling at all. Note this is a
DIFFERENT path from the `/buckets/{id}/backupSchedule` that was retracted from
`spec_pending.py` on 2026-09-12 after a live sweep returned Go's mux default
404 — that retraction stands, and this is the route that actually exists. Worth
a probe before shipping, precisely because of that history.

### 7. App Service admin user read/update (2 ops)

`GET|PUT .../appservices/{id}/adminUsers/{userId}` (`:23263/23336`) — we create
and delete them and can neither read nor update one.

### 8. `GET .../sampleBuckets[/{id}]`, `DELETE .../sampleBuckets/{id}` (`:33107/33278/33223`)

**Why:** we load a sample bucket and cannot list or unload it. Small, and it
matters for fixture teardown.

---

## P2 — add if the use case appears

- **Free-tier cluster / bucket / App Service** (~14 ops, `:20844-21114`,
  `:27986-28223`, `:22464-22642`). Directly relevant to the ephemeral-environment
  workflow `capella_env_*` is meant to serve; a free-tier cluster is the cheapest
  possible test environment. Reason to wait: `capella_env_*` is not implemented
  yet, so there is nothing to wire them into.
- **Cloud snapshot backups** (~10 ops, `:29743-30314`). `spec_pending.py` flagged
  this subsystem as unexamined before anyone probed it; three read operations were
  promoted on evidence and the writes were not. Fully mapped in the generated
  client now, so the unknown is gone.
- **Org users and API keys** (~9 ops, `:34098-34365`, `:16637-16888`). Note
  `PATCH`, not `PUT`, on user update. Reason to wait: an MCP server that can mint
  API keys is a different security proposition, and that decision should be made
  deliberately rather than because the endpoint existed.
- **`GET .../organizations/{id}`** (`:15539`), **`GET .../allowedcidrs/{id}`**
  (`:22344`), **`GET .../scopes/{name}`, `GET .../collections/{name}`**
  (`:29161/29436`). Trivial reads that fill obvious holes.

---

## P3 — deliberately NOT adding, with reasons

**Networking: private endpoints, network peers, mTLS** (~20 ops, `:30745-32168`).
These configure how a cluster is reachable, on infrastructure the person running
this container does not own and cannot see. A misconfiguration here does not
produce an error message, it produces an outage, and the blast radius is the
customer's VPC. The Terraform provider is the right tool for this — it has state,
a plan step, and a human reading a diff. **Reconsider if** a customer asks for
private-endpoint *inspection* (the GETs alone, read-only) rather than management.

**CMEK** (~8 ops + associate/unassociate, `:17078-17523`, `:30314/30369`).
Customer-managed encryption keys. Same argument, sharper: an agent that can
unassociate a CMEK can make a cluster's data unreadable. **Reconsider if** the
read operations are wanted for audit purposes; the writes should stay out.

**Analytics / Columnar** (~30 ops, `:16533-20455`). A whole separate product
surface with its own clusters, databases and scopes. Not a gap in a Capella
*admin* server — it is a different server. **Reconsider if** someone actually
asks. Shipping 30 untested operations to be thorough is how the verification
debt this repo just spent a night clearing gets recreated.

**aiServices** (~25 ops, `:15573-16497`, `:21465-22001`). Models, providers,
API keys, workflows, workflow runs. Same reasoning, plus it is new enough that
the surface will move. **Reconsider when** it stabilises and someone names a use.

**`PUT .../organizations/{id}/configuration`** (`:17568`) and
**`PUT .../clusters/{id}/bucketStorageMigration`** (`:27827`). Organization-wide
settings and a storage-engine migration: rare, irreversible, and not things an
agent should reach for. The console is the right place. **Reconsider** never,
absent a specific request with a named reason.

---

## Known behaviours worth encoding, from the same audit

These are not missing operations; they are facts about operations we ship that
callers get wrong.

- `capella_bucket_flush` expects **200**. It is the only PUT in the whole
  provider that does not expect 204 (`internal/resources/flush_bucket.go:57`).
- **DELETE answers 202, not 204**, for cluster, App Service, App Endpoint and
  backup cycle. Anything treating 204 as the success condition reads those as
  failures.
- **POST answers 202** for cluster create, backup create, backup restore, audit
  log export create, and all three activation toggles.
- `capella_query_index_manage` expects **200** (`internal/resources/gsi.go:716`).
- `capella_app_service_create`'s `loadBalancerCidr` is in the provider's
  hand-written struct (`internal/api/appservice/appservice.go:35`) but NOT in the
  generated client. Keep it; the generated client is behind here. This is the one
  place where "the generated client is the stronger source" does not hold, and it
  is worth knowing that the rule has an exception.
- `ListEventsParams` supports `clusterIds`, `projectIds`, `severityLevels`,
  `userIds` and `tags` beyond the `from`/`to` we expose.

---

## Coverage gaps in checks we DO ship

A check that silently does not cover something is worse than a missing check,
because it reports a pass. These are the places where a shipped verification
knows less than its name suggests, each with what would close it.

- **`capella_fixture_verify` does not verify index REPLICA counts.** Measured
  2026-09-14: `system:indexes` on Capella 7.x carries no replica column, so the
  cluster check can confirm that each recorded index exists and is online but
  not how many copies of it there are. The fixture side knows the answer —
  `capella_query_index_definitions_list` enumerates each replica as its own
  entry with `" (replica N)"` appended to `indexName`, so the entry count per
  base name IS the expected copy count — and the code already compares them
  whenever a replica column is present. The output says `replicas_checked:
  false` and why, so the gap is never reported as a pass.
  *What closes it:* establishing whether this server exposes replica identity
  under another keyspace (`system:indexes_all` is the candidate to check, NOT
  to assume) and, if so, adding it as the replica source. Until somebody
  measures that, a fixture whose source carried replicas can be satisfied by a
  cluster with fewer — which changes failover behaviour and read throughput,
  quietly, in exactly the kind of environment a fixture exists to reproduce
  faithfully.
- **`capella_fixture_export` is annotated `readOnlyHint=True` and writes files.**
  Read-only with respect to the CLUSTER, which is what the hint is about, but a
  caller reading the annotation alone would not expect a filesystem write. Decide
  deliberately rather than leave it as an accident.
