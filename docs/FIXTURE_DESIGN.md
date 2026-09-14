# Capella Fixtures — design note

Status: proposal. Two facts it rests on are unverified; both are flagged inline and
both are settled by one probe run. Do not treat the fidelity table as final until
they are.

Author context: written against CB-Admin-MCP as of 2026-08-13, 61 Capella v4 ops in
`handlers/capella/spec.py`, none of them backup or restore.

## The problem

Disney asked for backup and restore across clusters, with tags on backups and
filtering over those tags. Three example queries were given:

    latest backup where content-publisher-version = 1.6
    last month backup where 'trips' not in projectName
    backup where scenario = "Notification Center Hurricane" and version = 1.1

Read those queries again and notice what they are not. Nobody filters a *backup*
by publisher version. They are describing named, versioned test datasets. The
requirement is a fixture catalogue wearing backup vocabulary.

That reframing matters because it changes which Capella primitive is correct, and
because backup semantics are the one thing we cannot deliver well and fixture
semantics are something we can deliver completely.

## Why native Capella backup is the wrong primitive here

Capella's managed backup is a storage-layer snapshot held in Capella-managed
storage. It is the right tool for recovery. It is the wrong tool here for four
reasons:

  * Backups carry no user-defined metadata, so the three queries above have
    nothing to match against. No naming convention fixes this because Capella
    backups are cycle-based and not user-named.
  * Getting the bytes out is console-only. A download is requested in the UI, a
    URL arrives by email, you have twelve hours to retrieve the URL, one hour to
    start the download once copied, and the file is deleted after about
    twenty-four hours. There is no documented Management API equivalent. That
    rules it out of any automated loop.
  * Cross-provider movement requires the download path plus cbbackupmgr, which
    inherits the same manual step.
  * A restore returns index definitions with the indexes unbuilt. A cluster
    restored this way is not performance-comparable to its source until builds
    complete, which for load testing means the numbers are wrong in a way that
    reads as a Couchbase performance problem.

Native backup and restore should still be added to the MCP — it is six `Op`
records and it is the right answer for anything resembling recovery. It is just
not the answer to what was asked.

## Architecture

A fixture is a manifest plus a data payload, produced and consumed entirely over
HTTP. No shell, no CLI, no console. Three APIs are involved, which is the part
worth internalising: there is no single export endpoint on Capella and there is no
bulk export, no bulk-get, and no DCP over HTTP.

    Data API          POST   /_p/query/query/service                    SQL++ passthrough. The export engine.
                      GET    /_p/fts/api/bucket/{b}/scope/{s}/index      Search index definitions out.
                      PUT    /_p/fts/api/bucket/{b}/scope/{s}/index/{i}  Search index definitions in.
                      base   https://{clusterId}.data.cloud.couchbase.com
                      auth   HTTP Basic, cluster access credential

    v4 Management     GET    .../queryIndexes/definitions                GSI CREATE statements.
                      GET    .../queryIndexes/buildStatus                Build gating on import.
                      GET    .../eventing/functions                      Eventing out.
                      POST   .../eventing/functions                      Eventing in.
                      buckets / scopes / collections                     Structure. Already in spec.py.
                      auth   organization API key. A DIFFERENT credential
                             from the Data API. Both are needed.

    App Services      POST   /{keyspace}/_bulk_get                       Mobile-mode export.
    Public REST       POST   /{keyspace}/_bulk_docs                      Mobile-mode import.

The Data API is off by default and is enabled per cluster, either in the UI or by
setting `enableDataApi: true` on the v4 cluster resource. That means
`capella_cluster_update` needs the field exposed in its body schema, and
`capella_fixture_export` must fail with a clear message rather than a connection
error when the endpoint is not enabled.

### Export sequence

  1. Resolve the cluster, confirm the Data API endpoint is enabled, obtain both
     credentials.
  2. Read structure from v4: buckets with their settings, scopes, collections.
  3. Read GSI definitions from `GET .../queryIndexes/definitions`.
  4. Read Search index definitions per scope from the FTS passthrough.
  5. Read eventing functions from v4 — the function object and `/code` separately.
  6. Read documents with SQL++ over the query passthrough, selecting the body plus
     `META().id` and `META().expiration`, paginated by key range.
  7. Write the payload, hash it, write the manifest.

### Import sequence

  1. Read and validate the manifest against its schema and content hash.
  2. Create buckets, scopes and collections through v4 from the manifest's
     structure block.
  3. Load documents with `INSERT INTO ... (KEY, VALUE, OPTIONS)`, replaying
     expiry from the manifest.
  4. `PUT` the Search index definitions.
  5. `POST` the eventing functions, then set state.
  6. Create the GSI indexes, then `BUILD INDEX`, then poll
     `GET .../queryIndexes/buildStatus` until every index is online.
  7. Only then report ready. Reporting ready before step 6 completes is the
     failure mode this whole design exists to prevent.

Step 6 is not optional and it is not an optimisation. It is the difference between
a fixture and a trap.

## Pagination, and why not OFFSET

Key-range pagination, not `LIMIT`/`OFFSET`. `OFFSET` re-scans on every page and
degrades quadratically over a large collection, and it is not stable if anything
mutates mid-export. Order by `META().id` and carry the last key forward:

    SELECT META().id AS id, META().expiration AS exp, d.*
    FROM `bucket`.`scope`.`collection` AS d
    WHERE META().id > $last_key
    ORDER BY META().id
    LIMIT $page_size

The first page passes the empty string. This is stable, resumable, and the last
key is the only cursor state to persist.

## Manifest schema

One file per fixture, `manifest.json`, sitting beside a `data/` directory. JSON,
committed, diffable. The `tags` object is the entire answer to Disney's filtering
requirement and it is deliberately free-form.

```json
{
  "schema": "couchbase.capella.fixture/v1",
  "fixture_id": "notification-center-hurricane-1.1",
  "created_at": "2026-08-13T14:22:07Z",
  "created_by": "chris.ahrendt@couchbase.com",
  "mode": "server",

  "tags": {
    "scenario": "Notification Center Hurricane",
    "version": "1.1",
    "content-publisher-version": "1.6",
    "projectName": "parks-notifications"
  },

  "source": {
    "organization_id": "…",
    "project_id": "…",
    "project_name": "…",
    "cluster_id": "…",
    "cluster_name": "…",
    "server_version": "8.0.0-1928-enterprise",
    "cloud_provider": "aws",
    "region": "us-east-1"
  },

  "structure": {
    "buckets": [
      {
        "name": "parks",
        "settings": { "memoryAllocationInMb": 1024, "bucketConflictResolution": "seqno",
                      "durabilityLevel": "none", "replicas": 1, "flush": false,
                      "timeToLiveInSeconds": 0, "storageBackend": "couchstore" },
        "scopes": [
          { "name": "notifications",
            "collections": [ { "name": "messages", "maxTTL": 0 },
                             { "name": "audience",  "maxTTL": 0 } ] }
        ]
      }
    ]
  },

  "indexes": {
    "gsi": [
      { "keyspace": "parks.notifications.messages",
        "name": "idx_msg_type",
        "statement": "CREATE INDEX `idx_msg_type` ON `parks`.`notifications`.`messages`(`type`)",
        "num_replica": 1,
        "is_primary": false }
    ],
    "search": [
      { "bucket": "parks", "scope": "notifications", "name": "msg_fts",
        "definition": { "…": "verbatim JSON from GET /_p/fts/.../index/{name}" } }
    ]
  },

  "eventing": [
    { "name": "on_notification_write",
      "settings": { "…": "verbatim function object from v4" },
      "code_file": "eventing/on_notification_write.js",
      "target_state": "deployed" }
  ],

  "data": [
    { "keyspace": "parks.notifications.messages",
      "file": "data/parks.notifications.messages.jsonl",
      "document_count": 48213,
      "bytes": 61203944,
      "sha256": "…",
      "carries_expiry": true,
      "user_xattrs": ["metadata"] }
  ],

  "fidelity": {
    "cas_preserved": false,
    "expiry_preserved": true,
    "expiry_form": "absolute_unix_timestamp",
    "system_xattrs_preserved": false,
    "user_xattrs_preserved": true,
    "user_xattrs_enumerated": false,
    "tombstones_preserved": false
  },

  "payload_sha256": "…"
}
```

Two notes on the shape.

`fidelity` is written by the exporter, not by hand. It exists so that a restored
environment can be asked what it is missing rather than assumed complete. A
consumer that needs CAS or mobile sync state can refuse a fixture that says it
does not carry them.

`user_xattrs` is an explicit list per keyspace because `SELECT META().xattrs`
returns empty by design — the whole object is not selectable. Every attribute name
must be known in advance, at most fifteen per query, and the full surface requires
Server 8.0. If the list is wrong, xattrs are silently dropped. This is the sharpest
edge in the design and it is why the field is required rather than optional.

Data files are JSON Lines, one document per line, `{"id": …, "exp": …, "doc": {…},
"xattrs": {…}}`. Line-oriented so a large fixture streams and diffs sanely.

## Fidelity

| Property | Preserved | Mechanism / why not |
| --- | --- | --- |
| Document body | yes | SQL++ select, `INSERT` |
| Document key | yes | `META().id` |
| Expiry / TTL | yes, degraded | Read as absolute Unix timestamp; written via `OPTIONS {"expiration": …}`. A relative TTL is not recoverable as originally expressed |
| CAS | **no** | No documented API sets CAS. Data API exposes it only as an `If-Match` precondition. Every restored document gets a fresh CAS |
| User xattrs | yes, with a catch | Writable via `INSERT … OPTIONS {"xattrs": …}`; not enumerable on read, so names must be declared. 15 per query, Server 8.0 |
| System xattrs (`_sync`) | **no** | Not documented as readable or writable via SQL++; wholly absent from the Data API. Mobile sync state does not survive server mode |
| Tombstones | no | Not exposed |
| Bucket / scope / collection structure | yes | v4 |
| GSI definitions | yes | `GET .../queryIndexes/definitions` |
| Search index definitions | yes | FTS passthrough, both directions |
| Eventing functions | yes | v4, object plus `/code` plus `/state` |
| Bucket-wide / alias FTS indexes | unconfirmed | Only scope-level FTS paths are documented on Capella |

## Two modes, one manifest

**Server mode.** SQL++ export and import as above. Correct for any dataset that is
not mobile-synced. Loses `_sync`.

**Mobile mode.** App Services Public REST `_bulk_get` and `_bulk_docs`. This is the
only documented path that handles `_sync` correctly, because App Services owns that
xattr and regenerates it on write. It sees only documents in a mobile-synced
keyspace and it rewrites revision metadata, so it is not general purpose and
revision history is not preserved verbatim.

`mode` in the manifest records which was used. A fixture exported in server mode
must not be presented as suitable for a mobile scenario, and the manifest is what
makes that checkable rather than a matter of memory.

If a Disney scenario needs mobile sync state, server mode is wrong and no amount
of care in the exporter fixes it. Establish this per scenario before building.

## Throughput envelope

Documented limits on the Data API: 100 MB maximum per request and response, 120
second request timeout, 10,000 requests per second per node. No bulk-get on the KV
side, so throughput comes only from batching inside SQL++ statements.

This is sound for bounded fixtures. It is not a mechanism for moving hundreds of
gigabytes. If Disney's load-test datasets are large, the fixture should carry a
*generator specification* rather than the documents, and generation runs on the
target cluster. That is a different feature and it should not be smuggled into
this one.

**Open question for the SE:** order of magnitude of documents per scenario. Tens of
thousands means ship the data. Hundreds of millions means ship a generator.

## Guardrails

Export is a read. It still needs the org pin, because a fixture exported from a
project outside the sandbox is an exfiltration path with a friendly name.

Import is destructive to the target. It creates buckets and overwrites documents,
so it takes the existing treatment: `guarded=True`, project allowlist, name prefix
on any bucket it creates, and `confirm`. Unlike teardown I would not exempt
automation principals from `confirm` on import into an existing bucket, because
teardown is exempt so CI can clean up after itself and there is no equivalent
argument for overwriting live data.

Writing the payload to a path is the sensitive part. `handlers/egress.py` already
carries the machinery and the handoff records a MED finding where
`admin_backup_restore_run` was reachable as `target="s3://169.254.169.254/loot"`
through a scalar root. Fixture paths go through the same egress walk, and the tests
for that walk should gain fixture cases rather than the fixture tools inventing
their own check.

## What this removes from the CBSE list

Backup tagging and filtering. Solved outright by the manifest. Two of the three
example queries do not even need it — `capella_backups_list` returns timestamps and
project is already a path parameter — but with fixtures the whole question
dissolves.

FTS index administration. I previously recorded this as having no v4 equivalent,
citing unconfirmed reachability on 18094, and `CAPELLA_HANDOFF.md` calls it "the one
genuine capability gap rather than a responsibility Couchbase took over." That is
wrong. Read and write of Search index definitions are documented on Capella through
the Data API FTS passthrough. The handoff doc should be corrected.

What remains genuinely CBSE-worthy: downloadable managed backup via API, native
cross-CSP restore, and turn-off being refused during backup or maintenance with no
queue or deferral.

## Unverified, and how to settle it

Two items. Both are one probe run with `scripts/verify_capella_paths.py
--method-probe`, and neither should be designed around until settled.

**The restore path disagrees between two reads of the v4 reference.** One gave
`POST .../clusters/{clusterId}/backup/restore`, the other
`POST .../clusters/{clusterId}/backups/{backupId}/restore`. The second shape — a
backup id in the path alongside the target cluster — is the one that permits
cross-cluster restore natively. Settling this decides whether native
cross-cluster restore is a primitive or an orchestration problem, and it is the
question the Slack thread is waiting on.

**The `queryIndexes` schemas truncate in the rendered reference.** What `POST
.../queryIndexes` covers is unknown, and the response shape of `/definitions` is
unknown. Plain `CREATE INDEX` and `BUILD INDEX` over the query passthrough are the
more predictable route for import regardless, so this only affects export.

Separately, and not a fixture question: `mcp-server-couchbase`'s
`_validate_query_row` requires `metadata.definition` on `system:indexes` rows and
`process_index_data_from_query` returns it, but the documented `system:indexes`
schema lists `metadata` as containing only `last_scan_time`, `num_replica` and
`stats`. If 8.0 clusters do not emit `metadata.definition`, `list_indexes` degrades
to the raw fallback with a "please report this issue" warning on every row for the
entire v8-and-above path. Probably the docs page is incomplete. `SELECT metadata
FROM system:indexes LIMIT 1` against an 8.0 cluster settles it before anyone files
anything.

## Sequencing

  1. Probe run. Settles the restore path and the `queryIndexes` schemas, and
     promotes the new paths from `[DOC]` to `[LIVE+METHOD]`.
  2. Native backup and restore `Op` records. Six of them, mechanical, and the
     right answer for recovery even though it is not the answer to Disney's ask.
  3. Manifest schema and the catalogue read/write tools. Smallest piece, highest
     value, useful before either export mode exists.
  4. Server-mode export and import, with build gating.
  5. Mobile mode, only if a scenario needs `_sync`.
  6. Everything else deferred in the handoff — eventing, CMEK, audit-log export,
     billing, network peers, private endpoints — after.

---

## Scope: which planes the fixture family covers

**SUPERSEDED 2026-09-14, later the same day. Chris answered the question this
section said would settle it — both planes — so the family is no longer
Capella-only and an Enterprise Edition sibling is in scope.**

The reasoning below is kept rather than deleted, because it is still the
argument for why an EE implementation is a SECOND IMPLEMENTATION and not a port,
and that is the thing most likely to be underestimated by whoever picks the work
up. What has changed is the conclusion, not the analysis.

The original decision, for the record:

> **Decided 2026-09-14: the `capella_fixture_*` family is Capella-only, and that
> is a decision rather than an oversight. It is also not obviously the right one,
> so the argument against is recorded alongside it.**

This matters because the rest of the tool surface is verified against *both*
deployment targets, and `handlers/backup_catalog.py` is explicitly plane-aware —
every entry carries `plane: capella | enterprise` and the sync step marks entries
`out_of_scope` on the plane they do not belong to. Against that background, a
family that silently works on one plane only reads as something nobody got to.

### Why Capella-only

- **The mechanism is Capella's.** Export reads documents over the Capella Data
  API: a control-plane call to discover `connectionString`, an HTTP Basic cluster
  access credential, and the allowlist that governs it. Enterprise Edition has
  none of those three. There is no "enable the Data API" on EE because the query
  service is simply there, on port 18093, reached with cluster credentials.
- **So an EE implementation is not a port, it is a second implementation.** The
  structure walk would go through the EE REST API rather than v4 ops, document
  export would go through the EE query service or the SDK, and index state would
  come from the same `system:indexes` but reached differently. Roughly the only
  parts that transfer unchanged are the manifest schema, the integrity check, and
  `capella_fixture_list` — which is pure filesystem work and already
  plane-agnostic in everything but its name.
- **EE already has the thing fixtures substitute for.** `cbbackupmgr` is a real
  backup tool with real restore semantics, available on every EE node. The whole
  argument for fixtures (see the opening of this document) is that *Capella*
  backups cannot be named, carry no metadata, and cannot be moved between
  clusters on demand. That argument does not apply to EE.

### Why the decision might be wrong

- **A fixture is not a backup, on either plane.** The reason to want one is
  reproducibility — "the exact dataset scenario 1.6 was measured against" — and
  that need is identical on EE. `cbbackupmgr` answers recovery, not
  reproducibility, and a tagged, hash-verified, diffable JSON Lines payload is a
  different artifact from a binary backup.
- **The container story cuts against it.** Disney runs this in a container, and
  the hard rule is one container per plane. An operator running the EE container
  sees four `capella_fixture_*` tools that cannot work for them. Under the
  capability gating that is arguably correct — they should not be *loaded* at all
  in EE mode — but "correct" and "explicable" are not the same thing, and nobody
  has checked which of the two happens today.
- **The manifest is already plane-neutral.** `schema`, `tags`, `files`,
  `payload_sha256` and the integrity check say nothing about Capella. An
  `ee_fixture_export` writing the same manifest would produce fixtures
  interchangeable with Capella's, which is a genuinely valuable property: capture
  on a laptop's EE cluster, import into Capella, compare like for like.

### What settled it

Not an argument — a question, and it has been answered.

The question was: **do they need to reproduce a dataset on Enterprise Edition,
or only on Capella?** The answer, on 2026-09-14, was **both**.

So the work is the sibling pair this section predicted: an `admin_fixture_*`
family sharing the manifest schema, the integrity check and the path handling
with the Capella one, rather than a rewrite of the Capella path. The prefix is
`admin_` rather than `ee_` because that is this server's established prefix for
the self-managed surface, and a third prefix would be a new convention bought
for nothing.

The shared half lives in `handlers/fixture_core.py`. What is genuinely separate
is the three things named above: the structure walk, document export, and
document import — because EE reaches all three through the query service and the
SDK rather than through v4 operations and the Data API.

### Status of the EE family — ROUND-TRIPPED CLEAN 2026-09-14

**The Enterprise Edition round trip passed on its first run**, against
`travel-sample.inventory.airline` on a local 7.6 cluster:

    187 documents exported
    187 imported into travel-sample.roundtrip.airline
    187 exported back
    keys matching 187, bodies differing 0, expiries differing 0

That is the strongest statement available about a fixture family, and it is what
the section below used to say had not been made.

**It still found four defects**, all in the index step, which the document
comparison does not cover — which is the argument for running the thing rather
than reasoning about it, stated with evidence:

1. **A Search index was rendered as a `CREATE INDEX`.** `system:indexes` carries
   FTS indexes too, with `using` of `fts` and no `index_key`, and the exporter
   assembled one into `CREATE INDEX ... ON \`travel-sample\`.\`_default\`.\`_default\`()`
   — rejected with `syntax error ... near '(', at: )`. Rows are now filtered to
   `gsi`, and one with no keys that is not primary is skipped with a reason.
2. **Index definitions covered the whole bucket.** A fixture carrying ONE
   collection recorded 23 definitions and the import attempted all 23. On that
   cluster they existed already; against a fresh target it would have built
   indexes for collections the fixture carries no data for. Capture is now
   scoped to the keyspaces actually exported, which is why it happens after the
   document phase rather than before it.
3. **`keyspace_map` rewrote only the bucket.** Mapping
   `travel-sample.inventory.airline` to `travel-sample.roundtrip.airline` — same
   bucket, different scope — substituted `travel-sample` for `travel-sample`, a
   no-op, so every statement still named `inventory`.`airline`. On that cluster
   they already existed and it said so; on a fresh target it would have built
   the fixture's indexes on the SOURCE collection and left the imported one with
   none, reporting `ok` either way. **This was the worst of the four**, and the
   docstring on the function already described the failure mode it produced.
4. **`defer_build` was skipped on exactly the indexes that need it.** The check
   was `if " WITH " not in statement`, so an index already carrying a `WITH` —
   the ones with `num_replica`, the expensive ones — got nothing appended and
   was built eagerly while the importer went on to issue a `BUILD INDEX` for it.

Each is pinned by a test in `tests/test_ee_fixture.py` naming the run that found
it.

### The family as originally shipped — WRITTEN 2026-09-14

`handlers/fixture.py` ships four tools: `admin_fixture_export`,
`admin_fixture_import`, `admin_fixture_list`, `admin_fixture_verify`.

**Run 2026-09-14 and clean** — see above. Before that run this section said it
had not been, and the reason the claim was tracked so carefully is what the
Capella round trip found: per-file hashes, line counts and a
cluster-side `COUNT(*)` all agreed while 187 of 188 document keys were wrong.
Every one of those checks compares a fixture against itself. Only export →
import elsewhere → export back → compare found it.

So the EE family is carefully written code, not a verified capability, and the
one thing that would change that is a round trip on a real cluster.

What differs from the Capella implementation, and why:

| | Capella | Enterprise Edition |
|---|---|---|
| Structure | v4 bucket/scope ops | `GET /pools/default/buckets`, `.../scopes` |
| Index definitions | v4, returns a rendered `definition` | `system:indexes`, assembled here |
| Eventing | v4 op | `/_p/event/api/v1/functions` |
| Document read | Data API SQL over HTTP | SDK `cluster.query` |
| Document write | Data API KV over HTTP | SDK `collection.upsert` |
| Credential | org API key **plus** a cluster access credential | the cluster credential this server already holds |

Two deliberate refusals, both about not making capacity decisions on somebody
else's cluster as a side effect:

- **Export will not create an index.** A collection with none cannot be read by
  SQL++ at all, and the export says so with the statement to run — but building
  an index is a capacity decision, not a side effect of reading.
- **Import will not create a bucket.** A bucket is a memory-quota decision on a
  cluster somebody else sized. Scopes and collections it will create, because
  those are what the data needs and they cost nothing to hold.

### Checked — ANSWERED 2026-09-14

The open question was whether the `capella_fixture_*` tools are correctly
excluded from the tool list in EE mode, or merely present and failing at call
time. They are correctly excluded. Measured by loading the registry with
`CB_DEPLOYMENT` pinned, which is the same code path a container takes:

    measured 2026-09-14
    self_managed   142 tools loaded, fixture tools: []
    capella        158 tools loaded, fixture tools: [export, import, list, verify]

An operator running the EE container therefore does not see four tools that
cannot work for them, which was the concern.

**What this does NOT establish**, and the distinction matters: this measured the
gating, not the shipped image. A container could still differ — a different
entry point, an environment the compose file supplies differently — and the run
of `scripts/run-docker-verification.ps1` against the EE compose file would settle
that. What it would add is confirmation that the image behaves as the code does;
the gating logic itself is no longer the open part.
