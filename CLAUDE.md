# CLAUDE.md — CB Admin MCP

Read this before changing anything in this repository.

---

## 1. Verification mandate

**NEVER ASSUME. NEVER GUESS. ALWAYS VERIFY.** This outranks being fast and
outranks sounding certain. "I don't know yet, here is the one command that would
tell us" is a complete answer. A plausible cause stated as a finding is not.

### 1.1 Verify the write landed — by reading the content back

A tool reporting `written` is **not** evidence the file changed. On this setup
`device_commit_files` has returned `{"written": [...]}` for a write that did not
reach disk, twice in one session. Both times the next test run executed a stale
file and produced a failure that had already been fixed, which then cost a full
triage cycle to re-diagnose.

Size and mtime are not enough either — a partial or reverted write can carry a
fresh mtime. **Re-stage the file and grep it for the thing you changed.**

```
1. write        -> device_commit_files
2. read back    -> device_stage_files on the SAME path
3. prove        -> grep for the new symbol / string, and parse it
4. only then    -> tell Chris to run it
```

If step 3 fails, re-commit with `force: true` and repeat. Do not report a fix
as delivered until step 3 has passed.

### 1.2 Never invent a number

`assert len(OPS) > 100` was written into a test whose own docstring said "floors,
not exact counts". The registry held 97 AT THE TIME — it holds 125 as of
2026-09-14, which
is exactly why the sentence needed a tense: a count written in the present tense
becomes a false claim the moment the code moves, and this one sat wrong for
weeks. A floor that was not measured is a
guess with an assertion wrapped round it, and it fails for a reason unrelated to
the property under test — which trains the next person to edit the number rather
than read why it is there.

Assert the property that needs no magic number: non-emptiness, a relationship
between two measured values (`len(TOOLS) >= len(OPS)`), or equality against a
declared allowlist in the source.

### 1.3 Read the evidence before naming a cause

A hang was diagnosed as the VPN, then the VPN again after being told the tunnel
was down, then an absent local cluster, then a missing bucket. It was a
containerised cluster advertising `172.18.0.2` in its cluster map. Four confident
causes, zero tests run.

### 1.4 Say what would overturn it

Any claim worth making is worth stating alongside the observation that would
disprove it. If no such observation exists, it is not a finding.

### 1.5 Read the provider's generated client before probing the API

**The Terraform provider's generated client is the strongest source available
for a v4 request shape, and it outranks the rendered documentation pages.** It
is generated from Couchbase's own API document, so it carries the parameter
names, the required-vs-optional split and the content types as the service
actually implements them — not as a docs page describes them.

This rule has a price attached. `capella_app_endpoint_access_control_function_set`
was probed **43 measured times** against a live cluster, returning 400 "does not
evaluate to a function" on every attempt, and produced two retracted claims about
the body shape along the way. The answer was in the provider's source the whole
time: the body is **raw JavaScript with `Content-Type: application/javascript`**,
not JSON of any shape. Reading the generated client first would have cost one
grep.

The same source settled `bucket` being required-in-practice on the index
endpoints (`ListIndexDefinitionsParams`), the `/queryService/indexes` path, and
the restore body needing **both** `sourceClusterID` and `targetClusterID`.

Order of consultation, strongest first:

1. `internal/generated/api/openapi.gen.go` in the provider — generated, so it
   cannot drift from the API document.
2. The provider's hand-written structs under `internal/api/` — occasionally
   *ahead* of the generated client (see `loadBalancerCidr` in
   `internal/api/appservice/appservice.go`, which the generated client lacks).
   This is the one documented exception to rule 1.
3. A live probe.
4. The rendered docs pages. Last, not first: they have been wrong about the Data
   API base host and about the on/off schedule body.

See `docs/PROVIDER_SOURCE.md` for which checkout this refers to.

### 1.6 A probe that expects a refusal can perform the operation

**`body_required` is a claim about what a CALLER must send. It is not a claim
about what the SERVICE rejects.** Those are different propositions, and the
second one can only be established by asking.

On 2026-09-14 `scripts/verify_capella_paths.py --method-probe` read
`capella_data_api_set`'s `body_required=("enableDataApi",)`, inferred that an
empty body would be refused, and sent a real `PUT .../dataAPI` with `{}`.
Capella answered **202 Accepted**. An empty body means `enableDataApi: false`,
so the verification run **turned the Data API off on the cluster it was
measuring** — confirmed minutes later by `capella_data_api_get`:

    {"enabled": false, "state": "disabled", "connectionString": ""}

Everything in the fixture layer — export, import, cluster-side verify — reads
that connection string. A run whose whole purpose was to observe without
changing anything took the cluster's most load-bearing capability offline, and
the only reason it was caught is that the script reports a 2xx on a write as an
ERROR rather than a pass.

`Op.empty_body_accepted` is the override and it already existed
(`capella_alert_integration_update` carries it). The rule:

- Before relying on a refusal, ask whether the service has any reason to refuse.
  A PUT that replaces a small settings object usually has none.
- An operation whose empty body would be VALID input must carry
  `empty_body_accepted=True`, which drops it back to an OPTIONS probe.
- A 2xx from a probe is never evidence of a path. It is evidence that the probe
  did something, and the first question is what.

### 1.7 A harness must not report its own blind spot as a fact about the system

**"I could not find one" and "there is not one" are different claims.** A tool
that cannot tell them apart will report the first as the second, and the reader
has no way to know — because the output reads as evidence about the customer's
cluster.

This has now happened three times in `scripts/verify_capella_paths.py`, all of
them printed as though the cluster were empty:

1. A nested `{"data": [{"data": {...}}]}` response read as an empty list. The
   cluster had objects; the helper unwrapped one level and the endpoint used two.
2. `app_endpoint_name` and `app_endpoint_keyspace` were never discovered at all.
   **Twenty operations reported "no identifier available"**, six of them shipped
   ops that had therefore never been path-probed. The objects existed the whole
   time, and `scripts/verify_mcp_surface.py` had been discovering them from the
   same two calls all along.
3. The backup-cycle discovery looked for `cycleId`. The rows carry **`cycleID`**.
   It printed "this bucket has no cycles" in the same run in which
   `capella_bucket_backup_cycles_list` returned rows.

Each time the fix was local and the pattern survived. `_absence_detail` is the
structural answer: when no identifier is found, it inspects whether there were
ROWS, and says so explicitly —

    no rows -- the path is right and this cluster genuinely has none

    *** ROWS WERE RETURNED AND NONE CARRIED ['cycleId']. The keys present are
    ['createdAt', 'cycleID']. This is a limitation of THIS SCRIPT, not an empty
    cluster

The general rule, for any harness in this repository: **before reporting that
something is absent, establish that you looked somewhere it would have been.**
If that cannot be established, report the uncertainty rather than the absence.
This is §1.4 applied to tooling — a claim of absence is a finding, and a finding
needs the observation that would overturn it.

### 1.8 Retractions are recorded, not quietly corrected

A wrong cause stays in the document with the reason it failed. See
`CAPELLA-CONNECTIVITY.md`, which keeps all three of its retracted diagnoses.

---

## 2. Both surfaces, always

The server drives two unrelated control planes:

| Surface | Prefix | Reached via |
|---|---|---|
| Capella | `capella_*` | v4 API at `cloudapi.cloud.couchbase.com`, org API key |
| Enterprise Edition | `admin_*` | ns_server on 8091/18091, cluster-admin credential |
| Neutral | `cb_*` | SDK / SQL++ diagnostics and the server's own status |

`deployment.detect_mode()` decides which halves load, and **it infers that
decision from the environment when `CB_DEPLOYMENT` is unset**:

- Capella host in `CB_CONNECTION_STRING` → `capella`
- `CAPELLA_API_KEY_SECRET` set, no connection string → `capella`
- both set → `both`
- otherwise → `self_managed`

### 2.1 HARD RULE: one container, one control plane

**A deployment drives exactly one surface. Never both.** An EE container and a
Capella container, separately configured and separately networked.

`both` is a mode the server supports and that **no deployment artifact
configures and no documentation demonstrates**. Do not add one, do not show a
customer how to reach it, and do not suggest it as a convenience. It switches
capability gating off, which removes the containment that per-surface
deployments exist to provide: in a `both` deployment a misconfiguration can act
on a cluster nobody meant it to reach; in a per-surface deployment there is no
route to reach it through.

The `both` code path is still TESTED — `tests/test_no_vacuous_coverage.py`
covers all three modes — because a supported-by-the-code path that nothing
exercises is how gating regressions ship. Tested is not the same as advertised.

`CB_ADMIN_REQUIRE_DEPLOYMENT` declares the surface and the server refuses to
start if the configuration resolves to anything else. Every artifact under
`deploy/` sets it, and `tests/test_one_container_one_surface.py` fails CI if a
shipped compose file ever gains the variable that would widen it.

### 2.2 The inference is the hazard

A developer with a Capella key and no connection string gets `capella`, which
unloads every `admin_*` tool. Any test that iterates the LOADED registry then
reports a clean run having exercised one surface. This has bitten three times:

- `test_gating_still_comes_first` skipped itself silently.
- Seven dispatch tests took `next(iter(server._HANDLERS))`, got
  `admin_bucket_list`, and failed on a refusal rather than the transport.
- The org-discovery tests in `test_verify_capella_paths.py` silently moved onto
  the wrong branch because `CB_CAPELLA_ORG_ID` was exported.

**Any test whose subject is the tool registry must pin `CB_DEPLOYMENT`
explicitly**, and pin it in a subprocess if `server` has to be re-imported —
`server` and `handlers.shared` snapshot their configuration at import, so
`importlib.reload` leaks into every test that runs afterwards.

`tests/test_no_vacuous_coverage.py` holds the mode matrix. The Capella-mode
`admin_*` set is asserted equal to `deployment.CAPELLA_REACHABLE_ADMIN_TOOLS`,
so an exception has to be declared in source, with a reason, to pass.

### 2.3 Service APIs need their ns_server proxy prefix

Search, Eventing and Backup are not served on the management port bare:

| Service | Prefix |
|---|---|
| Search / FTS | `/_p/fts` |
| Eventing | `/_p/event` |
| Backup | `/_p/backup` |

All nine Search tools shipped with bare `/api/index` and 404'd against every
cluster. `tests/test_service_proxy_paths.py` asserts the property by parsing the
handler source, not by pinning individual strings.

---

## 3. Tests may not pass vacuously

An empty `parametrize` is reported as a SKIP that sits in the list looking
exactly like "needs Developer Mode". A `for` loop over an empty collection is a
plain green tick.

`tests/test_no_vacuous_coverage.py` scans every test module and fails, naming
file, line and collection, if a test parametrises over or loops over something
nothing asserts is non-empty. `MAY_BE_EMPTY` is the escape hatch and it costs a
companion test proving emptiness is the success state.

Do not weaken that scan to make a new test pass. Add the guard.

---

## 4. Environment

Chris runs **Windows / PowerShell 5.1**. Use `$env:VAR = '...'`, never
`set VAR=`. Do not hand him POSIX paths in commands.

| Thing | Setting |
|---|---|
| uv on this network | `$env:UV_SYSTEM_CERTS = '1'` — the proxy re-signs TLS; without it `uv sync` fails with `invalid peer certificate: UnknownIssuer`, which reads like a broken index |
| npm on this network | `NODE_EXTRA_CA_CERTS` pointing at the exported corporate roots. **Never** `npm config set strict-ssl false` |
| Credentials | `C:\Work\Development\cbenv.bat` (uses `setx`, so a NEW window is needed) |
| `CAPELLA_API_KEY_SECRET` | the **secret**, used as the v4 Bearer token. `CAPELLA_ACCESS_KEY_ID` is the key id. Not interchangeable — and the 401 Capella returns for the wrong one blames the IP allowlist, which is a lie |
| Test order | `pytest-randomly` is active. A test that passes on statement ordering is a coin flip, not a pass |

Platform limits, probed in `tests/_platform.py` rather than inferred from
`os.name`: symlink creation needs Developer Mode or elevation; file permission
bits do not exist, so `logging_config._restrict_to_owner` deliberately does
nothing there rather than calling `os.chmod` and looking enforced.

### 4.0 The mutation harnesses are only meaningful where symlinks work

On a plain Windows shell, `scripts/mutation_rounds_1_3.py` and
`mutation_round_4.py` report three SURVIVORS, all in the audit-sink family:

    audit sink: degrade silently instead of refusing to start
    audit sink: server no longer refuses to start
    audit sink: GUI no longer refuses to start

**Nothing is wrong with the code.** Every test that covers those lines is marked
`@requires_symlinks`, because it proves the property by CREATING a symlink where
the audit file is expected. Without Developer Mode those tests skip, a skipped
test cannot fail, and the harness scores the mutation as uncaught. Run the
harnesses in the Linux container, or on Windows with Developer Mode enabled.

This is section 1.7 applied to our own tooling, and the harness has the blind
spot the rule is about: it prints `SURVIVED`, which reads as a claim about the
CODE, when what it observed was that the covering test did not run on this
machine. It knows which test files it invoked and could say "the target suite
skipped N tests" beside a survivor. Until it does, treat an audit-sink survivor
from a Windows host as unproven rather than as a finding.

CONTRIBUTING.md tells a contributor both harnesses must report all mutations
caught and does not mention this. On a fresh Windows checkout that instruction
cannot be satisfied, and the failure looks like a missing security control.

**MEASURED 2026-09-15 — the container run is clean.** Both harnesses were run
end to end in `python:3.12-slim` for the first time: **52 of 52 caught**, 25 and
27, no survivors and no ANCHOR-GONE. Every audit-sink entry above was caught
once its `@requires_symlinks` tests actually ran. So the survivors really were
the blind spot and not the code, which until this run was an argument rather
than an observation.

    docker run --rm -v "C:\path\to\CB-Admin-MCP:/src:ro" python:3.12-slim bash -lc "set -e; cp -a /src /work; cd /work; rm -rf .venv .pytest_cache .ruff_cache; export PIP_CERT=/work/deploy/ca/corp-roots.crt REQUESTS_CA_BUNDLE=/work/deploy/ca/corp-roots.crt SSL_CERT_FILE=/work/deploy/ca/corp-roots.crt UV_PROJECT_ENVIRONMENT=/venv; pip install -q uv; uv sync --extra dev; set +e; /venv/bin/python scripts/mutation_rounds_1_3.py; /venv/bin/python scripts/mutation_round_4.py"

Three details in that line are not incidental:

  * **The three CA variables.** Behind corporate TLS interception the container
    fails at `pip install uv` with `CERTIFICATE_VERIFY_FAILED: self-signed
    certificate in certificate chain`, which reads as a broken image or a dead
    network and is neither. `deploy/ca/corp-roots.crt` is already in the tree
    for the image build; pip needs `PIP_CERT`, uv and urllib need
    `SSL_CERT_FILE`, requests needs `REQUESTS_CA_BUNDLE`.
  * **UV_PROJECT_ENVIRONMENT=/venv**, outside the tree. The harness copytrees
    the working directory once per mutation -- 52 times -- and a venv inside it
    is copied every time.
  * **set +e before the harnesses.** They exit non-zero when a mutation
    survives, which is a result to read, not a failure that should stop the
    second harness from running.

### 4.1 Docker on Windows: three ways the fixture looks broken and is not

Each of these produces a symptom that reads as a tool defect. All three were
diagnosed the slow way on 2026-09-13; none of them are in the code.

**A restarted container can lose its published ports.** `docker start` reports
success, the container reports `running`, and the host gets *connection
refused* on every port. The tell is the ports column:

    8091-8097/tcp                    <- EXPOSED only. Nothing is published.
    0.0.0.0:8091->8091/tcp           <- what a working mapping looks like

and `docker exec <c> curl -s http://127.0.0.1:8091/pools` answering **401**,
which proves Couchbase is healthy and the failure is entirely host-side. Port
mappings are fixed at CREATION, so this cannot be repaired in place — remove
the container and rebuild. Suspected cause: Docker Desktop restarting while
another container holds the port under `restart: unless-stopped`.

**`unless-stopped` resurrects the thing you stopped.** `docker stop` holds a
container down, but a Docker Desktop restart brings it back and it takes the
port again. Check with
`docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' <name>`.

**The Backup service dies if an external alternate address exists.** It reads
`/pools/default/nodeServices`, picks the EXTERNAL address as its own cluster
endpoint, asks cbauth for credentials for that hostport, does not find it, and
exits — restarting on a ~7.5 s cycle forever. Nothing listens on 8097, so every
`admin_backup_*` call through `/_p/backup` answers **500 Unexpected server
error** and every backup tool looks broken. The fix is topological, not code:
publish ports 1:1 and set no alternate address (`-PortOffset 0`, now the
default), or better, run the MCP server in a container on the same Docker
network and publish nothing at all.

The general shape: **a 404 or 500 from a service endpoint is a claim about the
environment until proven otherwise.** Read the service's own log under
`/opt/couchbase/var/lib/couchbase/logs/` before editing a handler.

---

## 5. Working style

- **Never paste code for Chris to copy in.** Edit the file, commit it, verify it
  per §1.1, then tell him what to run.
- Fix security bugs found in passing, in the same change.
- No Capella API key as a GitHub secret.
- Deleting GitHub workflow runs is permanently destructive and has never been
  approved.
- Research before contradicting him. "You can't change node services in place"
  was wrong; `POST /controller/rebalance` with `topology[<service>]` does exactly
  that. He was right and had done it before.

---

## 6. Known open

### Restore: DONE on Enterprise Edition, NOT on Capella

`admin_backup_restore_run` was performed on 2026-09-12 against the `mcptest`
repository and answered `{"task_name": "RESTORE-dd7647a6-..."}`. Run twice, both
accepted. `scripts/restore_cycle_test.py` reproduces it.

It settled a disagreement that mattered: this server's schema described the
`target` object as a FILTER BLOCK ("filter_keys, filter_values, mappings,
include, exclude") and the service wants a FLAT object whose `target` is the
DESTINATION CLUSTER URL with `user` and `password` beside it. A model following
the shipped description would have built a body the service rejects. The schema
is corrected from what was accepted.

**`capella_backup_restore` was PERFORMED cross-cluster on 2026-09-13.** 202
Accepted, Bride-of-Frankenstein -> ashmahadevsatyanarayanan, bucket
`travel-sample`, backup `bfacf78e-...` (full, 63,349 items), via
`scripts/capella_cross_cluster_restore.py --perform`. It took three attempts and
each rejection was a finding — see "Cross-cluster restore" below.

### The zero-skip target was set and MET — 2026-09-14

`verify_mcp_surface.py` reports **SKIPPED 0** and exits 0. The run that this
section used to describe — OK 60, SKIPPED 95 — was from 2026-09-01 and sat here
in the present tense for two weeks.

What got it there: the harness learned to discover the identifiers it had been
missing, rather than the tools being changed to need fewer. Those 95 were never
defects in the tools, and that distinction is the same one rule 1.7 is about.

**Counts move. Do not quote one here without a date beside it.** As of
2026-09-14: 125 operations in the Capella registry, 284 tools in the server's
raw registry, 1 entry in `SHIPPED_UNVERIFIED`.

### The fixture round trip is the only check that compares against something else

`scripts/fixture_round_trip.py`, RUNBOOK section 11. Export, import into a
scratch keyspace, export back, compare keys AND bodies.

**Every other fixture check compares a fixture against itself** — a per-file
sha256 matches the hash recorded for that same wrong file, 188 wrong documents
are still 188 lines, and a cluster-side `COUNT(*)` counted the wrong documents
correctly. All three passed while the Capella exporter was recording the wrong
key for 187 of 188 documents.

Enterprise Edition round-tripped CLEAN on 2026-09-14, first attempt: 187
documents out and back, keys, bodies and expiries identical. **It still found
four defects**, all in the index step, which the document comparison does not
cover — an FTS row rendered as a `CREATE INDEX`, definitions captured for the
whole bucket, a `keyspace_map` that rewrote only the bucket, and `defer_build`
skipped on the indexes that most need it.

The lesson is not "the round trip works". It is that **a clean result on the
thing you measured says nothing about the thing beside it**, and the index step
was beside it.

**The fresh-target run is DONE, 2026-09-14, and it is clean.** This section used
to say the index path was unexercised because every recorded index already
existed. `scratch.inventory.airline`, a bucket created for the purpose, closed
that: 187 documents out and back identical, and the import reported
`created: ["def_inventory_airline_primary"]` with no failures -- index creation
running for the first time rather than reporting `already exists`.

What that run does NOT cover, stated so the next reader does not take it wider
than it goes: the source collection carried exactly one GSI definition, a
primary index, and `fidelity.search_definitions` is false, so the exporter never
captured a Search index and the FTS-rendered-as-CREATE-INDEX fix was not
exercised by it. A collection with a real secondary index and a search index
would test more.

**Capella round-tripped clean the same day**, 188 documents, and the `META().id`
fix is confirmed by reading the fixture rather than by the comparison alone: the
recorded key is `airline_10` with the document's own `id: 10` nested under
`doc`, where it cannot reach the alias. That distinction matters, because a
round trip cannot catch a defect symmetric across both exports -- if both had
recorded `10`, `identical: true` would still hold.

**It also found a real defect**, which is the point of running it. The import's
structure step remapped only the bucket while the document step remapped the
whole keyspace, so a same-bucket `keyspace_map` created nothing and every
document write answered 404 ScopeNotFound. Fixed. A second finding, the
exporter carrying every index in the bucket rather than the fixture's own
keyspaces, is fixed too. Both are the Capella twins of defects already fixed on
the EE side, and both hid behind a round trip that mapped into a DIFFERENT
bucket -- which is the shape that happens to work.

### Two fixture questions left open on 2026-09-14

**The Capella exporter carries `_sync:syncInfo` into fixtures.** It is the 188th
document where EE records 187: a Sync Gateway metadata document with an empty
body, exported and then written into the target collection on import. The
manifest's fidelity note says system xattrs "including `_sync`" are not
captured, which is true and misleading together — this is a `_sync:` DOCUMENT,
not an xattr. It matters because this repository already decided the neighbouring
case: the path verifier was changed to never bind an App Endpoint over a real
collection, on the grounds that writing sync metadata into somebody's bucket is
not a verification tool's business. Importing a `_sync:` document into a fresh
collection is the quieter version of the same act. Either skip `_sync:*` keys by
default or record them and say so in `not_applied`. NEEDS A DECISION, because it
changes what a fixture contains.

**The GSI definition filter is applied after the fact, not to the request.**
`capella_query_index_definitions_list` declares bucket, scope and collection as
query parameters; the export sends only `bucket` and now filters the response by
parsing each rendered `definition` statement. That is correct and it is a second
best. Narrowing the request needs the parameter names as the service implements
them, which is `internal/generated/api/openapi.gen.go` in the Terraform provider
— section 1.5, and the checkout that task is parked on.

### Capella write bodies: MOSTLY PROVEN NOW, and the failure mode has changed

This said "one write of roughly 45 has been performed". That was true on
2026-09-01. Most writes now carry a measured 400, 405 or 422 earned by a probe
that did not perform them, and several carry a real performed status recorded in
`LIVE_VERIFIED_OUT_OF_BAND`.

The standing hazard is unchanged and worth restating, because it bit again on
2026-09-14: **a path probe never sends a body, so it cannot catch a wrong one.**
This registry had already shipped three wrong bodies behind verified paths —
`access` missing from both credential creates, and `deltaSync` for
`deltaSyncEnabled`. Since then:

- `capella_bucket_update` and `capella_app_service_update` were written as
  PARTIAL updates and are FULL REPLACEMENTS. A partial bucket resize would have
  returned success and silently removed the bucket's replicas, because
  `replicas: 0` is a legal value no validator rejects.
- Three operations answered 405 on their paths and are still parked, because
  they declare no body at all.

### Never exercised at all

  * ~~the HTTP transport. Everything has been driven over stdio.~~
    **WRONG, CORRECTED 2026-09-22.** This bullet was written 2026-09-14 and the
    run that falsified it happened 2026-09-15: the Keycloak 26.7.3 lab drove the
    authorization model end to end OVER THE HTTP TRANSPORT, on the host and then
    again inside `cb-admin-mcp:ee`, and `README.md` records it in full. The claim
    survived a week in this file and in `docs/CONTAINER_DEPLOYMENT.md` §10 — the
    guide a customer reads — where it understated the one transport a container
    deployment actually uses. Kept struck through rather than deleted, because a
    stale "never exercised" is the same failure shape as section 1.7 and deleting
    it hides that this file was the source.
  * the GUI's `POST /api/call` parity with MCP dispatch. NARROWED 2026-09-14:
    the two surfaces are now asserted to advertise an IDENTICAL tool set, in
    both directions, by tests/test_gui_authorization.py — which was added after
    handlers/backup_catalog.py was found to have been absent from the console
    for its entire life. What is still unexercised is DISPATCH behaviour:
    whether a call through the console enforces the same confirmation, scope
    and audit path as the same call through MCP. Membership is guarded;
    behaviour is not.
  * `deploy/k8s/*.yaml` — written, asserted by tests, never applied.
  * `deploy/docker-compose.*.yml` — never brought up. The container verification
    uses `docker run` probes, which exercise the image but not the compose files.

### Cross-cluster restore: PERFORMED 2026-09-13

`capella_backup_restore` takes `sourceClusterID` and `targetClusterID` as
SEPARATE required fields, which is a shape that only makes sense if they can
differ. It is now exercised end to end: 202 Accepted, a real restore from one
Capella cluster into another, driven through an MCP client.

Getting there cost three attempts, and each rejection corrected something this
file or the registry had asserted without measuring:

  1. **422 code 5026** — "The source cluster ID is invalid. Please ensure the
     source cluster id matches the id in the path." `spec.py` said the path
     names the TARGET. It names the SOURCE. A model following the shipped tool
     description would build a request that cannot succeed, and a customer
     hitting it would reasonably conclude cross-cluster restore does not work.
     Capella has a dedicated error code for this confusion, which is evidence
     the confusion is common.

         path cluster_id  == sourceClusterID   owns the backup, read only
         targetClusterID  (body only)          OVERWRITTEN

     Consequence beyond the wrong sentence: the ownership guardrail in
     `handlers/capella/__init__.py` fetches the PATH cluster, so on this one
     operation it guarded the cluster being READ and left the cluster being
     OVERWRITTEN unchecked. `CAPELLA_PROTECTED_CLUSTERS` could name a production
     cluster and a restore could still overwrite it. Fixed: check 2a guards
     `body.targetClusterID` and refuses if it is absent.

  2. **422 code 5022** — "Unable to target a restore for a cluster that is not
     in a healthy state." The target was in `peering` while an XDCR replication
     established its network path. A cluster leaves `healthy` for ordinary
     reasons long after provisioning, so "it deployed fine" is a different
     claim. Both ends are now preflighted.

  3. **The target bucket must already exist**, with the same name AND the same
     conflict resolution as the source. The v4 restore body has no auto-create
     flag — unlike the self-managed Backup Service body, which has
     `auto_create_buckets`. The script creates it with
     `capella_bucket_create`, copying `storageBackend`, quota, replicas and
     conflict resolution off the SOURCE bucket rather than using defaults.

None of this was visible from `[LIVE 405]`. An OPTIONS probe matched the route
and said nothing about the path semantics, the preconditions, or the body —
which is the standing argument in this repository for why a path-only
verification is not a verified operation, stated here with three counts of
evidence.

**One honest limit on the evidence.** A two-way XDCR replication had been
running before the restore and had already moved ~31,592 documents into the
target bucket, so a raw item count does not by itself separate "arrived by
restore" from "arrived by replication". The replication was DELETED before the
restore was issued, so anything the count gains from here is attributable to
the restore and nothing else is writing. Say it that way rather than quoting a
final count as if it proved the restore alone.

- `admin_backup_*` — all four candidate paths 404 with the Backup service
  present. **Not guessed.** Unresolved and recorded as unresolved.
- `scripts/verify_mcp_surface.py` still reports SKIPPED for tools whose write
  bodies cannot be synthesised from the shipped schema. That is a limitation of
  the harness, not a defect in those tools, and must be reported as such — see
  §1.4. Reporting 41 already-live-verified operations as PROTOCOL FAILURES is
  the mistake to avoid.
