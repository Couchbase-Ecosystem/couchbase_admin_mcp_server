# Fixtures: named, hash-verified datasets on both planes

**Source:** `handlers/fixture_core.py` (the shared half), `handlers/fixture.py` (Enterprise
Edition, `admin_fixture_*`), `handlers/capella/fixture.py` (Capella, `capella_fixture_*`),
`scripts/fixture_round_trip.py` (the check that matters most).
**Spec:** `docs/spec.md` S9 (fixtures and the backup catalogue).
**Longer history:** `docs/FIXTURE_DESIGN.md`. Its opening line still says "Status: proposal"
and its fidelity table is marked not final. Both are out of date: both planes are built and
round-tripped. Read it for the reasoning and the measured Capella limits, and this note for the
current state.

## What it decides

A fixture is a manifest plus one JSON Lines file per keyspace: structure, index definitions,
eventing functions and document bodies with their expiry, each file hashed. Four tools per
plane: export, import, list and verify. Three things are decided here.

1. **What a fixture is for.** Reproducibility, not recovery. "The exact dataset scenario 1.6 was
   measured against, tagged, diffable, loadable into a cluster that is not the one it came
   from." It is not a backup. Export iterates, so it is not point-in-time consistent. CAS is
   not preserved. In server mode system xattrs (Sync Gateway state) are not preserved.
   Anything resembling recovery uses the backup tools. Nothing in the fixture code is named
   "backup", on purpose.
2. **What is shared between the planes** (`fixture_core.py`, and only that): where a fixture may
   be written, how a manifest is read, the integrity check, keyspace splitting, the export
   statement and its column names, and the index-definition rewrites.
3. **What is not shared.** Capella reads documents over the Data API with a cluster access
   credential and the org API key for structure. Enterprise Edition reads over the query
   service and writes over KV through the SDK, with the credentials the server already holds.
   The EE family is a second implementation, not a port. Chris Ahrendt decided on 2026-09-14
   that both planes are in scope.

## Why it is built this way

**One implementation of the manifest, because a fixture must travel.** A fixture captured on a
laptop's Enterprise Edition cluster and imported into Capella is only meaningful if both sides
agree exactly on what the manifest means. A second copy of the hash comparison is a second place
to be subtly wrong, and the failure is silent: a fixture that verifies on the plane that wrote it
and nowhere else. `fixture_core.py` uses only the standard library and names no plane, and tests
hold both facts (see below).

**The export aliases begin with two underscores, and that is load-bearing.** The export query
selected `META().id AS id, META().expiration AS exp, d.*`. Because `d.*` comes last, any document
with its own `id` field overwrote the key. travel-sample's airlines have `{"id": 10}` under the
key `airline_10`, so every fixture recorded `10`, and popping the field out as the key also
stripped it from the body. The aliases are now `__fixture_meta_id` and `__fixture_meta_exp`, and
`_export` refuses a row where a collision would still happen instead of preferring one.

**Key-range pagination, not `OFFSET`.** `OFFSET` re-scans on every page, degrades quadratically
and is unstable if anything changes mid-export. Ordering by `META().id` and carrying the last key
is stable, and a failed export can resume from it.

**Fixtures are confined to one directory.** `CB_ADMIN_FIXTURE_ROOT` bounds every path a fixture
tool reads or writes. `resolve_under_root` resolves symlinks before the containment test, since a
check on the literal string followed by an open of the resolved path is one a symlink walks
through. A path argument on a tool that writes files is the sensitive part of the whole family.

**Import is destructive and says so.** Both imports are annotated destructive, so the server's
confirmation gate applies (`docs/design/authorization.md`). The Enterprise Edition schema also
requires `confirm`. The Capella import checks the project allowlist, then fetches the live target
cluster and refuses one that lacks `CAPELLA_ENV_NAME_PREFIX` or is in
`CAPELLA_PROTECTED_CLUSTERS`, then checks the name prefix of any bucket it would create. It
refuses a malformed `keyspace_map` before importing anything. The cluster check was added on
2026-11-09 (Q-008, Chris Ahrendt): before it, an import could overwrite documents on a protected
or hand-made cluster in an allowlisted project. It fails closed, so a cluster response that is
not an object with a name is a refusal, the same rule as `_fetch_cluster`.

**Two refusals on Enterprise Edition, both about not making capacity decisions on someone else's
cluster as a side effect.** Export will not create an index. A collection with none cannot be read
by SQL++, so export says so and gives the statement to run, because building an index is a
capacity decision. Import will not create a bucket, because a bucket is a memory-quota decision.
It will create scopes and collections, which cost nothing to hold.

**Import reports ready only when the indexes are online.** Indexes are created deferred, then
built, then polled. An index that exists but is not online makes the cluster look slow in a way
that reads as a Couchbase problem.

**A listing never hides a broken fixture.** `list` reports a manifest that will not parse instead
of skipping it. A listing that quietly omits one answers "what do I have" with a confident lie.

**Each plane's tools are loaded only on that plane.** Measured on 2026-09-14 by loading the
registry with `CB_DEPLOYMENT` pinned: the self-managed profile loaded no fixture tools under the
Capella name and the Capella profile loaded only the four `capella_fixture_*` tools. That measured
the gating logic, not the shipped container image.

## What went wrong before

- **187 of 188 keys were wrong and every check passed.** The metadata-alias defect above was
  invisible to per-file hashes, line counts and `capella_fixture_verify`'s `COUNT(*)`, because each
  compares a fixture against itself. Only export, import elsewhere, export back, compare found it
  (2026-09-14). `scripts/fixture_round_trip.py` is that check, and the lesson is that no check
  that compares a fixture only to itself can be the last one.
- **The first Enterprise Edition round trip passed on its documents and still found four defects
  in the index step.** A Search index was rendered as a `CREATE INDEX`. Index definitions covered
  the whole bucket instead of the exported keyspaces. `keyspace_map` rewrote only the bucket, so
  mapping `inventory.airline` to `roundtrip.airline` in the same bucket changed nothing and the
  indexes were built on the source collection while the import reported `ok`. `defer_build` was
  skipped for exactly the indexes that carry a `WITH` clause. `docs/FIXTURE_DESIGN.md` records
  each and says each is pinned in `tests/test_ee_fixture.py`.

## Where it is tested

| Property | Test |
| --- | --- |
| The shared module imports only the standard library, names no plane, and each plane uses it | `tests/test_fixture_core_is_plane_neutral.py` |
| The round trip catches the key-corruption defect and names its cause; a lost document, a changed body and a changed expiry are reported separately; an empty export refuses | `tests/test_fixture_round_trip.py` |
| The comparison logic | `tests/test_fixture_round_trip_compare.py` |
| Import creates only what the data needs, never a bucket; reports a failed scope or collection | `tests/test_ee_fixture_import.py` |
| Export, list, and the index and eventing steps | `tests/test_ee_fixture_export_and_list.py`, `tests/test_ee_fixture_index_and_eventing.py` |
| Capella verify, import flow, transport | `tests/test_capella_fixture_verify.py`, `tests/test_capella_fixture_import_flow.py`, `tests/test_capella_fixture_transport.py` |
| The import refuses an unprefixed, a protected and an unreadable target cluster, and writes nothing | `tests/test_capella_fixture_import_flow.py` (`test_a_cluster_without_the_name_prefix_is_refused` and the four after it) |
| A real cluster | `scripts/fixture_round_trip.py --perform`, by hand. Last recorded clean: 187 documents on a local 7.6 cluster, 2026-09-14 |

## Before you change it

- A change to the manifest, the hash, the aliases or the index rewrites goes in `fixture_core.py`
  and nowhere else, then both planes are re-round-tripped with `scripts/fixture_round_trip.py`.
  Unit tests passing is not enough here. That is what the first defect proved.
- Do not add a plane name or a network call to `fixture_core.py`. The test fails it.
- Do not let a fixture tool take a path that does not go through `resolve_under_root`.
- GAP: only the Capella import ownership check is mutation-checked (round 6). The shared
  `fixture_core.py` and the Enterprise Edition fixture module have no mutation, and no round trip
  has been recorded since 2026-09-14.
- Keep the ownership check in `capella_fixture_import` ahead of every write. Three mutations in
  `scripts/mutation_round_6.py` break it.
- Record a change to what a fixture preserves in `docs/design-decisions.md`. Chris Ahrendt
  decides it.
