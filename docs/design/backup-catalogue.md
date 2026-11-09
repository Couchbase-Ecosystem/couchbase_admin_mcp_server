# The backup catalogue: tags for backups that neither plane can tag

**Source:** `handlers/backup_catalog.py` (six tools, `cb_backup_catalog_*`).
**Spec:** `docs/spec.md` S9 (fixtures and the backup catalogue).
**Configuration:** `CB_ADMIN_CATALOG_ROOT`, or the `catalog_root` argument on any of the tools.
**Related:** `docs/design/fixtures.md`. The two share a vocabulary (tags, filtering) and nothing
else.

## What it decides

A backup needs to be found by what it was for: "the latest backup where
`content-publisher-version` is 1.6", or "where `scenario` is a named scenario and `version` is 1.1".
Neither plane can answer that. A Capella backup has an opaque id, a bucket, a timestamp and a size,
and cannot be named or tagged. An Enterprise Edition repository can be named, but one string is
not a tag set, and a naming convention that packs five fields into it needs a parser that will be
written wrong.

So the metadata lives here, in a local catalogue of pointers. An entry points at a backup and says
what it was for. It does not contain the backup, copy any data, or reach a cluster. Six tools:
record, list, get, update, delete and sync.

## Why it is built this way

**One JSON file per entry, in a directory.** A single document would be rewritten by every write,
so a crash mid-write would lose the whole catalogue and two callers racing would lose each other's
work silently. With one file per entry a partial failure costs one entry, and the directory diffs
cleanly in git, which is where a catalogue worth keeping belongs. The default `.backup-catalog/` is
ignored by `.gitignore` as scratch. Set `CB_ADMIN_CATALOG_ROOT` to a real directory to commit one.

**A write refuses to run until the location is stated.** Reads fall back to `.backup-catalog/`;
writes do not. The default is a relative path, so it resolves against the working directory. In a
container that is the image layer, and a catalogue written there is gone on the next restart with
no error, which is the worst failure this module has, because the catalogue is the only record that
a backup existed. The refusal was also earned in the test run: the contract harness calls every tool
with the value `"sample"`, and two real entries appeared in the repository tree on 2026-09-14.

**An entry is a pointer, and deleting it never touches a backup.** The tools never delete backup
bytes, and the delete result says so. A tool that could delete a customer's backup while claiming to
tidy metadata is one nobody should run.

**Sync marks entries and never deletes them.** A catalogue of pointers goes stale when the plane
expires a backup, and an entry for a backup that is gone answers "yes, you have that" when you do
not. `cb_backup_catalog_sync` takes the ids the plane reports and marks each in-scope entry
`present` or `missing`. It does not delete a missing one, because "expired on schedule" and
"someone deleted the wrong thing" look the same from here and only a person can tell them apart.
The entry may be the only surviving record that the backup existed.

**Sync takes the plane's list from the caller.** The tool does not call the plane. The caller passes
`backup_ids` from `capella_backups_list` or `admin_backup_list`. An empty list marks every in-scope
entry missing, and the result carries a warning saying so, because a list call that failed and
returned nothing looks the same. Without `cluster_id` or `plane`, entries for other clusters are
marked missing too.

**Tag values are strings, whatever the shell produced.** `-a tags.version=1.1` arrives as the float
1.1. The schema accepts strings, numbers and booleans, and the entry stores strings. Filters
normalize the query the same way, so `1.6` finds `"1.6"` and `2.0` finds `"2"`.

**An Enterprise Edition entry must name its repository.** A backup name is unique only within its
repository, so a pointer without one cannot be resolved.

**A filter that cannot be understood is an error.** An unparseable `created_after` is refused rather
than ignored, since an ignored filter matches everything. An entry with no readable timestamp cannot
satisfy a date filter, since matching it would answer "what did we take last month" with something
of unknown age.

**Listing never hides a broken entry.** A file that will not parse is reported under `unreadable`,
and a missing directory is reported as missing, not as an empty catalogue.

**A catalogue id becomes a filename, so it is checked.** Only letters, digits, `-`, `_` and `.` are
accepted, and a `catalog_root` containing `..` is refused, not normalized.

## What went wrong before

- **Test runs wrote into the repository tree** (2026-09-14), described above. The fix was to make
  writes require a stated location.

## Where it is tested

| Property | Test |
| --- | --- |
| A write is refused with no location; a read falls back; `..` is refused on every tool | `tests/test_backup_catalog.py` (`test_a_write_is_refused_when_no_location_is_configured`, `test_a_read_still_falls_back_to_the_default`, `test_every_read_and_write_tool_refuses_a_traversing_root`) |
| Tag values and filters: whole numbers, exclusion, scalar fields | same file |
| Date filters, newest first, `latest_only`, an unparseable date is refused | same file |
| An unreadable entry or a missing directory is reported | same file |
| Update merges or replaces tags; delete is idempotent and says the backup is untouched | same file |
| Sync marks and never deletes; an empty list warns; scope by plane and cluster | same file |
| A failed write, update, delete or sync write is reported, not hidden | same file |

## Before you change it

- Never let a catalogue tool delete or change a backup, or call a plane.
- Never make a write fall back to a default location.
- Never make sync delete an entry.
- Bump `CATALOG_SCHEMA` on a breaking change to the entry shape.
- GAP: `CB_ADMIN_CATALOG_ROOT` is named in no README, Dockerfile or deploy file (searched on
  2026-11-09), so an operator finds it only by hitting the refusal. A container deployment must
  mount a volume and set it.
- GAP: no mutation breaks a guard in this module (`scripts/mutation_*.py`, searched 2026-11-09).
- GAP: an entry is read, changed and rewritten with no lock and no atomic replace, so two calls that
  update the same entry at once can lose one of the changes. A crash during a rewrite can truncate
  that one file. Not reproduced, read from the code.
- Chris Ahrendt decides the behavior. Record a change in `docs/design-decisions.md`.
