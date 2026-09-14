"""
handlers/backup_catalog.py — user-defined metadata for backups, on both planes.

THE PROBLEM THIS SOLVES
=======================
The requirement was for backups carrying tags, retrievable by queries like
"latest where content-publisher-version = 1.6" and "where scenario = 'Notification
Center Hurricane' and version = 1.1".

Neither plane can do it:

  * CAPELLA backups cannot be named and carry no user-defined metadata. The API
    gives you an opaque id, a bucket, a timestamp and a size. capella_backups_list
    has nothing to filter on.
  * ENTERPRISE EDITION repositories can be named, and that name is the only place
    a human-meaningful string fits. One string is not a tag set, and a naming
    convention that encodes five fields is a parser waiting to be written wrong.

So the metadata lives HERE, in a local catalogue that POINTS AT the backup rather
than containing it. The bytes stay where the plane put them; this records what
they were for.

WHAT IT IS NOT
==============
It is NOT a backup, it does not copy data, and deleting a catalogue entry does
not delete a backup. Those are deliberate: a tool that could delete a customer's
backup while claiming to tidy metadata is a tool nobody should run.

It is also NOT the fixture layer. handlers/capella/fixture.py EXPORTS data into a
portable artifact; this annotates a backup that already exists on the plane. They
share a vocabulary (tags, filtering) and nothing else, and the two are kept apart
because "restore this fixture" and "restore this backup" are different actions
with different recovery guarantees.

THE RECONCILIATION PROBLEM, STATED PLAINLY
==========================================
A catalogue of pointers goes stale the moment the plane expires a backup. An
entry whose backup no longer exists is worse than no entry: it answers "yes, you
have a backup of that scenario" when you do not.

cb_backup_catalog_sync is the answer. It reads the plane's own list and marks
every entry present, missing or unchecked. It does NOT delete stale entries --
that decision belongs to a human who can tell "expired on schedule" from "someone
deleted the wrong thing".
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import uuid
from datetime import datetime, timezone
from typing import Any

from mcp.types import Tool, ToolAnnotations

from handlers.shared import err, ok
from logging_config import get_logger

_log = get_logger("handlers.backup_catalog")

#: Bump on any breaking change to the entry shape.
CATALOG_SCHEMA = "couchbase.backup.catalog/v1"

#: Where entries live. One JSON file per entry, named by catalog_id.
#:
#: A DIRECTORY OF FILES, NOT ONE FILE. A single JSON document would mean every
#: write rewrites every entry, so a crash mid-write loses the catalogue rather
#: than one record, and two callers racing lose each other's work silently.
#: One file per entry makes a partial failure cost exactly one entry, and makes
#: the whole thing diffable in git, which is where a catalogue like this belongs.
_CATALOG_ROOT_ENV = "CB_ADMIN_CATALOG_ROOT"
_DEFAULT_CATALOG_DIR = ".backup-catalog"

_READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)
#: Writes touch LOCAL FILES ONLY -- never a cluster, never a backup. destructiveHint
#: is still true for the delete: it destroys a record someone may be relying on.
_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False)
_DELETE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True)

_TAGS = {
    "type": "object",
    "description": (
        "Free-form scenario metadata, recorded verbatim and the basis for all "
        "filtering. This is the thing neither plane can store. Example: "
        '{"scenario": "Notification Center Hurricane", "version": "1.1", '
        '"content-publisher-version": "1.6"}'
    ),
    # ACCEPTS NUMBERS AND BOOLEANS, STORES STRINGS.
    #
    # A tag value is a string by definition -- it is matched by equality and never
    # by ordering, so 1.1 and "1.1" mean the same thing and a caller should not
    # have to know which one their shell produced. `-a tags.version=1.1` parses as
    # the float 1.1 in every JSON-aware argument parser, and refusing it would be
    # refusing the obvious spelling of the value the requirement actually names
    # ("version = 1.1", "content-publisher-version = 1.6").
    #
    # So the schema accepts the three scalar types and _record coerces to string.
    # Filtering already compares with str() on both sides, which means a value
    # stored as a float would have matched anyway -- and stored inconsistently,
    # which is worse than either rule applied consistently.
    "additionalProperties": {"type": ["string", "number", "boolean"]},
}


def _string_tags(tags: Any) -> dict:
    """Tag values as strings, whatever scalar the caller's shell produced."""
    if not isinstance(tags, dict):
        return {}
    out = {}
    for key, value in tags.items():
        if isinstance(value, bool):
            out[str(key)] = "true" if value else "false"
        elif isinstance(value, float) and value.is_integer():
            # 2.0 from a shell means "2", not "2.0". json.loads produces the
            # float; storing its repr would make an exact-match filter for "2"
            # miss the entry it was written for.
            out[str(key)] = str(int(value))
        else:
            out[str(key)] = str(value)
    return out


#: Filter half of _TAGS. Same scalar union, because a value that can be stored
#: must be expressible as a query; comparison is str() on both sides either way.
_TAG_FILTER = {
    "type": "object",
    "description": "Exact tag matches, ANDed together.",
    "additionalProperties": {"type": ["string", "number", "boolean"]},
}


def _root(args: dict, *, writing: bool = False) -> pathlib.Path:
    """The catalogue directory, resolved and traversal-checked.

    A WRITE REQUIRES THE LOCATION TO BE STATED. Reads may fall back to the
    default; writes may not, and that asymmetry was earned:

    The default is a RELATIVE path, so it resolves against the working
    directory. During a pytest run that is the repository, and two entries with
    generated ids appeared in the tree on 2026-09-14:

        capella-nobucket-20260914T032629Z-d66ba9   backup_id "sample"
        capella-nobucket-20260914T033035Z-1e23ab   backup_id "sample"

    "sample" is tests/test_handler_contract.py:301 -- the value that harness
    synthesises for a string field. It calls every tool in every handler group,
    and this one wrote real files to disk each time. A unit test that leaves
    artifacts in the working tree is a handler that writes wherever it happens
    to be started.

    The container case is the serious one. There the working directory is /app,
    which is image layer, not volume: a catalogue written there is gone on the
    next restart. The whole point of this module is to hold the only record that
    a backup existed and what it was for. Losing that silently, because nobody
    said where to put it, is the worst failure it has -- and it would look like
    success every single time until someone went looking.

    So: set CB_ADMIN_CATALOG_ROOT to a mounted volume, or pass catalog_root.
    """
    explicit = (args.get("catalog_root") or "").strip() if isinstance(
        args.get("catalog_root"), str) else args.get("catalog_root")
    configured = (os.environ.get(_CATALOG_ROOT_ENV) or "").strip()
    if writing and not explicit and not configured:
        raise ValueError(
            f"refusing to write: no catalogue location is configured. The "
            f"default {_DEFAULT_CATALOG_DIR!r} is RELATIVE, so it resolves "
            f"against the working directory -- inside a container that is the "
            f"image layer, and the catalogue disappears on the next restart "
            f"without ever reporting a failure.\n"
            f"Set {_CATALOG_ROOT_ENV} to a mounted volume, or pass catalog_root. "
            f"Reads still fall back to the default, so an existing catalogue "
            f"remains listable."
        )
    raw = explicit or configured or _DEFAULT_CATALOG_DIR
    path = pathlib.Path(str(raw)).expanduser()
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"catalog_root could not be resolved: {exc}") from exc
    if ".." in pathlib.Path(str(raw)).parts:
        raise ValueError(
            f"catalog_root {raw!r} contains '..'. Give an absolute path or a "
            f"plain relative one; traversal is refused rather than normalised."
        )
    return resolved


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _entry_path(root: pathlib.Path, catalog_id: str) -> pathlib.Path:
    safe = "".join(c for c in catalog_id if c.isalnum() or c in "-_.")
    if not safe or safe != catalog_id:
        raise ValueError(
            f"catalog_id {catalog_id!r} may contain only letters, digits, "
            f"'-', '_' and '.'. It becomes a filename, and a catalog_id that "
            f"can contain a path separator is a catalog_id that can write "
            f"outside the catalogue."
        )
    return root / f"{safe}.json"


def _read_entries(root: pathlib.Path) -> tuple[list[dict], list[dict]]:
    """(entries, unreadable). An entry that will not parse is REPORTED."""
    entries: list[dict] = []
    unreadable: list[dict] = []
    if not root.is_dir():
        return entries, unreadable
    for path in sorted(root.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            unreadable.append({"file": str(path), "error": str(exc)})
            continue
        if not isinstance(payload, dict):
            unreadable.append({"file": str(path), "error": "not a JSON object"})
            continue
        payload["_file"] = str(path)
        entries.append(payload)
    return entries, unreadable


def _matches(entry: dict, args: dict) -> bool:
    tags = entry.get("tags") or {}
    if not isinstance(tags, dict):
        return False
    # Normalise the QUERY the same way the record did, so 1.6 finds "1.6" and
    # 2.0 finds "2". Comparing str(1.6) to "1.6" happens to work; comparing
    # str(2.0) to "2" does not, and that asymmetry would be invisible until a
    # caller filtered on a whole number.
    for key, value in _string_tags(args.get("match_tags") or {}).items():
        if str(tags.get(key)) != value:
            return False
    for key, value in _string_tags(args.get("exclude_tags") or {}).items():
        if str(tags.get(key)) == value:
            return False
    for field, wanted in (("plane", args.get("plane")),
                          ("cluster_id", args.get("cluster_id")),
                          ("bucket", args.get("bucket"))):
        if wanted and str(entry.get(field)) != str(wanted):
            return False
    after = _parse_timestamp(args.get("created_after"))
    before = _parse_timestamp(args.get("created_before"))
    if after or before:
        created = _parse_timestamp(entry.get("backup_created_at")
                                   or entry.get("recorded_at"))
        # An entry with no readable timestamp CANNOT satisfy a date filter.
        # Matching it would answer "what did we take last month" with something
        # of unknown age.
        if created is None:
            return False
        if after and created < after:
            return False
        if before and created > before:
            return False
    return True


TOOLS: list[Tool] = [
    Tool(
        name="cb_backup_catalog_record",
        description=(
            "Record user-defined metadata for a backup that already exists, on "
            "EITHER plane. This is the tool that answers what neither plane can: "
            "Capella backups cannot be named and carry no metadata; an EE "
            "repository name is one string, not a tag set.\n\n"
            "Records a POINTER plus tags. It does not copy data and it does not "
            "create a backup — take the backup first with capella_backup_create "
            "or admin_backup_run, then record what it was for."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "catalog_id": {
                    "type": "string",
                    "description": (
                        "Stable identifier and filename. Omit and one is "
                        "generated from the plane, bucket and timestamp."
                    ),
                },
                "plane": {
                    "type": "string",
                    "enum": ["capella", "enterprise"],
                    "description": "Which control plane holds the backup.",
                },
                "backup_id": {
                    "type": "string",
                    "description": (
                        "Capella: the opaque backup id from capella_backups_list, "
                        "e.g. '690fcea4-aeb3-4bd2-8029-b667bb43bcc2'.\n"
                        "EE: the backup's DATE STRING from admin_backup_list, e.g. "
                        "'2026-09-14T00_32_02.521030212Z'. Measured 2026-09-14: an "
                        "EE backup has no name of its own. The repository carries a "
                        "UUID `name`, and each entry in its `backups` array is "
                        "identified by `date` -- with the colons replaced by "
                        "underscores, because it is a directory on disk. So an EE "
                        "pointer is (repository_id, date) and neither half is "
                        "optional."
                    ),
                },
                "backup_type": {
                    "type": "string",
                    "description": (
                        "EE reports FULL or INCR per backup. An INCREMENTAL backup "
                        "is not independently restorable, so a catalogue entry that "
                        "does not say which it is can promise more than it holds."
                    ),
                },
                "size_bytes": {"type": "integer"},
                "repository_id": {
                    "type": "string",
                    "description": "EE only: the backup repository holding it.",
                },
                "cluster_id": {"type": "string"},
                "bucket": {"type": "string"},
                "backup_created_at": {
                    "type": "string",
                    "description": (
                        "When the BACKUP was taken, ISO-8601. Distinct from when "
                        "this record was written; filtering uses this one."
                    ),
                },
                "tags": _TAGS,
                "notes": {"type": "string"},
                "catalog_root": {"type": "string"},
            },
            "required": ["plane", "backup_id"],
        },
        annotations=_WRITE,
    ),
    Tool(
        name="cb_backup_catalog_list",
        description=(
            "List and filter catalogued backups by tag, plane, cluster, bucket "
            "and date. 'latest where content-publisher-version = 1.6' is "
            "match_tags plus latest_only. Local filesystem only."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                # THE FILTER MUST ACCEPT WHAT THE RECORD ACCEPTS. These two
                # declared `string` while the record schema took string, number or
                # boolean, so `-a match_tags.content-publisher-version=1.6` --
                # the requirement's own example query -- was refused with
                # "1.6 is not of type 'string'" against entries that had been
                # stored happily. A filter stricter than the field it filters is
                # a filter that cannot find what was written.
                "match_tags": _TAG_FILTER,
                "exclude_tags": _TAG_FILTER,
                "plane": {"type": "string", "enum": ["capella", "enterprise"]},
                "cluster_id": {"type": "string"},
                "bucket": {"type": "string"},
                "created_after": {"type": "string"},
                "created_before": {"type": "string"},
                "latest_only": {"type": "boolean"},
                "catalog_root": {"type": "string"},
            },
        },
        annotations=_READ,
    ),
    Tool(
        name="cb_backup_catalog_get",
        description="Fetch one catalogue entry by catalog_id.",
        inputSchema={
            "type": "object",
            "properties": {
                "catalog_id": {"type": "string"},
                "catalog_root": {"type": "string"},
            },
            "required": ["catalog_id"],
        },
        annotations=_READ,
    ),
    Tool(
        name="cb_backup_catalog_update",
        description=(
            "Change the tags or notes on an existing entry. Tags are MERGED by "
            "default: pass replace_tags=true to substitute the whole set. The "
            "pointer fields (plane, backup_id, cluster) cannot be changed — an "
            "entry that points somewhere else is a different entry."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "catalog_id": {"type": "string"},
                "tags": _TAGS,
                "notes": {"type": "string"},
                "replace_tags": {"type": "boolean"},
                "catalog_root": {"type": "string"},
            },
            "required": ["catalog_id"],
        },
        annotations=_WRITE,
    ),
    Tool(
        name="cb_backup_catalog_delete",
        description=(
            "Delete a catalogue ENTRY. THIS DOES NOT DELETE THE BACKUP — the "
            "bytes stay wherever the plane put them, and this server has no way "
            "to remove them from here. Use capella_backup_cycle_delete or the "
            "EE tooling for that, deliberately and separately."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "catalog_id": {"type": "string"},
                "catalog_root": {"type": "string"},
            },
            "required": ["catalog_id"],
        },
        annotations=_DELETE,
    ),
    Tool(
        name="cb_backup_catalog_sync",
        description=(
            "Reconcile the catalogue against a list of backups the plane "
            "actually holds, and mark each entry present, missing or unchecked.\n\n"
            "Pass `backup_ids` from capella_backups_list (or admin_backup_list "
            "for EE). Entries whose backup is gone are MARKED, never deleted: "
            "'expired on schedule' and 'someone deleted the wrong thing' look "
            "identical here, and only a human can tell them apart. A catalogue "
            "that quietly tidied away the evidence would destroy the one record "
            "that a backup ever existed."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "backup_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Every backup id the plane currently reports.",
                },
                "plane": {"type": "string", "enum": ["capella", "enterprise"]},
                "cluster_id": {
                    "type": "string",
                    "description": (
                        "Limit reconciliation to one cluster. WITHOUT IT, every "
                        "entry not in backup_ids is marked missing — including "
                        "entries for other clusters whose backups were never in "
                        "the list you passed."
                    ),
                },
                "catalog_root": {"type": "string"},
            },
            "required": ["backup_ids"],
        },
        annotations=_WRITE,
    ),
]

TOOL_NAMES = frozenset(t.name for t in TOOLS)


def _record(args: dict):
    try:
        root = _root(args, writing=True)
    except ValueError as exc:
        return err(str(exc), tool="cb_backup_catalog_record")

    plane = args.get("plane")
    backup_id = str(args.get("backup_id") or "").strip()
    if not backup_id:
        return err("backup_id is required", tool="cb_backup_catalog_record")
    if plane == "enterprise" and not args.get("repository_id"):
        return err(
            "repository_id is required for plane=enterprise: an EE backup name "
            "is unique only within its repository, so a pointer without one "
            "cannot be resolved back to a backup.",
            tool="cb_backup_catalog_record",
        )

    catalog_id = str(args.get("catalog_id") or "").strip()
    if not catalog_id:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        seed = f"{plane}-{args.get('bucket') or 'nobucket'}-{stamp}"
        catalog_id = f"{seed}-{uuid.uuid4().hex[:6]}"
    try:
        path = _entry_path(root, catalog_id)
    except ValueError as exc:
        return err(str(exc), tool="cb_backup_catalog_record")
    if path.exists():
        return err(
            f"catalog_id {catalog_id!r} already exists at {path}. Use "
            f"cb_backup_catalog_update to change it; overwriting a pointer "
            f"silently is how a catalogue starts lying.",
            tool="cb_backup_catalog_record",
        )

    entry = {
        "schema": CATALOG_SCHEMA,
        "catalog_id": catalog_id,
        "plane": plane,
        "backup_id": backup_id,
        "repository_id": args.get("repository_id"),
        "cluster_id": args.get("cluster_id"),
        "bucket": args.get("bucket"),
        "backup_created_at": args.get("backup_created_at"),
        "backup_type": args.get("backup_type"),
        "size_bytes": args.get("size_bytes"),
        "recorded_at": _now(),
        "tags": _string_tags(args.get("tags")),
        "notes": args.get("notes") or "",
        "sync": {"status": "unchecked", "checked_at": None},
    }
    try:
        root.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entry, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        return err(f"could not write the entry: {exc}",
                   tool="cb_backup_catalog_record", catalog_root=str(root))
    entry["_file"] = str(path)
    return ok(entry)


def _list(args: dict):
    try:
        root = _root(args)
    except ValueError as exc:
        return err(str(exc), tool="cb_backup_catalog_list")
    for label in ("created_after", "created_before"):
        if args.get(label) and _parse_timestamp(args[label]) is None:
            return err(
                f"{label}={args[label]!r} is not an ISO-8601 timestamp. A filter "
                f"that cannot be parsed must not silently match everything.",
                tool="cb_backup_catalog_list",
            )

    entries, unreadable = _read_entries(root)
    matched = [e for e in entries if _matches(e, args)]
    matched.sort(
        key=lambda e: (_parse_timestamp(e.get("backup_created_at")
                                        or e.get("recorded_at"))
                       or datetime.min.replace(tzinfo=timezone.utc)),
        reverse=True,
    )
    if args.get("latest_only") and matched:
        matched = matched[:1]

    result: dict[str, Any] = {
        "catalog_root": str(root),
        "entries": matched,
        "matched": len(matched),
        "scanned": len(entries) + len(unreadable),
    }
    if unreadable:
        result["unreadable"] = unreadable
        result["note"] = (
            f"{len(unreadable)} catalogue file(s) could not be read or parsed. "
            f"They are listed rather than skipped: a pointer you can no longer "
            f"read is exactly the thing you need to be told about."
        )
    if not root.is_dir():
        result["note"] = (
            f"{root} does not exist yet. An empty catalogue and a missing one "
            f"look the same in the entry list, so they are distinguished here."
        )
    return ok(result)


def _get(args: dict):
    try:
        root = _root(args)
        path = _entry_path(root, str(args.get("catalog_id") or ""))
    except ValueError as exc:
        return err(str(exc), tool="cb_backup_catalog_get")
    if not path.is_file():
        return err(f"no catalogue entry {args.get('catalog_id')!r} under {root}",
                   tool="cb_backup_catalog_get")
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return err(f"entry could not be read: {exc}", tool="cb_backup_catalog_get")
    entry["_file"] = str(path)
    return ok(entry)


def _update(args: dict):
    try:
        root = _root(args, writing=True)
        path = _entry_path(root, str(args.get("catalog_id") or ""))
    except ValueError as exc:
        return err(str(exc), tool="cb_backup_catalog_update")
    if not path.is_file():
        return err(f"no catalogue entry {args.get('catalog_id')!r} under {root}",
                   tool="cb_backup_catalog_update")
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return err(f"entry could not be read: {exc}", tool="cb_backup_catalog_update")

    if args.get("tags") is not None:
        incoming = _string_tags(args["tags"])
        if args.get("replace_tags"):
            entry["tags"] = incoming
        else:
            merged = dict(entry.get("tags") or {})
            merged.update(incoming)
            entry["tags"] = merged
    if args.get("notes") is not None:
        entry["notes"] = args["notes"]
    entry["updated_at"] = _now()

    try:
        path.write_text(json.dumps(entry, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        return err(f"could not write the entry: {exc}", tool="cb_backup_catalog_update")
    entry["_file"] = str(path)
    return ok(entry)


def _delete(args: dict):
    try:
        root = _root(args, writing=True)
        path = _entry_path(root, str(args.get("catalog_id") or ""))
    except ValueError as exc:
        return err(str(exc), tool="cb_backup_catalog_delete")
    if not path.is_file():
        # Idempotent on purpose: deleting an entry that is already gone is the
        # desired end state, not an error worth failing a cleanup script over.
        return ok({"catalog_id": args.get("catalog_id"), "deleted": False,
                   "note": "no such entry; nothing to delete"})
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        entry = {}
    try:
        path.unlink()
    except OSError as exc:
        return err(f"could not delete the entry: {exc}", tool="cb_backup_catalog_delete")
    return ok({
        "catalog_id": args.get("catalog_id"),
        "deleted": True,
        "removed_entry": entry,
        "note": (
            "The catalogue ENTRY is gone. The BACKUP is untouched — this server "
            "cannot delete backup bytes from here, deliberately."
        ),
    })


def _sync(args: dict):
    try:
        root = _root(args, writing=True)
    except ValueError as exc:
        return err(str(exc), tool="cb_backup_catalog_sync")
    ids = {str(i) for i in (args.get("backup_ids") or [])}
    plane = args.get("plane")
    cluster_id = args.get("cluster_id")

    entries, unreadable = _read_entries(root)
    present, missing, skipped = [], [], []
    checked_at = _now()

    for entry in entries:
        in_scope = True
        if plane and entry.get("plane") != plane:
            in_scope = False
        if cluster_id and str(entry.get("cluster_id")) != str(cluster_id):
            in_scope = False
        if not in_scope:
            skipped.append(entry.get("catalog_id"))
            continue

        status = "present" if str(entry.get("backup_id")) in ids else "missing"
        entry["sync"] = {"status": status, "checked_at": checked_at}
        (present if status == "present" else missing).append(entry.get("catalog_id"))
        try:
            pathlib.Path(entry["_file"]).write_text(
                json.dumps({k: v for k, v in entry.items() if k != "_file"},
                           indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError as exc:
            _log.warning("catalogue entry could not be updated: %s", exc)

    result = {
        "catalog_root": str(root),
        "checked_at": checked_at,
        "present": present,
        "missing": missing,
        "out_of_scope": skipped,
        "present_count": len(present),
        "missing_count": len(missing),
    }
    if missing:
        result["note"] = (
            f"{len(missing)} entr(ies) point at a backup the plane no longer "
            f"reports. They are MARKED, not deleted: an expired backup and a "
            f"wrongly-deleted one look identical from here, and the entry is the "
            f"only surviving record that the backup ever existed. Decide "
            f"deliberately, then use cb_backup_catalog_delete."
        )
    if not ids:
        result["warning"] = (
            "backup_ids was EMPTY, so every in-scope entry is now marked "
            "missing. If that was not intended -- for example the list call "
            "failed and returned nothing -- re-run sync with the real list."
        )
    if unreadable:
        result["unreadable"] = unreadable
    return ok(result)


HANDLERS = {
    "cb_backup_catalog_record": _record,
    "cb_backup_catalog_list": _list,
    "cb_backup_catalog_get": _get,
    "cb_backup_catalog_update": _update,
    "cb_backup_catalog_delete": _delete,
    "cb_backup_catalog_sync": _sync,
}


def handle(name: str, args: dict[str, Any]):
    handler = HANDLERS.get(name)
    if handler is None:
        return err(f"Unknown backup catalog tool: {name}", tool=name)
    return handler(args or {})


__all__ = ["TOOLS", "TOOL_NAMES", "handle", "CATALOG_SCHEMA"]
