"""Fixture mechanics that belong to no control plane.

WHY THIS MODULE EXISTS
======================
A fixture is a named, tagged, hash-verified capture of a dataset: a manifest
plus one JSON Lines file per keyspace. Capella needs them because Capella
backups cannot be named, carry no metadata and cannot be moved between clusters
on demand. Enterprise Edition needs them for a different reason -- cbbackupmgr
answers recovery, not REPRODUCIBILITY, and "the exact dataset scenario 1.6 was
measured against" is a reproducibility question.

So there are two implementations, and `docs/FIXTURE_DESIGN.md` is explicit that
the second is not a port of the first: Capella reaches documents through the
Data API with a cluster access credential, and Enterprise Edition reaches them
through the query service and the SDK with cluster credentials. The structure
walk, the document read and the document write are genuinely different code.

WHAT IS GENUINELY SHARED IS IN HERE, AND ONLY THAT
==================================================
Everything in this module is decidable without knowing which plane a fixture
came from:

  * where a fixture may be written (CB_ADMIN_FIXTURE_ROOT, traversal refusal)
  * how a manifest is read, and how an unreadable one is REPORTED not skipped
  * the integrity check -- files present, hashes recompute, line counts agree
  * keyspace splitting, which has to handle a bucket name containing dots
  * the index-definition rewrites: dropping the source cluster's node placement
    and remapping the bucket a CREATE INDEX targets

THE POINT IS ONE IMPLEMENTATION, NOT TWO THAT AGREE TODAY
=========================================================
`fixture_integrity` was already extracted once, so that export's verify and
import's preflight ran the same check rather than two that drift. The same
argument applies across planes and with more force: a fixture captured on
Enterprise Edition and imported into Capella is a genuinely valuable thing --
capture on a laptop, import into the cloud, compare like for like -- and it is
only possible if both sides agree byte for byte on what the manifest means.

A second copy of the hash comparison is a second place for it to be subtly
wrong, and the failure would be silent: a fixture that verifies on the plane
that wrote it and nowhere else.

NOTHING HERE TOUCHES A CLUSTER OR A CONTROL PLANE. Standard library only. If a
function in this module needs an HTTP call or a credential, it is in the wrong
module.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
from datetime import datetime, timezone
from typing import Any

#: Root under which fixture paths must live, when the operator sets one.
#:
#: WHY THIS IS DEFINED HERE AND NOT IN handlers/egress.py. The export docstring
#: says to run fixture_path through "the egress walk", and that advice does not
#: survive contact with the module: handlers/egress.py guards HOSTS -- allowlists,
#: CIDRs, DNS resolution, SSRF. It has no notion of a filesystem path and nothing
#: in it can be reused here. Writing a bespoke check was the instruction's spirit
#: to avoid; having no check at all is worse. This is that check, named, in one
#: place, with the reasoning attached.
#:
#: Unset means "any absolute path", which is the correct default for a tool run
#: from a developer workstation and the wrong one for a shared container. Set it
#: in any deployment where the caller is not the operator.
FIXTURE_ROOT_ENV = "CB_ADMIN_FIXTURE_ROOT"


def resolve_under_root(raw: str, *, field: str, tool: str) -> pathlib.Path:
    """Resolve `raw` to an absolute path, refusing traversal and root escapes.

    Symlinks are resolved BEFORE the containment test, not after. A check that
    compares the literal string and then opens the resolved path is a check that
    a symlink walks straight through.
    """
    if not raw or not str(raw).strip():
        raise ValueError(f"{field} is required")
    path = pathlib.Path(str(raw)).expanduser()
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:  # RuntimeError: symlink loop
        raise ValueError(f"{field} could not be resolved: {exc}") from exc

    root = (os.environ.get(FIXTURE_ROOT_ENV) or "").strip()
    if root:
        root_resolved = pathlib.Path(root).expanduser().resolve(strict=False)
        if root_resolved not in resolved.parents and resolved != root_resolved:
            raise ValueError(
                f"{field} {resolved} is outside {FIXTURE_ROOT_ENV} "
                f"({root_resolved}). Fixtures may only be read from and written "
                f"to that subtree."
            )
    return resolved


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def count_lines(path: pathlib.Path) -> int:
    """Non-empty lines in a JSON Lines file. One line is one document."""
    count = 0
    with path.open("rb") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def parse_timestamp(value: Any) -> datetime | None:
    """An ISO-8601 timestamp, or None. Trailing Z is accepted."""
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


def read_manifest(directory: pathlib.Path) -> dict:
    """Read one fixture's manifest.json.

    A manifest that will not parse is REPORTED, never skipped. A fixture
    directory that has quietly stopped being readable is the single thing a
    caller most needs to be told about, and a listing that omits it answers
    "what fixtures do I have" with a confident lie.
    """
    manifest_path = directory / "manifest.json"
    entry: dict[str, Any] = {"fixture_path": str(directory)}
    try:
        raw = manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        entry.update(readable=False, error=f"manifest.json could not be read: {exc}")
        return entry
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        entry.update(readable=False, error=f"manifest.json is not valid JSON: {exc}")
        return entry
    if not isinstance(manifest, dict):
        entry.update(readable=False, error="manifest.json is not a JSON object")
        return entry
    entry.update(
        readable=True,
        schema=manifest.get("schema"),
        fixture_id=manifest.get("fixture_id"),
        name=manifest.get("name"),
        mode=manifest.get("mode"),
        created_at=manifest.get("created_at"),
        tags=manifest.get("tags") or {},
        document_count=manifest.get("document_count"),
        manifest=manifest,
    )
    return entry


NODES_CLAUSE = re.compile(r'"nodes"\s*:\s*\[[^\]]*\]\s*,?', re.IGNORECASE)


def strip_index_nodes(statement: str) -> tuple[str, bool]:
    """Remove a recorded CREATE INDEX's `"nodes": [...]` placement list.

    THIS IS NOT COSMETIC. A definition captured by the exporter carries the
    SOURCE cluster's index nodes by hostname:

        WITH { "defer_build":true,
               "nodes":[ "svc-qi-node-004.vn1kiibitcyvwrw.cloud.couchbase.com:18091",
                         "svc-qi-node-005.vn1kiibitcyvwrw.cloud.couchbase.com:18091" ],
               "num_replica":1 }

    Replayed verbatim onto a DIFFERENT cluster those hostnames do not exist, and
    the index either fails to create or is pinned to nodes the target does not
    have. The placement is a property of the machine the index came from, not of
    the index, so it does not travel with the fixture.

    `num_replica` is deliberately KEPT. It is a property of the index's intended
    shape, and a target that cannot satisfy it should fail loudly rather than
    quietly build a less redundant index than the fixture recorded.
    """
    stripped = NODES_CLAUSE.sub("", statement)
    if stripped == statement:
        return statement, False
    # Tidy the punctuation the removal can leave behind: "{ , x }" or "{ x, }".
    stripped = re.sub(r"\{\s*,", "{", stripped)
    stripped = re.sub(r",\s*\}", " }", stripped)
    stripped = re.sub(r",\s*,", ",", stripped)
    return stripped, True


def remap_keyspace(keyspace: str, keyspace_map: dict) -> str:
    """Apply a keyspace_map entry, exact match only."""
    return str(keyspace_map.get(keyspace) or keyspace)


def rewrite_index_keyspace(statement: str, keyspace_map: dict) -> tuple[str, str]:
    """(statement, why_not). Rewrites the bucket a CREATE INDEX targets.

    CONSERVATIVE BY DESIGN. Rewriting SQL with regular expressions is how an
    index quietly gets built against the wrong keyspace, so this only handles the
    one form the exporter actually produces -- a backticked bucket name directly
    after ON -- and REFUSES anything else rather than guessing. A refused index is
    a reported problem; an index silently built somewhere else is a corrupted
    environment that still reports success.
    """
    if not keyspace_map:
        return statement, ""
    sources = {k.split(".", 1)[0] for k in keyspace_map}
    for source in sorted(sources):
        token = f"`{source}`"
        if token not in statement:
            continue
        targets = {
            remap_keyspace(k, keyspace_map).split(".", 1)[0]
            for k in keyspace_map
            if k.split(".", 1)[0] == source
        }
        if len(targets) != 1:
            return statement, (
                f"keyspace_map rewrites bucket {source!r} to more than one "
                f"target ({sorted(targets)}), so the bucket this index belongs "
                f"to is ambiguous"
            )
        statement = statement.replace(token, f"`{targets.pop()}`")
    return statement, ""


def split_keyspace(keyspace: str) -> tuple[str, str, str] | None:
    """`bucket.scope.collection` -> its three parts, or None if it is not three.

    rsplit, NOT split. A Couchbase BUCKET NAME MAY CONTAIN DOTS -- the name
    charset allows them -- while scope and collection names may not. Splitting
    left-to-right therefore mangles a bucket called `my.bucket`; splitting from
    the right takes the last two separators, which are always the scope and
    collection ones. This is not a hypothetical: the fixture manifest stores the
    keyspace as a single joined string, so this function is the only thing
    standing between a dotted bucket name and a query against a keyspace that
    does not exist.
    """
    parts = keyspace.rsplit(".", 2)
    if len(parts) != 3 or not all(parts):
        return None
    return parts[0], parts[1], parts[2]


def fixture_integrity(directory: pathlib.Path,
                       manifest: dict) -> tuple[list[dict], list[str], str | None]:
    """(file checks, problems, payload hash) for a fixture on disk.

    EXTRACTED so that _verify and _import run the SAME check rather than two
    that agree today and drift later. The importer needs exactly this answer
    before it touches a cluster, and a second implementation of it would be a
    second place for the hash comparison to be subtly wrong.

    Every check here is decidable from the filesystem alone:
      * every data file named in the manifest exists
      * each file's sha256 recomputes to the recorded value
      * each file's line count matches the recorded document_count
      * the payload hash recomputes over the per-file hashes

    A MISMATCH IS NOT A WARNING. A fixture whose bytes have changed since it was
    written is not a fixture, it is an unlabelled dataset, and the whole point of
    the manifest is that it can say so.
    """
    problems: list[str] = []
    checks: list[dict] = []

    files = manifest.get("files")
    if files is None:
        files = []
    if not isinstance(files, list):
        problems.append("manifest 'files' is not a list")
        files = []

    file_hashes: list[str] = []
    for record in files:
        if not isinstance(record, dict):
            problems.append(f"file entry is not an object: {record!r}")
            continue
        rel = str(record.get("path") or "")
        check: dict[str, Any] = {"path": rel}
        target = directory / rel
        if not rel:
            problems.append("a file entry has no path")
            continue
        if not target.is_file():
            check.update(present=False, ok=False)
            problems.append(f"{rel} is named in the manifest and does not exist")
            checks.append(check)
            continue

        actual_hash = sha256_file(target)
        expected_hash = record.get("sha256")
        file_hashes.append(actual_hash)
        check.update(present=True, sha256=actual_hash)
        if expected_hash and actual_hash != expected_hash:
            check["ok"] = False
            problems.append(
                f"{rel} sha256 is {actual_hash}, manifest says {expected_hash} "
                f"-- the file has changed since the fixture was written"
            )
        expected_count = record.get("document_count")
        if isinstance(expected_count, int):
            actual_count = count_lines(target)
            check["document_count"] = actual_count
            if actual_count != expected_count:
                check["ok"] = False
                problems.append(
                    f"{rel} holds {actual_count} documents, manifest says "
                    f"{expected_count}"
                )
        check.setdefault("ok", True)
        checks.append(check)

    expected_payload = manifest.get("payload_sha256")
    payload_sha = hashlib.sha256(
        "".join(sorted(file_hashes)).encode()
    ).hexdigest() if file_hashes else None
    if expected_payload and payload_sha and expected_payload != payload_sha:
        problems.append(
            f"payload_sha256 is {payload_sha}, manifest says {expected_payload}"
        )
    return checks, problems, payload_sha


#: Trailing " (replica 1)" on a control-plane index definition's indexName.
#:
#: A REPLICA IS NOT A SEPARATE INDEX. capella_query_index_definitions_list
#: enumerates every replica as its own entry -- same `definition` string,
#: verbatim, with the replica number appended to `indexName`:
#:
#:     {"indexName": "sg_users_x1",              "definition": "CREATE INDEX ..."}
#:     {"indexName": "sg_users_x1 (replica 1)",  "definition": "CREATE INDEX ..."}
#:
#: system:indexes reports the base name only, so comparing the two registers
#: name-for-name reported every replica as an index that does not exist on the
#: cluster. Measured 2026-09-14 against fixtures/mcptest-data-1, whose four
#: recorded definitions are two indexes each carrying num_replica 1; the first
#: run of the cluster check called two of the four missing, which was wrong and
#: was this tool's fault rather than the cluster's.
REPLICA_SUFFIX = re.compile(r"\s*\(replica\s+\d+\)\s*$")


def base_index_name(name: str) -> str:
    """An index definition's indexName with any replica suffix removed."""
    return REPLICA_SUFFIX.sub("", name).strip()
