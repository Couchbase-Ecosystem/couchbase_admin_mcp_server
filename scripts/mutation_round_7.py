"""Mutation-check the backup catalogue: location, traversal, sync, atomic and serialised writes.

Component: mutation check of `handlers/backup_catalog.py` in a temporary copy of the repository.
Spec: docs/spec.md S9 (fixtures and the backup catalogue).
Main items: `main`.
Callers: none; run by hand from the repository root; see scripts/README.md
Callees: none

Same contract as rounds 1-6: break one guard, run the suite that is supposed to notice, and
report anything that stays green. No earlier round touched this module, which holds the only
record that a backup existed.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile


class MutationTimeoutError(RuntimeError):
    """A mutation run that neither passed nor failed. Never counted as caught."""


ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = "tests/test_backup_catalog.py"
BC = "handlers/backup_catalog.py"

MUTATIONS = [
    (
        "catalogue: a write with no stated location falls back to the default",
        BC,
        "    if writing and not explicit and not configured:",
        "    if False:",
        CATALOG,
    ),
    (
        "catalogue: a catalog_root containing .. is accepted",
        BC,
        '    if ".." in pathlib.Path(str(raw)).parts:',
        "    if False:",
        CATALOG,
    ),
    (
        "catalogue: a catalog_id that is not a plain filename is accepted",
        BC,
        "    if not safe or safe != catalog_id:",
        "    if not safe:",
        CATALOG,
    ),
    (
        "catalogue: recording over an existing entry overwrites it",
        BC,
        '    if path.exists():\n        return err(\n            f"catalog_id {catalog_id!r} already exists',
        '    if False:\n        return err(\n            f"catalog_id {catalog_id!r} already exists',
        CATALOG,
    ),
    (
        "catalogue: an Enterprise Edition entry may omit its repository",
        BC,
        '    if plane == "enterprise" and not args.get("repository_id"):',
        "    if False:",
        CATALOG,
    ),
    (
        "catalogue: an entry with no readable timestamp satisfies a date filter",
        BC,
        "        if created is None:\n            return False",
        "        if created is None:\n            return True",
        CATALOG,
    ),
    (
        "catalogue: sync deletes an entry whose backup is gone",
        BC,
        '    result = {\n        "catalog_root": str(root),\n        "checked_at": checked_at,',
        '    for _gone in missing:\n        (root / f"{_gone}.json").unlink()\n    result = {\n        "catalog_root": str(root),\n        "checked_at": checked_at,',
        CATALOG,
    ),
    (
        "catalogue: sync ignores the cluster scope",
        BC,
        '        if cluster_id and str(entry.get("cluster_id")) != str(cluster_id):',
        "        if False:",
        CATALOG,
    ),
    (
        "catalogue: an entry is written in place, so a failure can leave half of it",
        BC,
        "        temporary.write_text(",
        "        path.write_text(",
        CATALOG,
    ),
    (
        "catalogue: writes are not serialised",
        BC,
        "        with _WRITE_LOCK:\n            return handler(args or {})",
        "        return handler(args or {})",
        CATALOG,
    ),
]


def run(target: str, cwd: pathlib.Path) -> bool:
    """True when the suite passes, i.e. the mutation SURVIVED."""
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-x",
                "-q",
                "-p",
                "no:randomly",
                "-m",
                "not live",
                *target.split(),
            ],
            check=False,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=150,
        )
    except subprocess.TimeoutExpired:
        # A TIMEOUT IS NOT A KILL. `return False` here means "tests failed", which this
        # harness reports as the mutation being CAUGHT -- with no assertion having failed
        # anywhere. So any mutation that merely made the target slow enough to exceed the
        # timeout was recorded as covered by a test. That is the harness telling the
        # comfortable story, in the one tool whose entire job is to say which controls
        # are untested. Raised so the run fails loudly instead.
        raise MutationTimeoutError(
            f"pytest timed out on {target}; this mutation is NOT proven caught. "
            "Re-run with a longer timeout before trusting the result."
        ) from None
    return result.returncode == 0


def main(argv: list[str] | None = None) -> int:
    """Run every mutation in this round and report which ones the test suite caught.

    Mutation-check the backup catalogue.

    `--list` prints each mutation and runs nothing; `--help` prints usage. With no option
    it runs the whole round.

    Args:
        argv: The command line without the program name; `None` reads `sys.argv`.

    Returns:
        The process exit code.
    """
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print each mutation (label, file, test that should notice) and run nothing",
    )
    args = parser.parse_args(argv)
    if args.list:
        for label, relpath, _old, _new, target in MUTATIONS:
            print(f"{label}  [{relpath}; caught by {target}]")
        print(f"{len(MUTATIONS)} mutations. Nothing was run.")
        return 0

    survivors = []
    for label, relpath, old, new, target in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp) / "cb"
            shutil.copytree(
                ROOT,
                work,
                ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".git"),
            )
            # `old`/`new` may each be a LIST, applying several edits as ONE mutation.
            #
            # Needed for LAYERED guards. The symlink protection in logging_config is both an
            # `islink` check and `O_NOFOLLOW` on the open; removing either alone leaves the
            # outcome identical, because the other still refuses. A single-edit mutation
            # therefore "survives" while the guard is perfectly well tested — the mutation is
            # the thing at fault, not the test. Removing both together is the edit that
            # actually changes behaviour, and it is caught.
            edits = (
                list(zip(old, new, strict=False))
                if isinstance(old, list)
                else [(old, new)]
            )
            path = work / relpath
            # UTF-8 explicitly. Bare read_text() uses the locale code page, which is
            # cp1252 on Windows: every anchor containing an em-dash then matched zero
            # times and reported ANCHOR-GONE there while matching once in CI. Measured
            # 2026-09-29 -- five of them.
            text = path.read_text(encoding="utf-8")
            missing = [o for o, _ in edits if o not in text]
            if missing:
                # Not a pass. An anchor that no longer matches means this mutation tested
                # nothing, and the guard it was written for is now unverified.
                print(f"  ANCHOR-GONE  {label} ({relpath})", flush=True)
                survivors.append((label, "anchor not found"))
                continue
            orig_counts = {o: text.count(o) for o, _ in edits}
            for one_old, one_new in edits:
                text = text.replace(one_old, one_new, 1)
            path.write_text(text, encoding="utf-8")
            # How many times each anchor occurs, against how many times the mutant lists
            # it. A mismatch is often deliberate -- "mutate any inputSchema" is served by
            # the first of seven -- so it is not a failure on its own. It matters when the
            # mutant SURVIVES, because then the edit may have landed on a different site
            # from the one the label describes: on 2026-09-29 the 404 mutant disabled the
            # first of two `if status == 404:` branches and survived for exactly that reason.
            listed = {o: sum(1 for x, _ in edits if x == o) for o, _ in edits}
            if run(target, work):
                print(f"  SURVIVED     {label}", flush=True)
                drift = [
                    f"{o[:40]!r} found {orig_counts[o]}x, listed {k}x"
                    for o, k in listed.items()
                    if orig_counts[o] != k
                ]
                why = "no test caught it"
                if drift:
                    why += (
                        " -- ANCHOR COUNT MISMATCH, the edit may have hit the wrong site: "
                        + "; ".join(drift)
                    )
                survivors.append((label, why))
            else:
                print(f"  caught       {label}", flush=True)

    print(flush=True)
    if survivors:
        print(f"{len(survivors)} of {len(MUTATIONS)} NOT CAUGHT:")
        for label, why in survivors:
            print(f"  - {label}  [{why}]")
        return 1
    print(f"All {len(MUTATIONS)} mutations caught.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
