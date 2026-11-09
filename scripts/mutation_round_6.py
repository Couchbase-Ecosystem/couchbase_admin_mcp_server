"""Mutation-check the Capella sandbox: the guardrail policy, the ownership check, the fixture import.

Component: mutation check of the Capella guardrails (`handlers/capella/guardrails.py`, the
    ownership check in `handlers/capella/__init__.py`) and of the ownership check in the Capella
    fixture import, in a temporary copy of the repository.
Spec: docs/spec.md S8 (Capella operations) and S9 (fixtures); docs/questions.md Q-008.
Main items: `main`.
Callers: none; run by hand from the repository root; see scripts/README.md
Callees: none

Same contract as rounds 1-5: break one guard, run the suite that is supposed to notice, and
report anything that stays green. Rounds 1-5 broke 7 guards in `client.py` and 5 in
`environment.py` and none in the sandbox itself, which is the code that decides whether a
destructive call is allowed at all. This round does.

NOT covered, and why: the transport refusals in `server.py` (a non-loopback bind without
authentication, and `TransportSecuritySettings`). No test exercises them, so a mutation there
would survive. The test comes first; see docs/design/transports.md.
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
GUARD = "tests/test_capella.py tests/test_capella_guardrail_hardening.py"
WRITE_TARGET = (
    "tests/test_guarded_write_target.py tests/test_capella_guardrail_hardening.py"
)
OWNERSHIP = "tests/test_capella_ownership_marker_guard.py"
IMPORT_FLOW = "tests/test_capella_fixture_import_flow.py"
GP = "handlers/capella/guardrails.py"
CI = "handlers/capella/__init__.py"
FX = "handlers/capella/fixture.py"

MUTATIONS = [
    (
        "policy: destructive work allowed with no project allowlist (fails open)",
        GP,
        "        return bool(self.allowed_projects) or self.allow_unscoped_destructive",
        "        return True",
        GUARD,
    ),
    (
        "policy: the protected list is compared with case (a spelling difference unprotects)",
        GP,
        "    protected = {p.strip().casefold() for p in policy.protected_clusters if p.strip()}",
        "    protected = {p.strip() for p in policy.protected_clusters if p.strip()}",
        GUARD,
    ),
    (
        "policy: the protected list matches names only, not ids",
        GP,
        "    if (rid and rid.casefold() in protected) or (name and name.casefold() in protected):",
        "    if name and name.casefold() in protected:",
        GUARD,
    ),
    (
        "policy: the protected list matches ids only, not names",
        GP,
        "    if (rid and rid.casefold() in protected) or (name and name.casefold() in protected):",
        "    if rid and rid.casefold() in protected:",
        GUARD,
    ),
    (
        "policy: a live cluster without the name prefix is accepted as managed",
        GP,
        '    if policy.name_prefix and not name.startswith(policy.name_prefix):\n        raise GuardrailError(\n            f"Refusing to {verb}',
        '    if False:\n        raise GuardrailError(\n            f"Refusing to {verb}',
        GUARD,
    ),
    (
        "policy: the environment ceiling is off by one (allows one more than set)",
        GP,
        "    if current_count >= policy.max_environments:",
        "    if current_count > policy.max_environments:",
        GUARD,
    ),
    (
        "ownership: an unusable cluster response skips the check instead of refusing",
        CI,
        '    if not isinstance(cluster, dict) or not cluster.get("name"):\n        raise guardrails.GuardrailError(\n            "Could not establish',
        '    if False:\n        raise guardrails.GuardrailError(\n            "Could not establish',
        OWNERSHIP,
    ),
    (
        "ownership: a restore is checked on its source cluster, not the one it writes",
        CI,
        '    "capella_backup_restore": ("targetClusterID",),\n',
        "",
        WRITE_TARGET,
    ),
    (
        "ownership: a replication is checked on its source cluster, not the one it writes",
        CI,
        '    "capella_replication_create": ("target", "cluster"),\n',
        "",
        WRITE_TARGET,
    ),
    (
        "ownership: a restore or replication is also checked on its source cluster",
        CI,
        '    if "cluster_id" in placeholders and name not in _WRITES_ELSEWHERE:',
        '    if "cluster_id" in placeholders:',
        WRITE_TARGET,
    ),
    (
        "fixture import: the target cluster is not checked for ownership",
        FX,
        "        g.assert_managed(\n            target_cluster,",
        "        (lambda *a, **k: None)(\n            target_cluster,",
        IMPORT_FLOW,
    ),
    (
        "fixture import: an unusable cluster response is skipped instead of refused",
        FX,
        '    if not isinstance(target_cluster, dict) or not target_cluster.get("name"):',
        "    if False:",
        IMPORT_FLOW,
    ),
    (
        "fixture import: a failed cluster lookup is ignored instead of stopping the import",
        FX,
        '    except Exception as exc:\n        return err(\n            f"could not read the target cluster',
        '    except ZeroDivisionError as exc:\n        return err(\n            f"could not read the target cluster',
        IMPORT_FLOW,
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

    Mutation-check the Capella sandbox: the guardrail policy, the ownership check and the fixture import.

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
