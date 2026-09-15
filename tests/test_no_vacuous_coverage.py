"""Tests that pass while asserting nothing, and how this suite stops shipping them.

THE FAILURE MODE
================
Three separate times in this repository a test reported success while checking
nothing, and each took a live incident or a full-suite triage to notice:

  * `test_a_failed_registry_crosscheck_is_reported_rather_than_swallowed` asserted
    a cross-check FAILED, and got that result because the registry happened not to
    be importable from the directory it ran in. When it became importable the
    cross-check started passing and the test started failing -- it had been an
    assertion about the wrong branch for months.
  * Five org-discovery tests in `test_verify_capella_paths.py` exercised the
    "no organization supplied" path. A developer with CB_CAPELLA_ORG_ID exported
    silently moved them onto the other branch.
  * `test_gating_still_comes_first` skipped itself whenever `detect_mode()`
    inferred `capella`, which is what it infers on any machine with a Capella key
    and no connection string -- so the gating-before-dry-run property went
    unchecked on exactly the machines where someone was most likely to change it.

The common shape is not a bug in any of those tests. It is that a test whose
subject is a COLLECTION reports the same green tick whether the collection holds
two hundred items or none, and pytest reports an empty `parametrize` as a skip
that reads exactly like a platform skip.

`test_handler_contract.py` already solved this for itself, with
`test_there_is_something_to_test` and `test_the_module_list_matches_what_the_
package_exposes`. This module makes that pattern mandatory instead of exemplary.
"""

from __future__ import annotations

import ast
import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = HERE.parent

#: Collections that may legitimately be empty, and why.
#:
#: An entry here is a CLAIM that emptiness is a success state, so each one needs a
#: companion test proving the collection is empty for the stated reason rather
#: than because an import failed or a filter went wrong. `PENDING_OPS` has
#: `test_the_parked_registry_is_empty_by_success_not_by_accident` below.
MAY_BE_EMPTY = {
    "PENDING_OPS": (
        "the parking lot empties as parked operations are promoted into spec.py; "
        "empty is the finished state, not a broken one"
    ),
}


def _test_modules() -> list[pathlib.Path]:
    return sorted(
        p for p in HERE.glob("test_*.py") if p.name != pathlib.Path(__file__).name
    )


def _guarded_names(tree: ast.AST) -> set[str]:
    """Every name that appears inside an `assert` somewhere in this module.

    Deliberately permissive about SHAPE, because the guards already in the suite
    take several forms -- `assert OPS`, `assert len(ALL_TOOLS) > 100`,
    `assert on_disk == set(MODULE_NAMES)` -- and pinning one would make this
    check about style rather than substance. It is not permissive about
    SUBSTANCE: a test that loops `for op in OPS` and asserts on `op` never
    mentions `OPS` inside an assert, so it is still reported.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Name):
                names.add(inner.id)
            elif isinstance(inner, ast.Attribute):
                names.add(inner.attr)
    return names


def _bound_to_a_literal(function: ast.AST, name: str) -> bool:
    """Is `name` assigned a non-empty literal inside this function?

    Only list/tuple/set/dict displays with at least one element count. A name
    assigned `[]` is exactly the case worth reporting, and one assigned from a
    call or an import is opaque here and stays reportable.
    """
    for node in ast.walk(function):
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if name not in targets:
            continue
        value = node.value
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)) and value.elts:
            return True
        if isinstance(value, ast.Dict) and value.keys:
            return True
    return False


def test_every_parametrised_collection_is_guarded_against_being_empty():
    """An empty `parametrize` is reported as a SKIP, next to the platform skips.

    So a registry that silently came back empty looks identical to a test that
    needs Developer Mode, in a list nobody reads closely. Requiring a guard in the
    same module makes the difference loud.
    """
    missing: list[str] = []
    for path in _test_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        guarded = _guarded_names(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                if "parametrize" not in ast.dump(decorator.func):
                    continue
                if len(decorator.args) < 2:
                    continue
                argument = decorator.args[1]
                if not isinstance(argument, (ast.Name, ast.Attribute)):
                    continue  # a literal list cannot surprise anyone
                name = argument.id if isinstance(argument, ast.Name) else argument.attr
                if name in MAY_BE_EMPTY:
                    continue
                if name not in guarded:
                    missing.append(f"{path.name}:{node.lineno} {node.name} <- {name}")

    assert not missing, (
        "these tests parametrise over a collection that nothing asserts is "
        "non-empty, so they report a SKIP indistinguishable from a platform skip "
        'if it ever comes back empty. Add `assert <name>, "..."` to the module '
        "(see test_handler_contract.test_there_is_something_to_test), or add the "
        "name to MAY_BE_EMPTY with a companion test proving why:\n  "
        + "\n  ".join(missing)
    )


def test_every_collection_a_test_only_loops_over_is_guarded():
    """The quieter half: a test whose assertions live ENTIRELY inside a `for`.

    An empty iterable there is not even a skip. It is a green tick.
    """
    missing: list[str] = []
    for path in _test_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        guarded = _guarded_names(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            asserts = [n for n in ast.walk(node) if isinstance(n, ast.Assert)]
            loops = [n for n in node.body if isinstance(n, ast.For)]
            if not asserts or not loops:
                continue
            inside = {
                id(n)
                for loop in loops
                for n in ast.walk(loop)
                if isinstance(n, ast.Assert)
            }
            if len(inside) != len(asserts):
                continue  # something is asserted outside the loop
            iterated = loops[0].iter
            # Literals, ranges and comprehensions are visible at the call site.
            if not isinstance(iterated, (ast.Name, ast.Attribute)):
                continue
            name = iterated.id if isinstance(iterated, ast.Name) else iterated.attr
            if name in MAY_BE_EMPTY or name in guarded:
                continue
            # A name bound to a literal a few lines up is as visible as the
            # literal itself -- `pairs = [(a, b), (c, d)]` cannot surprise
            # anyone, and demanding `assert pairs` there teaches people that the
            # guard is a formality to satisfy rather than a question to answer.
            # That is how a check like this stops being read.
            if _bound_to_a_literal(node, name):
                continue
            missing.append(
                f"{path.name}:{node.lineno} {node.name} <- for ... in {name}"
            )

    assert not missing, (
        "every assertion in these tests is inside a loop over a collection that "
        "nothing proves is non-empty, so an empty collection is a silent pass:\n  "
        + "\n  ".join(missing)
    )


def test_the_parked_registry_is_empty_by_success_not_by_accident():
    """PENDING_OPS is in MAY_BE_EMPTY. This is the price of that entry.

    Without it, `spec_pending` failing to populate and `spec_pending` having
    nothing left to hold produce the same six skips in `test_capella_pending.py`.
    """
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella import spec_pending

    assert hasattr(spec_pending, "PENDING_OPS"), (
        "spec_pending no longer exposes PENDING_OPS; the pending tests are "
        "parametrising over something that does not exist"
    )
    assert isinstance(spec_pending.PENDING_OPS, (list, tuple)), (
        f"PENDING_OPS is {type(spec_pending.PENDING_OPS).__name__}, not a sequence"
    )
    # Whatever IS parked must still be a record, not a leftover placeholder.
    for op in spec_pending.PENDING_OPS:
        assert getattr(op, "name", ""), "a parked record has no name"
        assert getattr(op, "path", ""), f"{op.name} has no path"


# ── Both surfaces ────────────────────────────────────────────────────────────
#
# The server drives two unrelated control planes: Capella's v4 API at
# cloudapi.cloud.couchbase.com, and ns_server on a self-managed Enterprise
# Edition cluster. `deployment.detect_mode()` decides which halves load, and it
# INFERS that decision from the environment when CB_DEPLOYMENT is unset.
#
# That inference is the risk these two tests exist for. A developer with a
# Capella key and no connection string gets `capella`, which unloads every
# admin_* tool -- and a suite that only ever iterates the LOADED registry then
# reports a clean run having tested one surface. Both of the following pin the
# mode explicitly rather than trusting whatever the machine happens to be
# configured for.


def test_both_surfaces_are_registered_independently_of_deployment_mode():
    """The handler packages hold both surfaces whatever the mode says.

    Imported directly rather than through `server._TOOLS`, because this is the
    question of whether the code SHIPS both, not whether this posture loads both.
    """
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    import importlib

    from handlers.capella import TOOLS as CAPELLA_TOOLS

    capella = {getattr(t, "name", "") for t in CAPELLA_TOOLS}
    assert capella, "the Capella surface registered no tools"
    assert all(n.startswith("capella_") for n in capella), sorted(
        n for n in capella if not n.startswith("capella_")
    )

    # The ns_server / Enterprise Edition side, from its own handler groups.
    ns_server: set[str] = set()
    for name in ("buckets", "cluster", "collections", "indexes", "security", "stats"):
        module = importlib.import_module(f"handlers.{name}")
        ns_server |= {getattr(t, "name", "") for t in module.TOOLS}

    assert ns_server, (
        "the Enterprise Edition surface registered no tools; every admin_* "
        "contract test would pass vacuously"
    )
    assert not (capella & ns_server), sorted(capella & ns_server)


def test_each_deployment_mode_loads_the_surfaces_it_claims():
    """Run in SUBPROCESSES, one per mode.

    `server` snapshots gating decisions at import and `handlers.shared` snapshots
    CB_ADMIN_READ_ONLY_MODE at import, so reloading them in-process leaks into
    every test that runs afterwards -- `test_dry_run` carries a fixture and a long
    comment about exactly that. A subprocess cannot leak.

    Compares NAME SETS against `deployment.CAPELLA_REACHABLE_ADMIN_TOOLS`, not
    counts. The first version of this test asserted `admin == 0` under Capella and
    failed on `admin_prometheus_targets` -- which is in that allowlist on purpose,
    with a comment explaining that Capella does expose the Prometheus service
    discovery endpoint to a database credential. Asserting against the allowlist
    means the exception has to be DECLARED to pass, so widening it silently is
    what fails here, rather than the exception that was argued for in writing.
    """
    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    import deployment

    reachable = set(deployment.CAPELLA_REACHABLE_ADMIN_TOOLS)

    loaded = {
        mode: _tool_names_under(mode) for mode in ("capella", "self_managed", "both")
    }

    # Capella: the whole capella_* family, plus EXACTLY the declared exceptions.
    capella_side = {n for n in loaded["capella"] if n.startswith("capella_")}
    admin_side = {n for n in loaded["capella"] if n.startswith("admin_")}
    assert capella_side, "CB_DEPLOYMENT=capella loaded no Capella tools"
    assert admin_side == reachable, (
        "the admin_* tools loaded under Capella do not match "
        "deployment.CAPELLA_REACHABLE_ADMIN_TOOLS.\n"
        f"  loaded but not declared reachable: {sorted(admin_side - reachable)}\n"
        f"  declared reachable but not loaded: {sorted(reachable - admin_side)}"
    )

    # Self-managed: the Enterprise Edition surface, and no Capella control plane.
    assert not {n for n in loaded["self_managed"] if n.startswith("capella_")}, (
        "CB_DEPLOYMENT=self_managed loaded Capella control-plane tools; there is "
        "no organization, project or cloudapi for them to call"
    )
    ee = {n for n in loaded["self_managed"] if n.startswith("admin_")}
    assert ee, (
        "CB_DEPLOYMENT=self_managed loaded no admin_* tools, so the entire "
        "Enterprise Edition surface is unreachable in the posture that exists to "
        "serve it"
    )

    # Both: a superset of each, which is the property `both` promises.
    assert capella_side <= loaded["both"], sorted(capella_side - loaded["both"])
    assert ee <= loaded["both"], sorted(ee - loaded["both"])


def _tool_names_under(mode: str) -> set[str]:
    """Every tool name `server` loads with CB_DEPLOYMENT pinned to `mode`."""
    probe = (
        "import json, os, sys;"
        "sys.path.insert(0, os.getcwd());"
        "import server;"
        "print(json.dumps([getattr(t,'name','') for t in server._TOOLS]))"
    )
    env = {
        **os.environ,
        "CB_DEPLOYMENT": mode,
        "CB_ADMIN_PROFILE": "workstation",
        "CB_ADMIN_LOG_SINKS": "stderr",
    }
    # The inference inputs must not reach the child. CB_DEPLOYMENT wins over them
    # today; if that precedence is ever changed, this test should fail rather than
    # quietly go back to measuring whatever the developer's shell is configured for.
    for leaked in ("CAPELLA_API_KEY_SECRET", "CB_CONNECTION_STRING"):
        env.pop(leaked, None)

    result = subprocess.run(
        [sys.executable, "-c", probe],
        check=False,
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    import json

    return set(json.loads(result.stdout.strip().splitlines()[-1]))
