"""
Shared pytest fixtures.

The Capella guardrails keep one piece of deliberate PROCESS-GLOBAL state: a short
memo of a recent environment-ceiling refusal, so a looping agent cannot re-trigger
a multi-project paginated listing on every rejected retry. That is correct for a
long-running server, where the ceiling is genuinely global, but in a test session
it leaks across tests — one test that legitimately hits the ceiling would make
every later test in the run see a refusal it never asked for.

Reset it around every test. This is also the honest place to note the tradeoff:
the memo is global rather than per-project because the ceiling it protects is
global.
"""

from __future__ import annotations

import os
import pathlib

import pytest


@pytest.fixture(autouse=True)
def _reset_capella_guardrail_state():
    from handlers.capella import guardrails

    guardrails.reset_ceiling_memo()
    yield
    guardrails.reset_ceiling_memo()


@pytest.fixture(autouse=True)
def _restore_environ():
    """Snapshot and restore os.environ around every test.

    ``profile_config.apply_profile()`` sets environment variables directly — that
    is its job, since it supplies defaults that later imports read. But direct
    assignment is invisible to ``monkeypatch``, so a test exercising the workstation
    profile left CB_ADMIN_HTTP_REQUIRE_AUTH=false (and several others) set for
    everything that ran afterwards. The suite passed in file order and failed under
    ``-p randomly``, which is the signature of exactly this kind of leak and the
    reason the random-order run is worth keeping in CI.
    """
    snapshot = dict(os.environ)
    for name in AMBIENT_CREDENTIALS:
        os.environ.pop(name, None)
    yield
    os.environ.clear()
    os.environ.update(snapshot)


#: Variables a developer with working Capella credentials has EXPORTED, and which
#: unit tests must not see.
#:
#: Seven tests in this suite passed in CI and failed on the machine of the person
#: who had just used the tools for real. ``verify_capella_paths.py`` defaults its
#: ``--org`` argument from CB_CAPELLA_ORG_ID and reads CB_CAPELLA_API_KEY at call
#: time; ``verify_mcp_surface.py`` reads CAPELLA_ORG_ID and CB_BUCKET. Tests that
#: assert on the org-DISCOVERY path -- "no organization visible names the likely
#: cause", "several visible organizations refuse to guess" -- can only exercise it
#: when no organization is supplied, so an exported one silently converted them
#: into tests of a different branch, and the failure named a real org id, which
#: reads like a fixture bug rather than a leak.
#:
#: Removed before every test rather than fixed test by test: a test that wants one
#: of these sets it with monkeypatch, which runs after this fixture and therefore
#: still wins. Deliberately NOT including CB_CONNECTION_STRING, CB_USERNAME or
#: CB_PASSWORD -- nothing has been observed leaking through those, and clearing
#: them on no evidence is the kind of change that turns a green suite red for a
#: reason nobody can reconstruct later.
#: CB_ADMIN_CATALOG_ROOT is not a credential and it is here for a related reason:
#: it is a WRITE DESTINATION an operator exports for their own use, and
#: test_handler_contract calls every tool in every group with synthesised
#: arguments. On 2026-09-14 that wrote two real backup-catalogue entries into the
#: working tree -- backup_id "sample", the value that harness invents for a string
#: field. handlers/backup_catalog.py now refuses a write with no configured root,
#: which stops it when the variable is UNSET; it cannot stop it when a developer
#: has exported one, and "the suite writes files on your machine but not in CI" is
#: exactly the class of difference the block above exists to remove.
AMBIENT_CREDENTIALS = (
    "CAPELLA_ORG_ID",
    "CAPELLA_API_KEY_SECRET",
    "CAPELLA_ACCESS_KEY_ID",
    "CB_CAPELLA_ORG_ID",
    "CB_CAPELLA_API_KEY",
    "CB_CAPELLA_API_URL",
    "CB_BUCKET",
    "CB_ADMIN_CATALOG_ROOT",
)


# ── Shared, PRUNING repository walk ──────────────────────────────────────────
#
# Several documentation tests need "every file in the repository". The obvious
# `ROOT.rglob("*")` cannot prune, so it enumerates .git (2.4 MB) and the vendored console
# runtime (3.0 MB) in full before any filter runs. Three tests doing that made themselves
# the slowest in the suite — 21 seconds between them — and a slow suite is one people stop
# running, which costs more than the checks are worth.

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Directories with nothing a documentation check needs to read.
PRUNED_DIRS = frozenset(
    {
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        ".mypy_cache",
        "vendor",  # third-party bundles; nothing in them refers to this project
    }
)


@pytest.fixture(scope="session")
def repo_files():
    """Session fixture exposing `_repo_files`.

    A fixture rather than a plain import: `from conftest import ...` is not valid from a
    test module (conftest is not on the import path under that name), and a session scope
    means the walk is shared rather than repeated per test.
    """
    return _repo_files


def _repo_files(*suffixes: str) -> list[pathlib.Path]:
    """Every tracked-ish file under the repository root, pruning noise directories.

    `suffixes` filters by extension (with the dot, case-insensitive); omit it for all
    files. os.walk is used rather than rglob specifically because it allows pruning the
    directory list in place, which rglob does not.
    """
    wanted = {s.lower() for s in suffixes}
    found: list[pathlib.Path] = []
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in PRUNED_DIRS]
        for filename in filenames:
            path = pathlib.Path(dirpath) / filename
            if not wanted or path.suffix.lower() in wanted:
                found.append(path)
    return found
