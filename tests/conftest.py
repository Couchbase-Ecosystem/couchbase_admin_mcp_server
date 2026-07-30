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
    yield
    os.environ.clear()
    os.environ.update(snapshot)


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
