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
