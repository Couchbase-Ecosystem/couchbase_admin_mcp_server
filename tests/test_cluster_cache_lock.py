"""The cached SDK cluster is built once, however many threads ask at the same moment.

Component: regression suite for `get_sdk_cluster` in `handlers/shared.py`.
Spec: docs/spec.md S3 step 8; docs/THREADING_MODEL.md; docs/questions.md Q-001 (decided
    2026-11-05: create the cached cluster under a lock).
Main items: `test_concurrent_first_calls_build_one_cluster`,
    `test_a_failed_build_leaves_the_cache_empty_and_the_lock_free`.
Callers: none; collected by pytest.
Callees: `tests.test_shared_helpers`; it reaches `handlers.shared` through the `sdk` fixture.

WHY THIS EXISTS
===============
Handlers run on worker threads. Before the lock, two calls arriving together before the
first connection existed could both build a Cluster, and the second assignment replaced the
first, which was never closed. The test makes the race likely rather than hoping for it: the
stub cluster sleeps while it is being built, so every thread is inside `get_sdk_cluster`
before any of them has published a result.
"""

from __future__ import annotations

import threading
import time

import pytest

from tests.test_shared_helpers import (  # noqa: F401  (fixture used by name)
    _FakeCluster,
    sdk,
)


def test_concurrent_first_calls_build_one_cluster(sdk, monkeypatch):  # noqa: F811
    """Eight threads, one build. Without the lock this builds up to eight."""
    original = _FakeCluster.__init__

    def slow_init(self, connection_string, options):
        time.sleep(0.05)  # keep every other thread inside the function meanwhile
        original(self, connection_string, options)

    monkeypatch.setattr(_FakeCluster, "__init__", slow_init)
    start = threading.Barrier(8)
    results: list[object] = []
    errors: list[BaseException] = []

    def ask() -> None:
        try:
            start.wait()
            results.append(sdk.get_sdk_cluster())
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=ask) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors, errors
    assert len(results) == 8, "a thread did not finish, so the lock may be held forever"
    assert len(_FakeCluster.instances) == 1, (
        f"{len(_FakeCluster.instances)} clusters were built; the others leaked"
    )
    assert all(r is results[0] for r in results), "threads got different clusters"


def test_a_failed_build_leaves_the_cache_empty_and_the_lock_free(sdk, monkeypatch):  # noqa: F811
    """A readiness failure must not cache a cluster or keep the lock, so the next call retries."""
    calls = {"n": 0}
    original = _FakeCluster.wait_until_ready

    def flaky(self, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("not ready yet")
        original(self, timeout)

    monkeypatch.setattr(_FakeCluster, "wait_until_ready", flaky)
    with pytest.raises(TimeoutError):
        sdk.get_sdk_cluster()
    assert sdk._cluster is None
    assert not sdk._cluster_lock.locked(), "the lock was left held after a failure"

    cluster = sdk.get_sdk_cluster()
    assert cluster is sdk._cluster
    assert calls["n"] == 2
