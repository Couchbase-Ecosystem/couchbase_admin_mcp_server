"""Parking and resuming an environment, and the reaper's refusal to overclaim.

Every assertion here is about a DOMAIN CODE rather than a message, because that
distinction has already cost real money in this project.

Capella answers 7011 for "already off" and 7010 for "already on", and both are
idempotent successes a reconciler should absorb. The code used to be matched with
`"7011" in str(exc)` -- which also matched the HTTP status, the path's cluster and
project UUIDs and the request id. So ANY failure whose rendered text happened to
contain those four digits, including a 500 or a 503, was reported as

    billing: stopped

for a cluster that was still running and still billing. The parsed code is the
only thing that distinguishes the two, and these tests drive both directions:
the real 7011, and a failure that merely contains the digits.

The reaper has the same shape one level up. A teardown that returns
"nothing_to_do" or "not_found" deleted nothing, and counting it as reaped shows
on an operator's dashboard as a successful collection of a cluster that may still
exist. It is reported as REFUSED instead, with the instruction to verify by hand.
"""

from __future__ import annotations

import pytest

from handlers.capella import environment as env
from handlers.capella import guardrails as g
from handlers.capella.client import CapellaError

CLUSTER = {"id": "c1", "name": "mcp-fx", "description": "", "currentState": "healthy"}


def _error(status: int, code: int | None, message: str = "refused") -> CapellaError:
    exc = CapellaError(message, status=status)
    if code is not None:
        exc.code = code
    return exc


@pytest.fixture
def sandbox(monkeypatch):
    """A managed cluster, with the primitive invocation under the test's control."""
    state = {"invoke_error": None, "invocations": []}

    def invoke(op_name, args, body=None, composite=""):
        state["invocations"].append(op_name)
        if isinstance(state["invoke_error"], Exception):
            raise state["invoke_error"]
        return {}

    monkeypatch.setattr(env, "_resolve_context", lambda args: ("o", "p", None))
    monkeypatch.setattr(
        env, "_get_cluster_for_destructive", lambda org, project, name: dict(CLUSTER)
    )
    monkeypatch.setattr(env, "_refetch_cluster", lambda org, project, c: dict(CLUSTER))
    monkeypatch.setattr(g, "assert_managed", lambda *a, **k: None)
    monkeypatch.setattr(env, "_invoke", invoke)
    return state


# ── park ─────────────────────────────────────────────────────────────────────


def test_parking_a_running_cluster_reports_that_it_is_turning_off(sandbox):
    result = env._park({"env_name": "fx"})
    assert result["state"] == "turning_off"
    assert "capella_cluster_turn_off" in sandbox["invocations"]


def test_a_cluster_already_off_is_an_idempotent_success(sandbox):
    sandbox["invoke_error"] = _error(422, 7011, "cluster is already off")
    result = env._park({"env_name": "fx"})
    assert result["state"] == "already_off"
    assert result["billing"] == "stopped"


def test_a_failure_whose_text_merely_contains_7011_is_not_already_off(sandbox):
    """`"7011" in str(exc)` also matched the status, the path's UUIDs and the
    request id, so a 500 was reported as `billing: stopped` for a cluster that was
    still running and still billing."""
    sandbox["invoke_error"] = _error(
        500, None, "internal error on cluster 7011abcd-0000-0000-0000-000000007011"
    )
    with pytest.raises(CapellaError):
        env._park({"env_name": "fx"})


def test_another_domain_code_is_not_swallowed(sandbox):
    sandbox["invoke_error"] = _error(422, 4002, "not permitted")
    with pytest.raises(CapellaError):
        env._park({"env_name": "fx"})


def test_parking_an_environment_with_no_cluster_is_refused(monkeypatch, sandbox):
    monkeypatch.setattr(
        env, "_get_cluster_for_destructive", lambda org, project, name: None
    )
    with pytest.raises(g.GuardrailError) as caught:
        env._park({"env_name": "fx"})
    assert "No cluster found" in str(caught.value)


def test_parking_uses_the_ownership_check_not_the_deletion_check(monkeypatch, sandbox):
    """Refusing a park because the cluster is protected from DELETION would push
    an operator toward switching protection off to get ordinary work done."""
    called: list[str] = []
    monkeypatch.setattr(
        g, "assert_managed", lambda *a, **k: called.append(k.get("verb", "?"))
    )
    monkeypatch.setattr(
        g,
        "assert_deletable",
        lambda *a, **k: pytest.fail("park must not use the deletion guard"),
    )
    env._park({"env_name": "fx"})
    assert called == ["park"]


# ── resume ───────────────────────────────────────────────────────────────────


def test_resuming_reports_that_it_is_turning_on(sandbox):
    result = env._resume({"env_name": "fx"})
    assert result["state"] == "turning_on"
    assert result["retry_after_s"]
    assert "capella_env_status" in result["note"]


def test_the_linked_app_service_is_turned_on_with_the_cluster(monkeypatch, sandbox):
    """A cluster back online with its App Service still off presents as an
    auth or connectivity failure rather than 'not started yet'."""
    bodies: list[dict] = []

    def invoke(op_name, args, body=None, composite=""):
        bodies.append(body or {})
        return {}

    monkeypatch.setattr(env, "_invoke", invoke)
    env._resume({"env_name": "fx"})
    assert bodies[0].get("turnOnLinkedAppService") is True


def test_a_cluster_already_on_is_an_idempotent_success(sandbox):
    sandbox["invoke_error"] = _error(422, 7010, "already on")
    assert env._resume({"env_name": "fx"})["state"] == "already_on"


def test_a_failure_whose_text_merely_contains_7010_is_not_already_on(sandbox):
    sandbox["invoke_error"] = _error(503, None, "upstream 7010 unavailable")
    with pytest.raises(CapellaError):
        env._resume({"env_name": "fx"})


def test_resuming_an_unmanaged_cluster_is_refused(monkeypatch, sandbox):
    """Resuming one starts billing on infrastructure this server does not own."""

    def refuse(*a, **k):
        raise g.GuardrailError("not a managed cluster")

    monkeypatch.setattr(g, "assert_managed", refuse)
    with pytest.raises(g.GuardrailError):
        env._resume({"env_name": "fx"})


def test_resuming_an_environment_with_no_cluster_is_refused(monkeypatch, sandbox):
    monkeypatch.setattr(
        env, "_get_cluster_for_destructive", lambda org, project, name: None
    )
    with pytest.raises(g.GuardrailError):
        env._resume({"env_name": "fx"})
