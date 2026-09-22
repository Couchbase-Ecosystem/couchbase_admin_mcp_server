"""The reaper's accounting, where every defect has been a number that lied.

This sweep deletes billable infrastructure and reports what it did. Three
failures have come out of it, and all three are the same shape -- a count that
read as more certain than the work performed:

  * The dry run reported every expired entry as "would delete" while the real run
    separately refused those lacking a cluster id, so an operator sizing a sweep
    from the preview got a number the real run would not match. Both now go
    through _classify_expired, so they cannot disagree.

  * An `elif entry.get("environment")` dropped an expired entry whose marker
    carried env:"" from BOTH lists. capella_env_list advertised it as expired and
    reapable while both reap modes returned reaped:[] and refused:[] -- a billing
    resource simultaneously flagged for collection and silently skipped. Nothing
    may leave that function unaccounted for.

  * A teardown returning "nothing_to_do" or "not_found" issued zero DELETEs and
    the cluster may still exist, but any outcome was appended to `reaped` and
    counted. On a dashboard that reads as a successful collection.

So the tests below assert conservation -- every input appears in exactly one
output list -- rather than just the happy path.
"""

from __future__ import annotations

import pytest

from handlers.capella import environment as env
from handlers.capella import guardrails as g
from handlers.capella.client import CapellaError


def _entry(environment="fx", cluster_id="c1", project_id="p"):
    return {
        "environment": environment,
        "cluster_id": cluster_id,
        "project_id": project_id,
        "expired": True,
    }


# ── classification: nothing may go unaccounted for ───────────────────────────


def test_an_entry_with_a_name_and_an_id_is_reapable():
    reapable, unpinnable = env._classify_expired([_entry()])
    assert [e["environment"] for e in reapable] == ["fx"]
    assert unpinnable == []


def test_an_entry_with_no_cluster_id_is_reported_not_resolved_by_name():
    reapable, unpinnable = env._classify_expired([_entry(cluster_id="")])
    assert reapable == []
    assert unpinnable[0]["environment"] == "fx"
    assert "cannot be pinned" in unpinnable[0]["error"]


def test_an_entry_with_a_blank_name_is_still_reported():
    """The `elif entry.get("environment")` form dropped this from BOTH lists, so
    a billing resource was flagged for collection and silently skipped at once."""
    reapable, unpinnable = env._classify_expired([_entry(environment="")])
    assert reapable == []
    assert unpinnable[0]["environment"] == "(unnamed)"
    assert "blank `env` name" in unpinnable[0]["error"]
    assert "mcp-env marker" in unpinnable[0]["error"]


def test_every_entry_appears_in_exactly_one_list():
    """Conservation is the property; the individual verdicts are detail."""
    entries = [
        _entry("a", "c1"),
        _entry("b", ""),
        _entry("", "c3"),
        _entry("", ""),
    ]
    reapable, unpinnable = env._classify_expired(entries)
    assert len(reapable) + len(unpinnable) == len(entries)


# ── the dry run and the real run agree ───────────────────────────────────────


@pytest.fixture
def sweep(monkeypatch):
    state = {"expired": [], "outcomes": {}, "errors": {}}

    def list_envs(args):
        return {"managed": state["expired"]}

    def teardown(args):
        name = args["env_name"]
        if name in state["errors"]:
            raise state["errors"][name]
        return {"result": state["outcomes"].get(name, "deleted")}

    monkeypatch.setattr(env, "_list_envs", list_envs)
    monkeypatch.setattr(env, "_teardown", teardown)
    return state


def test_the_preview_deletes_nothing_and_says_so(sweep):
    sweep["expired"] = [_entry()]
    result = env._reap({"dry_run": True})
    assert result["dry_run"] is True
    assert result["would_delete_count"] == 1
    assert "Nothing was deleted" in result["note"]
    assert "checked against the guardrails individually" in result["note"]


def test_the_preview_and_the_run_classify_the_same_entries(sweep):
    """An operator sizing a sweep from the preview must get a number the real run
    matches."""
    sweep["expired"] = [_entry("a", "c1"), _entry("b", "")]
    preview = env._reap({"dry_run": True})
    actual = env._reap({"dry_run": False})
    assert preview["would_delete_count"] == actual["reaped_count"]
    assert len(preview["would_refuse"]) == len(actual["refused"])


# ── a sweep that deleted nothing is not a reap ───────────────────────────────


@pytest.mark.parametrize("outcome", ["nothing_to_do", "not_found"])
def test_a_teardown_that_issued_no_delete_is_refused_not_counted(sweep, outcome):
    """Zero DELETEs were issued and the cluster may still be billing. Counting it
    reads on the operator's dashboard as a successful collection."""
    sweep["expired"] = [_entry()]
    sweep["outcomes"] = {"fx": outcome}
    result = env._reap({"dry_run": False})
    assert result["reaped_count"] == 0
    assert result["refused"][0]["environment"] == "fx"
    assert "nothing was deleted" in result["refused"][0]["error"]
    assert "Verify by hand" in result["refused"][0]["error"]


def test_a_real_deletion_is_counted(sweep):
    sweep["expired"] = [_entry()]
    result = env._reap({"dry_run": False})
    assert result["reaped_count"] == 1
    assert result["reaped"][0]["outcome"] == "deleted"


@pytest.mark.parametrize(
    "failure",
    [g.GuardrailError("protected cluster"), CapellaError("403 forbidden", status=403)],
)
def test_one_environment_refusing_does_not_abort_the_sweep(sweep, failure):
    sweep["expired"] = [_entry("a", "c1"), _entry("b", "c2")]
    sweep["errors"] = {"a": failure}
    result = env._reap({"dry_run": False})
    assert result["reaped_count"] == 1
    assert [r["environment"] for r in result["reaped"]] == ["b"]
    assert any(r["environment"] == "a" for r in result["refused"])


def test_the_sweep_pins_the_cluster_whose_expiry_triggered_it(monkeypatch, sweep):
    """Resolving by name at teardown time could delete a DIFFERENT cluster that
    has since taken the name."""
    seen: list[dict] = []

    def teardown(args):
        seen.append(args)
        return {"result": "deleted"}

    monkeypatch.setattr(env, "_teardown", teardown)
    sweep["expired"] = [_entry("fx", "c-original")]
    env._reap({"dry_run": False})
    assert seen[0]["expected_cluster_id"] == "c-original"


def test_the_result_says_teardown_is_multi_step(sweep):
    """Environments with an App Service need a second pass, and an operator who
    does not know that reads a non-empty refused list as a failure."""
    sweep["expired"] = [_entry()]
    result = env._reap({"dry_run": False})
    assert "second reap pass" in result["note"]


def test_an_empty_sweep_is_not_an_error(sweep):
    result = env._reap({"dry_run": False})
    assert result["reaped_count"] == 0
    assert result["refused"] == []
