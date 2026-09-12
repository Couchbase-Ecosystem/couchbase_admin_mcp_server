"""The dry-run policy: authorized, audited, and not performed.

These tests exist because the architecture document asserted that every Admin MCP tool
takes a dry-run flag while exactly one did. The claim is now true, and these are what keep
it true -- in particular the two properties that are easy to break by accident:

  * a write must NOT reach its handler under a dry run, and
  * the environment must win over the caller, or preview mode is not a control.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dryrun
import server


@pytest.fixture(scope="module", autouse=True)
def _writes_loaded():
    """Load the write tools for this module only, then put the environment back.

    Setting CB_ADMIN_READ_ONLY_MODE at import time was the first attempt and it poisoned
    the session: handlers.shared snapshots that variable at import, so every module that
    ran afterwards saw writes enabled and several tests failed in a combined run while
    passing alone. conftest's autouse snapshot cannot save this -- it is function-scoped,
    so it captures the already-mutated environment as its baseline.
    """
    saved = dict(os.environ)
    os.environ["CB_ADMIN_PROFILE"] = "workstation"
    os.environ["CB_ADMIN_READ_ONLY_MODE"] = "false"

    # Pin the deployment mode. Without this, `deployment.detect_mode()` INFERS it,
    # and on a developer machine with CAPELLA_API_KEY_SECRET exported and no
    # CB_CONNECTION_STRING it infers `capella` -- which unloads every ns_server
    # admin_* tool, so `test_gating_still_comes_first` skipped itself and the
    # gating-before-dry-run property went unchecked on exactly the machine where
    # someone was most likely to be changing it.
    #
    # conftest's credential scrub cannot save this one: it is function-scoped and
    # this fixture is module-scoped, so server is reloaded -- and _TOOLS built --
    # before the first test's scrub runs.
    #
    # `both` rather than `self_managed` because this module is about the dry-run
    # policy applying to EVERY tool, so the widest surface is the right one to
    # load; explicit CB_DEPLOYMENT always beats inference.
    os.environ["CB_DEPLOYMENT"] = "both"

    import handlers.shared
    import profile_config

    for module in (profile_config, handlers.shared, server):
        importlib.reload(module)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)
        for module in (profile_config, handlers.shared, server):
            importlib.reload(module)


def call(name: str, arguments: dict) -> dict:
    """Invoke the dispatch the way the MCP client does, and parse the single text block.

    The loop is created if the thread has none. Other modules in this suite close the
    session's loop, and `asyncio.get_event_loop()` on Python 3.10 raises rather than
    replacing it -- so a bare get_event_loop() here passes alone and fails in a combined
    run, which says nothing about the dry-run policy.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("closed")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    result = loop.run_until_complete(server.call_tool(name, arguments))
    return json.loads(result[0].text)


@pytest.fixture
def audited(monkeypatch):
    """Audit records, captured at audit.emit_tool_call.

    NOT at server._audit: that is a closure defined inside call_tool so it can capture the
    principal and the correlation id, so there is no module attribute to patch — and
    patching a name that does not exist passes silently while the assertion reads an empty
    list.
    """
    records: list[dict] = []
    monkeypatch.setattr(
        server.audit,
        "emit_tool_call",
        lambda **kwargs: records.append(kwargs),
        raising=False,
    )
    return records


@pytest.fixture
def executed(monkeypatch):
    """Names of tools whose handler was actually reached.

    Patched on the handler MODULE registered for the tool, which is how the dispatch
    resolves one: `server._HANDLERS[name].handle`.
    """
    reached: list[str] = []

    def fake(name, args):
        reached.append(name)
        # A real result, not []: the dispatch reads result[0] to classify and return it,
        # so an empty list makes every call that REACHES a handler raise IndexError --
        # which reads like a dry-run failure and is not one.
        return server.shared.ok({"stub": True})

    for module in set(server._HANDLERS.values()):
        monkeypatch.setattr(module, "handle", fake, raising=False)
    return reached


@pytest.fixture(autouse=True)
def _no_preview_mode():
    previous = os.environ.pop(dryrun.ENV, None)
    yield
    if previous is None:
        os.environ.pop(dryrun.ENV, None)
    else:
        os.environ[dryrun.ENV] = previous


@pytest.fixture
def a_write_tool() -> str:
    tool = next(
        t
        for t in server._TOOLS
        if not server._is_read_only(t) and not dryrun.handler_owns(t)
    )
    return tool.name


def test_a_write_is_not_performed(a_write_tool, executed):
    """The handler must not be reached. This is the whole point."""
    payload = call(a_write_tool, {"dry_run": True, "confirm": True})
    assert executed == [], f"{a_write_tool} executed during a dry run"
    assert payload["dry_run"] is True
    assert payload["executed"] is False
    assert payload["tool"] == a_write_tool


def test_the_preview_says_what_would_have_happened(a_write_tool):
    payload = call(a_write_tool, {"dry_run": True, "confirm": True, "name": "widgets"})
    text = payload["message"]
    assert "DRY RUN" in text
    assert a_write_tool in text
    assert "widgets" in text
    # The control field itself is not part of the proposal.
    assert dryrun.ARG not in payload["arguments"]


def test_the_environment_beats_the_caller(a_write_tool, executed, monkeypatch):
    """`dry_run: false` must not escape a server-wide preview mode."""
    monkeypatch.setenv(dryrun.ENV, "true")
    payload = call(a_write_tool, {"dry_run": False, "confirm": True})
    assert executed == []
    assert payload["dry_run"] is True
    assert dryrun.ENV in payload["reason"]


def test_a_read_still_runs(executed):
    """Refusing reads would remove the information the plan is checked against."""
    read_tool = next(t for t in server._TOOLS if server._is_read_only(t))
    call(read_tool.name, {"dry_run": True})
    assert executed == [read_tool.name]


def test_the_flag_never_reaches_the_handler(a_write_tool, monkeypatch):
    """Under preview mode OFF, dry_run:false must still be stripped from the arguments.

    A stray member in a Capella v4 request body is a 400 at best, and a member the API
    quietly honours at worst -- the same hazard `confirm` and `correlation_id` are stripped
    for.
    """
    seen: dict = {}

    def fake(name, args):
        seen.update(args)
        return server.shared.ok({"stub": True})

    for module in set(server._HANDLERS.values()):
        monkeypatch.setattr(module, "handle", fake, raising=False)
    call(a_write_tool, {"dry_run": False, "confirm": True, "name": "widgets"})
    assert dryrun.ARG not in seen
    assert seen.get("name") == "widgets"


def test_every_loaded_write_tool_advertises_the_flag():
    """Undiscoverable is as good as absent: a model cannot send a field it cannot see."""
    missing = [
        t.name
        for t in server._TOOLS
        if not server._is_read_only(t)
        and t.name not in server._ALWAYS_LOADED_IN_READ_ONLY
        and dryrun.ARG not in (t.inputSchema.get("properties") or {})
    ]
    assert missing == []


def test_read_tools_do_not_advertise_it():
    """Advertising it on a read would promise behaviour the dispatch does not implement."""
    wrong = [
        t.name
        for t in server._TOOLS
        if server._is_read_only(t)
        and not dryrun.handler_owns(t)
        and dryrun.ARG in (t.inputSchema.get("properties") or {})
    ]
    assert wrong == []


def test_the_handler_keeps_its_own_flag():
    """capella_env_reap implements a real dry run whose default is TRUE.

    Registration reads the RAW schemas, before the dispatch advertises dry_run on write
    tools -- if it read the filtered ones, every tool would look handler-owned and the
    interception would stop happening everywhere.
    """
    owned = dryrun.handler_owned_tools()
    assert "capella_env_reap" in owned
    assert len(owned) == 1, f"unexpected handler-owned dry runs: {sorted(owned)}"


def test_a_dry_run_is_its_own_audit_decision(a_write_tool, audited, executed):
    """Not `allowed`: a SIEM rule counting privileged writes must not count previews."""
    call(a_write_tool, {"dry_run": True, "confirm": True})
    assert [r for r in audited if r.get("decision") == "dry_run"], audited
    assert not [r for r in audited if r.get("decision") == "allowed"]


def test_gating_still_comes_first(executed, monkeypatch):
    """A dry run of a tool you may not call is a refusal, not a preview."""
    monkeypatch.setattr(server, "_CONFIRMATION_REQUIRED", {"admin_bucket_delete"})
    # An assertion, not a skip. The mode is pinned to `both` by _writes_loaded, so
    # this tool missing is a defect in tool loading -- not a property of the
    # machine the suite happens to be running on.
    assert any(t.name == "admin_bucket_delete" for t in server._TOOLS), (
        "admin_bucket_delete is not loaded under CB_DEPLOYMENT=both; the gating "
        "test cannot run and previously skipped itself silently"
    )
    payload = call("admin_bucket_delete", {"dry_run": True, "name": "b"})
    assert payload.get("requires_confirmation") is True
    assert payload.get("dry_run") is not True
