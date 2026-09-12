"""
`scripts/verify_mcp_surface.py`: the MCP-client-level live check.

WHY THIS FILE EXISTS
====================
The script it covers is the one that decides whether a live run "passed", and a
verifier that is wrong in the optimistic direction is worse than no verifier at
all — it converts an untested surface into a green transcript somebody files.
Every check here is aimed at that failure mode rather than at coverage:

  * a tool that was skipped must never be counted as one that worked
  * a refusal must be told apart from a result, and from an upstream error
  * a write must never be able to reach a handler in the preview phase

The last one has teeth. The preview phase calls every write tool the server
advertises, and its safety rests on two facts about ``server.py``: the dry-run
interception sits between the gates and the handler, and ``CB_ADMIN_DRY_RUN`` is
read from the environment before the arguments, so a caller cannot switch it off.
The single exception is a tool that implements ``dry_run`` in its own handler —
those are deliberately not intercepted, and ``capella_env_reap`` is one of them.
``test_a_handler_owned_dry_run_tool_is_never_called_in_the_write_phase`` is the
check that this script cannot reap a cluster.

None of this needs a cluster, and none of it needs the ``mcp`` client library:
the script imports that inside the function that starts a server, precisely so it
stays importable in a checkout where nothing is installed.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import pathlib
import sys
from types import ModuleType, SimpleNamespace

import pytest

# Loaded by path rather than imported by name: `scripts/` is not a package and
# is not on sys.path during a test run. The alternative — adding it — would put
# every mutation harness in scripts/ on the import path too, and those copy the
# tree and run pytest in a subprocess.
_SCRIPT = (
    pathlib.Path(__file__).resolve().parent.parent / "scripts" / "verify_mcp_surface.py"
)
_spec = importlib.util.spec_from_file_location("verify_mcp_surface", _SCRIPT)
vms = importlib.util.module_from_spec(_spec)
# Registered BEFORE it is executed. `@dataclass` resolves its own module out of
# sys.modules to check the annotations, so a module that is not there yet fails
# collection with `'NoneType' object has no attribute '__dict__'` — an error that
# says nothing about the real cause.
sys.modules[_spec.name] = vms
_spec.loader.exec_module(vms)


# ── Doubles ──────────────────────────────────────────────────────────────────


def _tool(name, *, read_only=True, properties=None, required=None):
    """A stand-in for an advertised mcp Tool.

    A SimpleNamespace rather than the real model so the suite runs on either mcp
    major version, which is the same reason `mcp_compat` exists.
    """
    return SimpleNamespace(
        name=name,
        inputSchema={
            "type": "object",
            "properties": properties or {},
            "required": required or [],
        },
        annotations=SimpleNamespace(readOnlyHint=read_only),
    )


class _Response:
    def __init__(self, payload):
        text = payload if isinstance(payload, str) else json.dumps(payload)
        self.content = [SimpleNamespace(type="text", text=text)]


class _FakeSession:
    """Records every call and answers from a table keyed by tool name."""

    def __init__(self, answers=None, default=None, advertises=()):
        self.advertises = list(advertises)
        self.answers = answers or {}
        self.default = default if default is not None else {"ok": True}
        self.calls = []

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, dict(arguments or {})))
        answer = self.answers.get(name, self.default)
        if callable(answer):
            answer = answer(len(self.calls))
        return _Response(answer)

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"_FakeSession(calls={[n for n, _ in self.calls]})"

    async def list_tools(self):
        return SimpleNamespace(tools=list(self.advertises))


def _run(advertised=None, status=None, **flags):
    """A Run wired for tests, with output discarded."""
    argv = list(flags.pop("argv", []))
    args = vms.build_parser().parse_args(argv)
    for key, value in flags.items():
        setattr(args, key, value)
    run = vms.Run(args)
    run.advertised = advertised or []
    run.status = status or {}
    run.say = lambda *_a, **_k: None
    return run


# ── Argument resolution ──────────────────────────────────────────────────────


def test_a_required_argument_the_context_cannot_fill_skips_the_tool():
    """Calling with a hole in the arguments is the tempting shortcut and the wrong one.

    The handler would answer 400 or raise a KeyError, and either reads in the
    transcript as "the tool is broken" when what actually happened is that this
    script never found an id to pass it.
    """
    schema = {"properties": {"cluster_id": {}}, "required": ["cluster_id"]}
    arguments, missing = vms.resolve_arguments(schema, {})
    assert arguments == {}
    assert missing == ["cluster_id"]


def test_a_resolvable_required_argument_is_filled():
    schema = {"properties": {"cluster_id": {}}, "required": ["cluster_id"]}
    arguments, missing = vms.resolve_arguments(schema, {"cluster_id": "abc"})
    assert arguments == {"cluster_id": "abc"}
    assert missing == []


def test_an_optional_keyspace_selector_is_filled_but_other_optionals_are_not():
    """The one place an optional argument is supplied, and why.

    The /queryService/ reads declare `bucket`, `scope` and `collection` as
    optional query parameters. A keyspace read without a bucket answers 400 — and
    400 was once recorded as proof the route existed, which is a verified verdict
    for a call that never looked at an index. Every other optional stays out,
    because supplying one changes what the call means.
    """
    schema = {
        "properties": {
            "bucket": {},
            "scope": {},
            "collection": {},
            "sortBy": {},
            "perPage": {},
        },
        "required": [],
    }
    context = {
        "bucket": "travel-sample",
        "scope": "inventory",
        "collection": "airline",
        "sortBy": "name",
        "perPage": "5",
    }
    arguments, missing = vms.resolve_arguments(schema, context)
    assert missing == []
    assert arguments == {
        "bucket": "travel-sample",
        "scope": "inventory",
        "collection": "airline",
    }


def test_the_dispatch_control_fields_are_never_resolved_from_context():
    """`confirm`, `dry_run` and `correlation_id` are the phases' business.

    Resolving them from context would let a stray value in the discovery map turn
    a read into a confirmed write. The phases set them explicitly or not at all.
    """
    schema = {
        "properties": {"confirm": {}, "dry_run": {}, "correlation_id": {}},
        "required": [],
    }
    context = {"confirm": "true", "dry_run": "false", "correlation_id": "x"}
    arguments, _ = vms.resolve_arguments(schema, context)
    assert arguments == {}


def test_a_tool_that_requires_confirm_is_skipped_rather_than_confirmed():
    """No tool declares `confirm` as required today. If one ever does, skip it.

    The alternative — treating a required `confirm` as satisfiable — would make
    this script confirm a write on the strength of a schema change.
    """
    schema = {"properties": {"confirm": {}}, "required": ["confirm"]}
    arguments, missing = vms.resolve_arguments(schema, {"confirm": True})
    assert arguments == {}
    assert missing == ["confirm"]


# ── Classification ───────────────────────────────────────────────────────────


def test_a_confirmation_refusal_is_not_an_upstream_error():
    """The confirmation gate working is the thing the write phase proves.

    Reading the discriminators in the wrong order reports the working case as
    sixteen failures, which is how a correct run gets rewritten to be wrong.
    """
    payload = {
        "error": "Confirmation required",
        "requires_confirmation": True,
        "_is_error": True,
    }
    assert vms.classify(payload, phase="write")[0] == vms.GATED


def test_a_guardrail_refusal_is_told_apart_from_an_api_refusal():
    guard = {"error": "outside the allowlist", "guardrail": True, "_is_error": True}
    api = {"error": "not found", "status": 404, "_is_error": True}
    assert vms.classify(guard, phase="read")[0] == vms.GUARDED
    assert vms.classify(api, phase="read")[0] == vms.UPSTREAM


def test_an_unroutable_tool_is_a_protocol_failure_not_an_upstream_one():
    """ "Unknown tool" and "not enabled" come from the dispatch, not the API.

    They carry no status, so the generic branch would file them as upstream
    errors — which is exactly backwards: an advertised tool that will not
    dispatch is the defect this script exists to find.
    """
    for message in ("Unknown tool: capella_x", "Tool capella_x is not enabled"):
        payload = {"error": message, "_is_error": True}
        assert vms.classify(payload, phase="read")[0] == vms.PROTOCOL


def test_a_response_with_no_json_is_a_protocol_failure():
    """Every handler returns through ok() or err(), and both serialise a dict."""
    assert vms.classify(None, phase="read")[0] == vms.PROTOCOL


def test_a_dry_run_preview_is_recognised_as_a_preview():
    payload = {"dry_run": True, "executed": False, "tool": "capella_bucket_create"}
    outcome, _ = vms.classify(payload, phase="write")
    assert outcome == vms.PREVIEW


def test_a_response_that_says_it_executed_is_a_hard_failure():
    """The one finding that must never be softened.

    `executed: true` in a phase whose entire premise is that nothing runs means a
    write was performed against a live control plane.
    """
    payload = {"dry_run": False, "executed": True, "tool": "capella_bucket_delete"}
    outcome, _ = vms.classify(payload, phase="write")
    assert outcome == vms.PERFORMED
    assert outcome in vms._HARD_FAILURES


def test_a_write_phase_result_with_no_preview_marker_is_a_hard_failure():
    """A plain success in the write phase means the dry run did not intercept.

    This is the shape the failure would actually take: not a payload announcing
    `executed: true`, but an ordinary result from a handler that ran.
    """
    outcome, _ = vms.classify({"id": "new-bucket-id"}, phase="write")
    assert outcome == vms.PERFORMED


def test_the_same_payload_in_a_read_phase_is_an_ordinary_result():
    """The write-phase rule must not leak into the read phase."""
    assert vms.classify({"id": "abc"}, phase="read")[0] == vms.OK


def test_an_empty_listing_is_empty_but_a_scalar_answer_is_not():
    """`{"data": []}` is a list with nothing in it; `{"state": "healthy"}` is an answer.

    Calling the second one EMPTY would read as a gap where there is none, and the
    whole point of the EMPTY outcome is to say "this ran and there was nothing
    there" without that being mistaken for a failure.
    """
    assert vms.classify({"data": [], "cursor": {}}, phase="read")[0] == vms.EMPTY
    assert vms.classify({"state": "healthy"}, phase="read")[0] == vms.OK


def test_skipped_is_not_one_of_the_successful_outcomes():
    """The whole reason the outcomes are not a boolean.

    A run where forty tools could not be given arguments is not a run where forty
    tools passed, and the summary must not be able to say otherwise.
    """
    assert vms.SKIPPED not in vms._SUCCESSFUL


# ── Envelopes ────────────────────────────────────────────────────────────────


def test_the_v4_list_envelopes_all_parse():
    """v4 list responses are NOT uniform, and assuming they were cost real time.

    Most answer {"data": [...]}; GET .../scopes answers {"scopes": [...]}; a scope
    answers {"collections": [...]}. Reading only `data` produced silent empty
    discovery for two of the three, and "no scopes found" looks identical to "no
    scopes exist".
    """
    assert vms._items({"data": [1, 2], "cursor": {}}) == [1, 2]
    assert vms._items({"scopes": [{"name": "inventory"}]}) == [{"name": "inventory"}]
    assert vms._items({"collections": [{"name": "airline"}]}) == [{"name": "airline"}]
    assert vms._items([1, 2, 3]) == [1, 2, 3]


def test_an_ambiguous_envelope_yields_nothing_rather_than_a_guess():
    """Two lists and no `data` key: which one is the rows? Refuse to pick."""
    assert vms._items({"alpha": [1], "beta": [2]}) == []


def test_a_doubly_nested_item_is_unwrapped():
    """Some v4 items arrive as {"data": {"data": {...}}}."""
    assert vms._unwrap({"data": {"data": {"id": "x"}}}) == {"id": "x"}
    assert vms._unwrap({"id": "x"}) == {"id": "x"}


def test_a_bucket_id_decodes_to_its_bucket_name():
    """A keyspace is three NAMES, while everything else in v4 takes the opaque id.

    Sending the id where a name belongs produces "Index not found in key space",
    which is true and tells you nothing.
    """
    assert vms._decode_bucket_id("dHJhdmVsLXNhbXBsZQ==") == "travel-sample"


def test_an_id_that_is_not_base64_decodes_to_nothing_rather_than_mojibake():
    assert vms._decode_bucket_id("not-base-64!") == ""


# ── Selection and reporting ──────────────────────────────────────────────────


def test_an_internal_bucket_is_not_chosen_when_a_real_one_exists():
    """Discovery that lands on _system sends every keyspace read somewhere dull."""
    run = _run()
    rows = [{"id": "a", "name": "_system"}, {"id": "b", "name": "travel-sample"}]
    assert run._choose("capella_buckets_list", rows, "id") == "b"


def test_an_internal_bucket_is_still_chosen_when_it_is_the_only_one():
    """Better a thin run than no run — but the report says what was picked."""
    run = _run()
    rows = [{"id": "a", "name": "_system"}]
    assert run._choose("capella_buckets_list", rows, "id") == "a"


def test_a_row_without_the_named_field_is_not_selected():
    run = _run()
    rows = [{"name": "no id here"}, {"id": "b", "name": "real"}]
    assert run._choose("capella_clusters_list", rows, "id") == "b"


def test_the_response_shape_reports_keys_and_counts_but_never_values():
    """Evidence files get attached to tickets.

    The server redacts what it knows to be secret, but allowlist CIDRs, credential
    ids and eventing source are not secrets by that definition and are still not
    things to paste into a ticket by default. --print-bodies is the deliberate
    override.
    """
    shape = vms._shape({"data": [{"cidr": "203.0.113.118/32"}], "cursor": {}})
    assert "203.0.113.118" not in shape
    assert "2 row" not in shape
    assert "1 row" in shape and "cursor" in shape


def test_every_discovery_entry_fills_a_distinct_key_WITHIN_ITS_SIDE():
    """Two entries writing the same key on the same side means the second never runs.

    `key in self.context_for(tool)` is the guard, so a duplicate is not an error —
    it is a silently dead table row, the kind of thing that survives review.

    ACROSS sides a repeat is expected and correct: `function_name` is filled by
    capella_eventing_functions_list on the control plane and by admin_eventing_list
    on a cluster, and they are different functions. Asserting global uniqueness was
    right when there was one context and would now forbid the fix.
    """
    by_side: dict[str, list[str]] = {}
    for tool_name, key, _field in vms._DISCOVERY:
        by_side.setdefault(vms.side_of(tool_name), []).append(key)
    for side, keys in by_side.items():
        duplicates = {k for k in keys if keys.count(k) > 1}
        assert not duplicates, f"{side}-side entries collide on {sorted(duplicates)}"


def test_the_two_sides_are_addressed_separately():
    """THE DEFECT, with two live symptoms in one transcript.

    `admin_bucket_get` asked a laptop for `travel-sample` and `admin_eventing_get`
    asked it for the Capella eventing function `test`. Both 404'd, and both read
    as broken tools. One shared context could not express "these are two clusters".
    """
    run = _run()
    run.contexts[vms.CAPELLA_SIDE]["function_name"] = "capella-fn"
    run.contexts[vms.CLUSTER_SIDE]["function_name"] = "local-fn"

    assert run.context_for("capella_eventing_function_get")["function_name"] == (
        "capella-fn"
    )
    assert run.context_for("admin_eventing_get")["function_name"] == "local-fn"


def test_a_cluster_side_tool_cannot_see_a_capella_object_name():
    """The failure mode, asserted directly: no leakage across the boundary."""
    run = _run()
    run.contexts[vms.CAPELLA_SIDE]["bucket_id"] = "dHJhdmVsLXNhbXBsZQ=="
    assert "bucket_id" not in run.context_for("admin_bucket_get")


def test_the_sdk_tools_that_hang_are_not_named_by_a_prefix_list():
    """The prefix list was a guess and it missed two.

    It named cb_get_/cb_perf_/cb_index_/cb_explain_ and left out admin_index_list
    and admin_xdcr_conflict_log_query, both of which go through the SDK and both of
    which hung for thirty seconds each in the same run.
    """
    for name in (
        "admin_index_list",
        "admin_xdcr_conflict_log_query",
        "cb_get_schema_for_collection",
        "cb_perf_longest_running",
    ):
        assert vms._is_data_plane(name), name
    for name in ("capella_projects_list", "cb_mcp_status", "cb_mcp_list_tools"):
        assert not vms._is_data_plane(name), name


# ── The write phase's refusals ───────────────────────────────────────────────


def test_the_write_phase_refuses_when_the_server_cannot_report_its_dry_run_posture():
    """Fail closed, and say why.

    Without the posture the handler-owned set is unknown, and a handler-owned tool
    called with confirm:true runs for real. Guessing here would be guessing about
    capella_env_reap.
    """
    run = _run(advertised=[_tool("capella_bucket_create", read_only=False)])
    run.status = {"safety": {"read_only_mode": False}}
    session = _FakeSession()
    asyncio.run(run.phase_writes(session))
    assert session.calls == []
    assert any("WRITE PHASE NOT RUN" in note for note in run.notes)


def test_the_write_phase_refuses_when_server_wide_dry_run_is_not_in_effect():
    """A caller-supplied dry_run is not the control. The environment is.

    `dryrun.in_effect` consults CB_ADMIN_DRY_RUN before the arguments precisely so
    a caller cannot escape preview mode — which also means a caller cannot create
    it. If the server says preview is off, a write would reach its handler.
    """
    run = _run(advertised=[_tool("capella_bucket_create", read_only=False)])
    run.status = {
        "safety": {
            "read_only_mode": False,
            "dry_run": {"server_wide": False, "handler_owned": []},
        }
    }
    session = _FakeSession()
    asyncio.run(run.phase_writes(session))
    assert session.calls == []


def test_a_handler_owned_dry_run_tool_is_never_called_in_the_write_phase():
    """The check that this script cannot reap a cluster.

    capella_env_reap implements dry_run itself, so `dryrun.handler_owns` is true
    and server.py deliberately does NOT intercept it — CB_ADMIN_DRY_RUN does not
    protect it. It is excluded by name, from the set the server reports, and never
    from anything this script infers.
    """
    run = _run(
        advertised=[
            _tool("capella_env_reap", read_only=False),
            _tool("capella_bucket_create", read_only=False),
        ]
    )
    run.status = {
        "safety": {
            "read_only_mode": False,
            "dry_run": {
                "server_wide": True,
                "handler_owned": ["capella_env_reap"],
            },
        }
    }
    session = _FakeSession(
        default={"dry_run": True, "executed": False, "tool": "capella_bucket_create"}
    )
    asyncio.run(run.phase_writes(session))
    assert "capella_env_reap" not in {name for name, _ in session.calls}
    assert "capella_bucket_create" in {name for name, _ in session.calls}


def test_the_write_phase_asks_without_confirm_first_and_only_then_with_it():
    """Two calls, in that order, or the gate is never exercised.

    Sending confirm:true straight away would prove the dry run and nothing about
    the confirmation gate — and the gate is the control that stands between an
    agent and a real write when preview mode is off.
    """
    run = _run(advertised=[_tool("capella_bucket_create", read_only=False)])
    run.status = {
        "safety": {
            "read_only_mode": False,
            "dry_run": {"server_wide": True, "handler_owned": []},
        }
    }
    gated = {
        "error": "Confirmation required",
        "requires_confirmation": True,
        "_is_error": True,
    }
    preview = {"dry_run": True, "executed": False, "tool": "capella_bucket_create"}
    session = _FakeSession(
        answers={"capella_bucket_create": lambda n: gated if n == 1 else preview}
    )
    asyncio.run(run.phase_writes(session))

    assert [name for name, _ in session.calls] == [
        "capella_bucket_create",
        "capella_bucket_create",
    ]
    assert "confirm" not in session.calls[0][1]
    assert session.calls[1][1]["confirm"] is True


def test_a_write_tool_that_is_not_confirmation_gated_is_reported():
    """An ungated write tool is a finding, not a convenience.

    It went straight to the dry run without being asked to confirm, which means
    that with preview mode off it would have gone straight to the handler. The
    same omission was found once by a test rather than by an incident —
    capella_alert_integration_test shipped unguarded.
    """
    run = _run(advertised=[_tool("capella_thing_create", read_only=False)])
    run.status = {
        "safety": {
            "read_only_mode": False,
            "dry_run": {"server_wide": True, "handler_owned": []},
        }
    }
    session = _FakeSession(
        default={"dry_run": True, "executed": False, "tool": "capella_thing_create"}
    )
    asyncio.run(run.phase_writes(session))
    assert any("NOT confirmation-gated" in note for note in run.notes)


# ── Calls ────────────────────────────────────────────────────────────────────


def test_every_call_carries_the_run_correlation_id():
    """Provenance, and the reason the audit log is greppable after a run.

    correlation_id was advertised in the schemas and plumbed through
    audit.build_record for a while before any caller sent one, so every record was
    untraceable back to the action that produced it. A run of this script is a
    fan-out of a hundred calls; one id ties them together.
    """
    run = _run()
    session = _FakeSession()
    _payload, result = asyncio.run(
        run.call(
            session, "capella_projects_list", {"organization_id": "o"}, phase="read"
        )
    )
    assert result.outcome in (vms.OK, vms.EMPTY)
    assert session.calls[0][1]["correlation_id"] == run.correlation
    assert run.correlation.startswith("verify-mcp-surface-")


def test_a_client_exception_is_recorded_rather_than_raised():
    """One unroutable tool must not end the run.

    An exception escaping here abandons every tool after it and leaves a partial
    transcript that looks like a short tool list.
    """

    class _Boom:
        async def call_tool(self, name, arguments=None):
            raise RuntimeError("transport closed")

    run = _run()
    payload, result = asyncio.run(run.call(_Boom(), "capella_x", {}, phase="read"))
    assert payload is None
    assert result.outcome == vms.PROTOCOL
    assert "transport closed" in result.detail


def test_a_call_that_never_answers_times_out_into_a_result():
    """A hung call is a finding with a name, not a hung script.

    And it is TIMEOUT, not PROTOCOL. Folding the two together made every VPN-up
    run exit 1 the moment cb_get_schema_for_collection hung on port 11207 — the
    data plane being unreachable, reported as a defect in the MCP surface.
    """

    class _Hang:
        async def call_tool(self, name, arguments=None):
            await asyncio.sleep(5)

    run = _run(timeout=0.05)
    _payload, result = asyncio.run(run.call(_Hang(), "capella_x", {}, phase="read"))
    assert result.outcome == vms.TIMEOUT
    assert result.outcome not in vms._HARD_FAILURES
    assert "no response" in result.detail


def test_the_json_summary_records_argument_names_but_not_their_values():
    """Same reasoning as the shape summary, applied to the machine-readable half."""
    result = vms.Result(
        "capella_bucket_get",
        vms.OK,
        arguments={"bucket_id": "dHJhdmVsLXNhbXBsZQ=="},
    )
    assert result.as_dict()["arguments"] == ["bucket_id"]
    assert "dHJhdmVs" not in json.dumps(result.as_dict())


# ── Reads ────────────────────────────────────────────────────────────────────


def test_a_read_tool_whose_arguments_never_resolve_is_recorded_as_skipped():
    """Named, in the transcript, with what was missing. Silence would read as coverage."""
    run = _run(
        advertised=[
            _tool(
                "capella_backup_get",
                properties={"backup_id": {}},
                required=["backup_id"],
            )
        ]
    )
    session = _FakeSession()
    asyncio.run(run.phase_reads(session))
    assert session.calls == []
    skipped = [r for r in run.results if r.outcome == vms.SKIPPED]
    assert [r.tool for r in skipped] == ["capella_backup_get"]
    assert "backup_id" in skipped[0].detail


def test_a_tool_becomes_callable_once_an_earlier_read_supplies_its_id():
    """The fixpoint, which is why the read phase is a loop rather than one pass.

    capella_backup_get cannot be called until capella_backups_list has answered,
    and hard-coding that order would mean editing this script every time the
    registry grows a dependency.
    """
    run = _run(
        advertised=[
            _tool(
                "capella_backup_get",
                properties={"backup_id": {}},
                required=["backup_id"],
            ),
            _tool("capella_backups_list"),
        ]
    )
    session = _FakeSession(
        answers={"capella_backups_list": {"data": [{"id": "backup-1"}]}}
    )
    asyncio.run(run.phase_reads(session))

    called = dict(session.calls)
    assert "capella_backup_get" in called
    assert called["capella_backup_get"]["backup_id"] == "backup-1"
    assert not [r for r in run.results if r.outcome == vms.SKIPPED]


def test_a_write_tool_is_never_called_in_the_read_phase():
    run = _run(
        advertised=[
            _tool("capella_bucket_create", read_only=False),
            _tool("capella_buckets_list"),
        ]
    )
    session = _FakeSession(answers={"capella_buckets_list": {"data": []}})
    asyncio.run(run.phase_reads(session))
    assert "capella_bucket_create" not in {name for name, _ in session.calls}


def test_the_only_filter_restricts_both_the_calls_and_the_skips():
    """--only must not turn everything it excludes into a skipped tool.

    A filtered run that reports eighty skips has buried its own result.
    """
    run = _run(
        advertised=[_tool("capella_projects_list"), _tool("admin_bucket_list")],
        only="capella_",
    )
    session = _FakeSession(default={"data": []})
    asyncio.run(run.phase_reads(session))
    assert [name for name, _ in session.calls] == ["capella_projects_list"]
    assert not [r for r in run.results if r.outcome == vms.SKIPPED]


# ── Exit codes ───────────────────────────────────────────────────────────────


def test_a_protocol_failure_fails_the_run_without_strict():
    run = _run()
    run.results.append(vms.Result("capella_x", vms.PROTOCOL, "unroutable"))
    assert run.report() == 1


def test_an_unreachable_data_plane_does_not_fail_the_default_run():
    """The exit code answers "is the surface broken", and a hung SDK read is not that.

    With the corporate tunnel up, cb_get_schema_for_collection hangs rather than
    failing — Capella drops packets from unlisted sources. A run that exits 1 for
    that reason cannot be used to tell a real defect from a network state.
    """
    lenient = _run()
    lenient.results.append(
        vms.Result(
            "cb_get_schema_for_collection", vms.TIMEOUT, "no response within 30s"
        )
    )
    assert lenient.report() == 0

    strict = _run(strict=True)
    strict.results.append(
        vms.Result(
            "cb_get_schema_for_collection", vms.TIMEOUT, "no response within 30s"
        )
    )
    assert strict.report() == 2


def test_an_upstream_error_fails_the_run_only_under_strict():
    """An upstream 4xx is often the environment, not the code.

    capella_cluster_audit_log_export_get needs an Enterprise plan and answers 4xx
    on a Developer Pro one. Failing the default run on that would mean the script
    could never be green on the cluster it is actually run against, and a check
    that cannot pass gets switched off.
    """
    lenient = _run()
    lenient.results.append(vms.Result("capella_x", vms.UPSTREAM, "HTTP 403"))
    assert lenient.report() == 0

    strict = _run(strict=True)
    strict.results.append(vms.Result("capella_x", vms.UPSTREAM, "HTTP 403"))
    assert strict.report() == 2


def test_skipped_tools_fail_a_strict_run():
    strict = _run(strict=True)
    strict.results.append(
        vms.Result("capella_x", vms.SKIPPED, "no value for backup_id")
    )
    assert strict.report() == 3


def test_a_performed_write_outranks_every_other_finding():
    """It is reported first and it fails the run, whatever else the run found."""
    run = _run(strict=True)
    run.results.append(vms.Result("capella_x", vms.UPSTREAM, "HTTP 403"))
    run.results.append(
        vms.Result("capella_bucket_delete", vms.PERFORMED, "it executed", phase="write")
    )
    assert run.report() == 1
    summary = run.summary()
    assert summary["hard_failures"][0]["tool"] == "capella_bucket_delete"


def test_a_clean_run_exits_zero():
    run = _run()
    run.results.append(vms.Result("capella_projects_list", vms.OK))
    run.results.append(vms.Result("capella_backups_list", vms.EMPTY, "no rows"))
    assert run.report() == 0


# ── Child environment ────────────────────────────────────────────────────────


def test_the_read_phase_child_never_inherits_a_dry_run_from_the_shell():
    """An inherited CB_ADMIN_DRY_RUN=true would make the read phase look normal.

    Reads execute under a dry run, so nothing would appear wrong — and the write
    phase would then report a safe posture it did not establish. The phase sets
    what it needs rather than hoping.
    """
    env = vms._client_env(read_only=True, dry_run=False)
    assert "CB_ADMIN_DRY_RUN" not in env
    assert env["CB_ADMIN_READ_ONLY_MODE"] == "true"


def test_the_write_phase_child_asks_for_preview_mode_explicitly():
    env = vms._client_env(read_only=False, dry_run=True)
    assert env["CB_ADMIN_DRY_RUN"] == "true"
    assert env["CB_ADMIN_READ_ONLY_MODE"] == "false"


@pytest.mark.parametrize("flag", ["--write-preview", "--strict", "--print-bodies"])
def test_the_dangerous_looking_flags_are_all_off_by_default(flag):
    """Nothing that widens what the script does is the default."""
    defaults = vms.build_parser().parse_args([])
    name = flag.lstrip("-").replace("-", "_")
    assert getattr(defaults, name) is False


# ── The protocol phase ───────────────────────────────────────────────────────


def _status(read_only=True, **safety):
    body = {
        "tools": {"registered": 3, "loaded": 3, "filtered_out": 0},
        "safety": {
            "read_only_mode": read_only,
            "disabled_tools_count": 0,
            "confirmation_required_count": 1,
            **safety,
        },
    }
    return body


def test_the_protocol_phase_records_the_advertised_list_and_the_posture():
    """cb_mcp_status is called first on purpose.

    It touches no cluster, so if it answers then the transport, the dispatch, the
    audit path and the response encoding all work — and every later failure is
    about Capella rather than about this server.
    """
    tools = [_tool("cb_mcp_status"), _tool("capella_projects_list")]
    session = _FakeSession(
        advertises=tools, answers={"cb_mcp_status": _status()}, default={"data": []}
    )
    run = _run()
    asyncio.run(run.phase_protocol(session))

    assert [t.name for t in run.advertised] == [t.name for t in tools]
    assert session.calls[0][0] == "cb_mcp_status"
    assert run.status["safety"]["read_only_mode"] is True


def test_two_tools_with_the_same_name_is_a_protocol_failure():
    """A client resolves a call by name. Two tools sharing one means the second is
    unreachable and nothing anywhere reports it."""
    session = _FakeSession(
        advertises=[_tool("capella_projects_list"), _tool("capella_projects_list")],
        default=_status(),
    )
    run = _run()
    asyncio.run(run.phase_protocol(session))
    failures = [r for r in run.results if r.outcome == vms.PROTOCOL]
    assert failures and "duplicate" in failures[0].detail


def test_a_tool_with_an_unreadable_input_schema_is_a_protocol_failure():
    """An advertised schema a client cannot read is a tool a client cannot call.

    It reaches the model as "takes no arguments", and nothing looks broken until
    every call to it fails on a missing required field.
    """
    broken = SimpleNamespace(
        name="capella_broken",
        inputSchema={"type": "object", "properties": "not a mapping"},
        annotations=SimpleNamespace(readOnlyHint=True),
    )
    session = _FakeSession(advertises=[broken], default=_status())
    run = _run()
    asyncio.run(run.phase_protocol(session))
    assert any(
        r.outcome == vms.PROTOCOL and "unreadable input schema" in r.detail
        for r in run.results
    )


def test_a_failed_registry_crosscheck_is_reported_rather_than_swallowed(monkeypatch):
    """A cross-check that quietly does not run is worse than one that fails.

    The report still looks complete, so the reader concludes the registry and the
    advertised surface agree when nothing compared them.

    The failure is FORCED here rather than borrowed from the environment. The
    first version of this test relied on `handlers.capella` not being importable
    from the test process's working directory -- true when it was written, false
    under `pytest` from the repository root. So it quietly became an assertion
    about a cross-check that had SUCCEEDED, and passed for the wrong reason until
    the rest of the suite was clean enough for it to be noticed. That is the same
    mistake the test itself is about.
    """
    session = _FakeSession(advertises=[], default=_status())
    run = _run()

    # A module object with no TOOLS attribute: `from handlers.capella import
    # TOOLS` then raises ImportError, which is the real shape of this failure --
    # a renamed or half-installed registry -- rather than a synthetic exception
    # the production path would never see.
    monkeypatch.setitem(
        sys.modules, "handlers.capella", ModuleType("handlers.capella")
    )

    asyncio.run(run.phase_protocol(session))
    assert any("cross-check UNAVAILABLE" in note for note in run.notes)


def test_the_registry_crosscheck_actually_runs_when_the_registry_is_importable():
    """The other half, and the half that was missing.

    Without it, a cross-check that never ran again would be caught by nothing:
    the test above is satisfied by the note, and the note is what an unavailable
    cross-check emits. Asserting the note is ABSENT in the normal case is what
    makes the pair meaningful.
    """
    session = _FakeSession(advertises=[], default=_status())
    run = _run()
    asyncio.run(run.phase_protocol(session))
    assert not any("cross-check UNAVAILABLE" in note for note in run.notes), (
        "the registry is importable from the repository root; if this fires, the "
        "cross-check stopped running rather than started failing"
    )


def test_a_note_repeated_by_the_second_protocol_phase_is_recorded_once():
    """--write-preview runs the protocol phase twice, once per server.

    A note appended by both reads as two findings when it is one, and a report
    that inflates its own findings is the mirror of one that hides them.
    """
    session = _FakeSession(advertises=[], default=_status())
    run = _run()
    asyncio.run(run.phase_protocol(session))
    asyncio.run(run.phase_protocol(session))
    assert len(run.notes) == len(set(run.notes))


# ── Discovery ────────────────────────────────────────────────────────────────


def test_discovery_walks_the_object_graph_in_dependency_order():
    run = _run(
        advertised=[
            _tool("capella_organizations_list"),
            _tool(
                "capella_projects_list",
                properties={"organization_id": {}},
                required=["organization_id"],
            ),
            _tool(
                "capella_clusters_list",
                properties={"organization_id": {}, "project_id": {}},
                required=["organization_id", "project_id"],
            ),
        ]
    )
    session = _FakeSession(
        answers={
            "capella_organizations_list": {"data": [{"id": "org-1", "name": "FE"}]},
            "capella_projects_list": {"data": [{"id": "proj-1", "name": "sandbox"}]},
            "capella_clusters_list": {"data": [{"id": "clus-1", "name": "bride"}]},
        }
    )
    asyncio.run(run.phase_discovery(session))
    assert run.context["organization_id"] == "org-1"
    assert run.context["project_id"] == "proj-1"
    assert run.context["cluster_id"] == "clus-1"


def test_an_organization_in_the_environment_is_used_without_a_call():
    """CAPELLA_ORG_ID is what the server itself reads; honouring it keeps the run
    pointed where the operator pointed the server."""
    import os

    run = _run(advertised=[_tool("capella_organizations_list")])
    session = _FakeSession()
    os.environ["CAPELLA_ORG_ID"] = "org-from-env"
    try:
        asyncio.run(run.phase_discovery(session))
    finally:
        del os.environ["CAPELLA_ORG_ID"]
    assert run.context["organization_id"] == "org-from-env"
    assert "capella_organizations_list" not in {n for n, _ in session.calls}


def test_a_discovery_tool_that_is_not_advertised_is_not_called():
    """Read-only mode and deployment gating both legitimately remove tools."""
    run = _run(advertised=[])
    session = _FakeSession()
    asyncio.run(run.phase_discovery(session))
    assert session.calls == []


def test_the_keyspace_resolves_to_three_names_not_an_id():
    """The bucket is a NAME here and an opaque id everywhere else in v4.

    Sending the id where a name belongs produces "Index not found in key space",
    which is true and tells you nothing — and it is how a keyspace read came to be
    recorded as verified on the strength of a 400.
    """
    run = _run(
        advertised=[
            _tool(
                "capella_scopes_list",
                properties={"cluster_id": {}, "bucket_id": {}},
                required=["cluster_id", "bucket_id"],
            )
        ]
    )
    run.context.update({"cluster_id": "clus-1", "bucket_id": "dHJhdmVsLXNhbXBsZQ=="})
    session = _FakeSession(
        answers={
            "capella_scopes_list": {
                "scopes": [
                    {"name": "_default", "collections": []},
                    {"name": "inventory", "collections": [{"name": "airline"}]},
                ]
            }
        }
    )
    asyncio.run(run._discover_keyspace(session, {"capella_scopes_list"}))

    assert run.context["bucket"] == "travel-sample"
    assert run.context["scope"] == "inventory"
    assert run.context["collection"] == "airline"


def test_a_scope_with_no_collections_is_passed_over():
    """_default is usually present and usually empty. Selecting it would make every
    keyspace read look like the cluster had nothing in it."""
    run = _run(advertised=[_tool("capella_scopes_list")])
    run.context.update({"cluster_id": "c", "bucket_id": "dHJhdmVsLXNhbXBsZQ=="})
    session = _FakeSession(
        answers={"capella_scopes_list": {"scopes": [{"name": "_default"}]}}
    )
    asyncio.run(run._discover_keyspace(session, {"capella_scopes_list"}))
    assert "collection" not in run.context


def test_the_report_names_the_alternatives_not_only_the_choice():
    """Printing the alternatives is what found the defects, not better selection logic.

    A report that names one id looks identical whether there was one candidate or
    forty, and guessing wrong about which cluster a run had selected cost hours.
    """
    lines = []
    run = _run()
    run.say = lines.append
    run._report_choice(
        "cluster_id",
        "clus-1",
        [{"id": "clus-1", "name": "bride"}, {"id": "clus-2", "name": "steel"}],
        "id",
    )
    assert "1 of 2" in lines[0]
    assert "steel" in lines[0]


# ── Output ───────────────────────────────────────────────────────────────────


def test_the_transcript_goes_to_a_file_when_one_is_asked_for(tmp_path):
    target = tmp_path / "evidence.txt"
    run = _run(out=str(target))
    run.open_output()
    try:
        print("hello", file=run.out)
    finally:
        run.close_output()
    assert target.read_text(encoding="utf-8").strip() == "hello"


def test_closing_output_leaves_stdout_alone_when_no_file_was_asked_for():
    """close_output() runs in main()'s finally on every path, including the one
    where the transcript is stdout. Closing it there would take the interpreter's
    output stream with it."""
    run = _run()
    run.open_output()
    run.close_output()
    assert not sys.stdout.closed


# ── The registry cross-check ─────────────────────────────────────────────────


def _fake_spec(monkeypatch, ops, unverified=(), registered=None, writes=()):
    """Stand in for handlers.capella.spec without importing the real registry.

    The real one would make these assertions really be assertions about the
    current tool list, which moves every time an operation ships.
    """
    import types

    package = types.ModuleType("handlers")
    package.__path__ = []
    capella = types.ModuleType("handlers.capella")
    capella.__path__ = []
    # handlers.capella.TOOLS is what the SERVER registers: the primitive registry
    # plus the environment and fixture tools, which have no Op record at all.
    write_set = set(writes)
    capella.TOOLS = [
        SimpleNamespace(
            name=n,
            annotations=SimpleNamespace(readOnlyHint=n not in write_set),
        )
        for n in (registered if registered is not None else ops)
    ]
    spec = types.ModuleType("handlers.capella.spec")
    spec.OPS_BY_NAME = {
        name: SimpleNamespace(read_only=name not in set(writes)) for name in ops
    }
    spec.SHIPPED_UNVERIFIED = dict.fromkeys(unverified, "reason 2026-09-01")
    monkeypatch.setitem(sys.modules, "handlers", package)
    monkeypatch.setitem(sys.modules, "handlers.capella", capella)
    monkeypatch.setitem(sys.modules, "handlers.capella.spec", spec)


def test_a_read_tool_that_is_not_advertised_is_named_as_unexplained(monkeypatch):
    """The drift no HTTP-level probe can see.

    verify_capella_paths.py would report the path verified and this server would
    never expose it, and both reports would look clean. A READ tool missing is not
    explained by read-only mode, so it gets its own line.
    """
    _fake_spec(monkeypatch, ["capella_projects_list", "capella_backups_list"])
    run = _run()
    run._crosscheck_registry(["capella_projects_list"])
    assert any(
        "NOT explained by read-only mode" in note and "capella_backups_list" in note
        for note in run.notes
    )


def test_a_write_tool_with_no_op_record_is_still_recognised_as_a_write(monkeypatch):
    """THE DEFECT: six write tools reported as read tools that should have loaded.

    capella_env_* and capella_fixture_import are handled by environment.py and
    fixture.py and have no Op record, so a classifier reading OPS_BY_NAME could
    not see them. The annotation is on the Tool, and it is what the read-only
    filter itself reads.
    """
    _fake_spec(
        monkeypatch,
        ["capella_projects_list"],
        registered=["capella_projects_list", "capella_env_ensure", "capella_env_reap"],
        writes=["capella_env_ensure", "capella_env_reap"],
    )
    run = _run()
    run._crosscheck_registry(["capella_projects_list"])
    assert not any("NOT explained" in n for n in run.notes)
    note = next(n for n in run.notes if "not advertised in this posture" in n)
    assert "2 of them are write tools" in note


def test_absent_write_tools_are_counted_as_the_filter_working(monkeypatch):
    """Fifty-three missing write tools under read-only mode is not drift.

    The first live run reported the count with no reason attached, which reads as
    a problem. It is the read-only filter doing exactly what it is for.
    """
    _fake_spec(
        monkeypatch,
        ["capella_projects_list", "capella_bucket_create", "capella_bucket_delete"],
        writes=["capella_bucket_create", "capella_bucket_delete"],
    )
    run = _run()
    run._crosscheck_registry(["capella_projects_list"])
    note = next(n for n in run.notes if "not advertised in this posture" in n)
    assert "2 of them are write tools" in note
    assert not any("NOT explained" in n for n in run.notes)


def test_the_environment_and_fixture_tools_are_not_reported_as_strays(monkeypatch):
    """THE DEFECT, from the first live run: seven false strays.

    capella_env_*, capella_fixture_* and capella_guardrails_status are handled by
    environment.py and fixture.py and have no Op record, so comparing against
    spec.OPS_BY_NAME alone reported every one of them as advertised by nobody.
    handlers.capella.TOOLS is what the server actually registers.
    """
    _fake_spec(
        monkeypatch,
        ["capella_projects_list"],
        registered=[
            "capella_projects_list",
            "capella_env_list",
            "capella_fixture_list",
            "capella_guardrails_status",
        ],
    )
    run = _run()
    run._crosscheck_registry(
        [
            "capella_projects_list",
            "capella_env_list",
            "capella_fixture_list",
            "capella_guardrails_status",
        ]
    )
    assert not any(
        "stray" in note or "registered by no handler" in note for note in run.notes
    )


def test_a_capella_tool_registered_by_no_handler_is_named(monkeypatch):
    """The other direction: advertised and belonging to nothing the server knows."""
    _fake_spec(monkeypatch, ["capella_projects_list"])
    run = _run()
    run._crosscheck_registry(["capella_projects_list", "capella_mystery_get"])
    assert any("capella_mystery_get" in note for note in run.notes)


def test_a_non_capella_tool_is_not_reported_as_a_stray(monkeypatch):
    """admin_* tools have no entry in the Capella registry and never should."""
    _fake_spec(monkeypatch, ["capella_projects_list"])
    run = _run()
    run._crosscheck_registry(["capella_projects_list", "admin_bucket_list"])
    assert not any("admin_bucket_list" in note for note in run.notes)


def test_the_shipped_but_unverified_operations_are_carried_into_the_transcript(
    monkeypatch,
):
    """They are the ones a reader must not mistake for confirmed.

    A 404 from one of these may mean the path is wrong rather than the object
    absent, and an evidence file that does not say so invites the opposite reading.
    """
    _fake_spec(
        monkeypatch,
        ["capella_cluster_audit_log_export_get"],
        unverified=["capella_cluster_audit_log_export_get"],
    )
    run = _run()
    run._crosscheck_registry(["capella_cluster_audit_log_export_get"])
    assert any("unverified" in note for note in run.notes)


# ── The run as a whole ───────────────────────────────────────────────────────


def test_a_read_only_run_starts_exactly_one_server():
    """One server, read-only, no preview flag. The default shape."""
    started = []

    async def _fake_drive(run, *, read_only, dry_run, phases):
        started.append((read_only, dry_run, [p.__name__ for p in phases]))

    run = _run()
    original = vms._drive
    vms._drive = _fake_drive
    try:
        assert asyncio.run(vms.run_all(run)) == 0
    finally:
        vms._drive = original

    assert started == [
        (True, False, ["phase_protocol", "phase_discovery", "phase_reads"])
    ]


def test_the_write_preview_starts_a_second_server_rather_than_reconfiguring_the_first():
    """Read-only mode and the dry-run flag are read at import or from the
    environment. Flipping them inside a running process is not something the
    server supports, so asking it to would test a configuration that cannot occur.
    """
    started = []

    async def _fake_drive(run, *, read_only, dry_run, phases):
        started.append((read_only, dry_run))

    run = _run(write_preview=True)
    original = vms._drive
    vms._drive = _fake_drive
    try:
        asyncio.run(vms.run_all(run))
    finally:
        vms._drive = original

    assert started == [(True, False), (False, True)]


def test_the_context_discovered_by_the_read_phase_survives_into_the_write_phase():
    """The write phase resolves arguments from the same context.

    Rebuilding it would mean a second discovery pass against the same cluster, and
    losing it would make every write tool unresolvable and therefore skipped —
    which would look like a clean run.
    """

    async def _fake_drive(run, *, read_only, dry_run, phases):
        if read_only:
            run.context["project_id"] = "proj-1"
        else:
            assert run.context["project_id"] == "proj-1"

    run = _run(write_preview=True)
    original = vms._drive
    vms._drive = _fake_drive
    try:
        asyncio.run(vms.run_all(run))
    finally:
        vms._drive = original
    assert run.context["project_id"] == "proj-1"


# ── The missing-client failure ───────────────────────────────────────────────


def test_a_missing_mcp_client_fails_before_the_banner_and_names_uv(monkeypatch):
    """THE DEFECT. The import lives inside _drive, so this arrived as a traceback
    several screens below a header announcing the repository, the interpreter and
    a correlation id — which reads as "the server failed to start", the one thing
    it does not mean.

    And it happens on the obvious command: this repository's dependencies are
    uv-managed, so `python scripts\\verify_mcp_surface.py` runs under whatever is
    on PATH, which has neither `mcp` nor `couchbase`.
    """
    import importlib.util

    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name: None if name == "mcp" else importlib.util.find_spec(name),
    )
    with pytest.raises(SystemExit) as raised:
        vms.main([])
    message = str(raised.value)
    assert "uv run python" in message
    assert "mcp" in message


def test_the_check_passes_when_the_client_is_importable():
    """It must not fire on the ordinary path, where it would be a new failure mode."""
    vms._require_mcp_client()


def test_the_client_check_runs_before_any_output_is_opened(monkeypatch, tmp_path):
    """--out must not leave a truncated transcript behind when the run never began.

    open_output() truncates, so a file created and then abandoned is worse than no
    file: it reads as a run that produced nothing rather than one that never
    started.
    """
    import importlib.util

    target = tmp_path / "evidence.txt"
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name: None if name == "mcp" else importlib.util.find_spec(name),
    )
    with pytest.raises(SystemExit):
        vms.main(["--out", str(target)])
    assert not target.exists()


# ── Which bucket the run points at ───────────────────────────────────────────


def test_a_sample_bucket_is_chosen_over_the_one_with_real_data():
    """THE DEFECT, found on the first live run.

    Discovery picked `harvester` — the bucket holding the customer data — because
    it was simply the first non-system row. Nothing was at risk: the read phase
    only reads and the server redacts on the way out. But a tool checking whether
    a surface dispatches has no business selecting that bucket when travel-sample
    is on the same cluster. Least sensitive thing that exercises the same path.
    """
    run = _run()
    rows = [
        {"id": "sys", "name": "N1QL_SYSTEM_BUCKET"},
        {"id": "harv", "name": "harvester"},
        {"id": "supp", "name": "supportal"},
        {"id": "trav", "name": "travel-sample"},
    ]
    assert run._choose("capella_buckets_list", rows, "id") == "trav"


def test_a_real_bucket_is_still_chosen_when_no_sample_bucket_exists():
    """A thin run beats no run. Most clusters carry no sample bucket at all."""
    run = _run()
    rows = [{"id": "sys", "name": "_system"}, {"id": "harv", "name": "harvester"}]
    assert run._choose("capella_buckets_list", rows, "id") == "harv"


def test_an_explicitly_named_bucket_wins_over_the_preference():
    run = _run(bucket="harvester")
    rows = [
        {"id": "trav", "name": "travel-sample"},
        {"id": "harv", "name": "harvester"},
    ]
    assert run._choose("capella_buckets_list", rows, "id") == "harv"


def test_a_named_bucket_that_is_absent_is_reported_rather_than_ignored():
    """Silently falling back would point the run somewhere the caller did not ask
    for while the transcript showed the bucket they named nowhere at all."""
    run = _run(bucket="not-on-this-cluster")
    rows = [{"id": "trav", "name": "travel-sample"}]
    assert run._choose("capella_buckets_list", rows, "id") == "trav"
    assert any("not-on-this-cluster" in note for note in run.notes)


def test_the_bucket_preference_does_not_leak_into_other_selections():
    """`travel-sample` is not a cluster name. The ordering is bucket-specific."""
    run = _run()
    rows = [{"id": "c1", "name": "bride"}, {"id": "c2", "name": "travel-sample"}]
    assert run._choose("capella_clusters_list", rows, "id") == "c1"


# ── The timeout breaker ──────────────────────────────────────────────────────


def test_consecutive_timeouts_stop_the_read_phase_and_say_why():
    """Three in a row means the data plane is unreachable, not that three tools are
    broken.

    Capella DROPS packets from unlisted sources, so an SDK read on 11207 hangs
    rather than failing, and at the old 90-second default six of those in a row
    was nine minutes of silence that read as a hung script.
    """

    class _Hang:
        async def call_tool(self, name, arguments=None):
            await asyncio.sleep(5)

    run = _run(
        advertised=[_tool(f"cb_slow_{n}") for n in range(8)],
        timeout=0.01,
        max_timeouts=3,
    )
    asyncio.run(run.phase_reads(_Hang()))

    timed_out = [r for r in run.results if r.outcome == vms.TIMEOUT]
    assert len(timed_out) == 3
    assert any("READ PHASE STOPPED" in note for note in run.notes)
    # The tools it never reached are still named, not silently dropped -- and NOT
    # as "skipped", which would claim their arguments could not be resolved.
    not_reached = [r for r in run.results if r.outcome == vms.NOT_REACHED]
    assert len(not_reached) == 5
    assert not [r for r in run.results if r.outcome == vms.SKIPPED]
    assert "stopped before its turn" in not_reached[0].detail


def test_one_answer_resets_the_timeout_streak():
    """A slow tool between two working ones is not a dead data plane."""
    run = _run()
    run._consecutive_timeouts = 2
    asyncio.run(run.call(_FakeSession(), "capella_projects_list", {}, phase="read"))
    assert run._consecutive_timeouts == 0


# ── In-flight visibility ─────────────────────────────────────────────────────


def test_a_call_is_named_before_it_is_made_not_after():
    """THE DEFECT that made a working run look hung.

    The name was printed on completion, so the tool a reader was staring at was
    the last one that SUCCEEDED — which points at the wrong tool entirely. The
    same lesson as the keyspace sweep: print what is being asked, not only what
    answered.
    """
    written = []

    run = _run()
    run._out = SimpleNamespace(write=written.append, flush=lambda: None)
    run.say = lambda line="": written.append(line + "\n")

    async def _slow(name, arguments=None):
        # The name must already be on the wire at this point.
        assert any("capella_projects_list" in chunk for chunk in written)
        return _Response({"data": []})

    asyncio.run(
        run.call(
            SimpleNamespace(call_tool=_slow), "capella_projects_list", {}, phase="read"
        )
    )


def test_a_result_recorded_without_an_open_line_still_names_its_tool():
    """SKIPPED rows and protocol findings never opened a line of their own."""
    lines = []
    run = _run()
    run.say = lines.append
    run.record(vms.Result("capella_backup_get", vms.SKIPPED, "no value for backup_id"))
    assert "capella_backup_get" in lines[0]


# ── What a timeout is allowed to imply ───────────────────────────────────────


def test_a_timeout_names_the_cluster_the_server_is_pointed_at():
    """THE DEFECT, and it was mine twice in one session.

    cb_get_schema_for_collection hung, and I read it as evidence about the
    corporate VPN — once with the tunnel up, and again after being told it was
    down. Both times the reading was an inference laid over a blank.

    The SDK tools default to couchbase://localhost when CB_CONNECTION_STRING is
    unset, and a connection to a cluster that is not there blocks exactly as a
    firewalled one does. The detail line now answers the question rather than
    inviting a theory about it.
    """
    run = _run()
    run.status = {"connection": {"connection_string": "couchbase://localhost"}}

    class _Hang:
        async def call_tool(self, name, arguments=None):
            await asyncio.sleep(5)

    run.args.timeout = 0.01
    _payload, result = asyncio.run(
        run.call(_Hang(), "cb_get_schema_for_collection", {}, phase="read")
    )
    assert result.outcome == vms.TIMEOUT
    assert "couchbase://localhost" in result.detail


def test_a_timeout_without_a_status_payload_claims_nothing():
    """When the connection is unknown the line must not invent a cause.

    Saying "the data plane is unreachable" here would be the same error in a
    different sentence.
    """
    run = _run()
    run.status = {}

    class _Hang:
        async def call_tool(self, name, arguments=None):
            await asyncio.sleep(5)

    run.args.timeout = 0.01
    _payload, result = asyncio.run(run.call(_Hang(), "cb_thing", {}, phase="read"))
    assert "says nothing about the tool" in result.detail
    for word in ("VPN", "tunnel", "firewall", "allowlist"):
        assert word not in result.detail


def test_the_breaker_note_points_at_the_connection_string_first():
    """The cheapest check comes first, and it is not a network one."""

    class _Hang:
        async def call_tool(self, name, arguments=None):
            await asyncio.sleep(5)

    run = _run(
        advertised=[_tool(f"cb_slow_{n}") for n in range(5)],
        timeout=0.01,
        max_timeouts=3,
    )
    run.status = {"connection": {"connection_string": "couchbase://localhost"}}
    asyncio.run(run.phase_reads(_Hang()))

    note = next(n for n in run.notes if "READ PHASE STOPPED" in n)
    assert "CB_CONNECTION_STRING" in note
    assert "couchbase://localhost" in note


# ── Not reached is not skipped ───────────────────────────────────────────────


def test_a_tool_abandoned_by_the_breaker_is_not_reported_as_unresolvable():
    """THE DEFECT, from the first full live run.

    Three cb_* diagnostics hung, the breaker fired, and the forty-eight
    control-plane tools after them in the advertised order were reported as
    "skipped — no value for" with an empty list after it. Their arguments had
    resolved fine; their turn never came.

    That understates coverage and points the reader at the registry instead of at
    the timeout, which is the same class of error as counting a skip as a pass.
    """

    class _Hang:
        async def call_tool(self, name, arguments=None):
            await asyncio.sleep(5)

    run = _run(
        advertised=[_tool(f"cb_get_slow_{n}") for n in range(5)],
        timeout=0.01,
        max_timeouts=3,
    )
    asyncio.run(run.phase_reads(_Hang()))

    abandoned = [r for r in run.results if r.outcome == vms.NOT_REACHED]
    assert len(abandoned) == 2
    assert not [r for r in run.results if r.outcome == vms.SKIPPED]
    assert "no value for" not in abandoned[0].detail


def test_a_hanging_data_plane_no_longer_costs_the_control_plane_run():
    """The whole point of the reordering, stated as a behaviour.

    Before it, admin_prometheus_targets was followed by three cb_* diagnostics,
    they hung, the breaker fired, and every control-plane tool after them was
    abandoned — forty-eight of them, each of which would have answered in under a
    second.
    """

    class _Mixed:
        def __init__(self):
            self.calls = []

        async def call_tool(self, name, arguments=None):
            self.calls.append(name)
            if name.startswith("cb_get_"):
                await asyncio.sleep(5)
            return _Response({"data": [{"id": "x"}]})

    session = _Mixed()
    run = _run(
        advertised=[_tool(f"cb_get_slow_{n}") for n in range(4)]
        + [_tool("capella_guardrails_status"), _tool("capella_projects_list")],
        timeout=0.01,
        max_timeouts=3,
    )
    asyncio.run(run.phase_reads(session))

    assert "capella_guardrails_status" in session.calls
    assert "capella_projects_list" in session.calls
    answered = {r.tool for r in run.results if r.outcome in vms._SUCCESSFUL}
    assert {"capella_guardrails_status", "capella_projects_list"} <= answered


def test_no_skip_reason_is_ever_an_empty_list():
    """ "no value for " with nothing after it is not a reason, it is a bug telling
    on itself — and it shipped."""
    run = _run(
        advertised=[
            _tool("capella_x", properties={"a": {}}, required=["a"]),
            _tool("capella_y"),
        ]
    )
    session = _FakeSession(default={"data": []})
    asyncio.run(run.phase_reads(session))
    for result in run.results:
        if result.outcome in (vms.SKIPPED, vms.NOT_REACHED):
            assert not result.detail.rstrip().endswith("for")


def test_the_data_plane_tools_run_after_the_control_plane_ones():
    """Ordering was accidental and cost a whole run.

    The tools most likely to hang are also the least informative about the surface
    under test, so they are the ones to run once everything else is recorded. A
    hanging cluster then truncates the tail rather than the middle.
    """
    ordered = vms._read_order(
        [
            _tool("cb_get_schema_for_collection"),
            _tool("capella_projects_list"),
            _tool("cb_perf_longest_running"),
            _tool("capella_cluster_get"),
        ]
    )
    names = [t.name for t in ordered]
    assert names.index("capella_projects_list") < names.index(
        "cb_get_schema_for_collection"
    )
    assert names.index("capella_cluster_get") < names.index("cb_perf_longest_running")


def test_the_read_order_is_stable_within_each_group():
    """Two tools of the same kind keep their advertised order, so a run is
    reproducible and two transcripts can be diffed."""
    tools = [_tool(n) for n in ("capella_b", "capella_a", "cb_get_b", "cb_get_a")]
    assert [t.name for t in vms._read_order(tools)] == [
        "capella_b",
        "capella_a",
        "cb_get_b",
        "cb_get_a",
    ]


# ── Saying it before the run, not during ─────────────────────────────────────


def test_an_unset_connection_string_is_called_out_in_the_protocol_phase():
    """THE DEFECT, and the expensive one.

    CB_CONNECTION_STRING defaults to couchbase://localhost, which is the normal
    state for a server configured for Capella — the control plane needs no
    connection string at all. Every cb_* diagnostic then blocks on a cluster that
    does not exist.

    That cost a run, and then it cost something worse: the hang was read as
    evidence about the corporate network twice, once in each direction. The
    information was already in the cb_mcp_status payload the protocol phase had
    just fetched. Nothing was missing except the sentence.
    """
    tools = [_tool("cb_mcp_status"), _tool("cb_get_schema_for_collection")]
    session = _FakeSession(
        advertises=tools,
        answers={
            "cb_mcp_status": {
                "tools": {"registered": 2, "loaded": 2, "filtered_out": 0},
                "safety": {"read_only_mode": True},
                "connection": {"connection_string": "couchbase://localhost"},
            }
        },
    )
    run = _run()
    asyncio.run(run.phase_protocol(session))

    note = next(n for n in run.notes if "CB_CONNECTION_STRING" in n)
    assert "NOT the network" in note
    # It must not claim the variable is unset: a server explicitly pointed at
    # couchbase://localhost looks identical from here.
    assert "is not set" not in note
    assert "--only capella_" in note
    assert "CB_BUCKET" in note
    # It must NAME the configuration and offer candidates, not declare a cause.
    # Something was in fact listening on 11210 on the machine this was written
    # for — several local clusters, as it turned out — and every wrong reading in
    # this investigation came from a line like this asserting one.
    assert "indistinguishable" in note
    assert "If they time out" in note


def test_no_such_warning_when_the_server_points_at_a_real_cluster():
    """It must not fire on a configured server, where it would be noise."""
    tools = [_tool("cb_mcp_status"), _tool("cb_get_schema_for_collection")]
    session = _FakeSession(
        advertises=tools,
        answers={
            "cb_mcp_status": {
                "tools": {},
                "safety": {},
                "connection": {
                    "connection_string": "couchbases://cb.example.cloud.couchbase.com"
                },
            }
        },
    )
    run = _run()
    asyncio.run(run.phase_protocol(session))
    assert not any("CB_CONNECTION_STRING" in n for n in run.notes)


def test_no_such_warning_when_no_data_plane_tool_is_advertised():
    """A control-plane-only posture has nothing to dial, so the warning would be
    describing a problem that cannot occur."""
    tools = [_tool("cb_mcp_status"), _tool("capella_projects_list")]
    session = _FakeSession(
        advertises=tools,
        answers={
            "cb_mcp_status": {
                "tools": {},
                "safety": {},
                "connection": {"connection_string": "couchbase://localhost"},
            }
        },
    )
    run = _run()
    asyncio.run(run.phase_protocol(session))
    assert not any("CB_CONNECTION_STRING" in n for n in run.notes)


# ── Two vocabularies, one context ────────────────────────────────────────────


def test_the_capella_bucket_is_not_written_into_the_self_managed_key():
    """`bucket` and `bucket_name` are two vocabularies, not two spellings.

    v4 keyspace query parameters are `bucket`/`scope`/`collection`; ns_server
    addresses a bucket as `bucket_name`. Writing the Capella bucket into
    `bucket_name` sent every self-managed tool in a `both`-mode run looking for
    travel-sample on the local cluster — a screenful of 404s that read as broken
    tools. Found before the run rather than in it, for once.
    """
    run = _run(advertised=[_tool("capella_scopes_list")])
    run.context.update(
        {
            "cluster_id": "c",
            "bucket_id": "dHJhdmVsLXNhbXBsZQ==",
            "bucket_name": "mcptest",
        }
    )
    session = _FakeSession(
        answers={
            "capella_scopes_list": {
                "scopes": [{"name": "inventory", "collections": [{"name": "route"}]}]
            }
        }
    )
    asyncio.run(run._discover_keyspace(session, {"capella_scopes_list"}))

    assert run.context["bucket"] == "travel-sample"
    assert run.context["bucket_name"] == "mcptest"


def test_a_scope_discovered_by_the_self_managed_side_is_not_overwritten():
    """First writer wins, and the alternative is worse than either choice.

    Overwriting meant whichever discovery step ran last silently decided what the
    other side would be asked for.
    """
    run = _run(advertised=[_tool("capella_scopes_list")])
    run.context.update(
        {
            "cluster_id": "c",
            "bucket_id": "dHJhdmVsLXNhbXBsZQ==",
            "scope_name": "local_scope",
            "collection_name": "local_collection",
        }
    )
    session = _FakeSession(
        answers={
            "capella_scopes_list": {
                "scopes": [{"name": "inventory", "collections": [{"name": "route"}]}]
            }
        }
    )
    asyncio.run(run._discover_keyspace(session, {"capella_scopes_list"}))

    assert run.context["scope"] == "inventory"
    assert run.context["scope_name"] == "local_scope"
    assert run.context["collection_name"] == "local_collection"


# ── Honouring the server's own configuration ─────────────────────────────────


def test_the_cluster_side_uses_cb_bucket_when_one_is_configured(monkeypatch):
    """THE DEFECT: CB_BUCKET=mcptest was set and every admin_* read went to harvester.

    CB_BUCKET is what the SERVER was configured with, so it is the bucket the
    cluster-side tools will actually be asked about. Discovery picking the first
    non-system row instead is arbitrary, and it was not what anyone asked for.
    """
    monkeypatch.setenv("CB_BUCKET", "mcptest")
    run = _run()
    rows = [
        {"id": "h", "name": "harvester"},
        {"id": "m", "name": "mcptest"},
        {"id": "s", "name": "supportal"},
    ]
    assert run._choose("admin_bucket_list", rows, "id") == "m"


def test_cb_bucket_does_not_steer_the_capella_side(monkeypatch):
    """It names a bucket on the SELF-MANAGED cluster. The two are unrelated, and a
    Capella cluster that happens to share the name would be a coincidence."""
    monkeypatch.setenv("CB_BUCKET", "mcptest")
    run = _run()
    rows = [{"id": "t", "name": "travel-sample"}, {"id": "m", "name": "mcptest"}]
    assert run._choose("capella_buckets_list", rows, "id") == "t"


def test_an_explicit_bucket_flag_still_beats_the_environment(monkeypatch):
    monkeypatch.setenv("CB_BUCKET", "mcptest")
    run = _run(bucket="supportal")
    rows = [{"id": "m", "name": "mcptest"}, {"id": "s", "name": "supportal"}]
    assert run._choose("admin_bucket_list", rows, "id") == "s"


# ── --out must not mean a silent terminal ────────────────────────────────────


def test_writing_to_a_file_still_shows_progress_on_the_terminal(tmp_path, capsys):
    """A run that was working looked like one that had returned instantly.

    --out sent every line to the file and left the console empty, which is
    indistinguishable from a crash and from a run that is genuinely slow. stderr
    rather than stdout, because stdout carries the --json payload.
    """
    target = tmp_path / "evidence.txt"
    run = _run(out=str(target))
    del run.say  # the helper silences it; this test is about the real one
    run.open_output()
    try:
        run.say("== reads ==")
    finally:
        run.close_output()

    assert "== reads ==" in target.read_text(encoding="utf-8")
    assert "== reads ==" in capsys.readouterr().err


def test_nothing_is_mirrored_when_the_transcript_is_already_the_terminal(capsys):
    """Otherwise every line would appear twice."""
    run = _run()
    del run.say  # as above
    run.open_output()
    run.say("once")
    captured = capsys.readouterr()
    assert captured.out.count("once") == 1
    assert "once" not in captured.err


# ── Ids that were already on screen ──────────────────────────────────────────


def test_an_id_is_read_from_whichever_field_the_api_used():
    """v4 does not name its ids uniformly.

    Audit-log exports come back as `exportId` in some shapes and `id` in others,
    and a single-field lookup guessing wrong is a silent empty discovery rather
    than an error — the tool depending on it just reports "no value for".
    """
    run = _run()
    rows = [{"exportId": "exp-1"}]
    assert (
        run._choose("capella_cluster_audit_log_exports_list", rows, ("exportId", "id"))
        == "exp-1"
    )
    rows = [{"id": "exp-2"}]
    assert (
        run._choose("capella_cluster_audit_log_exports_list", rows, ("exportId", "id"))
        == "exp-2"
    )


def test_the_index_and_export_ids_are_harvested_at_all():
    """THE DEFECT, visible in a live transcript.

    capella_query_index_definitions_list returned 8 rows and
    capella_cluster_audit_log_exports_list returned 1, and three tools two lines
    later reported "no value for index_name / export_id". The ids were on screen.

    One of those three is capella_cluster_audit_log_export_get — the only
    shipped-but-unverified operation left in the registry.
    """
    filled = {key for _tool, key, _field in vms._DISCOVERY}
    assert "index_name" in filled
    assert "export_id" in filled


def test_a_bucket_preference_still_works_with_candidate_fields():
    """The preference ordering reads the id through the same accessor."""
    run = _run()
    rows = [{"id": "h", "name": "harvester"}, {"id": "t", "name": "travel-sample"}]
    assert run._choose("capella_buckets_list", rows, "id") == "t"


# ── --only must mean only ────────────────────────────────────────────────────


def test_the_only_filter_restricts_discovery_as_well_as_reads():
    """An evidence file for one deployment must not carry the other's failures.

    `--only capella_` restricted the read phase but not the discovery loop, so the
    run still called admin_backup_repository_list and admin_eventing_list and
    counted their 404s — two of the three UPSTREAM results in a file whose whole
    purpose was to show the Capella surface.
    """
    run = _run(
        advertised=[_tool("capella_projects_list"), _tool("admin_bucket_list")],
        only="capella_",
    )
    session = _FakeSession(default={"data": [{"id": "x", "name": "n"}]})
    asyncio.run(run.phase_discovery(session))
    assert "admin_bucket_list" not in {name for name, _ in session.calls}


# ── Harvest-only entries ─────────────────────────────────────────────────────


def test_a_harvest_only_tool_is_not_called_during_discovery():
    """THE DEFECT: I moved a working tool to the one place it could not work.

    capella_query_index_definitions_list takes bucket/scope/collection as OPTIONAL
    query parameters, so the resolver sees nothing missing and calls it — but the
    keyspace is resolved at the END of discovery, so it goes out without a bucket
    and answers 400. In the read phase it has the keyspace and returns rows.

    "Its required arguments resolve" is not "it will succeed here", and the
    resolver cannot tell the difference for an optional parameter the API treats
    as mandatory.
    """
    run = _run(
        advertised=[
            _tool("capella_projects_list"),
            _tool("capella_query_index_definitions_list"),
        ]
    )
    session = _FakeSession(default={"data": [{"id": "x", "name": "n"}]})
    asyncio.run(run.phase_discovery(session))
    assert "capella_query_index_definitions_list" not in {
        name for name, _ in session.calls
    }


def test_a_harvest_only_tool_still_fills_context_from_the_read_phase():
    """It is excluded from the loop, not from the mechanism."""
    run = _run(advertised=[_tool("capella_query_index_definitions_list")])
    run._harvest(
        "capella_query_index_definitions_list",
        {"definitions": [{"indexName": "ix_trial_count"}]},
    )
    assert run.context["index_name"] == "ix_trial_count"


# ── Saying why a selection failed ────────────────────────────────────────────


def test_a_failed_selection_reports_the_keys_that_were_actually_there():
    """ "returned nothing to select" covers two situations and only one is normal.

    An empty list is normal. Rows that carry none of the named fields is a wrong
    field name — and the answer is in the row that was just parsed. Throwing it
    away meant the next step was another guess at the spelling, which is how
    `exportId` and `id` were both tried and both wrong.
    """
    run = _run()
    message = run._nothing_to_select(
        [{"auditLogExportId": "e1", "status": "done"}], ("exportId", "id")
    )
    assert "auditLogExportId" in message
    assert "exportId/id" in message


def test_an_empty_list_says_so_rather_than_blaming_the_field_name():
    run = _run()
    assert run._nothing_to_select([], ("id",)) == "returned no rows"


def test_a_harvest_that_cannot_select_says_why_too():
    """A silent failure moved rather than being fixed.

    Putting a tool in _HARVEST_ONLY took it out of the loop that reports a failed
    selection, so a wrong field name went quiet again: the tool answered `ok`, the
    context stayed empty, and the dependent tool reported "no value for" with
    nothing pointing at the cause. Every place that selects must be able to say
    why it could not.
    """
    lines = []
    run = _run()
    run.say = lines.append
    run._harvest(
        "capella_cluster_audit_log_exports_list",
        {"data": [{"auditLogDownloadId": "x", "status": "complete"}]},
    )
    assert "export_id" not in run.context
    assert any("auditLogDownloadId" in line for line in lines)


def test_a_harvest_with_no_rows_stays_quiet():
    """An empty list is normal and does not need a line in the transcript."""
    lines = []
    run = _run()
    run.say = lines.append
    run._harvest("capella_cluster_audit_log_exports_list", {"data": []})
    assert lines == []


def test_the_audit_export_id_is_read_from_the_field_the_list_actually_uses():
    """`auditLogExportId`, confirmed against the live response on 2026-09-12.

    `exportId` and `id` were both guessed and both wrong. The create response and
    the list response spell it differently, which is why the field is a tuple --
    and why a failed selection prints the row's keys instead of inviting a third
    guess.
    """
    run = _run()
    rows = [
        {
            "auditLogExportId": "8e632720-243e-43d1-9ae1-b3032a9a0676",
            "status": "no audit log files exist within the requested time frame",
        }
    ]
    entry = next(
        e for e in vms._DISCOVERY if e[0] == "capella_cluster_audit_log_exports_list"
    )
    assert run._choose(entry[0], rows, entry[2]) == (
        "8e632720-243e-43d1-9ae1-b3032a9a0676"
    )


def test_a_non_json_response_reports_what_it_actually_said():
    """THE DEFECT: 86 write-phase failures all reading "no JSON payload".

    The pattern — every *_create failing while every *_update and *_delete passed
    — pointed at argument validation rejecting the call before dispatch, which
    would be the schema working rather than the server failing. But the message
    discarded the response, so the category was all anyone had.

    Severity stays: it is still a failure until the text says otherwise. What
    changes is that the text is there to read.
    """
    outcome, detail = vms.classify(
        None,
        phase="write",
        text="Input validation error: 'body' is a required property",
    )
    assert outcome == vms.PROTOCOL
    assert "body" in detail and "required" in detail


def test_a_truly_empty_response_says_that_instead():
    outcome, detail = vms.classify(None, phase="read", text="   ")
    assert outcome == vms.PROTOCOL
    assert "no content at all" in detail


def test_the_raw_text_survives_alongside_the_parsed_payload():
    response = SimpleNamespace(content=[SimpleNamespace(text='{"ok": true}')])

    text, payload = vms._text_and_payload(response)
    assert payload == {"ok": True}
    assert text == '{"ok": true}'


def test_a_write_tool_with_no_synthesisable_body_is_skipped_not_failed():
    """THE DEFECT, and the one that misrepresented the server.

    The write phase sent partial arguments on the reasoning that the confirmation
    gate runs before the handler. True of the server, false of the path to it: the
    MCP SDK validates against the input schema first, so a *_create with no
    synthesisable body is rejected upstream of the gate and never tests it.

    Reported as PROTOCOL, that produced 41 entries reading like failures of
    operations verify_capella_paths.py had already confirmed live with method
    probes. The tools were fine. The harness cannot invent a bucket spec.
    """
    run = _run(
        advertised=[
            _tool(
                "capella_bucket_create",
                read_only=False,
                properties={"project_id": {}, "body": {}},
                required=["project_id", "body"],
            )
        ]
    )
    run.contexts[vms.CAPELLA_SIDE]["project_id"] = "p1"
    run.status = {
        "safety": {
            "read_only_mode": False,
            "dry_run": {"server_wide": True, "handler_owned": []},
        }
    }
    session = _FakeSession()
    asyncio.run(run.phase_writes(session))

    assert session.calls == []
    result = next(r for r in run.results if r.tool == "capella_bucket_create")
    assert result.outcome == vms.SKIPPED
    assert result.outcome not in vms._HARD_FAILURES
    assert "body" in result.detail and "Level 3" in result.detail


def test_a_write_tool_whose_arguments_resolve_is_still_exercised():
    """The skip must not swallow the tools that CAN be tested."""
    run = _run(
        advertised=[
            _tool(
                "capella_bucket_delete",
                read_only=False,
                properties={"bucket_id": {}},
                required=["bucket_id"],
            )
        ]
    )
    run.contexts[vms.CAPELLA_SIDE]["bucket_id"] = "b1"
    run.status = {
        "safety": {
            "read_only_mode": False,
            "dry_run": {"server_wide": True, "handler_owned": []},
        }
    }
    gated = {
        "error": "Confirmation required",
        "requires_confirmation": True,
        "_is_error": True,
    }
    preview = {"dry_run": True, "executed": False, "tool": "capella_bucket_delete"}
    session = _FakeSession(
        answers={"capella_bucket_delete": lambda n: gated if n == 1 else preview}
    )
    asyncio.run(run.phase_writes(session))
    assert len(session.calls) == 2


# ── Body synthesis ───────────────────────────────────────────────────────────


def test_a_required_body_is_built_from_the_shipped_schema():
    """The 41 "cannot synthesise" skips, closed from the registry rather than by hand.

    Every write op in spec.py already declares `body` as a map of JSON-schema
    properties plus `body_required`. Hand-written fixtures would restate that and
    drift from it silently.
    """
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "memoryAllocationInMb": {"type": "integer", "minimum": 100},
            "flush": {"type": "boolean"},
        },
        "required": ["name", "memoryAllocationInMb", "flush"],
    }
    body, guessed = vms.synthesise_body(schema, {}, "mcptest")
    assert body["name"] == "mcptest-name"
    assert body["memoryAllocationInMb"] == 100
    assert body["flush"] is False
    assert guessed == ["name"]


def test_a_discovered_value_beats_an_invented_one():
    schema = {"properties": {"bucketId": {"type": "string"}}, "required": ["bucketId"]}
    body, guessed = vms.synthesise_body(schema, {"bucketId": "real-id"}, "mcptest")
    assert body["bucketId"] == "real-id"
    assert guessed == []


def test_an_enum_takes_a_real_member_rather_than_a_guess():
    """A closed set has no room for invention, so this is not a guess and is not
    reported as one."""
    schema = {
        "properties": {"plan": {"type": "string", "enum": ["basic", "developer pro"]}},
        "required": ["plan"],
    }
    body, guessed = vms.synthesise_body(schema, {}, "mcptest")
    assert body["plan"] == "basic"
    assert guessed == []


def test_a_boolean_is_always_false():
    """False, never True.

    Several booleans here widen an operation. `forceUpdates` on a restore
    overwrites documents in the target even where the target's copy is newer —
    the flag that turns a restore into data loss. The safe value is also the
    honest default.
    """
    schema = {
        "properties": {"forceUpdates": {"type": "boolean"}},
        "required": ["forceUpdates"],
    }
    body, _ = vms.synthesise_body(schema, {}, "mcptest")
    assert body["forceUpdates"] is False


def test_an_invented_identifier_is_obviously_not_a_real_one():
    """A fabricated UUID reads as a real one in a transcript six weeks later."""
    schema = {
        "properties": {"sourceClusterId": {"type": "string"}},
        "required": ["sourceClusterId"],
    }
    body, guessed = vms.synthesise_body(schema, {}, "mcptest")
    assert "NOT-A-REAL" in body["sourceClusterId"]
    assert "sourceClusterId" in guessed


def test_a_nested_object_is_built_recursively():
    schema = {
        "properties": {
            "cloudProvider": {
                "type": "object",
                "properties": {"type": {"type": "string", "enum": ["aws"]}},
                "required": ["type"],
            }
        },
        "required": ["cloudProvider"],
    }
    body, _ = vms.synthesise_body(schema, {}, "mcptest")
    assert body["cloudProvider"] == {"type": "aws"}


def test_a_self_referential_schema_is_reported_not_recursed_forever():
    schema: dict = {"properties": {}, "required": ["loop"]}
    schema["properties"]["loop"] = schema
    _body, guessed = vms.synthesise_body(schema, {}, "mcptest")
    assert guessed


def test_optional_properties_are_left_out():
    """Minimal means minimal. Supplying an optional field changes what the call
    means, which is the same rule the read phase follows."""
    schema = {
        "properties": {"name": {"type": "string"}, "description": {"type": "string"}},
        "required": ["name"],
    }
    body, _ = vms.synthesise_body(schema, {}, "mcptest")
    assert set(body) == {"name"}


def test_a_missing_path_id_is_never_synthesised():
    """The safety line, asserted directly.

    Bodies are payload and are never routed. Path ids are targets and always are.
    Inventing a cluster_id would preview a call against a cluster that does not
    exist, and without the dry run it would be a real request to a fabricated path.
    """
    run = _run(
        advertised=[
            _tool(
                "capella_cluster_get_thing",
                read_only=False,
                properties={"cluster_id": {}},
                required=["cluster_id"],
            )
        ]
    )
    run.status = {
        "safety": {
            "read_only_mode": False,
            "dry_run": {"server_wide": True, "handler_owned": []},
        }
    }
    session = _FakeSession()
    asyncio.run(run.phase_writes(session))
    assert session.calls == []
    assert [r.outcome for r in run.results] == [vms.SKIPPED]


def test_a_synthesised_body_lets_the_gate_be_exercised():
    run = _run(
        advertised=[
            _tool(
                "capella_bucket_create",
                read_only=False,
                properties={
                    "project_id": {},
                    "body": {
                        "type": "object",
                        "properties": {"name": {"type": "string"}},
                        "required": ["name"],
                    },
                },
                required=["project_id", "body"],
            )
        ]
    )
    run.contexts[vms.CAPELLA_SIDE]["project_id"] = "p1"
    run.status = {
        "safety": {
            "read_only_mode": False,
            "dry_run": {"server_wide": True, "handler_owned": []},
        }
    }
    gated = {
        "error": "Confirmation required",
        "requires_confirmation": True,
        "_is_error": True,
    }
    preview = {"dry_run": True, "executed": False, "tool": "capella_bucket_create"}
    session = _FakeSession(
        answers={"capella_bucket_create": lambda n: gated if n == 1 else preview}
    )
    asyncio.run(run.phase_writes(session))

    assert len(session.calls) == 2
    assert session.calls[0][1]["body"] == {"name": "mcptest-name"}


def test_the_transcript_says_the_body_was_invented():
    """A preview reached with an invented body proves the GATE and the DISPATCH.

    It does not prove the body is one Capella would accept. Saying otherwise is
    exactly the conflation this script keeps finding in its own output.
    """
    lines = []
    run = _run(
        advertised=[
            _tool(
                "capella_bucket_create",
                read_only=False,
                properties={
                    "body": {
                        "type": "object",
                        "properties": {"name": {"type": "string"}},
                        "required": ["name"],
                    }
                },
                required=["body"],
            )
        ]
    )
    # say() takes a default-empty argument for blank lines, so a bare
    # `lines.append` raises on the first one.
    run.say = lambda line="": lines.append(line)
    run.status = {
        "safety": {
            "read_only_mode": False,
            "dry_run": {"server_wide": True, "handler_owned": []},
        }
    }
    gated = {"error": "c", "requires_confirmation": True, "_is_error": True}
    preview = {"dry_run": True, "executed": False, "tool": "capella_bucket_create"}
    session = _FakeSession(
        answers={"capella_bucket_create": lambda n: gated if n == 1 else preview}
    )
    asyncio.run(run.phase_writes(session))
    assert any("schema validity NOT proven" in line for line in lines)


def test_a_missing_object_and_a_missing_body_get_different_reasons():
    """Conflating them misdirects the fix.

    A missing BODY is a limitation of this script. A missing ID is a fact about
    the environment, fixed by creating the object. "cannot synthesise
    app_service_id — provable only with a real body" said body when it meant
    object, and pointed at the wrong remedy.
    """
    run = _run(
        advertised=[
            _tool(
                "capella_app_service_delete",
                read_only=False,
                properties={"app_service_id": {}},
                required=["app_service_id"],
            )
        ]
    )
    run.status = {
        "safety": {
            "read_only_mode": False,
            "dry_run": {"server_wide": True, "handler_owned": []},
        }
    }
    asyncio.run(run.phase_writes(_FakeSession()))
    detail = next(
        r for r in run.results if r.tool == "capella_app_service_delete"
    ).detail
    assert "no app_service_id exists on this cluster" in detail
    assert "body" not in detail


# ── Nothing here may pass vacuously ──────────────────────────────────────────
#
# Every test above asserts inside a `for` over one of these collections, so an
# empty one is a green tick rather than a failure. `test_no_vacuous_coverage.py`
# enforces that this guard exists; the floors below are what it cannot know.

def test_there_is_something_to_discover():
    """`_DISCOVERY` is the object graph the read phase walks.

    Empty means the harness resolves no identifiers, every dependent tool reports
    NOT_REACHED, and the run still exits 0 -- a clean report over nothing.
    """
    assert vms._DISCOVERY, "the discovery graph is empty"
