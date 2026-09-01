"""
`handlers/capella/spec_pending.py`: the parked v4 operations.

WHY THIS FILE EXISTS
====================
Nothing imported the pending module and nothing tested it. That is a bad combination
for a parking lot: a record sits there for weeks, and a typo in a path or a missing
tag is invisible until someone tries to promote it — at which point the mistake looks
like a live-API problem rather than a transcription one.

These checks are deliberately about SHAPE, not behaviour. The whole point of the module
is that its contents have not been confirmed against a live control plane, so there is
nothing here that asserts a path is correct. What is asserted is that every record is
well-formed, honestly tagged, and genuinely unreachable from the shipped registry.
"""

from __future__ import annotations

import re

import pytest

from handlers.capella.spec import OPS, OPS_BY_NAME, build_tools
from handlers.capella.spec_pending import PENDING_OPS

#: Provenance tags a PARKED record may carry. Both mean "sourced but not observed":
#:
#:   [DOC]  transcribed from Couchbase's published API reference
#:   [TF]   read out of the official Terraform provider's generated OpenAPI client
#:
#: [TF] joined this set when a live probe found 19 of the 36 parked paths were simply
#: wrong — /eventing/functions for /eventingFunctions, /queryIndexes/definitions for
#: /queryService/indexes, /auditLogExport for /auditLogExports. They were corrected
#: against the provider, which is generated from Couchbase's own API document and is a
#: better source than a rendered reference page. It is still not a live observation.
#:
#: [LIVE] and [LIVE+METHOD] are deliberately ABSENT: a record carrying either belongs in
#: spec.py, and one sitting here would be a half-finished promotion.
_UNVERIFIED_TAGS = ("[DOC", "[TF")


def test_every_pending_op_is_tagged_as_unverified():
    """The tag is how a reader knows a path was transcribed rather than observed.

    `[DOC` rather than `[DOC]` exactly: capella_backup_restore carries
    `[DOC — path disputed, ...]`, and a qualified tag is more informative than the bare
    one, so the convention allows it.
    """
    untagged = [
        o.name for o in PENDING_OPS if not any(t in o.summary for t in _UNVERIFIED_TAGS)
    ]
    assert not untagged, (
        f"pending ops with no {_UNVERIFIED_TAGS} tag: {untagged}. An untagged record "
        "reads as verified, which is the one thing it is not."
    )


def test_no_pending_op_claims_live_verification():
    """The failure this guards is a promotion that edited the tag and forgot to move the
    record. It would then read as verified while sitting in the registry that cannot
    reach a caller — verified and unreachable, the worst of both."""
    claiming = [o.name for o in PENDING_OPS if "[LIVE" in o.summary]
    assert not claiming, (
        f"parked records claiming live verification: {claiming}. A [LIVE] record belongs "
        "in OPS in spec.py; one here is a promotion that was started and not finished."
    )


def test_no_pending_op_leaks_into_the_shipped_registry():
    """THE property this module exists to guarantee. If a pending name became callable,
    the server would advertise a tool whose path nobody has confirmed."""
    shipped = {o.name for o in OPS}
    leaked = sorted({o.name for o in PENDING_OPS} & shipped)
    assert not leaked, f"pending ops present in the shipped registry: {leaked}"

    tool_names = {t.name for t in build_tools()}
    for op in PENDING_OPS:
        assert op.name not in tool_names, f"{op.name} is advertised as a tool"
        assert op.name not in OPS_BY_NAME, f"{op.name} is dispatchable"


def test_pending_op_names_are_unique():
    """Two records with one name means whichever is promoted second is silently lost."""
    names = [o.name for o in PENDING_OPS]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    assert not duplicates, f"duplicate pending op names: {duplicates}"


@pytest.mark.parametrize("op", PENDING_OPS, ids=lambda o: o.name)
def test_each_pending_op_is_structurally_plausible(op):
    """Catches transcription slips while they are still cheap: a path that does not
    start at /v4/organizations, an unbalanced brace, a method that is not a verb, or a
    read-only record that carries a request body."""
    assert op.path.startswith("/v4/organizations/{organization_id}"), op.path
    assert op.path.count("{") == op.path.count("}"), f"unbalanced braces: {op.path}"
    assert not op.path.endswith("/"), f"trailing slash: {op.path}"
    assert "//" not in op.path, f"double slash: {op.path}"
    assert op.method in {"GET", "POST", "PUT", "PATCH", "DELETE"}, op.method
    assert op.name.startswith("capella_"), op.name
    assert op.group, f"{op.name} has no group"
    assert op.summary.strip(), f"{op.name} has no summary"

    if op.read_only:
        assert op.method == "GET", f"{op.name} is read_only but {op.method}"
        assert not op.body, f"{op.name} is read_only but declares a body"
        assert not op.destructive, f"{op.name} is both read_only and destructive"
    if op.method == "GET":
        assert not op.destructive, f"{op.name} is a GET marked destructive"

    # Every path placeholder must be a snake_case name the schema builder can turn
    # into an argument; a camelCase slip from the reference would produce a tool
    # argument nobody can guess.
    for placeholder in re.findall(r"{(\w+)}", op.path):
        assert placeholder.islower() or "_" in placeholder, (
            f"{op.name}: path placeholder {{{placeholder}}} is not snake_case"
        )


def test_a_destructive_pending_op_is_guarded():
    """Promotion is a small edit, and the guardrail is easy to leave off. A destructive
    Capella op that is not guarded ignores the project allowlist and the name prefix."""
    unguarded = [o.name for o in PENDING_OPS if o.destructive and not o.guarded]
    assert not unguarded, f"destructive pending ops with no guardrail: {unguarded}"
