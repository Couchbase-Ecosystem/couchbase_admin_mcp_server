"""Every operation that writes to a cluster it does not name in its path must say so.

WHY THIS TEST EXISTS
====================
Twice, an operation was guarded on the wrong cluster:

    capella_backup_restore      path = SOURCE, writes body.targetClusterID
    capella_replication_create  path = SOURCE, writes body.target.cluster

Both were found by running them against a live control plane and reading the
refusal. Neither was visible from the spec, from the tests, or from `[LIVE 405]`
— an OPTIONS probe matches a route without ever learning what the route means.

The consequence was not cosmetic. `handlers/capella/__init__.py` fetches the
PATH cluster to decide ownership, so on these two operations the guard protected
the cluster being READ and left the cluster being WRITTEN unchecked. A cluster
named in CAPELLA_PROTECTED_CLUSTERS could have been the destination of a restore
or of a continuous replication, and nothing would have fired. A protection that
reads as configured and does not hold is worse than no protection, because it
stops anyone looking.

A third operation with this shape is likelier than not — the registry grows, and
Capella's resource model puts child objects under the cluster that owns them, so
"the path names the source" will keep recurring. This test is the thing that
catches the third one at review time instead of in production.

WHAT IT ASSERTS
---------------
  1. Every mutating Op whose body names a CLUSTER is registered in
     _WRITES_ELSEWHERE, or is explicitly acknowledged below with a reason.
  2. Every entry in _WRITES_ELSEWHERE still points at a real Op, whose path
     really does carry {cluster_id}, and whose body really does declare the
     field the entry names. A stale table disables the ordinary guard and
     replaces it with a lookup that finds nothing.
  3. The detector itself is not vacuous: it must still find the two known cases.
     A refactor that renames a body field would otherwise turn this file into a
     test that passes because it sees nothing.
"""

from __future__ import annotations

import re

import pytest

from handlers.capella import _WRITES_ELSEWHERE
from handlers.capella.spec import OPS, OPS_BY_NAME

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

#: A body field that names a CLUSTER. Deliberately narrow: `bucketConflictResolution`
#: and `enableBucketLevelAccess` match a loose /cluster|bucket/ and are an enum and a
#: boolean. The question is not "does this field mention a resource" but "does this
#: field hold a cluster id".
_NAMES_A_CLUSTER = re.compile(r"(?:^|\.)(?:\w*cluster(?:id)?)$", re.IGNORECASE)

#: Operations whose body names a cluster but which do NOT write to it.
#:
#: Empty, and that is the point: every known case is a real one. An entry here
#: must carry a reason, because "it looked fine" is how both bugs shipped.
ACKNOWLEDGED_SAFE: dict[str, str] = {}


def _body_fields(op) -> list[str]:
    """Top-level body field names, plus one level into nested object schemas.

    One level is enough for `target.cluster` and is where the second bug lived.
    Deeper nesting has not appeared in this registry; if it does, this test will
    not see it, which is worth knowing rather than assuming.
    """
    body = getattr(op, "body", None)
    if not isinstance(body, dict):
        return []
    found: list[str] = []
    for key, schema in body.items():
        found.append(key)
        if isinstance(schema, dict):
            nested = schema.get("properties")
            if isinstance(nested, dict):
                found.extend(f"{key}.{sub}" for sub in nested)
    return found


def _cluster_fields(op) -> list[str]:
    return [f for f in _body_fields(op) if _NAMES_A_CLUSTER.search(f)]


def _mutating_ops_naming_a_cluster() -> list[tuple[str, list[str]]]:
    out = []
    for op in OPS:
        if op.method.upper() not in MUTATING:
            continue
        fields = _cluster_fields(op)
        if fields:
            out.append((op.name, fields))
    return out


def test_the_detector_still_finds_the_two_known_cases() -> None:
    """Guard against a green run that proves nothing.

    If a field is renamed and the pattern stops matching, every other assertion
    in this file passes over an empty list. That is the failure mode this
    repository has hit before, so it is checked first and by name.
    """
    found = dict(_mutating_ops_naming_a_cluster())
    assert "capella_backup_restore" in found, (
        "the detector no longer sees capella_backup_restore's targetClusterID — "
        "either the field was renamed or _NAMES_A_CLUSTER stopped matching it. "
        "Until that is fixed this whole file is inert."
    )
    assert "capella_replication_create" in found, (
        "the detector no longer sees capella_replication_create's target.cluster."
    )


@pytest.mark.parametrize(
    "name,fields",
    _mutating_ops_naming_a_cluster(),
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_an_op_that_names_a_cluster_in_its_body_is_registered(
    name: str, fields: list[str]
) -> None:
    """The rule that both bugs broke."""
    if name in ACKNOWLEDGED_SAFE:
        assert ACKNOWLEDGED_SAFE[name].strip(), (
            f"{name} is in ACKNOWLEDGED_SAFE with an empty reason."
        )
        return
    assert name in _WRITES_ELSEWHERE, (
        f"{name} is a mutating operation whose body names a cluster "
        f"({', '.join(fields)}), but it is not in _WRITES_ELSEWHERE and not in "
        f"ACKNOWLEDGED_SAFE.\n\n"
        f"Decide which it is:\n"
        f"  - If the cluster in the body is the one this operation WRITES TO, "
        f"add it to _WRITES_ELSEWHERE in handlers/capella/__init__.py with the "
        f"path to that field. The ownership guard currently checks the cluster "
        f"in the URL, which for these operations is the one being READ.\n"
        f"  - If the body field is something else entirely, add it to "
        f"ACKNOWLEDGED_SAFE here WITH A REASON.\n\n"
        f"This has been wrong twice. Both times the guard read as configured "
        f"and protected nothing."
    )


@pytest.mark.parametrize("name", sorted(_WRITES_ELSEWHERE))
def test_every_registered_op_exists_and_still_has_the_field(name: str) -> None:
    """A stale entry is worse than a missing one.

    _WRITES_ELSEWHERE both EXEMPTS an operation from the ordinary path-cluster
    check and tells the guard where to look instead. An entry pointing at a
    field that no longer exists therefore removes a guard and replaces it with
    nothing. It fails closed — the guard refuses for want of the field — but for
    a reason that says the caller made a mistake, which sends whoever hits it in
    the wrong direction.
    """
    assert name in OPS_BY_NAME, (
        f"_WRITES_ELSEWHERE names {name!r}, which is not an operation in this "
        "registry. Remove it, or fix the spelling."
    )
    op = OPS_BY_NAME[name]
    assert "{cluster_id}" in op.path, (
        f"{name} is in _WRITES_ELSEWHERE, which exempts it from the path-cluster "
        f"ownership check — but its path carries no {{cluster_id}}, so there was "
        f"nothing to exempt. path={op.path}"
    )
    path = _WRITES_ELSEWHERE[name]
    assert _body_fields(op), f"{name} declares no body, so {path} cannot be read."
    spelling = ".".join(path)
    assert spelling in _body_fields(op), (
        f"_WRITES_ELSEWHERE maps {name} to body.{spelling}, which its body no "
        f"longer declares. Declared: {sorted(_body_fields(op))}"
    )
