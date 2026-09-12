"""Every Backup service path carries its repository STATE segment.

The five `admin_backup_*` tools all returned 404 against a cluster running the
Backup service, and the cause was one missing path segment shared by all of
them: `/cluster/self/repository/<state>/...` where state is `active`,
`imported` or `archived`.

The worst of the five was `admin_backup_repository_get`, which sent
`/repository/<repository_id>`. That is a well-formed URL -- the id simply landed
in the slot the service reads as the STATE -- so it failed as "unknown state"
rather than "no such path", and read like a broken service rather than a broken
client.

Asserted as a PROPERTY of the source, the same way `test_service_proxy_paths.py`
asserts the `/_p/fts` prefix. Pinning the five literal strings would pass while
a sixth tool was added without one.
"""

from __future__ import annotations

import ast
import inspect
import re

import pytest

from handlers import backup

#: Path-building sites: a literal or f-string mentioning the repository
#: collection.
_REPOSITORY_PATH = re.compile(r"cluster/self/repository(?P<rest>\S*)")

#: What must follow it: a state segment, literal or interpolated.
_HAS_STATE = re.compile(r"^/(?:active|imported|archived|\{state\})\b")


def _path_expressions(module) -> list[str]:
    """Every string the module BUILDS, with prose excluded.

    Matched against the AST rather than the source text, and this is not a
    refinement -- the first version of this test regexed `inspect.getsource`
    and failed against the module docstring, which describes the very rule it
    is checking. The same shape cost two false alarms during the fix: a grep
    for `/backups` matched the comment saying there is no `/backups` endpoint.

    Comments do not exist in an AST at all, and docstrings are identifiable by
    position, so working from the tree removes both problems structurally
    instead of by making the pattern cleverer.
    """
    tree = ast.parse(inspect.getsource(module))

    docstrings = set()
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        first = node.body[0] if node.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            docstrings.add(id(first.value))

    # An f-string's literal fragments are Constant nodes INSIDE it, and
    # `ast.walk` yields them too -- so `f"{_BACKUP}/cluster/self/repository/{state}"`
    # also surfaces as the bare fragment "/cluster/self/repository/", which looks
    # exactly like a path with the state segment missing. Take the f-string whole
    # and skip its parts.
    inside_fstring = {
        id(part)
        for node in ast.walk(tree)
        if isinstance(node, ast.JoinedStr)
        for part in ast.walk(node)
        if part is not node
    }

    built: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            built.append(ast.unparse(node))
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
            and id(node) not in inside_fstring
        ):
            built.append(node.value)
    return built


def test_every_repository_path_names_a_state():
    expressions = _path_expressions(backup)
    sites = [
        (text, match)
        for text in expressions
        for match in [_REPOSITORY_PATH.search(text)]
        if match
    ]
    assert sites, "no repository paths found; this test has gone stale"

    bad = [
        text
        for text, match in sites
        if not _HAS_STATE.match(match.group("rest"))
        and "{state}" not in match.group("rest")
    ]
    assert not bad, (
        "these Backup service paths have no repository state segment, so the "
        "service will read the next segment as the state and reject it:\n  "
        + "\n  ".join(bad)
    )


def test_the_state_is_validated_rather_than_interpolated_raw():
    """An unchecked state would be a path-injection point as well as a 404."""
    with pytest.raises(ValueError):
        backup._repository_path({"repository_id": "r", "state": "../../etc"})
    with pytest.raises(ValueError):
        backup._repository_path({"repository_id": "r", "state": "nonsense"})


def test_the_state_defaults_to_active():
    """Callers that do not care must still produce a legal path."""
    built = backup._repository_path({"repository_id": "repo1"})
    assert built == "/_p/backup/api/v1/cluster/self/repository/active/repo1"


def test_an_archived_repository_is_addressable():
    """The whole reason the segment is exposed rather than hard-coded."""
    built = backup._repository_path({"repository_id": "repo1", "state": "archived"})
    assert "/repository/archived/repo1" in built


def test_the_repository_id_is_still_escaped():
    """The state segment is new; the existing escaping must survive it."""
    built = backup._repository_path({"repository_id": "a/../b"})
    assert "/repository/active/" in built
    assert "a/../b" not in built


def test_listing_backups_asks_for_repository_info():
    """There is no `/backups` endpoint.

    Individual backups come back inside the repository info document, so a path
    built from the tool's own name -- `admin_backup_list` -> `/backups` -- is a
    plausible invention that the service has never served.
    """
    built = _path_expressions(backup)
    offenders = [text for text in built if "/backups" in text]
    assert not offenders, (
        "the Backup service has no /backups endpoint; backups are carried in "
        f"the repository /info response. Offending path(s): {offenders}"
    )
    assert any("/info" in text for text in built) or 'suffix="/info"' in inspect.getsource(
        backup.handle
    ), "nothing asks for the repository /info document, so admin_backup_list returns no backups"


#: Tools that name a repository but are NOT state-addressed, and why.
#:
#: An exception list rather than a looser rule: each entry is a claim someone
#: has to justify, and a new tool that quietly skips `state` still fails.
_STATE_NOT_APPLICABLE = {
    # Creates always land in `active`. `imported` and `archived` are states a
    # repository REACHES; a repository cannot be born archived, so offering the
    # argument would advertise a call the service rejects.
    "admin_backup_repository_create",
}


def test_every_repository_addressed_tool_declares_the_state_argument():
    """A path that takes a state and a schema that hides it leaves the caller
    unable to reach anything but `active` -- and an archived repository is
    exactly what someone restoring from last quarter needs.

    Scoped to tools that ADDRESS a repository. The first version asserted this
    of every tool in the module and broke the moment a plan-listing tool was
    added, which addresses no repository at all -- the test was describing the
    module as it happened to be rather than the property it cared about.
    """
    missing = []
    for tool in backup.TOOLS:
        if tool.name in _STATE_NOT_APPLICABLE:
            continue
        properties = (tool.inputSchema or {}).get("properties", {})
        if "repository_id" not in properties and tool.name != "admin_backup_repository_list":
            continue  # addresses no repository; the state means nothing here
        if "state" not in properties:
            missing.append(tool.name)
    assert not missing, (
        f"these tools address a repository but do not declare `state`: {missing}"
    )


def test_the_state_exceptions_are_still_real_tools():
    """An exception list that names something gone stops guarding anything."""
    names = {t.name for t in backup.TOOLS}
    stale = sorted(_STATE_NOT_APPLICABLE - names)
    assert not stale, f"_STATE_NOT_APPLICABLE names tools that no longer exist: {stale}"


def test_there_is_something_to_test():
    """`backup.TOOLS` drives the two loops below.

    Found by `test_no_vacuous_coverage.py` on the run that introduced this file,
    which is the scanner doing exactly its job on freshly written code.
    """
    assert backup.TOOLS, "the backup handler advertises no tools"
    assert backup._STATES, "no repository states are declared"


def test_the_declared_states_match_the_ones_the_code_accepts():
    """Two lists that can drift, in a module where drift means a 404."""
    for tool in backup.TOOLS:
        spec = (tool.inputSchema or {}).get("properties", {}).get("state")
        if not spec:
            continue
        assert set(spec["enum"]) == set(backup._STATES), tool.name
        assert spec["default"] == "active", tool.name


# ── The repository-create gap ────────────────────────────────────────────────


def test_a_repository_can_be_created_through_this_server():
    """Five backup tools shipped and none of them could make a repository.

    Every one of them addresses a repository -- list, get, list backups, run,
    restore -- and a cluster with none (which is every cluster until someone
    makes one by hand) made the whole family correct and unusable. That is not a
    configuration problem, and it does not show up as a failure anywhere: each
    tool answers honestly that there is nothing there.
    """
    names = {t.name for t in backup.TOOLS}
    assert "admin_backup_repository_create" in names, (
        "nothing in this server can create a backup repository, so the other "
        "backup tools have nothing to act on"
    )
    assert "admin_backup_plans_list" in names, (
        "a repository must name a plan, so the plans must be discoverable"
    )


def test_the_plan_list_does_not_use_the_documented_path():
    """`/cluster/plan` is what the reference says and it answers 400.

    `/cluster/<name>` takes a cluster name, "self" is the only valid one, so the
    service reads "plan" as a cluster: {"msg": "Remote cluster not supported",
    "extras": "Invalid cluster: plan"}. The real path is /plan. Pinned because
    the next person to read that reference page will "fix" this back.
    """
    # `ast.unparse` renders an f-string WITH its quotes -- f'{_BACKUP}/plan' --
    # so a tail match on "/plan" fails on the trailing quote rather than on the
    # path. Strip the quoting before comparing; the same trap cost a false
    # failure in the sibling test earlier today.
    built = [text.strip().rstrip("\"'") for text in _path_expressions(backup)]
    assert any(text.endswith("/plan") for text in built), (
        f"no call to /plan; the plan list is how a repository chooses a "
        f"schedule. Paths seen: {built}"
    )
    assert not any("cluster/plan" in text for text in built), (
        "/cluster/plan answers 400 -- the service reads 'plan' as a cluster name"
    )


def test_the_archive_destination_is_egress_guarded():
    """`archive` can be s3:// -- a destination cluster data is written to.

    An unallowlisted archive is exfiltration with a backup's name on it, and the
    restore target already gets this guard. A create that skipped it would be
    the same hole through a different door.
    """
    import inspect

    source = inspect.getsource(backup.handle)
    create = source[source.index('admin_backup_repository_create'):]
    create = create[:create.index('admin_backup_repository_get')]
    assert "guard_nested_host_fields" in create, (
        "repository_create forwards `archive` to the Backup service with no "
        "egress guard"
    )


def test_a_repository_is_created_in_the_active_state():
    """imported and archived are states a repository REACHES, not starts in."""
    built = _path_expressions(backup)
    creates = [t for t in built if "repository/active/" in t]
    assert creates, "the create path does not target the active state"
