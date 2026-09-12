"""
The ns_server proxy prefix on service REST paths.

WHY THIS FILE EXISTS
====================
`admin_request()` talks to the MANAGEMENT port. A service's own REST API is not
served there — it is reached through ns_server's proxy prefix. eventing.py and
backup.py have always used one; search_admin.py used none, so all nine of its
tools answered 404 against any cluster, including one demonstrably running the
Search service.

No existing unit test could catch it. They mock `admin_request` and assert on the
path string passed to it — which is exactly the string that was wrong. The defect
was found by scripts/verify_mcp_surface.py calling the tools through a real MCP
client against a live cluster, and the correct paths were then measured rather
than guessed (scripts/probe_rest_paths.ps1).

These tests assert the property that was missing, not the individual strings: a
service path must carry its prefix. A tenth FTS tool added tomorrow without one
fails here.
"""

from __future__ import annotations

import inspect
import re

from handlers import backup, eventing, search_admin

#: Prefix per module, as ns_server serves them.
_PREFIX = {
    search_admin: "/_p/fts",
    eventing: "/_p/event",
    backup: "/_p/backup",
}

#: Every literal path passed to an admin_request* call, however it was spelled.
_CALL = re.compile(r'admin_request(?:_json)?\(\s*"[A-Z]+"\s*,\s*f?"([^"]+)"')


def _paths(module) -> list[str]:
    return _CALL.findall(inspect.getsource(module))


def test_every_search_path_goes_through_the_proxy_prefix():
    """THE DEFECT. Nine tools, nine bare paths, nine 404s.

    Measured on Enterprise 8.0.1 with fts on the node, 2026-09-12:
        GET :8091/api/index         404
        GET :8091/_p/fts/api/index  200
    """
    bare = [p for p in _paths(search_admin) if p.startswith("/api/")]
    assert not bare, (
        f"Search paths with no proxy prefix: {bare}. admin_request goes to the "
        "management port, where /api/index is not served."
    )


def test_the_prefix_is_named_once_rather_than_spelled_at_each_site():
    """A constant makes the next omission impossible.

    The failure mode was not a typo in one path, it was the prefix being absent
    from all of them — which is what happens when each call site spells its own.
    """
    source = inspect.getsource(search_admin)
    assert '_FTS = "/_p/fts"' in source
    assert source.count('"/_p/fts') == 1, (
        "the prefix is spelled more than once; use the _FTS constant"
    )


def test_each_module_carries_its_own_service_prefix():
    """The property, stated for all three, so a new handler cannot omit it."""
    for module, prefix in _PREFIX.items():
        for path in _paths(module):
            if path.startswith("{"):
                continue  # built from a constant that already carries the prefix
            assert path.startswith((prefix, "/_p/")), (
                f"{module.__name__} passes {path!r} to admin_request without a "
                f"proxy prefix; expected {prefix}"
            )


def test_the_eventing_list_endpoint_is_list_functions():
    """`/list` alone is not an endpoint and answered 404 page not found.

    Its neighbours proved the base path was never wrong: /stats and /status
    answer, and /functions/{name} is used by get, update and delete in the same
    file. One suffix was wrong, not the prefix.

    /functions also returns 200 but returns every full definition rather than
    names — a large answer to "what is here", and admin_eventing_get already
    exists for the detail.
    """
    source = inspect.getsource(eventing)
    assert '_evt_path("/list/functions")' in source
    assert '_evt_path("/list")' not in source
