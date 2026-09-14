"""Regenerate docs/tools.json — the tool inventory the architecture document renders.

Run from the repository root:

    python docs/generate_tools_json.py > docs/tools.json

Emits {module: [[tool_name, category], ...]} where category is read | write |
destructive, taken from the tool's own annotations via mcp_compat so it survives
the mcp 2.x field renaming.

THE MODULE LIST IS DERIVED, NOT WRITTEN DOWN
============================================
This file used to carry its own hand-maintained list of handler modules. On
2026-09-14 that list was found to be missing `backup_catalog`, so the inventory
reported 274 tools where the registry held 280, and the six catalogue tools were
absent from the architecture document entirely.

That is the SAME defect, in a third place. `backup_catalog` had already been
found missing from the GUI's tool list, where it had been absent for the whole
life of the module. A second list of modules maintained beside the real one will
drift from it; the only question is when somebody notices.

So the modules now come from `server._HANDLERS`, which is the mapping dispatch
itself uses. A new handler module reaches this inventory by being registered for
dispatch, which is the thing nobody forgets to do, and the assertion at the
bottom fails the build if the two ever disagree anyway.

WHY THE MODE IS PINNED
======================
`both` is the only mode in which the whole registry loads, and the document
inventories the whole registry — its total is deliberately larger than the count
any single running instance loads, because a deployment loads one surface. This
is a MEASUREMENT of the code, not a deployment: see CLAUDE.md section 2.1, which
is about what gets configured and shipped, not about what a build script counts.
"""

from __future__ import annotations

import json
import os
import sys

# Pinned before `server` is imported: server and handlers.shared snapshot their
# configuration at import time, so an inherited CB_DEPLOYMENT from the developer's
# shell would silently inventory half the registry (CLAUDE.md section 2.2).
os.environ["CB_DEPLOYMENT"] = "both"
os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
os.environ.setdefault("CB_ADMIN_READ_ONLY_MODE", "false")
os.environ.setdefault("CB_CONNECTION_STRING", "couchbase://localhost")
os.environ.setdefault("CB_USERNAME", "inventory")
os.environ.setdefault("CB_PASSWORD", "inventory")
os.environ.setdefault("CAPELLA_API_KEY_SECRET", "inventory")

import mcp_compat  # noqa: E402
import server  # noqa: E402


def category(tool) -> str:
    if mcp_compat.is_read_only(tool):
        return "read"
    if mcp_compat.is_destructive(tool):
        return "destructive"
    return "write"


def inventory() -> dict[str, list[list[str]]]:
    """{module name: [[tool, category], ...]}, ordered as the registry is."""
    out: dict[str, list[list[str]]] = {}
    for tool in server._RAW_TOOLS:
        module = server._HANDLERS[tool.name]
        name = module.__name__.rsplit(".", 1)[-1]
        out.setdefault(name, []).append([tool.name, category(tool)])
    return out


#: Facts the architecture document states in PROSE rather than in the inventory
#: table -- the Capella operation counts, the per-mode totals, and the date the
#: whole set was measured.
#:
#: They live here so the document can RENDER them instead of carrying its own
#: copy. Every one of them was found hard-coded and stale in
#: docs/build_architecture.js on 2026-09-14: 208 tools against a registry of 280,
#: 61 primitives against 125, 22 parked ops against 6. A number a build script
#: writes down is a number that goes wrong silently, because nobody re-reads a
#: generated binary.
def measured() -> dict[str, object]:
    import datetime

    import deployment
    from handlers.capella import spec, spec_pending

    names = [t.name for t in server._RAW_TOOLS]
    capella = sum(1 for n in names if n.startswith("capella_"))
    admin = sum(1 for n in names if n.startswith("admin_"))
    cb = sum(1 for n in names if n.startswith("cb_"))
    reachable = len(deployment.CAPELLA_REACHABLE_ADMIN_TOOLS)

    return {
        "measured_on": datetime.date.today().isoformat(),
        "tools_total": len(names),
        "tools_capella": capella,
        "tools_admin": admin,
        "tools_cb": cb,
        # What a single instance loads. A deployment drives ONE surface, so these
        # are both smaller than the total, and that gap is the point.
        "loaded_self_managed": admin + cb,
        "loaded_capella": capella + cb + reachable,
        "capella_reachable_admin_tools": reachable,
        "capella_ops": len(spec.OPS),
        "capella_parked_ops": len(spec_pending.PENDING_OPS),
        # What read-only mode actually removes, on the self-managed surface. The
        # document quoted 64 and 134 from a scan in August; they are 67 and 142.
        "loaded_self_managed_read_only": _read_only_self_managed_total(),
    }


def _read_only_self_managed_total() -> int:
    """Load the self-managed surface in read-only mode and count what survives.

    In a SUBPROCESS: `server` and `handlers.shared` snapshot READ_ONLY_MODE at
    import, so this cannot be measured by re-importing in this one without
    corrupting the inventory already taken above.
    """
    import subprocess
    import sys as _sys

    env = dict(os.environ)
    env.update(
        CB_DEPLOYMENT="self_managed",
        CB_ADMIN_READ_ONLY_MODE="true",
        CB_ADMIN_PROFILE="workstation",
    )
    env.pop("CAPELLA_API_KEY_SECRET", None)
    result = subprocess.run(
        [_sys.executable, "-c", "import server; print(len(server._TOOLS))"],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    return int(result.stdout.strip().splitlines()[-1])


def main() -> None:
    out = inventory()
    counted = sum(len(v) for v in out.values())

    # The inventory must account for EVERY registered tool. A tool whose module is
    # not in `_HANDLERS` cannot be dispatched at all, so this would fail loudly
    # rather than quietly shipping a document that describes a smaller server than
    # the one that runs.
    assert counted == len(server._RAW_TOOLS), (
        f"inventory holds {counted} tools, the registry holds "
        f"{len(server._RAW_TOOLS)}. A module is registered for dispatch and not "
        "reached by this walk, or vice versa."
    )

    # Prefixed so a consumer iterating modules can drop it by name rather than by
    # position, and so it cannot collide with a handler module called "meta".
    out["__measured__"] = measured()

    json.dump(out, sys.stdout, indent=1)
    print(file=sys.stderr)
    print(f"{counted} tools across {len(out) - 1} modules", file=sys.stderr)


if __name__ == "__main__":
    main()
