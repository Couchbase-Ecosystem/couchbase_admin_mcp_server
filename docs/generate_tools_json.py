"""Regenerate docs/tools.json — the tool inventory the architecture document renders.

Run from the repository root:

    CB_ADMIN_PROFILE=workstation CB_ADMIN_READ_ONLY_MODE=false \
        python docs/generate_tools_json.py > docs/tools.json

Emits {module: [[tool_name, category], ...]} where category is read | write |
destructive, taken from the tool's own annotations via mcp_compat so it survives the
mcp 2.x field renaming. This is the FULL registry across every handler module, before
profile and deployment-mode filtering — which is why the document's total (208) is
larger than the count any single running instance loads.
"""

from __future__ import annotations

import json
import os
import sys

os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
os.environ.setdefault("CB_ADMIN_READ_ONLY_MODE", "false")

import mcp_compat  # noqa: E402
from handlers import (  # noqa: E402
    backup,
    buckets,
    capella,
    cluster,
    collections,
    diagnostics,
    eight_x,
    encryption,
    eventing,
    indexes,
    mcp_status,
    search_admin,
    security,
    stats,
    xdcr,
)

MODULES = {
    "backup": backup,
    "buckets": buckets,
    "capella": capella,
    "cluster": cluster,
    "collections": collections,
    "diagnostics": diagnostics,
    "eight_x": eight_x,
    "encryption": encryption,
    "eventing": eventing,
    "indexes": indexes,
    "mcp_status": mcp_status,
    "search_admin": search_admin,
    "security": security,
    "stats": stats,
    "xdcr": xdcr,
}


def category(tool) -> str:
    if mcp_compat.is_read_only(tool):
        return "read"
    if mcp_compat.is_destructive(tool):
        return "destructive"
    return "write"


out = {
    name: [[t.name, category(t)] for t in module.TOOLS]
    for name, module in MODULES.items()
}
json.dump(out, sys.stdout, indent=1)
print(file=sys.stderr)
print(
    f"{sum(len(v) for v in out.values())} tools across {len(out)} modules",
    file=sys.stderr,
)
