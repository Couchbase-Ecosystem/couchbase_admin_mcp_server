"""docs/tools.json is the tool inventory the architecture document renders.

WHY THIS FILE EXISTS
====================
`docs/tools.json` is committed so a reader can rebuild the architecture document
without a working Python environment. That convenience is also the hazard: it is
a snapshot of the registry that nothing forced anyone to refresh.

On 2026-09-14 it held 208 tools against a registry of 280, and its generator
carried its own hand-written list of handler modules that was missing
`backup_catalog` -- so six tools were absent from the inventory even after a
regeneration. That is the THIRD place `backup_catalog` has been found missing
from a second list of modules maintained beside the real one; the GUI was the
first, and it had been absent there for the whole life of the module.

The generator now derives its modules from `server._HANDLERS`, which is what
dispatch itself uses. This file makes the committed artifact prove it.

WHAT IS ASSERTED
================
Set equality between the inventory and the registry, in BOTH directions, plus
agreement on every measured count the document renders from. Not a pinned
number anywhere -- each assertion compares two measured values, so it fails when
the code moves and names what to regenerate, rather than failing for a reason
unrelated to the property under test (CLAUDE.md rule 1.2).

Regenerate with, from the repository root:

    python docs/generate_tools_json.py > docs/tools.json
    node docs/build_architecture.js
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "docs" / "tools.json"
BUILDER = ROOT / "docs" / "build_architecture.js"

_MEASURE = """
import json
import deployment
import server
from handlers.capella import spec, spec_pending

names = [t.name for t in server._RAW_TOOLS]
print(json.dumps({
    "names": names,
    "tools_total": len(names),
    "tools_capella": sum(1 for n in names if n.startswith("capella_")),
    "tools_admin": sum(1 for n in names if n.startswith("admin_")),
    "tools_cb": sum(1 for n in names if n.startswith("cb_")),
    "capella_reachable_admin_tools": len(deployment.CAPELLA_REACHABLE_ADMIN_TOOLS),
    "capella_ops": len(spec.OPS),
    "capella_parked_ops": len(spec_pending.PENDING_OPS),
}))
"""


def _registry() -> dict:
    """Measured in a subprocess with the mode pinned.

    `server` and `handlers.shared` snapshot their configuration at import, so an
    inherited CB_DEPLOYMENT would inventory half the registry and this file would
    report the difference as drift. CLAUDE.md section 2.2.
    """
    result = subprocess.run(
        [sys.executable, "-c", _MEASURE],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "SYSTEMROOT": "C:\\Windows",
            "PYTHONPATH": str(ROOT),
            "CB_DEPLOYMENT": "both",
            "CB_ADMIN_PROFILE": "workstation",
            "CB_ADMIN_READ_ONLY_MODE": "false",
            "CB_CONNECTION_STRING": "couchbase://localhost",
            "CB_USERNAME": "measurement",
            "CB_PASSWORD": "measurement",
            "CAPELLA_API_KEY_SECRET": "measurement",
        },
    )
    assert result.returncode == 0, (
        "could not measure the registry:\n" + result.stdout + result.stderr
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


REGISTRY = _registry()
DOCUMENT = json.loads(INVENTORY.read_text(encoding="utf-8"))
MEASURED = DOCUMENT.get("__measured__", {})
MODULES = {k: v for k, v in DOCUMENT.items() if not k.startswith("__")}


def test_the_inventory_and_the_registry_were_both_read():
    """Premise. Two empty collections are equal, and that equality means nothing."""
    assert REGISTRY["names"], "the registry measured as empty"
    assert MODULES, "docs/tools.json has no modules"
    assert MEASURED, (
        "docs/tools.json carries no __measured__ block. Regenerate it:\n"
        "  python docs/generate_tools_json.py > docs/tools.json"
    )


def test_the_inventory_lists_every_registered_tool():
    listed = {name for rows in MODULES.values() for name, _ in rows}
    missing = sorted(set(REGISTRY["names"]) - listed)
    assert not missing, (
        f"{len(missing)} registered tools are absent from docs/tools.json, so "
        f"the architecture document describes a smaller server than the one that "
        f"runs: {missing[:10]}\n\nRegenerate:\n"
        "  python docs/generate_tools_json.py > docs/tools.json"
    )


def test_the_inventory_lists_nothing_that_is_not_registered():
    """The other direction. A tool removed from the code but left in the
    inventory documents something a customer cannot call."""
    listed = {name for rows in MODULES.values() for name, _ in rows}
    stale = sorted(listed - set(REGISTRY["names"]))
    assert not stale, (
        f"docs/tools.json lists tools the registry does not have: {stale[:10]}"
    )


def test_every_measured_count_agrees_with_the_code():
    disagreements = []
    for key, expected in REGISTRY.items():
        if key == "names":
            continue
        stated = MEASURED.get(key)
        if stated != expected:
            disagreements.append(f"{key}: document says {stated}, code says {expected}")
    assert not disagreements, (
        "docs/tools.json states counts the code does not produce, and the "
        "architecture document renders them:\n  " + "\n  ".join(disagreements)
    )


def test_the_measurement_carries_its_date():
    """Same rule as tests/test_docs_are_not_stale.py: a count without a date
    cannot be told apart from a fossil."""
    assert re.fullmatch(r"20\d\d-\d\d-\d\d", str(MEASURED.get("measured_on", ""))), (
        f"docs/tools.json has no usable measurement date: "
        f"{MEASURED.get('measured_on')!r}"
    )


def test_the_document_builder_hard_codes_no_tool_count():
    """Every count in the document must come from the measured block.

    The builder carried eleven hard-coded ones and all eleven were wrong. A
    number written into a build script goes stale silently, because nobody
    re-reads a generated binary to check it.
    """
    offenders = []
    for number, line in enumerate(BUILDER.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("//"):
            continue  # the comment recording what the stale numbers WERE
        for match in re.finditer(r"(?<![\w.$])(\d{2,4})\s+(?:tools|ops)\b", line):
            offenders.append(f"line {number}: {match.group(0)!r}")
    assert not offenders, (
        "docs/build_architecture.js states a tool or operation count as a "
        "literal instead of rendering it from the measured block:\n  "
        + "\n  ".join(offenders)
        + "\n\nUse ${M.tools_total}, ${M.capella_ops} and so on -- see the "
        "__measured__ key in docs/tools.json."
    )


def test_the_builder_reads_the_measured_block():
    """Guards the check above from passing because the interpolation was
    removed along with the numbers."""
    source = BUILDER.read_text(encoding="utf-8")
    assert "__measured__" in source and "${M.tools_total}" in source, (
        "docs/build_architecture.js no longer renders its counts from the "
        "measured block"
    )


# ── The generated binaries ───────────────────────────────────────────────────
#
# The .docx is rebuilt from docs/tools.json, and the .pptx is hand-built with no
# builder at all. Both are committed binaries, which means a stale count in one
# survives every code change silently -- nobody diffs a .docx, and the deck is
# the artifact most likely to be put in front of a customer.
#
# So the check is on the RENDERED TEXT: whatever produced it, the number it shows
# has to be the number the code holds.

import zipfile  # noqa: E402

DOCX = ROOT / "docs" / "CB_Admin_MCP_Architecture.docx"
DECK = ROOT / "docs" / "ARCHITECTURE Deck.pptx"


def _office_text(path: pathlib.Path, member_prefix: str) -> str:
    """Every <a:t>/<w:t> run in the parts under `member_prefix`, space joined."""
    assert path.is_file(), f"{path.name} is missing"
    runs: list[str] = []
    with zipfile.ZipFile(path) as archive:
        for name in sorted(archive.namelist()):
            if not name.startswith(member_prefix) or not name.endswith(".xml"):
                continue
            body = archive.read(name).decode("utf-8", errors="replace")
            runs.extend(re.findall(r"<(?:a|w):t[^>]*>([^<]*)</(?:a|w):t>", body))
    return " ".join(runs)


def test_the_generated_document_shows_the_real_tool_total():
    """docs/CB_Admin_MCP_Architecture.docx is rebuilt with:

        python docs/generate_tools_json.py > docs/tools.json
        node docs/build_architecture.js
    """
    text = _office_text(DOCX, "word/")
    total = REGISTRY["tools_total"]
    assert f"{total} tools" in text, (
        f"the architecture document does not state {total} tools anywhere, so "
        "the committed .docx predates the current registry. Rebuild it:\n"
        "  python docs/generate_tools_json.py > docs/tools.json\n"
        "  node docs/build_architecture.js"
    )


def test_the_generated_document_carries_no_superseded_total():
    """A rebuild that leaves an old number somewhere is the failure mode this
    catches -- the document stated 208 in five places and 280 in none."""
    text = _office_text(DOCX, "word/")
    total = REGISTRY["tools_total"]
    stale = {
        n
        for n in re.findall(r"(?<![\w.])(\d{2,4}) tools\b", text)
        if int(n)
        not in {
            total,
            REGISTRY["tools_capella"],
            REGISTRY["tools_admin"],
            REGISTRY["tools_cb"],
            MEASURED.get("loaded_self_managed"),
            MEASURED.get("loaded_capella"),
            MEASURED.get("loaded_self_managed_read_only"),
        }
    }
    assert not stale, (
        f"the architecture document states tool counts that match nothing the "
        f"code produces: {sorted(stale)}"
    )


def test_the_slide_deck_shows_the_real_tool_total():
    """The deck has NO builder -- it is edited in place -- which is exactly why
    its numbers need a test rather than a convention."""
    text = _office_text(DECK, "ppt/slides/")
    total = REGISTRY["tools_total"]
    assert f"{total} tools" in text, (
        f"docs/ARCHITECTURE Deck.pptx does not state {total} tools. It has no "
        "builder, so edit the slide text in place and re-check."
    )


def test_the_slide_deck_carries_no_superseded_total():
    text = _office_text(DECK, "ppt/slides/")
    allowed = {
        REGISTRY["tools_total"],
        REGISTRY["tools_capella"],
        REGISTRY["tools_admin"],
        REGISTRY["tools_cb"],
        MEASURED.get("loaded_self_managed"),
        MEASURED.get("loaded_capella"),
    }
    stale = {
        n for n in re.findall(r"(?<![\w.])(\d{2,4}) tools\b", text) if int(n) not in allowed
    }
    assert not stale, (
        f"the slide deck states tool counts that match nothing the code "
        f"produces: {sorted(stale)}"
    )
