"""The architecture diagrams state counts. Those counts must be the real ones.

WHY THIS FILE EXISTS
====================
`docs/diagrams-src/*.mmd` and the inline Mermaid in `docs/ARCHITECTURE.md` are
the pictures a customer and a new engineer look at first. On 2026-09-14 they
said:

    "authz + auth + 208 tools"        the registry held 280
    "spec.py - 61 primitives"          spec.OPS held 125
    "spec_pending.py - 22 ops"         6 were parked
    "fixture.py - 4 tools,             export and import had been
     handlers refuse"                  implemented that morning
    "capella_* - 74 tools"             138

None of those were wrong when drawn. Each became wrong because the code moved
and the picture did not, and a picture is the single worst place for a stale
fact: nobody diffs a PNG, and a reader trusts a diagram more than prose.

WHAT THIS ASSERTS
=================
Not the numbers themselves -- that would be CLAUDE.md rule 1.2's exact failure,
a magic number in a test that fails on every legitimate change and trains the
next person to edit it without reading why.

It asserts a RELATIONSHIP between two measured values: the number the diagram
prints and the number the code actually produces. When the registry grows, this
fails and names the diagram to redraw, which is the outcome that was wanted.

Regenerate with, from the repository root:

    mmdc -i docs/diagrams-src/<name>.mmd -o docs/diagrams/arch<name>.png -b white -s 2
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "diagrams-src"
RENDERED = ROOT / "docs" / "diagrams"
ARCHITECTURE = ROOT / "docs" / "ARCHITECTURE.md"


# ── What the code actually holds ─────────────────────────────────────────────
#
# In a SUBPROCESS with CB_DEPLOYMENT pinned. `server` and `handlers.shared`
# snapshot their configuration at import, so importing the registry here would
# both take whatever mode the developer's shell implies and leak that import
# into every test that runs after it -- CLAUDE.md section 2.2.

_MEASURE = """
import json
import server
from handlers.capella import spec, spec_pending

raw = [t.name for t in server._RAW_TOOLS]
print(json.dumps({
    "tools": len(raw),
    "capella": sum(1 for n in raw if n.startswith("capella_")),
    "admin_and_cb": sum(1 for n in raw if n.startswith(("admin_", "cb_"))),
    "ops": len(spec.OPS),
    "parked": len(spec_pending.PENDING_OPS),
}))
"""


def _measured() -> dict[str, int]:
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
            # Pinned, not inferred. `both` is the only mode in which the WHOLE
            # registry loads, which is what a diagram of the whole system counts.
            # It is a measurement, not a deployment -- see CLAUDE.md 2.1.
            "CB_DEPLOYMENT": "both",
            "CB_ADMIN_PROFILE": "workstation",
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


MEASURED = _measured()


def test_the_measurement_itself_worked():
    """Premise. Every assertion below compares against this, so a zero here
    would make them all pass against nothing."""
    assert MEASURED["tools"] > 0
    assert MEASURED["ops"] > 0
    assert MEASURED["capella"] + MEASURED["admin_and_cb"] == MEASURED["tools"], (
        "every tool should carry one of the three known prefixes; a tool that "
        "carries none is a naming bug the diagrams cannot describe"
    )


def test_the_diagram_sources_exist():
    """A glob that matched nothing would make the checks below vacuous."""
    sources = sorted(SRC.glob("*.mmd"))
    assert len(sources) >= 6, f"diagram sources are missing, found {sources}"


def _text(name: str) -> str:
    path = SRC / name
    assert path.is_file(), f"{name} is gone; the diagram sources moved"
    return path.read_text(encoding="utf-8")


def _number_before(text: str, phrase: str, source: str) -> int:
    """The integer immediately preceding `phrase`."""
    match = re.search(r"(\d[\d,]*)\s*" + re.escape(phrase), text)
    assert match, (
        f"{source} no longer says '<number> {phrase}'. If the label was "
        "reworded, update this matcher -- do not delete the check, or the "
        "diagram stops being compared to the code at all."
    )
    return int(match.group(1).replace(",", ""))


def test_the_context_diagram_states_the_real_tool_count():
    assert (
        _number_before(_text("01_context.mmd"), "tools", "01_context.mmd")
        == (MEASURED["tools"])
    ), "docs/diagrams-src/01_context.mmd states a tool count the registry does not have"


def test_the_module_map_states_the_real_tool_count():
    assert (
        _number_before(_text("03_modules.mmd"), "tools", "03_modules.mmd")
        == (MEASURED["tools"])
    )


def test_the_capella_diagram_states_the_real_operation_counts():
    text = _text("05_capella.mmd")
    assert _number_before(text, "primitives", "05_capella.mmd") == MEASURED["ops"], (
        "the Capella layering diagram states a primitive count that is not "
        "len(spec.OPS)"
    )
    assert _number_before(text, "parked ops", "05_capella.mmd") == MEASURED["parked"]


def test_the_matrix_diagram_states_the_real_per_surface_counts():
    text = _text("08_matrix.mmd")
    assert _number_before(text, "tools, 2026", "08_matrix.mmd") == MEASURED["capella"]
    admin = re.search(r"admin_\* and cb_\* · (\d+) tools", text)
    assert admin, "08_matrix.mmd no longer labels the self-managed tool count"
    assert int(admin.group(1)) == MEASURED["admin_and_cb"]


def test_the_architecture_documents_inline_diagram_agrees():
    """The Markdown carries its own copy of the same numbers, and the two have
    drifted apart before."""
    text = ARCHITECTURE.read_text(encoding="utf-8")
    assert f"{MEASURED['tools']} registered tools" in text, (
        "docs/ARCHITECTURE.md states a registered-tool count that is not the "
        f"registry's {MEASURED['tools']}"
    )
    assert _number_before(text, "primitives", "ARCHITECTURE.md") == MEASURED["ops"]


@pytest.mark.parametrize("source", sorted(p.name for p in SRC.glob("*.mmd")))
def test_no_diagram_presents_both_as_a_deployment(source):
    """CLAUDE.md 2.1. A diagram is documentation, and `both` is the one mode no
    documentation demonstrates.

    Naming the mode while DESCRIBING deployment.py is description, not a
    demonstration -- what is refused is a diagram that shows a deployment
    configured that way.
    """
    text = _text(source)
    offenders = [
        line.strip()
        for line in text.splitlines()
        if re.search(r"CB_DEPLOYMENT\s*=\s*[\"']?both", line, re.I)
    ]
    assert not offenders, (
        f"{source} shows a deployment configured as 'both', which switches "
        "capability gating off:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("source", sorted(p.name for p in SRC.glob("*.mmd")))
def test_every_diagram_source_has_been_rendered(source):
    """A source edited without re-rendering leaves the PNG -- the thing actually
    embedded in the deck, the docx and the README -- showing the old numbers,
    which is the failure this file exists to catch, one step further along."""
    rendered = RENDERED / f"arch{source.replace('.mmd', '.png')}"
    assert rendered.is_file(), (
        f"{source} has no rendered counterpart at {rendered.relative_to(ROOT)}. "
        "Render it with:\n  mmdc -i docs/diagrams-src/" + source + " -o docs/"
        "diagrams/" + rendered.name + " -b white -s 2"
    )
    assert rendered.stat().st_mtime >= (SRC / source).stat().st_mtime - 1, (
        f"{rendered.name} is older than {source}: the source was edited and the "
        "picture was not re-rendered, so the published diagram shows the old "
        "numbers."
    )


# ── The matplotlib figure set ────────────────────────────────────────────────
#
# fig03_deployment_gating is the one figure whose whole subject is HOW MANY
# tools each mode loads, which makes it the one most certain to go stale. It
# said 134 / 84 / 204 while the modes loaded 142 / 158 / 280 -- and it is
# embedded in the architecture docx and the slide deck, where nobody would see
# the drift.

GENERATOR = ROOT / "docs" / "make_arch_diagrams.py"


def _per_mode_totals() -> dict[str, int]:
    """Load each mode in its own subprocess and count what the registry holds.

    A subprocess per mode because `server` and `handlers.shared` snapshot their
    configuration at import: reloading in-process would leak the last mode into
    every test that ran afterwards. CLAUDE.md section 2.2.
    """
    totals = {}
    for mode in ("self_managed", "capella", "both"):
        result = subprocess.run(
            [sys.executable, "-c", "import server; print(len(server._TOOLS))"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "SYSTEMROOT": "C:\\Windows",
                "PYTHONPATH": str(ROOT),
                "CB_DEPLOYMENT": mode,
                "CB_ADMIN_PROFILE": "workstation",
                "CB_CONNECTION_STRING": "couchbase://localhost",
                "CB_USERNAME": "measurement",
                "CB_PASSWORD": "measurement",
                "CAPELLA_API_KEY_SECRET": "measurement",
            },
        )
        assert result.returncode == 0, (
            f"could not load mode {mode}:\n{result.stdout}{result.stderr}"
        )
        totals[mode] = int(result.stdout.strip().splitlines()[-1])
    return totals


PER_MODE = _per_mode_totals()


def test_the_per_mode_measurement_worked():
    """Premise for the checks below."""
    assert set(PER_MODE) == {"self_managed", "capella", "both"}
    assert all(total > 0 for total in PER_MODE.values()), PER_MODE
    assert PER_MODE["both"] == MEASURED["tools"], (
        "`both` loads the whole registry by definition; if it no longer does, "
        "the gating changed and every diagram describing it is wrong"
    )


@pytest.mark.parametrize("mode", sorted(PER_MODE))
def test_the_gating_figure_states_the_real_loaded_total(mode):
    """`fig03_deployment_gating` prints '= N loaded' for each mode."""
    source = GENERATOR.read_text(encoding="utf-8")
    stated = re.findall(r"=\s*(\d+)\s+loaded", source)
    assert len(stated) == 3, (
        "expected three '= N loaded' labels in docs/make_arch_diagrams.py, "
        f"found {stated}. If the figure was relabelled, fix this matcher rather "
        "than dropping the comparison."
    )
    expected = [PER_MODE["self_managed"], PER_MODE["capella"], PER_MODE["both"]]
    assert [int(n) for n in stated] == expected, (
        "docs/make_arch_diagrams.py states loaded totals "
        f"{stated} but the modes load {expected}. Update the figure and "
        "re-run:\n  python docs/make_arch_diagrams.py"
    )


def test_the_gating_figure_dates_its_counts():
    """A figure is the worst place for an undated count: nobody diffs a PNG, and
    a reader trusts a picture more than prose. Same rule as
    tests/test_docs_are_not_stale.py, applied to the thing that gets embedded in
    the deck."""
    source = GENERATOR.read_text(encoding="utf-8")
    block = source.split("def deployment_gating", 1)
    assert len(block) == 2, "the deployment-gating figure builder was renamed"
    assert re.search(r"20\d\d-\d\d-\d\d", block[1][:4000]), (
        "the deployment-gating figure states per-mode tool counts with no date "
        "on the face of the picture"
    )
