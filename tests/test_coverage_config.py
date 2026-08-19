"""
The coverage configuration itself, because exclusions are how a coverage number gets faked.

WHY THIS FILE EXISTS
====================
A coverage percentage is only meaningful alongside what it excludes. Widening `omit` or adding
a permissive `exclude_lines` pattern raises the number without testing anything, and neither
shows up in a diff of source files — it looks like configuration housekeeping.

So the exclusions are pinned here, each with the reason it is defensible:

  * `tests/*` — measuring the tests with the tests is circular.
  * `scripts/mutation_*` — those harnesses COPY the tree and run pytest in a subprocess, so
    their lines never execute in the measured process.
  * `gui/static/*` — vendored third-party JavaScript.
  * `.venv/*` — the virtual environment. Third-party library code is not this
    project's to test, and on a local run it dwarfs the first-party total.
  * `if __name__ == "__main__":` — reaching it means running the module as a program, which the
    packaging tests do in a subprocess. The lines DO execute; not in this process.

Anything beyond that list should have to argue for itself in review, which is what a failing
test here forces.

AND the number has to actually be produced and gated, which it was not: no CI job ran
`--cov` and there was no `fail_under`, so every assertion in this file constrained the
shape of a measurement that never happened. `fail_under` is now pinned here too.
"""

from __future__ import annotations

import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "pyproject.toml"


@pytest.fixture(scope="module")
def parsed() -> dict:
    """The `[tool.coverage]` tables.

    In pyproject.toml, not `.coveragerc`. A dotfile with that name is deleted by the
    `rm -f .coverage*` everyone types to clear stale data files — which is exactly what
    happened while writing this, silently, in every measurement command.
    """
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.10
        tomllib = pytest.importorskip("tomli")

    assert CONFIG.exists()
    data = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    coverage = data.get("tool", {}).get("coverage", {})
    assert coverage, "no [tool.coverage] configuration, so the number is unreproducible"
    return coverage


def _lines(config, section, option) -> list[str]:
    return list(config.get(section, {}).get(option, []))


# ── omit ─────────────────────────────────────────────────────────────────────


def test_the_omit_list_is_exactly_what_is_defensible(parsed):
    """A new entry here removes a whole file from the measurement. That is occasionally right
    and always worth an argument, so it fails here until someone makes it."""
    assert set(_lines(parsed, "run", "omit")) == {
        "tests/*",
        "scripts/mutation_*",
        "gui/static/*",
        ".venv/*",
    }


def test_no_production_module_is_omitted(parsed):
    """The failure mode: omitting the one file with poor coverage. Every omitted pattern must
    match test infrastructure or vendored code, never a module the server imports."""
    for pattern in _lines(parsed, "run", "omit"):
        assert pattern.startswith(
            ("tests/", "scripts/mutation_", "gui/static/", ".venv/")
        ), f"{pattern!r} could omit production code from the coverage measurement"


def test_the_handlers_and_auth_packages_are_measured(parsed):
    """Stated positively, because these are where the security controls live."""
    omitted = _lines(parsed, "run", "omit")
    for critical in (
        "handlers/",
        "auth/",
        "server.py",
        "gui/gui_server.py",
        "authz.py",
    ):
        assert not any(critical in pattern for pattern in omitted), (
            f"{critical} is excluded from coverage"
        )


# ── exclude_lines ────────────────────────────────────────────────────────────


EXPECTED_EXCLUSIONS = {
    "pragma: no cover",
    "if __name__ == .__main__.:",
    "if TYPE_CHECKING:",
    "raise NotImplementedError",
}


def test_the_line_exclusions_are_exactly_the_four_conventional_ones(parsed):
    assert set(_lines(parsed, "report", "exclude_lines")) == EXPECTED_EXCLUSIONS


@pytest.mark.parametrize(
    "dangerous",
    [".*", ".+", "def ", "return", "if ", "raise", "except", "^", "$", "..*"],
)
def test_no_exclusion_pattern_is_broad_enough_to_hide_real_code(parsed, dangerous):
    """`exclude_lines = .*` would report 100% on an untested repository, and it is one line in
    a config file nobody reads. Each of these would hide a large fraction of real branches."""
    patterns = _lines(parsed, "report", "exclude_lines")
    assert dangerous not in patterns, (
        f"{dangerous!r} as an exclusion pattern hides real code from the measurement"
    )


def test_pragma_no_cover_is_used_sparingly_and_always_explained():
    """It is the one exclusion that can be applied anywhere, so its uses are counted. Each must
    carry a reason on the same line — an unexplained one is indistinguishable from hiding a
    branch that was inconvenient to test."""
    import os
    import re

    unexplained: list[str] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [
            d
            for d in dirnames
            if d
            not in {".git", "__pycache__", "tests", ".venv", "vendor", "node_modules"}
        ]
        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            path = pathlib.Path(dirpath) / filename
            for number, line in enumerate(
                path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1
            ):
                if "pragma: no cover" not in line:
                    continue
                total += 1
                # A reason follows the pragma, e.g. `# pragma: no cover - diagnostic only`.
                if not re.search(r"pragma:\s*no cover\s*[-—:]\s*\S", line):
                    unexplained.append(f"{path.name}:{number}: {line.strip()[:70]}")

    assert not unexplained, (
        "these suppress coverage with no stated reason:\n  " + "\n  ".join(unexplained)
    )
    assert total < 20, f"{total} coverage suppressions is more than sparing"


# ── The measurement is honest about what it covers ───────────────────────────


def test_the_config_documents_why_each_exclusion_is_defensible():
    """A pattern with no comment beside it is one nobody can evaluate later."""
    text = CONFIG.read_text(encoding="utf-8")
    for pattern, expected_word in (
        ("scripts/mutation_", "subprocess"),
        ("gui/static/", "Vendored"),
        ("if __name__", "subprocess"),
        ("if TYPE_CHECKING", "runtime"),
    ):
        assert pattern in text
        assert expected_word in text, (
            f"the reason for excluding {pattern!r} is not stated in pyproject.toml"
        )


def test_branch_coverage_is_off_and_that_is_stated(parsed):
    """Stated so the number is not read as stronger than it is: 92% of STATEMENTS is not 92%
    of branches, and the difference matters for a codebase this full of guards."""
    assert parsed["run"]["branch"] is False


def test_coverage_is_actually_gated():
    """A configured coverage block with no threshold gates nothing.

    This file pinned the exclusions -- which shape the number -- while nothing produced
    or checked the number itself. Pinning `fail_under` means lowering the bar becomes a
    visible edit to a tested value rather than a quiet deletion.
    """
    text = CONFIG.read_text(encoding="utf-8")
    assert "fail_under" in text, (
        "no fail_under in [tool.coverage.report]: the coverage configuration shapes a "
        "number that nothing enforces"
    )
    import re

    match = re.search(r"^fail_under\s*=\s*(\d+)", text, re.MULTILINE)
    assert match, "fail_under is present but not parseable as a number"
    floor = int(match.group(1))
    assert floor >= 85, f"fail_under={floor} is too low to catch a real regression"


def test_the_ci_workflow_measures_coverage():
    """The gate has to run somewhere, or fail_under is also decoration."""
    workflow = ROOT / ".github" / "workflows" / "ci.yml"
    if not workflow.is_file():
        pytest.skip("no CI workflow in this checkout")
    text = workflow.read_text(encoding="utf-8")
    assert "--cov" in text, (
        "no CI step runs pytest with --cov, so fail_under is never evaluated"
    )
