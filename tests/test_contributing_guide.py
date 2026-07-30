"""
Keep CONTRIBUTING.md honest.

A contributing guide is the one document a newcomer trusts completely, and it is also the
document nobody re-reads once it is written. So the checkable claims are checked: the files
it points at, the helpers it tells you to call, the commands it tells you to run, and the
counts it quotes.

This is not pedantry about documentation. The guide's whole purpose is to stop someone
removing a safety control by doing the obvious thing — if it names a helper that has been
renamed, the reader reasonably concludes the convention no longer applies.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUIDE = ROOT / "CONTRIBUTING.md"


@pytest.fixture(scope="module")
def guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def test_the_guide_exists_and_is_substantial(guide):
    assert len(guide) > 4000


def test_every_repository_path_it_names_exists(guide, repo_files):
    """A guide that points at a moved file teaches the wrong layout."""
    # Paths in the layout tree and inline code spans, e.g. `handlers/egress.py`.
    candidates = set(
        re.findall(r"`([\w./-]+\.(?:py|md|yaml|yml|toml|html|example))`", guide)
    )
    candidates |= set(re.findall(r"^├── ([\w./-]+\.py)", guide, re.MULTILINE))
    candidates |= set(re.findall(r"^│   ├── ([\w./-]+\.py)", guide, re.MULTILINE))

    # Names that are illustrative rather than real paths in this repo.
    ignore = {"pyproject.toml", ".env.example", "index.html", "server.json"}

    # One walk, not one per candidate. The previous version called ROOT.rglob() inside the
    # loop for every path that was not found relative to the root, which walked the whole
    # tree — including the 2.9 MB vendored console runtime — dozens of times and made this
    # the slowest test in the suite at 12.6s. A slow suite gets skipped, which costs more
    # than the check is worth.
    every_name = {path.name for path in repo_files()}

    missing = [
        candidate
        for candidate in sorted(candidates - ignore)
        if "*" not in candidate
        and not (ROOT / candidate).exists()
        # Some spans name a file by its basename inside a package listed elsewhere.
        and pathlib.Path(candidate).name not in every_name
    ]
    assert not missing, f"CONTRIBUTING.md points at files that do not exist: {missing}"


@pytest.mark.parametrize(
    ("symbol", "module"),
    [
        ("refuse_undeclared", "handlers/shared.py"),
        ("form_data_declared", "handlers/shared.py"),
        ("ok_allow_secrets", "handlers/shared.py"),
        ("assert_egress_allowed", "handlers/egress.py"),
        ("guard_nested_host_fields", "handlers/egress.py"),
        ("evaluate", "authz.py"),
    ],
)
def test_every_helper_it_tells_you_to_call_exists(guide, symbol, module):
    """If the guide names a helper that has been renamed, a reader concludes the
    convention no longer applies — which is precisely backwards."""
    assert symbol in guide, f"{symbol} is no longer mentioned in CONTRIBUTING.md"
    source = (ROOT / module).read_text(encoding="utf-8")
    # The opening parenthesis matters: "def refuse_undeclared" is a substring of
    # "def refuse_undeclared_RENAMED", so without it a rename passes this test — which is
    # exactly the substring mistake this codebase has had to fix elsewhere.
    assert f"def {symbol}(" in source, (
        f"{symbol} is documented in CONTRIBUTING.md but absent from {module}"
    )


def test_the_scripts_it_tells_you_to_run_exist(guide):
    for script in re.findall(r"scripts/([\w.-]+\.py)", guide):
        assert (ROOT / "scripts" / script).is_file(), f"scripts/{script} does not exist"


def test_the_mutation_counts_are_accurate(guide):
    """The guide quotes how many mutations each harness carries. A stale number
    undersells or oversells the evidence."""
    claimed = {
        "mutation_rounds_1_3.py": int(
            re.search(r"mutation_rounds_1_3\.py.*?(\d+) mutations", guide, re.S).group(
                1
            )
        ),
        "mutation_round_4.py": int(
            re.search(r"mutation_round_4\.py.*?(\d+) mutations", guide, re.S).group(1)
        ),
    }
    for name, count in claimed.items():
        source = (ROOT / "scripts" / name).read_text(encoding="utf-8")
        # Each entry is a tuple opened at one indent level inside MUTATIONS.
        actual = len(re.findall(r"^    \(", source, re.MULTILINE))
        assert actual == count, (
            f"{name}: guide says {count} mutations, file has {actual}"
        )


def test_the_provenance_tags_it_documents_match_the_spec(guide):
    """The tag table is how a contributor learns what evidence a new path needs."""
    for tag in ("[TF]", "[DOC]", "[LIVE]", "[LIVE+METHOD]", "[PAT]"):
        assert tag in guide, f"{tag} is missing from the provenance table"

    spec = (ROOT / "handlers" / "capella" / "spec.py").read_text(encoding="utf-8")
    for tag in ("[TF]", "[DOC]", "[LIVE]", "[PAT]"):
        assert tag in spec, f"{tag} is documented in the guide but unknown to spec.py"


def test_the_claim_that_no_inferred_paths_remain_is_true(guide):
    """The guide states none remain. If one is added later this must fail, because the
    sentence would then be actively misleading about the state of the surface."""
    if "none currently remain" not in guide:
        pytest.skip("the guide no longer makes that claim")

    import os

    os.environ.setdefault("CB_ADMIN_PROFILE", "workstation")
    from handlers.capella.spec import OPS_BY_NAME

    inferred = [n for n, o in OPS_BY_NAME.items() if "[PAT]" in (o.summary or "")]
    assert not inferred, (
        "CONTRIBUTING.md says no [PAT] paths remain, but these are tagged: "
        f"{sorted(inferred)}. Either verify them or update the guide."
    )


def test_the_profile_variable_it_warns_about_really_has_no_default(guide):
    """The guide leads with 'CB_ADMIN_PROFILE has no default' as the first thing that will
    trip you up. If a default were added, that section would send people the wrong way."""
    assert "CB_ADMIN_PROFILE" in guide

    import importlib

    import profile_config

    importlib.reload(profile_config)
    assert set(profile_config._VALID) == {"workstation", "enterprise"}
    # No default: an unset or unrecognised value resolves to None, and validate() then
    # returns a fatal error rather than assuming one of the two.
    assert profile_config.profile_name() in (None, "workstation", "enterprise")
    assert profile_config.validate(None), (
        "an unset profile is no longer fatal, so the guide's leading warning is wrong"
    )


def test_the_precommit_config_the_guide_promises_exists():
    """`pre-commit` was a declared dev dependency with no config file, so
    `uv run pre-commit install` — which the guide tells you to run — failed."""
    config = ROOT / ".pre-commit-config.yaml"
    assert config.is_file(), "the guide tells contributors to install pre-commit hooks"
    text = config.read_text(encoding="utf-8")
    assert "ruff" in text

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    pinned = re.search(r'"ruff==([\d.]+)"', pyproject)
    assert pinned, "ruff is not pinned in the dev extra"
    assert f"v{pinned.group(1)}" in text, (
        "the pre-commit ruff revision differs from the pinned dev version; the two would "
        "format differently and leave a diff nobody can land"
    )


def test_the_issue_link_points_at_the_chosen_org(guide):
    assert (
        "github.com/Couchbase-Ecosystem/couchbase-admin-mcp-server/issues" in guide
    ), "the guide sends bug reports somewhere other than the chosen org"
