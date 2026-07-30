"""
Publication metadata: the target org, and the URLs that encode it.

WHY PIN THIS
============
The repository is published under `github.com/Couchbase-Ecosystem/`. That decision is
encoded in more than one place — `pyproject.toml`'s Homepage and Issues URLs, and the
README's support section — and those are exactly the strings that rot when a file is
copied from another project or a URL is updated in one place only.

Getting it wrong is not cosmetic: the Issues URL is where the README tells users to
report bugs, so a stale org sends every bug report into a repository that does not
exist, and the reporter has no way to tell.

There is a specific reason to be strict here. During the review I recorded in the
handoff that the official `mcp-server-couchbase` had been "graduated out of
Couchbase-Ecosystem into couchbase/". That was wrong — it is still in
Couchbase-Ecosystem. An assertion is cheaper than a claim in a document nobody re-checks.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The single stated home for this project.
ORG = "Couchbase-Ecosystem"
REPO = "couchbase-admin-mcp-server"
REPO_URL = f"https://github.com/{ORG}/{REPO}"


def _pyproject() -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - 3.10
        tomllib = pytest.importorskip("tomli")
    with open(ROOT / "pyproject.toml", "rb") as handle:
        return tomllib.load(handle)


def test_the_declared_urls_point_at_the_chosen_org():
    urls = _pyproject()["project"]["urls"]
    assert urls["Homepage"] == REPO_URL, urls["Homepage"]
    assert urls["Issues"] == f"{REPO_URL}/issues", urls["Issues"]


def test_the_package_name_matches_the_repository_name():
    """A mismatch here is the kind of thing that only surfaces at publish time."""
    assert _pyproject()["project"]["name"] == REPO


def test_the_readme_sends_bug_reports_to_the_right_place():
    """The README tells users where to report problems. If that URL is stale, reports go
    to a repository that does not exist and the reporter gets no signal."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"{REPO_URL}/issues" in readme, (
        "the README's issue link does not point at the chosen org/repo"
    )


def test_no_file_points_at_a_different_org_for_this_project(repo_files):
    """Catches a half-finished rename: this project's own repo URL under any other org.

    Deliberately narrow. It looks for THIS repository's name under a DIFFERENT
    organisation, rather than banning every mention of other orgs — links to the
    Terraform provider, the data-plane server and the upstream this derives from are all
    legitimate and must keep working.
    """
    pattern = re.compile(
        r"github\.com/(?!" + re.escape(ORG) + r"/)([\w.-]+)/" + re.escape(REPO)
    )
    # Skip directories that hold vendored or generated content: nothing in them names this
    # repository, and walking them was most of this test's 4.9s runtime.
    skip_dirs = {
        ".git",
        "__pycache__",
        "vendor",
        "dist",
        "build",
        ".ruff_cache",
        ".pytest_cache",
        "node_modules",
    }

    offenders: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or skip_dirs & set(path.parts):
            continue
        if path.suffix.lower() not in (
            ".py",
            ".md",
            ".toml",
            ".yml",
            ".yaml",
            ".example",
            ".json",
            ".txt",
        ) and path.name not in ("Dockerfile", ".env.example"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in pattern.finditer(text):
            offenders.append(f"{path.relative_to(ROOT)}: {match.group(0)}")
    assert not offenders, "this repo is referenced under another org:\n" + "\n".join(
        offenders
    )


def test_the_licence_metadata_and_files_agree():
    """LICENSE said MIT/an individual while pyproject said Apache-2.0/Couchbase, Inc.
    The two disagreeing is the sort of thing that stops a publication review rather than
    a build, so it is asserted rather than remembered."""
    project = _pyproject()["project"]
    assert project["license"] == "Apache-2.0"
    assert any("Couchbase" in a.get("name", "") for a in project["authors"]), project[
        "authors"
    ]

    licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in licence
    assert "Version 2.0, January 2004" in licence
    assert "MIT License" not in licence

    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "Couchbase, Inc." in notice


def test_both_licence_files_ship_in_the_wheel():
    """Apache 2.0 section 4(d) requires NOTICE to travel with redistributions."""
    declared = _pyproject()["project"].get("license-files", [])
    assert "LICENSE" in declared and "NOTICE" in declared, declared
