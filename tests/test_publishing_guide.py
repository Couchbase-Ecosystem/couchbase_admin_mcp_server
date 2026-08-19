"""
PUBLISHING.md must describe the repository that actually exists.

WHY THIS IS TESTED AND NOT JUST WRITTEN
=======================================
A publication checklist is read exactly once, by someone who cannot tell a stale instruction
from a correct one — they have no basis for judging it. Every name in it (CI job, secret,
environment variable, console entry point, repository URL) is a name defined somewhere else in
the tree, and every one of them can drift.

The specific failure this prevents: renaming a CI job so the branch-protection command in
step 4 silently requires a check that will never report, which leaves `main` unprotected while
looking protected.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "PUBLISHING.md"


@pytest.fixture(scope="module")
def doc() -> str:
    return DOC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def workflow() -> str:
    return (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ci_jobs(workflow) -> set[str]:
    """Top-level job names in the workflow.

    Two-space indentation under `jobs:`; anything deeper is a step or a key. Parsed rather
    than hard-coded, so adding a job cannot make this test stale in the direction that
    matters.
    """
    body = workflow.split("\njobs:", 1)[1]
    return set(re.findall(r"^  ([a-z][a-z0-9-]*):$", body, re.MULTILINE))


def test_the_guide_exists_and_is_not_a_stub(doc):
    assert len(doc.splitlines()) > 60


def test_the_repository_url_matches_the_project_metadata(doc):
    """A push to the wrong URL creates a stray repository under whatever account can write
    there, which is a mess to unpick."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    homepage = re.search(r'Homepage\s*=\s*"([^"]+)"', pyproject)
    assert homepage, "pyproject.toml declares no Homepage"
    slug = homepage.group(1).rstrip("/").removeprefix("https://github.com/")
    assert slug in doc, f"the guide does not name the repository from pyproject: {slug}"


def test_every_required_status_check_is_a_real_ci_job(doc, ci_jobs):
    """THE failure this file exists for. Branch protection that requires a job name which
    does not exist leaves the branch unprotected while the settings page says otherwise."""
    required = set(
        re.findall(r"required_status_checks\[contexts\]\[\]=([a-z0-9-]+)", doc)
    )
    assert required, "the guide's branch-protection command lists no required checks"
    missing = required - ci_jobs
    assert not missing, (
        f"the guide requires CI checks that do not exist: {sorted(missing)}. "
        f"Real jobs: {sorted(ci_jobs)}"
    )


def test_the_mutation_job_is_among_the_required_checks(doc):
    """It is the only job that fails when a security guard is deleted and the suite stays
    green. Advisory-only would defeat the point of having it."""
    required = set(
        re.findall(r"required_status_checks\[contexts\]\[\]=([a-z0-9-]+)", doc)
    )
    assert "mutation" in required


def test_the_live_capella_job_is_deliberately_not_required(doc, ci_jobs):
    """It cannot pass on a fork's pull request, because GitHub withholds secrets there.
    Requiring it would block every external contribution — so the guide must both exclude it
    AND say why, or the next person will "fix" the omission."""
    assert "capella-paths" in ci_jobs
    required = set(
        re.findall(r"required_status_checks\[contexts\]\[\]=([a-z0-9-]+)", doc)
    )
    assert "capella-paths" not in required
    assert "fork" in doc.lower(), (
        "the exclusion is unexplained, so it looks like an oversight"
    )


def test_the_secret_name_matches_what_the_workflow_reads(doc, workflow):
    """A secret set under the wrong name does not error. The job takes its "not configured"
    branch and exits 0, so CI stays green and nothing is verified."""
    names = set(re.findall(r"secrets\.([A-Z_][A-Z0-9_]*)", workflow))
    assert names, "the workflow reads no secrets"
    for name in names:
        assert name in doc, (
            f"the workflow reads secrets.{name} but the guide never names it"
        )


def test_the_key_environment_variable_matches_the_verifier(doc):
    """The guide, the workflow and the script have to agree on one spelling."""
    script = (ROOT / "scripts" / "verify_capella_paths.py").read_text(encoding="utf-8")
    assert 'os.environ.get("CB_CAPELLA_API_KEY"' in script
    assert "CB_CAPELLA_API_KEY" in doc


def test_the_guide_says_the_key_is_the_secret_not_the_id(doc):
    """The single most common way to run this wrong, and it fails as a 401 that reads like a
    permissions problem. The script itself warns about it; so should the setup guide."""
    assert re.search(r"\bSECRET\b", doc)
    assert re.search(r"not the (key )?\*\*?id\*\*?|not the key id", doc, re.IGNORECASE)


def test_the_guide_names_the_real_console_entry_point(doc):
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    scripts = re.findall(
        r"^([a-z][\w-]*)\s*=\s*\"[\w.]+:\w+\"", pyproject, re.MULTILINE
    )
    assert scripts, "pyproject declares no console script"
    assert any(name in doc for name in scripts), (
        f"the guide's post-push check names none of the real entry points: {scripts}"
    )


def test_the_verification_commands_in_the_guide_are_real(doc):
    """Every command offered as evidence must exist. A checklist that tells you to run a
    script that was renamed is worse than no checklist: it produces a confident "done"."""
    referenced = set(re.findall(r"(scripts/[\w./-]+\.py)", doc))
    assert referenced, "the guide references no scripts"
    for relative in referenced:
        assert (ROOT / relative).exists(), (
            f"the guide references a missing file: {relative}"
        )


def test_the_bootstrap_flag_pairing_is_stated_correctly(doc):
    """If the guide or runbook showed --bootstrap-app-service without --yes-really-mutate,
    following it would just print a refusal — and the reader would conclude the feature is
    broken rather than that they are missing a flag."""
    runbook = (ROOT / "RUNBOOK.md").read_text(encoding="utf-8")
    for name, text in (("PUBLISHING.md", doc), ("RUNBOOK.md", runbook)):
        for line in text.splitlines():
            if "--bootstrap-app-service" in line and "python" in line:
                assert "--yes-really-mutate" in line, (
                    f"{name} shows a --bootstrap-app-service command without "
                    f"--yes-really-mutate, which will only ever print a refusal: {line.strip()}"
                )
