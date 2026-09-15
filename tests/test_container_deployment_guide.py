"""Every configuration printed in the deployment guide must actually start.

WHY THIS FILE EXISTS
====================
`docs/CONTAINER_DEPLOYMENT.md` is the document a customer follows to stand this
server up in Docker, on AWS and on GCP. It is therefore the one place where a
stale environment variable does not produce a failing test -- it produces a
customer with a container that refuses to boot and a guide that told them to do
exactly that.

This repository has been here before. Every startup control added during the
security review made some documented example stale, and none of them failed a
test until `tests/test_documented_configurations_start.py` began extracting the
README's examples and running them through the real `_enforce_profile()`. This
file does the same for the deployment guide, and adds the rule that is specific
to deployment artifacts:

    ONE CONTAINER, ONE CONTROL PLANE.

`both` is a mode the server supports, that no artifact configures, and that no
document demonstrates. It switches capability gating off, which removes the
containment per-surface deployments exist to provide. A guide that showed a
customer how to reach it would undo the rule everything else enforces -- so the
guide is parsed and asserted, not trusted.

WHAT IS ASSERTED, AND WHAT IS NOT
=================================
Asserted: every `ini` configuration block in the guide starts under the real
startup validation, declares its surface, and never carries both surfaces'
credentials. Also that the JSON and shell examples -- the ECS task definition
and the `gcloud run deploy` line, which a customer pastes verbatim -- carry the
same declaration and the same absence.

NOT asserted: that the AWS and GCP resources around those configurations exist,
are reachable, or are named correctly. Nothing here deploys anything. The guide
says so in its own section 10, and that honesty is itself checked below.
"""

from __future__ import annotations

import importlib
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUIDE = ROOT / "docs" / "CONTAINER_DEPLOYMENT.md"

#: A block the guide marks as a named configuration:
#:
#:     ```ini
#:     # CONFIGURATION: local-capella-stdio
#:     KEY=value
#:     ```
_BLOCK = re.compile(
    r"```ini\n# CONFIGURATION: ([A-Za-z0-9-]+)\n(.*?)```",
    re.S,
)


def _configurations() -> dict[str, dict[str, str]]:
    text = GUIDE.read_text(encoding="utf-8")
    found: dict[str, dict[str, str]] = {}
    for name, body in _BLOCK.findall(text):
        env: dict[str, str] = {}
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
        found[name] = env
    return found


_CONFIGURATIONS = _configurations()


def test_the_guide_exists_and_its_configurations_are_extractable():
    """The premise for everything below.

    A regex that silently matched nothing would turn every parametrised test in
    this file into an empty green tick -- which is the failure
    tests/test_no_vacuous_coverage.py exists to catch, stated here explicitly
    because this file's whole value is that the extraction worked.
    """
    assert GUIDE.is_file(), "docs/CONTAINER_DEPLOYMENT.md is gone"
    assert len(_CONFIGURATIONS) >= 4, (
        f"expected the guide's named configuration blocks to be found, got "
        f"{sorted(_CONFIGURATIONS)}. If the block format changed, fix the regex "
        "-- do not delete the test, or the guide stops being checked at all."
    )
    for name, env in _CONFIGURATIONS.items():
        assert env, f"configuration {name!r} parsed as empty"


def _enforce(env: dict, monkeypatch) -> list[str]:
    """Run the server's REAL startup validation under `env`.

    Same harness as tests/test_documented_configurations_start.py, which is the
    point: a guide checked by a weaker imitation of the startup path would pass
    while the container refuses to boot.
    """
    import os

    for key in [k for k in list(os.environ) if k.startswith(("CB_", "OAUTH_"))]:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    import audit
    import profile_config
    import tls_config

    importlib.reload(profile_config)
    importlib.reload(tls_config)
    audit.reset_audit_sink()

    problems = list(profile_config.PROFILE_ERRORS)
    sink = audit.audit_sink_error()
    if sink:
        problems.append(sink)
    problems.extend(
        tls_config.validate(
            env.get("CB_ADMIN_HOST", "127.0.0.1"),
            env.get("CB_ADMIN_TRANSPORT", "stdio").lower(),
        )
    )
    return problems


@pytest.mark.parametrize("name", sorted(_CONFIGURATIONS))
def test_a_documented_configuration_starts(name, tmp_path, monkeypatch):
    """A guide that documents a configuration the server refuses is worse than a
    guide with no example: the reader follows it and concludes the product is
    broken."""
    env = dict(_CONFIGURATIONS[name])

    # The guide names a container path for the audit sink, which does not exist
    # on the machine running the tests. The question under test is whether the
    # CONFIGURATION is coherent, not whether this checkout can create /var/log --
    # so the path is redirected and the sink still has to open.
    if "CB_ADMIN_AUDIT_FILE" in env:
        env["CB_ADMIN_AUDIT_FILE"] = str(tmp_path / "audit.log")

    problems = _enforce(env, monkeypatch)
    assert not problems, (
        f"the guide's {name!r} configuration refuses to start:\n  "
        + "\n  ".join(problems)
        + "\n\nFix the guide, not this test. A customer follows that block "
        "verbatim."
    )


@pytest.mark.parametrize("name", sorted(_CONFIGURATIONS))
def test_a_documented_configuration_declares_its_surface(name):
    """Without the declaration the mode is whatever the environment implies, and
    the inference that matters resolves to `both`."""
    env = _CONFIGURATIONS[name]
    declared = env.get("CB_ADMIN_REQUIRE_DEPLOYMENT")
    assert declared in ("capella", "self_managed"), (
        f"configuration {name!r} declares CB_ADMIN_REQUIRE_DEPLOYMENT="
        f"{declared!r}. Every configuration in a deployment guide must declare "
        "exactly one surface."
    )


@pytest.mark.parametrize("name", sorted(_CONFIGURATIONS))
def test_a_documented_configuration_carries_one_surface_only(name):
    """THE rule. A Capella key plus a non-Capella connection string is `both`,
    which switches capability gating off -- and it reads like adding reach."""
    env = _CONFIGURATIONS[name]
    capella = {"CAPELLA_API_KEY_SECRET", "CAPELLA_ACCESS_KEY_ID"} & set(env)
    self_managed = {"CB_CONNECTION_STRING"} & set(env)
    assert not (capella and self_managed), (
        f"configuration {name!r} carries Capella credentials {sorted(capella)} "
        f"AND {sorted(self_managed)}. That resolves to 'both'."
    )

    declared = env.get("CB_ADMIN_REQUIRE_DEPLOYMENT")
    if declared == "capella":
        assert not self_managed, (
            f"{name!r} declares capella but sets {sorted(self_managed)}; the "
            "container would refuse to start, having been told to do this"
        )
    if declared == "self_managed":
        assert not capella, f"{name!r} declares self_managed but sets {sorted(capella)}"


def test_the_guide_never_demonstrates_both():
    """Not a single block, in any language, anywhere in the document.

    Scanned as raw text rather than per-parsed-block, because the ECS task
    definition and the `gcloud run deploy` line are neither, and they are what a
    customer pastes verbatim.
    """
    text = GUIDE.read_text(encoding="utf-8")
    offenders = [
        f"line {n}: {line.strip()}"
        for n, line in enumerate(text.splitlines(), start=1)
        if re.search(
            r"(CB_DEPLOYMENT|CB_ADMIN_REQUIRE_DEPLOYMENT)\W+(\"|')?both", line, re.I
        )
    ]
    assert not offenders, (
        "the deployment guide demonstrates the 'both' mode, which switches "
        "capability gating off:\n  " + "\n  ".join(offenders)
    )


def test_every_pasteable_example_declares_its_surface():
    """The ECS task definition and the gcloud line are the two things a reader
    copies wholesale. Each must carry the declaration; a JSON block that sets
    CB_DEPLOYMENT and omits CB_ADMIN_REQUIRE_DEPLOYMENT is exactly the shape
    that silently widens."""
    text = GUIDE.read_text(encoding="utf-8")

    fenced = re.findall(r"```(?:json|bash)\n(.*?)```", text, re.S)
    checked = 0
    for block in fenced:
        if "CB_DEPLOYMENT" not in block:
            continue
        checked += 1
        assert "CB_ADMIN_REQUIRE_DEPLOYMENT" in block, (
            "a pasteable example sets CB_DEPLOYMENT without declaring "
            "CB_ADMIN_REQUIRE_DEPLOYMENT, so the surface is inferred:\n" + block[:400]
        )

    assert checked >= 2, (
        f"expected the ECS task definition and the gcloud deploy example to be "
        f"found and checked, matched {checked}. If they were reformatted, fix "
        "this matcher rather than losing the check."
    )


def test_the_guide_states_what_has_not_been_exercised():
    """CLAUDE.md rule 1.7, applied to a document: a guide that reads as though
    every path in it had been run is making a claim it cannot support.

    The HTTP transport has never been exercised and the cloud shapes have never
    been deployed by this project. A customer debugging one of them deserves to
    know that before they start, not after.
    """
    text = GUIDE.read_text(encoding="utf-8")
    for required in (
        "Never exercised",
        "never applied",
        "Never brought up",
    ):
        assert required.lower() in text.lower(), (
            f"the deployment guide no longer states {required!r}. If a path has "
            "since been exercised, say so with a date -- do not simply delete "
            "the admission."
        )
