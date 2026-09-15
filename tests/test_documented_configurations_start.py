"""
The configurations the README hands people must actually start.

WHY THIS EXISTS
===============
The Quick start told you to set "at minimum CB_CONNECTION_STRING / CB_USERNAME /
CB_PASSWORD". Following it produced:

    [couchbase-admin-mcp] REFUSING TO START: CB_ADMIN_PROFILE is not set.

The refusal is correct — the two deployment profiles have opposite security postures and
guessing between them is how an unauthenticated admin API ends up on a network interface.
But the README did not mention the variable, so the documented path was a dead end, and the
docker-compose example was worse: `workstation` + HTTP + `0.0.0.0` is fatal twice over
without two explicit acknowledgements.

Every startup control added during the security review made some documented example stale,
and none of them failed a test. So the examples are now extracted FROM THE README and run
through the real `_enforce_profile()`.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"


#: Run in a CHILD process, printing the problems as JSON on the last line.
_VALIDATION_SCRIPT = """
import json, os, sys
sys.path.insert(0, os.environ["CB_TEST_REPO_ROOT"])
import audit, profile_config, tls_config
problems = list(profile_config.PROFILE_ERRORS)
sink = audit.audit_sink_error()
if sink:
    problems.append(sink)
problems.extend(tls_config.validate(
    os.environ.get("CB_ADMIN_HOST", "127.0.0.1"),
    os.environ.get("CB_ADMIN_TRANSPORT", "stdio").lower(),
))
print("PROBLEMS_JSON " + json.dumps(problems))
"""


def _enforce(env: dict, _monkeypatch=None) -> list[str]:
    """Run the real startup validation under `env`, IN A SUBPROCESS.

    WHY A SUBPROCESS AND NOT importlib.reload
    =========================================
    profile_config and tls_config snapshot configuration AT IMPORT. This helper
    used to reload them in-process under a synthetic environment -- including,
    deliberately, configurations that FAIL, because that is how each requirement
    is proven load-bearing. monkeypatch restores the environment afterwards; it
    cannot restore a module's snapshot of it.

    What leaked: gui/gui_server.py used to call sys.exit(2) at module scope when
    profile_config.PROFILE_ERRORS was non-empty, so the next test to import the
    console died during COLLECTION, naming an OAuth control unrelated to it.
    MEASURED 2026-09-15 under randomised order.

    CLAUDE.md section 2.2 already prescribed this: "pin it in a subprocess if
    `server` has to be re-imported -- `server` and `handlers.shared` snapshot
    their configuration at import, so `importlib.reload` leaks into every test
    that runs afterwards." A teardown that reloads afterwards is a cleanup that
    has to be correct; a child process cannot leak at all.

    The `_monkeypatch` argument is vestigial and kept so the existing call sites
    read unchanged. Nothing is patched in this process any more.

    The child inherits this process's environment MINUS every CB_* and OAUTH_*
    variable, so a developer's shell cannot leak in -- and PATH, SYSTEMROOT and
    the rest survive, which a hand-built env dict would get wrong on Windows.
    """
    child_env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("CB_", "OAUTH_"))
    }
    child_env.update({str(k): str(v) for k, v in env.items()})
    child_env["CB_TEST_REPO_ROOT"] = str(ROOT)

    result = subprocess.run(
        [sys.executable, "-c", _VALIDATION_SCRIPT],
        env=child_env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,  # the whole point is to inspect a FAILING validation
    )
    assert result.returncode == 0, (
        f"the validation subprocess failed:\n{result.stdout}\n{result.stderr}"
    )
    marker = [
        line for line in result.stdout.splitlines()
        if line.startswith("PROBLEMS_JSON ")
    ]
    assert marker, (
        f"the validation subprocess printed no result:\n{result.stdout}\n{result.stderr}"
    )
    return json.loads(marker[-1][len("PROBLEMS_JSON "):])


# ── The Quick start ──────────────────────────────────────────────────────────


def test_the_quick_start_names_the_profile():
    """It is the one variable with no default, so omitting it makes the whole section a
    dead end."""
    readme = README.read_text(encoding="utf-8")
    quick_start = readme.split("## Quick start", 1)[1].split("---", 1)[0]
    assert "CB_ADMIN_PROFILE" in quick_start, (
        "the Quick start does not mention CB_ADMIN_PROFILE, without which the server "
        "refuses to start"
    )


def test_the_documented_quick_start_configuration_starts(monkeypatch):
    problems = _enforce(
        {
            "CB_ADMIN_PROFILE": "workstation",
            "CB_CONNECTION_STRING": "couchbase://localhost",
            "CB_USERNAME": "Administrator",
            "CB_PASSWORD": "password",
        },
        monkeypatch,
    )
    assert not problems, problems


def test_omitting_the_profile_is_still_fatal(monkeypatch):
    """Guards the test above from passing because the check was removed."""
    problems = _enforce(
        {
            "CB_CONNECTION_STRING": "couchbase://localhost",
            "CB_USERNAME": "Administrator",
            "CB_PASSWORD": "password",
        },
        monkeypatch,
    )
    assert problems, "an unset profile is no longer fatal"
    assert any("CB_ADMIN_PROFILE" in p for p in problems)


# ── The examples embedded in the README ──────────────────────────────────────


def _compose_environment() -> dict:
    """Pull the `environment:` block out of the README's docker-compose example."""
    readme = README.read_text(encoding="utf-8")
    block = re.search(r"# docker-compose\.yml.*?environment:\n(.*?)\n```", readme, re.S)
    assert block, "the docker-compose example is no longer in the README"

    env: dict[str, str] = {}
    for line in block.group(1).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r'([A-Z_][A-Z0-9_]*):\s*"?([^"#]*)"?', stripped)
        if match:
            env[match.group(1)] = match.group(2).strip()
    return env


def test_the_compose_example_is_extractable():
    """Premise for the test below; a silently-empty extraction would make it vacuous."""
    env = _compose_environment()
    assert env.get("CB_ADMIN_PROFILE"), env
    assert env.get("CB_ADMIN_TRANSPORT") == "http", env


def test_the_documented_compose_configuration_starts(monkeypatch):
    """`workstation` + HTTP + 0.0.0.0 is fatal twice over — once for the locality premise
    and once for cleartext bearer tokens — so the example has to carry both
    acknowledgements. It did not."""
    problems = _enforce(_compose_environment(), monkeypatch)
    assert not problems, (
        "the README's docker-compose example refuses to start:\n  "
        + "\n  ".join(problems)
    )


def test_removing_either_compose_acknowledgement_is_fatal(monkeypatch):
    """Both are load-bearing. If either becomes unnecessary, the comments explaining them
    are misleading and should go."""
    base = _compose_environment()
    for dropped in (
        "CB_ADMIN_WORKSTATION_CONTAINER_BIND",
        "CB_ADMIN_TLS_TERMINATED_EXTERNALLY",
    ):
        env = {k: v for k, v in base.items() if k != dropped}
        problems = _enforce(env, monkeypatch)
        assert problems, f"dropping {dropped} is no longer fatal"


# ── The enterprise shape, which is what the unattended agent chain uses ────────────


def test_a_complete_enterprise_configuration_starts(tmp_path, monkeypatch):
    """The unattended shape has the most requirements, so it is the easiest to document
    incompletely."""
    problems = _enforce(
        {
            "CB_ADMIN_PROFILE": "enterprise",
            "CB_ADMIN_TRANSPORT": "http",
            "CB_ADMIN_HOST": "0.0.0.0",
            "CB_CONNECTION_STRING": "couchbases://cluster.example",
            "CB_USERNAME": "Administrator",
            "CB_PASSWORD": "password",
            "OAUTH_ISSUER": "https://idp.example/realms/mcp",
            "OAUTH_AUDIENCE": "api://couchbase-admin-mcp",
            "CB_ADMIN_HTTP_REQUIRE_AUTH": "true",
            "CB_ADMIN_AUDIT_FILE": str(tmp_path / "audit.log"),
            "CB_ADMIN_TLS_TERMINATED_EXTERNALLY": "1",
        },
        monkeypatch,
    )
    assert not problems, problems


@pytest.mark.parametrize(
    "dropped",
    [
        "OAUTH_ISSUER",
        "OAUTH_AUDIENCE",
        "CB_ADMIN_HTTP_REQUIRE_AUTH",
        "CB_ADMIN_TLS_TERMINATED_EXTERNALLY",
    ],
)
def test_each_enterprise_requirement_is_load_bearing(dropped, tmp_path, monkeypatch):
    """Every one of these was a real finding: no issuer means no principal to authorize,
    no audience accepts a token minted for another application, auth off means no scope
    separation at all, and no TLS puts the automation-scoped bearer token on the wire in
    cleartext."""
    env = {
        "CB_ADMIN_PROFILE": "enterprise",
        "CB_ADMIN_TRANSPORT": "http",
        "CB_ADMIN_HOST": "0.0.0.0",
        "OAUTH_ISSUER": "https://idp.example/realms/mcp",
        "OAUTH_AUDIENCE": "api://couchbase-admin-mcp",
        "CB_ADMIN_HTTP_REQUIRE_AUTH": "true",
        "CB_ADMIN_AUDIT_FILE": str(tmp_path / "audit.log"),
        "CB_ADMIN_TLS_TERMINATED_EXTERNALLY": "1",
    }
    if dropped == "CB_ADMIN_HTTP_REQUIRE_AUTH":
        env[dropped] = "false"  # explicitly off is the dangerous case, not merely unset
    else:
        env.pop(dropped)

    problems = _enforce(env, monkeypatch)
    assert problems, f"the enterprise profile no longer requires {dropped}"


# ── The SHIPPED compose files, as opposed to the README's example ─────────────
#
# test_a_complete_enterprise_configuration_starts above proves a HAND-WRITTEN
# enterprise environment starts. Nothing proved that the artifact we ship can be
# given one, and it could not: docker-compose.ee.yml defaulted CB_ADMIN_PROFILE
# to `enterprise` and named none of the variables that profile requires, so
# compose -- which substitutes only what the file NAMES -- had no way to pass
# them in. MEASURED 2026-09-15, the first time either file was brought up.

DEPLOY = ROOT / "deploy"

_SUBSTITUTION = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::[-?]([^}]*))?\}")


def _compose_service_environment(filename: str, supplied: dict) -> dict:
    """The environment a compose service actually gets, given these variables.

    Mirrors compose's own `${VAR:-default}` / `${VAR:?required}` substitution.
    Reading the file rather than restating it is the point: a variable dropped
    from the file must fail this, which a hand-written dict cannot notice.
    """
    from tests._compose import load as load_compose

    document = load_compose(DEPLOY / filename)
    services = document.get("services") or {}
    assert len(services) == 1, f"{filename} no longer has exactly one service"
    raw = (next(iter(services.values())).get("environment") or {})

    resolved: dict[str, str] = {}
    for key, value in raw.items():
        text = str(value)

        def _replace(match):
            name, default = match.group(1), match.group(2)
            return supplied.get(name, default if default is not None else "")

        text = _SUBSTITUTION.sub(_replace, text)
        if text != "":
            resolved[key] = text
    return resolved


def _enterprise_inputs() -> dict:
    return {
        "CB_CONNECTION_STRING": "couchbase://cluster",
        "CB_USERNAME": "Administrator",
        "CB_PASSWORD": "password",
        "CAPELLA_API_KEY_SECRET": "secret",
        "OAUTH_ISSUER": "https://idp.example/realms/mcp",
        "OAUTH_AUDIENCE": "api://couchbase-admin-mcp",
        "CB_ADMIN_HTTP_REQUIRE_AUTH": "true",
        "CB_ADMIN_TLS_TERMINATED_EXTERNALLY": "1",
    }


def _with_local_audit(env: dict, tmp_path) -> dict:
    env = dict(env)
    env["CB_ADMIN_AUDIT_FILE"] = str(tmp_path / "audit.log")
    return env


@pytest.mark.parametrize(
    "filename", ["docker-compose.ee.yml", "docker-compose.capella.yml"]
)
def test_a_shipped_compose_file_can_satisfy_the_profile_it_defaults_to(
    filename, tmp_path, monkeypatch
):
    """The artifact must be configurable into a state that starts.

    Not "an enterprise configuration starts" -- that is already covered. This is
    "the file we ship can be GIVEN one", which is a different claim and was
    false.
    """
    env = _compose_service_environment(filename, _enterprise_inputs())
    assert env.get("CB_ADMIN_PROFILE") == "enterprise", env
    problems = _enforce(_with_local_audit(env, tmp_path), monkeypatch)
    assert not problems, (
        f"{filename} cannot be configured to start even with every variable "
        f"supplied:\n  " + "\n  ".join(problems)
    )


@pytest.mark.parametrize(
    "dropped",
    [
        "OAUTH_ISSUER",
        "OAUTH_AUDIENCE",
        "CB_ADMIN_TLS_TERMINATED_EXTERNALLY",
    ],
)
def test_each_pass_through_the_compose_file_adds_is_load_bearing(
    dropped, tmp_path, monkeypatch
):
    """Deleting a pass-through from the compose file must break the test above.

    Without this, the variables could be removed from the file and the first
    test would still pass on whatever the environment happened to hold -- which
    is how the gap arose in the first place.
    """
    supplied = _enterprise_inputs()
    supplied.pop(dropped)
    env = _compose_service_environment("docker-compose.ee.yml", supplied)
    problems = _enforce(_with_local_audit(env, tmp_path), monkeypatch)
    assert problems, (
        f"dropping {dropped} no longer stops the shipped EE compose file from "
        f"starting, so the pass-through is not doing anything"
    )


def test_the_lab_override_runs_the_transport_without_an_identity_provider(
    tmp_path, monkeypatch
):
    """docker-compose.ee.lab.yml exists so the HTTP transport can be exercised on
    a machine with no IdP. If it stops starting, the only route to that evidence
    is gone.

    Compose merges later files over earlier ones, which is what this reproduces.
    """
    base = _compose_service_environment(
        "docker-compose.ee.yml",
        {"CB_CONNECTION_STRING": "couchbase://cluster",
         "CB_USERNAME": "Administrator", "CB_PASSWORD": "password"},
    )
    override = _compose_service_environment("docker-compose.ee.lab.yml", {})
    merged = {**base, **override}

    assert merged["CB_ADMIN_PROFILE"] == "workstation", merged
    assert merged["CB_ADMIN_TRANSPORT"] == "http", merged
    problems = _enforce(_with_local_audit(merged, tmp_path), monkeypatch)
    assert not problems, (
        "the lab override refuses to start:\n  " + "\n  ".join(problems)
    )


@pytest.mark.parametrize(
    "dropped",
    ["CB_ADMIN_WORKSTATION_CONTAINER_BIND", "CB_ADMIN_TLS_TERMINATED_EXTERNALLY"],
)
def test_each_lab_acknowledgement_is_load_bearing(dropped, tmp_path, monkeypatch):
    """Both are stated in that file as deliberate. If either stops being required
    the comment explaining it is misleading and should go."""
    base = _compose_service_environment(
        "docker-compose.ee.yml",
        {"CB_CONNECTION_STRING": "couchbase://cluster",
         "CB_USERNAME": "Administrator", "CB_PASSWORD": "password"},
    )
    override = _compose_service_environment("docker-compose.ee.lab.yml", {})
    merged = {**base, **override}
    merged.pop(dropped)
    problems = _enforce(_with_local_audit(merged, tmp_path), monkeypatch)
    assert problems, f"dropping {dropped} from the lab override is no longer fatal"
