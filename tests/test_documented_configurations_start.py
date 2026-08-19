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

import importlib
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"


def _enforce(env: dict, monkeypatch) -> list[str]:
    """Run the real startup validation under `env`. Returns the fatal problems."""
    for key in [
        k for k in list(__import__("os").environ) if k.startswith(("CB_", "OAUTH_"))
    ]:
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
