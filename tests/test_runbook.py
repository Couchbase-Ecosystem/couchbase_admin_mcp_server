"""
The runbook has to be right, because it is the document somebody follows at 2am.

A wrong tool name costs an hour. A wrong environment variable name costs longer, because
the failure looks like a permissions problem rather than a typo — which is exactly what
happened while writing it: the draft said `CAPELLA_API_KEY` and the server reads
`CAPELLA_API_KEY_SECRET`, so following it would have produced a 401 with no hint that the
variable name was the cause.

So every checkable claim is checked: the tools it names, the arguments it passes, the
environment variables it sets, the response fields it tells you to read, and — most
importantly — that both documented configurations actually start.
"""

from __future__ import annotations

import importlib
import os
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNBOOK = ROOT / "RUNBOOK.md"


@pytest.fixture(scope="module")
def doc() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def exposed_tools() -> dict[str, set[str]]:
    """Every tool a caller can actually see, with its argument names.

    Loaded with gating off and writes enabled, because that is the union of what an
    operator following this runbook could reach — a Capella-only or read-only load would
    make the check vacuous for whole sections.
    """
    os.environ["CB_ADMIN_PROFILE"] = "workstation"
    os.environ["CB_DEPLOYMENT"] = "both"
    os.environ["CB_ADMIN_READ_ONLY_MODE"] = "false"

    import handlers.shared
    import profile_config

    importlib.reload(profile_config)
    importlib.reload(handlers.shared)
    import server

    importlib.reload(server)
    return {
        tool.name: set((tool.inputSchema or {}).get("properties", {}))
        for tool in server._TOOLS
    }


# ── Names and arguments ──────────────────────────────────────────────────────


def test_every_tool_the_runbook_names_exists(doc, exposed_tools):
    named = set(re.findall(r"\b((?:capella|admin|cb)_[a-z0-9_]+)\b", doc))
    # Prose words that match the pattern but are not tools.
    named -= {"cb_url", "capella_api_key_secret"}
    unknown = sorted(n for n in named if n not in exposed_tools)
    assert not unknown, f"RUNBOOK.md names tools that do not exist: {unknown}"


def test_the_tool_scan_is_not_vacuous(doc, exposed_tools):
    """If the regex stopped matching, the test above would pass trivially."""
    named = set(re.findall(r"\b((?:capella|admin|cb)_[a-z0-9_]+)\b", doc))
    assert len(named & set(exposed_tools)) >= 8, sorted(named)


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        (
            "capella_env_ensure",
            [
                "env_name",
                "app_services",
                "bucket_name",
                "allowed_cidrs",
                "ttl_hours",
                "owner",
                "correlation_id",
            ],
        ),
        ("capella_env_connection_info", ["env_name"]),
        ("capella_env_teardown", ["env_name", "correlation_id"]),
        ("capella_env_reap", ["dry_run"]),
    ],
)
def test_the_arguments_the_runbook_passes_are_real(tool, arguments, exposed_tools):
    """The CI recipe is meant to be copy-pasteable. An argument the tool does not declare
    is now REFUSED rather than ignored, so a wrong name there fails the pipeline."""
    assert tool in exposed_tools, f"{tool} is not exposed"
    unknown = [a for a in arguments if a not in exposed_tools[tool]]
    assert not unknown, f"{tool}: RUNBOOK passes undeclared arguments {unknown}"


# ── Environment variables ────────────────────────────────────────────────────


def _documented_variables(doc: str) -> set[str]:
    """Variables the runbook tells you to EXPORT or set in a container env block."""
    found = set(re.findall(r"^(?:# )?export ([A-Z][A-Z0-9_]*)=", doc, re.MULTILINE))
    found |= set(re.findall(r'^\s*"(C[BA][A-Z0-9_]*)":', doc, re.MULTILINE))
    return found


def test_every_variable_the_runbook_sets_is_read_somewhere(doc, repo_files):
    """The failure this prevents: the draft said CAPELLA_API_KEY, the code reads
    CAPELLA_API_KEY_SECRET, and the resulting 401 looks like a permissions problem rather
    than a typo."""
    documented = _documented_variables(doc)
    assert documented, "no variables extracted — the scan is broken"

    read_by_code = set()
    for path in repo_files(".py"):
        if "tests" in path.parts:
            continue
        read_by_code |= set(
            re.findall(
                r'"((?:CB|CAPELLA|OAUTH)_[A-Z0-9_]+)"',
                path.read_text(encoding="utf-8", errors="ignore"),
            )
        )

    # Variables belonging to the CI example's own shell, not to this server.
    ci_locals = {
        "MCP",
        "ENV_NAME",
        "TOKEN",
        "CB_URL",
        "SYNC_URL",
        "OAUTH_TOKEN_URL",
        "OAUTH_CLIENT_ID",
        "OAUTH_CLIENT_SECRET",
        "PHASE",
        "INFO",
    }

    unread = sorted(documented - read_by_code - ci_locals)
    assert not unread, (
        f"RUNBOOK.md sets variables the server never reads: {unread}. "
        "Following it would appear to work and change nothing."
    )


def test_the_api_key_variable_is_the_one_the_client_reads(doc):
    """Named explicitly because it is the single easiest thing to get wrong here, and the
    verification script deliberately uses a DIFFERENT variable."""
    assert "CAPELLA_API_KEY_SECRET" in doc
    client = (ROOT / "handlers" / "capella" / "client.py").read_text(encoding="utf-8")
    assert "CAPELLA_API_KEY_SECRET" in client

    # ...and the runbook should say so, since the two names are a trap.
    assert "CB_CAPELLA_API_KEY" in doc, (
        "the runbook does not mention that scripts/verify_capella_paths.py reads a "
        "different variable; someone will set one and wonder why the other fails"
    )


# ── The response fields it tells you to read ─────────────────────────────────


def test_the_connection_info_fields_it_documents_are_produced(doc):
    """The phone app is wired up from these. A renamed field silently yields null."""
    source = (ROOT / "handlers" / "capella" / "environment.py").read_text(
        encoding="utf-8"
    )
    for field in (
        "connection_string",
        "couchbase_lite_url_pattern",
        "app_services_admin_url",
        "allowed_cidrs",
    ):
        assert field in doc, f"{field} is no longer documented"
        assert f'"{field}"' in source, (
            f"the runbook tells operators to read {field}, which environment.py no "
            "longer produces"
        )


def test_the_example_response_keys_are_the_real_ones(doc):
    """The prose and the sample JSON must agree with the code AND with each other.

    They did not: the sample said "app_service_pattern" while the code emits
    "couchbase_lite_url_pattern" and the CI recipe below it read the correct name. Someone
    wiring a phone app from the sample would have got null and had no reason to suspect the
    document rather than their own setup.
    """
    sample = re.search(r'"environment": "mcp-test-pr-1421".*?\n```', doc, re.S)
    assert sample, "the connection-info sample response is no longer in the runbook"

    keys = set(re.findall(r'^\s*"([a-z_]+)":', sample.group(0), re.MULTILINE))
    assert keys, "no keys extracted from the sample"

    source = (ROOT / "handlers" / "capella" / "environment.py").read_text(
        encoding="utf-8"
    )
    invented = sorted(k for k in keys if f'"{k}"' not in source)
    assert not invented, (
        f"the sample response invents keys the code never emits: {invented}"
    )


def test_the_phase_contract_is_real(doc):
    """The CI loop polls on phase == 'ready' and on retry_after_s."""
    source = (ROOT / "handlers" / "capella" / "environment.py").read_text(
        encoding="utf-8"
    )
    assert "retry_after_s" in doc and "retry_after_s" in source
    assert '"ready"' in doc or "ready" in doc
    assert 'phase == "ready"' in source or '"ready"' in source


# ── The guardrail defaults it quotes ─────────────────────────────────────────


def test_the_quoted_guardrail_defaults_match_the_code(doc):
    """A runbook that overstates a default gives false comfort: someone reads
    'max 10 environments' and does not set it, and the real default is different."""
    from handlers.capella.guardrails import Policy

    table = {
        "CAPELLA_MAX_ENVIRONMENTS": Policy.max_environments,
        "CAPELLA_ENV_TTL_HOURS": Policy.default_ttl_hours,
    }
    for variable, actual in table.items():
        row = re.search(rf"\|\s*`{variable}`\s*\|\s*`?(\d+)`?\s*\|", doc)
        assert row, f"{variable} has no default in the guardrails table"
        assert int(row.group(1)) == actual, (
            f"{variable}: runbook says {row.group(1)}, code default is {actual}"
        )


# ── Both documented configurations must start ────────────────────────────────


def _startup_problems(env: dict, monkeypatch) -> list[str]:
    for key in [
        k for k in list(os.environ) if k.startswith(("CB_", "OAUTH_", "CAPELLA_"))
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


def test_shape_a_the_laptop_configuration_starts(monkeypatch):
    """Section 2, as written."""
    problems = _startup_problems(
        {
            "CB_ADMIN_PROFILE": "workstation",
            "CB_ADMIN_READ_ONLY_MODE": "false",
            "CAPELLA_API_KEY_SECRET": "secret-value",
            "CAPELLA_ORG_ID": "00000000-0000-0000-0000-00000000org1",
            "CAPELLA_ALLOWED_PROJECTS": "00000000-0000-0000-0000-0000000proj1",
            "CAPELLA_ENV_NAME_PREFIX": "mcp-test-",
            "CAPELLA_MAX_ENVIRONMENTS": "3",
            "CAPELLA_ENV_TTL_HOURS": "8",
        },
        monkeypatch,
    )
    assert not problems, problems


def test_shape_b_the_unattended_configuration_starts(tmp_path, monkeypatch):
    """Section 3, as written, with TLS terminated here rather than in front."""
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    cert.write_text("x")
    key.write_text("x")

    problems = _startup_problems(
        {
            "CB_ADMIN_PROFILE": "enterprise",
            "CB_ADMIN_TRANSPORT": "http",
            "CB_ADMIN_HOST": "0.0.0.0",
            "CB_ADMIN_PORT": "8000",
            "OAUTH_ISSUER": "https://idp.corp.example/realms/mcp",
            "OAUTH_AUDIENCE": "api://couchbase-admin-mcp",
            "CB_ADMIN_HTTP_REQUIRE_AUTH": "true",
            "CB_ADMIN_SCOPE_READ": "couchbase-admin-mcp:read",
            "CB_ADMIN_SCOPE_WRITE": "couchbase-admin-mcp:write",
            "CB_ADMIN_SCOPE_AUTOMATION": "couchbase-admin-mcp:automation",
            "CB_ADMIN_TLS_CERT_FILE": str(cert),
            "CB_ADMIN_TLS_KEY_FILE": str(key),
            "CB_ADMIN_AUDIT_FILE": str(tmp_path / "audit.log"),
            "CB_ADMIN_EGRESS_ALLOWED_HOSTS": ".corp.example",
        },
        monkeypatch,
    )
    assert not problems, problems


def test_shape_b_with_external_tls_also_starts(tmp_path, monkeypatch):
    """The commented-out alternative in section 3 must be equally valid."""
    problems = _startup_problems(
        {
            "CB_ADMIN_PROFILE": "enterprise",
            "CB_ADMIN_TRANSPORT": "http",
            "CB_ADMIN_HOST": "0.0.0.0",
            "OAUTH_ISSUER": "https://idp.corp.example/realms/mcp",
            "OAUTH_AUDIENCE": "api://couchbase-admin-mcp",
            "CB_ADMIN_HTTP_REQUIRE_AUTH": "true",
            "CB_ADMIN_TLS_TERMINATED_EXTERNALLY": "1",
            "CB_ADMIN_AUDIT_FILE": str(tmp_path / "audit.log"),
        },
        monkeypatch,
    )
    assert not problems, problems


# ── The troubleshooting table must describe real messages ────────────────────


@pytest.mark.parametrize(
    ("symptom", "source_file"),
    [
        ("CB_ADMIN_PROFILE is not set", "profile_config.py"),
        ("incoherent security posture", "server.py"),
        ("cannot be used", "audit.py"),
        ("requires scope", "auth/scope_gate.py"),
        ("hard ceiling", "authz.py"),
    ],
)
def test_the_error_messages_it_quotes_are_real(doc, symptom, source_file):
    """A troubleshooting table listing messages the software never emits sends the reader
    looking for the wrong thing."""
    assert symptom in doc, f"{symptom!r} is no longer in the troubleshooting table"
    source = (ROOT / source_file).read_text(encoding="utf-8")
    assert symptom in source, (
        f"the runbook quotes {symptom!r} but {source_file} does not produce it"
    )


def test_the_preflight_checklist_is_actionable(doc):
    """Every item should be something the reader can actually run or inspect."""
    checklist = doc.split("Before you trust this in production", 1)[1]
    items = re.findall(r"^- \[ \] (.+)$", checklist, re.MULTILINE)
    assert len(items) >= 8, items
    # It must name the tools and scripts that answer each question.
    assert any("capella_guardrails_status" in i for i in items)
    assert any("verify_capella_paths" in i for i in items)
    assert any("dry_run" in i for i in items)
