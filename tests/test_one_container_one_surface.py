"""A deployment declares its control plane, and gets that one or does not start.

THE RULE
========
One container, one surface. An Enterprise Edition container talks to ns_server
and has no Capella credentials; a Capella container talks to the v4 control
plane and has no route to the cluster network. `both` is a mode the server
supports and that no deployment artifact in this repository configures, because
it switches capability gating off and removes exactly the blast-radius
containment that running two containers buys.

WHAT GOES WRONG WITHOUT THIS
============================
`detect_mode()` INFERS. A container meant for Capella that also inherits a
`CB_CONNECTION_STRING` -- from `.env.example`, a shared env file, a copied
compose stanza -- resolves to `both`. Nothing errors. The tool list silently
doubles, and the first sign is a tool acting on a cluster nobody intended it to
reach.

`CB_ADMIN_REQUIRE_DEPLOYMENT` turns that silent widening into a refusal to
start. Unset, inference behaves exactly as it always did.
"""

from __future__ import annotations

import pytest

import deployment


@pytest.fixture(autouse=True)
def _no_ambient_declaration(monkeypatch):
    """The variable under test must not be inherited from the developer's shell."""
    monkeypatch.delenv(deployment.REQUIRE_ENV, raising=False)


def test_no_declaration_changes_nothing():
    """The guard is opt-in. A laptop that never sets it keeps inferring."""
    assert deployment.declared_mode_error("both") is None
    assert deployment.declared_mode_error("capella") is None
    assert deployment.declared_mode_error("self_managed") is None


@pytest.mark.parametrize("mode", ["capella", "self_managed", "both"])
def test_a_satisfied_declaration_starts(monkeypatch, mode):
    monkeypatch.setenv(deployment.REQUIRE_ENV, mode)
    assert deployment.declared_mode_error(mode) is None


def test_a_capella_container_that_drifted_into_both_refuses_to_start(monkeypatch):
    """THE case this exists for.

    A Capella deployment that picks up a connection string is not a Capella
    deployment any more, and the only outward sign is a longer tool list.
    """
    monkeypatch.setenv(deployment.REQUIRE_ENV, "capella")
    problem = deployment.declared_mode_error("both")

    assert problem, "a Capella container silently became 'both' and started anyway"
    # The message has to name the fix, not just the mismatch: whoever reads it is
    # looking at a container that booted yesterday and does not know which of two
    # environment variables is the intruder.
    assert "CAPELLA_API_KEY_SECRET" in problem
    assert "CB_CONNECTION_STRING" in problem
    assert "gating off" in problem


def test_an_ee_container_that_drifted_into_both_refuses_to_start(monkeypatch):
    monkeypatch.setenv(deployment.REQUIRE_ENV, "self_managed")
    problem = deployment.declared_mode_error("both")
    assert problem
    assert "self_managed" in problem and "both" in problem


def test_an_ee_container_pointed_at_capella_refuses_to_start(monkeypatch):
    """The connection string names a Capella host, so inference says `capella`
    while the deployment believes it is talking to its own cluster."""
    monkeypatch.setenv(deployment.REQUIRE_ENV, "self_managed")
    problem = deployment.declared_mode_error("capella")
    assert problem
    assert "CB_DEPLOYMENT" in problem


def test_a_typo_in_the_declaration_is_refused_rather_than_ignored(monkeypatch):
    """A misspelled declaration that silently did nothing would be worse than no
    declaration at all: the operator believes the rule is enforced."""
    monkeypatch.setenv(deployment.REQUIRE_ENV, "capela")
    problem = deployment.declared_mode_error("capella")
    assert problem
    assert "not one of" in problem


def test_the_declaration_is_case_and_space_tolerant(monkeypatch):
    """Compose files and env files carry stray whitespace; that must not read as
    a mismatch and take a deployment down."""
    monkeypatch.setenv(deployment.REQUIRE_ENV, "  Capella \n")
    assert deployment.declared_mode_error("capella") is None


def test_the_refusal_is_wired_into_startup():
    """The check is only worth having if `_enforce_profile` consults it.

    Parsed rather than executed: importing `server` under a deliberately
    incoherent posture would need the whole startup path, and this asserts the
    wiring, which is the part that can silently go missing.
    """
    import ast
    import inspect

    import server

    tree = ast.parse(inspect.getsource(server._enforce_profile))
    called = {
        f"{node.func.value.id}.{node.func.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
    }
    assert "deployment.declared_mode_error" in called, (
        "_enforce_profile no longer consults the deployment declaration, so "
        "CB_ADMIN_REQUIRE_DEPLOYMENT is documented but not enforced"
    )


# ── The deployment artifacts must obey the rule too ──────────────────────────
#
# The guard above stops a container starting in the wrong mode. These stop the
# repository from SHIPPING a file that puts one there -- which is the more
# likely failure, because a compose file is edited by someone adding a variable
# they need and not reading why the neighbouring ones are absent.


import pathlib  # noqa: E402

import yaml  # noqa: E402

DEPLOY = pathlib.Path(__file__).resolve().parent.parent / "deploy"


def _compose(name: str) -> dict:
    path = DEPLOY / name
    assert path.is_file(), f"{name} is missing; the deployment artifacts moved"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _only_service(document: dict) -> dict:
    services = document["services"]
    assert len(services) == 1, (
        f"a per-surface compose file must define exactly ONE service, found "
        f"{sorted(services)}. Two services in one file share a network and come "
        "up together on a bare `docker compose up`, which is not a separation."
    )
    return next(iter(services.values()))


def test_the_capella_deployment_carries_no_connection_string():
    """The single most dangerous line that could be added to that file.

    A Capella API key plus any non-Capella connection string resolves to
    'both', which switches capability gating off. It reads like adding reach.
    It removes a gate.
    """
    service = _only_service(_compose("docker-compose.capella.yml"))
    environment = service["environment"]

    assert "CB_CONNECTION_STRING" not in environment, (
        "the Capella compose file sets CB_CONNECTION_STRING. With a Capella API "
        "key also present this resolves to 'both' and loads every ns_server "
        "tool. Remove it -- the Capella container has no cluster to reach."
    )
    assert environment.get("CB_ADMIN_REQUIRE_DEPLOYMENT") == "capella"
    assert environment.get("CB_DEPLOYMENT") == "capella"


def test_the_capella_deployment_has_no_route_to_a_cluster_network():
    """The containment is the missing route, not the configuration.

    An isolated bridge that this file alone creates. An `external` network is a
    network something else owns and something else can attach a cluster to.
    """
    document = _compose("docker-compose.capella.yml")
    service = _only_service(document)

    for name in service.get("networks", []):
        definition = document["networks"][name]
        assert not definition.get("external"), (
            f"the Capella container is attached to external network {name!r}. "
            "An external network is shared; the point of this container is that "
            "there is no path from it to a cluster."
        )


def test_the_ee_deployment_carries_no_capella_credentials():
    """The mirror image, and the same 'both' resolution from the other side."""
    service = _only_service(_compose("docker-compose.ee.yml"))
    environment = service["environment"]

    for leaked in ("CAPELLA_API_KEY_SECRET", "CAPELLA_ACCESS_KEY_ID"):
        assert leaked not in environment, (
            f"the Enterprise Edition compose file sets {leaked}. With a "
            "connection string also present this resolves to 'both'."
        )
    assert environment.get("CB_ADMIN_REQUIRE_DEPLOYMENT") == "self_managed"
    assert environment.get("CB_DEPLOYMENT") == "self_managed"


def test_no_shipped_compose_file_configures_both():
    """`both` is supported by the server and configured by nothing here.

    Deliberate: it disables capability gating, so it removes the containment
    that running one container per surface exists to provide. If a deployment
    ever genuinely needs it, that is a decision to take explicitly and write
    down -- not something to inherit from a file in this repository.
    """
    offenders = []
    for path in DEPLOY.glob("docker-compose*.yml"):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for service_name, service in document.get("services", {}).items():
            environment = service.get("environment", {}) or {}
            for key in ("CB_DEPLOYMENT", "CB_ADMIN_REQUIRE_DEPLOYMENT"):
                if str(environment.get(key, "")).strip().lower() == "both":
                    offenders.append(f"{path.name}:{service_name}:{key}")

    assert not offenders, (
        "these shipped deployment artifacts configure 'both', which switches "
        "capability gating off:\n  " + "\n  ".join(offenders)
    )


def test_every_shipped_compose_file_declares_its_surface():
    """A file without the declaration falls back on inference, which is the
    thing all of this exists to stop relying on."""
    undeclared = []
    for path in DEPLOY.glob("docker-compose*.yml"):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for service_name, service in document.get("services", {}).items():
            environment = service.get("environment", {}) or {}
            if not environment.get("CB_ADMIN_REQUIRE_DEPLOYMENT"):
                undeclared.append(f"{path.name}:{service_name}")

    assert not undeclared, (
        "these services do not declare CB_ADMIN_REQUIRE_DEPLOYMENT, so the mode "
        "they run in is whatever the environment happens to imply:\n  "
        + "\n  ".join(undeclared)
    )


def test_the_deployment_templates_are_not_named_into_the_ignore_rules():
    """A template nobody can copy is worse than no template.

    `.gitignore` carries `.env.*`, and `!.env.example` does not rescue a file
    called `.env.ee.example` -- that negation matches one exact basename. A
    dot-prefixed template therefore sits on disk looking committed while the
    repository ships without it, which is the worst shape for a file whose only
    job is to be copied by somebody else.

    So the templates are named `env.<surface>.example`, with no leading dot.
    They are not credentials, they are documentation of which knobs exist; the
    file the operator fills in is `.env.<surface>`, which the existing rules
    ignore exactly as they should.
    """
    templates = sorted(p.name for p in DEPLOY.glob("env.*.example"))
    assert templates, (
        "the per-surface env templates are gone, or were renamed with a leading "
        "dot -- which the repository's own .env.* rule would exclude"
    )

    dotted = sorted(p.name for p in DEPLOY.glob(".env.*.example"))
    assert not dotted, (
        f"{dotted} start with a dot, so `.env.*` in .gitignore excludes them "
        "from the repository. Drop the leading dot: these are templates, not "
        "credentials."
    )


def test_each_env_template_matches_its_compose_file():
    """A template that omits a variable the compose file marks required fails at
    `docker compose up` with a message about a variable the operator never saw."""
    import re

    pairs = [
        ("docker-compose.ee.yml", "env.ee.example"),
        ("docker-compose.capella.yml", "env.capella.example"),
    ]
    required_pattern = re.compile(r"\$\{([A-Z_][A-Z0-9_]*):\?")

    for compose_name, env_name in pairs:
        compose_text = (DEPLOY / compose_name).read_text(encoding="utf-8")
        env_text = (DEPLOY / env_name).read_text(encoding="utf-8")
        declared = {
            line.split("=", 1)[0].strip()
            for line in env_text.splitlines()
            if line.strip() and not line.strip().startswith("#") and "=" in line
        }
        required = set(required_pattern.findall(compose_text))
        missing = sorted(required - declared)
        assert not missing, (
            f"{compose_name} marks {missing} as required (:?) but {env_name} "
            "does not mention them, so `docker compose up` fails on a variable "
            "the template never told the operator about"
        )
