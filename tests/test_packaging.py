"""
What actually ships must be able to start.

The Dockerfile and the wheel both listed the top-level modules to include BY HAND,
and both lists were missing ``audit.py``, ``authz.py`` and ``profile_config.py`` —
every module added during the security review. So `import server` inside the built
image raised ModuleNotFoundError on the first one, and the artifact an operator would
deploy could not boot at all, with none of the controls present.

A green test suite said nothing about this, because the suite runs from the source
tree where every file exists.

These tests derive the required list from server.py's ACTUAL imports rather than
restating it, so adding a module to the server and forgetting the packaging is a test
failure rather than a runtime one.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _stdlib_names() -> set[str]:
    names = set(getattr(sys, "stdlib_module_names", ()))
    return names | {
        "mcp",
        "starlette",
        "uvicorn",
        "flask",
        "flask_cors",
        "jwt",
        "couchbase",
    }


def _first_party_top_level_modules(source_file: pathlib.Path) -> set[str]:
    """Top-level first-party MODULES (not packages) that `source_file` imports.

    A module is first-party if a same-named .py sits beside it in the repo root.
    """
    tree = ast.parse(source_file.read_text(encoding="utf-8"))
    candidates: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                candidates.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                candidates.add(node.module.split(".")[0])

    return {
        name for name in candidates - _stdlib_names() if (ROOT / f"{name}.py").is_file()
    }


REQUIRED_MODULES = _first_party_top_level_modules(ROOT / "server.py")


def test_the_import_scan_found_something():
    """Guards the two tests below from vacuously passing on an empty set."""
    assert "audit" in REQUIRED_MODULES
    assert "profile_config" in REQUIRED_MODULES
    assert "authz" in REQUIRED_MODULES
    assert len(REQUIRED_MODULES) >= 5


def test_the_dockerfile_copies_every_module_server_imports():
    """The image could not start: audit.py, authz.py and profile_config.py were absent."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    copied = set(re.findall(r"^COPY[^\n]*?(\w+)\.py", dockerfile, re.MULTILINE))
    missing = sorted(REQUIRED_MODULES - copied)
    assert not missing, (
        f"Dockerfile does not COPY {missing}, which server.py imports. The built "
        "image will raise ModuleNotFoundError at startup."
    )


def test_the_wheel_includes_every_module_server_imports():
    """Same defect in the installed console script."""
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - 3.10
        tomllib = pytest.importorskip("tomli")

    with open(ROOT / "pyproject.toml", "rb") as handle:
        config = tomllib.load(handle)

    wheel = config["tool"]["hatch"]["build"]["targets"]["wheel"]
    included = set(wheel.get("packages", []))
    forced = wheel.get("force-include", {})
    included |= {pathlib.Path(k).stem for k in forced}

    missing = sorted(REQUIRED_MODULES - included)
    assert not missing, (
        f"pyproject force-include is missing {missing}; `pip install .` then running "
        "the couchbase-admin-mcp-server entrypoint raises ModuleNotFoundError."
    )


def test_the_gui_is_shipped_if_it_is_documented():
    """The console is part of the deliverable, so it has to be in the image."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^COPY[^\n]*\bgui\b", dockerfile, re.MULTILINE), (
        "gui/ is not copied into the image, so the admin console cannot run there"
    )


def test_the_enterprise_audit_directory_exists_in_the_image():
    """The enterprise profile defaults CB_ADMIN_AUDIT_FILE to
    /var/log/couchbase-admin-mcp/audit.log, and an unwritable audit path is fatal at
    startup — so the image must create that directory and give it to the runtime user,
    or every enterprise container refuses to boot."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    import profile_config

    default_path = profile_config._ENTERPRISE_DEFAULTS["CB_ADMIN_AUDIT_FILE"]
    directory = str(pathlib.PurePosixPath(default_path).parent)
    assert directory in dockerfile, (
        f"{directory} is never created in the Dockerfile, but the enterprise profile "
        f"defaults its audit sink to {default_path}"
    )
    assert re.search(rf"chown[^\n]*{re.escape(directory)}", dockerfile), (
        f"{directory} is created but not chowned to the non-root runtime user"
    )


def test_the_image_installs_the_console_dependencies_it_copies():
    """Shipping code without its runtime is worse than shipping neither.

    The image COPYs gui/ but the builder stage installed no flask/flask-cors, so the
    console could not start there — and the test above passes on the COPY line alone.
    """
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    copies_gui = bool(re.search(r"^COPY[^\n]*\bgui\b", dockerfile, re.MULTILINE))
    if not copies_gui:
        pytest.skip("the image does not ship the console")
    for requirement in ("flask", "flask-cors"):
        assert re.search(rf'"{re.escape(requirement)}[>=<]', dockerfile), (
            f"the image copies gui/ but never installs {requirement}, so the console "
            "cannot run in the container"
        )


def test_the_wheel_ships_the_console():
    """`pip install .` produced an installation containing handlers and auth only —
    no console at all — while the [gui] extra dutifully installed Flask for it."""
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - 3.10
        tomllib = pytest.importorskip("tomli")

    with open(ROOT / "pyproject.toml", "rb") as handle:
        config = tomllib.load(handle)

    packages = config["tool"]["hatch"]["build"]["targets"]["wheel"].get("packages", [])
    assert "gui" in packages, (
        "gui is not in the wheel's packages, so an installed copy has no admin console"
    )


def test_every_shipped_package_directory_exists():
    """Guards the assertion above from passing on a typo."""
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - 3.10
        tomllib = pytest.importorskip("tomli")

    with open(ROOT / "pyproject.toml", "rb") as handle:
        config = tomllib.load(handle)

    for package in config["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]:
        assert (ROOT / package).is_dir(), f"{package} is declared but does not exist"
