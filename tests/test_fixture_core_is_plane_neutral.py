"""handlers/fixture_core.py must stay usable by BOTH planes.

WHY THIS FILE EXISTS
====================
The fixture family exists on two control planes and the two halves are genuinely
different code: Capella reaches documents through the Data API with a cluster
access credential, Enterprise Edition through the query service and the SDK with
cluster credentials. `docs/FIXTURE_DESIGN.md` is explicit that the second is a
second implementation and not a port.

What must NOT be duplicated is the part that decides what a fixture MEANS -- the
manifest, the integrity check, where a fixture may be written, how a keyspace is
split. A fixture captured on Enterprise Edition and imported into Capella is a
genuinely valuable artifact ("capture on a laptop, import into the cloud, compare
like for like") and it only works if both sides agree byte for byte.

Two copies of a hash comparison is two places for it to be subtly wrong, and the
failure is silent: a fixture that verifies on the plane that wrote it and nowhere
else. `fixture_integrity` was already extracted once for exactly this reason --
so export's verify and import's preflight could not drift -- and the same
argument across planes is the stronger one.

WHAT IS ASSERTED
================
That the shared module stays shared: standard library only, no plane-specific
identifiers, and no plane-specific module importing it and then shadowing what it
imported with a local copy.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pathlib

import pytest

import handlers.fixture_core as core

SOURCE = pathlib.Path(inspect.getsourcefile(core))
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"))

#: Everything fixture_core is allowed to import. Standard library only: a
#: function here that needs an HTTP client or a credential belongs in the plane's
#: own module, not in the shared one.
_ALLOWED_IMPORTS = {
    "hashlib",
    "json",
    "os",
    "pathlib",
    "re",
    "datetime",
    "typing",
    "__future__",
}


def test_there_is_something_to_check():
    """A parse that found no imports and no functions would pass everything
    below without checking anything."""
    assert SOURCE.is_file()
    functions = [n for n in TREE.body if isinstance(n, ast.FunctionDef)]
    assert len(functions) >= 8, (
        f"fixture_core exports only {len(functions)} functions; the shared half "
        "has been hollowed out"
    )


def test_the_shared_module_imports_only_the_standard_library():
    """The moment this module needs a transport, it has stopped being shared."""
    imported = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    forbidden = sorted(imported - _ALLOWED_IMPORTS)
    assert not forbidden, (
        f"handlers/fixture_core.py imports {forbidden}. It is the half both "
        "planes share, so it may not depend on either one's transport, "
        "credentials or tool registry. Move the function that needs them into "
        "the plane's own module."
    )


def test_no_function_in_the_shared_module_names_a_plane():
    """Checked on IDENTIFIERS, not on the raw text.

    The module docstring says the words Capella and Enterprise Edition several
    times, and should -- explaining why the split exists is the point. What must
    not appear is a function, parameter or attribute that only makes sense on one
    plane, because that is a dependency wearing a neutral name.
    """
    offenders = []
    for node in ast.walk(TREE):
        name = None
        if isinstance(node, ast.FunctionDef):
            name = node.name
        elif isinstance(node, ast.arg):
            name = node.arg
        elif isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.Name):
            name = node.id
        if not name:
            continue
        lowered = name.lower()
        for marker in ("capella", "data_api", "ns_server", "cbbackupmgr"):
            if marker in lowered:
                offenders.append(f"{marker} in {name!r}")
    assert not offenders, (
        "handlers/fixture_core.py contains plane-specific identifiers, so it is "
        f"not actually shared: {sorted(set(offenders))}"
    )


#: Modules that implement a fixture family for one plane. Add the Enterprise
#: Edition one here when it lands -- the check below is what stops it growing its
#: own copy of the manifest rules.
_PLANE_MODULES = ["handlers.capella.fixture"]


@pytest.mark.parametrize("module_name", _PLANE_MODULES)
def test_a_plane_module_uses_the_shared_helpers_rather_than_its_own(module_name):
    """Imported-and-then-shadowed is the failure this catches.

    An import gives the right answer until somebody defines a local function with
    the same name below it. Python takes the later definition, the import goes
    quietly unused, and the two planes are running different code under one name.
    """
    module = importlib.import_module(module_name)
    shared = {
        "fixture_integrity",
        "read_manifest",
        "resolve_under_root",
        "split_keyspace",
        "sha256_file",
        "base_index_name",
        "strip_index_nodes",
        "rewrite_index_keyspace",
    }
    wrong_home = []
    for attribute in dir(module):
        target = getattr(module, attribute)
        if not callable(target) or not hasattr(target, "__module__"):
            continue
        if getattr(target, "__name__", "") in shared:
            if target.__module__ != core.__name__:
                wrong_home.append(
                    f"{module_name}.{attribute} is {target.__module__}."
                    f"{target.__name__}, not the shared one"
                )
    assert not wrong_home, (
        "a plane module defines its own copy of a shared fixture helper:\n  "
        + "\n  ".join(wrong_home)
        + "\n\nImport it from handlers.fixture_core instead. Two copies of the "
        "manifest rules is how a fixture comes to verify on the plane that "
        "wrote it and nowhere else."
    )


def test_the_plane_module_list_is_not_empty_and_is_current():
    """Guards the parametrisation above from silently covering nothing, and
    fails when an Enterprise Edition family lands without being listed."""
    assert _PLANE_MODULES, "no plane modules listed; the check above is vacuous"

    package = pathlib.Path(inspect.getsourcefile(core)).parent
    found = {
        "handlers.capella.fixture" if path.parent.name == "capella"
        else f"handlers.{path.stem}"
        for path in package.rglob("fixture.py")
    }
    missing = sorted(found - set(_PLANE_MODULES))
    assert not missing, (
        f"these fixture modules exist and are not checked: {missing}. Add them "
        "to _PLANE_MODULES."
    )
