"""The documentation gate: the build fails when the documentation falls behind the code.

Component: regression suite. Runs with every other test (`uv run pytest -q -p no:randomly --cov`).
Spec: documentation standard rules D1 to D15 (docs/plans/documentation-standard-gap.md).
Main items: `GATE` (the mode of each check), `_python_files`, `_public_items`, the header
    helpers (`_header_fields`, `_computed_callers`, `_computed_callees`), and one test per rule.
Callers: none; collected by pytest and run by CI.
Callees: none; the standard library and `git`.

WHY THIS FILE EXISTS
====================
Documentation that nothing checks goes stale. On 2026-09-14 a sweep found seven claims in
this repository's own docs that had quietly become false (see test_docs_are_not_stale.py).
The standard says a new engineer, or a new AI session with no history, must be able to
understand, maintain and change any part of the code from the repository alone. Rule D7
makes that checkable: this file is the check.

HOW THE MODES WORK
==================
Each rule has a mode in `GATE`:

  * "fail"   - a gap fails the build.
  * "report" - a gap is listed as a warning and does not fail the build.

The gate was added with most rules in "report" mode, because the repository had 159
public items without a doc comment and no handover set when the gate arrived. Report mode
fixes the baseline: the gaps are listed on every run, so none can be forgotten. Each rule
moves to "fail" in the same commit that closes its last gap. Do not move a rule back to
"report" to get a build through. Close the gap instead.

A SCAN THAT FINDS NOTHING MUST NOT PASS
=======================================
Every check first asserts that it scanned something. This is the same rule as
tests/test_no_vacuous_coverage.py: a scan over an empty list passes without testing
anything, which is the most dangerous way for a gate to fail.
"""

from __future__ import annotations

import ast
import pathlib
import re
import subprocess
import warnings

import pytest

_REPO = pathlib.Path(__file__).resolve().parent.parent

#: Mode per rule. "fail" breaks the build, "report" lists the gap as a warning.
#: Moving a rule to "fail" is part of the commit that closes its last gap.
GATE = {
    "D1-header": "fail",
    "D1-header-fields": "fail",
    "D1-header-matches-imports": "fail",
    "D2-public-doc-comment": "fail",
    "D6-handover-set": "fail",
    "D10-contributor-guides": "fail",
    "D11-changelog": "fail",
    "D12-examples": "fail",
    "D14-folder-readme": "fail",
    "D7-docs-name-live-things": "fail",
    "D5-clean-room": "fail",
}

#: The handover set. Every file must exist and be linked from docs/README.md (D6, D9).
#: Files marked pending are created by later steps of the plan; the gate lists them as a
#: gap until they exist, so the set cannot be declared complete while one is missing.
HANDOVER_FILES = [
    "docs/README.md",
    "docs/ARCHITECTURE.md",
    "docs/MODULE_MAP.md",
    "docs/BUILD_GUIDE.md",
    "docs/THREADING_MODEL.md",
    "docs/design-decisions.md",
    "docs/spec.md",
    "docs/questions.md",
]

#: Top-level folders that hold code or documents and so need a README (D14).
README_FOLDERS = ["auth", "deploy", "docs", "gui", "handlers", "scripts", "tests"]

#: The tool groups that need one tested example each (D12, decision Q5).
#: Taken from tests/test_handler_contract.py so the two lists cannot disagree.
EXAMPLE_TEST = "tests/test_tool_group_examples.py"


def _tracked(pattern: str) -> list[pathlib.Path]:
    """Return tracked files matching a git pathspec, as paths under the repo root.

    Uses git rather than a directory walk so virtual environments, caches and build
    output are never scanned. Falls back to a walk when git is not available (a source
    archive), and says so by returning everything under the root that matches.
    """
    try:
        out = subprocess.run(
            ["git", "ls-files", pattern],
            cwd=_REPO,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        skip = {".venv", "__pycache__", "node_modules", ".git"}
        return [
            p
            for p in _REPO.rglob(pattern)
            if not skip.intersection(p.relative_to(_REPO).parts)
        ]
    return [_REPO / name for name in out]


def _python_files() -> list[pathlib.Path]:
    """Every tracked Python file: source, tests and scripts alike (D1 covers all three)."""
    return _tracked("*.py")


def _public_items(tree: ast.AST) -> list[ast.AST]:
    """Public functions, methods and classes in a module (no leading underscore).

    Nested functions are skipped: they are implementation detail of their parent, and
    D3 covers them with why-comments instead.
    """
    items: list[ast.AST] = []

    def visit(node: ast.AST, depth_in_function: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not depth_in_function and not child.name.startswith("_"):
                    items.append(child)
                visit(child, True)
            elif isinstance(child, ast.ClassDef):
                if not depth_in_function and not child.name.startswith("_"):
                    items.append(child)
                visit(child, depth_in_function)
            else:
                visit(child, depth_in_function)

    visit(tree, False)
    return items


def _enforce(rule: str, gaps: list[str]) -> None:
    """Fail or warn about `gaps` according to the rule's mode in `GATE`.

    A "report" rule with gaps emits one warning listing the first 25 and the total, so
    the baseline is visible on every run without flooding the output.
    """
    if not gaps:
        return
    shown = "\n  ".join(gaps[:25])
    more = f"\n  ... and {len(gaps) - 25} more" if len(gaps) > 25 else ""
    message = f"{rule}: {len(gaps)} gap(s)\n  {shown}{more}"
    if GATE[rule] == "fail":
        pytest.fail(message, pytrace=False)
    warnings.warn(message, stacklevel=2)


def test_every_rule_has_a_mode():
    """A rule with no mode would be skipped silently, so the modes are checked here."""
    assert GATE, "GATE is empty, so the gate checks nothing"
    assert set(GATE.values()) <= {"fail", "report"}


def test_d1_every_python_file_has_a_header():
    """D1: every source file, test and script opens with a docstring that says what it is."""
    files = _python_files()
    assert files, (
        "found no Python files, so this scan would pass without checking anything"
    )
    gaps = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if not ast.get_docstring(tree):
            gaps.append(str(path.relative_to(_REPO)))
    _enforce("D1-header", gaps)


#: The labels every Python header carries (D1): what it is, where it sits in the spec, what
#: it holds, who calls it and what it calls.
HEADER_LABELS = ("Component", "Spec", "Main items", "Callers", "Callees")


def _header_fields(tree: ast.Module) -> dict[str, str]:
    """Return the labelled lines of a module header, continuation lines joined.

    A field starts at a line that begins with its label and a colon. Lines indented under
    it continue it, which is how the headers wrap at 100 columns.
    """
    doc = ast.get_docstring(tree) or ""
    fields: dict[str, str] = {}
    label = None
    for line in doc.splitlines():
        match = re.match(rf"({'|'.join(HEADER_LABELS)}): ?(.*)$", line)
        if match:
            label = match.group(1)
            fields[label] = match.group(2)
        elif label and line.startswith("    "):
            fields[label] += " " + line.strip()
        else:
            label = None
    return fields


def _module_name(path: pathlib.Path) -> str:
    """The dotted module name of a repository file (a package file names the package)."""
    parts = list(path.relative_to(_REPO).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imported_names(path: pathlib.Path) -> set[str]:
    """Every module name a file imports, relative imports resolved against its package."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    package = ".".join(path.parent.relative_to(_REPO).parts)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".") if package else []
                if node.level > 1:
                    parts = parts[: len(parts) - (node.level - 1)]
                base = ".".join(parts + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            if base:
                names.add(base)
                names |= {f"{base}.{alias.name}" for alias in node.names}
    return names


def _import_graph() -> tuple[dict[str, set[str]], set[str]]:
    """Imports per tracked Python file, and the set of module names the repository defines."""
    files = _python_files()
    graph = {str(p.relative_to(_REPO).as_posix()): _imported_names(p) for p in files}
    local = {_module_name(p) for p in files}
    return graph, local


def _computed_callees(rel: str, graph, local) -> list[str]:
    """The repository modules a file imports, naming a package only when no module of it is named."""
    own = _module_name(_REPO / rel)
    found = {name for name in graph[rel] if name in local and name != own}
    return sorted(n for n in found if not any(o.startswith(n + ".") for o in found))


def _computed_callers(rel: str, graph) -> list[str]:
    """The repository files that import this one (test files count only for test files)."""
    own = _module_name(_REPO / rel)
    callers = sorted(k for k, names in graph.items() if own in names and k != rel)
    if rel.startswith("tests/"):
        return callers
    return [c for c in callers if not c.startswith("tests/")]


def _named(text: str) -> list[str]:
    """The backticked names before the first semicolon of a Callers or Callees line."""
    return re.findall(r"`([^`]+)`", text.split(";")[0])


def test_d1_every_header_has_the_five_fields():
    """D1: component, spec, main items, callers and callees, in every Python header."""
    files = _python_files()
    assert files, "found no Python files, so this scan would check nothing"
    gaps = []
    for path in files:
        fields = _header_fields(ast.parse(path.read_text(encoding="utf-8")))
        missing = [label for label in HEADER_LABELS if not fields.get(label)]
        if missing:
            gaps.append(f"{path.relative_to(_REPO)}: no {', '.join(missing)}")
    _enforce("D1-header-fields", gaps)


def test_d1_header_callers_and_callees_match_the_imports():
    """D1: a header that names the wrong callers or callees is worse than none.

    The two lines are compared with what the files really import, so a new import fails
    the build until the header says so. Only the names before the first semicolon count;
    the text after it (the test count, the libraries) is free.

    One limit: the check reads import statements. A module loaded by name at run time, such
    as the console loaded through `importlib` in a test, is not seen.
    """
    graph, local = _import_graph()
    assert graph and local, "found no imports, so this scan would check nothing"
    checked = 0
    gaps = []
    for rel in sorted(graph):
        fields = _header_fields(ast.parse((_REPO / rel).read_text(encoding="utf-8")))
        if not (fields.get("Callers") and fields.get("Callees")):
            continue  # D1-header-fields reports a missing field once
        checked += 1
        for label, computed in (
            ("Callers", _computed_callers(rel, graph)),
            ("Callees", _computed_callees(rel, graph, local)),
        ):
            named = sorted(_named(fields[label]))
            if named != computed:
                wrong = sorted(set(named) ^ set(computed))
                gaps.append(f"{rel}: {label} differs from the imports at {wrong}")
    assert checked, "no header had Callers and Callees, so this scan checked nothing"
    _enforce("D1-header-matches-imports", gaps)


def test_d2_every_public_item_has_a_doc_comment():
    """D2: every public function, method and class (outside tests) has a docstring.

    Test functions are excluded because a test's name and the module header carry its
    purpose; D1 covers the test files themselves.
    """
    files = [p for p in _python_files() if "tests" not in p.relative_to(_REPO).parts]
    assert files, "found no non-test Python files, so this scan would check nothing"
    scanned = 0
    gaps = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for item in _public_items(tree):
            scanned += 1
            if not ast.get_docstring(item):
                gaps.append(f"{path.relative_to(_REPO)}:{item.lineno} {item.name}")
    assert scanned, "found no public items, so this scan would check nothing"
    _enforce("D2-public-doc-comment", gaps)


def test_d6_handover_set_is_complete_and_linked():
    """D6 and D9: the handover files exist and docs/README.md links every one."""
    gaps = [
        f"missing: {name}" for name in HANDOVER_FILES if not (_REPO / name).is_file()
    ]
    index = _REPO / "docs" / "README.md"
    if index.is_file():
        text = index.read_text(encoding="utf-8")
        for name in HANDOVER_FILES:
            base = pathlib.PurePosixPath(name).name
            if name != "docs/README.md" and base not in text:
                gaps.append(f"not linked from docs/README.md: {name}")
    _enforce("D6-handover-set", gaps)


def test_d10_contributor_guides_exist_and_agree():
    """D10 and Q4: CONTRIBUTING.md and AGENTS.md exist, and CLAUDE.md points at AGENTS.md."""
    gaps = [
        f"missing: {name}"
        for name in ("CONTRIBUTING.md", "AGENTS.md", "CLAUDE.md")
        if not (_REPO / name).is_file()
    ]
    claude = _REPO / "CLAUDE.md"
    if claude.is_file() and (_REPO / "AGENTS.md").is_file():
        if "AGENTS.md" not in claude.read_text(encoding="utf-8"):
            gaps.append("CLAUDE.md does not point at AGENTS.md")
    _enforce("D10-contributor-guides", gaps)


def test_d11_changelog_exists_and_has_a_build_number():
    """D11 and Q2: CHANGELOG.md exists and names the build (version plus short commit)."""
    changelog = _REPO / "CHANGELOG.md"
    gaps = []
    if not changelog.is_file():
        gaps.append("missing: CHANGELOG.md")
    elif not re.search(
        r"\b\d+\.\d+\.\d+\+[0-9a-f]{7,}\b", changelog.read_text(encoding="utf-8")
    ):
        gaps.append("CHANGELOG.md names no build number of the form <version>+<commit>")
    _enforce("D11-changelog", gaps)


def test_d12_every_tool_group_has_a_tested_example():
    """D12 and Q5: one tested example per tool group, counted from the handler list."""
    contract = (_REPO / "tests" / "test_handler_contract.py").read_text(
        encoding="utf-8"
    )
    block = re.search(r"MODULE_NAMES = \[(.*?)\n\]", contract, re.S)
    assert block, "could not find MODULE_NAMES in test_handler_contract.py"
    groups = re.findall(r'"([a-z_0-9]+)",', block.group(1))
    assert groups, "found no tool groups, so this scan would check nothing"
    example_file = _REPO / EXAMPLE_TEST
    gaps = []
    if not example_file.is_file():
        gaps.append(
            f"missing: {EXAMPLE_TEST} (needs one example for each of {len(groups)} groups)"
        )
    else:
        text = example_file.read_text(encoding="utf-8")
        gaps.extend(
            f"no example for tool group: {g}"
            for g in groups
            if not re.search(rf'\(\s*"{g}",', text)
            and f"def test_the_{g}_example" not in text
        )
    _enforce("D12-examples", gaps)


def test_d14_every_top_level_folder_has_a_readme():
    """D14: a README.md in every top-level folder, so the folder explains itself."""
    assert README_FOLDERS, "README_FOLDERS is empty, so this scan would check nothing"
    gaps = [
        f"missing: {name}/README.md"
        for name in README_FOLDERS
        if not (_REPO / name / "README.md").is_file()
    ]
    _enforce("D14-folder-readme", gaps)


#: A backticked path that looks like a repository file, such as `handlers/shared.py`.
_PATH_IN_DOC = re.compile(
    r"`((?:[a-z_]+/)+[A-Za-z0-9_.\-]+\.(?:py|md|ps1|yml|yaml|json|toml))`"
)


def test_d7_docs_do_not_name_files_that_no_longer_exist():
    """D7: a handover document that names a file which is gone is a stale document.

    Only the handover documents are scanned. Paths written as examples or as output of
    a run are common in other documents and would raise false alarms.
    """
    docs = [_REPO / name for name in HANDOVER_FILES if (_REPO / name).is_file()]
    assert docs, "found no handover documents, so this scan would check nothing"
    gaps = []
    for doc in docs:
        for match in _PATH_IN_DOC.finditer(doc.read_text(encoding="utf-8")):
            if "<" in match.group(1) or "*" in match.group(1):
                continue
            if not (_REPO / match.group(1)).exists():
                gaps.append(
                    f"{doc.relative_to(_REPO)} names a missing file: {match.group(1)}"
                )
    _enforce("D7-docs-name-live-things", gaps)


#: What a real identifier looks like, as opposed to a stand-in. Stand-ins are the
#: 11111111-2222-... UUIDs and the "example..." cluster ids used throughout the repository.
#: An internal support ticket id (decision Q-007, 2026-11-05: the repository is public, so a
#: ticket id is replaced by the reasoning it stood for).
_TICKET_ID = re.compile(r"\bCBSE-\d+\b")
#: A staff mailbox. Example data uses example.com instead (decision Q-007).
_STAFF_EMAIL = re.compile(r"[\w.+-]+@couchbase\.com", re.IGNORECASE)

_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
_STAND_IN_UUID = re.compile(r"^(0{8}-|11111111-2222-)")
#: A Capella cluster host carries a 15 or 16 character generated id. Placeholders such as
#: `xxxx`, `<id>` and `{clusterId}` and the `example...` stand-ins do not match.
_REAL_CAPELLA_HOST = re.compile(
    r"\b(?:cb\.|svc-[a-z]-node-\d+\.)?(?!example)[a-z0-9]{15,16}\.(?:data\.|dp\.)?cloud\.couchbase\.com"
)


def test_d5_no_real_identifiers_or_lab_passwords_in_tracked_files():
    """D5: no real cluster hosts, UUIDs, ticket ids or staff mailboxes, and no lab password literal.

    The `.py` and text files are scanned. Binary documents (.pptx, .docx, images) are not:
    they are generated from the Markdown sources.
    """
    skip_suffix = (".pptx", ".docx", ".png", ".lock", ".crt", ".jpg", ".ico")
    files = [p for p in _tracked("*") if not p.name.endswith(skip_suffix)]
    assert files, "found no files, so this scan would check nothing"
    gaps = []
    for path in files:
        if path.name == "test_documentation_gate.py":
            continue  # holds the patterns themselves
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(_REPO)
        for number, line in enumerate(text.splitlines(), 1):
            if _REAL_CAPELLA_HOST.search(line):
                gaps.append(f"{rel}:{number} a real-looking Capella host")
            if _TICKET_ID.search(line):
                gaps.append(f"{rel}:{number} an internal ticket id")
            if _STAFF_EMAIL.search(line):
                gaps.append(f"{rel}:{number} a staff email address")
            for match in _UUID.finditer(line):
                if not _STAND_IN_UUID.match(match.group(0)):
                    gaps.append(
                        f"{rel}:{number} a real-looking UUID {match.group(0)[:8]}..."
                    )
            if (
                re.search(r"(?i)(?:password|\$pass)\s*=\s*'[^'<$]{4,}'", line)
                and path.suffix == ".ps1"
            ):
                gaps.append(f"{rel}:{number} a password literal")
    _enforce("D5-clean-room", gaps)
