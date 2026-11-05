"""The audit decision vocabulary is defined once, and everything that lists it agrees.

Component: regression suite for `audit.DECISIONS` (docs/questions.md Q-003).
Spec: docs/spec.md S4 (audit record); docs/questions.md Q-003 (decided 2026-11-05: define the
    vocabulary once and test that the code, the docstring and the spec agree with it).
Main items: `test_every_denial_the_code_emits_is_in_the_vocabulary`,
    `test_the_vocabulary_has_no_name_the_code_never_emits`,
    `test_the_build_record_docstring_lists_the_vocabulary`, `test_the_spec_lists_the_vocabulary`.
Callers: none; collected by pytest.
Callees: `audit`.

WHY THIS EXISTS
===============
The docstring of `audit.build_record` listed nine decisions and called the vocabulary closed,
while the code emitted fourteen. A SIEM rule written from the docstring would have missed
five of them, including every authentication failure. The denial names are string literals
scattered through the source, so the test reads the source rather than trusting a list.
"""

from __future__ import annotations

import pathlib
import re

import audit

_REPO = pathlib.Path(__file__).resolve().parent.parent
_NAME = re.compile(r"^(allowed|dry_run|error|denied_[a-z_]+)$")


def _source_files() -> list[pathlib.Path]:
    """The server's own Python files: everything but the tests, scripts, docs and virtualenv."""
    skip = {"tests", "scripts", "docs", ".venv", "__pycache__", "node_modules"}
    return [
        p
        for p in _REPO.rglob("*.py")
        if not skip.intersection(p.relative_to(_REPO).parts)
    ]


def _emitted_denials() -> set[str]:
    """Every `denied_*` name that appears as a string literal in the server's source."""
    import ast

    found: set[str] = set()
    files = _source_files()
    assert files, "found no source files, so this scan would check nothing"
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        # The table itself names every decision, so reading it would make "never emitted"
        # impossible to detect. Leave its own subtree out of the scan.
        table = {
            id(inner)
            for node in ast.walk(tree)
            if isinstance(node, ast.AnnAssign)
            and getattr(node.target, "id", "") == "DECISIONS"
            for inner in ast.walk(node)
        }
        for node in ast.walk(tree):
            if id(node) in table:
                continue
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.startswith("denied_")
                and _NAME.match(node.value)
            ):
                found.add(node.value)
    assert found, "found no denial names, so this scan would check nothing"
    return found


def test_the_vocabulary_is_the_fourteen_names_the_spec_describes():
    """A guard against the table being emptied or truncated."""
    assert len(audit.DECISIONS) == 14
    assert {"allowed", "dry_run", "error"} <= set(audit.DECISIONS)
    assert all(meaning.strip() for meaning in audit.DECISIONS.values())


def test_every_denial_the_code_emits_is_in_the_vocabulary():
    """A new refusal must be registered, so a SIEM rule written from the table sees it."""
    missing = sorted(_emitted_denials() - set(audit.DECISIONS))
    assert not missing, f"emitted but not in audit.DECISIONS: {missing}"


def test_the_vocabulary_has_no_name_the_code_never_emits():
    """A name nothing writes is a rule that can never fire, and a lie in the table."""
    denials = {name for name in audit.DECISIONS if name.startswith("denied_")}
    unused = sorted(denials - _emitted_denials())
    assert not unused, f"in audit.DECISIONS but never emitted: {unused}"


def test_the_build_record_docstring_lists_the_vocabulary():
    """The docstring names every decision and no other `denied_*` name."""
    doc = audit.build_record.__doc__ or ""
    names = set(re.findall(r"\b(allowed|dry_run|error|denied_[a-z_]+)\b", doc))
    assert names == set(audit.DECISIONS), (
        f"docstring and DECISIONS differ at {sorted(names ^ set(audit.DECISIONS))}"
    )


def test_the_spec_lists_the_vocabulary():
    """Section S4 of the spec names the same fourteen decisions."""
    text = (_REPO / "docs" / "spec.md").read_text(encoding="utf-8")
    start = text.index("## S4.")
    section = text[start : text.index("\n## S5.", start)]
    names = {t for t in re.findall(r"`([^`]+)`", section) if _NAME.match(t)}
    assert names == set(audit.DECISIONS), (
        f"spec and DECISIONS differ at {sorted(names ^ set(audit.DECISIONS))}"
    )
