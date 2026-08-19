"""
Reading Tool metadata under either mcp 1.x or 2.x field naming.

WHY THIS MATTERS
================
mcp 2.0 renamed the fields on `Tool` and `ToolAnnotations`:

    Tool.inputSchema              -> Tool.input_schema
    annotations.readOnlyHint      -> .read_only_hint
    annotations.destructiveHint   -> .destructive_hint
    annotations.idempotentHint    -> .idempotent_hint

`readOnlyHint` is not decoration here: it decides whether a tool loads in read-only mode,
whether the confirmation gate applies, and whether the hard ceiling refuses the call. An
accessor that silently returns False for a write tool because it looked for the wrong
spelling would load that tool in read-only mode and skip its gate. That is why these are
accessors with a named `is_read_only`, rather than a `getattr` at each of nineteen sites.

The suite runs against ONE installed mcp version, so a real Tool object only exercises one
naming. The stubs below carry the other, which is the only way to test both without two
environments — and the point of the module is precisely the version it is not running on.
"""

from __future__ import annotations

import pytest
from mcp.types import Tool, ToolAnnotations

import mcp_compat

# ── Stubs for the naming this environment does not have ──────────────────────


class _Annotations2x:
    """ToolAnnotations as mcp 2.x names them."""

    def __init__(self, read_only=False, destructive=False, idempotent=False):
        self.read_only_hint = read_only
        self.destructive_hint = destructive
        self.idempotent_hint = idempotent


class _Tool2x:
    """Tool as mcp 2.x names it: input_schema, and 2.x-named annotations."""

    def __init__(self, schema=None, annotations=None):
        self.name = "stub"
        self.input_schema = schema if schema is not None else {"type": "object"}
        self.annotations = annotations


class _Annotations1x:
    def __init__(self, read_only=False, destructive=False, idempotent=False):
        self.readOnlyHint = read_only
        self.destructiveHint = destructive
        self.idempotentHint = idempotent


class _Tool1x:
    def __init__(self, schema=None, annotations=None):
        self.name = "stub"
        self.inputSchema = schema if schema is not None else {"type": "object"}
        self.annotations = annotations


# ── input_schema ─────────────────────────────────────────────────────────────


def test_the_real_installed_tool_type_is_readable():
    """Whichever version is installed, the accessor must work on a genuine Tool.

    Not redundant with the stub tests: it is the only one that would notice a THIRD
    renaming in some future release.
    """
    tool = Tool(name="probe", description="d", inputSchema={"type": "object", "x": 1})
    assert mcp_compat.input_schema(tool)["x"] == 1


@pytest.mark.parametrize(
    "factory", [_Tool1x, _Tool2x], ids=["1.x naming", "2.x naming"]
)
def test_input_schema_is_read_under_either_naming(factory):
    assert mcp_compat.input_schema(factory({"type": "object", "n": 2}))["n"] == 2


def test_a_missing_schema_yields_an_empty_dict_not_none():
    """Every caller goes on to read ["properties"], so returning None would only move the
    failure one line down."""

    class _NoSchema:
        inputSchema = None  # noqa: N815 - mimics the mcp 1.x field name
        annotations = None

    assert mcp_compat.input_schema(_NoSchema()) == {}


def test_an_object_with_neither_spelling_raises_a_useful_error():
    """Silence here would be worse than a crash: a tool with an unreadable schema would be
    advertised to the model with no arguments at all."""

    class _Alien:
        name = "alien"

    with pytest.raises(AttributeError, match="renamed"):
        mcp_compat.input_schema(_Alien())


# ── annotations ──────────────────────────────────────────────────────────────


def test_the_real_installed_annotations_are_readable():
    tool = Tool(
        name="probe",
        description="d",
        inputSchema={"type": "object"},
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True
        ),
    )
    assert mcp_compat.is_read_only(tool) is True
    assert mcp_compat.is_destructive(tool) is False
    assert mcp_compat.is_idempotent(tool) is True


@pytest.mark.parametrize(
    ("tool_factory", "annotations_factory"),
    [(_Tool1x, _Annotations1x), (_Tool2x, _Annotations2x)],
    ids=["1.x naming", "2.x naming"],
)
def test_every_hint_is_read_under_either_naming(tool_factory, annotations_factory):
    tool = tool_factory(
        annotations=annotations_factory(
            read_only=True, destructive=False, idempotent=True
        )
    )
    assert mcp_compat.is_read_only(tool) is True
    assert mcp_compat.is_destructive(tool) is False
    assert mcp_compat.is_idempotent(tool) is True


@pytest.mark.parametrize(
    ("tool_factory", "annotations_factory"),
    [(_Tool1x, _Annotations1x), (_Tool2x, _Annotations2x)],
    ids=["1.x naming", "2.x naming"],
)
def test_a_destructive_tool_is_not_reported_read_only(
    tool_factory, annotations_factory
):
    """The consequence that matters. A write tool read as read-only would load in
    read-only mode and bypass its confirmation gate."""
    tool = tool_factory(
        annotations=annotations_factory(read_only=False, destructive=True)
    )
    assert mcp_compat.is_read_only(tool) is False
    assert mcp_compat.is_destructive(tool) is True


def test_absent_annotations_are_false_rather_than_an_error():
    """Some tools carry none. Absent must mean "not read-only", i.e. treated as a write —
    the cautious direction."""
    assert mcp_compat.is_read_only(_Tool1x(annotations=None)) is False
    assert mcp_compat.is_destructive(_Tool1x(annotations=None)) is False


def test_an_unset_hint_is_false_not_none():
    """`bool` in, `bool` out: these values flow into JSON responses where a null would
    read as "unknown" rather than "no"."""

    class _Partial:
        readOnlyHint = True  # noqa: N815 - mimics the mcp 1.x field name
        # destructiveHint deliberately absent

    tool = _Tool1x(annotations=_Partial())
    assert mcp_compat.is_destructive(tool) is False
    assert isinstance(mcp_compat.is_destructive(tool), bool)


def test_the_camel_to_snake_conversion_is_correct():
    """The accessor derives the 2.x spelling from the 1.x one, so the derivation itself is
    worth pinning — an off-by-one in the conversion would silently return False."""

    class _Only2x:
        read_only_hint = True
        destructive_hint = True
        idempotent_hint = True

    tool = _Tool2x(annotations=_Only2x())
    assert mcp_compat.annotation(tool, "readOnlyHint") is True
    assert mcp_compat.annotation(tool, "destructiveHint") is True
    assert mcp_compat.annotation(tool, "idempotentHint") is True


# ── The call sites must actually use it ──────────────────────────────────────


_RENAMED = frozenset(
    {"inputSchema", "readOnlyHint", "destructiveHint", "idempotentHint"}
)


def _direct_reads(source: str) -> list[tuple[int, str]]:
    """Line numbers where `source` reads a renamed mcp field as an attribute.

    Parsed rather than grepped. A regex over lines cannot tell `x = t.inputSchema` from the
    same words inside a docstring that explains the rule — `auth/scope_gate.py` documents
    its predicate as "read-side == annotations.readOnlyHint is True", and a line-based scan
    reports that prose as a violation.

    Attribute reads only. Constructions are not flagged and must not be: 2.x keeps the
    camelCase spellings as pydantic aliases, so `Tool(inputSchema=...)` works on both
    versions and there are several hundred of them. In the AST a keyword argument is a
    `keyword`, not an `Attribute`, so this distinction comes free.
    """
    import ast

    tree = ast.parse(source)
    return [
        (node.lineno, node.attr)
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr in _RENAMED
    ]


def test_no_module_reads_the_renamed_fields_directly(repo_files):
    """The nineteen direct reads are what broke under 2.x. A twentieth added later would
    reintroduce exactly the same failure silently, so it is a test rather than a convention
    in CONTRIBUTING.md.
    """
    offenders: list[str] = []
    for path in repo_files(".py"):
        if path.name == "mcp_compat.py" or "tests" in path.parts:
            continue
        source = path.read_text(encoding="utf-8", errors="ignore")
        for lineno, attr in _direct_reads(source):
            offenders.append(f"{path.parent.name}/{path.name}:{lineno}: .{attr}")

    assert not offenders, (
        "these read a renamed mcp field as an attribute instead of going through "
        "mcp_compat, and will raise AttributeError under mcp 2.x:\n  "
        + "\n  ".join(offenders)
    )


def test_the_scan_above_would_catch_a_real_offender():
    """Without this, the test above would also pass if the parser stopped finding anything.

    Also pins the construction-vs-read distinction, which is the whole reason the scan is
    an AST walk: flagging constructions would produce hundreds of false positives and the
    check would be deleted.
    """
    assert _direct_reads("x = tool.inputSchema") == [(1, "inputSchema")]
    assert _direct_reads("if t.annotations.readOnlyHint:\n    pass") == [
        (1, "readOnlyHint")
    ]
    assert _direct_reads("y = a.b.destructiveHint or a.b.idempotentHint") == [
        (1, "destructiveHint"),
        (1, "idempotentHint"),
    ]
    # Constructions are fine on both versions.
    assert _direct_reads("Tool(name='x', inputSchema={})") == []
    assert _direct_reads("ToolAnnotations(readOnlyHint=True)") == []
    # Prose is not code.
    assert _direct_reads('"""read-side == annotations.readOnlyHint is True"""') == []
    assert _direct_reads("# tool.inputSchema is renamed in 2.x") == []
