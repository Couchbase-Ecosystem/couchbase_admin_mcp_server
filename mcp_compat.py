"""
mcp_compat.py — read Tool metadata on either mcp 1.x or 2.x.

THE PROBLEM
===========
mcp 2.0 renamed the fields on the `Tool` and `ToolAnnotations` models:

    1.x                    2.x
    Tool.inputSchema       Tool.input_schema
    annotations.readOnlyHint      .read_only_hint
    annotations.destructiveHint   .destructive_hint
    annotations.idempotentHint    .idempotent_hint

CONSTRUCTION IS NOT THE PROBLEM. 2.x keeps the camelCase spellings as pydantic aliases,
so all ~150 `Tool(... inputSchema=...)` and ~360 `ToolAnnotations(readOnlyHint=...)` calls
in this project keep working untouched. Verified against 2.0.0.

Only ATTRIBUTE READS break, and there were nineteen of them:

    $ pip install 'mcp==2.0.0' && python -c "import server"
    AttributeError: 'Tool' object has no attribute 'inputSchema'.
                    Did you mean: 'input_schema'?

That is worth stating plainly because the first assessment of this — mine — was that it
touched 400-odd call sites and needed a compatibility layer over the whole Tool model.
That number came from counting constructions, which were never affected. Measuring the
reads separately turned "a real piece of work" into this file.

WHY ACCESSORS RATHER THAN A VERSION CHECK
=========================================
A branch on `mcp.__version__` decides once, at import, and is wrong the moment a release
changes something else. `getattr` in preference order asks the object what it actually has,
which is also what makes this file testable against both versions without installing
either twice.
"""

from __future__ import annotations

from typing import Any

_UNSET = object()


def _first_attr(obj: Any, *names: str, default: Any = _UNSET) -> Any:
    """The first attribute present on `obj`, tried in order."""
    for name in names:
        value = getattr(obj, name, _UNSET)
        if value is not _UNSET:
            return value
    if default is not _UNSET:
        return default
    raise AttributeError(
        f"{type(obj).__name__} has none of {names!r}. The installed mcp version may have "
        "renamed them again; add the new spelling here rather than at each call site."
    )


def input_schema(tool: Any) -> dict:
    """A tool's JSON input schema, on any supported mcp version.

    Two different absences, deliberately handled differently:

    - The field EXISTS and is None — a tool with no schema. Returns `{}`, because every
      caller goes on to read `["properties"]` and a None would only move the failure one
      line down.
    - NEITHER spelling exists — the installed mcp renamed the field again. Raises. Coercing
      this to `{}` would be worse than a crash: every tool would be advertised to the model
      as taking no arguments, and nothing would look broken.
    """
    schema = _first_attr(tool, "inputSchema", "input_schema")
    return schema or {}


def annotation(tool: Any, name: str) -> bool:
    """One annotation hint by its 1.x name, or False when unset.

    `name` is the camelCase 1.x spelling — `readOnlyHint`, `destructiveHint`,
    `idempotentHint` — because that is what this codebase says everywhere else, and having
    one vocabulary matters more than matching whichever version is installed.
    """
    annotations = getattr(tool, "annotations", None)
    if annotations is None:
        return False

    snake = "".join(f"_{ch.lower()}" if ch.isupper() else ch for ch in name)
    return bool(_first_attr(annotations, name, snake, default=False))


def is_read_only(tool: Any) -> bool:
    """Whether the tool is annotated read-only.

    Read-only-ness decides whether a tool loads in read-only mode and whether the
    confirmation gate applies, so it gets a named accessor rather than a string lookup at
    each site — a typo in `"readOnlyHint"` would silently return False and quietly turn a
    write tool into one that loads in read-only mode.
    """
    return annotation(tool, "readOnlyHint")


def is_destructive(tool: Any) -> bool:
    return annotation(tool, "destructiveHint")


def is_idempotent(tool: Any) -> bool:
    return annotation(tool, "idempotentHint")
