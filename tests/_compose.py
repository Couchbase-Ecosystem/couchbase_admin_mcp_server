"""Load a Compose file as Compose understands it, not as a YAML subset.

WHY THIS EXISTS
===============
`yaml.safe_load` refuses any tag it has no constructor for, and Compose defines
its own merge-control tags. `ports: !override` -- which is how an override file
REPLACES a list instead of extending it -- made three test modules raise

    yaml.constructor.ConstructorError: could not determine a constructor for the
    tag '!override'

on a file `docker compose config` renders perfectly well. MEASURED 2026-09-15.

The tests were not wrong about the file; they were wrong about YAML. A guard that
parses every shipped compose file has to parse the language those files are
written in, or it fails on valid input and the natural fix is to stop using a
valid feature -- which is the wrong direction entirely.

THE TAGS
========
`!override` replaces the value inherited from an earlier file rather than merging
with it. `!reset` removes the key altogether; it is represented here as None,
because that is what "not present" means to every caller in this suite.

Both are merge instructions rather than content, so a single-file read sees the
value with the instruction stripped -- which is exactly what a guard inspecting
one file should see.
"""

from __future__ import annotations

import pathlib

import yaml


class ComposeLoader(yaml.SafeLoader):
    """SafeLoader that understands Compose's merge-control tags."""


def _override(loader: ComposeLoader, node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    return loader.construct_scalar(node)


def _reset(loader: ComposeLoader, node):
    return None


ComposeLoader.add_constructor("!override", _override)
ComposeLoader.add_constructor("!reset", _reset)


def load(path: pathlib.Path) -> dict:
    """Parse one compose file. Tags are honoured rather than fatal."""
    return yaml.load(path.read_text(encoding="utf-8"), Loader=ComposeLoader)
