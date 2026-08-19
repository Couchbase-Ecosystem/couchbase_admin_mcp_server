#!/usr/bin/env python3
"""Generate the architecture diagrams.

    python docs/make_arch_diagrams.py

WHY THE BOXES ARE MEASURED RATHER THAN SIZED BY HAND
====================================================
The first version of this file hard-coded a width and height for every box and left the caller to
guess whether the text fitted. It did not, repeatedly: headings landed on top of subtitles, the
last line of a panel rendered outside its border, captions overran the canvas. Each one was
invisible until the image was opened, and fixing one nudged another.

So every panel here is measured with the real renderer before its box is drawn, and the box is
sized to the text plus padding. `check_layout()` then asserts, at save time, that no text escapes
its own box and that no two boxes overlap -- a build that would produce a messy diagram fails
instead of writing one.

SIZE IS A CONSTRAINT
====================
Each figure is placed in the document at 504pt, the text column of US Letter with 0.75in margins.
A figure authored 10 inches wide is therefore shown at about 70%, and 8pt type in it lands near
5.5pt. Figures accordingly carry little prose: the explanations live in the body text, where they
are legible and searchable. What belongs in a figure is what is spatial -- who talks to whom, in
what order, and where the trust boundaries fall.

THE PALETTE CARRIES MEANING
===========================
    blue    the Admin MCP and the control planes it drives
    teal    the CRUD MCP and the data planes it reaches
    purple  the AI Data Plane's memory and catalog components
    amber   read-only surfaces and advisory notes
    red     destructive or high-blast-radius operations, and refusals
    grey    the agent, decisions, and anything that is not a Couchbase component
"""

from __future__ import annotations

import pathlib

import matplotlib

matplotlib.use("Agg")

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = pathlib.Path(__file__).resolve().parent / "diagrams"
OUT.mkdir(parents=True, exist_ok=True)

DPI = 200

ADMIN = ("#1f4e79", "#dbe9f6")
CRUD = ("#0f6b5c", "#d5efe9")
AIDP = ("#5b3a8e", "#e9e1f7")
READ = ("#7a6300", "#fbf3d0")

#: Attention / high blast radius / refusal.
#:
#: NOT red-pink any more. Red against the teal used for the data plane is the single worst pair
#: for the commonest form of colour blindness (deuteranomaly), and a reader who cannot separate
#: them loses the distinction the whole document is built on. Orange separates from teal by hue
#: AND by lightness, so it survives greyscale printing too -- and `hatched()` adds a shape cue so
#: the meaning does not rest on colour at all.
DANGER = ("#9a4a00", "#fbe2c9")

NEUTRAL = ("#3f3f3f", "#f0f0f0")
INK = "#222222"
MUTED = "#5f5f5f"

MONO = "DejaVu Sans Mono"

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 9,
        "figure.facecolor": "white",
        "savefig.facecolor": "white",
    }
)

#: Every rectangle drawn on the current figure, and every text bounding box, in data units.
#: `check_layout()` reads these; `canvas()` clears them.
_RECTS: list[tuple[str, tuple[float, float, float, float]]] = []
_TEXTS: list[tuple[str, tuple[float, float, float, float]]] = []


def canvas(width: float, height: float):
    """A fresh 100x100 drawing surface. Coordinates are percentages of the figure."""
    _RECTS.clear()
    _TEXTS.clear()
    figure, axes = plt.subplots(figsize=(width, height))
    axes.set_xlim(0, 100)
    axes.set_ylim(0, 100)
    axes.axis("off")
    figure.canvas.draw()  # a renderer must exist before anything can be measured
    return figure, axes


def measure(
    axes, text, *, fontsize, weight="normal", family=None
) -> tuple[float, float]:
    """The size this text will occupy, in data units, measured with the real renderer.

    Drawn, measured and removed. Matplotlib has no way to size a string without laying it out, and
    an approximation from character counts is exactly what produced the overflowing boxes this
    function exists to prevent -- bold text, monospace text and punctuation all break the estimate
    in different directions.
    """
    figure = axes.figure
    renderer = figure.canvas.get_renderer()
    handle = axes.text(
        0,
        0,
        text,
        fontsize=fontsize,
        weight=weight,
        family=family,
        linespacing=1.4,
        va="top",
        ha="left",
    )
    extent = handle.get_window_extent(renderer=renderer)
    inverse = axes.transData.inverted()
    (x0, y0), (x1, y1) = inverse.transform(
        [[extent.x0, extent.y0], [extent.x1, extent.y1]]
    )
    handle.remove()
    return abs(x1 - x0), abs(y1 - y0)


def _record_text(axes, name, handle):
    renderer = axes.figure.canvas.get_renderer()
    extent = handle.get_window_extent(renderer=renderer)
    inverse = axes.transData.inverted()
    (x0, y0), (x1, y1) = inverse.transform(
        [[extent.x0, extent.y0], [extent.x1, extent.y1]]
    )
    _TEXTS.append((name, (min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1))))


def rect(
    axes, x, y, w, h, style=NEUTRAL, *, name="box", radius=1.4, alpha=1.0, hatch=None
):
    """A rounded rectangle, registered for the layout check.

    `hatch` carries meaning that colour alone should not: a box marked as an attention or refusal
    box stays distinguishable in greyscale and to a reader with colour-vision deficiency.
    """
    edge, fill = style
    axes.add_patch(
        FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle=f"round,pad=0,rounding_size={radius}",
            linewidth=1.6 if hatch else 1.3,
            edgecolor=edge,
            facecolor=fill,
            alpha=alpha,
            hatch=hatch,
        )
    )
    _RECTS.append((name, (x, y, x + w, y + h)))
    return x, y, w, h


def panel(
    axes,
    x,
    y,
    *,
    heading=None,
    body=None,
    style=NEUTRAL,
    width=None,
    height=None,
    heading_size=8.8,
    body_size=8.2,
    body_family=None,
    pad_x=2.2,
    pad_y=2.4,
    centre=False,
    name=None,
    draw=True,
    hatch=None,
    accent=False,
):
    """A box sized to its own contents. `x, y` is the lower-left corner.

    `width` and `height` are minimums, not fixed values: if the text needs more, the box grows.
    That is the whole point -- a caller can lay out a row of equal-width panels without having to
    know which of them holds the longest line.
    """
    heading_w = heading_h = 0.0
    if heading:
        heading_w, heading_h = measure(
            axes, heading, fontsize=heading_size, weight="bold"
        )
    body_w = body_h = 0.0
    if body:
        body_w, body_h = measure(axes, body, fontsize=body_size, family=body_family)

    if accent:
        pad_x += 2.4  # room for the bar, so the text does not start on top of it
    gap = 1.6 if (heading and body) else 0.0
    needed_w = max(heading_w, body_w) + 2 * pad_x
    needed_h = heading_h + gap + body_h + 2 * pad_y
    w = max(width or 0.0, needed_w)
    h = max(height or 0.0, needed_h)

    if not draw:
        # Measure-only. Probing by drawing off-canvas and deleting the RECORDS left the ARTISTS
        # behind, and `bbox_inches="tight"` then expanded the saved PNG to include them -- which
        # produced a figure with a page of garbled text below it.
        return x, y, w, h

    label = name or (heading or (body or "panel").split("\n")[0])[:40]
    rect(axes, x, y, w, h, style, name=label, hatch=hatch)
    if accent:
        # A shape cue that does not sit under the text: a solid bar down the inside left edge,
        # legible in greyscale and to a reader who cannot separate the hues.
        axes.add_patch(
            FancyBboxPatch(
                (x + 0.6, y + 0.8),
                1.5,
                h - 1.6,
                boxstyle="round,pad=0,rounding_size=0.4",
                linewidth=0,
                facecolor=style[0],
            )
        )

    cursor = y + h - pad_y
    if heading:
        handle = axes.text(
            x + w / 2 if centre else x + pad_x,
            cursor,
            heading,
            fontsize=heading_size,
            weight="bold",
            color=INK,
            va="top",
            ha="center" if centre else "left",
            linespacing=1.4,
        )
        _record_text(axes, label, handle)
        cursor -= heading_h + gap
    if body:
        handle = axes.text(
            x + w / 2 if centre else x + pad_x,
            cursor,
            body,
            fontsize=body_size,
            color=INK,
            va="top",
            ha="center" if centre else "left",
            family=body_family,
            linespacing=1.4,
        )
        _record_text(axes, label, handle)
    return x, y, w, h


def row(
    axes,
    y,
    items,
    *,
    gap=2.0,
    height=None,
    heading_size=8.5,
    body_size=7.9,
    centre=True,
    connect=False,
    connect_color=INK,
    draw=True,
):
    """Lay out equal-width panels across the canvas, sized to the widest cell.

    `items` is a sequence of (heading, body, style). The width and the pitch are DERIVED from the
    measured content rather than chosen: picking a pitch by eye is what produced panels that grew
    past their neighbours and off the right edge. If the row cannot fit at the requested type
    size, the sizes are scaled down once and re-measured -- a smaller diagram beats a broken one.

    Returns (x_positions, width, height).
    """

    def widths(h_size, b_size):
        needed = []
        for heading, body, _ in items:
            w = 0.0
            if heading:
                w = max(w, measure(axes, heading, fontsize=h_size, weight="bold")[0])
            if body:
                w = max(w, measure(axes, body, fontsize=b_size)[0])
            needed.append(w + 4.4)
        return needed

    count = len(items)
    needed = widths(heading_size, body_size)
    width = max(needed)
    total = count * width + (count - 1) * gap

    # Shrink ITERATIVELY, not once. A single proportional step undershoots because the padding
    # inside each panel does not scale with the font, so the first attempt still overflowed the
    # right edge -- which the layout check caught, which is the point of having it.
    attempts = 0
    while total > 100.0 and attempts < 8 and heading_size > 5.5:
        heading_size *= 0.94
        body_size *= 0.94
        needed = widths(heading_size, body_size)
        width = max(needed)
        total = count * width + (count - 1) * gap
        attempts += 1
    if total > 100.0:
        raise AssertionError(
            f"a row of {count} panels cannot fit: {total:.1f} units needed. "
            f"Shorten the text rather than shrinking the type further."
        )

    tallest = 0.0
    for heading, body, _ in items:
        h = 4.8
        if heading:
            h += measure(axes, heading, fontsize=heading_size, weight="bold")[1]
        if body:
            h += measure(axes, body, fontsize=body_size)[1] + 1.6
        tallest = max(tallest, h)
    height = max(height or 0.0, tallest)

    origin = max(0.0, (100.0 - total) / 2.0)
    positions = []
    for index, (heading, body, style) in enumerate(items):
        x = origin + index * (width + gap)
        positions.append(x)
        panel(
            axes,
            x,
            y,
            heading=heading,
            body=body,
            style=style,
            width=width,
            height=height,
            centre=centre,
            heading_size=heading_size,
            body_size=body_size,
            name=heading or f"row{index}",
            draw=draw,
        )
        if draw and connect and index:
            previous = positions[index - 1] + width
            arrow(
                axes,
                (previous, y + height / 2),
                (x, y + height / 2),
                color=connect_color,
            )
    return positions, width, height


def note(
    axes, x, y, text, *, fontsize=8.2, color=MUTED, ha="left", va="top", weight="normal"
):
    """Free text outside any box. Registered so it cannot silently land on top of one."""
    handle = axes.text(
        x,
        y,
        text,
        fontsize=fontsize,
        color=color,
        ha=ha,
        va=va,
        weight=weight,
        linespacing=1.4,
    )
    _record_text(axes, "<note>", handle)
    return handle


def arrow(axes, start, end, *, color=INK, lw=1.25, dashed=False, rad=0.0, both=False):
    axes.add_patch(
        FancyArrowPatch(
            start,
            end,
            arrowstyle="<|-|>" if both else "-|>",
            mutation_scale=10,
            linewidth=lw,
            color=color,
            linestyle="--" if dashed else "-",
            connectionstyle=f"arc3,rad={rad}",
            shrinkA=1,
            shrinkB=1,
        )
    )


def title(axes, text, subtitle="") -> float:
    """Draw the title block and return the y coordinate content must stay below."""
    handle = axes.text(0, 99.5, text, fontsize=13.5, weight="bold", color=INK, va="top")
    _, height = measure(axes, text, fontsize=13.5, weight="bold")
    bottom = 99.5 - height
    _record_text(axes, "<title>", handle)
    if subtitle:
        gap = 1.4
        handle = axes.text(
            0,
            bottom - gap,
            subtitle,
            fontsize=8.6,
            color=MUTED,
            va="top",
            linespacing=1.4,
        )
        _, sub_height = measure(axes, subtitle, fontsize=8.6)
        bottom = bottom - gap - sub_height
        _record_text(axes, "<subtitle>", handle)
    return bottom - 3.0


def legend(axes, entries, y=0.0):
    """A colour key along the bottom. Swatch widths are measured, not assumed."""
    x = 0.0
    for style, text in entries:
        edge, fill = style
        axes.add_patch(
            mpatches.Rectangle(
                (x, y + 0.2), 2.2, 2.2, linewidth=1.1, edgecolor=edge, facecolor=fill
            )
        )
        handle = axes.text(
            x + 3.2, y + 1.3, text, fontsize=7.8, color=MUTED, va="center"
        )
        width, _ = measure(axes, text, fontsize=7.8)
        _record_text(axes, "<legend>", handle)
        x += 3.2 + width + 4.5


def check_layout(name: str) -> None:
    """Fail the build rather than write a messy diagram.

    Two rules. Text must sit inside the box it was drawn into, and boxes must not overlap each
    other. Both were violated repeatedly by the hand-sized version of this file, and both are
    invisible without opening the image -- which is precisely the kind of defect worth spending a
    check on.
    """
    tolerance = 0.35
    problems: list[str] = []

    by_name: dict[str, tuple[float, float, float, float]] = {}
    for label, box in _RECTS:
        by_name.setdefault(label, box)

    for label, text_box in _TEXTS:
        owner = by_name.get(label)
        if owner is None:
            continue
        bx0, by0, bx1, by1 = owner
        tx0, ty0, tx1, ty1 = text_box
        if (
            tx0 < bx0 - tolerance
            or tx1 > bx1 + tolerance
            or ty0 < by0 - tolerance
            or ty1 > by1 + tolerance
        ):
            problems.append(
                f"  text escapes its box {label!r}: text=({tx0:.1f},{ty0:.1f})-({tx1:.1f},{ty1:.1f}) "
                f"box=({bx0:.1f},{by0:.1f})-({bx1:.1f},{by1:.1f})"
            )

    # Free text (notes, captions) must not sit on top of a box either. This was missed: the
    # blast-radius column in the trust-boundary figure ran straight under the gate column, and
    # nothing complained because a note has no owning box to be checked against.
    owned = {label for label, _ in _RECTS}
    for label, text_box in _TEXTS:
        if label in owned:
            continue
        tx0, ty0, tx1, ty1 = text_box
        for box_label, (bx0, by0, bx1, by1) in _RECTS:
            overlap_x = min(tx1, bx1) - max(tx0, bx0)
            overlap_y = min(ty1, by1) - max(ty0, by0)
            if overlap_x > tolerance and overlap_y > tolerance:
                problems.append(
                    f"  free text {label!r} overlaps box {box_label!r} "
                    f"({overlap_x:.1f} x {overlap_y:.1f} units)"
                )

    for index, (label_a, a) in enumerate(_RECTS):
        for label_b, b in _RECTS[index + 1 :]:
            overlap_x = min(a[2], b[2]) - max(a[0], b[0])
            overlap_y = min(a[3], b[3]) - max(a[1], b[1])
            if overlap_x > tolerance and overlap_y > tolerance:
                problems.append(
                    f"  boxes overlap: {label_a!r} and {label_b!r} "
                    f"({overlap_x:.1f} x {overlap_y:.1f} units)"
                )

    for label, (x0, y0, x1, y1) in _RECTS + _TEXTS:
        if x0 < -0.6 or x1 > 100.6 or y0 < -0.6 or y1 > 100.6:
            problems.append(
                f"  {label!r} runs off the canvas: ({x0:.1f},{y0:.1f})-({x1:.1f},{y1:.1f})"
            )

    if problems:
        raise AssertionError(f"layout problems in {name}:\n" + "\n".join(problems))


#: White margin left around the trimmed image, in pixels at DPI.
TRIM_MARGIN = 18


def save(figure, name):
    """Check the layout, write the PNG, then trim the empty margin off it.

    `bbox_inches="tight"` crops to the AXES, not to the ink, so a figure whose content stops
    two-thirds of the way down still carries a third of a page of white -- which then appears as a
    gap in the document. Trimming to the actual pixels means each figure occupies exactly the
    space its content needs, and the canvas height stops being something to tune by hand.
    """
    check_layout(name)
    path = OUT / name
    figure.savefig(path, dpi=DPI, bbox_inches="tight", pad_inches=0.10)
    plt.close(figure)

    from PIL import Image

    image = Image.open(path).convert("RGB")
    ink = image.point(lambda value: 255 - value).convert("L").getbbox()
    if ink:
        left, upper, right, lower = ink
        image.crop(
            (
                max(0, left - TRIM_MARGIN),
                max(0, upper - TRIM_MARGIN),
                min(image.width, right + TRIM_MARGIN),
                min(image.height, lower + TRIM_MARGIN),
            )
        ).save(path)
    print(f"  ok  docs/diagrams/{name}  ({image.width}x{image.height})")


# ── 1. Reference architecture ───────────────────────────────────────────────


def reference_architecture():
    """Three levels, and the middle one is a gate rather than a shortcut.

    The agent is a direct client of all five components -- that part is flat, and drawing it any
    other way invents a hierarchy that does not exist. What is NOT flat is the reach to a cluster:
    the agent holds no cluster credential and has no line of its own to Enterprise Edition or to
    Capella. Every change to a cluster is made by an MCP server on the agent's behalf, which is
    what makes the authorization path, the confirmation prompt, the audit record and the emergency
    stop possible at all. A direct agent-to-cluster edge would route around all four.

    So the picture has one crossing point for change and one for state:
      - the two MCP servers meet at a gate bar, and one line leaves it for the cluster band;
      - Memory, Catalog and Tracer meet at their own dashed bar, because they are PERSISTED INTO a
        keyspace rather than operating on the cluster that holds it.
    Cutting the gate bar stops every change in flight without touching the clusters themselves,
    which is the damage-control property the emergency stop depends on.
    """
    figure, axes = canvas(9.6, 7.0)
    top = title(
        axes,
        "Reference architecture",
        "One agent, five components, one gated path to a cluster. The agent talks to all five\n"
        "components directly and to no cluster at all: every change goes through an MCP server,\n"
        "so it can be authorized, confirmed, recorded — and stopped.",
    )

    # ── level 1: the agent ──────────────────────────────────────────────
    agent = panel(
        axes,
        22,
        top - 12.5,
        heading="AI AGENT",
        body="any Python framework: LangGraph, CrewAI, LlamaIndex\n"
        "holds an identity token — never a cluster credential",
        style=NEUTRAL,
        centre=True,
        width=56,
        height=12.5,
        heading_size=9.6,
        body_size=8.2,
        name="agent",
    )
    agent_x, agent_bottom, agent_w, _ = agent

    # ── level 2: the five components the agent calls ────────────────────
    # Headings and bodies are broken onto short lines deliberately. Five panels across a 6.5"
    # column is a fixed width budget: whatever the longest line is, the type has to shrink until
    # five of them fit. Set on one line, "COUCHBASE MCP SERVER" alone drove the whole row down to
    # roughly 4pt on the printed page. Narrow cells buy back the font size.
    components = [
        ("ADMIN\nMCP SERVER", "clusters, buckets,\nusers, allowlists\nlifecycle", ADMIN, False),
        ("COUCHBASE\nMCP SERVER", "KV and SQL++,\nschema, health,\nqueries", CRUD, False),
        ("AGENT\nMEMORY", "state across\nsessions: user /\nsession / block", AIDP, True),
        ("AGENT\nCATALOG", "tool and prompt\ndefinitions, pinned\nby git commit", AIDP, True),
        ("AGENT\nTRACER", "spans for every\ntool call, LLM call\nand hand-off", AIDP, True),
    ]
    cells = [(h, b, s) for h, b, s, _ in components]
    _, _, comp_h = row(
        axes, 0, cells, gap=1.8, heading_size=9.0, body_size=8.2, draw=False
    )
    comp_y = agent_bottom - 9.0 - comp_h
    positions, comp_w, _ = row(
        axes, comp_y, cells, gap=1.8, heading_size=9.0, body_size=8.2
    )

    # Fanned out from the agent box's own bottom edge, so every line visibly touches it. The fan
    # is the point: this level is FLAT -- the agent holds five independent connections, and no
    # component sits behind another.
    for index, (x, (_, _, style, _)) in enumerate(
        zip(positions, components, strict=True)
    ):
        share = (index + 0.5) / len(components)
        arrow(
            axes,
            (agent_x + share * agent_w, agent_bottom),
            (x + comp_w / 2, comp_y + comp_h),
            color=style[0],
        )

    # ── the gate: two bars, one for change and one for state ────────────
    # Two bars rather than one, at the same height. A single bar spanning all five would say that
    # any of the five may change a cluster, and only two of them may.
    bar_y = comp_y - 7.0
    change_left = positions[0] + comp_w / 2
    change_right = positions[1] + comp_w / 2
    state_left = positions[2] + comp_w / 2
    state_right = positions[4] + comp_w / 2

    axes.plot(
        [change_left, change_right],
        [bar_y, bar_y],
        color=DANGER[0],
        linewidth=2.4,
        solid_capstyle="round",
    )
    axes.plot(
        [state_left, state_right],
        [bar_y, bar_y],
        color=AIDP[0],
        linewidth=1.4,
        linestyle=(0, (5, 2)),
        solid_capstyle="round",
    )
    for x, (_, _, style, stored) in zip(positions, components, strict=True):
        arrow(
            axes,
            (x + comp_w / 2, comp_y),
            (x + comp_w / 2, bar_y + 0.5),
            color=style[0],
            lw=1.1,
            dashed=stored,
        )

    # ── level 3: the cluster, either edition ────────────────────────────
    band_body = (
        "Enterprise Edition: ns_server Management REST, 8091 / 18091          "
        "Capella: Management API v4 on 443\n"
        "managed keyspaces — buckets, scopes, collections, users          "
        "agent state keyspaces — memory, agent_catalog, agent_activity"
    )
    band_h_probe = panel(
        axes,
        0,
        0,
        heading="COUCHBASE SERVER ENTERPRISE EDITION   —or—   COUCHBASE CAPELLA",
        body=band_body,
        style=NEUTRAL,
        centre=True,
        heading_size=9.0,
        body_size=7.6,
        draw=False,
    )
    band_h = band_h_probe[3]
    band_y = bar_y - 13.0 - band_h
    band = panel(
        axes,
        0,
        band_y,
        heading="COUCHBASE SERVER ENTERPRISE EDITION   —or—   COUCHBASE CAPELLA",
        body=band_body,
        style=NEUTRAL,
        centre=True,
        width=100,
        height=band_h,
        heading_size=9.0,
        body_size=7.6,
        name="cluster band",
    )
    band_top = band[1] + band[3]

    # One line down from each bar, dropped from the bar's OUTER end rather than its midpoint. From
    # the midpoint each line ran straight through its own caption -- and the layout check does not
    # see arrows, so nothing complained. At the ends, the captions have the space between them.
    arrow(axes, (change_left, bar_y), (change_left, band_top), color=DANGER[0], lw=1.8)
    arrow(
        axes,
        (state_right, bar_y),
        (state_right, band_top),
        color=AIDP[0],
        lw=1.2,
        dashed=True,
    )

    note(
        axes,
        change_left + 3.0,
        bar_y - 1.8,
        "THE ONLY PATH TO A CLUSTER\n"
        "authorized, confirmed, audited —\nand cut by the emergency stop",
        fontsize=7.8,
        color=DANGER[0],
        weight="bold",
        ha="left",
    )
    note(
        axes,
        state_right - 3.0,
        bar_y - 1.8,
        "PERSISTED INTO a keyspace you own,\n"
        "with its own credential — these three\nchange nothing in the environment",
        fontsize=7.8,
        color=AIDP[0],
        ha="right",
    )

    save(figure, "fig01_reference_architecture.png")


# ── 2. Division of labor ───────────────────────────────────────────────────


def responsibilities():
    figure, axes = canvas(9.8, 5.4)
    top = title(
        axes,
        "Division of labor",
        "The split is by blast radius. A credential that can drop a cluster should not live in the\n"
        "same process as the one that writes a document.",
    )

    quadrants = [
        (
            0,
            ADMIN,
            # No provenance label. Where the code came from is not a division-of-labor
            # fact, and the reviewer names the repository in the component table anyway.
            "ADMIN MCP",
            "clusters, buckets, scopes, collections\n"
            "users, allowlists, rebalance, failover\n"
            "XDCR, backup, eventing, encryption\n"
            "Capella project and cluster lifecycle\n"
            "\n"
            "credential:  cluster admin / API key\n"
            "blast radius:  the organization",
        ),
        (
            51,
            CRUD,
            "COUCHBASE MCP SERVER  (AI Data Plane)",
            "get / insert / upsert / replace / delete\n"
            "run and explain SQL++, list indexes\n"
            "schema discovery, cluster health\n"
            "query performance advisors\n"
            "\n"
            "credential:  database user\n"
            "blast radius:  the data it is scoped to",
        ),
    ]
    # Measured first so both panels can share a baseline, without drawing anything yet.
    row1_h = max(
        panel(
            axes,
            x,
            0,
            heading=heading,
            body=body,
            style=style,
            width=49,
            heading_size=8.6,
            body_size=8.0,
            draw=False,
        )[3]
        for x, style, heading, body in quadrants
    )
    row1_y = top - row1_h
    for x, style, heading, body in quadrants:
        panel(
            axes,
            x,
            row1_y,
            heading=heading,
            body=body,
            style=style,
            width=49,
            height=row1_h,
            heading_size=8.6,
            body_size=8.0,
            name=heading,
        )

    lower = [
        (
            0,
            AIDP,
            "AGENT MEMORY",
            "what the agent knows across sessions:\n"
            "which environment exists and its shape,\n"
            "which data version seeded it,\n"
            "what was decided last time\n"
            "\n"
            "NOT a backup store — see the pointer rule",
        ),
        (
            51,
            AIDP,
            "AGENT CATALOG",
            "how the agent is allowed to do it:\n"
            "versioned tool and prompt definitions,\n"
            "semantic lookup, git-commit pinning,\n"
            "and the trace of everything it did\n"
            "\n"
            "the runbook, under source control",
        ),
    ]
    row2_h = max(
        panel(
            axes,
            x,
            0,
            heading=heading,
            body=body,
            style=style,
            width=49,
            heading_size=8.6,
            body_size=8.0,
            draw=False,
        )[3]
        for x, style, heading, body in lower
    )
    row2_y = row1_y - row2_h - 4.0
    for x, style, heading, body in lower:
        panel(
            axes,
            x,
            row2_y,
            heading=heading,
            body=body,
            style=style,
            width=49,
            height=row2_h,
            heading_size=8.6,
            body_size=8.0,
            name=heading,
        )

    note(
        axes,
        0,
        row2_y - 3.5,
        "The agent composes them: the CATALOG says what may be done and how, MEMORY says what was "
        "done before and to what,\nthe ADMIN MCP changes infrastructure, and the CRUD MCP changes "
        "data. Only the last two hold a credential to a cluster.",
        fontsize=8.3,
        color=INK,
    )
    save(figure, "fig02_responsibilities.png")


# ── 3. Deployment gating ────────────────────────────────────────────────────


def deployment_gating():
    figure, axes = canvas(9.8, 6.0)
    top = title(
        axes,
        "How the Admin MCP decides which tools exist",
        "Deny by default: a tool that cannot work against the connected target is never loaded, so\n"
        "the agent cannot call it and then reason about the error.",
    )

    root = panel(
        axes,
        28,
        top - 7.5,
        heading="CB_DEPLOYMENT   (default: auto)",
        style=NEUTRAL,
        width=44,
        centre=True,
        heading_size=9.2,
        name="root",
    )
    root_y = root[1]

    detect_body = (
        "1.  a Capella host marker in CB_CONNECTION_STRING\n"
        "2.  CAPELLA_API_KEY_SECRET set, no connection string\n"
        "3.  key set AND a non-Capella string  →  both\n"
        "4.  otherwise self_managed"
    )
    detect = panel(
        axes,
        0,
        root_y - 27,
        heading="AUTO-DETECTION, in order",
        body=detect_body,
        style=READ,
        width=48,
        heading_size=8.4,
        body_size=7.9,
        name="detect",
    )
    explicit = panel(
        axes,
        52,
        detect[1] + 3,
        heading="AN EXPLICIT VALUE ALWAYS WINS",
        body="capella   |   self_managed   |   both",
        style=NEUTRAL,
        width=48,
        centre=True,
        heading_size=8.4,
        body_size=8.2,
        name="explicit",
    )

    arrow(axes, (42, root_y), (26, detect[1] + detect[3]))
    arrow(axes, (58, root_y), (74, explicit[1] + explicit[3]))
    note(axes, 25.0, root_y - 1.0, "auto", ha="right", fontsize=7.9)
    note(axes, 75.0, root_y - 1.0, "set explicitly", ha="left", fontsize=7.9)

    bus_y = detect[1] - 6.0
    axes.plot(
        [15, 85], [bus_y, bus_y], color=INK, linewidth=1.2, solid_capstyle="round"
    )
    arrow(axes, (24, detect[1]), (24, bus_y + 0.4), lw=1.1)
    arrow(axes, (76, explicit[1]), (76, bus_y + 0.4), lw=1.1)

    modes = [
        (
            "self_managed",
            "121 admin_* tools\n13 cb_* tools\n= 134 loaded",
            "no capella_* tools",
            ADMIN,
        ),
        (
            "capella",
            "70 capella_* tools\n13 cb_* tools\n+ 1 allowlisted admin\n= 84 loaded",
            "every other admin_* unloaded",
            CRUD,
        ),
        ("both", "121 + 70 + 13\n= 204 loaded", "a host that manages both", AIDP),
    ]
    body_heights = [measure(axes, body, fontsize=8.2)[1] for _, body, _, _ in modes]
    mode_h = max(body_heights) + 12.0
    mode_y = bus_y - 7.0 - mode_h
    for index, (name, body, footnote, style) in enumerate(modes):
        x = index * 35.0
        centre = x + 15
        arrow(axes, (centre, bus_y), (centre, mode_y + mode_h), lw=1.1)
        panel(
            axes,
            x,
            mode_y,
            heading=name,
            body=body,
            style=style,
            width=30,
            height=mode_h,
            centre=True,
            heading_size=9.2,
            body_size=8.2,
            name=name,
        )
        note(axes, x, mode_y - 1.4, footnote, fontsize=7.8)

    note(
        axes,
        0,
        mode_y - 7.5,
        "Read-only mode and the disabled-tool list are applied after this, and the same filter runs "
        "again at dispatch — so a tool\nthat somehow slipped through loading is still refused, with "
        "the reason recorded as denied_deployment.",
        fontsize=8.3,
        color=INK,
    )
    save(figure, "fig03_deployment_gating.png")


# ── 4. Authorization path ───────────────────────────────────────────────────


def authorization_path():
    figure, axes = canvas(9.4, 6.0)
    top = title(
        axes,
        "From an agent's tool call to a cluster",
        "Seven checks, in this order. Every outcome — allowed or refused — writes one audit record\n"
        "carrying the caller's identity from the validated token.",
    )

    steps = [
        (
            "1",
            "handler exists",
            "an unknown name is refused before anything else",
            NEUTRAL,
        ),
        (
            "2",
            "tool is loaded",
            "deployment mode, read-only mode, disabled list",
            ADMIN,
        ),
        ("3", "scope gate", "read / write / automation, from the OAuth token", AIDP),
        (
            "4",
            "hard ceiling",
            "evaluated for EVERY tool, read-only ones included",
            DANGER,
        ),
        ("5", "confirmation", "every write tool by default; automation may skip", READ),
        (
            "6",
            "guardrails",
            "org pin, project allowlist, prefix, TTL, ceilings",
            DANGER,
        ),
        ("7", "egress allowlist", "where the CLUSTER is told to dial out", DANGER),
    ]
    step_h = 5.4
    gap = 2.6
    y = top - step_h
    for number, name, detail, style in steps:
        panel(
            axes,
            0,
            y,
            heading=number,
            style=style,
            width=6.4,
            height=step_h,
            centre=True,
            heading_size=9.4,
            name=f"n{number}",
        )
        panel(
            axes,
            8,
            y,
            heading=name,
            style=style,
            width=27,
            height=step_h,
            heading_size=8.8,
            name=name,
        )
        note(axes, 37.5, y + step_h / 2 + 1.4, detail, fontsize=8.0)
        last_step_bottom = y
        y -= step_h + gap
    last_y = y + gap

    outcome_y = last_y - 13.0
    handler = panel(
        axes,
        0,
        outcome_y,
        heading="HANDLER RUNS",
        body="against Enterprise Edition or Capella",
        style=ADMIN,
        width=46,
        centre=True,
        heading_size=8.8,
        body_size=8.0,
        name="handler",
    )
    panel(
        axes,
        54,
        outcome_y,
        heading="AUDIT RECORD",
        body="one JSON line, allowed or refused",
        style=NEUTRAL,
        width=46,
        centre=True,
        heading_size=8.8,
        body_size=8.0,
        name="audit",
    )
    arrow(axes, (3.2, last_step_bottom), (3.2, outcome_y + handler[3]), lw=1.1)
    arrow(axes, (46, outcome_y + handler[3] / 2), (54, outcome_y + handler[3] / 2))

    note(
        axes,
        0,
        outcome_y - 3.0,
        "The automation scope grants exactly one extra privilege: skipping the human confirmation on "
        "an ordinary gated write.\nIt never substitutes for the write scope, and it never lifts the "
        "hard ceiling.",
        fontsize=8.3,
        color=INK,
    )
    save(figure, "fig04_authorization_path.png")


# ── 5. Lifecycle sequence ───────────────────────────────────────────────────


def lifecycle_sequence():
    """Three phases, not one long run -- and the tester is not necessarily the agent.

    Corrected after review. Two things were wrong. First, the environment agent was drawn as if it
    also ran the workload; in practice the test may be run by a different agent or by a person, and
    the environment agent should not sit holding a session open while that happens. So the run
    splits at a notification boundary: set up, hand over, and only tear down when told the testing
    is finished. State is written to memory BEFORE the hand-over, so nothing depends on the agent
    surviving the wait.

    Second, index creation was attributed to the CRUD MCP alone. Either server can create an index
    -- the Admin MCP has index tools, the CRUD MCP runs SQL++ DDL -- and the choice matters,
    because the CRUD MCP still needs a human to approve a write.
    """
    figure, axes = canvas(10.2, 9.6)
    top = title(
        axes,
        "An environment's life, in three phases",
        "Actors across the top, time running down. The environment agent hands over rather than\n"
        "waiting: whoever runs the workload tells it when they are finished.",
    )

    actors = [
        ("ENV AGENT", NEUTRAL),
        ("CATALOG", AIDP),
        ("ADMIN MCP", ADMIN),
        ("CRUD MCP", CRUD),
        ("MEMORY", AIDP),
        ("TESTER", READ),
    ]
    lane_w = 15.0
    pitch = 17.0
    header_h = 6.4
    header_y = top - header_h
    lifelines = []
    for index, (name, style) in enumerate(actors):
        x = index * pitch
        panel(
            axes,
            x,
            header_y,
            heading=name,
            style=style,
            width=lane_w,
            height=header_h,
            centre=True,
            heading_size=8.4,
            name=name,
        )
        lifelines.append(x + lane_w / 2)

    phases = [
        (
            "PHASE 1 — the agent builds the environment",
            [
                (0, 4, "recall the last known environment state"),
                (0, 1, "fetch the provisioning prompt and tools, pinned to a commit"),
                (
                    0,
                    2,
                    "create project, cluster, bucket, scope, collection, allowlist, credential",
                ),
                (2, 0, "healthy, and here is the connection string"),
                (0, 2, "create the deferred indexes  (Admin MCP: no human needed)"),
                (
                    0,
                    3,
                    "load the base data  (CRUD MCP: a human must approve each write)",
                ),
                (0, 3, "verify the document count against what memory expected"),
            ],
        ),
        (
            "PHASE 2 — somebody else runs the workload",
            [
                (
                    0,
                    4,
                    "record environment id, shape, data version, expected count  ← BEFORE handing over",
                ),
                (0, 5, "hand over: the environment is ready, here is how to reach it"),
                (5, 0, "testing finished  (an agent or a person sends this)"),
            ],
        ),
        (
            "PHASE 3 — the agent puts it away",
            [
                (0, 4, "read back what this run created"),
                (0, 2, "tear down everything in that record"),
                (0, 4, "record the teardown, so the next session does not hunt for it"),
            ],
        ),
    ]

    step = 4.2
    y = header_y - 4.5
    for heading, messages in phases:
        note(axes, 0, y + 1.2, heading, fontsize=8.6, color=INK, weight="bold")
        y -= 5.6
        for source, target, text in messages:
            start_x, end_x = lifelines[source], lifelines[target]
            reply = source != 0
            arrow(
                axes,
                (start_x, y),
                (end_x, y),
                lw=1.1,
                color=MUTED if reply else INK,
                dashed=reply,
            )
            handle = note(
                axes,
                min(start_x, end_x) + 1.0,
                y + 3.2,
                text,
                fontsize=7.7,
                color=INK,
                ha="left",
                va="top",
            )
            handle.set_bbox({"facecolor": "white", "edgecolor": "none", "pad": 1.0})
            y -= step
        y -= 1.0

    for x in lifelines:
        axes.plot(
            [x, x],
            [header_y, y + 3.0],
            color="#9a9a9a",
            linewidth=0.9,
            linestyle=(0, (3, 3)),
            zorder=0,
        )

    note(
        axes,
        0,
        y + 0.5,
        "Writing state to memory BEFORE the hand-over is what lets the agent stop: nothing depends "
        "on it surviving the wait,\nand a run that is never reported finished leaves a record "
        "somebody else can tear down.",
        fontsize=8.2,
        color=INK,
    )
    save(figure, "fig08_lifecycle_sequence.png")


# ── 6. Agent Memory ─────────────────────────────────────────────────────────


def memory_model():
    figure, axes = canvas(9.8, 5.4)
    top = title(
        axes,
        "Agent Memory, and the pointer rule",
        "Memory holds what the agent needs to RECOGNISE and RE-CREATE a state. It is not where the\n"
        "state itself is kept.",
    )

    chain = [
        ("USER", "an identifier you generate;\nmemory is isolated per user", AIDP),
        ("SESSION", "one run or interaction;\nactive, or permanently ended", AIDP),
        ("MEMORY BLOCK", "fact + embedding + summary\n+ timestamp, optional TTL", AIDP),
    ]
    _, _, chain_h = row(
        axes, 0, chain, gap=6.0, heading_size=8.8, body_size=8.0, draw=False
    )
    chain_y = top - chain_h
    row(axes, chain_y, chain, gap=6.0, heading_size=8.8, body_size=8.0, connect=True)

    rules = [
        (
            "PUT IN MEMORY",
            "the environment identifier and its shape\n"
            "the data VERSION or URI — not the data\n"
            "the expected document count\n"
            "the index definitions actually applied\n"
            "decisions, and the reasons for them\n"
            "what failed last time, and what fixed it",
            CRUD,
        ),
        (
            "DO NOT PUT IN MEMORY",
            "the documents themselves\n"
            "credentials of any kind\n"
            "anything non-textual — explicitly unsupported\n"
            "anything needed for a byte-exact restore\n"
            "\n"
            "those belong in object storage, a golden\nbucket, or the repository",
            DANGER,
        ),
    ]
    # Both panels get the same height, taken from the taller one, so their tops line up.
    _, _, rules_h = row(
        axes,
        0,
        rules,
        gap=3.0,
        heading_size=8.8,
        body_size=8.0,
        centre=False,
        draw=False,
    )
    rules_y = chain_y - rules_h - 6.0
    row(axes, rules_y, rules, gap=3.0, heading_size=8.8, body_size=8.0, centre=False)

    note(
        axes,
        0,
        rules_y - 3.0,
        "WHY: a memory block is a fact with an embedding and an LLM-generated summary — optimised "
        "for semantic recall, not for\nfidelity. Restoring base data from memory alone would be "
        "restoring a paraphrase of it.",
        fontsize=8.3,
        color=INK,
    )
    save(figure, "fig05_memory_model.png")


# ── 7. Agent Catalog ────────────────────────────────────────────────────────


def catalog_workflow():
    figure, axes = canvas(10.0, 5.0)
    top = title(
        axes,
        "Agent Catalog: from a file in git to a tool the agent can find",
        "The catalog executes nothing. It stores definitions, versions them by git commit, and hands\n"
        "them back to whichever framework runs them.",
    )

    stages = [
        ("agentc init", "in the project repo,\noptional git hook", NEUTRAL),
        ("agentc add", "one of five record\nkinds, scaffolded", AIDP),
        ("agentc index", "builds the local JSON,\nrefuses a dirty tree", READ),
        ("agentc publish", "writes agent_catalog\ninto your bucket", AIDP),
        ("catalog.find(...)", "by name, or by question,\npinned to a commit", CRUD),
    ]
    _, _, stage_h = row(axes, 0, stages, gap=1.6, heading_size=8.3, body_size=7.6)
    # Measured once at y=0 to learn the height, then drawn for real at the right baseline.
    axes.clear()
    axes.set_xlim(0, 100)
    axes.set_ylim(0, 100)
    axes.axis("off")
    _RECTS.clear()
    _TEXTS.clear()
    top = title(
        axes,
        "Agent Catalog: from a file in git to a tool the agent can find",
        "The catalog executes nothing. It stores definitions, versions them by git commit, and hands\n"
        "them back to whichever framework runs them.",
    )
    stage_y = top - stage_h
    row(axes, stage_y, stages, gap=1.6, heading_size=8.3, body_size=7.6, connect=True)

    lower = [
        (
            "WHERE IT LANDS",
            "scope  agent_catalog\n"
            "    tool_catalog         indexed tools\n"
            "    tool_metadata        tool metadata\n"
            "    prompt_catalog       indexed prompts\n"
            "    prompt_metadata      prompt metadata\n"
            "\n"
            "you create the bucket; publish creates the scope",
            AIDP,
        ),
        (
            "WHY IT MATTERS FOR ENVIRONMENTS",
            "the spin-up runbook becomes a versioned\n"
            "artifact: the prompt that drives provisioning,\n"
            "and the tools it may call, pinned to a commit\n"
            "\n"
            "two operators then run the same procedure,\n"
            "and a change to it is a diff",
            CRUD,
        ),
    ]
    _, _, lower_h = row(
        axes,
        0,
        lower,
        gap=3.0,
        heading_size=8.5,
        body_size=7.8,
        centre=False,
        draw=False,
    )
    lower_y = stage_y - lower_h - 5.0
    row(axes, lower_y, lower, gap=3.0, heading_size=8.5, body_size=7.8, centre=False)

    note(
        axes,
        0,
        lower_y - 3.0,
        "Version identity is the GIT COMMIT HASH. The same string is the catalog_id in a lookup, the "
        "cid on every trace record,\nand the version selector in the Capella Tools and Prompts Hub — "
        "one identifier ties a run to the definition behind it.",
        fontsize=8.3,
        color=INK,
    )
    save(figure, "fig06_catalog_workflow.png")


# ── 8. Tracing ──────────────────────────────────────────────────────────────


def tracing():
    figure, axes = canvas(9.8, 4.8)
    top = title(
        axes,
        "Agent Tracer: what the agent did, after the fact",
        "Spans are written locally first, then forwarded to the cluster, where they become ordinary\n"
        "documents you can query.",
    )

    flow = [
        ("ROOT SPAN", "the application", AIDP),
        ("CHILD SPANS", "tool call, LLM call,\nretrieval, hand-off", AIDP),
        (".agent-activity", "written locally first", READ),
        ("THE CLUSTER", "forwarded, then\nqueryable", NEUTRAL),
    ]
    _, _, flow_h = row(
        axes, 0, flow, gap=2.4, heading_size=8.4, body_size=7.8, draw=False
    )
    flow_y = top - flow_h
    row(axes, flow_y, flow, gap=2.4, heading_size=8.4, body_size=7.8, connect=True)

    views = [
        (
            "Sessions()",
            "one row per session: sid, cid (the catalog version),\nroot span, start time, content, annotations",
        ),
        (
            "Exchanges()",
            "user input paired with the assistant output,\nand everything in between",
        ),
        (
            "ToolInvocations()",
            "tool-call paired with tool-result by tool_call_id —\nwhat was asked, and what came back",
        ),
    ]
    view_h = 9.4
    y = flow_y - 7.5 - view_h
    for heading, body in views:
        panel(
            axes,
            0,
            y,
            heading=heading,
            style=CRUD,
            width=27,
            height=view_h,
            centre=True,
            heading_size=8.6,
            name=heading,
        )
        note(axes, 29, y + view_h - 1.6, body, fontsize=8.0, color=INK)
        y -= view_h + 2.8

    note(
        axes,
        0,
        y + 1.4,
        "For a provisioning agent this answers 'which run created this cluster, under which version "
        "of the runbook, and what did\nit decide' — which neither MCP server's audit log can answer, "
        "because neither knows about the agent's reasoning.",
        fontsize=8.3,
        color=INK,
    )
    save(figure, "fig07_tracing.png")


# ── 9. Trust boundaries ─────────────────────────────────────────────────────


def trust_boundaries():
    """Adds the two things review found missing: who still needs a human, and dry-run first."""
    figure, axes = canvas(10.2, 6.4)
    top = title(
        axes,
        "Trust boundaries, credentials, and who still needs a human",
        "Four credentials, four blast radii, no component holding two — and one component that\n"
        "cannot yet act without a person in the loop.",
    )

    rows = [
        (
            "AGENT / LLM",
            "an OAuth token from your IdP",
            "identity only",
            "n/a",
            NEUTRAL,
        ),
        (
            "ADMIN MCP",
            "cluster admin, or a Capella API key",
            "all infrastructure",
            "automation scope",
            ADMIN,
        ),
        (
            "CRUD MCP",
            "a database user",
            "documents in its scope",
            "HUMAN REQUIRED",
            DANGER,
        ),
        (
            "AGENT MEMORY",
            "a database user for its own bucket",
            "memory blocks only",
            "n/a",
            AIDP,
        ),
        (
            "AGENT CATALOG",
            "a database user for the catalog bucket",
            "the catalog scope",
            "n/a",
            AIDP,
        ),
    ]

    name_w = (
        max(measure(axes, r[0], fontsize=8.6, weight="bold")[0] for r in rows) + 5.0
    )
    cred_w = (
        max(measure(axes, r[1], fontsize=8.2, weight="bold")[0] for r in rows) + 5.0
    )
    # Ask panel() how wide each gate cell needs to be, accent bar included. Measuring the text and
    # adding a constant was guessing: the accent allowance lives inside panel(), where the caller
    # cannot see it, so the widest row grew past the right edge.
    gate_w = max(
        panel(
            axes,
            0,
            0,
            heading=row_data[3],
            style=NEUTRAL,
            heading_size=8.0,
            accent=row_data[4] is DANGER,
            draw=False,
        )[2]
        for row_data in rows
    )
    gap = 1.8
    radius_x = name_w + gap + cred_w + gap
    gate_x = 100 - gate_w

    note(axes, gate_x, top + 3.4, "unattended?", fontsize=7.8, weight="bold", color=INK)

    row_h = 8.0
    y = top - row_h
    for name, credential, radius, gate, style in rows:
        flag = style is DANGER
        panel(
            axes,
            0,
            y,
            heading=name,
            style=style,
            width=name_w,
            height=row_h,
            centre=True,
            heading_size=8.6,
            name=name,
            accent=flag,
        )
        panel(
            axes,
            name_w + gap,
            y,
            heading=credential,
            style=style,
            width=cred_w,
            height=row_h,
            centre=True,
            heading_size=8.2,
            name=credential,
            accent=flag,
        )
        note(axes, radius_x, y + row_h / 2 + 1.4, radius, fontsize=7.9)
        panel(
            axes,
            gate_x,
            y,
            heading=gate,
            style=style if gate != "n/a" else NEUTRAL,
            width=gate_w,
            height=row_h,
            centre=True,
            heading_size=8.0,
            name=f"gate {name}",
            accent=flag,
        )
        y -= row_h + 2.2

    # Checked against the code, because it used to be checked against nothing: the claim
    # "every Admin MCP tool takes a dry-run flag" was written when exactly one did.
    # dry_run is now advertised on every write tool's schema and enforced centrally, with
    # CB_ADMIN_DRY_RUN forcing it server-wide, so the sentence is true as stated.
    dry_run = (
        "DRY RUN FIRST. Every Admin MCP write tool takes dry_run, and CB_ADMIN_DRY_RUN=true "
        "forces it server-wide: the call is\nauthorized and audited, then NOT performed, and the "
        "response says what it WOULD have done. Reads still run, because a\nplan cannot be checked "
        "without them. Put that output in front of a person before the first real run against an "
        "organization\n— it is the cheapest review that exists, and the artifact to attach to a "
        "change request. It is not validation: nothing is sent."
    )
    dry_h = measure(axes, dry_run, fontsize=8.0)[1] + 6.0
    dry_y = y - dry_h + 3.0
    panel(
        axes,
        0,
        dry_y,
        body=dry_run,
        style=READ,
        width=100,
        height=dry_h,
        body_size=8.0,
        name="dryrun",
    )

    note(
        axes,
        0,
        dry_y - 3.0,
        "The agent never holds a cluster credential. It holds a token saying who it is and what it "
        "may ask for; the MCP servers hold the\ncredentials and decide whether to act. Until the "
        "open CBSE enhancement lands, the CRUD MCP's decision still requires a\nperson — so an "
        "unattended pipeline should run it read-only and route writes through a path that refuses.",
        fontsize=8.2,
        color=INK,
    )
    save(figure, "fig09_trust_boundaries.png")


# ── 10. Topologies ──────────────────────────────────────────────────────────


def topologies():
    """Compact: the version with a six-row comparison table ran past the bottom of the page.

    The comparison content lives in the body text of the deployment-topologies section, so the
    figure keeps only what is spatial: the two shapes, and the band that says what each MCP server
    does when nobody is watching.
    """
    figure, axes = canvas(10.0, 5.6)
    top = title(
        axes,
        "Two topologies, and the limit of unattended operation",
        "The difference is not scale. It is whether a human is present — and only one of the two\n"
        "MCP servers is currently built for their absence.",
    )

    shapes = [
        (
            "WORKSTATION",
            "both MCP servers over stdio, in the\n"
            "developer's client process\n"
            "Agent Memory optional, local\n"
            "catalog indexed locally\n"
            "\n"
            "a human sees every prompt, so\n"
            "confirmation IS the control",
            NEUTRAL,
        ),
        (
            "ENTERPRISE",
            "both over Streamable HTTP, behind\n"
            "OAuth with audience validation\n"
            "Memory and Catalog on shared clusters\n"
            "audit to a private rotating file\n"
            "\n"
            "no human is present — so read the\n"
            "band below before enabling writes",
            ADMIN,
        ),
    ]
    _, _, shape_h = row(
        axes,
        0,
        shapes,
        gap=2.0,
        heading_size=9.0,
        body_size=8.0,
        centre=False,
        draw=False,
    )
    shape_y = top - shape_h
    row(axes, shape_y, shapes, gap=2.0, heading_size=9.0, body_size=8.0, centre=False)

    unattended = [
        (
            "ADMIN MCP — built for it",
            "the automation scope skips the per-call\n"
            "human confirmation on a gated write\n"
            "without it, a gated write is REFUSED\n"
            "the hard ceiling denies outright\n"
            "→ FAILS CLOSED",
            ADMIN,
        ),
        (
            "CRUD MCP — human in the loop required",
            "every action assumes a person will\n"
            "approve it. Confirmation is an MCP\n"
            "elicitation; a client that cannot elicit\n"
            "runs the tool ANYWAY, unconfirmed.\n"
            "→ FAILS OPEN   (CBSE open, not started)",
            DANGER,
        ),
    ]
    _, _, un_h = row(
        axes,
        0,
        unattended,
        gap=2.0,
        heading_size=8.6,
        body_size=7.9,
        centre=False,
        draw=False,
    )
    un_y = shape_y - un_h - 7.5
    note(
        axes,
        0,
        un_y + un_h + 4.6,
        "WITH NO HUMAN PRESENT",
        fontsize=9.0,
        color=INK,
        weight="bold",
    )
    positions, width, _ = row(
        axes,
        un_y,
        unattended,
        gap=2.0,
        heading_size=8.6,
        body_size=7.9,
        centre=False,
        draw=False,
    )
    for x, (heading, body, style) in zip(positions, unattended, strict=True):
        panel(
            axes,
            x,
            un_y,
            heading=heading,
            body=body,
            style=style,
            width=width,
            height=un_h,
            heading_size=8.6,
            body_size=7.9,
            name=heading,
            accent=style is DANGER,
        )

    note(
        axes,
        0,
        un_y - 3.0,
        "Until that gap closes, run the CRUD MCP read-only in an unattended deployment, or disable "
        "its write tools and route every\nmutation through a path that does refuse — the Admin MCP, "
        "or a script with its own gate.",
        fontsize=8.2,
        color=INK,
    )
    save(figure, "fig10_topologies.png")


def main() -> None:
    print("generating architecture diagrams")
    for builder in (
        reference_architecture,
        responsibilities,
        deployment_gating,
        authorization_path,
        lifecycle_sequence,
        memory_model,
        catalog_workflow,
        tracing,
        trust_boundaries,
        topologies,
    ):
        builder()
    print("all diagrams passed the layout check")


if __name__ == "__main__":
    main()
