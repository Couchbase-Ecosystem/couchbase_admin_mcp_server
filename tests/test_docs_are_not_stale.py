"""Documentation may not state a registry count without a date beside it.

WHY THIS FILE EXISTS
====================
On 2026-09-14 a sweep of this repository's own documentation found seven claims
that had quietly become false, all of them in the present tense:

    CLAUDE.md  "The registry holds 97."                  It held 125.
    CLAUDE.md  "SKIPPED 95"                              Surface skips were 0.
    CLAUDE.md  "One write of roughly 45 has been         Most writes were
                performed"                                verified.
    CLAUDE.md  "The 244/244 target was set and not met"  It had been met.

None of those were wrong when written. Every one became wrong because the code
moved and the sentence did not, and a reader — a customer, or the next person
picking this up — has no way to tell a fact from a fossil.

WHAT THIS ASSERTS, AND WHAT IT DELIBERATELY DOES NOT
====================================================
Pinning the numbers themselves would be worse than useless: the test would fail
on every legitimate change and train people to edit the number without reading
why it was there, which is the exact failure CLAUDE.md rule 1.2 records.

So this asserts something weaker and far more durable: **a sentence that quotes
a count of operations, tools or skips must carry a DATE in the same paragraph.**
A dated claim that goes out of date is still honest — it says when it was true.
An undated one silently becomes a lie.

That is CLAUDE.md's own instruction, written the same day:

    Counts move. Do not quote one here without a date beside it.
"""

from __future__ import annotations

import pathlib
import re

import pytest

_REPO = pathlib.Path(__file__).resolve().parent.parent

#: Phrases that state a measured count of the surface. Each is a claim about the
#: code that a reader would reasonably take as current.
_COUNT_CLAIM = re.compile(
    r"""(
        \b\d{2,4}\s+(?:operations|ops|tools)\b
      | \bregistry\s+(?:holds|held)\s+\d+
      | \bSKIPPED[=\s]+\d+
      | \bOK\s+\d{2,}\b
    )""",
    re.IGNORECASE | re.VERBOSE,
)

#: A date, in any of the forms this repository actually uses.
_DATE = re.compile(r"20\d\d-\d\d-\d\d|\b(?:early |late )?[A-Z][a-z]+ 20\d\d\b")

#: Documents exempt, each for a stated reason.
_EXEMPT = {
    # Generated from the registry itself, so it cannot drift from it.
    "docs/tools.json",
}

#: A document may declare ITSELF historical, in its first paragraph, and is then
#: exempt. CAPELLA_HANDOFF.md is the case this was written for: 65 KB of
#: reasoning and measured findings from early September, several still
#: load-bearing, whose counts were true when written and are not now.
#:
#: Dating each of its sentences individually would be busywork that makes the
#: document no more honest -- the banner already tells the reader the whole file
#: is a record rather than a status. What the banner must NOT do is appear on a
#: document someone still treats as current, which is why it has to be the
#: FIRST thing in the file rather than a footnote.
_HISTORICAL_BANNER = "HISTORICAL RECORD"


def _declares_itself_historical(text: str) -> bool:
    return _HISTORICAL_BANNER in text[:1200]


def _paragraphs(text: str):
    """(first line number, paragraph text) for each blank-line-separated block."""
    line = 1
    for block in text.split("\n\n"):
        yield line, block
        line += block.count("\n") + 2


def _docs() -> list[pathlib.Path]:
    found = sorted(_REPO.glob("*.md"))
    found += sorted((_REPO / "docs").glob("*.md"))
    found += sorted((_REPO / "deploy").glob("*.md"))
    return [d for d in found if str(d.relative_to(_REPO)).replace("\\", "/")
            not in _EXEMPT]


def test_there_are_documents_to_check():
    """A scan over an empty set is a green tick that checked nothing — see
    CLAUDE.md section 3 and tests/test_no_vacuous_coverage.py."""
    assert len(_docs()) >= 8, "expected the repository's markdown docs to be found"


@pytest.mark.parametrize("doc", _docs(), ids=lambda p: p.name)
def test_a_count_claim_carries_a_date(doc: pathlib.Path):
    """Every stated count must say WHEN it was true."""
    text = doc.read_text(encoding="utf-8", errors="replace")
    if _declares_itself_historical(text):
        pytest.skip(f"{doc.name} declares itself a HISTORICAL RECORD up front")
    # A date in the FILENAME dates every claim in the file, which is the whole
    # point of naming a scan report after the day it was run.
    if _DATE.search(doc.name):
        pytest.skip(f"{doc.name} carries its date in the filename")
    undated = []
    for line_no, block in _paragraphs(text):
        for match in _COUNT_CLAIM.finditer(block):
            if not _DATE.search(block):
                undated.append(f"{doc.name}:{line_no}: {match.group(0).strip()!r}")
    assert not undated, (
        "these sentences state a count of the surface with no date in the same "
        "paragraph, so a reader cannot tell a current fact from a stale one:\n  "
        + "\n  ".join(undated)
        + "\n\nAdd the date the count was measured. Do NOT pin the number in a "
        "test -- that fails on every legitimate change and trains the next "
        "person to edit the number rather than read why it is there, which is "
        "the failure CLAUDE.md rule 1.2 records."
    )
