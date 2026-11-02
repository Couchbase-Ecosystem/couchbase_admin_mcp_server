# Documentation standard: gap assessment and plan

Status: the plan is approved. Q1 to Q5 were decided by Chris Ahrendt on
2026-11-02 (see "Decisions" below). The order of work is still [DESIGN] until
each step is accepted.

Change in this version: v0.2 (2026-11-02), records the decisions on Q1 to Q5.
v0.1 was the first draft, the same day.

Measured against `main` at commit `e57765b` (2026-10-09). The scan script and
commands are listed under "How this was measured", so anyone can re-run it.

## Roles

Chris Ahrendt is the architect. He decides the architecture and every design
decision. AI assists under his direction: it drafts specs he approves and writes
code from the specs he approved.

## What the standard needs, and what is there today

| Rule | Needs | Today | Gap |
|---|---|---|---|
| D1 | Header on every source file, test and script: purpose, component, main items, callers and callees, spec sections and question numbers | 153 of 155 Python files have a module docstring. 107 of them name no callers or callees. None cite spec sections or question numbers, because there is no numbered spec. The 14 PowerShell scripts and 1 HTML file have not been checked | Callers and callees in about 107 headers. Spec references in every header (Q1 is decided, so this is unblocked) |
| D2 | Doc comment on every public item | 159 of 390 public functions and classes outside `tests/` have no docstring: scripts 93 of 139, handlers 33 of 116, root modules 16 of 67, docs 12 of 27, gui 5 of 11, auth 0 of 30 | 159 docstrings. Private helpers still to be judged one by one |
| D3, D15 | Why-comments, and a design note per hard subsystem | 66 functions exceed complexity 10 under `ruff C901`, 37 of them outside `tests/` and `scripts/`. The heaviest are the fixture handlers, the Capella client, egress, the GUI server and `server.py`. Many already carry long why-comments. `docs/design/` does not exist | A design note per hard area. A review of each flagged function for the D15 doc-comment fields |
| D4 | Wire constants cite a public source | Not checked | A pass over HTTP paths, status codes and error codes |
| D5 | Clean room: no real hostnames, credentials or descriptions of another product's internal code | Real Capella hostnames in `CAPELLA-CONNECTIVITY.md` and `handlers/capella/fixture.py`. Real cluster and organization names in 11 places. 12 UUID-like strings to review. 47 references to the Terraform provider's source code (Q3, decided: public material) | Scrub and replace with stand-ins |
| D6, D9 | Handover set in `docs/`, linked from `docs/README.md` | `docs/ARCHITECTURE.md` exists. Missing: `docs/README.md`, module map, build guide, threading model, `docs/design-decisions.md` | Create the missing files |
| D7 | A documentation gate in the regression run | None. Some tests already check single facts in the docs, such as the license and the tool lists | New gate test, run in CI |
| D8 | Docs updated in the same commit as behavior | A working practice. Nothing enforces it | Covered by the D7 gate |
| D10 | `CONTRIBUTING.md` and `AGENTS.md` at the root | `CONTRIBUTING.md` exists. `AGENTS.md` does not. `CLAUDE.md` holds the agent rules today | Add `AGENTS.md`. Decide how it relates to `CLAUDE.md` (Q4, decided) |
| D11 | `CHANGELOG.md` with a build number, shipped in every package | None. No build-number scheme | Add the file and pick a scheme (Q2, decided) |
| D12 | A tested example for every public entry point | None. There are 284 tools plus the scripts | Decide what counts as an entry point (Q5, decided) |
| D13 | Headers describe the present. History goes to the decision log | Many headers and `CLAUDE.md` sections carry dated history and retractions inline | Move history into `docs/design-decisions.md` |
| D14 | `README.md` in every top-level folder | Only `deploy/` has one. Missing in `auth/`, `docs/`, `gui/`, `handlers/`, `scripts/`, `tests/` | 6 READMEs |
| Scripts | Usage in the folder README, plus a dry-run or `-WhatIf` mode | No `scripts/README.md`. 12 scripts show no dry-run switch in a text search (list below). The search is crude, so each one needs confirming | `scripts/README.md`, and dry-run modes where missing |

Scripts with no dry-run match in the search: `add-local-services.ps1`,
`find-couchbase-clusters.ps1`, `load_test_data.py`, `measure-egress.ps1`,
`mutation_round_4.py`, `probe-alternate-ports.ps1`, `probe_backup_paths.ps1`,
`probe_data_api.py`, `probe_local_sdk.py`, `probe_rest_paths.ps1`,
`seed-ee-bucket.ps1`, `start-ee-cluster.ps1`.

## Decisions

Decided by Chris Ahrendt on 2026-11-02.

| Q | Decision | Effect |
|---|---|---|
| Q1 | (a) Write a numbered `docs/spec.md` from today's behavior and start `docs/questions.md`. Headers cite both | Spec and question log are in the handover set |
| Q2 | (a) Build number is the `pyproject.toml` version plus the short commit hash | Changelog entries carry that build number |
| Q3 | Yes. The Terraform provider source is public material | The citations stay. D5 does not require removing them |
| Q4 | (a) `AGENTS.md` holds the rules. `CLAUDE.md` points at it | One copy of the rules |
| Q5 | (a) One tested example per tool group (17 modules), reusing the existing test harness | The gate counts the examples |

The questions below are kept as asked, so the reasoning stays on record.

## Questions for Chris

**Q1 [DECIDED]. What do the headers cite as the spec?** D1 wants spec sections and
question numbers, and there is no numbered spec.
- (a) Write `docs/spec.md` from today's behavior, with numbered sections, and
  start `docs/questions.md`. Headers cite both.
- (b) Make the exception request v8 the spec of record and number its sections.
- Recommendation: (a). The exception request is a business case and changes for
  other reasons.

**Q2 [DECIDED]. Build numbers for the changelog?**
- (a) The version from `pyproject.toml` plus the short commit hash.
- (b) The CI run number.
- Recommendation: (a). It needs no CI change and is reproducible.

**Q3 [DECIDED]. Is the Terraform provider source "public material"?** The
provider is open source, and `CLAUDE.md` 1.5 makes its generated client the
primary source. D5 forbids describing another product's internal code.
- (a) Keep the citations: it is public code.
- (b) Cite only the published API reference, and keep provider findings as
  observed behavior.
- Recommendation: this one is for Chris and legal to call.
- Decision: (a), by Chris Ahrendt, 2026-11-02.

**Q4 [DECIDED]. `AGENTS.md` and `CLAUDE.md`.**
- (a) `AGENTS.md` holds the rules, and `CLAUDE.md` points at it.
- (b) Keep both and let the gate check they agree.
- Recommendation: (a). One copy cannot drift.

**Q5 [DECIDED]. What is a "public entry point" for D12?**
- (a) Each tool group (17 modules) gets one tested example, run against stubs.
- (b) Every one of the 284 tools.
- Recommendation: (a) now, with (b) added group by group.

## Proposed order of work

Each step is its own commit, tested, and pushed only after Chris approves it.

1. **Gate first, in report mode.** `tests/test_documentation_gate.py` lists every
   gap and does not fail the build yet. This fixes the baseline.
2. **Handover set.** `docs/README.md`, the module map, the build guide, the
   threading model, `docs/design-decisions.md`, `AGENTS.md`, `CHANGELOG.md`,
   and the six folder READMEs.
3. **Clean room.** Scrub hostnames, names and identifiers. Settle Q3.
4. **Headers and doc comments, one module group at a time.** Handlers first, then
   the root modules, auth, the GUI, scripts and tests. Each group's gate check
   moves to fail mode when that group is done.
5. **Hard subsystems.** `docs/design/` notes for authorization, the Capella
   client, fixtures, egress and the transports. D15 doc comments on the flagged
   functions.
6. **Examples and dry-run modes.**
7. **Gate in fail mode for everything.**

Effort: not estimated. It depends on Q1 and Q5.

## How this was measured

From the repository root at `e57765b`:

- Headers and docstrings: a Python `ast` scan of `git ls-files '*.py'`, counting
  module docstrings and public (no leading underscore) functions and classes.
  Callers and callees were detected by keywords, which is a heuristic.
- Complexity: `uv run ruff check --select C901 --config 'lint.mccabe.max-complexity=10' --exit-zero --statistics .`
- Dry-run modes: a case-insensitive text search of `scripts/*` for
  `WhatIf|SupportsShouldProcess|dry-run|--perform|read-only`.
- Clean room: `git grep` for UUID patterns, `*.cloud.couchbase.com` hostnames
  and named clusters.

Not measured: D1 headers in PowerShell, JavaScript and HTML; D4 constants;
D13 history inside headers.
