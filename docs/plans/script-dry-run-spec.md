# Spec: dry-run modes and usage for the scripts

Status: APPROVED by Chris Ahrendt, 2026-11-06, all four decisions (1a, 2a, 3a, 4a). Built the same day.
Origin: `docs/questions.md` Q-004, decided 2026-11-05, option (a): scripts get dry-run
modes and a usage section in `scripts/README.md`. Standard: documentation standard,
"scripts" rule. Drafted 2026-11-06 from reading the scripts; counts below were checked
by text search, not by running them.

## What exists today

- 23 Python scripts. 13 already take `--perform` and preview without it. 10 do not.
- 14 PowerShell scripts. None supports `-WhatIf`.

## Proposal: Python (the 10 without `--perform`)

| Script | What it does to anything outside itself | Proposal |
| --- | --- | --- |
| `load_test_data.py` | Creates scopes, collections and indexes and upserts about 2,200 documents. No gate at all. | CODE. Add `--perform`. Without it, print the plan (bucket, target, counts, keyspaces, indexes) and exit 0 without connecting. |
| `probe_data_api.py` | `--enable` turns on the Capella Data API (billable); `--disable` turns it off. Without either it only reads. | DOCS only. The action flag is the opt-in. State that in the usage section. |
| `verify_capella_paths.py` | GET and OPTIONS only. `--write-probe` is already the opt-in for the writes. | DOCS only. |
| `capella_backup_readiness.py` | Read-only by its own header. | DOCS only. Say "read-only; nothing to preview". |
| `probe_local_sdk.py` | Opens connections only. | DOCS only. Same wording. |
| `verify_mcp_surface.py` | Drives the server over stdio and stops short of writes; the server's own dry run intercepts. | DOCS only. |
| `idp_lab_assertions.py` | Calls tools through the running server, so its gates apply. | DOCS only. |
| `mutation_rounds_1_3.py`, `mutation_round_4.py`, `mutation_round_5.py` | Change only a temporary copy of the repository. No parser: `--help` starts a full round. | CODE. Add a parser. `--help` prints usage and exits. `--list` prints each mutation (file, anchor text, tests that should notice) and runs nothing. |

## Proposal: PowerShell (the 14)

Eight change something outside the script. By reading their headers and commands:
`start-ee-cluster`, `ee-lab`, `seed-ee-bucket`, `add-local-services`,
`probe-alternate-ports`, `run-docker-verification`, `commit-session`, `fetch-ee-backup`.

- CODE. Each gets `[CmdletBinding(SupportsShouldProcess)]`, and every call that changes
  something (`docker run/rm/build/network create/cp`, `bucket-create`, `cbimport`, REST
  PUT/POST, `git branch/add/commit`) sits behind `$PSCmdlet.ShouldProcess(target, action)`.
  `-WhatIf` then prints what would happen. Native commands such as `docker` do not honour
  `-WhatIf` by themselves, so the wrapping is explicit.
- The other six are read-only: `find-couchbase-clusters`, `measure-egress`,
  `probe_backup_paths`, `probe_backup_repository`, `probe_rest_paths`, `run-mcp-evidence`.
  DOCS only: the header and usage say "read-only; nothing to preview".

The eight are sorted from headers and a text search. Each is re-read when its change is made;
a script found to belong in the other group is moved and the move is noted in the commit.

## Usage section

`scripts/README.md` gets, per script: the command line, the environment variables it reads,
what it changes (a column: `nothing`, `preview unless --perform`, or `-WhatIf`), and what a
successful run prints. The Python ones are checked against `--help` so the two cannot drift.

## Tests and the gate

- `load_test_data`: a test with a fake cluster proves nothing is written without `--perform`
  and that `--perform` writes.
- Mutation scripts: a test proves `--help` and `--list` return in seconds and start no round.
- Gate: a new rule, fail mode from the start. Every file in `scripts/` is either in an explicit
  read-only tuple (with a reason) or accepts `--perform` / `-WhatIf`, and every script is named in
  `scripts/README.md`. A new script therefore forces the decision.
- GAP, stated plainly: CI runs on Linux without PowerShell, so `-WhatIf` behaviour is not
  tested in CI. The gate checks only that `SupportsShouldProcess` is present. Behaviour is
  verified by hand on Chris's Windows machine, and that is recorded.

## Decisions (all taken 2026-11-06 by Chris Ahrendt)

1. DECIDED (a). `load_test_data.py` previews by default, so anyone who runs it as before gets a plan and
   no data until they add `--perform`. (a) yes; (b) keep loading by default and add `--dry-run`.
2. DECIDED (a), all eight. `-WhatIf` for all eight PowerShell scripts, or only the three that touch a cluster
   (`start-ee-cluster`, `seed-ee-bucket`, `add-local-services`)?
3. DECIDED yes. Mutation scripts get a parser with `--help` and `--list`: yes or no.
4. DECIDED yes. The new gate rule: `scripts-preview` in `tests/test_documentation_gate.py`.

## What was built, and what was not checked

Built: the gate rule, the README section "Preview before you change anything", `--perform` on
`load_test_data.py`, `--help` and `--list` on the three mutation scripts, `-WhatIf` on the eight
PowerShell scripts, and `tests/test_script_dry_runs.py`. NOT run: the PowerShell changes, because
CI and the build sandbox have no PowerShell. Chris runs each `-WhatIf` once on Windows.

## Order of work

1. Gate rule and README usage section (docs, no behaviour change).
2. `load_test_data` and the three mutation scripts, with tests.
3. PowerShell `-WhatIf`, one script per commit so each can be run by hand before the next.
