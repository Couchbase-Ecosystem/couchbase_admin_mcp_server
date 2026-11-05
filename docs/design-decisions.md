# Design decisions

The decision log. Each entry has a date, what was decided, and who decided. Reasoning and
alternatives are in `docs/questions.md` or the named design note. Newest first.

History that used to sit inside source headers and `AGENTS.md` moves here over time (D13).
A header says what the code does now, and cites a question number for the reasoning.

| Date | Decision | Decided by | Where the reasoning is |
| --- | --- | --- | --- |
| 2026-11-05 | Customer names and internal ticket ids leave the public repository; the reasoning stays (Q-007 option b) | Chris Ahrendt | `docs/questions.md` Q-007 |
| 2026-11-05 | The lab password is read from `CB_LAB_PASSWORD`, with no default (Q-006 option a) | Chris Ahrendt | `docs/questions.md` Q-006 |
| 2026-11-05 | `CHANGELOG.md` stays beside the top-level modules in the wheel (Q-005 option a) | Chris Ahrendt | `docs/questions.md` Q-005 |
| 2026-11-05 | Only tools get a tested example. Scripts get dry-run modes and a usage section (Q-004 option a) | Chris Ahrendt | `docs/questions.md` Q-004 |
| 2026-11-05 | The audit decision vocabulary is defined once, as `audit.DECISIONS`, and tested (Q-003 option a) | Chris Ahrendt | `docs/questions.md` Q-003 |
| 2026-11-05 | The three import cycles stay, documented (Q-002 option a) | Chris Ahrendt | `docs/questions.md` Q-002 |
| 2026-11-05 | The cached SDK cluster is created under a lock (Q-001 option a) | Chris Ahrendt | `docs/questions.md` Q-001 |
| 2026-11-02 | The tool-group example (D12) is one tested example per tool group, 17 groups, reusing the handler contract harness | Chris Ahrendt | `docs/plans/documentation-standard-gap.md` Q5 |
| 2026-11-02 | `AGENTS.md` holds the working rules and `CLAUDE.md` points at it | Chris Ahrendt | Same file, Q4 |
| 2026-11-02 | The Terraform provider source is public material, so its citations stay | Chris Ahrendt | Same file, Q3 |
| 2026-11-02 | The build number is the `pyproject.toml` version plus the short commit hash | Chris Ahrendt | Same file, Q2 |
| 2026-11-02 | A numbered `docs/spec.md` is written from today's behavior and headers cite it, with `docs/questions.md` | Chris Ahrendt | Same file, Q1 |
| 2026-10-09 | The replica-count check on Capella reads `num_replica` from the live cluster response | Chris Ahrendt | Commit `e57765b` |
| 2026-09-14 | Capella capability priorities P0 and P1 are built, P2 waits for a use case, P3 is not added | Chris Ahrendt | `docs/CAPELLA_SURFACE_TODO.md` |
| 2026-08 | One container drives one control plane, never both | Chris Ahrendt | `AGENTS.md` rule 2.1, `docs/CONTAINER_DEPLOYMENT.md` |

Entries before 2026-11-02 were gathered from commit messages, `AGENTS.md` and the design
documents on that date. [VERIFY] Chris to confirm the earlier dates and wording, and to
add older decisions that were taken in conversation and never written down.
