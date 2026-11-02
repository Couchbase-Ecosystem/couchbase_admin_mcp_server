# Questions

Every design question, with options, trade-offs and a recommendation. Source headers cite
the number, for example "Q-004". Status values: [DECIDED] with who and when, [OPEN] waiting
for Chris Ahrendt, [VERIFY] a fact still to be checked.

Documentation-standard questions Q1 to Q5 were asked and decided on 2026-11-02. They are
recorded in `docs/plans/documentation-standard-gap.md`, and summarized in
`docs/design-decisions.md`.

## Q-001 [OPEN]. Should the cached SDK cluster connection be created under a lock?

**Found 2026-11-02**, by reading `get_sdk_cluster` in `handlers/shared.py`. The cache
`_cluster` is a module global with no lock. Handlers run on worker threads, so two calls
that arrive together before the first connection exists can both build a cluster. The last
assignment wins and the other cluster is never closed. Not reproduced: this is read from
the code, not measured.

- (a) Add a `threading.Lock` around creation. Cost: a few lines and one more lock to
  document. Closes the leak.
- (b) Leave it, and document it. Cost: none now. A leaked connection on a first-use race.
- Recommendation: (a). It is small and the enterprise profile runs concurrent agents.

## Q-002 [OPEN]. Should the three import cycles be removed?

**Found 2026-11-02** (`docs/MODULE_MAP.md`): `logging_config` and `handlers.shared`,
`mcp_compat` and `dryrun`, `handlers.mcp_status` and `server`. They work because one
side imports inside a function.

- (a) Leave them. Document them (done). Cost: a future change can break start-up.
- (b) Move the shared pieces (`redact`, the dry-run helpers) into a small module that
  imports nothing from the repository. Cost: a refactor of three modules and their tests.
- Recommendation: (a) now. Revisit if a change trips one.

## Q-003 [OPEN]. What is the audit decision vocabulary, and where is it defined?

**Found 2026-11-02.** The docstring of `audit.build_record` lists nine decisions and calls
the vocabulary closed. The code emits fourteen (`docs/spec.md` S4). A SIEM rule written
from the docstring would miss five.

- (a) Define the vocabulary once as a constant in `audit.py`, make the docstring and the
  spec read from it, and add a test that every emitted decision is in it.
- (b) Only correct the docstring.
- Recommendation: (a). It makes "closed" true.

## Q-004 [OPEN]. Which public entry points besides tools need a tested example (D12)?

Decision Q5 gives one tested example per tool group (17 groups). The console endpoints, the
scripts and the `couchbase-admin-mcp-server` console script are also entry points.

- (a) Tools only, as decided. Scripts get a dry-run mode and a usage section in
  `scripts/README.md`.
- (b) Also add an example for each console endpoint.
- Recommendation: (a).

## Q-005 [OPEN]. Where does `CHANGELOG.md` sit inside the wheel?

The standard says the changelog ships in every package. In the container image it is at
`/app/CHANGELOG.md`. In the wheel it was added to the same `force-include` list as the
top-level modules, so it lands beside them in `site-packages`.

- (a) Keep it there. Consistent with the existing list. A stray file at the root of
  `site-packages`.
- (b) Put it in a folder named for this package, with a name Chris chooses. Cleaner, and a
  different path from the image.
- (c) Rely on the sdist and on the wheel's own metadata. Does not satisfy "every package".
- Recommendation: (b), once Chris names the folder.

## Q-006 [OPEN]. How should the lab password be supplied to the three lab scripts?

**Found 2026-11-02** by text search (and a fourth by the new gate check): `seed-ee-bucket.ps1`,
`probe-alternate-ports.ps1`, `probe_rest_paths.ps1` and `ee-lab.ps1` contain a lab password as a literal. It belongs to a throwaway local
container. The standard (D5) says no credentials in the repository, and a literal is also the
pattern that teaches the next script to hard-code a real one.

- (a) Read it from an environment variable (`CB_LAB_PASSWORD`), and fail with a clear message
  when it is unset. No default. Cost: one more thing to set before running a lab.
- (b) Generate a random password when the lab starts and write it to a git-ignored file the
  other scripts read. Cost: more code, and a state file.
- Recommendation: (a). It is the smallest change and nothing is stored.

## Q-007 [OPEN]. Should customer names and internal ticket numbers stay in the repository?

**Found 2026-11-02** by text search. A customer name appears in comments and documents
(`docs/FIXTURE_DESIGN.md`, `docs/OKTA_LAB.md`, `docs/ARCHITECTURE.md`,
`deploy/keycloak/README.md`, `handlers/capella/spec.py`), a personal email address in
`docs/FIXTURE_DESIGN.md`, and internal support ticket numbers (`CBSE-` ids) in
`handlers/capella/spec.py`, `handlers/capella/spec_pending.py` and elsewhere. D5 names
secrets, real hostnames and credentials. It does not name these, so this is a policy call.
The repository is public.

- (a) Keep them. They explain why a capability exists. Cost: a customer relationship and
  internal ticket ids are visible in a public repository.
- (b) Replace customer names with "a customer" and drop the ticket ids, keeping the reasoning.
  Cost: a pass over about 40 comments, and a reader loses the pointer to the ticket.
- (c) Keep ticket ids, remove customer names only.
- Recommendation: (b), or (c) if the ticket ids are useful to Couchbase staff and not sensitive.
  Not done until Chris decides.
