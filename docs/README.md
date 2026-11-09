# Documentation index

Start here. The goal of this folder: a new engineer, or a new AI session with no
history, can understand, maintain and change any part of the server from the
repository alone. Nothing lives only in a chat.

Chris Ahrendt is the architect. He decides the architecture and every design
decision. AI assists under his direction: it drafts specs that he approves and
writes code from the specs he approved.

## The handover set

Read these in order if you are new.

| File | What it answers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | What the server is, what it talks to, how a call is authorized, where the trust boundaries sit |
| [MODULE_MAP.md](MODULE_MAP.md) | Which file does what, and who calls whom |
| [THREADING_MODEL.md](THREADING_MODEL.md) | Which code runs on the event loop, which runs on worker threads, and what is shared |
| [BUILD_GUIDE.md](BUILD_GUIDE.md) | How to set up, run, test, build a package and build the image |
| [spec.md](spec.md) | The numbered specification of today's behavior. Source file headers cite its section numbers |
| [questions.md](questions.md) | Every design question, with options, trade-offs, a recommendation and who decided. Headers cite its question numbers |
| [design-decisions.md](design-decisions.md) | The decision log: what was decided, when, and by whom |

## Other documents

| File | What it covers |
| --- | --- |
| [design/README.md](design/README.md) | One note per hard subsystem: what it decides, why it is built that way, what went wrong before, which tests hold it. Authorization, the Capella client and guardrails, the egress allowlist, fixtures, the transports |
| [FIXTURE_DESIGN.md](FIXTURE_DESIGN.md) | How data, indexes and functions are exported and re-imported |
| [CONTAINER_DEPLOYMENT.md](CONTAINER_DEPLOYMENT.md) | Container and Kubernetes deployment, one container per control plane |
| [CAPELLA_SURFACE_TODO.md](CAPELLA_SURFACE_TODO.md) | The Capella operations to add, in what order, and what is left out on purpose |
| [PROVIDER_SOURCE.md](PROVIDER_SOURCE.md) | The public Terraform provider code used as the first source for Capella API shapes |
| [OKTA_LAB.md](OKTA_LAB.md) | The identity provider lab used to test authorization over HTTP |
| [plans/documentation-standard-gap.md](plans/documentation-standard-gap.md) | How far the repository is from the documentation standard, and the order of work |

## Folder READMEs

Each top-level folder explains itself: [auth](../auth/README.md),
[deploy](../deploy/README.md), [gui](../gui/README.md),
[handlers](../handlers/README.md), [scripts](../scripts/README.md) and
[tests](../tests/README.md).

## Rules for changing these documents

- A change to behavior updates the comments and the documents in the same commit (D8).
- `tests/test_documentation_gate.py` fails the build when a handover file is
  missing, is not linked here, or names a file that no longer exists.
- Mark each decision honestly: the owner's decisions as his, proposals `[DESIGN]`
  until he approves, open items `[OPEN]` or `[VERIFY]`.
- Counts move. Never quote a count without a date beside it
  (`tests/test_docs_are_not_stale.py` checks this).
