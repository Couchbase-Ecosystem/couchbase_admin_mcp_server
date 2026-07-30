# Publishing this repository

Everything that can be verified from inside the repository has been. What remains needs
credentials or GitHub org permissions, so it is listed here as exact commands rather than
prose. Each step says what it unblocks and how you know it worked.

Destination: **`github.com/Couchbase-Ecosystem/couchbase-admin-mcp-server`** (the URL already
in `pyproject.toml`).

---

## What has already been checked

Re-runnable at any time — this is the evidence, not a claim:

```bash
# No customer name anywhere in the working tree, or in any of the 28 commits
grep -rIl "isney" --exclude-dir=.git .                      # 0 files
git rev-list --all | while read -r r; do git grep -Il "isney" "$r"; done   # 0 hits

# No credential-shaped literals
grep -rInE "(api[_-]?key|secret|password|token)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9/+=_-]{16,}" \
  --exclude-dir=.git --exclude-dir=vendor .

# The suite, the linter, and the tests that prove the tests
python -m pytest -q -p no:randomly
python -m ruff check . && python -m ruff format --check .
python scripts/mutation_rounds_1_3.py && python scripts/mutation_round_4.py \
  && python scripts/mutation_round_5.py
```

Live organization and project UUIDs were removed from the working tree **and rewritten out of
all commits**, and the pre-rewrite objects were pruned, so the old SHAs no longer resolve.

---

## 1. Create the repository

`Couchbase-Ecosystem` is an organization, so this may need someone with org-level
permissions. Either:

```bash
gh repo create Couchbase-Ecosystem/couchbase-admin-mcp-server \
  --public \
  --description "MCP server for administering Couchbase Server and Capella"
```

or ask an org owner to create an empty repository with that exact name. **Do not** let the
creation wizard add a README, `.gitignore` or licence — all three already exist here and an
initial commit on the remote turns the first push into a merge.

---

## 2. Push

```bash
cd C:\Work\Development\CB-Admin-MCP
git remote add origin https://github.com/Couchbase-Ecosystem/couchbase-admin-mcp-server.git
git branch -M main          # the local branch is currently `master`
git push -u origin main
```

The branch rename is worth doing before the first push rather than after: renaming a default
branch that already has protection rules and open PRs against it is a chore.

**Before you push, decide on the two commit identities.** All 28 commits are yours, under two
addresses:

```
Chris Ahrendt <chris.ahrendt@couchbase.com>
Chris Ahrendt <celticht32@github.com>
```

Both are you, so this is cosmetic — but if you want a single identity in the public history,
it has to be done **before** the push, because rewriting after other people have cloned is
not something you can take back. `git filter-branch --env-filter` or `git-filter-repo`
--mailmap will do it.

---

## 3. Add `CB_CAPELLA_API_KEY` as a repository secret

This activates the `capella-paths` CI job, which is currently a no-op:

```yaml
if [ -z "$CB_CAPELLA_API_KEY" ]; then
  echo "CB_CAPELLA_API_KEY is not configured; skipping the live path check."
  exit 0
fi
```

That early exit is deliberate — a job that fails for everyone without credentials gets
disabled, which takes the check with it. But until the secret exists, nothing verifies that
the 61 Capella v4 paths are still real, and Capella's control plane is not frozen.

```bash
gh secret set CB_CAPELLA_API_KEY \
  --repo Couchbase-Ecosystem/couchbase-admin-mcp-server
# then paste the key SECRET at the prompt
```

Or: **Settings → Secrets and variables → Actions → New repository secret**, name
`CB_CAPELLA_API_KEY`.

### What the key needs, and what it must not have

Create it under **Organization Settings → API Keys** with:

- the **Organization Member** role, and
- **read** access to one project containing at least one provisioned cluster.

Nothing more. The CI job runs the verifier in its default mode: GETs are real, and every
write is probed with `OPTIONS` — a method the API does not implement — so a 405 confirms the
route exists without creating, modifying or deleting anything. It never sends POST, PUT,
PATCH or DELETE without `--write-probe`, which CI does not pass.

The value is the key **SECRET**, not the key **id**. That is the usual stumble, and it fails
as a 401 that looks like a permissions problem.

### Two caveats

- **A fork's pull request cannot see the secret.** GitHub withholds secrets from
  `pull_request` runs originating in forks, which is why the job is gated on
  `github.event_name == 'push' || workflow_dispatch'`. External contributions will not run
  this check; it runs on merge.
- **The key is a long-lived credential in CI.** Rotate it on the same schedule as any other
  CI secret, and scope it to a project you would not mind an attacker enumerating.

---

## 4. Branch protection

The suite is the thing standing between a contributor and a silently broken security control,
so it should be required rather than advisory:

```bash
gh api -X PUT \
  repos/Couchbase-Ecosystem/couchbase-admin-mcp-server/branches/main/protection \
  -F required_status_checks[strict]=true \
  -f 'required_status_checks[contexts][]=lint' \
  -f 'required_status_checks[contexts][]=test' \
  -f 'required_status_checks[contexts][]=mutation' \
  -f 'required_status_checks[contexts][]=package' \
  -F enforce_admins=false \
  -F required_pull_request_reviews[required_approving_review_count]=1 \
  -F restrictions=null
```

`capella-paths` is deliberately **not** required: it cannot pass on a fork PR, so requiring it
would block every external contribution.

`mutation` matters more than it sounds. It is the job that fails when a guard is deleted and
the suite stays green — the failure mode a normal test run cannot see.

---

## 5. After the first push

- [ ] All five CI jobs appear; `lint`, `test`, `mutation`, `package` pass
- [ ] `capella-paths` reports `MISSING=0` (not "skipping the live path check")
- [ ] `pip install git+https://github.com/Couchbase-Ecosystem/couchbase-admin-mcp-server`
      then `couchbase-admin-mcp-server --help` works from a clean virtualenv
- [ ] `docker build .` succeeds and `python -c "import server"` works inside the image
- [ ] The README's Quick start is followed **verbatim** by someone who has not seen this
      repository. `tests/test_documented_configurations_start.py` checks the examples start,
      but it cannot tell you whether the prose makes sense.

---

## One judgment call left

`CAPELLA_HANDOFF.md` (998 lines) is the full engineering review record: what was added, the
two real bugs found in the previous Capella handler, every finding from four adversarial
review rounds, and the live-verification results. It contains no customer references.

Publishing it is defensible and arguably useful — it is the provenance for why the paths are
what they are, and why several guards exist. But it is written as an internal handoff
("what still needs a human before this goes to ..."), and a public repository is not
obviously where it belongs.

Three reasonable options: publish as is, rewrite the framing as a `DESIGN.md`, or keep it out
of the public repo and hand it over separately. Your call — it is the only content decision
that has not been made.
