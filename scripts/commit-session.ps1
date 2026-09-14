<#
  commit-session.ps1

  Commit this session's work as a SEQUENCE of reviewable commits rather than one
  "fixes" blob.

  WHY THE SPLIT MATTERS
  ---------------------
  Three real server defects are in here, each of which would have reached a
  customer, mixed in with a much larger body of test-integrity work. In one
  commit the defects are invisible. Separated, someone reviewing "what actually
  changed about the server's behaviour" reads three small commits and stops.

  SAFE BY DEFAULT. Without -Execute it prints the plan and touches nothing.

      .\scripts\commit-session.ps1              # show the plan
      .\scripts\commit-session.ps1 -Execute     # make the commits
      .\scripts\commit-session.ps1 -Execute -Push

  It does NOT push unless asked, and it refuses to run on the default branch
  without -AllowMainBranch.
#>

[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$Push,
    [switch]$AllowMainBranch,

    # Unwind the commits this script made and remake them. Only touches commits
    # on THIS branch that are not on $BaseBranch, and only with --soft, so no
    # working-tree change is ever discarded. For repairing a bad message or a
    # bad grouping before anything is pushed.
    [switch]$Redo,
    [string]$BaseBranch = 'main',
    [string]$Branch = 'session/verification-and-backup-paths'
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

$attribution = @'

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Tgs9tim9N1Lncch4fHv7Mg
'@

# Each group: the paths, and the message. Order matters -- the defect fixes go
# first so they are the ones near the top of a `git log --oneline`.
$groups = @(
    @{
        Name  = 'Service path defects'
        # encryption.py belongs HERE and not with the Capella spec work: KMIP is
        # the same defect as the Search and Eventing prefixes -- a handler
        # pointed at a REST path the server does not serve, answering 404 on
        # every cluster, for as long as the tool has existed.
        # xdcr.py joins the same group for the same reason as encryption.py:
        # admin_xdcr_replications_list read /settings/replications/ -- the
        # global tuning document -- and so never listed a replication in its
        # life while answering 200 every time. A handler pointed at a path that
        # cannot serve it, exactly like the Search prefixes and KMIP.
        #
        # test_handler_contract.py comes too: its _body() assumed every handler
        # returns a JSON object, which is why fixing this tool broke it.
        Paths = @('handlers/search_admin.py', 'handlers/eventing.py',
                  'handlers/backup.py', 'handlers/encryption.py',
                  'handlers/xdcr.py',
                  'tests/test_service_proxy_paths.py',
                  'tests/test_backup_paths.py',
                  'tests/test_handler_contract.py')
        Message = @'
fix: service REST paths that 404 against every cluster

Three families of admin_* tools used paths the services do not serve.
Each was measured against a running cluster, not inferred.

SEARCH (9 tools): used bare /api/index and /api/cfg on the management
port. ns_server does not serve service APIs there without a proxy
prefix. Measured: :8091/api/index -> 404, :8091/_p/fts/api/index -> 200,
:8094/api/index -> 200.

EVENTING: /list -> 404. The neighbouring /stats, /status and
/functions/{name} all answered, which proved the base path was right and
localised it to the segment. Correct path is /list/functions.

BACKUP (5 tools): every repository path omitted the required state
segment, so /cluster/self/repository/<active|imported|archived>/... was
sent as /cluster/self/repository/... . The worst case was
admin_backup_repository_get, which put the repository id in the slot the
service reads as the STATE -- a well-formed URL that fails as "unknown
state" rather than "no such path", so it read as a broken service.
admin_backup_list used /{id}/backups, which does not exist at all;
individual backups are carried in the repository /info response.

CONFIRMED, once the Backup service was actually running. Every earlier
sweep 404'd for the mundane reason that no node had the service, which
proves nothing about a path:

    OLD  /cluster/self/repository          -> 404  no such route
    NEW  /cluster/self/repository/active   -> 200  answered

and the diagnosis for repository_get confirmed itself:

    OLD  /cluster/self/repository/<id>     -> 400, NOT 404

Only a handler that ran can call a request malformed, so a 400 there is
the service saying "<id> is not one of active, imported, archived" --
the id sitting in the state slot, exactly as described.

ALSO ADDS THE TWO MISSING TOOLS. All five backup tools address a
repository, and nothing in this server could create one -- so on any
cluster where nobody had made one by hand the whole family was correct
and useless, and NOTHING FAILED: each tool honestly reported an empty
list. That is the vacuous-pass problem one level up, in the product
rather than in the tests.

  admin_backup_plans_list       GET /plan. The reference says
                                /cluster/plan, which answers 400 --
                                /cluster/<name> takes a cluster name and
                                "self" is the only valid one, so the
                                service reads "plan" as a cluster.
  admin_backup_repository_create
                                POST /cluster/self/repository/active/<name>.
                                `archive` goes through the egress guard:
                                it can be an s3:// URI, which makes it a
                                destination cluster data is written to.

Verified end to end through an MCP client against a real cluster:
2205 documents loaded, backed up, and read back with complete:true and
mutations matching the load exactly.

The tests assert PROPERTIES by parsing handler source rather than
pinning literal strings, so a sixth tool added without a prefix fails.
'@
    },
    @{
        Name  = 'Windows portability'
        Paths = @('logging_config.py', 'tests/_platform.py',
                  'tests/test_logging_hardening.py', 'tests/test_logging_and_client.py',
                  'tests/test_round3_hardening.py', 'tests/test_tls.py',
                  'scripts/mutation_round_5.py')
        Message = @'
fix: server and console could not start on Windows

os.fchmod is POSIX-only, and AttributeError is not OSError -- so it flew
past the handler in _ensure_private_logfile whose whole job is to turn
"this path cannot be prepared" into a False return. A requested audit
sink therefore RAISED instead of reporting itself unusable, and since
server._enforce_profile() and gui._enforce_gui_posture() both treat an
unusable-but-requested sink as fatal, every process with
CB_ADMIN_AUDIT_FILE set died at startup on that platform.

_restrict_to_owner() sets the mode where modes exist and, where they do
not, leaves the file alone and says so once. It deliberately does NOT
call os.chmod on Windows: that toggles the read-only attribute and
removes read access from nobody, so calling it would make the control
look enforced while doing nothing. The symlink refusal and hard-link
warning around it are platform independent and unchanged.

This single defect accounted for 74 GUI test errors that looked
unrelated.

tests/_platform.py probes for symlink and file-mode support rather than
inferring it from os.name, so Developer Mode machines still run the six
tests that build a symlink as their fixture.
'@
    },
    @{
        Name  = 'One container, one control plane'
        # .gitattributes belongs with the other repo plumbing. It pins *.ps1 to
        # CRLF so PowerShell files stop showing as modified whenever git touches
        # them -- noise this very script has to see through -- and pins .env* to
        # LF, because a CRLF there ends up INSIDE the value and a correct
        # CB_PASSWORD then fails authentication.
        Paths = @('deployment.py', 'server.py', 'deploy',
                  'tests/test_one_container_one_surface.py', '.gitignore',
                  '.gitattributes', 'pyproject.toml', 'uv.lock',
                  'Dockerfile', '.dockerignore')
        Message = @'
feat: a deployment declares its control plane and must get it

detect_mode() INFERS, and the inference that matters resolves to 'both'
whenever a Capella API key and any non-Capella connection string are
both present. 'both' switches capability gating off. So a container
built for one control plane silently loads the tools for two, and the
trigger is inheriting an env file rather than any decision.

CB_ADMIN_REQUIRE_DEPLOYMENT declares the surface; _enforce_profile()
refuses to start when the configuration resolves to anything else, and
the message names the variable to remove. Unset, inference is unchanged.

deploy/ ships one artifact per surface: separate compose files (not two
services in one file, which share a network and come up together), and
separate Kubernetes namespaces with a NetworkPolicy that denies the
Capella workload egress to RFC1918 space. The containment is the absent
route, not the configuration.

Nothing here configures 'both'. The code path stays TESTED, because an
unexercised gating path is how gating regressions ship, but no artifact
selects it and no document demonstrates it.

tests/test_one_container_one_surface.py parses the shipped files, so a
CB_CONNECTION_STRING added to the Capella compose fails CI.

THE IMAGE DID NOT BUILD BEHIND A TLS PROXY. pip could not verify
pypi.org:

    certificate verify failed: self-signed certificate in certificate
    chain / No matching distribution found for mcp<2.0,>=1.10

which reads as a broken package index. It is not: python:3.12-slim
carries its own CA set and has never heard of the organization's root.
The Dockerfile now installs anything in deploy/ca/ into the trust store
and points PIP_CERT at it; the directory ships empty, so a network
without interception is unaffected. .dockerignore gains an exception,
because its *.crt rule silently stripped the certificates out of the
build context -- which would have failed with the IDENTICAL error and
read as "the fix does not work".

A preflight runs BEFORE pip and stops with a named cause, the export
command and a pointer to deploy/ca/README.md. Verified both ways: with
the certificate, --no-cache builds clean; without it, the build stops at
the preflight. Deliberately NOT --trusted-host, which removes
verification for every package the image installs.

Proven in a container, not only in CI: scripts/run-docker-verification.ps1
builds the image, completes TLS to cloudapi from inside it, reaches the
cluster BY CONTAINER NAME on the shared network, and watches the guard
refuse a posture that drifted to 'both' while an undeclared one still
starts.
'@
    },
    @{
        Name  = 'Tests that could pass while asserting nothing'
        Paths = @('tests/test_no_vacuous_coverage.py', 'tests/conftest.py',
                  'handlers/mcp_status.py',
                  'tests/test_capella.py', 'tests/test_capella_guardrail_hardening.py',
                  'tests/test_mcp_status.py', 'tests/test_verify_mcp_surface.py',
                  'tests/test_server_dispatch.py', 'tests/test_transport_edge.py',
                  'tests/test_dry_run.py', 'tests/test_gui_frontend.py',
                  # Belongs here rather than with the tooling: it is a test that
                  # fails when a future operation ships guarded on the wrong
                  # cluster, and it checks its own detector is not vacuous first.
                  'tests/test_guarded_write_target.py')
        Message = @'
test: close the gaps where a green run proved nothing

Several tests reported success while checking nothing, each found only
because the run before it got clean enough to notice:

* A registry cross-check asserted it had FAILED, and passed only because
  handlers.capella happened to be unimportable from the test's cwd. When
  it became importable the test started failing -- it had been an
  assertion about the wrong branch.
* Seven dispatch tests took next(iter(server._HANDLERS)) and got a tool
  the deployment gate had already removed, so they asserted against a
  refusal. Two of the seven passed purely on statement ordering under
  pytest-randomly.
* Five org-discovery tests exercised the "no organization supplied"
  branch, which an exported CB_CAPELLA_ORG_ID silently moved them off.
  conftest now strips ambient Capella credentials; a test that wants one
  sets it with monkeypatch, which still wins.
* test_gating_still_comes_first skipped itself whenever detect_mode()
  inferred 'capella' -- which it does on any machine with a Capella key
  and no connection string, i.e. exactly the machines where someone is
  most likely to be changing gating.

tests/test_no_vacuous_coverage.py makes the guard mandatory: it walks
every test module and fails, naming file, line and collection, when a
test parametrises over or loops over something nothing proves non-empty.
MAY_BE_EMPTY is the escape hatch and costs a companion test proving
emptiness is the success state.

It found 17 unguarded sites, including one in a file added in the same
session.
'@
    },
    @{
        Name  = 'Capella surface: a bootstrap trap and a retraction'
        Paths = @('handlers/capella/spec.py', 'handlers/capella/spec_pending.py',
                  'handlers/capella/__init__.py', 'handlers/capella/client.py')
        Message = @'
spec: cloud snapshot reads, and a retracted transcription

RETRACTED: four backupSchedule operations parked against
.../buckets/{bucket_id}/backupSchedule. A live sweep returned Go's
default "404 page not found" -- the body a mux emits when nothing
matched -- for that path and six other spellings. The verdict is sound
because the discriminator was proved first: a known-good route with a
bogus id answers with JSON ({"code": 5017, ...}), so JSON means the
route matched and plain text means no such route.

They are DELETED rather than left parked. A parked record means "written,
awaiting confirmation"; these were disconfirmed. Per-bucket backup
scheduling is not a gap in this server -- it is absent from the API.

The source was a rendered docs page. spec_pending.py already recorded
that the provider's generated client is the stronger source, and that 19
parked paths were wrong for exactly this reason. That warning was there
and I did not follow it.

ADDED: three cloud snapshot READ operations, each backed by an observed
200. The subsystem spec_pending.py flagged as unexamined is live, and
/restores is a listable collection -- restores are first-class objects
that can be tracked, which the managed-backup family has no counterpart
for. Only the reads: the write routes answered 405 to a GET, which
confirms the route and says nothing about method or body.

Their provenance is recorded in LIVE_VERIFIED_OUT_OF_BAND rather than
inheriting the LIVE_VERIFIED_ON banner, which names a different date and
a different tool.

FIXED: a deployment holding only an API key could not list its own
organizations. _handle_primitive resolved an organization id for EVERY
primitive, and capella_organizations_list's path is /v4/organizations --
no {organization_id} in it, none needed. So the first call anyone makes
on a new install was refused with:

    No Capella organization id available.
    hint: ... capella_organizations_list will show which organizations
          the API key can see.

The hint names the tool being refused. The only way through was to
already know the answer it would have given.

Exactly one of 100 operations is affected, which is why it survived:
every unit test supplies an organization id, because anyone writing one
already has it to hand. It took calling the tool from a container with
nothing but a key.

Also: capella_backup_create was PERFORMED for real (202, and the backup
appeared in the list), which settles body={} as an observation rather
than an omission. The 202 is recorded in LIVE_VERIFIED_OUT_OF_BAND and
NOT in LIVE_VERIFIED -- that register holds what the non-mutating probe
saw, and test_no_write_is_recorded_with_a_success_status caught the 202
when it was put there by hand. It fired on a deliberate, careful edit
that would still have corrupted the register's meaning, which is the
rule earning its keep.

Also settles the capella_backup_restore path dispute (two sources agree
on .../backups/{backup_id}/restore) and replaces a stale hard-coded
count in a comment with the property the test actually checks.
'@
    },
    @{
        Name  = 'Verification tooling'
        Paths = @('scripts', 'CLAUDE.md', 'CAPELLA-CONNECTIVITY.md', 'RUNBOOK.md', 'docs')
        Message = @'
chore: scripts and runbooks for verifying against real clusters

scripts/verify_mcp_surface.py drives the server over stdio with a real
MCP client and reports which tools a client can actually call -- startup,
gating, scope gate, hard ceiling, confirmation, dry-run interception,
argument marshalling, redaction and the audit record.

Supporting probes, each written because a wrong assumption cost a run:

  find-couchbase-clusters.ps1   several local clusters exist and are not
                                interchangeable; the backup service was
                                added to one and probed on another.
  probe_backup_paths.ps1        asks nodeServices WHERE the service runs
                                before probing, and says plainly when a
                                404 sweep proves nothing.
  capella_backup_readiness.py   read-only: plan, buckets, existing
                                backups, and a route sweep with a
                                matched-route control.
  load_test_data.py             ~2200 documents, so backup, stats and
                                index tools act on something real.
  probe_backup_repository.ps1   the plan endpoint and the create route,
                                swept and printed with their bodies -- a
                                400 is a MATCH, and its message is the
                                answer.
  backup_cycle_test.py          the whole cycle through a real MCP
                                client: plans -> create -> get -> run ->
                                info. Asserts the unconfirmed create is
                                REFUSED and the confirmed one is
                                previewed under CB_ADMIN_DRY_RUN before
                                --perform does it for real.

add-local-services.ps1: -Mgmt is now mandatory (its default pointed at
one specific cluster), credentials come from the environment rather than
being hard-coded, and it no longer ECHOES THE PASSWORD -- it is normally
run inside a transcript destined for a ticket.

CLAUDE.md records the rules this session established, including that a
write reporting success is not evidence it landed: read it back.
'@
    }
)

# -- Plan ---------------------------------------------------------------------

$branchNow = (git rev-parse --abbrev-ref HEAD).Trim()
Write-Host ''
Write-Host "current branch : $branchNow" -ForegroundColor Cyan

$isDefault = $branchNow -in @('main', 'master')
if ($isDefault -and -not $AllowMainBranch) {
    Write-Host "  Refusing to commit directly to $branchNow." -ForegroundColor Yellow
    Write-Host "  A branch will be created: $Branch"
    Write-Host '  Pass -AllowMainBranch to commit here instead.'
}

Write-Host ''
Write-Host '== working tree ==' -ForegroundColor Cyan
git status --short

# Every path git reports as changed must belong to a group, or it is silently
# left behind -- which looks like "committed" right up until someone clones the
# repository and the build fails on a file that only ever existed locally.
$claimed = @()
foreach ($g in $groups) { $claimed += $g.Paths }

$changed = @(git status --porcelain | ForEach-Object {
    $path = $_.Substring(3).Trim('"')
    # Renames read as "old -> new"; the new name is the one to account for.
    if ($path -match ' -> ') { $path = ($path -split ' -> ')[-1] }
    $path
})

$orphans = @($changed | Where-Object {
    $p = $_
    -not ($claimed | Where-Object { $p -eq $_ -or $p.StartsWith($_.TrimEnd('/') + '/') })
})

Write-Host ''
Write-Host '== plan ==' -ForegroundColor Cyan
$i = 0
foreach ($g in $groups) {
    $i++
    $present = @($g.Paths | Where-Object { Test-Path $_ })
    $first = ($g.Message -split "`n")[0]
    Write-Host ("  {0}. {1,-42} {2}" -f $i, $g.Name, $first)
    foreach ($p in $present) { Write-Host "       $p" -ForegroundColor DarkGray }
    $missing = @($g.Paths | Where-Object { -not (Test-Path $_) })
    foreach ($p in $missing) { Write-Host "       $p  (not present -- skipped)" -ForegroundColor Yellow }
}

if ($orphans.Count -gt 0) {
    Write-Host ''
    Write-Host '== NOT CLAIMED BY ANY GROUP ==' -ForegroundColor Yellow
    foreach ($o in $orphans) { Write-Host "    $o" -ForegroundColor Yellow }
    Write-Host ''
    Write-Host '  These would be left uncommitted. Either add them to a group in'
    Write-Host '  this script, or add them to .gitignore if they are run artifacts.'
    if ($Execute) {
        Write-Host '  REFUSING to commit a partial session.' -ForegroundColor Red
        exit 1
    }
}

if (-not $Execute) {
    Write-Host ''
    Write-Host '  Dry run. Nothing was committed. Re-run with -Execute.' -ForegroundColor Green
    Write-Host ''
    exit 0
}

# -- Execute ------------------------------------------------------------------

if ($isDefault -and -not $AllowMainBranch) {
    git checkout -b $Branch
    Write-Host "  created and switched to $Branch" -ForegroundColor Green
}

if ($Redo) {
    $base = (git merge-base HEAD $BaseBranch).Trim()
    $ahead = [int](git rev-list --count "$base..HEAD").Trim()
    if ($ahead -eq 0) {
        Write-Host '  -Redo: nothing on this branch to unwind.' -ForegroundColor DarkGray
    } else {
        # Refuse if any of them is already published. Rewriting pushed history
        # is a different decision and not one to take as a side effect.
        $pushed = (git branch -r --contains HEAD 2>$null)
        if ($pushed) {
            Write-Host '  -Redo REFUSED: these commits exist on a remote branch.' -ForegroundColor Red
            Write-Host '  Rewriting published history is a deliberate act; do it by hand.'
            exit 1
        }
        Write-Host ("  -Redo: unwinding {0} commit(s) back to {1} (--soft, nothing lost)" -f $ahead, $base.Substring(0,8)) -ForegroundColor Yellow
        git reset --soft $base
    }
}

foreach ($g in $groups) {
    $present = @($g.Paths | Where-Object { Test-Path $_ })
    if ($present.Count -eq 0) { continue }

    # `git add` first, because a group's files may be UNTRACKED and an untracked
    # file is invisible to `git diff HEAD`.
    git add -- $present

    # Does this group differ from HEAD? Scoped to the group's own paths, NOT the
    # whole index. `git diff --cached --quiet` with no paths asks "is anything at
    # all staged", which is a different question and answers yes for every group
    # once the index is dirty.
    git diff --cached --quiet HEAD -- $present
    if ($LASTEXITCODE -eq 0) {
        Write-Host ("  {0}: nothing changed, skipped" -f $g.Name) -ForegroundColor DarkGray
        continue
    }

    $message = $g.Message + $attribution
    $file = [IO.Path]::GetTempFileName()
    # UTF-8 WITHOUT a BOM. `Set-Content -Encoding utf8` writes one on PowerShell
    # 5.1, and git takes the message file literally -- so the BOM became the
    # first character of every commit SUBJECT. Invisible in most viewers,
    # breaks `git log --grep`, breaks conventional-commit tooling, and shows as
    # a stray glyph on GitHub.
    [IO.File]::WriteAllText($file, $message, (New-Object Text.UTF8Encoding $false))

    # --only, and the paths repeated: commit THESE PATHS and nothing else,
    # whatever else happens to be staged.
    #
    # Without it `git commit` takes the entire index. That is harmless on a
    # clean index -- the first run worked -- and wrong after `-Redo`, where
    # `reset --soft` leaves every file staged: the first group's commit
    # swallowed all six groups' changes and the rest reported "nothing changed".
    # Two commits instead of six, and the grouping that is the whole point of
    # this script silently lost.
    git commit --only --file $file -- $present | Out-Null
    Remove-Item $file -Force
    Write-Host ("  committed: {0}" -f $g.Name) -ForegroundColor Green
}

Write-Host ''
Write-Host '== what is still uncommitted ==' -ForegroundColor Cyan
git status --short
Write-Host ''
git log --oneline -8

# A BOM at the start of a subject is invisible in the log, so check the bytes.
$base = (git merge-base HEAD $BaseBranch).Trim()
$bad = @()
foreach ($sha in (git rev-list "$base..HEAD")) {
    $subject = (git log -1 --format=%s $sha)
    if ($subject.Length -gt 0 -and [int][char]$subject[0] -eq 0xFEFF) { $bad += $sha.Substring(0,8) }
}
$made = [int](git rev-list --count "$base..HEAD").Trim()
$expected = @($groups | Where-Object { @($_.Paths | Where-Object { Test-Path $_ }).Count -gt 0 }).Count
Write-Host ''
if ($made -lt $expected) {
    Write-Host ("  {0} commit(s) made, {1} groups had files. A group whose changes were" -f $made, $expected) -ForegroundColor Yellow
    Write-Host '  swept into an earlier commit is the failure mode here -- check the log'
    Write-Host '  above before pushing, and use -Redo -Execute to remake them.'
}

if ($bad.Count -gt 0) {
    Write-Host ("  {0} commit subject(s) start with a BOM: {1}" -f $bad.Count, ($bad -join ', ')) -ForegroundColor Red
    Write-Host '  Re-run with -Redo -Execute to remake them.'
} else {
    Write-Host '  commit subjects are clean (no BOM).' -ForegroundColor Green
}

if ($Push) {
    Write-Host ''
    git push -u origin (git rev-parse --abbrev-ref HEAD)
}
Write-Host ''
