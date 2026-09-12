<#
  run-mcp-evidence.ps1

  Capture a transcript of this server being driven by a real MCP client, the way
  mcp-crud-couchbase\run-capella-evidence2.ps1 captured one for the four KV pull
  requests.

  WHAT IT PRODUCES
  ----------------
      evidence-mcp-read-<date>.txt    every read tool a client could call
      evidence-mcp-write-<date>.txt   every write tool, gated and previewed

  Both are PowerShell transcripts, so they carry the commit, the posture and the
  timestamps alongside the output -- which is what makes them attachable to a
  ticket rather than just readable.

  WHAT THE ALLOWLIST DOES AND DOES NOT GATE
  -----------------------------------------
  Worth knowing before debugging a failure here, because it is the opposite of
  the CRUD repo's situation. The admin server's Capella tools talk to the v4
  control plane at cloudapi.cloud.couchbase.com over 443, authenticated with the
  organization API key. That is NOT gated by the per-cluster IP allowlist, and it
  is not on port 11207. So this run works with the VPN up, and a failure here is
  a credential or a server problem rather than a network one.

  The allowlist gates the DATA plane -- the SDK's 11207 connection, the Data API,
  and therefore the fixture tools and anything reaching a cluster directly. That
  side has an open question about the VPN and the NAT pool; CAPELLA-CONNECTIVITY.md
  separates what was measured from what was inferred. None of it applies here.
#>

[CmdletBinding()]
param(
    # The write phase starts a second server with CB_ADMIN_DRY_RUN=true and calls
    # every write tool twice -- once unconfirmed, which must be refused, once
    # confirmed, which must come back as a preview. Nothing is performed. Off by
    # default anyway: a run that only reads is the one to take first.
    [switch]$IncludeWrites,

    # Fail the run on upstream 4xx and on tools whose arguments could not be
    # resolved, not only on defects in the surface itself.
    [switch]$Strict,

    # uv by default, because this repository's dependencies are uv-managed and a
    # bare `python` on PATH has neither mcp nor couchbase -- which fails several
    # screens into a run that has already printed a banner.
    #
    # An ARRAY, because `-Python 'uv run python'` as a single string would be
    # looked up as one executable with a space in its name. Pass -Python python
    # for a plain interpreter, or -Python C:\path\to\venv\Scripts\python.exe.
    [string[]]$Python = @('uv', 'run', 'python')
)

$PythonExe = $Python[0]
$PythonArgs = @($Python | Select-Object -Skip 1)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ── Pre-flight ───────────────────────────────────────────────────────────────
#
# Cheap checks that fail in seconds, rather than a hundred tool calls that each
# time out. Each one names what to do about it.

Write-Host ''
Write-Host '== pre-flight ==' -ForegroundColor Cyan

if (-not $env:CAPELLA_API_KEY_SECRET) {
    Write-Host '  CAPELLA_API_KEY_SECRET is not set.' -ForegroundColor Yellow
    Write-Host '  Run C:\Work\Development\cbenv.bat, then open a NEW window -- it uses setx,'
    Write-Host '  so the current shell does not see it.'
    exit 1
}
if (-not $env:CAPELLA_ORG_ID) {
    Write-Host '  CAPELLA_ORG_ID is not set. Same fix as above.' -ForegroundColor Yellow
    exit 1
}
Write-Host '  credentials present.' -ForegroundColor Green

# The control plane, not the data plane. See the header: 443 to cloudapi, which
# the cluster allowlist does not gate.
try {
    $probe = Invoke-WebRequest -Uri 'https://cloudapi.cloud.couchbase.com/v4/organizations' `
        -Headers @{ Authorization = "Bearer $env:CAPELLA_API_KEY_SECRET" } `
        -UseBasicParsing -TimeoutSec 20
    Write-Host "  control plane answers ($($probe.StatusCode))." -ForegroundColor Green
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    Write-Host "  cloudapi.cloud.couchbase.com answered $status." -ForegroundColor Yellow
    if ($status -eq 401) {
        Write-Host '  401 is the API key, not the network. CAPELLA_API_KEY_SECRET must be the'
        Write-Host '  SECRET, not CAPELLA_ACCESS_KEY_ID -- they are different values and the'
        Write-Host '  hint Capella returns for this blames the IP allowlist, which is wrong.'
    } else {
        Write-Host "  $($_.Exception.Message)"
    }
    exit 1
}

$commit = (git rev-parse HEAD 2>$null)
if (-not $commit) { $commit = '(not a git checkout)' }

# ── Read phase ───────────────────────────────────────────────────────────────

$readOut = Join-Path $RepoRoot "evidence-mcp-read-$stamp.txt"
Write-Host ''
Write-Host '== reads ==' -ForegroundColor Cyan

Start-Transcript -Path $readOut -Force | Out-Null
Write-Host "repository : $RepoRoot"
Write-Host "commit     : $commit"
Write-Host "python     : $(& $PythonExe @PythonArgs -V 2>&1)"
Write-Host "org        : $env:CAPELLA_ORG_ID"
Write-Host "date       : $(Get-Date -Format o)"
Write-Host ''

$readArgs = $PythonArgs + @('scripts\verify_mcp_surface.py', '--verbose')
if ($Strict) { $readArgs += '--strict' }
& $PythonExe @readArgs
$readExit = $LASTEXITCODE

Stop-Transcript | Out-Null
Write-Host "  wrote $readOut (exit $readExit)" -ForegroundColor Green

# ── Write phase ──────────────────────────────────────────────────────────────

$writeExit = 0
if ($IncludeWrites) {
    $writeOut = Join-Path $RepoRoot "evidence-mcp-write-$stamp.txt"
    Write-Host ''
    Write-Host '== writes (previewed) ==' -ForegroundColor Cyan

    Start-Transcript -Path $writeOut -Force | Out-Null
    Write-Host "repository : $RepoRoot"
    Write-Host "commit     : $commit"
    Write-Host "date       : $(Get-Date -Format o)"
    Write-Host ''
    Write-Host 'Nothing in this phase is performed. The server is started with'
    Write-Host 'CB_ADMIN_DRY_RUN=true, which a caller cannot override, and the phase'
    Write-Host 'refuses to run at all if the server does not confirm that posture.'
    Write-Host ''

    $writeArgs = $PythonArgs + @('scripts\verify_mcp_surface.py', '--write-preview', '--verbose')
    if ($Strict) { $writeArgs += '--strict' }
    & $PythonExe @writeArgs
    $writeExit = $LASTEXITCODE

    Stop-Transcript | Out-Null
    Write-Host "  wrote $writeOut (exit $writeExit)" -ForegroundColor Green
}

Write-Host ''
if ($readExit -eq 0 -and $writeExit -eq 0) {
    Write-Host '  all phases clean.' -ForegroundColor Green
} else {
    Write-Host "  read exit $readExit, write exit $writeExit — read the transcript." -ForegroundColor Yellow
    Write-Host '  exit 1 is a defect in the surface (a tool that would not dispatch, or a'
    Write-Host '  write that was performed). exit 2 and 3 are only reachable with -Strict'
    Write-Host '  and mean upstream errors or unresolvable arguments.'
}
Write-Host ''
exit ([math]::Max($readExit, $writeExit))
