<#
  probe_backup_repository.ps1

  Everything needed to CREATE a backup repository, read off the cluster instead
  of assumed.

  Creating one needs three things -- a plan name, an archive path the service can
  write, and a bucket -- and all three were about to be guessed:

    * the plan list endpoint answered 400 to /api/v1/cluster/plan, so the path
      this script's sibling tried is not right and the real one is unknown;
    * the archive path must be writable INSIDE the Couchbase container, which is
      not the same filesystem as the host running this script;
    * and there is no admin_backup_repository_create tool at all, so nothing in
      the MCP can make the repository the other four backup tools need.

  READ-ONLY. It sweeps candidate paths and prints what comes back. A 400 or 422
  is a MATCH -- only a handler that ran can call a request malformed -- so the
  bodies are where the answer is, and they are printed in full.
#>

[CmdletBinding()]
param(
    [string]$ClusterHost = '127.0.0.1',
    [int]$ManagementPort = 8091,
    [string]$Username = $env:CB_USERNAME,
    [string]$Password = $env:CB_PASSWORD
)

$ErrorActionPreference = 'Continue'

if (-not $Username -or -not $Password) {
    Write-Host 'CB_USERNAME / CB_PASSWORD are not set. Run cbenv.bat, then a NEW window.' -ForegroundColor Yellow
    exit 1
}

$headers = @{ Authorization = 'Basic ' + [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes("$Username`:$Password")) }

$backup = "http://${ClusterHost}:${ManagementPort}/_p/backup/api/v1"

function Try-Path {
    param([string]$Label, [string]$Url, [string]$Method = 'GET')
    try {
        $r = Invoke-WebRequest -Uri $Url -Headers $headers -Method $Method -UseBasicParsing -TimeoutSec 15
        $code = $r.StatusCode
        $body = $r.Content
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        $body = ''
        try {
            $reader = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
            $body = $reader.ReadToEnd()
        } catch { $body = $_.Exception.Message }
    }

    $routed = $code -and ($code -ne 404)
    $colour = if ($routed) { 'Green' } else { 'DarkGray' }
    Write-Host ('  {0,-40} {1,-5} {2}' -f $Label, $code, $(if ($routed) { 'ROUTE MATCHED' } else { 'no such route' })) -ForegroundColor $colour
    if ($routed -and $body) {
        $trimmed = $body.Trim()
        if ($trimmed.Length -gt 600) { $trimmed = $trimmed.Substring(0, 600) + ' ...' }
        Write-Host "        $trimmed" -ForegroundColor DarkGray
    }
    return [pscustomobject]@{ Label = $Label; Code = $code; Body = $body; Routed = $routed }
}

Write-Host ''
Write-Host '== 1. what the Backup service says about itself ==' -ForegroundColor Cyan
$self = Try-Path 'cluster/self' "$backup/cluster/self"

Write-Host ''
Write-Host '== 2. where are the PLANS? ==' -ForegroundColor Cyan
Write-Host '   A repository must name a plan. /cluster/plan answered 400, so the'
Write-Host '   path is wrong or it wants a parameter. Sweep, and print the bodies.'
$planCandidates = @(
    @{ L = 'cluster/plan';        U = "$backup/cluster/plan" },
    @{ L = 'cluster/plans';       U = "$backup/cluster/plans" },
    @{ L = 'plan';                U = "$backup/plan" },
    @{ L = 'plans';               U = "$backup/plans" },
    @{ L = 'cluster/self/plan';   U = "$backup/cluster/self/plan" },
    @{ L = 'cluster/self/plans';  U = "$backup/cluster/self/plans" }
)
$planHits = @()
foreach ($c in $planCandidates) {
    $r = Try-Path $c.L $c.U
    if ($r.Code -eq 200) { $planHits += $r }
}

Write-Host ''
Write-Host '== 3. the repository CREATE route ==' -ForegroundColor Cyan
Write-Host '   Probed with OPTIONS, which mutates nothing. A 405 or 200 confirms'
Write-Host '   the path; the BODY is settled separately by the create itself.'
Try-Path 'POST .../repository/active/<name>' "$backup/cluster/self/repository/active/probe-only-not-created" 'OPTIONS' | Out-Null

Write-Host ''
Write-Host '== 4. the ARCHIVE path ==' -ForegroundColor Cyan
Write-Host '   Must be writable by the Backup service INSIDE its container. The'
Write-Host '   host filesystem this script runs on is not that filesystem, so'
Write-Host '   this reports candidates rather than testing them -- the create'
Write-Host '   call is what proves one, and its error names the reason.'
Write-Host ''
Write-Host '   Conventional locations in the couchbase image:'
Write-Host '     /opt/couchbase/var/lib/couchbase/backup    (inside the data volume)'
Write-Host '     /backups                                   (only if mounted)'
Write-Host ''
Write-Host '   Confirm with:  docker exec <container> ls -ld /opt/couchbase/var/lib/couchbase'
Write-Host '   and create the directory there if it does not exist.'

Write-Host ''
Write-Host '== what this settles ==' -ForegroundColor Cyan
if ($planHits.Count -gt 0) {
    Write-Host ('  PLANS: ' + (($planHits | ForEach-Object { $_.Label }) -join ', ')) -ForegroundColor Green
    Write-Host '  Use a plan name from the body above when creating the repository.'
} else {
    Write-Host '  No plan endpoint answered 200. Read the 400/422 bodies above --' -ForegroundColor Yellow
    Write-Host '  they name what the handler wanted, which is the answer.'
}
Write-Host ''
Write-Host '  NOTE: there is no admin_backup_repository_create tool in this server.' -ForegroundColor Yellow
Write-Host '  The four shipped backup tools all need a repository that nothing in'
Write-Host '  the MCP can make. That is a gap, not a configuration problem.'
Write-Host ''
