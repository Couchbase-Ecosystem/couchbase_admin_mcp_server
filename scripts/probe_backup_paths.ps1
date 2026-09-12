<#
  probe_backup_paths.ps1

  Settle the admin_backup_* 404s by MEASUREMENT, not by reading the docs.

  The Backup service API reference says every repository path carries a state
  segment -- /cluster/self/repository/<active|imported|archived>/... -- and that
  there is no /backups endpoint at all. handlers/backup.py has been changed on
  that basis. This script is the observation that has to agree before the change
  is called a fix.

  It probes each path BOTH ways:

    * direct to the Backup service on 8097, which is what the docs describe;
    * through ns_server's proxy on 8091 under /_p/backup, which is what the MCP
      server actually uses -- one port, one credential, and the reason the FTS
      tools needed /_p/fts for the same reason.

  A 401 or 403 is a PASS for this purpose: it proves the route matched and
  authentication rejected it, which is the distinction a 404 cannot make.
#>

[CmdletBinding()]
param(
    [string]$ClusterHost = 'localhost',
    [int]$ManagementPort = 8091,
    [int]$BackupPort = 8097,
    [string]$Username = $env:CB_USERNAME,
    [string]$Password = $env:CB_PASSWORD
)

$ErrorActionPreference = 'Continue'

if (-not $Username -or -not $Password) {
    Write-Host 'CB_USERNAME / CB_PASSWORD are not set. Run cbenv.bat, then a NEW window.' -ForegroundColor Yellow
    exit 1
}

$pair = "$Username`:$Password"
$auth = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
$headers = @{ Authorization = $auth }

function Probe {
    param([string]$Label, [string]$Url, [string]$Method = 'GET')
    try {
        $r = Invoke-WebRequest -Uri $Url -Headers $headers -Method $Method `
            -UseBasicParsing -TimeoutSec 15
        $code = $r.StatusCode
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if (-not $code) { $code = "ERR: $($_.Exception.Message)" }
    }

    # A 400 is a MATCH, not a mystery. Only a handler that ran can decide a
    # request is malformed -- an unrouted URL never gets that far. This mattered
    # on 2026-09-12: the shipped `/repository/<id>` path answered 400 rather
    # than 404, which is the service saying "<id> is not one of active,
    # imported, archived". That is the diagnosis confirming itself, and calling
    # it 'inconclusive' hid the best evidence in the run.
    $verdict = switch -Regex ("$code") {
        '^(200|201|202|204)$' { 'ROUTE MATCHED (answered)'          ; break }
        '^(400|422)$'         { 'ROUTE MATCHED (handler rejected)'  ; break }
        '^(401|403)$'         { 'ROUTE MATCHED (auth rejected)'     ; break }
        '^(405)$'             { 'ROUTE MATCHED (wrong method)'      ; break }
        '^404$'               { 'NO SUCH ROUTE'                     ; break }
        default               { 'inconclusive'                      }
    }
    $colour = if ($verdict -like 'ROUTE MATCHED*') { 'Green' }
              elseif ($verdict -eq 'NO SUCH ROUTE') { 'Red' }
              else { 'Yellow' }

    '{0,-46} {1,-6} {2}' -f $Label, $code, $verdict | Write-Host -ForegroundColor $colour
}

$direct = "http://${ClusterHost}:${BackupPort}/api/v1"
$proxy  = "http://${ClusterHost}:${ManagementPort}/_p/backup/api/v1"

# -- WHERE does the Backup service actually run? ------------------------------
#
# The first version of this script probed localhost and reported 404 for every
# path, old and new alike, which proves nothing about the paths -- only that
# nothing answered. Asking the cluster which nodes run which services, and on
# which ports, is one call and it is the difference between "the paths are
# wrong" and "you are talking to the wrong node".

Write-Host ''
Write-Host '== where does the Backup service run? ==' -ForegroundColor Cyan

$backupNodes = @()
try {
    $services = Invoke-RestMethod -Uri "http://${ClusterHost}:${ManagementPort}/pools/default/nodeServices" `
        -Headers $headers -TimeoutSec 15

    foreach ($node in $services.nodesExt) {
        $name = if ($node.hostname) { $node.hostname } else { "$ClusterHost (this node)" }
        $svc = $node.services
        $backupApi = $svc.backupAPI
        $backupPort = $svc.backup

        $has = $backupApi -or $backupPort
        $line = '  {0,-42} backupAPI={1,-6} backup={2}' -f $name, "$backupApi", "$backupPort"
        Write-Host $line -ForegroundColor ($(if ($has) { 'Green' } else { 'DarkGray' }))

        if ($has) {
            $backupNodes += [pscustomobject]@{
                Host = $(if ($node.hostname) { $node.hostname } else { $ClusterHost })
                Port = $(if ($backupApi) { $backupApi } else { $backupPort })
            }
        }
    }
} catch {
    Write-Host "  could not read nodeServices: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host '  Without this the rest is guesswork. Check CB_USERNAME/CB_PASSWORD and'
    Write-Host "  that ${ClusterHost}:${ManagementPort} is a cluster manager."
}

if ($backupNodes.Count -eq 0) {
    Write-Host ''
    Write-Host '  NO NODE IS RUNNING THE BACKUP SERVICE.' -ForegroundColor Red
    Write-Host '  Every path below will 404 for that reason and NOTHING here says'
    Write-Host '  anything about whether the paths are right. Add the service first:'
    Write-Host ''
    Write-Host '      .\scripts\add-local-services.ps1'
    Write-Host ''
    Write-Host '  then re-run this. Note that add-local-services enumerates EVERY'
    Write-Host '  non-Data service deliberately: POST /controller/rebalance with'
    Write-Host '  topology[] REMOVES any service you leave out.'
    Write-Host ''
} else {
    Write-Host ''
    Write-Host ("  backup service on: " + (($backupNodes | ForEach-Object { "$($_.Host):$($_.Port)" }) -join ', ')) -ForegroundColor Green
    # Probe the node that actually has it, not the one we happened to be pointed at.
    $chosen = $backupNodes[0]
    $direct = "http://$($chosen.Host):$($chosen.Port)/api/v1"
    Write-Host "  probing direct at $direct"
}

Write-Host ''
Write-Host '== is the Backup service answering? ==' -ForegroundColor Cyan
Probe 'cluster info (direct)'        "$direct/cluster/self"
Probe 'cluster info (proxy  8091)'   "$proxy/cluster/self"

Write-Host ''
Write-Host '== the SHIPPED paths (expected: NO SUCH ROUTE) ==' -ForegroundColor Cyan
Probe 'OLD repository_list'          "$proxy/cluster/self/repository"
Probe 'OLD repository_get'           "$proxy/cluster/self/repository/someRepo"
Probe 'OLD backup_list'              "$proxy/cluster/self/repository/someRepo/backups"

Write-Host ''
Write-Host '== the CORRECTED paths (expected: ROUTE MATCHED) ==' -ForegroundColor Cyan
Probe 'NEW repository_list (active)' "$proxy/cluster/self/repository/active"
Probe 'NEW repository_list (imported)' "$proxy/cluster/self/repository/imported"
Probe 'NEW repository_list (archived)' "$proxy/cluster/self/repository/archived"
Probe 'NEW plans'                    "$proxy/cluster/plan"

Write-Host ''
Write-Host '== what exists right now ==' -ForegroundColor Cyan
foreach ($state in @('active', 'imported', 'archived')) {
    try {
        $body = Invoke-RestMethod -Uri "$proxy/cluster/self/repository/$state" `
            -Headers $headers -TimeoutSec 15
        $names = @($body | ForEach-Object { $_.id })
        if ($names.Count -eq 0) { $names = @('(none)') }
        Write-Host ("  {0,-9} {1}" -f $state, ($names -join ', '))
    } catch {
        Write-Host ("  {0,-9} could not read: {1}" -f $state, $_.Exception.Message)
    }
}

Write-Host ''
Write-Host 'READ IT LIKE THIS:' -ForegroundColor Cyan
Write-Host '  Old red + new green  -> the missing state segment was the whole cause.'
Write-Host '  Both red             -> the service is not reachable on this path at all;'
Write-Host '                          check the direct 8097 line before blaming the paths.'
Write-Host '  Both green           -> my reading of the docs is wrong and the old paths'
Write-Host '                          were fine. Say so and I will re-open it.'
Write-Host ''
