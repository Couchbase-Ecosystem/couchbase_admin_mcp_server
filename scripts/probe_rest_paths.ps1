<#
.SYNOPSIS
  Find which REST path a service actually answers on, for the handlers whose
  current path 404s against a cluster that IS running the service.

.DESCRIPTION
  WHAT THIS IS FOR

  scripts\verify_mcp_surface.py found two handlers returning 404 from a local
  cluster running both services:

    admin_fts_index_list      GET /api/index                 -> 404 Not found.
    admin_fts_settings_get    GET /api/cfg                   -> 404 Not found.
    admin_eventing_list       GET /_p/event/api/v1/list      -> 404 page not found

  Both look like a path defect rather than a missing service, because the
  neighbouring calls work: admin_eventing_stats and admin_eventing_status answer
  on /_p/event/api/v1/stats and /status, and fts is running on this node.

  Every admin_* handler reaches the cluster through admin_request(), which goes to
  the MANAGEMENT port. Reaching a service's own API that way needs ns_server's
  proxy prefix -- /_p/event/ and /_p/backup/ are used elsewhere in this codebase,
  but search_admin.py uses a bare /api/index with no prefix at all.

  WHY A PROBE RATHER THAN A FIX

  The Search docs say FTS REST is served on port 8094 and do not document the
  8091 proxy form, so there are two plausible corrections and picking one from
  memory is how the last several hours went. This asks the cluster.

  Nothing here writes. Every request is a GET.

.EXAMPLE
  powershell -File scripts\probe_rest_paths.ps1
#>

[CmdletBinding()]
param(
    [string]$User = 'Administrator',
    [string]$Pass = 'mcptest-password',
    [string]$Mgmt = 'http://127.0.0.1:9091',
    [string]$Fts  = 'http://127.0.0.1:9094'
)

$ErrorActionPreference = 'Continue'

$cred = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${User}:${Pass}"))
$auth = @{ Authorization = "Basic $cred" }

function Probe {
    <#
      Reports the status code and the first of the body, because a 200 that
      returns an HTML page is not the endpoint you were looking for -- and that
      distinction is invisible from the status code alone.
    #>
    param([string]$Label, [string]$Url)
    try {
        $r = Invoke-WebRequest -Uri $Url -Headers $auth -UseBasicParsing -TimeoutSec 10
        $body = $r.Content
        if ($body.Length -gt 70) { $body = $body.Substring(0, 70) }
        $body = ($body -replace '\s+', ' ').Trim()
        $mark = if ($r.StatusCode -eq 200) { 'OK ' } else { '   ' }
        $colour = if ($r.StatusCode -eq 200) { 'Green' } else { 'Gray' }
        Write-Host ("  {0} {1,-46} {2}  {3}" -f $mark, $Label, $r.StatusCode, $body) -ForegroundColor $colour
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if (-not $code) { $code = 'ERR' }
        Write-Host ("      {0,-46} {1}  {2}" -f $Label, $code, $_.Exception.Message.Split("`n")[0]) -ForegroundColor DarkGray
    }
}

Write-Host ''
Write-Host '== Search (FTS) index listing ==' -ForegroundColor Cyan
Write-Host '   current handler: admin_request GET /api/index  (management port)'
Probe 'mgmt  /api/index            (as shipped)' "$Mgmt/api/index"
Probe 'mgmt  /_p/fts/api/index'                  "$Mgmt/_p/fts/api/index"
Probe 'fts   /api/index            (direct 8094)' "$Fts/api/index"
Probe 'mgmt  /_p/fts/api/cfg'                    "$Mgmt/_p/fts/api/cfg"
Probe 'fts   /api/cfg              (direct 8094)' "$Fts/api/cfg"

Write-Host ''
Write-Host '== Eventing function listing ==' -ForegroundColor Cyan
Write-Host '   current handler: admin_request GET /_p/event/api/v1/list'
Probe '/_p/event/api/v1/list       (as shipped)' "$Mgmt/_p/event/api/v1/list"
Probe '/_p/event/api/v1/list/functions'          "$Mgmt/_p/event/api/v1/list/functions"
Probe '/_p/event/api/v1/functions'               "$Mgmt/_p/event/api/v1/functions"
Probe '/_p/event/api/v1/status     (known good)' "$Mgmt/_p/event/api/v1/status"

Write-Host ''
Write-Host '== Backup repository listing ==' -ForegroundColor Cyan
Write-Host '   current handler: admin_request GET /_p/backup/api/v1/cluster/self/repository'
Probe '/_p/backup/api/v1/cluster/self/repository' "$Mgmt/_p/backup/api/v1/cluster/self/repository"
Probe '.../repository/active'                     "$Mgmt/_p/backup/api/v1/cluster/self/repository/active"
Probe '.../repository/imported'                   "$Mgmt/_p/backup/api/v1/cluster/self/repository/imported"
Probe '/_p/backup/api/v1/cluster/self/plan'       "$Mgmt/_p/backup/api/v1/cluster/self/plan"

Write-Host ''
Write-Host '  A line marked OK is the path the handler should use.' -ForegroundColor Cyan
Write-Host '  If several answer 200, prefer the one matching the style already used'
Write-Host '  elsewhere in the file (the /_p/ proxy form) so one rule covers them all.'
Write-Host ''
