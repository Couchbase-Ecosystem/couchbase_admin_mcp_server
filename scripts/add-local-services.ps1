<#
.SYNOPSIS
  Add the Eventing and Backup services to the existing local cb-mcptest cluster,
  so the tools that depend on them can be verified instead of skipped.

.DESCRIPTION
  HOW THIS WORKS

  POST /controller/rebalance accepts topology[<service>] parameters naming which
  nodes should run each non-Data service. Listing a node adds the service to it;
  omitting a node removes it. The rebalance runs as part of the same call.

      curl -u user:pass -X POST host:8091/controller/rebalance \
        -d knownNodes="ns_1@a,ns_1@b" \
        -d topology[index]="ns_1@a" \
        -d topology[fts]="ns_1@b"

  An earlier version of this script added a THIRD CONTAINER, on the assumption
  that a node's services are fixed at initialisation and can only be changed by
  removing and re-adding the node. That is wrong, it was asserted without being
  checked, and it would have cost a gigabyte of Docker memory to work around a
  restriction that does not exist. Recorded here rather than quietly deleted.

  https://docs.couchbase.com/server/current/rest-api/rest-set-up-services-existing-nodes.html

  WHAT THIS UNBLOCKS

  Thirteen tools answered 404 because nothing was listening, not because they
  were wrong: admin_eventing_* (8) and admin_backup_* (5).

  WHAT IT CANNOT DO

  The Data service (kv) is not settable this way -- topology[] covers non-Data
  services only. kv placement still requires add/remove and rebalance.

  ANALYTICS IS OFF BY DEFAULT

  No tool in this server uses it, and cbas carries a 1024 MB minimum quota -- the
  largest memory cost available here for the least return. -IncludeAnalytics if
  that changes.

.NOTES
  No new container. Allow 2-5 minutes for the rebalance.
  Safe to re-run: a service already present is left where it is.
#>

[CmdletBinding()]
param(
    [switch]$IncludeAnalytics,

    # From the environment, not hard-coded. The previous defaults were the
    # cb-mcptest cluster's credentials and ITS port, so pointing this at any
    # other cluster failed on authentication -- and the 9091 default is how the
    # Backup service came to be added to one cluster and probed on another,
    # producing a wall of 404s that looked like a broken path fix.
    [string]$User = $(if ($env:CB_USERNAME) { $env:CB_USERNAME } else { 'Administrator' }),
    [string]$Pass = $env:CB_PASSWORD,

    # No default. Name the cluster deliberately -- run
    # scripts\find-couchbase-clusters.ps1 first if you are not certain which is
    # which. This performs a REBALANCE; it is not a call to make against a
    # cluster you did not mean.
    [Parameter(Mandatory = $true)]
    [string]$Mgmt
)

if (-not $Pass) {
    Write-Host 'CB_PASSWORD is not set and -Pass was not given.' -ForegroundColor Yellow
    Write-Host 'Run cbenv.bat, then a NEW window, or pass -Pass explicitly.'
    exit 1
}

$ErrorActionPreference = 'Stop'

$cred = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${User}:${Pass}"))
$auth = @{ Authorization = "Basic $cred" }

function Send-CB {
    # Form-encoded with the content type stated. PowerShell 5.1 does not
    # form-encode a hashtable body on every method, and the server's complaint
    # ("hostname should be specified") names the wrong problem.
    param([string]$Path, [string[]]$Pairs, [string]$Method = 'POST')
    Invoke-RestMethod -Uri "$Mgmt$Path" -Method $Method -Headers $auth `
        -ContentType 'application/x-www-form-urlencoded' -Body ($Pairs -join '&')
}
function Get-CB { param([string]$Path) Invoke-RestMethod -Uri "$Mgmt$Path" -Headers $auth }

function Wait-For {
    param([string]$Label, [scriptblock]$Test, [int]$Seconds = 900)
    Write-Host "[wait] $Label " -NoNewline
    for ($i = 0; $i -lt $Seconds; $i++) {
        try { if (& $Test) { Write-Host ' ok' -ForegroundColor Green; return } } catch { }
        Start-Sleep -Seconds 1
        if ($i % 5 -eq 0) { Write-Host '.' -NoNewline }
    }
    throw "timed out waiting for: $Label"
}

$wanted = @('eventing', 'backup')
if ($IncludeAnalytics) { $wanted += 'cbas' }

Write-Host ''
Write-Host "  adding to the existing cluster: $($wanted -join ', ')" -ForegroundColor Cyan
Write-Host ''

try { $pool = Get-CB '/pools/default' } catch {
    throw "cannot reach $Mgmt - is cb-mcptest running? Build it with mcp-crud-couchbase\setup-test-cluster-2node.ps1"
}

Write-Host ''
Write-Host 'THIS PERFORMS A REBALANCE.' -ForegroundColor Yellow
Write-Host ("  cluster : {0}" -f $Mgmt)
Write-Host ("  buckets : {0}" -f (@((Get-CB '/pools/default/buckets') | ForEach-Object { $_.name }) -join ', '))
Write-Host '  On a single-node cluster no data moves, but the services being added'
Write-Host '  start and the cluster is briefly busy. On a multi-node cluster data'
Write-Host '  DOES move. Ctrl-C now if this is not the cluster you meant.'
Write-Host ''
Start-Sleep -Seconds 5

Write-Host '[before]' -ForegroundColor Cyan
foreach ($n in $pool.nodes) {
    Write-Host ("    {0,-30} {1}" -f $n.otpNode, ($n.services -join ','))
}

# The node that will gain the services: the one already running the most of
# them, which keeps index/query/search co-located and avoids a data movement.
$host1 = ($pool.nodes | Sort-Object { $_.services.Count } -Descending | Select-Object -First 1).otpNode
Write-Host ""
Write-Host "[target] $host1"

# -- Quota first --------------------------------------------------------------
# A service cannot be placed without a quota for it, and the rebalance rejects
# the whole topology with a message that does not mention memory.
# Only set a quota that is not already set. The previous version sent
# eventingMemoryQuota=256 unconditionally -- on a cluster where Eventing is
# ALREADY RUNNING that is a live service being resized to whatever number this
# script happens to carry, on a host with six buckets competing for memory. The
# quota exists to let a service be PLACED; re-stating it for a service that is
# already placed changes a running system for no reason.
#
# The Backup service takes no memory quota at all, so adding backup alone
# needs nothing here.
$quotas = @()

if ($wanted -contains 'eventing') {
    $currentEventing = [int]$pool.eventingMemoryQuota
    if ($currentEventing -gt 0) {
        Write-Host "[quota] eventingMemoryQuota already $currentEventing MB - left alone"
    } else {
        $quotas += 'eventingMemoryQuota=256'
    }
}

if ($IncludeAnalytics) {
    $currentCbas = [int]$pool.cbasMemoryQuota
    if ($currentCbas -gt 0) {
        Write-Host "[quota] cbasMemoryQuota already $currentCbas MB - left alone"
    } else {
        $quotas += 'cbasMemoryQuota=1024'
    }
}

if ($quotas.Count -gt 0) {
    Write-Host "[quota] setting $($quotas -join ' ')"
    Send-CB '/pools/default' $quotas | Out-Null
} else {
    Write-Host '[quota] nothing to set'
}

# -- Build the full topology --------------------------------------------------
#
# EVERY non-Data service must be named, not just the new ones. A service left out
# of the topology is REMOVED -- that is how the API expresses removal -- so
# omitting index or fts here would silently strip them from the cluster.
$services = @('index', 'n1ql', 'fts', 'eventing', 'backup', 'cbas')
$topology = @()
foreach ($svc in $services) {
    $current = @($pool.nodes | Where-Object { $_.services -contains $svc } |
                 ForEach-Object { $_.otpNode })
    if ($wanted -contains $svc -and $current -notcontains $host1) { $current += $host1 }
    $value = ($current | Select-Object -Unique) -join ','

    # A service that is on NO node and is not wanted: omit the parameter rather
    # than sending an empty one. Removal is expressed by omission, so both spell
    # "not present" -- but whether the API ACCEPTS topology[cbas]= with an empty
    # value has never been observed, and a rejected parameter fails the whole
    # rebalance with a message that will not mention the service it choked on.
    # Sending nothing is the behaviour we have actually seen work.
    if (-not $value) {
        Write-Host ("    topology[{0,-9}] = (on no node -- parameter omitted)" -f $svc)
        continue
    }

    $topology += "topology[$svc]=$([uri]::EscapeDataString($value))"
    Write-Host ("    topology[{0,-9}] = {1}" -f $svc, $value)
}

$known = ($pool.nodes | ForEach-Object { $_.otpNode }) -join ','
Write-Host ""
Write-Host "[rebalance] knownNodes=$known"
Send-CB '/controller/rebalance' (@("knownNodes=$([uri]::EscapeDataString($known))") + $topology) | Out-Null

Wait-For 'rebalance complete' { (Get-CB '/pools/default/rebalanceProgress').status -eq 'none' }

# -- Verify, rather than announce ---------------------------------------------
$final = Get-CB '/pools/default'
Write-Host ''
Write-Host '[after]' -ForegroundColor Cyan
$present = @()
foreach ($n in $final.nodes) {
    Write-Host ("    {0,-30} {1}" -f $n.otpNode, ($n.services -join ','))
    $present += $n.services
}

$absent = $wanted | Where-Object { $present -notcontains $_ }
Write-Host ''
if ($absent) {
    Write-Host "  MISSING after rebalance: $($absent -join ', ')" -ForegroundColor Red
    Write-Host '  The rebalance completed but the service is not running. Either the'
    Write-Host '  service is not settable through topology[] on this version, or the'
    Write-Host '  node rejected it. Check:'
    Write-Host "    (Invoke-RestMethod -Uri '$Mgmt/pools/default' -Headers `$auth).nodes.services"
    exit 1
}
Write-Host "  present: $($wanted -join ', ')" -ForegroundColor Green

Write-Host ''
Write-Host '  Point the admin MCP at THIS cluster:' -ForegroundColor Cyan
# The password is NOT echoed. This script is normally run inside a PowerShell
# transcript so its output can be attached to a ticket, and a credential printed
# for convenience is a credential in a ticket. The port and connection string
# were also hard-coded to the cb-mcptest container, which is wrong for every
# other cluster -- they are derived from $Mgmt now.
$mgmtPort = ([uri]$Mgmt).Port
Write-Host "    `$env:CB_MGMT_PORT         = '$mgmtPort'"
Write-Host "    `$env:CB_USERNAME          = '$User'"
Write-Host "    `$env:CB_PASSWORD          = '<the password you passed; not echoed>'"
Write-Host  '    # connection string: run scripts\find-couchbase-clusters.ps1, which'
Write-Host  '    # reads the KV port and alternate-address state off this cluster.'
Write-Host ''
