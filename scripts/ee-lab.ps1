<#
.SYNOPSIS
    Stand up (or tear down) a disposable Enterprise Edition lab: one primary
    cluster plus any number of peers, all on one docker network, one password.

.DESCRIPTION
    WHY A LAB AND NOT A CLUSTER
    ===========================
    Verifying a new area of the surface keeps needing a cluster that did not
    exist five minutes ago, and several areas need TWO -- XDCR has no meaning
    with one cluster, and neither does a cross-cluster restore. Building those
    by hand went wrong the same way every time: mismatched passwords nobody
    wrote down, containers on different docker networks that could not resolve
    each other, and a second cluster given an external alternate address it did
    not need, which silently kills its Backup service.

    So this makes the pattern the default. One command, a known password, one
    network, and a teardown that leaves nothing behind.

    THE TWO ROLES ARE NOT THE SAME, AND THAT IS DELIBERATE
    -----------------------------------------------------
    PRIMARY  ports published 1:1, every service, no alternate address.
             The host's SDK and the MCP server connect to this one, and 1:1 is
             what lets the Backup service run -- see -PortOffset in
             start-ee-cluster.ps1 for the cbauth crash loop that an alternate
             address causes.

    PEER     ports published at an offset, -SkipAlternateAddress, fewer
             services. Nothing on the host dials a peer: it exists to be the
             far end of an XDCR reference or a restore, reached by CONTAINER
             NAME on the shared network. Publishing an offset port at all is
             only so THIS script can initialise it from the host.

    The primary needs host port 8091, so anything already holding it must be
    stopped first. This script says so rather than failing obscurely.

.PARAMETER Names
    Cluster/container names. The FIRST is the primary; the rest are peers.

.PARAMETER Down
    Remove every named container instead of creating them. The network is left
    alone -- it costs nothing and other things may be attached.

.EXAMPLE
    # the usual pair: one to drive, one to replicate into
    .\scripts\ee-lab.ps1 -Password 'reticuli' -Names cb-mcp-ee,cb-mcp-peer -LoadSample

.EXAMPLE
    .\scripts\ee-lab.ps1 -Names cb-mcp-ee,cb-mcp-peer -Down
#>
param(
    [string[]] $Names = @('cb-mcp-ee', 'cb-mcp-peer'),
    [string]   $Password = '',
    [string]   $Network = 'cb-mcp-net',
    [string]   $Image = 'couchbase/server:enterprise-8.0.1',
    [string]   $PrimaryServices = 'data,index,query,fts,eventing,backup',
    [string]   $PeerServices = 'data,index,query',
    [int]      $PeerPortOffset = 30000,
    [switch]   $LoadSample,
    [switch]   $Down
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

function Say([string] $T)  { Write-Host $T }
function Head([string] $T) { Write-Host "`n########## $T" -ForegroundColor Magenta }
function Ok([string] $T)   { Write-Host "   PASS  $T" -ForegroundColor Green }
function Die([string] $T)  { Write-Host "   FAIL  $T" -ForegroundColor Red; throw $T }

if ($Names.Count -lt 1) { Die "give at least one name" }

if ($Down) {
    Head "tearing down"
    foreach ($n in $Names) {
        & docker rm -f $n 2>$null | Out-Null
        Say "   removed $n (if it existed)"
    }
    Say ""
    Say "The network '$Network' was left in place; it costs nothing and other"
    Say "containers may be attached to it."
    return
}

if (-not $Password) { Die "-Password is required when creating a lab" }

# PORT 8091 BELONGS TO THE PRIMARY. Say which container is holding it rather
# than letting docker fail with a bind error that names no owner.
Head "port 8091"
$holder = docker ps --filter "publish=8091" --format '{{.Names}}'
if ($holder -and ($holder -split "`n") -notcontains $Names[0]) {
    Die ("8091 is published by: $holder. The primary needs it 1:1 -- that is " +
         "what lets its Backup service run. Stop that container first: " +
         "docker stop $holder")
}
Ok "free (or already the primary's)"

$primary = $Names[0]
$peers = @($Names | Select-Object -Skip 1)

Head "primary: $primary"
# A HASHTABLE, NOT AN ARRAY.
#
# Splatting an ARRAY passes its elements POSITIONALLY. The first version here
# was an array of '-Name', value, '-Network', value, ... which looks like named
# arguments and is not: start-ee-cluster.ps1 bound them by position, so
# -Password received the string '-Name' and refused it for being five
# characters long. The error named the right parameter and the wrong cause,
# which is the worst kind.
#
# A hashtable splat binds by NAME. Switches are passed as $true.
#
# NOT $args either: that is an automatic variable holding the enclosing scope's
# arguments, and assigning to it works right up until something reads it
# expecting the other meaning.
$primaryArgs = @{
    Name         = $primary
    Network      = $Network
    Password     = $Password
    Image        = $Image
    Services     = $PrimaryServices
    PortOffset   = 0
    WriteEnvFile = $true
}
if ($LoadSample) { $primaryArgs['LoadSample'] = $true }
& (Join-Path $here 'start-ee-cluster.ps1') @primaryArgs
if ($LASTEXITCODE) { Die "primary failed" }

$offset = $PeerPortOffset
foreach ($peer in $peers) {
    Head "peer: $peer  (internal only, host ports at +$offset)"
    & (Join-Path $here 'start-ee-cluster.ps1') `
        -Name $peer -Network $Network -Password $Password -Image $Image `
        -Services $PeerServices -PortOffset $offset -SkipAlternateAddress
    if ($LASTEXITCODE) { Die "peer $peer failed" }
    # Each peer needs its own block of host ports, or the second one collides
    # with the first on a bind that reads as "port already allocated" and says
    # nothing about which peer owns it.
    $offset += 1000
}

Head "the lab"
Say ""
Say "  primary   $primary            couchbase://127.0.0.1   (1:1 ports)"
foreach ($peer in $peers) {
    Say "  peer      $peer            reached as ${peer}:8091 ON '$Network'"
}
Say ""
Say "  Every cluster shares the password you passed and the network '$Network',"
Say "  so a peer is addressable from the primary by container name and needs no"
Say "  host route at all."
Say ""
Say "  Point the MCP server at the primary:"
Say "    `$env:CB_CONNECTION_STRING = 'couchbase://127.0.0.1'"
Say "    `$env:CB_USERNAME          = 'Administrator'"
Say "    `$env:CB_PASSWORD          = '<the password you passed>'"
Say "    `$env:CB_BUCKET            = 'travel-sample'"
Say "    Remove-Item Env:\CB_MGMT_PORT -ErrorAction SilentlyContinue"
Say ""
if ($peers.Count -ge 1) {
    Say "  XDCR fixture (the peer is the target, so create the bucket there first):"
    Say "    docker exec $($peers[0]) couchbase-cli bucket-create -c 127.0.0.1 ``"
    Say "        -u Administrator -p `$env:CB_PASSWORD --bucket mcptest-xdcr-target ``"
    Say "        --bucket-type couchbase --bucket-ramsize 256 --wait"
    Say "    uv run python scripts\ee_populate_test_cluster.py --perform ``"
    Say "        --xdcr-remote-host $($peers[0]):8091"
    Say ""
}
Say "  Tear the whole thing down:"
Say "    .\scripts\ee-lab.ps1 -Names $($Names -join ',') -Down"
Say ""
