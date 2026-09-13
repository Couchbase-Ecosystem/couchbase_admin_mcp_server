<#
.SYNOPSIS
    Start and initialise a self-managed Couchbase EE cluster in Docker, with
    credentials we choose, so the admin_* surface becomes testable.

.DESCRIPTION
    THE PROBLEM THIS SOLVES
    -----------------------
    Every admin_* tool answers HTTP 401 against the cluster this workstation has
    been pointed at, so no bucket resolves, so nothing bucket-shaped is testable.
    That single cause accounts for roughly 45 SKIPPED and all 54 UPSTREAM results
    in scripts/verify_mcp_surface.py. It is not a defect in any tool and no
    amount of work on the harness moves it: the credentials are simply not known.

    A cluster we start ourselves has credentials we set. That is the whole idea.

    WHAT deploy/docker-compose.ee.yml DOES AND DOES NOT DO
    -----------------------------------------------------
    It starts the MCP SERVER and attaches it to a network where a cluster
    already exists. It does NOT start Couchbase, and it still requires
    CB_USERNAME and CB_PASSWORD. So it cannot solve a credential problem -- it
    consumes the answer. This script produces the answer, and the cluster it
    starts is a valid COUCHBASE_NETWORK / CB_CONNECTION_STRING target for that
    compose file afterwards.

    ALTERNATE ADDRESSES, AND WHY
    ----------------------------
    A containerised node advertises its INTERNAL address in the cluster map. An
    SDK client on the host follows that map and tries to reach an address that
    does not exist out here, which presents as a hang rather than an error.
    Couchbase's answer is the external alternate address, and this script
    configures one:

        PUT /node/controller/setupAlternateAddresses/external -d hostname=127.0.0.1

    Host ports are container port + -PortOffset (30000 by default), because
    8091 was already allocated by the cluster this workstation was using. The
    per-service ports in the alternate map are therefore required, and the
    script LEARNS THE KEY NAMES from the node's own /pools/default/nodeServices
    rather than naming them -- those key names are not enumerated in the
    documentation, and guessing them is the failure mode this project keeps
    paying for.

    Clients then use  couchbase://127.0.0.1:41210?network=external  , the same
    shape this workstation already uses for its other cluster.

    TWO THINGS MEASURED RATHER THAN ASSUMED
    ---------------------------------------
    * Which alternate-address port keys this build accepts. Thirteen store;
      backupAPI and backupAPIHTTPS answer 200 and store nothing. See
      scripts/probe-alternate-ports.ps1, which established it one key at a time.
    * That /sampleBuckets/install is SYNCHRONOUS -- it withholds its response
      until the sample has loaded. Two earlier runs of this script looked hung
      at that step and were not.

    THE PASSWORD IS NEVER PRINTED
    ----------------------------
    An earlier script in this repository echoed a live password into a
    transcript destined for support tickets. This one takes the password as a
    parameter, uses it, and prints only the NAMES of the variables to set. The
    optional -WriteEnvFile writes deploy/.env.ee, which .gitignore already
    excludes via the `.env.*` rule.

.EXAMPLE
    .\scripts\start-ee-cluster.ps1 -Password 'choose-a-strong-one'

.EXAMPLE
    .\scripts\start-ee-cluster.ps1 -Password '...' -LoadSample -WriteEnvFile
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateLength(6, 128)]
    [string] $Password,

    [string] $Username  = 'Administrator',
    [string] $Name      = 'cb-mcp-ee',
    [string] $Network   = 'cb-mcp-net',
    [string] $Image     = 'couchbase/server:enterprise-7.6.6',

    # Services. `backup` and `eventing` are included on purpose: without them
    # the admin_backup_* and admin_eventing_* families answer 404 for the
    # mundane reason that no node runs the service, which proves nothing about
    # those tools. That exact confusion cost hours earlier in this project.
    [string] $Services  = 'data,index,query,fts,eventing,backup',

    [int] $DataRam      = 1024,
    [int] $IndexRam     = 512,
    [int] $FtsRam       = 256,
    [int] $EventingRam  = 256,

    # Host ports are CONTAINER port + this. 8091 was already allocated by the
    # cluster this workstation was using, and a fresh cluster must not fight it
    # for a port. 0 means publish 1:1.
    [int] $PortOffset = 30000,

    [switch] $LoadSample,
    [switch] $WriteEnvFile,
    [int] $ReadyTimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'

# The management port AS SEEN FROM THE HOST. Everything this script does from
# the outside goes here; everything it does with docker exec uses 8091, because
# inside the container the ports are unshifted.
$MgmtHost = 8091 + $PortOffset
$KvHost   = 11210 + $PortOffset

function Say([string] $Text) { Write-Host $Text }
function Step([string] $Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }
function Ok([string] $Text)  { Write-Host "   PASS  $Text" -ForegroundColor Green }
function Die([string] $Text) { Write-Host "   FAIL  $Text" -ForegroundColor Red; throw $Text }

function ConvertTo-FormBody([hashtable] $Fields) {
    $parts = foreach ($key in ($Fields.Keys | Sort-Object)) {
        "{0}={1}" -f [Uri]::EscapeDataString($key),
                     [Uri]::EscapeDataString([string] $Fields[$key])
    }
    return ($parts -join '&')
}

function Read-HttpError($ErrorRecord) {
    <#
      PowerShell reports a 400 as "The remote server returned an error: (400)
      Bad Request." and discards the body. ns_server puts the ACTUAL REASON in
      that body -- which parameter it did not recognise, or what value it
      rejected -- so throwing away the body turns a precise answer into a dead
      end. This is the same mistake as reporting a 422 without its message.
    #>
    try {
        $response = $ErrorRecord.Exception.Response
        if ($null -ne $response) {
            $stream = $response.GetResponseStream()
            $stream.Position = 0
            $reader = New-Object System.IO.StreamReader($stream)
            $text = $reader.ReadToEnd()
            $reader.Close()
            if ($text) { return $text.Trim() }
        }
    } catch { }
    return '(no response body)'
}

Step "docker is available"
docker version --format '{{.Server.Version}}' | Out-Null
if ($LASTEXITCODE -ne 0) { Die "docker is not responding. Is Docker Desktop running?" }
Ok "docker responds"

Step "network $Network"
$existing = docker network ls --filter "name=^$Network$" --format '{{.Name}}'
if ($existing -ne $Network) {
    docker network create $Network | Out-Null
    Ok "created"
} else {
    Ok "already present"
}

Step "container $Name"
$running = docker ps -a --filter "name=^$Name$" --format '{{.Names}}'
if ($running -eq $Name) {
    Ok "already exists — leaving it alone (docker rm -f $Name to start over)"
} else {
    $ports = @()
    foreach ($c in @(8091,8092,8093,8094,8095,8096,8097,9102,11207,11210,
                     18091,18092,18093,18094,18095,18096,18097)) {
        $ports += '-p'
        $ports += "$($c + $PortOffset):$c"
    }
    $runArgs = @('run','-d','--name',$Name,'--network',$Network) + $ports + @($Image)
    & docker @runArgs | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Die "docker run failed. A port is probably already bound — check with: netstat -ano | findstr $MgmtHost"
    }
    Ok "started from $Image"
}

Step "waiting for ns_server"
$deadline = (Get-Date).AddSeconds($ReadyTimeoutSeconds)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$MgmtHost/pools" -UseBasicParsing -TimeoutSec 5
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch {
        # 401 also means it is up: an initialised node demands credentials.
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 401) {
            $ready = $true; break
        }
    }
    Start-Sleep -Seconds 3
}
if (-not $ready) { Die "ns_server did not answer on $MgmtHost within $ReadyTimeoutSeconds s. docker logs $Name" }
Ok "ns_server answers on $MgmtHost"

Step "cluster-init"
# THE GRANULAR SEQUENCE, NOT cluster-init AND NOT /clusterInit.
#
# MEASURED 2026-09-13, on couchbase/server:enterprise-8.0.1 and 7.6.6:
#
#   couchbase-cli cluster-init --services data,index,query,fts,eventing,backup
#     -> "SUCCESS: Cluster initialized"
#     -> backupAPI absent from /pools/default/nodeServices
#     -> admin_backup_* answer 404 "Service backup not running on this node"
#
#   POST /node/controller/setupServices services=kv,index,n1ql,fts,eventing,backup
#     -> 200
#   POST /pools/default            (quotas)
#   POST /settings/indexes         storageMode=plasma
#   POST /settings/web             username / password / port=SAME
#     -> backupAPI : 8097 present
#
# The CLI reports success for a service it does not enable. /clusterInit is what
# the CLI drives underneath, so it is NOT assumed to be free of the same
# behaviour -- this script uses the four calls that were actually observed to
# work rather than the one that might.
#
# Why it matters beyond this fixture: a 404 from admin_backup_* reads as a
# broken tool, and it cost this project hours once already. The fix is to check
# nodeServices first. The step below does that and says so.
#
# REST SPELLINGS: kv / n1ql / cbas, not data / query / analytics.
$restServices = ($Services -split ',' | ForEach-Object {
    switch ($_.Trim()) {
        'data'      { 'kv' }
        'query'     { 'n1ql' }
        'analytics' { 'cbas' }
        default     { $_.Trim() }
    }
}) -join ','

function Init-Post([string] $Path, [hashtable] $Fields, [string] $Label) {
    try {
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$MgmtHost$Path" `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body (ConvertTo-FormBody $Fields) | Out-Null
        Ok $Label
        return $true
    } catch {
        $detail = Read-HttpError $_
        if ($detail -match 'already initialized|Cluster is already|unknown pool' -or
            $_.Exception.Response.StatusCode.value__ -eq 401) {
            Ok "$Label — already done"
            return $true
        }
        Die "$Label failed: $detail"
    }
}

Say "   services (REST spelling): $restServices"
Init-Post '/node/controller/setupServices' @{ services = $restServices } `
          'services assigned' | Out-Null
Init-Post '/pools/default' @{
    memoryQuota         = $DataRam
    indexMemoryQuota    = $IndexRam
    ftsMemoryQuota      = $FtsRam
    eventingMemoryQuota = $EventingRam
} 'memory quotas set' | Out-Null
Init-Post '/settings/indexes' @{ storageMode = 'plasma' } 'index storage mode set' | Out-Null
Init-Post '/settings/web' @{
    username = $Username
    password = $Password
    port     = 'SAME'
} 'administrator credentials set' | Out-Null

Step "which services actually came up"
# The whole reason for the paragraph above. Ask, and say so either way.
try {
    $svc = (Invoke-RestMethod -Uri "http://127.0.0.1:$MgmtHost/pools/default/nodeServices" `
        -Headers @{ Authorization = "Basic " + [Convert]::ToBase64String(
            [Text.Encoding]::ASCII.GetBytes("$($Username):$($Password)")) }
        ).nodesExt[0].services.PSObject.Properties.Name
    Say "   $($svc -join ' ')"
    if ($svc -contains 'backupAPI') {
        Ok "the Backup service is running — admin_backup_* are reachable"
    } elseif ($Services -match 'backup') {
        Say "   NOTE: 'backup' was requested and backupAPI is NOT present."
        Say "         admin_backup_repository_list and admin_backup_plans_list will"
        Say "         answer 404 'Service backup not running on this node'. That is"
        Say "         the ENVIRONMENT, not those tools -- they were verified against"
        Say "         a live Backup service on 2026-09-12."
    }
} catch {
    Say "   could not read nodeServices: $(Read-HttpError $_)"
}

Step "external alternate address"
# WHY THIS READS THE SERVER RATHER THAN NAMING PORTS ITSELF
# ---------------------------------------------------------
# The alternate-address object is keyed by service port NAMES (mgmt, kv, kvSSL,
# capi, n1ql, indexHttp, ...). Those names are not enumerated in any Couchbase
# documentation page I could find, and inventing them is exactly the kind of
# guess that has already cost this project three wrong request bodies.
#
# So: ask the node what it calls its own ports, and echo the same keys back with
# the published host port. Every key is then valid BY CONSTRUCTION, because the
# server produced it.
#
# One PUT carrying everything -- the docs are explicit that each PUT deletes all
# previous alternate settings, so an incremental call silently drops the rest.
$pair = "$($Username):$($Password)"
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))

# WAIT FOR THE SERVICES TO REGISTER FIRST.
#
# cluster-init returns as soon as the cluster is CONFIGURED, not once every
# service is listening. Reading nodeServices immediately after it gave a node
# advertising only mgmt, kv and capi -- so the alternate map was built from a
# half-started node and silently omitted n1ql, fts, indexHttp and eventing.
#
# Nothing fails at that point. The PUT succeeds, the read-back looks plausible,
# and the damage only shows up later as SDK query calls from the host dialling
# container ports. A map that is WRONG BY OMISSION is the worst shape this can
# take, because every check still passes.
#
# So: wait until the node advertises a port for each service that was asked for,
# and say plainly which ones never arrived rather than mapping what happens to
# be there at the moment we looked.
$expectedByService = @{
    'data'     = 'kv'
    'index'    = 'indexHttp'
    'query'    = 'n1ql'
    'fts'      = 'fts'
    'eventing' = 'eventingAdminPort'
}
$wanted = @('mgmt')
foreach ($svc in ($Services -split ',')) {
    $svc = $svc.Trim()
    if ($expectedByService.ContainsKey($svc)) { $wanted += $expectedByService[$svc] }
}

$ns = $null
$deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
    try {
        $ns = Invoke-RestMethod -Uri "http://127.0.0.1:$MgmtHost/pools/default/nodeServices" `
            -Headers @{ Authorization = "Basic $auth" }
        $have = @($ns.nodesExt[0].services.PSObject.Properties.Name)
        $missing = @($wanted | Where-Object { $have -notcontains $_ })
        if ($missing.Count -eq 0) { break }
    } catch {
        $ns = $null
    }
    Start-Sleep -Seconds 3
}
if ($null -eq $ns) { Die "could not read nodeServices" }
$have = @($ns.nodesExt[0].services.PSObject.Properties.Name)
$missing = @($wanted | Where-Object { $have -notcontains $_ })
if ($missing.Count -gt 0) {
    Say "   note: these never registered a port and will NOT be in the map:"
    Say "         $($missing -join ', ')"
    Say "         Re-run scripts/probe-alternate-ports.ps1 once they are up."
} else {
    Ok "every requested service has registered a port"
}
if (-not $ns.nodesExt -or $ns.nodesExt.Count -lt 1) {
    Die "nodeServices returned no nodesExt — cannot learn this node's port names"
}

# MEASURED, not assumed. scripts/probe-alternate-ports.ps1 sent each key on its
# own and read the map back, which separates three outcomes an all-at-once PUT
# collapses into one failure:
#
#   ACCEPTED  every key whose SERVICE IS RUNNING
#   IGNORED   200, and nothing stored, for a service that is not
#
# CORRECTED 2026-09-13. backupAPI and backupAPIHTTPS were first recorded as
# "ignored on 7.6.6", which was the wrong conclusion from one observation: the
# Backup service was not running on that node. Once it was, both keys stored
# normally. The endpoint silently drops port keys for absent services -- a 200
# that writes nothing, conditional on cluster state, which is the hardest shape
# of failure to notice and the reason this script reads the map back.
#
# nodeServices also reports internal ports (projector, indexStream*, ftsGRPC,
# the eventing debug port). Sending those is what made the first full PUT fail,
# so the set below is an allowlist rather than "everything the node mentions".
$ALTERNATE_KEYS = @(
    'mgmt','mgmtSSL','capi','capiSSL','n1ql','n1qlSSL',
    'fts','ftsSSL','indexHttp','eventingAdminPort','eventingSSL','kv','kvSSL'
)
$published = @(8091,8092,8093,8094,8095,8096,8097,9102,11207,11210,
               18091,18092,18093,18094,18095,18096,18097)
$body = @{ hostname = '127.0.0.1' }
$mapped = @()
foreach ($prop in $ns.nodesExt[0].services.PSObject.Properties) {
    $containerPort = [int] $prop.Value
    if (($published -contains $containerPort) -and ($ALTERNATE_KEYS -contains $prop.Name)) {
        $body[$prop.Name] = $containerPort + $PortOffset
        $mapped += "$($prop.Name)=$($containerPort + $PortOffset)"
    }
}
if ($body.Count -le 1) {
    Die "no published port matched anything in nodeServices — the map would be hostname-only and clients would use container ports"
}

# BUILD THE FORM BODY EXPLICITLY.
#
# Invoke-RestMethod given a hashtable decides the encoding for itself, and on
# PUT that decision is not the one ns_server expects: the first attempt sent a
# body carrying hostname and the node answered "hostname should be specified" --
# it never saw the field. Encoding it by hand with an explicit content type
# removes the guesswork; the wire format is then a property of this script
# rather than of the PowerShell version running it.
Say "   sending: hostname=127.0.0.1  $($mapped -join '  ')"
$altUri = "http://127.0.0.1:$MgmtHost/node/controller/setupAlternateAddresses/external"
try {
    Invoke-RestMethod -Method Put -Uri $altUri `
        -Headers @{ Authorization = "Basic $auth" } `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body (ConvertTo-FormBody $body) | Out-Null
    Ok "external 127.0.0.1 with $($mapped.Count) port(s)"
} catch {
    $detail = Read-HttpError $_

    # NOT every key in `services` is a key this endpoint accepts. nodeServices
    # reports internal ports too (projector, indexStreamInit, ftsGRPC, the
    # eventing debug port), and the endpoint rejects what it does not manage.
    # The body names them, so narrow to what it complained about rather than
    # guessing a shorter list -- a second guess is not better than the first.
    Say "   the node refused the full map. Its reason:"
    Say "     $detail"

    # `hostname` is NEVER a narrowing candidate. The first version of this
    # matched the word 'hostname' inside the message "hostname should be
    # specified" and removed the one field that must always be present --
    # turning the node's complaint that a field was MISSING into a retry that
    # guaranteed it stayed missing. A rule that reads the error as a list of
    # things to delete must exclude the things that are mandatory.
    $rejected = [regex]::Matches($detail, '[A-Za-z][A-Za-z0-9]*') |
                ForEach-Object { $_.Value } |
                Where-Object { $body.ContainsKey($_) -and $_ -ne 'hostname' } |
                Select-Object -Unique
    if ($rejected.Count -eq 0) {
        Die "the reason above names no parameter this script sent, so there is nothing to narrow. Fix by hand, or re-run with -PortOffset 0 if 8091 is free."
    }

    Say "   retrying without: $($rejected -join ', ')"
    foreach ($key in $rejected) { $body.Remove($key) | Out-Null }
    if ($body.Count -le 1) {
        Die "every port key was rejected; a hostname-only map would leave clients dialling container ports."
    }
    try {
        Invoke-RestMethod -Method Put -Uri $altUri `
            -Headers @{ Authorization = "Basic $auth" } `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body (ConvertTo-FormBody $body) | Out-Null
        Ok "external 127.0.0.1 with $($body.Count - 1) port(s), after dropping $($rejected.Count)"
    } catch {
        Die "still refused: $(Read-HttpError $_)"
    }
}

# Prove it rather than trust the 200: read the map back and show what a client
# on this host will actually be told to dial.
try {
    $check = Invoke-RestMethod -Uri "http://127.0.0.1:$MgmtHost/pools/default/nodeServices" `
        -Headers @{ Authorization = "Basic $auth" }
    $ext = $check.nodesExt[0].alternateAddresses.external
    if ($null -eq $ext) { Die "nodeServices reports no external alternate address after the PUT" }
    $shown = $ext.ports.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }
    Ok "read back: hostname=$($ext.hostname)  $($shown -join '  ')"
} catch {
    Die "could not read the alternate address back: $(Read-HttpError $_)"
}

if ($LoadSample) {
    Step "travel-sample"
    try {
        # /sampleBuckets LISTS what is available; /sampleBuckets/install is the
        # one that loads. The first answers 404 to a POST, which reads like the
        # endpoint being absent rather than like the wrong verb on the wrong
        # path. Taken from this repository's own admin_sample_buckets_install
        # rather than from memory -- it is the authority here, and it was
        # settled against a live cluster.
        # /sampleBuckets/install IS ASYNCHRONOUS -- 202 with a taskId:
        #
        #   {"tasks":[{"taskId":"f17000b3-...","sample":"travel-sample",
        #              "bucket":"travel-sample"}]}
        #
        # CORRECTED 2026-09-13. This comment previously asserted the endpoint was
        # SYNCHRONOUS, generalised from runs where it appeared to hang. It does
        # not block; those runs were hitting a cluster that had not finished
        # starting, which the node says plainly when asked at the right moment:
        # "System services have not completed startup. Please try again shortly."
        #
        # Two different causes with one symptom, and I called it the wrong one.
        # The short timeout below is kept anyway -- it costs nothing and it
        # covers a slow answer -- but the reason is no longer a claim about the
        # endpoint's shape.
        try {
            Invoke-RestMethod -Method Post `
                -Uri "http://127.0.0.1:$MgmtHost/sampleBuckets/install" `
                -Headers @{ Authorization = "Basic $auth" } `
                -ContentType 'application/json' `
                -TimeoutSec 10 `
                -Body '["travel-sample"]' | Out-Null
            Ok "install returned"
        } catch [System.Net.WebException] {
            if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::Timeout) {
                Ok "install accepted (the endpoint blocks until loaded; not waiting on it)"
            } else { throw }
        }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'already') { Ok "already present" } else { Say "   note: $msg" }
    }
}

if ($LoadSample) {
    Step "waiting for travel-sample"
    # A 200 on the install request means ACCEPTED, not loaded. Reporting the
    # cluster as ready here would hand the next step a bucket that is not there
    # yet, and the surface check would record it as "no bucket on this cluster".
    $deadline = (Get-Date).AddSeconds(300)
    $seen = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $bs = Invoke-RestMethod -Uri "http://127.0.0.1:$MgmtHost/pools/default/buckets" `
                -Headers @{ Authorization = "Basic $auth" }
            if ($bs.name -contains 'travel-sample') { $seen = $true; break }
        } catch { }
        Start-Sleep -Seconds 5
    }
    if ($seen) {
        Ok "travel-sample is present"
    } else {
        Say "   note: travel-sample has not appeared yet. It may still be loading;"
        Say "         re-check with GET /pools/default/buckets before the surface run."
    }
}

Step "proving the credentials"
# The exact call that was answering 401. Anything else is a weaker claim.
try {
    $buckets = Invoke-RestMethod -Uri "http://127.0.0.1:$MgmtHost/pools/default/buckets" `
        -Headers @{ Authorization = "Basic $auth" }
    Ok "GET /pools/default/buckets answered with $($buckets.Count) bucket(s)"
} catch {
    Die "still refused: $(Read-HttpError $_)"
}

if ($WriteEnvFile) {
    Step "deploy/.env.ee"
    $repo = Split-Path -Parent $PSScriptRoot
    $envPath = Join-Path $repo 'deploy\.env.ee'
    $lines = @(
        "COUCHBASE_NETWORK=$Network",
        "CB_CONNECTION_STRING=couchbase://$Name",
        "CB_USERNAME=$Username",
        "CB_PASSWORD=$Password",
        "CB_ADMIN_PROFILE=enterprise",
        "CB_ADMIN_READ_ONLY_MODE=true",
        "CB_ADMIN_TRANSPORT=http",
        "MCP_EE_PORT=8000",
        "CORP_CA_FILE=",
        "CORP_CA_IN_CONTAINER=/etc/ssl/certs/corp-ca.pem"
    )
    # No BOM: this file is read by docker compose, not by PowerShell.
    [IO.File]::WriteAllText($envPath, ($lines -join "`n") + "`n",
                            (New-Object Text.UTF8Encoding $false))
    Ok "written (it holds the password; .gitignore excludes it via .env.*)"
}

Say ""
Say "======================================================================"
Say " The cluster is up. Set these in the shell that runs the MCP server."
Say " The password is the one you passed; it is deliberately not echoed."
Say "======================================================================"
Say ""
Say "  `$env:CB_CONNECTION_STRING = 'couchbase://127.0.0.1:${KvHost}?network=external'"
Say "  `$env:CB_ADMIN_HOST        = 'http://127.0.0.1:${MgmtHost}'"
Say "  `$env:CB_USERNAME          = '$Username'"
Say "  `$env:CB_PASSWORD          = '<the password you passed>'"
Say "  `$env:CB_BUCKET            = 'travel-sample'"
Say ""
Say " Then:"
Say "  uv run python scripts\verify_mcp_surface.py --write-preview --json ``"
Say "      --capella-cluster vn1kiibitcyvwrw --out surface-skips.txt"
Say ""
Say " For the container form (closes the 'compose never brought up' gap):"
Say "  docker compose --env-file deploy/.env.ee -f deploy/docker-compose.ee.yml up -d"
Say ""
