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

    # Host ports are CONTAINER port + this. 0 means publish 1:1.
    #
    # DEFAULT CHANGED TO 0 ON 2026-09-13, AND THE REASON IS THE BACKUP SERVICE.
    #
    # A non-zero offset forces an external alternate address, because the host
    # cannot otherwise reach a remapped port. The Backup service then reads
    # /pools/default/nodeServices, PICKS THE EXTERNAL ALTERNATE ADDRESS as its
    # own cluster endpoint, and asks cbauth for credentials for that hostport --
    # which cbauth does not know, because cbauth knows the node by its real
    # identity. Measured from the service's own log:
    #
    #   (REST) Dispatching request to '.../pools/default/nodeServices'   (200)
    #   (REST) Failed to get credentials due to error: Unable to find given
    #          hostport in cbauth database: `127.0.0.1:38091'
    #   (Main) Failed to run node  err="could not create REST client: ..."
    #
    # It then EXITS AND IS RESTARTED, on a ~7.5 second cycle, forever. Nothing
    # listens on 8097, so every admin_backup_* call through /_p/backup answers
    # 500 "Unexpected server error" and every backup tool looks broken.
    #
    # So the offset is no longer the default. Pass one only when 8091 is
    # genuinely taken, and accept that the Backup service will not run.
    [int] $PortOffset = 0,

    # Bind-mount a HOST directory as the Backup service's archive, so backups
    # land on a real drive instead of inside a container that gets rm -f'd.
    #
    # Empty means the archive stays inside the container at the path below, and
    # a `docker rm` destroys every backup in it. That is fine for verifying the
    # tools and wrong for anything you want to keep.
    #
    # WINDOWS CAVEAT, stated because it will bite silently: a Docker Desktop
    # bind mount does not honour chown. The archive step below tries anyway and
    # reports what happened rather than assuming; if the Backup service still
    # answers "Location not accessible by all nodes", the mount is the reason
    # and a named volume plus scripts/fetch-ee-backup.ps1 is the way round it.
    [string] $BackupArchiveHost = '',

    # A CLUSTER NOTHING ON THE HOST EVER DIALS.
    #
    # An external alternate address exists so a client on the HOST can reach
    # remapped ports. A second cluster that serves only as an XDCR target is
    # reached by CONTAINER NAME on the docker network, by the first cluster --
    # the host's SDK never connects to it. Setting an alternate address for it
    # would buy nothing and cost the Backup service, which dies when one is
    # present (see -PortOffset).
    #
    # So: publish an offset port so THIS SCRIPT can initialise the node from the
    # host, and skip the alternate address and the node rename, both of which
    # exist only to disambiguate a map that will not be written.
    [switch] $SkipAlternateAddress,

    [switch] $LoadSample,
    [switch] $WriteEnvFile,
    [int] $ReadyTimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'

# The management port AS SEEN FROM THE HOST. Everything this script does from
# the outside goes here; everything it does with docker exec uses 8091, because
# inside the container the ports are unshifted.
#: Where the Backup service keeps repositories INSIDE the container. Bind-mount
#: a host directory here with -BackupArchiveHost to keep the backups.
$ArchivePath = '/opt/couchbase/var/lib/couchbase/backup-archive'
$MgmtHost = 8091 + $PortOffset
#: The node's own name. Must be an FQDN (ns_server refuses short names) and must
#: resolve on the container network, which "<container>.<network>" does.
$NodeFqdn = "$Name.$Network"
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
# EXISTS AND RUNNING ARE DIFFERENT QUESTIONS, and asking only the first one
# cost 180 seconds on 2026-09-13. A `docker run` that fails on a port bind still
# leaves the container BEHIND in state "created" -- it exists, it has never
# started, and nothing will ever answer on its ports. This branch saw it, said
# "leaving it alone", and the next step waited out its full timeout against a
# container that was not running. `docker ps -a` lists those; `docker ps` does
# not, so ask for the state rather than for the name.
$state = (docker ps -a --filter "name=^$Name$" --format '{{.State}}') -join ''
if ($state -eq 'running') {
    Ok "already running — leaving it alone (docker rm -f $Name to start over)"
} elseif ($state) {
    Say "   container exists in state '$state', not running — starting it"
    & docker start $Name | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Die "could not start the existing container. It was probably created by a docker run that failed on a port bind, and its port mapping is fixed at creation time: docker rm -f $Name and re-run."
    }
    Ok "started"
} else {
    $ports = @()
    foreach ($c in @(8091,8092,8093,8094,8095,8096,8097,9102,11207,11210,
                     18091,18092,18093,18094,18095,18096,18097)) {
        $ports += '-p'
        $ports += "$($c + $PortOffset):$c"
    }
    $mounts = @()
    if ($BackupArchiveHost) {
        if (-not (Test-Path $BackupArchiveHost)) {
            New-Item -ItemType Directory -Path $BackupArchiveHost -Force | Out-Null
        }
        # Resolve to a full path: docker rejects a relative one, and the error
        # it gives names the string it was handed, not the reason.
        $full = (Resolve-Path $BackupArchiveHost).Path
        $mounts = @('-v', "${full}:$ArchivePath")
        Say "   backup archive bind-mounted from $full"
    }
    $runArgs = @('run','-d','--name',$Name,'--network',$Network) + $ports + $mounts + @($Image)
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

if ($PortOffset -ne 0 -and -not $SkipAlternateAddress) {
Step "name the node after its container"
# WHY THIS MUST HAPPEN BEFORE ANYTHING ELSE
#
# A node initialised through 127.0.0.1 registers ITSELF as 127.0.0.1. Set an
# external alternate address of 127.0.0.1 on top of that and the two maps become
# indistinguishable: any client whose bootstrap host is 127.0.0.1 -- which
# includes every service running INSIDE the container -- matches the external
# entry and follows it to a port that exists only on the host.
#
# Measured twice before it was understood:
#
#   cbimport  -> "dial tcp 127.0.0.1:38091: connect: connection refused"
#   Backup    -> "Unable to find given hostport in cbauth database:
#                 `127.0.0.1:38091'" while creating a repository
#
# Both were read as client problems and worked around. They were the same
# problem, and it is this one.
#
# CORRECTED 2026-09-13, AFTER THE RENAME SHIPPED AND DID NOT FIX IT.
#
# The paragraph below claimed the rename fixes the Backup failure "at the root".
# It does not. With the node renamed AND an external alternate address set, the
# Backup service still chose 127.0.0.1:38091 out of nodeServices and still died
# on `Unable to find given hostport in cbauth database'. The rename fixes
# cbimport, which bootstraps from a host the alternate map can shadow; it does
# nothing for a service that reads the alternate map directly. The only fix for
# Backup is to not set an external alternate address at all -- see -PortOffset.
#
# Naming the node after its container fixes it at the root: internal clients
# resolve the container on the docker network, host clients use the 127.0.0.1
# alternate map, and neither can be mistaken for the other. Rename FIRST --
# it is only permitted while the node is uninitialised.
#
# IT MUST BE AN FQDN. `cb-mcp-ee` alone is refused:
#
#     Requested hostname "cb-mcp-ee" is not allowed: Short names are not
#     allowed. Please use a Fully Qualified Domain Name.
#
# `<container>.<network>` satisfies that AND is what Docker's embedded DNS
# already resolves on a user-defined network, so the name is both acceptable to
# ns_server and actually reachable -- which a made-up domain would not be.
try {
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$MgmtHost/node/controller/rename" `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body (ConvertTo-FormBody @{ hostname = $NodeFqdn }) | Out-Null
    Ok "node hostname is now '$NodeFqdn'"
} catch {
    $detail = Read-HttpError $_
    if ($detail -match 'already|initialized') {
        Ok "node already named — continuing"
    } else {
        # Not fatal on its own: the cluster still works for host clients. But
        # say plainly what will break, rather than letting it surface later as
        # an unrelated-looking 500 from the Backup service.
        Say "   NOTE: could not rename the node: $detail"
        Say "         In-container services (Backup, cbimport) may follow the"
        Say "         external alternate address and fail to authenticate."
    }
}

} else {
    Step "node name"
    # TWO REASONS TO SKIP THE RENAME, and they are not the same reason.
    # Printing the 1:1 explanation for a cluster whose ports are offset was a
    # false statement in the transcript -- small, but this is the project that
    # keeps finding bugs by reading its own output.
    if ($SkipAlternateAddress) {
        Say "   left as 127.0.0.1 - no alternate address will be written, so"
        Say "   there is no second map for the node's own name to be"
        Say "   distinguished from. Host ports are offset by $PortOffset, which"
        Say "   only this script uses."
    } else {
        Say "   left as 127.0.0.1 - ports are published 1:1, so no alternate"
        Say "   address is needed and cbauth, the host and in-container services"
        Say "   all agree on one identity. This is what lets Backup run."
    }
}

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

# Basic auth for every authenticated call below. DEFINED HERE, not further
# down: it used to be declared inside the alternate-address step, which is now
# conditional, so anything above that step referencing $auth got an empty
# string and a 401.
$pair = "$($Username):$($Password)"
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))

Step "waiting for every requested service to register"
# THIS WAITS. IT USED TO ONLY LOOK, AND ONLY INSIDE THE ALTERNATE-ADDRESS STEP.
#
# setupServices returns 200 the moment the services are ASSIGNED. They register
# their ports seconds to a minute later, and until they do, ns_server answers
# every proxied call with 404 "Service <name> not running on this node".
#
# Measured 2026-09-13: with -PortOffset 0 the wait was skipped entirely, because
# it lived inside the alternate-address block and that block is conditional. The
# fixture script ran immediately afterwards and got
#
#     404 on PUT /_p/fts/api/index/mcptest-fts: Service fts not running on
#     this node
#
# which reads exactly like the proxy-prefix defect that was fixed in
# handlers/search_admin.py -- a correct tool, a correct path, and a service that
# was not there yet. A readiness check that is skipped in the common case is
# worse than none, because its absence is invisible.
$expectedByService = @{
    'kv'       = 'kv'
    'data'     = 'kv'
    'index'    = 'indexHttp'
    'n1ql'     = 'n1ql'
    'query'    = 'n1ql'
    'fts'      = 'fts'
    'eventing' = 'eventingAdminPort'
    'backup'   = 'backupAPI'
    'cbas'     = 'cbas'
}
$wantPorts = @('mgmt')
foreach ($svc in ($Services -split ',')) {
    $svc = $svc.Trim()
    if ($expectedByService.ContainsKey($svc)) { $wantPorts += $expectedByService[$svc] }
}
$wantPorts = $wantPorts | Select-Object -Unique

$svc = @()
$deadline = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $deadline) {
    try {
        $svc = @((Invoke-RestMethod -Uri "http://127.0.0.1:$MgmtHost/pools/default/nodeServices" `
            -Headers @{ Authorization = "Basic $auth" }
            ).nodesExt[0].services.PSObject.Properties.Name)
        if (@($wantPorts | Where-Object { $svc -notcontains $_ }).Count -eq 0) { break }
    } catch { $svc = @() }
    Start-Sleep -Seconds 3
}
Say "   $($svc -join ' ')"
$late = @($wantPorts | Where-Object { $svc -notcontains $_ })
if ($late.Count -eq 0) {
    Ok "every requested service has registered a port"
} else {
    # Do NOT say the service is absent and the tools are fine. On 2026-09-13
    # backupAPI was in nodeServices the whole time while the Backup service
    # crash-looped on cbauth: "not registered yet" and "registered and dying"
    # are different states with the same symptom. Report the observation and
    # name the log that tells them apart.
    Say "   NOTE: these never registered a port within 180 s:"
    Say "         $($late -join ', ')"
    Say "         Tools for them will answer 404 'Service <name> not running on"
    Say "         this node'. If one answers 500 instead, it IS running and"
    Say "         failing -- read its log under"
    Say "         /opt/couchbase/var/lib/couchbase/logs/ before suspecting the tool."
}

Step "backup archive directory"
# OWNERSHIP, not just existence. The Backup service runs as `couchbase`; a
# directory made with `docker exec mkdir` is owned by root, and the service
# fails the repository create with a message that names the ARCHIVE and not the
# permission:
#
#     500 'Location not accessible by all nodes'
#     extras: node <uuid> cannot access location /opt/.../backup-archive:
#             mkdir .../.cbbs-<hash>: permission denied
#
# Creating it here, correctly, removes a manual step that was easy to get wrong
# in exactly this invisible way.
& docker exec -u 0 $Name bash -c "mkdir -p '$ArchivePath' && chown couchbase:couchbase '$ArchivePath' 2>/dev/null; ls -ld '$ArchivePath'"
if ($LASTEXITCODE -ne 0) {
    Say "   note: could not prepare $ArchivePath — create it inside the"
    Say "         container, owned by couchbase, before the first repository."
} elseif ($BackupArchiveHost) {
    # chown is a no-op on a Docker Desktop bind mount, so do not claim it
    # worked. The ls -ld above is the evidence; the repository create is the
    # real test and it happens a few seconds from now either way.
    Ok "$ArchivePath is bind-mounted from the host (see the ownership above)"
    Say "   if the first repository create answers 'Location not accessible by"
    Say "   all nodes', the mount is why -- re-run without -BackupArchiveHost"
    Say "   and use scripts/fetch-ee-backup.ps1 to copy the archive out."
} else {
    Ok "$ArchivePath exists and is owned by couchbase"
    Say "   NOTE: it lives INSIDE the container. docker rm destroys it."
    Say "         Pass -BackupArchiveHost <dir> to keep backups on a drive."
}

if ($PortOffset -ne 0 -and -not $SkipAlternateAddress) {
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
} else {
    Step "external alternate address"
    if ($SkipAlternateAddress) {
        Say "   NOT SET (-SkipAlternateAddress). Nothing on the host dials this"
        Say "   cluster; it is reached by container name on '$Network'. An"
        Say "   alternate address would break its Backup service for no gain."
    } else {
    Say "   NOT SET, deliberately. Ports are 1:1, so 127.0.0.1:<port> already"
    Say "   reaches this node, and an alternate address here would break the"
    Say "   Backup service - it reads the alternate map, dials the address it"
    Say "   finds there, and cbauth does not recognise that hostport."
    }
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
# CB_MGMT_PORT, NOT CB_ADMIN_HOST. This block named the wrong variable for most
# of 2026-09-13. _admin_url() derives the REST URL from CB_CONNECTION_STRING and
# DISCARDS the SDK port, assuming 8091 unless CB_MGMT_PORT says otherwise -- so
# CB_ADMIN_HOST was ignored, every REST call went to whatever was on 8091 with
# these credentials, and the surface run recorded 43 UPSTREAM 401s.
if ($PortOffset -eq 0) {
    Say "  `$env:CB_CONNECTION_STRING = 'couchbase://127.0.0.1'"
} else {
    Say "  `$env:CB_CONNECTION_STRING = 'couchbase://127.0.0.1:${KvHost}?network=external'"
    Say "  `$env:CB_MGMT_PORT         = '${MgmtHost}'"
}
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
