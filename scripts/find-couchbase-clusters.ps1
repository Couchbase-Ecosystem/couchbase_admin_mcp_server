<#
  find-couchbase-clusters.ps1

  WHICH CLUSTER AM I TALKING TO?

  There are several Couchbase clusters on this machine and they are not
  interchangeable. `add-local-services.ps1` defaults to 127.0.0.1:9091 (the
  cb-mcptest cluster); `probe_backup_paths.ps1` defaulted to 8091, which is a
  different, single-node cluster with no Backup service. So the Backup service
  was added to one cluster and probed on another, and the resulting wall of 404s
  looked like a broken path fix. It was a wrong address.

  This enumerates every cluster manager answering on this host and reports, for
  each: the nodes, the services each node runs, the buckets, and the connection
  string to use. Run it before anything that names a port.

  It probes ONLY loopback ports -- this is a local development inventory, not a
  network scan.
#>

[CmdletBinding()]
param(
    # Couchbase's default, plus the offsets the local multi-cluster setups use.
    [int[]]$Ports = @(8091, 9091, 10091, 11091, 12091, 13091),
    [string]$ClusterHost = '127.0.0.1',
    [string]$Username = $env:CB_USERNAME,
    [string]$Password = $env:CB_PASSWORD
)

$ErrorActionPreference = 'Continue'

if (-not $Username -or -not $Password) {
    Write-Host 'CB_USERNAME / CB_PASSWORD are not set. Run cbenv.bat, then a NEW window.' -ForegroundColor Yellow
    exit 1
}

$auth = @{ Authorization = 'Basic ' + [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes("$Username`:$Password")) }

$found = @()

foreach ($port in $Ports) {
    $base = "http://${ClusterHost}:${port}"
    try {
        $pool = Invoke-RestMethod -Uri "$base/pools/default" -Headers $auth -TimeoutSec 5
    } catch {
        continue   # nothing there, or not a cluster manager
    }

    Write-Host ''
    Write-Host "== $base ==" -ForegroundColor Cyan
    Write-Host ("  cluster name : {0}" -f $(if ($pool.clusterName) { $pool.clusterName } else { '(unnamed)' }))
    Write-Host ("  nodes        : {0}" -f $pool.nodes.Count)

    $allServices = @()
    foreach ($node in $pool.nodes) {
        $svc = ($node.services | Sort-Object) -join ','
        $allServices += $node.services
        $status = $node.status
        $colour = if ($status -eq 'healthy') { 'Green' } else { 'Yellow' }
        Write-Host ("    {0,-34} {1,-8} {2}" -f $node.otpNode, $status, $svc) -ForegroundColor $colour
    }

    # Buckets: the thing that decides where test data can go.
    try {
        $buckets = Invoke-RestMethod -Uri "$base/pools/default/buckets" -Headers $auth -TimeoutSec 5
        $names = @($buckets | ForEach-Object { $_.name })
        Write-Host ("  buckets      : {0}" -f $(if ($names) { $names -join ', ' } else { '(none)' }))
    } catch {
        $names = @()
        Write-Host "  buckets      : could not read ($($_.Exception.Message))"
    }

    # Alternate addresses decide whether a client on the HOST can use the cluster
    # map at all. A containerised cluster advertises 172.x internally; without
    # these, an SDK connection from Windows resolves to an unroutable address and
    # hangs until it times out -- which reads as the cluster being down.
    $external = $false
    try {
        $nodeServices = Invoke-RestMethod -Uri "$base/pools/default/nodeServices" -Headers $auth -TimeoutSec 5
        $external = [bool]($nodeServices.nodesExt | Where-Object { $_.alternateAddresses })
        $kv = ($nodeServices.nodesExt | Where-Object { $_.services.kv } | Select-Object -First 1)
        $kvPort = if ($kv.alternateAddresses.external.ports.kv) {
            $kv.alternateAddresses.external.ports.kv
        } else { $kv.services.kv }
    } catch { $kvPort = $null }

    Write-Host ("  alt addresses: {0}" -f $(if ($external) { 'yes (host clients OK)' } else { 'NO (host clients may hang)' })) `
        -ForegroundColor $(if ($external) { 'Green' } else { 'Yellow' })

    $hasBackup = $allServices -contains 'backup'
    Write-Host ("  backup svc   : {0}" -f $(if ($hasBackup) { 'YES' } else { 'no' })) `
        -ForegroundColor $(if ($hasBackup) { 'Green' } else { 'DarkGray' })

    if ($kvPort) {
        $suffix = if ($external) { '?network=external' } else { '' }
        Write-Host ("  connect      : couchbase://${ClusterHost}:${kvPort}${suffix}")
    }

    $found += [pscustomobject]@{
        Base = $base; Port = $port; Nodes = $pool.nodes.Count
        Backup = $hasBackup; Buckets = $names; KvPort = $kvPort; External = $external
    }
}

Write-Host ''
Write-Host '== what to use ==' -ForegroundColor Cyan

if ($found.Count -eq 0) {
    Write-Host '  No cluster manager answered on any probed port.' -ForegroundColor Red
    Write-Host '  Is Docker running? `docker ps` should list the couchbase containers.'
    exit 1
}

$backupCluster = $found | Where-Object { $_.Backup } | Select-Object -First 1
if ($backupCluster) {
    Write-Host ("  Backup service is on {0}. Probe it with:" -f $backupCluster.Base) -ForegroundColor Green
    Write-Host ("      .\scripts\probe_backup_paths.ps1 -ManagementPort {0}" -f $backupCluster.Port)
} else {
    Write-Host '  NO cluster is running the Backup service.' -ForegroundColor Yellow
    Write-Host '  Add it, naming the cluster explicitly:'
    Write-Host ("      .\scripts\add-local-services.ps1 -Mgmt {0}" -f $found[0].Base)
    Write-Host '  It enumerates every non-Data service on purpose: topology[] REMOVES'
    Write-Host '  any service left out of the call.'
}

$withMcptest = $found | Where-Object { $_.Buckets -contains 'mcptest' } | Select-Object -First 1
if ($withMcptest) {
    $suffix = if ($withMcptest.External) { '?network=external' } else { '' }
    Write-Host ''
    Write-Host ("  mcptest lives on {0}. Load data with:" -f $withMcptest.Base) -ForegroundColor Green
    Write-Host ("      `$env:CB_CONNECTION_STRING = 'couchbase://{0}:{1}{2}'" -f $ClusterHost, $withMcptest.KvPort, $suffix)
    Write-Host  '      uv run python scripts\load_test_data.py'
} else {
    Write-Host ''
    Write-Host '  No cluster has an mcptest bucket. Create one before loading data.' -ForegroundColor Yellow
}
Write-Host ''
