# Which alternate-address port keys does THIS node accept?
#
# The full map was refused and a narrowed one silently stored no ports at all.
# Rather than guess a third time, ask: send hostname plus ONE port key, read the
# map back, and see whether that key survived. A key that stores is accepted; a
# key that vanishes is ignored; a key that 400s is rejected outright — three
# different answers that a single all-at-once PUT collapses into one failure.
$ErrorActionPreference = 'Continue'
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("Administrator:reticuli"))
$h    = @{ Authorization = "Basic $auth" }
$base = 'http://127.0.0.1:38091'
$uri  = "$base/node/controller/setupAlternateAddresses/external"

function Body([hashtable] $f) {
    (($f.Keys | Sort-Object | ForEach-Object {
        '{0}={1}' -f [Uri]::EscapeDataString($_), [Uri]::EscapeDataString([string]$f[$_])
    }) -join '&')
}
function ErrText($e) {
    try {
        $s = $e.Exception.Response.GetResponseStream(); $s.Position = 0
        (New-Object IO.StreamReader($s)).ReadToEnd().Trim()
    } catch { '(no body)' }
}

$candidates = [ordered]@{
    mgmt              = 38091
    mgmtSSL           = 48091
    capi              = 38092
    capiSSL           = 48092
    n1ql              = 38093
    n1qlSSL           = 48093
    fts               = 38094
    ftsSSL            = 48094
    indexHttp         = 39102
    eventingAdminPort = 38096
    eventingSSL       = 48096
    backupAPI         = 38097
    backupAPIHTTPS    = 48097
    kv                = 41210
    kvSSL             = 41207
}

$accepted = [ordered]@{}
foreach ($k in $candidates.Keys) {
    $one = @{ hostname = '127.0.0.1'; $k = $candidates[$k] }
    try {
        Invoke-RestMethod -Method Put -Uri $uri -Headers $h `
            -ContentType 'application/x-www-form-urlencoded' -Body (Body $one) | Out-Null
        $back = (Invoke-RestMethod -Uri "$base/pools/default/nodeServices" -Headers $h).nodesExt[0].alternateAddresses.external
        $stored = $null
        if ($back.ports) { $stored = $back.ports.$k }
        if ($null -ne $stored) {
            "{0,-20} ACCEPTED  stored {1}" -f $k, $stored
            $accepted[$k] = $candidates[$k]
        } else {
            "{0,-20} IGNORED   200 but nothing stored" -f $k
        }
    } catch {
        "{0,-20} REFUSED   {1}" -f $k, (ErrText $_)
    }
}

""
"== applying every accepted key in one PUT =="
if ($accepted.Count -eq 0) {
    "none were accepted — the external map cannot carry ports on this build."
} else {
    $final = @{ hostname = '127.0.0.1' }
    foreach ($k in $accepted.Keys) { $final[$k] = $accepted[$k] }
    try {
        Invoke-RestMethod -Method Put -Uri $uri -Headers $h `
            -ContentType 'application/x-www-form-urlencoded' -Body (Body $final) | Out-Null
        $back = (Invoke-RestMethod -Uri "$base/pools/default/nodeServices" -Headers $h).nodesExt[0].alternateAddresses.external
        "hostname = $($back.hostname)"
        $back.ports.PSObject.Properties | ForEach-Object { "  {0,-20} {1}" -f $_.Name, $_.Value }
    } catch {
        "final PUT refused: $(ErrText $_)"
    }
}

""
"== sample bucket: what does install actually answer? =="
try {
    $r = Invoke-WebRequest -Method Post -Uri "$base/sampleBuckets/install" -Headers $h `
         -ContentType 'application/json' -Body '["travel-sample"]' -UseBasicParsing
    "status $($r.StatusCode)  body: $($r.Content)"
} catch {
    "refused: $(ErrText $_)"
}
