<#
.SYNOPSIS
    Copy an Enterprise Edition backup archive out of its container onto a drive.

.DESCRIPTION
    WHY THIS IS A SCRIPT AND NOT AN MCP TOOL
    ========================================
    The obvious shape for this is admin_backup_export, a tool that fetches a
    backup and writes it where the caller asks. It is deliberately NOT built.

    CB-Admin-MCP speaks REST to a cluster. Every tool it has reads or changes
    cluster state, and the blast radius of a mistake is bounded by what the
    cluster's own API permits. A tool that reads files out of a container and
    writes them to the operator's filesystem is a different capability: it is
    arbitrary file egress, driven by a model, with a path argument. Pointed at
    a production cluster it is a data-exfiltration primitive, and no
    confirmation gate makes that acceptable -- the gate protects against
    accident, not against the capability existing.

    So the mechanism lives here, in something a person runs on purpose, with
    the source and destination both on the command line.

    WHAT A BACKUP ARCHIVE IS
    ------------------------
    A directory tree, not a file: <archive>/<repository>/<backup>/... plus the
    repository metadata cbbackupmgr needs to read it back. Copy the whole tree
    or you have copied nothing usable, which is why this takes a directory
    destination and refuses a file.

.PARAMETER Container
    The Couchbase container holding the archive. Default cb-mcp-ee.

.PARAMETER ArchivePath
    The archive inside the container.

.PARAMETER Destination
    Host directory to copy into. Created if absent. The archive lands in a
    timestamped subdirectory so a second run never overwrites the first.

.PARAMETER Inspect
    Run `cbbackupmgr info` against the archive first and print what is in it,
    so you know whether the copy is worth making.

.EXAMPLE
    .\scripts\fetch-ee-backup.ps1 -Destination C:\Backups
    .\scripts\fetch-ee-backup.ps1 -Destination C:\Backups -Inspect
#>
param(
    [string] $Container   = 'cb-mcp-ee',
    [string] $ArchivePath = '/opt/couchbase/var/lib/couchbase/backup-archive',
    [Parameter(Mandatory = $true)]
    [string] $Destination,
    [switch] $Inspect
)

$ErrorActionPreference = 'Stop'

function Say([string] $Text)  { Write-Host $Text }
function Step([string] $Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }
function Ok([string] $Text)   { Write-Host "   PASS  $Text" -ForegroundColor Green }
function Die([string] $Text)  { Write-Host "   FAIL  $Text" -ForegroundColor Red; throw $Text }

Step "container $Container"
$state = (docker ps -a --filter "name=^$Container$" --format '{{.State}}') -join ''
if (-not $state)            { Die "no container named '$Container'." }
if ($state -ne 'running')   { Die "container '$Container' is in state '$state'. docker start $Container first." }
Ok "running"

Step "archive $ArchivePath"
# Ask whether it exists AND holds anything. An empty archive copies fine and
# tells you nothing, which is the failure mode worth catching here rather than
# after a long copy.
$listing = & docker exec $Container bash -c "ls -1 '$ArchivePath' 2>/dev/null"
if ($LASTEXITCODE -ne 0) { Die "no archive at $ArchivePath inside $Container." }
$repos = @($listing | Where-Object { $_ -and $_ -notmatch '^\.' })
if ($repos.Count -eq 0) {
    Die "archive exists but holds no repository. Create one (admin_backup_repository_create) and run a backup (admin_backup_run) before copying."
}
Ok "$($repos.Count) repository/repositories: $($repos -join ', ')"

if ($Inspect) {
    Step "cbbackupmgr info"
    # Read-only. Runs INSIDE the container so it reads the archive through the
    # same filesystem the Backup service wrote it with.
    & docker exec $Container /opt/couchbase/bin/cbbackupmgr info --archive $ArchivePath --all
    if ($LASTEXITCODE -ne 0) {
        Say "   note: cbbackupmgr info exited $LASTEXITCODE. The copy below is"
        Say "         still worth making -- info failing does not mean the"
        Say "         archive is unreadable, and a copy on disk can be examined"
        Say "         at leisure."
    }
}

Step "destination"
if (-not (Test-Path $Destination)) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
}
if (-not (Get-Item $Destination).PSIsContainer) {
    Die "$Destination is a file. An archive is a directory tree; give a directory."
}
# TIMESTAMPED, so a second fetch never silently merges into or overwrites the
# first. Two archives that got mixed together are worse than two copies.
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$target = Join-Path (Resolve-Path $Destination).Path "cb-backup-$stamp"
Ok "copying into $target"

Step "docker cp"
& docker cp "${Container}:${ArchivePath}" $target
if ($LASTEXITCODE -ne 0) { Die "docker cp failed." }

$files = @(Get-ChildItem -Path $target -Recurse -File -ErrorAction SilentlyContinue)
$bytes = ($files | Measure-Object -Property Length -Sum).Sum
if (-not $bytes) { $bytes = 0 }
Ok "$($files.Count) file(s), $([math]::Round($bytes / 1MB, 1)) MB"

Say ""
Say "======================================================================"
Say " The archive is a cbbackupmgr archive, not a loose dump. To restore it"
Say " you point cbbackupmgr at the directory, not at a file:"
Say ""
Say "   cbbackupmgr info    --archive <dir> --all"
Say "   cbbackupmgr restore --archive <dir> --repo <name> \"
Say "                       --cluster couchbase://<host> -u <user> -p <pass>"
Say ""
Say " Restoring into Capella is documented and works the same way, with the"
Say " Capella connection string and a database credential rather than an"
Say " administrator. See handlers/backup.py for what was measured."
Say "======================================================================"
