# Stops whatever start_all.ps1 started, using the recorded PIDs.
#
#   .\stop_all.ps1
#
# Each PID is verified to still be the process we started before it is killed.
# PIDs get recycled by the OS, and killing a stale one from a previous run means
# killing whatever unrelated process happens to hold that number now.

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$PidFile = Join-Path $Root ".demo-pids"

if (-not (Test-Path $PidFile)) {
    Write-Host "No .demo-pids file - nothing recorded as started." -ForegroundColor Yellow
    Write-Host "If something is still listening, find it with:" -ForegroundColor Yellow
    Write-Host '  Get-NetTCPConnection -LocalPort 8080,9000 -State Listen | ForEach-Object { Get-Process -Id $_.OwningProcess }'
    exit 0
}

$stopped = 0
foreach ($line in Get-Content $PidFile) {
    if ($line -notmatch '^(?<name>[^:]+):(?<procid>\d+)$') { continue }
    $name = $Matches['name']
    $procid = [int]$Matches['procid']

    $proc = Get-Process -Id $procid -ErrorAction SilentlyContinue
    if (-not $proc) {
        Write-Host "  $name (pid $procid) already gone"
        continue
    }
    # Only kill it if it is still a Python process - cheap guard against a
    # recycled PID now belonging to something else entirely.
    if ($proc.ProcessName -notlike "python*") {
        Write-Host "  SKIP $name (pid $procid): now '$($proc.ProcessName)', not ours" -ForegroundColor Yellow
        continue
    }
    Stop-Process -Id $procid -Force
    Write-Host "  stopped $name (pid $procid)" -ForegroundColor Green
    $stopped++
}

Remove-Item $PidFile
Write-Host ""
Write-Host "$stopped process(es) stopped." -ForegroundColor Green
