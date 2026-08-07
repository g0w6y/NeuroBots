# Stops whatever start_all.ps1 started.
#
#   .\stop_all.ps1
#   .\stop_all.ps1 -GatewayPort 18080 -UpstreamPort 19000   # match your start_all args
#
# Two mechanisms, because either one alone leaves the demo half-running:
#
# 1. Kill the recorded PID *and its descendants*. On Windows a venv's
#    Scripts\python.exe is a launcher shim that re-execs the real interpreter
#    (…\Programs\Python\Python311\python.exe) as a CHILD process, and it is the
#    child that binds the socket. Start-Process -PassThru hands back the parent,
#    so the previous "Stop-Process -Id $procid" killed the shim and orphaned the
#    listener: this script reported "0 process(es) stopped" while 8080 and 9000
#    stayed occupied, and the next start_all.ps1 aborted with "Port already in
#    use". Verified against a live stack before and after this change.
#
# 2. Sweep the demo ports for any python listener still standing afterwards.
#    That catches runs whose .demo-pids was lost, overwritten by a second
#    start_all, or left stale by a crash - the case where mechanism 1 has
#    nothing useful to work from.
#
# Both paths refuse to kill anything that is not a python process, so a
# recycled PID or an unrelated service on the port is left alone.

[CmdletBinding()]
param(
    [int]$GatewayPort = 8080,
    [int]$UpstreamPort = 9000
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$PidFile = Join-Path $Root ".demo-pids"

$script:stopped = 0

function Get-Descendants([int]$ParentId) {
    # Win32_Process gives the parent link; walk it breadth-first so a shim ->
    # interpreter -> worker chain of any depth is collected, not just one level.
    $found = @()
    $frontier = @($ParentId)
    while ($frontier.Count -gt 0) {
        $kids = Get-CimInstance Win32_Process -Filter "ParentProcessId = $($frontier[0])" -ErrorAction SilentlyContinue
        $frontier = @($frontier | Select-Object -Skip 1)
        foreach ($k in $kids) {
            $found += [int]$k.ProcessId
            $frontier += [int]$k.ProcessId
        }
    }
    return $found
}

function Stop-IfPython([int]$ProcId, [string]$Label) {
    $proc = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
    if (-not $proc) { return $false }
    if ($proc.ProcessName -notlike "python*") {
        Write-Host "  SKIP $Label (pid $ProcId): now '$($proc.ProcessName)', not ours" -ForegroundColor Yellow
        return $false
    }
    try {
        Stop-Process -Id $ProcId -Force -ErrorAction Stop
        Write-Host "  stopped $Label (pid $ProcId)" -ForegroundColor Green
        $script:stopped++
        return $true
    } catch {
        Write-Host "  could not stop $Label (pid $ProcId): $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

# --- 1. recorded PIDs, children first so the shim cannot outlive its listener ---

if (Test-Path $PidFile) {
    foreach ($line in Get-Content $PidFile) {
        if ($line -notmatch '^(?<name>[^:]+):(?<procid>\d+)$') { continue }
        $name = $Matches['name']
        $procid = [int]$Matches['procid']

        if (-not (Get-Process -Id $procid -ErrorAction SilentlyContinue)) {
            Write-Host "  $name (pid $procid) already gone"
            continue
        }
        foreach ($child in Get-Descendants $procid) {
            Stop-IfPython $child "$name child" | Out-Null
        }
        Stop-IfPython $procid $name | Out-Null
    }
    Remove-Item $PidFile
} else {
    Write-Host "No .demo-pids file - falling back to a port sweep." -ForegroundColor Yellow
}

# --- 2. anything still holding the demo ports ---

foreach ($port in @($GatewayPort, $UpstreamPort)) {
    $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        Stop-IfPython ([int]$c.OwningProcess) "orphan on port $port" | Out-Null
    }
}

Start-Sleep -Milliseconds 400
$busy = @($GatewayPort, $UpstreamPort) | Where-Object {
    Get-NetTCPConnection -LocalPort $_ -State Listen -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "$script:stopped process(es) stopped." -ForegroundColor Green
if ($busy) {
    Write-Host "STILL LISTENING on: $($busy -join ', ') - not a python process, inspect with:" -ForegroundColor Red
    Write-Host "  Get-NetTCPConnection -LocalPort $($busy -join ',') -State Listen | ForEach-Object { Get-Process -Id `$_.OwningProcess }"
} else {
    Write-Host "Ports $GatewayPort and $UpstreamPort are free." -ForegroundColor Green
}
