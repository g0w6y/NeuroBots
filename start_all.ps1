# Windows equivalent of start_all.sh - brings up the demo upstream API, the
# gateway and (if Redis is reachable) the ML worker, with real health checks
# between each step.
#
#   .\start_all.ps1
#   .\start_all.ps1 -GatewayPort 18080 -UpstreamPort 19000   # avoid a port clash
#   .\stop_all.ps1
#
# The frontend is deliberately not started here: run `npm run dev` in its own
# terminal so it stays visible and interactive during a demo.

[CmdletBinding()]
param(
    [int]$GatewayPort = 8080,
    [int]$UpstreamPort = 9000,
    [string]$AdminKey = $(if ($env:ADMIN_API_KEY) { $env:ADMIN_API_KEY } else { "changeme-admin-key" })
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$LogDir = Join-Path $Root ".demo-logs"
$PidFile = Join-Path $Root ".demo-pids"
$Python = Join-Path $Root "backend\venv\Scripts\python.exe"

New-Item -ItemType Directory -Force $LogDir | Out-Null
if (Test-Path $PidFile) { Remove-Item $PidFile }

if (-not (Test-Path $Python)) {
    Write-Host "No venv found. Creating one and installing requirements..." -ForegroundColor Yellow
    python -m venv (Join-Path $Root "backend\venv")
    & $Python -m pip install --quiet --upgrade pip
    & $Python -m pip install --quiet -r (Join-Path $Root "backend\requirements.txt")
    # ml/requirements.txt too: step 3 runs the ML worker out of this same venv,
    # and without scikit-learn/networkx it dies on import the moment it starts.
    & $Python -m pip install --quiet -r (Join-Path $Root "ml\requirements.txt")
} else {
    # $LASTEXITCODE, not $?: for a native executable $? reports only whether the
    # process launched, so it stays $true on a failed import and the install is
    # skipped exactly when it is needed.
    & $Python -c "import sklearn" *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installing ML requirements into the existing venv..." -ForegroundColor Yellow
        & $Python -m pip install --quiet -r (Join-Path $Root "ml\requirements.txt")
    }
}

function Test-PortFree([int]$Port) {
    -not (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

function Wait-For([string]$Url, [string]$Name) {
    foreach ($i in 1..20) {
        try {
            Invoke-WebRequest -Uri $Url -TimeoutSec 2 -UseBasicParsing | Out-Null
            Write-Host "  $Name is up ($Url)" -ForegroundColor Green
            return $true
        } catch {
            # 401/404 still prove something is listening and routing.
            $code = $_.Exception.Response.StatusCode.value__
            if ($code -in 401, 404) {
                Write-Host "  $Name is up ($Url)" -ForegroundColor Green
                return $true
            }
        }
        Start-Sleep -Milliseconds 500
    }
    Write-Host "  WARNING: $Name did not respond at $Url within 10s - check $LogDir" -ForegroundColor Red
    return $false
}

foreach ($p in @($GatewayPort, $UpstreamPort)) {
    if (-not (Test-PortFree $p)) {
        Write-Host "Port $p is already in use. Pass -GatewayPort/-UpstreamPort to use different ones, or run .\stop_all.ps1 first." -ForegroundColor Red
        exit 1
    }
}

Write-Host "=== 1/3 starting demo upstream API ===" -ForegroundColor Cyan
# demo_upstream.py hardcodes port 9000 in its __main__ block, so to honour
# -UpstreamPort we run the ASGI app through uvicorn directly instead.
$up = Start-Process -FilePath $Python `
    -ArgumentList "-m", "uvicorn", "demo_upstream:app", "--host", "127.0.0.1", "--port", "$UpstreamPort" `
    -WorkingDirectory (Join-Path $Root "backend") `
    -RedirectStandardOutput (Join-Path $LogDir "upstream.log") `
    -RedirectStandardError (Join-Path $LogDir "upstream.err.log") `
    -NoNewWindow -PassThru
"upstream:$($up.Id)" | Add-Content $PidFile
Wait-For "http://127.0.0.1:$UpstreamPort/api/accounts/1001" "demo upstream" | Out-Null

Write-Host "=== 2/3 starting gateway ===" -ForegroundColor Cyan
$env:LISTEN_PORT = "$GatewayPort"
$env:UPSTREAM_URL = "http://127.0.0.1:$UpstreamPort"
$env:ADMIN_API_KEY = $AdminKey
$gw = Start-Process -FilePath $Python -ArgumentList "main.py" `
    -WorkingDirectory (Join-Path $Root "backend") `
    -RedirectStandardOutput (Join-Path $LogDir "gateway.log") `
    -RedirectStandardError (Join-Path $LogDir "gateway.err.log") `
    -NoNewWindow -PassThru
"gateway:$($gw.Id)" | Add-Content $PidFile
Wait-For "http://127.0.0.1:$GatewayPort/health" "gateway" | Out-Null

Write-Host "=== 3/3 starting ML worker ===" -ForegroundColor Cyan
# Started unconditionally. This used to be gated on the gateway reporting
# Redis as "connected", which meant that on any machine without Redis - no
# Docker, no local redis-server, i.e. the ordinary laptop - the worker was
# never launched at all, and the IsolationForest / Markov / NetworkX models
# scored nothing for the entire demo. The worker now prefers Redis and falls
# back to publishing over the gateway's /admin/ml-signal endpoint, so it has
# real work to do either way.
$redisOk = $false
try {
    $health = Invoke-RestMethod "http://127.0.0.1:$GatewayPort/health" -TimeoutSec 3
    $redisOk = $health.shared_store_redis -eq "connected"
} catch {}

$env:GATEWAY_URL = "http://127.0.0.1:$GatewayPort"
if (-not $env:REDIS_URL) { $env:REDIS_URL = "redis://127.0.0.1:6379" }
$ml = Start-Process -FilePath $Python -ArgumentList "-u", "worker.py" `
    -WorkingDirectory (Join-Path $Root "ml") `
    -RedirectStandardOutput (Join-Path $LogDir "ml_worker.log") `
    -RedirectStandardError (Join-Path $LogDir "ml_worker.err.log") `
    -NoNewWindow -PassThru
"ml_worker:$($ml.Id)" | Add-Content $PidFile

if ($redisOk) {
    Write-Host "  ML worker started (pid $($ml.Id)), publishing over Redis" -ForegroundColor Green
} else {
    Write-Host "  ML worker started (pid $($ml.Id)) - no Redis, publishing over /admin/ml-signal" -ForegroundColor Green
}
Write-Host "  It only ever adds a signal; nothing in the request path depends on it." -ForegroundColor DarkGray

Write-Host ""
Write-Host "=== up ===" -ForegroundColor Green
Write-Host "  gateway:       http://127.0.0.1:$GatewayPort"
Write-Host "  demo upstream: http://127.0.0.1:$UpstreamPort"
Write-Host "  health:        curl http://127.0.0.1:$GatewayPort/health"
Write-Host "  logs:          $LogDir"
Write-Host ""
Write-Host "Attack suite:  .\backend\venv\Scripts\python.exe backend\attack_sim\simulate.py --gateway http://127.0.0.1:$GatewayPort"
Write-Host "Dashboard:     cd frontend; npm run dev"
Write-Host "Stop:          .\stop_all.ps1"
