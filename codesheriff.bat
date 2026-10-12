@echo off
setlocal enabledelayedexpansion
rem Every path below is relative to the repository root, so run from there whatever folder this
rem was started from (a double-click, or another terminal's working directory).
cd /d "%~dp0"

echo ===================================================
echo               CodeSheriff Controller
echo ===================================================

if "%1"=="" goto help
if "%1"=="dev" goto dev
if "%1"=="infra" goto infra
if "%1"=="test" goto test
if "%1"=="eval" goto eval
if "%1"=="frontend" goto frontend
if "%1"=="backend" goto backend
if "%1"=="clean" goto clean
if "%1"=="stop" goto stop
goto help

:dev
call :check_docker || goto end
call :check_port 8000 "the API" || goto end
call :check_port 3000 "the dashboard" || goto end
echo [*] Starting Docker Infrastructure (Postgres + Redis)...
docker compose up -d postgres redis
echo [*] Starting Backend API...
start "CodeSheriff API" cmd /k ".venv\Scripts\python.exe -m uvicorn codesheriff_api.main:app --reload --port 8000"
call :start_worker
call :start_smee
echo [*] Starting Frontend Dashboard...
cd frontend && npm run dev
goto end

:infra
call :check_docker || goto end
echo [*] Starting Postgres (pgvector) and Redis...
docker compose up -d postgres redis
goto end

:backend
call :check_docker || goto end
call :check_port 8000 "the API" || goto end
echo [*] Starting Backend API and Worker...
start "CodeSheriff API" cmd /k ".venv\Scripts\python.exe -m uvicorn codesheriff_api.main:app --reload --port 8000"
call :start_worker
call :start_smee
goto end

:start_worker
rem The worker runs in the Linux image, never on this host (D-104): it needs Semgrep, Semgrep
rem cannot run on Windows, and a worker without it would score a one-backend structural witness
rem with ratios fitted on two. Celery does not reload, so this recreates the container each time.
echo [*] Starting Backend Worker (Linux container, with Semgrep)...
docker compose --profile worker up -d --force-recreate worker
start "CodeSheriff Worker" cmd /k "docker logs -f codesheriff-worker"
exit /b 0

:start_smee
rem Forwards GitHub's webhooks from the smee.io channel to the local API (D-043). The channel is
rem read from SMEE_URL in .env so it never lands in a committed file. Without this window open,
rem webhooks are lost: smee does not store events for a client that is not listening.
set "SMEE_URL="
if exist .env (
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        if "%%A"=="SMEE_URL" set "SMEE_URL=%%B"
    )
)
if "!SMEE_URL!"=="" (
    echo [x] SMEE_URL is not set in .env, so GitHub webhooks will not reach this machine.
    echo     Add your channel, e.g. SMEE_URL=https://smee.io/yourchannel, and run this again.
    exit /b 0
)
echo [*] Starting webhook forwarder (smee) from !SMEE_URL!...
start "CodeSheriff Webhooks (smee)" cmd /k "npx -y smee-client --url !SMEE_URL! --target http://localhost:8000/webhooks/github"
exit /b 0

:check_docker
docker info >nul 2>&1
if errorlevel 1 (
    echo [x] Docker is not running. Start Docker Desktop, wait until it says it is running, and try again.
    exit /b 1
)
exit /b 0

:check_port
rem %1 is the port, %2 what needs it. Something else holding the port is how a second copy fails
rem quietly: the Claude app's preview (.claude/launch.json) starts its own API and dashboard on
rem these same ports, and a run that loses the race comes up half-started.
set "PORT_PID="
for /f "tokens=5" %%P in ('netstat -ano ^| findstr /R /C:":%1 .*LISTENING"') do set "PORT_PID=%%P"
if defined PORT_PID (
    echo [x] Port %1 is already in use ^(PID !PORT_PID!^), so %~2 cannot start.
    echo     Another copy is probably running, e.g. the Claude app's preview.
    echo     Run "codesheriff.bat stop" first, then try again.
    exit /b 1
)
exit /b 0

:stop
rem Everything "dev" starts: the API, the dashboard, the webhook forwarder and the worker log
rem window, plus whatever still holds ports 8000 or 3000 (an orphaned uvicorn --reload child
rem holds the port after its parent is killed). Containers are stopped, never removed, so the
rem database and Redis keep their data.
echo [*] Stopping the API, dashboard, webhook forwarder and worker log windows...
powershell -NoProfile -Command "$me=$PID; $ids=@(); Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $me -and ($_.CommandLine -match 'codesheriff_api\.main:app|smee-client|docker logs -f codesheriff-worker' -or ($_.CommandLine -match 'next' -and $_.CommandLine -match 'CodeSheriff')) } | ForEach-Object { $ids += [int]$_.ProcessId }; foreach ($p in 8000,3000) { Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $ids += [int]$_.OwningProcess } }; $ids = @($ids | Sort-Object -Unique); foreach ($i in $ids) { taskkill /T /F /PID $i 2>$null | Out-Null }; Write-Host ('    stopped ' + $ids.Count + ' process(es)')"
docker info >nul 2>&1
if errorlevel 1 (
    echo [*] Docker is not running, so there are no containers to stop.
) else (
    echo [*] Stopping containers ^(data is kept^)...
    docker compose --profile worker stop
)
goto end

:frontend
call :check_port 3000 "the dashboard" || goto end
echo [*] Starting Frontend Web Dashboard...
cd frontend && npm run dev
goto end

:test
echo [*] Running full test suite...
.venv\Scripts\pytest.exe -m "not db and not live_api and not wasm" -q
goto end

:eval
echo [*] Running baseline evaluation...
.venv\Scripts\python.exe examples\baseline_eval.py
goto end

:clean
echo [*] Cleaning cache files...
if exist .pytest_cache rmdir /s /q .pytest_cache
if exist .mypy_cache rmdir /s /q .mypy_cache
if exist .ruff_cache rmdir /s /q .ruff_cache
if exist .import_linter_cache rmdir /s /q .import_linter_cache
if exist .coverage del /f /q .coverage
echo [✓] Caches cleaned.
goto end

:help
echo Usage: codesheriff.bat [command]
echo.
echo Available Commands:
echo   dev       - Start Docker infra + API + Worker (container) + webhook forwarder (smee) + Dashboard
echo   infra     - Start Postgres (pgvector) and Redis containers
echo   backend   - Start FastAPI, the Worker and the webhook forwarder (smee)
echo   frontend  - Start only Next.js web dashboard
echo   stop      - Stop everything "dev" starts; containers are stopped, data is kept
echo   test      - Run test suite with pytest
echo   eval      - Run benchmark evaluation script
echo   clean     - Clean temporary Python caches (.pytest_cache, .ruff_cache, etc.)
echo   help      - Display this help message
echo.
goto end

:end
