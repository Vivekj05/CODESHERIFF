@echo off
setlocal enabledelayedexpansion

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
goto help

:dev
echo [*] Starting Docker Infrastructure (Postgres + Redis)...
docker compose up -d postgres redis
echo [*] Starting Backend API...
start "CodeSheriff API" cmd /k ".venv\Scripts\python.exe -m uvicorn codesheriff_api.main:app --reload --port 8000"
echo [*] Starting Backend Worker...
start "CodeSheriff Worker" cmd /k ".venv\Scripts\python.exe -m celery -A codesheriff_worker.celery_app worker --pool=solo --loglevel=info --queues=audits"
call :start_smee
echo [*] Starting Frontend Dashboard...
cd frontend && npm run dev
goto end

:infra
echo [*] Starting Postgres (pgvector) and Redis...
docker compose up -d postgres redis
goto end

:backend
echo [*] Starting Backend API and Worker...
start "CodeSheriff API" cmd /k ".venv\Scripts\python.exe -m uvicorn codesheriff_api.main:app --reload --port 8000"
start "CodeSheriff Worker" cmd /k ".venv\Scripts\python.exe -m celery -A codesheriff_worker.celery_app worker --pool=solo --loglevel=info --queues=audits"
call :start_smee
goto end

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

:frontend
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
echo   dev       - Start Docker infra + API + Worker + webhook forwarder (smee) + Dashboard
echo   infra     - Start Postgres (pgvector) and Redis containers
echo   backend   - Start FastAPI, the Worker and the webhook forwarder (smee)
echo   frontend  - Start only Next.js web dashboard
echo   test      - Run test suite with pytest
echo   eval      - Run benchmark evaluation script
echo   clean     - Clean temporary Python caches (.pytest_cache, .ruff_cache, etc.)
echo   help      - Display this help message
echo.
goto end

:end
