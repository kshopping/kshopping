@echo off
setlocal EnableExtensions

REM ============================================================
REM GenieSecurity Server Agent - INTERNAL MODE (Product) v7
REM Fixes:
REM  - Do NOT re-provision identity every run (prevents KID changes)
REM  - Requires Administrator CMD (net session == 0)
REM Flow:
REM  1) (once) Provision identity if missing: data\server_identity.dpapi
REM  2) Run server_agent in UNATTENDED=1
REM ============================================================

REM --- Admin check ---
net session >nul 2>&1
if not "%ERRORLEVEL%"=="0" (
  echo [ERROR] Run this in an Administrator CMD.
  pause
  exit /b 1
)

REM --- Paths ---
set "RUN_DIR=%~dp0"
for %%I in ("%RUN_DIR%..") do set "BASE_DIR=%%~fI"

set "PY_EXE=%BASE_DIR%\tools\python\python.exe"
set "AGENT_PY=%BASE_DIR%\agents\server\server_agent.py"

REM --- Defaults / env ---
if "%RELAY_BASE%"=="" set "RELAY_BASE=http://127.0.0.1:3000"
if "%SERVER_UUID%"=="" set "SERVER_UUID=serverUuidA"
if "%REGISTRY_PATH%"=="" set "REGISTRY_PATH=%BASE_DIR%\relay\data\registry.json"
if "%SERVER_IDENTITY_DPAPI_PATH%"=="" set "SERVER_IDENTITY_DPAPI_PATH=%BASE_DIR%\data\server_identity.dpapi"

set "UNATTENDED=1"
set "PAUSE_ON_EXIT=0"
set "PYTHONUNBUFFERED=1"

echo ============================================================
echo [ADMIN]       YES
echo [RUNNING_CMD] %~f0
echo [BASE_DIR]    %BASE_DIR%
echo [PY_EXE]      %PY_EXE%
echo [AGENT_PY]    %AGENT_PY%
echo [ENV] RELAY_BASE=%RELAY_BASE%
echo [ENV] SERVER_UUID=%SERVER_UUID%
echo [ENV] REGISTRY_PATH=%REGISTRY_PATH%
echo [ENV] SERVER_IDENTITY_DPAPI_PATH=%SERVER_IDENTITY_DPAPI_PATH%
echo [ENV] UNATTENDED=%UNATTENDED%
echo ============================================================

if not exist "%PY_EXE%" (
  echo [ERROR] python.exe missing: %PY_EXE%
  pause
  exit /b 1
)
if not exist "%AGENT_PY%" (
  echo [ERROR] server_agent.py missing: %AGENT_PY%
  pause
  exit /b 1
)

REM --- Provision ONCE if missing ---
if exist "%SERVER_IDENTITY_DPAPI_PATH%" goto :RUN_AGENT

echo.
echo [STEP 1/2] Provisioning server identity (first run only)...
pushd "%BASE_DIR%"
"%PY_EXE%" -u "%AGENT_PY%" --provision-identity
set "PROV_ERR=%ERRORLEVEL%"
popd
if not "%PROV_ERR%"=="0" (
  echo [ERROR] provision failed (code %PROV_ERR%)
  pause
  exit /b %PROV_ERR%
)
echo [OK] Identity provisioned: %SERVER_IDENTITY_DPAPI_PATH%

:RUN_AGENT
echo.
echo [STEP 2/2] Starting server agent (UNATTENDED=1)...
echo.
pushd "%BASE_DIR%"
"%PY_EXE%" -u "%AGENT_PY%"
set "ERR=%ERRORLEVEL%"
popd

echo.
echo [INFO] Server agent exited with code %ERR%
echo.
pause
exit /b %ERR%
