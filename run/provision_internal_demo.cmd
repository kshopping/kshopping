@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ============================================================
REM GenieSecurity - INTERNAL Demo Provisioning (Offline / No secrets shared)
REM - Registers demo client/server into relay registry via local HTTP API
REM - Then runs client_agent
REM
REM Requirements:
REM - Relay already running at http://127.0.0.1:3000
REM - Windows has curl (Windows 10/11 usually has it)
REM ============================================================

set "RUN_DIR=%~dp0"
for %%I in ("%RUN_DIR%..") do set "BASE_DIR=%%~fI"

REM --- demo values (change if you want) ---
set "RELAY_BASE=http://127.0.0.1:3000"
set "CLIENT_UUID=clientUuidA"
set "CLIENT_PSK=clientPskDummy"
set "SERVER_UUID=serverUuidA"
set "SERVER_PSK=serverPskDummy"

echo ============================================================
echo [RELAY_BASE]  %RELAY_BASE%
echo [CLIENT_UUID] %CLIENT_UUID%
echo [SERVER_UUID] %SERVER_UUID%
echo ============================================================
echo.

REM --- quick health check ---
curl -s "%RELAY_BASE%/api/self-check" >nul 2>nul
if not "%ERRORLEVEL%"=="0" (
  echo [ERROR] Relay not reachable. Start relay first: run_relay.cmd
  echo         Expected: %RELAY_BASE%
  echo.
  pause
  exit /b 1
)

echo [1/3] Register client (if already registered, it will just overwrite same id)
curl -s -X POST "%RELAY_BASE%/api/register/client" ^
  -H "Content-Type: application/json" ^
  -d "{\"clientUuid\":\"%CLIENT_UUID%\",\"clientPsk\":\"%CLIENT_PSK%\"}"
echo.
echo.

echo [2/3] Register server (for request-access existence check)
curl -s -X POST "%RELAY_BASE%/api/register/server" ^
  -H "Content-Type: application/json" ^
  -d "{\"serverUuid\":\"%SERVER_UUID%\",\"serverPsk\":\"%SERVER_PSK%\"}"
echo.
echo.

echo [3/3] Run client agent
pushd "%BASE_DIR%"
set "RELAY_BASE=%RELAY_BASE%"
set "CLIENT_UUID=%CLIENT_UUID%"
set "CLIENT_PSK=%CLIENT_PSK%"
set "SERVER_UUID=%SERVER_UUID%"

REM Use bundled python if present
set "PY_EXE=%BASE_DIR%\tools\python\python.exe"
if exist "%PY_EXE%" (
  "%PY_EXE%" -u "agents\client\client_agent.py"
) else (
  py -3 -u "agents\client\client_agent.py" 2>nul || python -u "agents\client\client_agent.py"
)
set "ERR=%ERRORLEVEL%"
popd

echo.
echo [INFO] client_agent exited with code %ERR%
echo.
pause
exit /b %ERR%
