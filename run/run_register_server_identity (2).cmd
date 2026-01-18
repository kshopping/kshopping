@echo off
setlocal EnableExtensions

REM ============================================================
REM GenieSecurity - Provision server identity into Relay Registry (Product)
REM Fix for: HTTP 403 / server_missing_identity
REM ============================================================

set "RUN_DIR=%~dp0"
for %%I in ("%RUN_DIR%..") do set "BASE_DIR=%%~fI"

set "PY_EXE=%BASE_DIR%\tools\python\python.exe"
set "TOOL_PY=%BASE_DIR%\run\register_server_identity.py"

if "%RELAY_BASE%"=="" set "RELAY_BASE=http://127.0.0.1:3000"
if "%SERVER_UUID%"=="" set "SERVER_UUID=serverUuidA"

echo ============================================================
echo [RUNNING_CMD] %~f0
echo [BASE_DIR]    %BASE_DIR%
echo [PY_EXE]      %PY_EXE%
echo [TOOL_PY]     %TOOL_PY%
echo [ENV] RELAY_BASE=%RELAY_BASE%
echo [ENV] SERVER_UUID=%SERVER_UUID%
echo ============================================================

if not exist "%PY_EXE%" (
  echo [ERROR] bundled python not found: %PY_EXE%
  pause
  exit /b 1
)

if not exist "%TOOL_PY%" (
  echo [ERROR] tool not found: %TOOL_PY%
  pause
  exit /b 1
)

REM NOTE: Relay must be running for this to work.
echo.
echo [STEP] Calling relay APIs: register-intent -> approve-server ...
echo.

"%PY_EXE%" -u "%TOOL_PY%"
set "ERR=%ERRORLEVEL%"

echo.
echo [INFO] exited with code %ERR%
echo.
pause
exit /b %ERR%
