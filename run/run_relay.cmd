@echo off
setlocal EnableExtensions

REM ============================================================
REM GenieSecurity Relay INTERNAL (HTTP) - Offline Product Mode (v2)
REM - No system Node.js required
REM - Uses bundled node.exe (tools\node\node.exe preferred)
REM - Uses bundled relay\node_modules (no npm install)
REM - Extra diagnostics printed for troubleshooting
REM ============================================================

REM Resolve base paths (BASE_DIR = parent of this file's folder)
set "RUN_DIR=%~dp0"
for %%I in ("%RUN_DIR%..") do set "BASE_DIR=%%~fI"

REM Paths
set "RELAY_DIR=%BASE_DIR%\relay"
set "SERVER_JS=%RELAY_DIR%\server.cjs"

REM Prefer node.exe under tools\node (your current layout)
set "NODE_EXE=%BASE_DIR%\tools\node\node.exe"

REM Fallback: standard bundled node\node.exe
if not exist "%NODE_EXE%" set "NODE_EXE=%BASE_DIR%\node\node.exe"

echo ============================================================
echo [RUNNING_CMD] %~f0
echo [THIS_DIR]    %RUN_DIR%
echo [BASE_DIR]    %BASE_DIR%
echo [RELAY_DIR]   %RELAY_DIR%
echo [SERVER_JS]   %SERVER_JS%
echo [NODE_EXE]    %NODE_EXE%
echo [CWD]         %CD%
echo [EXPECT]      http://127.0.0.1:3000
echo ============================================================

REM Validate node.exe
if not exist "%NODE_EXE%" (
  echo.
  echo [ERROR] Bundled node.exe not found.
  echo         Expected one of:
  echo         - %BASE_DIR%\tools\node\node.exe
  echo         - %BASE_DIR%\node\node.exe
  echo.
  echo [ACTION] Confirm the zip contains tools\node\node.exe and you are running this from GenieSecurity\run\
  echo.
  pause
  exit /b 1
)

REM Validate relay server entry
if not exist "%SERVER_JS%" (
  echo.
  echo [ERROR] relay entry not found: %SERVER_JS%
  echo.
  echo [ACTION] You likely ran the cmd from the wrong folder.
  echo         Put this file at: GenieSecurity\run\run_relay.cmd
  echo.
  pause
  exit /b 1
)

REM Optional env defaults (keep existing behavior)
if "%REQUIRE_VALID_CLIENT_IP%"=="" (
  set "REQUIRE_VALID_CLIENT_IP=false"
)
REM Seed client registry (NO DELETE) - required for /api/client/request-access PoP
set "SEED_CLIENTS=1"
set "SEED_CLIENT_ENTRIES=clientUuidA:clientPskDummy"
echo.
echo [INFO] REQUIRE_VALID_CLIENT_IP=%REQUIRE_VALID_CLIENT_IP%
echo.

REM Run relay with relay as working directory (so relative paths work)
set "ENV_FILE=%BASE_DIR%\config\.env.internal"
REM Force absolute data paths (avoid relay\relay\data path bug)
set "DATA_DIR=%RELAY_DIR%\data"
set "REGISTRY_PATH=%RELAY_DIR%\data\registry.json"
set "SESSIONS_PATH=%RELAY_DIR%\data\sessions.json"
set "AUDIT_LOG_PATH=%RELAY_DIR%\data\audit.jsonl"

pushd "%RELAY_DIR%"
echo [INFO] Starting relay...
"%NODE_EXE%" "%SERVER_JS%"
set "ERR=%ERRORLEVEL%"
popd

echo.
echo [INFO] Relay process exited with code %ERR%
echo.

pause
exit /b %ERR%
