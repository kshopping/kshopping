@echo off
setlocal EnableExtensions

REM ============================================================
REM GenieSecurity - RESET + Provision identity (ONE TIME)
REM Use only if you accidentally re-provisioned and KID changed.
REM ============================================================

set "RUN_DIR=%~dp0"
for %%I in ("%RUN_DIR%..") do set "BASE_DIR=%%~fI"

set "PY_EXE=%BASE_DIR%\tools\python\python.exe"
set "AGENT_PY=%BASE_DIR%\agents\server\server_agent.py"
set "ID_PATH=%BASE_DIR%\data\server_identity.dpapi"

net session >nul 2>&1
if not "%ERRORLEVEL%"=="0" (
  echo [ERROR] Run this in an Administrator CMD.
  pause
  exit /b 1
)

echo ============================================================
echo [BASE_DIR] %BASE_DIR%
echo [ID_PATH]  %ID_PATH%
echo ============================================================

if exist "%ID_PATH%" (
  echo [STEP 1/2] Deleting existing identity file...
  del /f /q "%ID_PATH%"
)

echo [STEP 2/2] Provisioning new identity...
pushd "%BASE_DIR%"
"%PY_EXE%" -u "%AGENT_PY%" --provision-identity
set "ERR=%ERRORLEVEL%"
popd

echo.
echo [INFO] provision exited with code %ERR%
echo.
pause
exit /b %ERR%
