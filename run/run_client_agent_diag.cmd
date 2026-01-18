@echo off
setlocal EnableExtensions

REM ============================================================
REM GenieSecurity Client Agent - Python Diagnostic (Offline)
REM ============================================================

set "RUN_DIR=%~dp0"
for %%I in ("%RUN_DIR%..") do set "BASE_DIR=%%~fI"

set "PY_EXE=%BASE_DIR%\tools\python\python.exe"
set "PY_DLL=%BASE_DIR%\tools\python\python312.dll"
set "AGENT_PY=%BASE_DIR%\agents\client\client_agent.py"

echo ============================================================
echo [BASE_DIR]  %BASE_DIR%
echo [PY_EXE]    %PY_EXE%
echo [PY_DLL]    %PY_DLL%
echo [AGENT_PY]  %AGENT_PY%
echo [CWD]       %CD%
echo ============================================================

echo.
echo [1] File existence check
if exist "%PY_EXE%" (echo  OK: python.exe exists) else (echo  FAIL: python.exe missing)
if exist "%PY_DLL%" (echo  OK: python312.dll exists) else (echo  FAIL: python312.dll missing)
if exist "%AGENT_PY%" (echo  OK: client_agent.py exists) else (echo  FAIL: client_agent.py missing)

echo.
echo [2] Run python.exe --version
"%PY_EXE%" --version
echo [ERRORLEVEL] %ERRORLEVEL%

echo.
echo [3] Run simple -c test
"%PY_EXE%" -c "import sys; print('executable=',sys.executable); print('version=',sys.version)"
echo [ERRORLEVEL] %ERRORLEVEL%

echo.
echo [4] Try running client_agent.py (prints first errors)
"%PY_EXE%" -u "%AGENT_PY%"
echo [ERRORLEVEL] %ERRORLEVEL%

echo.
pause
exit /b 0
