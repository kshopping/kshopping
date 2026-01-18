@echo off
setlocal

cd /d "%~dp0"
cd /d ".."

set RELAY_BASE=http://127.0.0.1:3000
set CLIENT_UUID=clientUuidA
set CLIENT_PSK=clientPskDummy
set CLIENT_TOKEN=clientTokenDummy
set SERVER_UUID=serverUuidA
echo [GenieSecurity] Client INTERNAL (PoP)
python agents\client\client_agent.py

pause
endlocal

