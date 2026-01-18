@echo off
setlocal

cd /d "%~dp0"
cd /d ".."

set RELAY_BASE=https://127.0.0.1:3000
set TLS_CA_BUNDLE=certs\ca.pem
set MTLS_CERT_PATH=certs\client.pem
set MTLS_KEY_PATH=certs\client.key

set CLIENT_UUID=clientUuidA
set CLIENT_PSK=clientPskDummy
set CLIENT_TOKEN=clientTokenDummy
set SERVER_UUID=serverUuidA

echo [GenieSecurity] Client SECURE (mTLS)
python agents\client\client_agent.py

pause
endlocal

