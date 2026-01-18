@echo off
setlocal

REM =====================================================
REM GenieSecurity Relay - SECURE (HTTPS+mTLS) - SINGLE PORT 3000
REM =====================================================

cd /d "%~dp0"
cd /d ".."

REM --- force port ---
set PORT=3000
set RELAY_BIND_HOST=0.0.0.0

REM --- enable HTTPS + mTLS ---
set TLS_KEY_PATH=certs\relay.key
set TLS_CERT_PATH=certs\relay.pem
set TLS_CA_PATH=certs\ca.pem
set MTLS_REQUIRE=1

REM --- secure proxy policy (default) ---
set TRUST_PROXY=0
set REQUIRE_VALID_CLIENT_IP=true
set ALLOW_PRIVATE_IP_CLIENT=false

echo [GenieSecurity] Relay SECURE (mTLS) starting...
echo [GenieSecurity] Expect: https://127.0.0.1:3000
node relay\server.cjs

pause
endlocal

