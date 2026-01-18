# client_agent.py
import requests
import sys
import time
import socket
import os
import random
import json


# =========================
# TLS / mTLS (제품급)
# - RELAY_BASE 가 https:// 일 때 사용
# - self-signed 운영이면 TLS_CA_BUNDLE 지정 권장
# - mTLS 운영이면 MTLS_CERT_PATH + MTLS_KEY_PATH 지정
# =========================
TLS_CA_BUNDLE = os.environ.get("TLS_CA_BUNDLE", "").strip()  # CA cert (PEM)
MTLS_CERT_PATH = os.environ.get("MTLS_CERT_PATH", "").strip()  # client cert (PEM)
MTLS_KEY_PATH = os.environ.get("MTLS_KEY_PATH", "").strip()    # client key (PEM)
INSECURE_SKIP_VERIFY = os.environ.get("INSECURE_SKIP_VERIFY", "0").strip() in ["1", "true", "yes", "on"]

def _requests_kwargs():
    kw = {}
    # verify
    if INSECURE_SKIP_VERIFY:
        kw["verify"] = False
    elif TLS_CA_BUNDLE:
        kw["verify"] = TLS_CA_BUNDLE
    # cert (mTLS)
    if MTLS_CERT_PATH and MTLS_KEY_PATH:
        kw["cert"] = (MTLS_CERT_PATH, MTLS_KEY_PATH)
    return kw


# =========================
#  제품급 기본값 (환경변수로 오버라이드 가능)
# =========================
POLL_INTERVAL_SEC = int(os.environ.get("POLL_INTERVAL_SEC", "3"))
POLL_MAX_SEC = int(os.environ.get("POLL_MAX_SEC", "180"))          # 최대 3분
TCP_TIMEOUT_SEC = int(os.environ.get("TCP_TIMEOUT_SEC", "2"))
TCP_RETRY = int(os.environ.get("TCP_RETRY", "10"))
TCP_RETRY_INTERVAL_SEC = int(os.environ.get("TCP_RETRY_INTERVAL_SEC", "2"))
HTTP_TIMEOUT_SEC = int(os.environ.get("HTTP_TIMEOUT_SEC", "10"))

# ==========================
# Device Fingerprint (v1)
# - Used for optional allowlist enforcement on Relay
# - Stable-ish: based on hostname + OS + MAC + python version
# ==========================
def get_device_fingerprint():
    try:
        import platform as _pf
        import uuid as _uuid
        import hashlib as _hashlib
        raw = "|".join([
            _pf.node() or "",
            _pf.system() or "",
            _pf.release() or "",
            _pf.machine() or "",
            hex(_uuid.getnode()),
            _pf.python_version() or "",
        ]).encode("utf-8", "ignore")
        fp_hex = _hashlib.sha256(raw).hexdigest()
        info = {
            "host": _pf.node(),
            "os": _pf.system(),
            "osRelease": _pf.release(),
            "arch": _pf.machine(),
        }
        return fp_hex, info
    except Exception:
        return "unknown", {}

#  UX (D): IP 변경/차단/실패 시 자동 재요청
#  필드 정답 적용:
# - request-access는 1회만 생성 (세션 폭증 방지)
# - 이후는 같은 sessionId를 재사용 (polling + connect retry)
# - 새 request-access는 자동으로 하지 않음 (필요 시 사용자가 재실행)
MAX_SESSION_ATTEMPTS = int(os.environ.get("MAX_SESSION_ATTEMPTS", "5"))          # (호환 유지용 - 더 이상 request-access 재호출 안함)
RETRY_BACKOFF_BASE_SEC = int(os.environ.get("RETRY_BACKOFF_BASE_SEC", "2"))      # 2s
RETRY_BACKOFF_MAX_SEC = int(os.environ.get("RETRY_BACKOFF_MAX_SEC", "25"))       # 최대 25s
RETRY_JITTER_SEC = int(os.environ.get("RETRY_JITTER_SEC", "2"))                  # 랜덤 지터 0~2s
RETRY_ON_BLOCKED = os.environ.get("RETRY_ON_BLOCKED", "true").strip().lower() in ["1", "true", "yes", "on"]

#  (C) 포트/토큰 사용자 노출 최소화
SHOW_PORT_TO_USER = os.environ.get("SHOW_PORT_TO_USER", "false").strip().lower() in ["1", "true", "yes", "on"]
SHOW_DEBUG = os.environ.get("SHOW_DEBUG", "false").strip().lower() in ["1", "true", "yes", "on"]

#  CONNECT TEST precheck (방화벽 OPEN 전) - 실패해도 계속 진행
PRECHECK_TCP_TIMEOUT_SEC = int(os.environ.get("PRECHECK_TCP_TIMEOUT_SEC", "1"))
PRECHECK_TCP_RETRY = int(os.environ.get("PRECHECK_TCP_RETRY", "2"))
PRECHECK_TCP_INTERVAL_SEC = int(os.environ.get("PRECHECK_TCP_INTERVAL_SEC", "1"))

#  Connect test target
TARGET_HOST = os.environ.get("TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "3389"))  # 예: RDP 3389 / SSH 22 / HTTP 80 등

#  Relay endpoint (기본값 3000)
RELAY_BASE = os.environ.get("RELAY_BASE", "http://127.0.0.1:3000")

#  Client identity
CLIENT_UUID = os.environ.get("CLIENT_UUID", "clientUuidA")
CLIENT_TOKEN = os.environ.get("CLIENT_TOKEN", "clientTokenDummy")  # v1에서는 토큰 검증이 단순
SERVER_UUID = os.environ.get("SERVER_UUID", "serverUuidA")

#  E2E Mode: input/pause 스킵 (자동화용)
E2E_MODE = os.environ.get("E2E_MODE", "0").strip() == "1"


# =========================
# utils
# =========================
def dbg(*args):
    if SHOW_DEBUG:
        print("[DEBUG]", *args)


def maybe_pause(msg="\n계속하려면 아무 키나 누르십시오 . . ."):
    """
    제품급:
    - E2E_MODE=1 이면 절대 입력 대기하지 않음(자동화 멈춤 방지)
    - 일반 실행이면 기존대로 input 대기
    """
    if E2E_MODE:
        return
    try:
        input(msg)
    except Exception:
        # 콘솔/인코딩 등 예외여도 멈추지 않게
        return


def api_post(path, payload):
    url = RELAY_BASE.rstrip("/") + path
    try:
        r = requests.post(url, json=payload, timeout=HTTP_TIMEOUT_SEC, **_requests_kwargs())
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def api_get(path):
    url = RELAY_BASE.rstrip("/") + path
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT_SEC, **_requests_kwargs())
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def safe_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def backoff_sleep(attempt):
    # attempt: 1..N
    base = RETRY_BACKOFF_BASE_SEC * (2 ** max(0, attempt - 1))
    base = min(base, RETRY_BACKOFF_MAX_SEC)
    jitter = random.randint(0, max(0, RETRY_JITTER_SEC))
    t = base + jitter
    time.sleep(t)


def tcp_probe(host, port, timeout_sec):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_sec)
    try:
        t0 = time.time()
        s.connect((host, port))
        t1 = time.time()
        s.close()
        return True, int((t1 - t0) * 1000), None
    except Exception as e:
        try:
            s.close()
        except Exception:
            pass
        return False, None, str(e)


# =========================
# Relay API wrappers
# =========================
def request_access(client_uuid, client_token, server_uuid):
    fp, fpInfo = get_device_fingerprint()
    payload = {
        "clientUuid": client_uuid,
        "clientToken": client_token,
        "serverUuid": server_uuid,
        "deviceFingerprint": fp,
        "deviceInfo": fpInfo
    }
    return api_post("/api/client/request-access", payload)


#  [P11] IP_CHANGED 발생 시에만 1회 새 세션 생성 재요청(폭증 방지 유지)
def request_access_with_ip_changed_retry(client_uuid, client_token, server_uuid):
    # 기본: 1회 요청
    code, txt = request_access(client_uuid, client_token, server_uuid)
    js = safe_json(txt) if isinstance(txt, str) else None

    # 성공이면 그대로 반환
    if code == 200 and js and js.get("ok") is True:
        return code, txt

    # 실패인데 IP_CHANGED인 경우에만 1회 추가 요청
    err = None
    if js and isinstance(js, dict):
        err = js.get("error")

    if err == "IP_CHANGED":
        print("[WARN] IP_CHANGED 감지됨. 폭증 방지 정책 유지: 1회만 새 세션 생성 재요청합니다...")
        time.sleep(1)
        code2, txt2 = request_access(client_uuid, client_token, server_uuid)
        return code2, txt2

    return code, txt


def get_session(session_id):
    return api_get(f"/api/session/{session_id}")


def report_client_event(event_type, meta):
    """
    재요청/재시도 같은 UX 이벤트를 relay audit에 남기기 위한 단순 endpoint를 쓰고 싶지만,
    v1 코드에 해당 endpoint가 없을 수 있음.
    그래서 안전하게 /api/client/report-event 를 시도하고 실패해도 무시하는 방식.
    """
    payload = {
        "clientUuid": CLIENT_UUID,
        "clientToken": CLIENT_TOKEN,
        "eventType": event_type,
        "meta": meta
    }
    code, text = api_post("/api/client/report-event", payload)
    # endpoint가 없으면 404일 수 있음 → 무시
    dbg("report_event", code, text[:200] if isinstance(text, str) else text)


def report_connect_test(client_uuid, client_token, result, reason=None, latency_ms=None,
                        target_host=None, target_port=None, assigned_port=None):
    payload = {
        "clientUuid": client_uuid,
        "clientToken": client_token,
        "result": result,
        "reason": reason,
        "latencyMs": latency_ms,
        "targetHost": target_host,
        "targetPort": target_port,
        "assignedPort": assigned_port
    }
    return api_post("/api/client/report-connect-test", payload)


# =========================
# session polling helpers
# =========================
def wait_for_status(session_id, wanted_statuses, exit_statuses, label="status"):
    """
    - session 상태를 폴링하면서 wanted_statuses면 True 반환
    - exit_statuses면 False 반환
    - 타임아웃이면 False 반환
    """
    t0 = time.time()
    last_status = None
    last_port = None

    while True:
        if time.time() - t0 > POLL_MAX_SEC:
            return False, last_status, last_port

        code, txt = get_session(session_id)
        js = safe_json(txt) if isinstance(txt, str) else None
        if code != 200 or not js or not js.get("ok"):
            time.sleep(POLL_INTERVAL_SEC)
            continue

        s = js.get("session", {})
        st = s.get("status")
        ap = s.get("assignedPort")
        last_status = st
        last_port = ap

        if st in wanted_statuses:
            return True, st, ap

        if st in exit_statuses:
            return False, st, ap

        time.sleep(POLL_INTERVAL_SEC)


# =========================
#  필드 정답: request-access는 1회만 생성
# =========================
def create_session_once():
    """
    request-access는 단 1회만 호출한다.
    - ok면 sessionId 반환
    - 실패면 종료(필요 시 사용자가 다시 실행)
    """
    code, txt = request_access_with_ip_changed_retry(CLIENT_UUID, CLIENT_TOKEN, SERVER_UUID)
    js = safe_json(txt) if isinstance(txt, str) else None

    if code == 200 and js and js.get("ok") is True:
        sid = js.get("sessionId")
        status = js.get("status")
        autoApproved = js.get("autoApproved", False)
        expiresAt = js.get("expiresAt")
        return True, {
            "sessionId": sid,
            "status": status,
            "autoApproved": autoApproved,
            "expiresAt": expiresAt
        }

    err = None
    if js and isinstance(js, dict):
        err = js.get("error")
    if not err:
        err = f"http_{code}"

    return False, {"error": err, "httpCode": code, "raw": txt}


# =========================
# Main Flow
# =========================
def main():
    print("\n==============================================")
    print(" GenieSecurity Client Agent (v1 UX) ")
    print(" - 서버 선택 → 접속 버튼만 누르게 설계")
    print(" - 포트/토큰 숨김 (기본)")
    print(" - 필드 정답 적용: request-access는 1회만 생성, 같은 세션 재사용")
    print("==============================================\n")

    print(f"Relay Base: {RELAY_BASE}")
    print(f"Target Host: {TARGET_HOST}")
    print(f"Server UUID: {SERVER_UUID}")
    print(f"Client UUID: {CLIENT_UUID}")

    #  1) request-access는 단 1회만
    print("\n 접속 시작...")
    ok, resp = create_session_once()
    if not ok:
        httpCode = resp.get("httpCode", 0)
        err = resp.get("error", "unknown")
        print(f" request-access 실패: http={httpCode} error={err}")

        if httpCode == 403:
            if not RETRY_ON_BLOCKED:
                print(" 서버가 차단(403)했고 RETRY_ON_BLOCKED=false 이므로 종료합니다.")
            else:
                print(" 서버가 차단(403)했습니다. (필드 정답 정책상 새 세션 자동 생성 금지) 다시 실행해주세요.")

        maybe_pause()
        return

    # ✅ E2E: request-access만 하고 즉시 종료 (e2e_test timeout 방지)
    if os.environ.get("E2E_REQUEST_ONLY", "0").strip() == "1":
        sid = resp["sessionId"]
        print(f"[E2E_REQUEST_ONLY_OK] sessionId={sid}")
        return

    session_id = resp["sessionId"]
    status = resp["status"]
    autoApproved = resp["autoApproved"]

    print("\n 접속 요청 완료. (세션 생성됨)")
    if autoApproved:
        print(" 자동 승인(Whitelist 조합) 적용됨. 잠시 후 자동 연결을 시도합니다.")
    else:
        print(" 운영자 승인 대기 중... (Dashboard에서 OPEN 승인 필요)")
    print(f"   sessionId = {session_id}")

    # audit에 남기기(엔드포인트 없을 수 있으므로 실패해도 무시)
    try:
        report_client_event("CLIENT_SESSION_CREATED", {
            "sessionId": session_id,
            "autoApproved": autoApproved,
            "status": status
        })
    except Exception:
        pass

    # 2) OPENED 될 때까지 같은 sessionId로만 기다림
    ok_opened, st, assigned_port = wait_for_status(
        session_id=session_id,
        wanted_statuses={"OPENED"},
        exit_statuses={"REJECTED", "EXPIRED"},
        label="OPENED"
    )
    if not ok_opened:
        print(f" 승인 대기 실패/종료: status={st}")
        print(" (필드 정답) 새 PENDING 자동 생성하지 않습니다. 필요하면 다시 실행하세요.")
        maybe_pause()
        return

    print(" 승인됨. 연결 준비 중...")

    #  3) PRECHECK TCP (방화벽 OPEN 전) - 실패해도 계속
    target_host = TARGET_HOST
    target_port = TARGET_PORT

    for _ in range(PRECHECK_TCP_RETRY):
        okp, latency, reason = tcp_probe(target_host, target_port, PRECHECK_TCP_TIMEOUT_SEC)
        if okp:
            dbg(f"PRECHECK OK latency={latency}ms")
            break
        else:
            dbg(f"PRECHECK fail: {reason}")
            time.sleep(PRECHECK_TCP_INTERVAL_SEC)

    #  4) server.cjs 현재 구조상 FIREWALL_OPEN 상태가 없을 수 있으므로
    #    OPENED 이후 바로 assignedPort로 CONNECT TEST 수행 (세션 폭증 방지)
    test_port = assigned_port
    if not test_port:
        # 혹시 assignedPort가 안 내려오면 session detail을 한번 더 읽어서 확보
        code, txt = get_session(session_id)
        js = safe_json(txt) if isinstance(txt, str) else None
        if code == 200 and js and js.get("ok"):
            s = js.get("session", {})
            test_port = s.get("assignedPort")

    if not test_port:
        print(" assignedPort를 가져오지 못했습니다.")
        maybe_pause()
        return

    #  사용자에게 포트 숨김
    if SHOW_PORT_TO_USER:
        print(f" 연결 시도 (port={test_port})")
    else:
        print(" 연결 시도 중...")

    #  5) CONNECT TEST (같은 세션에서만 재시도)
    okc = False
    last_reason = None
    last_latency = None

    for _ in range(TCP_RETRY):
        okc, latency, reason = tcp_probe(target_host, int(test_port), TCP_TIMEOUT_SEC)
        if okc:
            last_latency = latency
            last_reason = None
            break
        last_reason = reason
        time.sleep(TCP_RETRY_INTERVAL_SEC)

    if okc:
        print(" 접속 성공 (CONNECT_TEST_OK)")
        code, text = report_connect_test(
            CLIENT_UUID, CLIENT_TOKEN,
            result="OK",
            reason=None,
            latency_ms=last_latency,
            target_host=target_host,
            target_port=int(test_port),
            assigned_port=int(test_port)
        )
        dbg("report_connect_test OK:", code, text[:200] if isinstance(text, str) else text)
        print("\n 완료: Dashboard Audit에서 CONNECT_TEST_OK 확인 가능합니다.")
        maybe_pause()
        return

    # FAIL (세션 재사용 정책)
    print(" 접속 실패 (CONNECT_TEST_FAIL)")
    code, text = report_connect_test(
        CLIENT_UUID, CLIENT_TOKEN,
        result="FAIL",
        reason=last_reason,
        latency_ms=None,
        target_host=target_host,
        target_port=int(test_port),
        assigned_port=int(test_port)
    )
    dbg("report_connect_test FAIL:", code, text[:200] if isinstance(text, str) else text)

    print("\n (필드 정답) 새 PENDING 자동 생성하지 않습니다.")
    print("   - 같은 sessionId로 운영자가 상태/방화벽을 확인하세요.")
    print("   - 필요하면 client_agent를 다시 실행해서 새 세션을 수동으로 생성하세요.")
    maybe_pause()


if __name__ == "__main__":
    main()
