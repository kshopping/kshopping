import requests
import time
import subprocess
import sys
import os
import json
import base64
import secrets
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

# ============================================================
# GenieSecurity / NewIVSecret Dashboard - server_agent.py
# P6: Remote IP whitelist Windows Firewall 룰 완성 (제품급 / 최종 확정판)
# P7:  Fail-Block 강화 (룰 실패/remoteip 누락/예외 발생 즉시 차단 + CLOSE_ENFORCED)
#
#  규칙
# - Windows 명령은 CMD(netsh) 기준
# - 민감정보는 환경변수 우선 (운영 토큰은 DPAPI로 저장/로드)
# - 항상 전체 파일 100% 제공
# - 작업은 1개씩 안전하게
# - 검증은 .cmd로
#
#  기본값 우선순위(최종)
# 1) 환경변수 SERVER_UUID / SERVER_TOKEN
# 2) registry.json에서 serverUuid 자동 추출 (UUID-only)
# 3) last_inputs.json에서 serverUuid 자동 추출 (UUID-only)
# 4) 수동 입력
#
#  (추가) 상품화 필수:
# - 관리자 권한이 아니면 자동으로 UAC 상승(runAs) 후 재실행
#
#  (추가) 제품급 보완:
# - OPEN 직후 remoteip=clientIp 실제 적용 여부 verify
# - PAUSE_ON_EXIT=1일 때만 Enter pause
#
#  PATCH (2026-01-12)
# - UNATTENDED=1: 입력 프롬프트 없이 무인 실행 + 승인 전(409 no_consumable_opened_session) 폴링 대기
#
#  운영 보안 패치 (중요)
# - last_inputs.json 에 SERVER_TOKEN 평문 저장 금지 (UUID만 저장)
# - SERVER_TOKEN은 DPAPI로만 저장/로드 (data\server_token.dpapi)
# - DEFAULT_SERVER_TOKEN 같은 디폴트 토큰 제거
#
#  운영 경로 패치 (중요)
# - REGISTRY_PATH env가 안 먹히는 현상 대비:
#   (1) env가 있으면 그걸 사용
#   (2) 없으면 <project_root>\relay\data\registry.json 자동 탐색 (정본)
#   (3) 마지막으로 legacy 경로 agents\relay_server\data\registry.json
#
#  PATCH (2026-01-12-2)
# - 무인/제품화용 DPAPI 토큰 프로비저닝 옵션 추가(프롬프트 0, UAC 없이 가능)
#   --store-token : env SERVER_TOKEN을 data\server_token.dpapi로 저장 후 종료
#   --clear-token : data\server_token.dpapi 삭제 후 종료
#   --token-status: DPAPI 토큰 존재 여부 출력 후 종료
#
#  PATCH (2026-01-12-3)  [Step A-1 Service Mode]
# - --service : Windows Service(pywin32) 구동 모드
#   - 콘솔 입력/프롬프트/PAUSE 금지
#   - 파일 로그(logs\server_agent.log)만 사용
#   - service stop event 감지 시 Always-Closed cleanup 후 정상 종료
#   - 경로는 프로젝트 루트 기준 고정(서비스 실행 상태가 env에 의존하지 않도록)
#
#  PATCH (2026-01-12-4)  [Step A-1 FIX]
# - --service 는 "절대 종료하지 않고" 메인 루프를 돈다.
#   - (토큰 없음/릴레이 장애/예외) => exit 금지, 로그 후 대기/재시도
#   - 한 세션 OPEN->CLOSE 완료 후 다음 승인 대기 루프로 복귀
# ============================================================

# =========================
# ENV (stable)
# =========================
RELAY_BASE = os.environ.get("RELAY_BASE", "http://127.0.0.1:3000").strip()

# ==========================
# Device Fingerprint (v1)
# - Sent with every agent->relay request (optional allowlist enforcement)
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

FIREWALL_OPEN_SEC = int(os.environ.get("FIREWALL_OPEN_SEC", "180"))

# DRY_RUN=1이면 방화벽 명령 실제 실행 안함
DRY_RUN = os.environ.get("DRY_RUN", "0").strip().lower() in ["1", "true", "yes", "on"]

# local audit log path (may be overridden in --service)
AUDIT_PATH = os.environ.get("AUDIT_PATH", os.path.join("data", "server_agent.audit.jsonl")).strip()

# last inputs (UUID만 저장) (may be overridden in --service)
LAST_INPUTS_PATH = os.environ.get("LAST_INPUTS_PATH", os.path.join("data", "server_agent.last_inputs.json")).strip()

# Current approved session snapshot for local hooks (e.g., SSH command guard)
CURRENT_SESSION_PATH = os.environ.get("CURRENT_SESSION_PATH", os.path.join("data", "current_session.json")).strip()
# Optional policy path to export command deny/allow lists
POLICY_PATH = os.environ.get("POLICY_PATH", os.path.join("data", "policy.json")).strip()

# 운영용: SERVER_TOKEN 평문 저장 금지 → DPAPI로 암호화 저장/로드 (may be overridden in --service)
SERVER_TOKEN_DPAPI_PATH = os.environ.get("SERVER_TOKEN_DPAPI_PATH", os.path.join("data", "server_token.dpapi")).strip()
SERVER_IDENTITY_DPAPI_PATH = os.environ.get("SERVER_IDENTITY_DPAPI_PATH", os.path.join("data", "server_identity.dpapi")).strip()
DPAPI_SCOPE = os.environ.get("DPAPI_SCOPE", "machine").strip().lower()  # "user"(default) or "machine"

# report retry
REPORT_RETRY = int(os.environ.get("REPORT_RETRY", "3"))
REPORT_RETRY_WAIT = float(os.environ.get("REPORT_RETRY_WAIT", "1.5"))

# firewall delete retry
FW_DELETE_RETRY = int(os.environ.get("FW_DELETE_RETRY", "5"))
FW_DELETE_RETRY_WAIT = float(os.environ.get("FW_DELETE_RETRY_WAIT", "1.0"))

# 기본 UUID
DEFAULT_SERVER_UUID = os.environ.get("DEFAULT_SERVER_UUID", "serverUuidA").strip()

# 납품 자동화: 기본은 pause 없음. 필요할 때만 켜기
PAUSE_ON_EXIT = os.environ.get("PAUSE_ON_EXIT", "0").strip().lower() in ["1", "true", "yes", "on"]

# 무인 실행(운영): 입력 프롬프트 없이 자동 대기/승인 감지
UNATTENDED = os.environ.get("UNATTENDED", "0").strip().lower() in ["1", "true", "yes", "on"]
CONFIRM_OPEN_POLL_INTERVAL_SEC = float(os.environ.get("CONFIRM_OPEN_POLL_INTERVAL_SEC", "2"))
CONFIRM_OPEN_STATUS_PRINT_SEC = float(os.environ.get("CONFIRM_OPEN_STATUS_PRINT_SEC", "10"))

# Extend 동기화 polling 주기 (초)
SESSION_POLL_INTERVAL_SEC = int(os.environ.get("SESSION_POLL_INTERVAL_SEC", "5"))

# Startup Sweep 옵션 (기본 ON)
STARTUP_SWEEP_ALL_RULES = os.environ.get("STARTUP_SWEEP_ALL_RULES", "1").strip().lower() in ["1", "true", "yes", "on"]

# =========================
# SERVICE MODE (Step A-1)
# =========================
SERVICE_MODE = False
SERVICE_LOG_PATH = None

# Stop signal (NO file flag): Windows named event
# - genie_service.py sets this event on service stop
SERVICE_STOP_EVENT_NAME = os.environ.get("SERVICE_STOP_EVENT", "Local\\GenieSecurityAgentStop")
SERVICE_STOP_EVENT_HANDLE = None

# service backoff
SERVICE_LOOP_IDLE_SEC = float(os.environ.get("SERVICE_LOOP_IDLE_SEC", "1.0"))
SERVICE_ERROR_BACKOFF_SEC = float(os.environ.get("SERVICE_ERROR_BACKOFF_SEC", "5.0"))
SERVICE_NOT_ADMIN_BACKOFF_SEC = float(os.environ.get("SERVICE_NOT_ADMIN_BACKOFF_SEC", "30.0"))
SERVICE_MISSING_TOKEN_BACKOFF_SEC = float(os.environ.get("SERVICE_MISSING_TOKEN_BACKOFF_SEC", "10.0"))

def _project_root():
    """
    ...\agents\server\server_agent.py -> project_root is 3 levels up
    """
    try:
        here = Path(__file__).resolve()
        return here.parents[2]
    except Exception:
        return Path(os.getcwd()).resolve()

def _init_service_paths():
    """
    Service 모드에서는 경로를 프로젝트 루트 기준으로 고정한다.
    (환경변수에 실행 상태가 의존하지 않도록)
    """
    global AUDIT_PATH, LAST_INPUTS_PATH, SERVER_TOKEN_DPAPI_PATH, SERVER_IDENTITY_DPAPI_PATH, SERVICE_LOG_PATH, DPAPI_SCOPE
    root = _project_root()
    AUDIT_PATH = str(root / "data" / "server_agent.audit.jsonl")
    LAST_INPUTS_PATH = str(root / "data" / "server_agent.last_inputs.json")
    SERVER_TOKEN_DPAPI_PATH = str(root / "data" / "server_token.dpapi")
    SERVER_IDENTITY_DPAPI_PATH = str(root / "data" / "server_identity.dpapi")
    DPAPI_SCOPE = "machine"  # Service 운영 정석
    SERVICE_LOG_PATH = str(root / "logs" / "server_agent.log")


def _init_stop_event():
    """Service stop 신호용 named event 핸들 준비 (파일 stop flag 사용 안 함)."""
    global SERVICE_STOP_EVENT_HANDLE
    if not SERVICE_MODE:
        return
    if SERVICE_STOP_EVENT_HANDLE is not None:
        return
    try:
        import win32event
        import win32con
        # Open existing event first (created by service). If missing, create as fallback.
        try:
            h = win32event.OpenEvent(win32con.SYNCHRONIZE, False, SERVICE_STOP_EVENT_NAME)
        except Exception:
            h = win32event.CreateEvent(None, 1, 0, SERVICE_STOP_EVENT_NAME)
        SERVICE_STOP_EVENT_HANDLE = h
        service_log("INFO", "stop_event_ready", {"name": SERVICE_STOP_EVENT_NAME})
    except Exception as e:
        SERVICE_STOP_EVENT_HANDLE = None
        service_log("ERROR", "stop_event_init_failed", {"name": SERVICE_STOP_EVENT_NAME, "error": safe_str(e)})

def _ensure_dir(path):
    try:
        if path:
            os.makedirs(path, exist_ok=True)
    except Exception:
        pass

def ensure_dir_for_file(path):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def service_log(level, msg, data=None):
    """
    Service 모드 파일 로그: logs\server_agent.log
    """
    try:
        if not SERVICE_LOG_PATH:
            return
        ensure_dir_for_file(SERVICE_LOG_PATH)
        rec = {
            "ts": now_iso(),
            "level": str(level or "INFO"),
            "msg": str(msg or ""),
        }
        if data is not None:
            rec["data"] = data
        with open(SERVICE_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass

def out_print(*args, **kwargs):
    """
    출력 라우팅:
    - Service 모드: 파일 로그로만 기록(콘솔 의존 제거)
    - 일반 모드: 기존 print 유지
    """
    try:
        msg = " ".join([str(a) for a in args])
    except Exception:
        msg = "(print encoding error)"
    if SERVICE_MODE:
        service_log("INFO", msg)
        return
    print(*args, **kwargs)

def should_stop_service():
    """
    service stop event가 signaled이면 stop 요청으로 판단 (NO file flag)
    """
    try:
        if not SERVICE_MODE:
            return False
        _init_stop_event()
        if not SERVICE_STOP_EVENT_HANDLE:
            return False
        import win32event
        import win32con
        rc = win32event.WaitForSingleObject(SERVICE_STOP_EVENT_HANDLE, 0)
        return (rc == win32con.WAIT_OBJECT_0)
    except Exception:
        return False
    return False

def _pick_registry_path():
    # 1) explicit env
    env = os.environ.get("REGISTRY_PATH", "").strip()
    if env:
        return os.path.normpath(env)

    # 2) canonical path: <project_root>\relay\data\registry.json
    try:
        here = Path(__file__).resolve()
        # ...\agents\server\server_agent.py -> project_root is 3 levels up
        project_root = here.parents[2]  # agents/server -> agents -> project_root
        cand1 = project_root / "relay" / "data" / "registry.json"
        if cand1.exists():
            return str(cand1)
        # even if missing, prefer this canonical path
        return str(cand1)
    except Exception:
        pass

    # 3) legacy path (older layout): agents\relay_server\data\registry.json
    try:
        here = Path(__file__).resolve()
        cand2 = (here.parent.parent / "relay_server" / "data" / "registry.json").resolve()
        if cand2.exists():
            return str(cand2)
        return str(cand2)
    except Exception:
        return os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "relay_server", "data", "registry.json"))

REGISTRY_PATH = _pick_registry_path()

# =========================
# STATE (safe cleanup)
# =========================
STATE = {
    "opened": False,
    "connected": False,
    "rule_name": None,
    "assigned_port": None,
    "client_ip": None,
    "server_uuid": None,
    "server_token": None,
}

def reset_state():
    STATE["opened"] = False
    STATE["rule_name"] = None
    STATE["assigned_port"] = None
    STATE["client_ip"] = None
    # server_uuid/token은 유지하되, 세션 사이클마다 갱신 가능

# ============================================================
# Admin privilege (상품화 필수)
# ============================================================

def is_admin():
    """
    Windows 관리자 권한 여부 체크
    """
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_as_admin():
    """
    관리자 권한이 아니면 UAC 상승(runAs)으로 자기 자신 재실행
    - 성공 시 현재 프로세스 종료
    """
    try:
        import ctypes
        python_exe = sys.executable
        script_path = os.path.abspath(sys.argv[0])

        # 현재 args 유지
        args = [f'"{script_path}"']
        for a in sys.argv[1:]:
            args.append(f'"{a}"')
        params = " ".join(args)

        # runas => UAC prompt
        rc = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            python_exe,
            params,
            None,
            1
        )

        # rc > 32면 성공적으로 실행 요청됨
        if rc > 32:
            out_print(" 관리자 권한이 필요합니다. UAC 승인 후 관리자 모드로 다시 실행됩니다.")
            time.sleep(1)
            sys.exit(0)

        out_print("관리자 재실행(runAs) 실패. rc=", rc)
        return False
    except Exception as e:
        out_print("관리자 재실행(runAs) 예외:", str(e))
        return False

# ============================================================
# Args (제품화: 토큰 프로비저닝 + service mode)
# ============================================================

def parse_args(argv):
    """
    최소 파서 (보안/제품화)
    - --store-token : env SERVER_TOKEN을 DPAPI에 저장 후 종료
    - --clear-token : DPAPI 파일 삭제 후 종료
    - --token-status: DPAPI 토큰 존재 여부 출력 후 종료
    - --unattended  : 무인 실행
    - --service     : Windows Service 모드(콘솔/프롬프트/PAUSE 금지, 파일 로그 강제)
    - --provision-identity : 장기 서버 키(X25519) 생성 + DPAPI 저장 후 종료
    - --identity-status    : identity 파일 존재/상태 출력 후 종료
    - --clear-identity     : identity 파일 삭제 후 종료
    """
    flags = {
        "store_token": False,
        "clear_token": False,
        "token_status": False,
        "unattended": False,
        "service": False,
        "provision_identity": False,
        "identity_status": False,
        "clear_identity": False,
    }
    for a in (argv or []):
        t = str(a).strip().lower()
        if t == "--store-token":
            flags["store_token"] = True
        elif t == "--clear-token":
            flags["clear_token"] = True
        elif t == "--token-status":
            flags["token_status"] = True
        elif t == "--unattended":
            flags["unattended"] = True
        elif t == "--service":
            flags["service"] = True
        elif t == "--provision-identity":
            flags["provision_identity"] = True
        elif t == "--identity-status":
            flags["identity_status"] = True
        elif t == "--clear-identity":
            flags["clear_identity"] = True
    return flags

# ============================================================
# Utils
# ============================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ============================================================
# Current session snapshot (for local enforcement hooks)
# ============================================================

def _load_policy_command_lists():
    """Best-effort: load ssh command allow/deny lists from policy.json."""
    try:
        if not POLICY_PATH or not os.path.exists(POLICY_PATH):
            return None, None
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            pol = json.load(f)
        deny = pol.get("sshCommandDenylist") or pol.get("ssh_command_denylist")
        allow = pol.get("sshCommandAllowlist") or pol.get("ssh_command_allowlist")
        # normalize to list[str]
        deny = [str(x) for x in deny] if isinstance(deny, list) else None
        allow = [str(x) for x in allow] if isinstance(allow, list) else None
        return deny, allow
    except Exception as e:
        log_local("policy_cmdlist_load_fail", {"error": safe_str(e), "path": POLICY_PATH})
        return None, None

def write_current_session(session_id, assigned_port, client_ip, expires_at):
    """Write a local snapshot file so other local components can bind to SID."""
    try:
        if not CURRENT_SESSION_PATH:
            return False
        Path(os.path.dirname(CURRENT_SESSION_PATH)).mkdir(parents=True, exist_ok=True)
        deny, allow = _load_policy_command_lists()
        snap = {
            "sid": session_id,
            "assignedPort": assigned_port,
            "clientIp": client_ip,
            "expiresAt": expires_at,
            "openedAt": int(time.time()),
            "denylist": deny,
            "allowlist": allow,
        }
        with open(CURRENT_SESSION_PATH, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2)
        log_local("current_session_written", {"path": CURRENT_SESSION_PATH, "sid": session_id, "assignedPort": assigned_port})
        return True
    except Exception as e:
        log_local("current_session_write_fail", {"path": CURRENT_SESSION_PATH, "error": safe_str(e)})
        return False

def clear_current_session():
    try:
        if CURRENT_SESSION_PATH and os.path.exists(CURRENT_SESSION_PATH):
            os.remove(CURRENT_SESSION_PATH)
            log_local("current_session_cleared", {"path": CURRENT_SESSION_PATH})
            return True
        return False
    except Exception as e:
        log_local("current_session_clear_fail", {"path": CURRENT_SESSION_PATH, "error": safe_str(e)})
        return False

def now_sec():
    return int(time.time())

def safe_str(s, limit=500):
    t = str(s) if s is not None else ""
    if len(t) > limit:
        return t[:limit] + "..."
    return t

# ============================================================
# DPAPI token storage (운영용)
# ============================================================

def _dpapi_is_windows():
    return os.name == "nt"

def dpapi_encrypt(plaintext: str) -> bytes:
    if not _dpapi_is_windows():
        raise RuntimeError("DPAPI is only available on Windows")
    import ctypes
    from ctypes import wintypes

    CRYPTPROTECT_LOCAL_MACHINE = 0x4

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    data = plaintext.encode("utf-8")
    in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()

    flags = 0
    if DPAPI_SCOPE == "machine":
        flags |= CRYPTPROTECT_LOCAL_MACHINE

    if not crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, flags, ctypes.byref(out_blob)):
        raise ctypes.WinError()

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)

def dpapi_decrypt(ciphertext: bytes) -> str:
    if not _dpapi_is_windows():
        raise RuntimeError("DPAPI is only available on Windows")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    in_blob = DATA_BLOB(len(ciphertext), ctypes.cast(ctypes.create_string_buffer(ciphertext), ctypes.POINTER(ctypes.c_byte)))
    out_blob = DATA_BLOB()

    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise ctypes.WinError()

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData).decode("utf-8", errors="strict")
    finally:
        kernel32.LocalFree(out_blob.pbData)

def log_local(event, data=None):
    """
    로컬 audit jsonl 기록 (제품급)
    """
    try:
        ensure_dir_for_file(AUDIT_PATH)
        rec = {
            "ts": now_iso(),
            "event": event,
            "data": data or {}
        }
        with open(AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass

def load_token_dpapi():
    try:
        if not SERVER_TOKEN_DPAPI_PATH or not os.path.exists(SERVER_TOKEN_DPAPI_PATH):
            return None
        with open(SERVER_TOKEN_DPAPI_PATH, "rb") as f:
            blob = f.read()
        if not blob:
            return None
        token = dpapi_decrypt(blob).strip()
        return token or None
    except Exception as e:
        log_local("dpapi_load_fail", {"path": SERVER_TOKEN_DPAPI_PATH, "error": safe_str(e)})
        if SERVICE_MODE:
            service_log("ERROR", "dpapi_load_fail", {"path": SERVER_TOKEN_DPAPI_PATH, "error": safe_str(e)})
        return None

def save_token_dpapi(token: str):
    try:
        if not token:
            return False
        ensure_dir_for_file(SERVER_TOKEN_DPAPI_PATH)
        blob = dpapi_encrypt(token)
        with open(SERVER_TOKEN_DPAPI_PATH, "wb") as f:
            f.write(blob)
        log_local("dpapi_saved", {"path": SERVER_TOKEN_DPAPI_PATH, "scope": DPAPI_SCOPE})
        if SERVICE_MODE:
            service_log("INFO", "dpapi_saved", {"path": SERVER_TOKEN_DPAPI_PATH, "scope": DPAPI_SCOPE})
        return True
    except Exception as e:
        log_local("dpapi_save_fail", {"path": SERVER_TOKEN_DPAPI_PATH, "error": safe_str(e)})
        if SERVICE_MODE:
            service_log("ERROR", "dpapi_save_fail", {"path": SERVER_TOKEN_DPAPI_PATH, "error": safe_str(e)})
        return False

def clear_token_dpapi():
    try:
        if not SERVER_TOKEN_DPAPI_PATH:
            return False, "SERVER_TOKEN_DPAPI_PATH empty"
        if os.path.exists(SERVER_TOKEN_DPAPI_PATH):
            os.remove(SERVER_TOKEN_DPAPI_PATH)
            log_local("dpapi_cleared", {"path": SERVER_TOKEN_DPAPI_PATH})
            if SERVICE_MODE:
                service_log("INFO", "dpapi_cleared", {"path": SERVER_TOKEN_DPAPI_PATH})
            return True, "deleted"
        return True, "not_found"
    except Exception as e:
        log_local("dpapi_clear_fail", {"path": SERVER_TOKEN_DPAPI_PATH, "error": safe_str(e)})
        if SERVICE_MODE:
            service_log("ERROR", "dpapi_clear_fail", {"path": SERVER_TOKEN_DPAPI_PATH, "error": safe_str(e)})
        return False, str(e)



# -----------------------------
# Server Identity Proof (Long-term key) - DPAPI(machine) 정석
# -----------------------------
def _x25519_available():
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: F401
        return True
    except Exception:
        return False

def _ed25519_available():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
        return True
    except Exception:
        return False

def generate_server_identity():
    """
    Generate long-term server identity keys.
    - X25519: decrypt confirm-open KEM payload
    - Ed25519: server-only consumption signature (PoP) for consume-open (S-1)
    Returns (kid, x_pub_b64, x_priv_raw_b64, sig_pub_b64, sig_priv_raw_b64)
    """
    if not _x25519_available() or not _ed25519_available():
        raise RuntimeError("cryptography is required for X25519/Ed25519 identity generation")
    from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
    from cryptography.hazmat.primitives import serialization

    # X25519
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub = x_priv.public_key()
    x_priv_raw = x_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    x_pub_raw = x_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Ed25519
    s_priv = ed25519.Ed25519PrivateKey.generate()
    s_pub = s_priv.public_key()
    s_priv_raw = s_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    s_pub_raw = s_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    kid = time.strftime("%Y%m%d-") + secrets.token_hex(3)
    x_pub_b64 = base64.b64encode(x_pub_raw).decode("ascii")
    x_priv_raw_b64 = base64.b64encode(x_priv_raw).decode("ascii")
    sig_pub_b64 = base64.b64encode(s_pub_raw).decode("ascii")
    sig_priv_raw_b64 = base64.b64encode(s_priv_raw).decode("ascii")
    return kid, x_pub_b64, x_priv_raw_b64, sig_pub_b64, sig_priv_raw_b64

def save_identity_dpapi(kid: str, x_pub_b64: str, x_priv_raw_b64: str, sig_pub_b64: str, sig_priv_raw_b64: str):
    """
    Save identity to SERVER_IDENTITY_DPAPI_PATH.
    Private keys are DPAPI-protected blobs (never store plaintext private key bytes on disk).
    File schema:
      - version: idp.v2
      - x25519: pub + priv_dpapi
      - ed25519: sigPub + sigPriv_dpapi
    """
    try:
        if not SERVER_IDENTITY_DPAPI_PATH:
            return False, "SERVER_IDENTITY_DPAPI_PATH empty"
        ensure_dir_for_file(SERVER_IDENTITY_DPAPI_PATH)

        # DPAPI encrypt base64 strings of raw private keys
        x_blob = dpapi_encrypt(x_priv_raw_b64)
        s_blob = dpapi_encrypt(sig_priv_raw_b64)

        rec = {
            "version": "idp.v2",
            "kid": kid,
            "alg": "x25519-hkdf-aes256gcm",
            "pub": x_pub_b64,
            "priv_dpapi": base64.b64encode(x_blob).decode("ascii"),
            "sig_alg": "ed25519",
            "sigPub": sig_pub_b64,
            "sigPriv_dpapi": base64.b64encode(s_blob).decode("ascii"),
            "createdAt": now_iso(),
        }
        with open(SERVER_IDENTITY_DPAPI_PATH, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=2)

        log_local("identity_saved", {"path": SERVER_IDENTITY_DPAPI_PATH, "kid": kid, "scope": DPAPI_SCOPE, "version": "idp.v2"})
        if SERVICE_MODE:
            service_log("INFO", "identity_saved", {"path": SERVER_IDENTITY_DPAPI_PATH, "kid": kid, "scope": DPAPI_SCOPE, "version": "idp.v2"})
        return True, "saved"
    except Exception as e:
        log_local("identity_save_fail", {"path": SERVER_IDENTITY_DPAPI_PATH, "error": safe_str(e)})
        if SERVICE_MODE:
            service_log("ERROR", "identity_save_fail", {"path": SERVER_IDENTITY_DPAPI_PATH, "error": safe_str(e)})
        return False, str(e)

def load_identity_dpapi():
    """
    Load identity.
    Backward compatible:
      - idp.v1: X25519 only (no Ed25519 signer)
      - idp.v2: X25519 + Ed25519
    Returns (dict, status)
    dict keys:
      kid, alg, pub, priv_bytes,
      sig_alg, sig_pub, sig_priv_bytes (may be None for v1)
    """
    if not SERVER_IDENTITY_DPAPI_PATH or not os.path.exists(SERVER_IDENTITY_DPAPI_PATH):
        return None, "not_found"
    try:
        with open(SERVER_IDENTITY_DPAPI_PATH, "r", encoding="utf-8") as f:
            rec = json.load(f)

        # X25519
        xb = base64.b64decode(rec.get("priv_dpapi", ""))
        x_priv_raw_b64 = dpapi_decrypt(xb)
        x_priv_bytes = base64.b64decode(x_priv_raw_b64)

        out = {
            "version": rec.get("version"),
            "kid": rec.get("kid"),
            "alg": rec.get("alg"),
            "pub": rec.get("pub"),
            "priv_bytes": x_priv_bytes,
            "createdAt": rec.get("createdAt"),
        }

        # Ed25519 (optional)
        sig_pub = rec.get("sigPub")
        sig_priv_dpapi = rec.get("sigPriv_dpapi")
        if sig_pub and sig_priv_dpapi:
            sb = base64.b64decode(sig_priv_dpapi)
            s_priv_raw_b64 = dpapi_decrypt(sb)
            s_priv_bytes = base64.b64decode(s_priv_raw_b64)
            out["sig_alg"] = rec.get("sig_alg") or "ed25519"
            out["sig_pub"] = sig_pub
            out["sig_priv_bytes"] = s_priv_bytes
        else:
            out["sig_alg"] = None
            out["sig_pub"] = None
            out["sig_priv_bytes"] = None

        return out, "ok"
    except Exception as e:
        return None, safe_str(e)

def clear_identity_dpapi():
    try:
        if not SERVER_IDENTITY_DPAPI_PATH:
            return False, "SERVER_IDENTITY_DPAPI_PATH empty"
        if os.path.exists(SERVER_IDENTITY_DPAPI_PATH):
            os.remove(SERVER_IDENTITY_DPAPI_PATH)
            log_local("identity_cleared", {"path": SERVER_IDENTITY_DPAPI_PATH})
            if SERVICE_MODE:
                service_log("INFO", "identity_cleared", {"path": SERVER_IDENTITY_DPAPI_PATH})
            return True, "deleted"
        return True, "not_found"
    except Exception as e:
        log_local("identity_clear_fail", {"path": SERVER_IDENTITY_DPAPI_PATH, "error": safe_str(e)})
        if SERVICE_MODE:
            service_log("ERROR", "identity_clear_fail", {"path": SERVER_IDENTITY_DPAPI_PATH, "error": safe_str(e)})
        return False, str(e)

def mask_secret(s, head=6, tail=4):
    if not s:
        return ""
    t = str(s)
    if len(t) <= head + tail:
        return "*" * len(t)
    return t[:head] + "..." + t[-tail:]

def prompt_with_default(label, default_value, secret=False):
    """
    기본값이 있으면 엔터만 치면 기본값 사용.
    토큰은 기본값 표시 시 마스킹.
    (Service 모드에서는 절대 호출되면 안 됨)
    """
    if SERVICE_MODE:
        raise RuntimeError("prompt is not allowed in --service mode")
    if default_value:
        shown = mask_secret(default_value) if secret else default_value
        v = input(f"{label} (기본: {shown}) > ").strip()
        if v == "":
            return default_value
        return v
    else:
        return input(f"{label} > ").strip()

def print_banner():
    out_print("\n============================================================")
    out_print(" GenieSecurity - server_agent.py (P6 RemoteIP Final + P7 Fail-Block)")
    out_print("============================================================")
    out_print(f"  RELAY_BASE         = {RELAY_BASE}")
    out_print(f"  FIREWALL_OPEN_SEC  = {FIREWALL_OPEN_SEC}")
    out_print(f"  DRY_RUN            = {DRY_RUN}")
    out_print(f"  AUDIT_PATH         = {AUDIT_PATH}")
    out_print(f"  LAST_INPUTS_PATH   = {LAST_INPUTS_PATH}")
    out_print(f"  SERVER_TOKEN_DPAPI_PATH = {SERVER_TOKEN_DPAPI_PATH}")
    out_print(f"  DPAPI_SCOPE        = {DPAPI_SCOPE}")
    out_print(f"  REGISTRY_PATH      = {REGISTRY_PATH}")
    envp = os.environ.get("REGISTRY_PATH")
    if envp is not None:
        out_print(f"  REGISTRY_PATH(env) = {envp}")
    out_print(f"  PAUSE_ON_EXIT      = {PAUSE_ON_EXIT}")
    out_print(f"  UNATTENDED         = {UNATTENDED}")
    out_print(f"  CONFIRM_OPEN_POLL_INTERVAL_SEC = {CONFIRM_OPEN_POLL_INTERVAL_SEC}")
    out_print(f"  SESSION_POLL_INTERVAL_SEC = {SESSION_POLL_INTERVAL_SEC}")
    out_print(f"  STARTUP_SWEEP_ALL_RULES   = {STARTUP_SWEEP_ALL_RULES}")
    out_print(f"  IS_ADMIN           = {is_admin()}")
    if SERVICE_MODE:
        out_print(f"  SERVICE_MODE       = True")
        out_print(f"  SERVICE_LOG_PATH   = {SERVICE_LOG_PATH}")
        out_print(f"  SERVICE_STOP_EVENT = {SERVICE_STOP_EVENT_NAME}")
    out_print("============================================================\n")

def pause_if_enabled():
    if SERVICE_MODE:
        return
    if UNATTENDED:
        return
    if PAUSE_ON_EXIT:
        try:
            input("\nEnter 누르면 종료합니다 . . .")
        except Exception:
            pass

def run_cmd(args):
    """
    CMD(netsh) 실행. shell=False (보안)
    """
    try:
        proc = subprocess.run(args, capture_output=True, text=True, shell=False)
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        ok = (proc.returncode == 0)
        return ok, out, err, proc.returncode
    except Exception as e:
        return False, "", str(e), 999

def load_last_inputs():
    """운영용: last_inputs에는 UUID만 저장한다."""
    try:
        if not os.path.exists(LAST_INPUTS_PATH):
            return None
        with open(LAST_INPUTS_PATH, "r", encoding="utf-8") as f:
            obj = json.load(f)
        su = (obj.get("serverUuid") or "").strip()
        return su or None
    except Exception:
        return None

def save_last_inputs(server_uuid):
    """운영용: UUID만 저장 (토큰은 DPAPI로만 저장)."""
    try:
        ensure_dir_for_file(LAST_INPUTS_PATH)
        obj = {
            "savedAt": now_iso(),
            "serverUuid": server_uuid
        }
        with open(LAST_INPUTS_PATH, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        log_local("last_inputs_saved", {"path": LAST_INPUTS_PATH, "serverUuid": server_uuid})
    except Exception:
        pass

def load_registry_uuid_only():
    try:
        if not REGISTRY_PATH or not os.path.exists(REGISTRY_PATH):
            return None
        with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
            obj = json.load(f)

        if isinstance(obj, dict):
            servers = obj.get("servers")
            if isinstance(servers, list) and len(servers) > 0:
                first = servers[0]
                if isinstance(first, dict):
                    su = first.get("serverUuid") or first.get("server_uuid") or first.get("SERVER_UUID")
                    if su:
                        return str(su).strip()

            if isinstance(servers, dict):
                for k in servers.keys():
                    if k:
                        return str(k).strip()

            su = obj.get("serverUuid") or obj.get("server_uuid") or obj.get("SERVER_UUID")
            if su:
                return str(su).strip()

    except Exception:
        return None

    return None

# ============================================================
# HTTP
# ============================================================

# =========================
# TLS / mTLS (제품급)
# - RELAY_BASE 가 https:// 일 때 사용
# - self-signed 운영이면 TLS_CA_BUNDLE 지정 권장
# - mTLS 운영이면 MTLS_CERT_PATH + MTLS_KEY_PATH 지정
# =========================
TLS_CA_BUNDLE = os.environ.get("TLS_CA_BUNDLE", "").strip()  # CA cert (PEM)
MTLS_CERT_PATH = os.environ.get("MTLS_CERT_PATH", "").strip()  # client cert (PEM)
MTLS_KEY_PATH = os.environ.get("MTLS_KEY_PATH", "").strip()    # client key (PEM)
INSECURE_SKIP_VERIFY = os.environ.get("INSECURE_SKIP_VERIFY", "0").strip().lower() in ["1", "true", "yes", "on"]

def _requests_kwargs():
    kw = {}
    if INSECURE_SKIP_VERIFY:
        kw["verify"] = False
    elif TLS_CA_BUNDLE:
        kw["verify"] = TLS_CA_BUNDLE
    if MTLS_CERT_PATH and MTLS_KEY_PATH:
        kw["cert"] = (MTLS_CERT_PATH, MTLS_KEY_PATH)
    return kw

def http_post(path, payload, timeout=10):
    url = f"{RELAY_BASE}{path}"
    # attach device identity (optional allowlist)
    try:
        if isinstance(payload, dict) and "deviceFingerprint" not in payload:
            fp, info = get_device_fingerprint()
            payload = {**payload, "deviceFingerprint": fp, "deviceInfo": info}
    except Exception:
        pass
    r = requests.post(url, json=payload, timeout=timeout, **_requests_kwargs())
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"ok": False, "error": f"non-json response: {safe_str(r.text)}"}

def http_get(path, timeout=10):
    url = f"{RELAY_BASE}{path}"
    r = requests.get(url, timeout=timeout, **_requests_kwargs())
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"ok": False, "error": f"non-json response: {safe_str(r.text)}"}


def confirm_open(server_uuid, server_token=None):
    """
    Step2: SERVER_TOKEN 제거 → 공개키 기반 confirm-open
    - Relay /api/server/confirm-open 에 serverUuid + kid만 전송
    - Relay가 KEM 패키지(kem, challenge, mac) 반환
    - server_agent는 DPAPI(machine)로 보호된 X25519 priv로 복호화 + PoP(proof)로 consume-open 호출
    - 성공 시 기존 호환 형태로 {ok, sessionId, assignedPort, clientIp, expiresAt, extendCount} 리턴
    """
    try:
        ident, st = load_identity_dpapi()
        if not ident or st != "ok":
            return 403, {"ok": False, "error": "service_missing_identity"}

        kid = ident.get("kid")
        priv_bytes = ident.get("priv_bytes")
        sig_priv_bytes = ident.get("sig_priv_bytes")
        if not kid or not priv_bytes or not sig_priv_bytes:
            return 403, {"ok": False, "error": "service_missing_identity"}

        # 1) confirm-open(KEM 발급)
        code, resp = http_post(
            "/api/server/confirm-open",
            {"serverUuid": server_uuid, "kid": kid},
            timeout=12
        )
        if code != 200 or not isinstance(resp, dict) or not resp.get("ok", False):
            return code, resp

        kem = resp.get("kem") or {}
        challenge_b64 = resp.get("challenge") or ""
        mac_b64 = resp.get("mac") or ""

        eph_pub_b64 = kem.get("ephPub") or ""
        salt_b64 = kem.get("salt") or ""
        iv_b64 = kem.get("iv") or ""
        tag_b64 = kem.get("tag") or ""
        ct_b64 = kem.get("ct") or ""
        aad_b64 = kem.get("aad") or ""
        jti = None

        # 2) derive keys + verify mac + decrypt
        try:
            from cryptography.hazmat.primitives.asymmetric import x25519
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import hmac
            import hashlib

            eph_pub_raw = base64.b64decode(eph_pub_b64)
            if len(eph_pub_raw) != 32:
                return 500, {"ok": False, "error": "invalid_kem_eph_pub"}

            salt = base64.b64decode(salt_b64)
            iv = base64.b64decode(iv_b64)
            tag = base64.b64decode(tag_b64)
            ct = base64.b64decode(ct_b64)
            aad = base64.b64decode(aad_b64) if aad_b64 else b""

            priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
            pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_raw)
            shared = priv.exchange(pub)

            okm = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=salt,
                info=b"GenieSecurity.confirm-open.v2",
            ).derive(shared)
            key_enc = okm[:32]
            key_mac = okm[32:]

            expected_mac = hmac.new(
                key_mac,
                f"confirm-open:{challenge_b64}:{''}".encode("utf-8"),
                digestmod=hashlib.sha256
            ).digest()
            # 위 expected_mac은 jti를 알아야 완전 검증 가능 -> 복호화 후 jti 포함 payload에서 최종 검증한다.

            aesgcm = AESGCM(key_enc)
            plaintext = aesgcm.decrypt(iv, ct + tag, aad)
            payload = json.loads(plaintext.decode("utf-8"))

            jti = payload.get("jti") or ""
            if not jti:
                return 500, {"ok": False, "error": "missing_jti_in_payload"}

            # mac 최종 검증
            expected_mac2 = hmac.new(
                key_mac,
                f"confirm-open:{challenge_b64}:{jti}".encode("utf-8"),
                digestmod=hashlib.sha256
            ).digest()
            mac_in = base64.b64decode(mac_b64) if mac_b64 else b""
            if not (len(mac_in) == len(expected_mac2) and hmac.compare_digest(mac_in, expected_mac2)):
                return 403, {"ok": False, "error": "kem_mac_invalid"}

            # 3) consume-open (PoP) - S-1: Ed25519 signature proof (server-only consumption)
            try:
                from cryptography.hazmat.primitives.asymmetric import ed25519
                s_priv = ed25519.Ed25519PrivateKey.from_private_bytes(sig_priv_bytes)

                # Canonical message (must match relay verification)
                msg = ("GenieSecurity/consume-open/v1\n"
                       f"{server_uuid}\n"
                       f"{kid}\n"
                       f"{payload.get('sid') or payload.get('sessionId') or ''}\n"
                       f"{jti}\n"
                       f"{challenge_b64}\n").encode("utf-8")

                sig = s_priv.sign(msg)
                sig_b64 = base64.b64encode(sig).decode("ascii")
            except Exception as e:
                return 500, {"ok": False, "error": f"consume_sign_fail: {safe_str(e)}"}

            c2, r2 = http_post(
                "/api/server/consume-open",
                {"serverUuid": server_uuid, "kid": kid, "jti": jti, "challenge": challenge_b64, "sig": sig_b64},
                timeout=10
            )
            if c2 != 200 or not isinstance(r2, dict) or not r2.get("ok", False):
                return c2, r2

            # 4) 기존 호환 형태로 반환
            out = {
                "ok": True,
                "status": "OPENED",
                "assignedPort": payload.get("assignedPort"),
                "sessionId": payload.get("sid") or payload.get("sessionId"),
                "clientIp": payload.get("clientIp"),
                "expiresAt": payload.get("expiresAt") or payload.get("exp"),
                "extendCount": payload.get("extendCount") or 0,
            }
            return 200, out

        except Exception as e:
            return 500, {"ok": False, "error": f"kem_decrypt_fail: {safe_str(e)}"}

    except Exception as e:
        return 500, {"ok": False, "error": safe_str(e)}

def get_session(session_id):
    sid = str(session_id or "").strip()
    if not sid:
        return 400, {"ok": False, "error": "sessionId missing"}
    return http_get(f"/api/session/{sid}", timeout=8)

def fail_block(server_uuid, server_token, session_id, reason, meta=None):
    """
    Fail-Block 강화: 실패 즉시 Relay에 신고하여
    Relay가 세션 EXPIRED + CLOSE_ENFORCED enqueue하도록 강제
    """
    try:
        payload = {
        "serverUuid": server_uuid,
        **({"serverToken": server_token} if server_token else {}),
        "sessionId": session_id,
            "reason": reason,
            "meta": meta or {},
            "ts": now_iso()
        }
        log_local("fail_block_attempt", {"payload": {**payload, "serverToken": "(masked)"}})
        code, resp = http_post("/api/server/fail-block", payload, timeout=10)
        log_local("fail_block_response", {"code": code, "resp": resp})
        return True
    except Exception as e:
        log_local("fail_block_exception", {"error": safe_str(e)})
        return False

def report_firewall(server_uuid, server_token, event, session_id=None, assigned_port=None, rule_name=None, message=None, remote_ip=None):
    payload = {
        "serverUuid": server_uuid,
        **({"serverToken": server_token} if server_token else {}),
        "event": event,
        "sessionId": session_id,
        "assignedPort": assigned_port,
        "ruleName": rule_name,
        "message": message,
        "remoteIp": remote_ip,
        "ts": now_iso()
    }

    log_local("relay_report_attempt", {"event": event, "payload": {**payload, "serverToken": "(masked)"}})

    last_err = None
    for _ in range(REPORT_RETRY):
        try:
            code, resp = http_post("/api/server/report-firewall", payload, timeout=10)
            if code == 200 and isinstance(resp, dict) and resp.get("ok", False):
                log_local("relay_report_ok", {"event": event, "resp": resp})
                return True, resp
            last_err = f"code={code}, resp={safe_str(resp)}"
        except Exception as e:
            last_err = str(e)

        time.sleep(REPORT_RETRY_WAIT)

    log_local("relay_report_fail", {"event": event, "error": last_err})
    return False, {"ok": False, "error": last_err}

# ============================================================
# Remote IP Normalize (strict, allow IP or CIDR)
# ============================================================

def normalize_client_ip(ip_str):
    """
    RemoteIP 정규화:
    - 단일 IP: "1.2.3.4"
    - CIDR: "1.2.3.0/24"
    - IPv4-mapped IPv6(::ffff:1.2.3.4) 처리
    - 여러개/공백/이상값은 차단(None)
    """
    if not ip_str:
        return None

    t = str(ip_str).strip()
    if t.startswith("::ffff:"):
        t = t.replace("::ffff:", "")
    t = t.strip()

    # RemoteIP는 "단일 1개" 정책 (comma/space 있으면 차단)
    if "," in t:
        return None
    if " " in t:
        return None

    # CIDR 허용
    try:
        if "/" in t:
            ipaddress.ip_network(t, strict=False)
            return t
        else:
            ipaddress.ip_address(t)
            return t
    except Exception:
        return None

# ============================================================
# Firewall (Windows netsh) - RemoteIP Only
# ============================================================

def build_rule_name(session_id, port):
    """
    요구사항: GenieSecurityTempRule_{port}_{sid}
    """
    sid = str(session_id or "nosid").strip()
    sid = sid.replace('"', "").replace("'", "").replace(" ", "_")

    base = f"GenieSecurityTempRule_{port}_"
    max_total = 180
    max_sid_len = max_total - len(base)
    if max_sid_len < 8:
        max_sid_len = 8
    if len(sid) > max_sid_len:
        sid = sid[:max_sid_len]

    return f"{base}{sid}"

def firewall_add_rule(port, rule_name, remote_ip):
    if not remote_ip:
        return False, "", "remote_ip missing", 400

    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=allow",
        "protocol=TCP",
        f"localport={port}",
        f"remoteip={remote_ip}"
    ]

    if DRY_RUN:
        log_local("dryrun_firewall_add", {"cmd": cmd})
        return True, "(DRY_RUN) firewall add skipped", "", 0

    ok, out, err, rc = run_cmd(cmd)
    log_local("firewall_add", {"ok": ok, "rc": rc, "out": out, "err": err, "cmd": cmd})
    return ok, out, err, rc

def firewall_delete_rule(rule_name):
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ]

    if DRY_RUN:
        log_local("dryrun_firewall_delete", {"cmd": cmd})
        return True, "(DRY_RUN) firewall delete skipped", "", 0

    last = None
    for i in range(FW_DELETE_RETRY):
        ok, out, err, rc = run_cmd(cmd)
        log_local("firewall_delete_try", {"try": i+1, "ok": ok, "rc": rc, "out": out, "err": err, "cmd": cmd})

        msg = (out + " " + err).lower()
        if ok or ("no rules match" in msg) or ("일치하는 규칙이 없습니다" in msg):
            return True, out, err, rc

        last = (out, err, rc)
        time.sleep(FW_DELETE_RETRY_WAIT)

    return False, safe_str(last[0] if last else ""), safe_str(last[1] if last else "delete failed"), (last[2] if last else 500)

def firewall_delete_all_for_port(port):
    """
    제품급: 포트 기준 잔재 룰 전부 삭제
    """
    prefix = f"GenieSecurityTempRule_{port}_"
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={prefix}*"
    ]

    if DRY_RUN:
        log_local("dryrun_firewall_delete_all_for_port", {"cmd": cmd, "port": port})
        return True, "(DRY_RUN) firewall delete all skipped", "", 0

    last = None
    for i in range(FW_DELETE_RETRY):
        ok, out, err, rc = run_cmd(cmd)
        log_local("firewall_delete_all_for_port_try", {"try": i+1, "ok": ok, "rc": rc, "out": out, "err": err, "cmd": cmd})

        msg = (out + " " + err).lower()
        if ok or ("no rules match" in msg) or ("일치하는 규칙이 없습니다" in msg):
            return True, out, err, rc

        last = (out, err, rc)
        time.sleep(FW_DELETE_RETRY_WAIT)

    return False, safe_str(last[0] if last else ""), safe_str(last[1] if last else "delete failed"), (last[2] if last else 500)

def firewall_delete_all_genie_rules():
    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        "name=GenieSecurityTempRule_*"
    ]

    if DRY_RUN:
        log_local("dryrun_firewall_delete_all_genie_rules", {"cmd": cmd})
        return True, "(DRY_RUN) sweep skipped", "", 0

    ok, out, err, rc = run_cmd(cmd)
    log_local("firewall_sweep_delete_all", {"ok": ok, "rc": rc, "out": out, "err": err, "cmd": cmd})

    msg = (out + " " + err).lower()
    if ok or ("no rules match" in msg) or ("일치하는 규칙이 없습니다" in msg):
        return True, out, err, rc

    return False, out, err, rc

def firewall_rule_exists(rule_name):
    cmd = [
        "netsh", "advfirewall", "firewall", "show", "rule",
        f"name={rule_name}"
    ]

    if DRY_RUN:
        return False

    ok, out, err, rc = run_cmd(cmd)
    txt = (out + " " + err).lower()
    if ("no rules match" in txt) or ("일치하는 규칙이 없습니다" in txt):
        return False
    return True if (out.strip() != "" and ok) else False

def firewall_verify_remoteip(rule_name, expected_ip):
    """
    제품급: 실제 RemoteIP가 expected_ip로 들어갔는지 검증
    """
    cmd = [
        "netsh", "advfirewall", "firewall", "show", "rule",
        f"name={rule_name}",
        "verbose"
    ]

    if DRY_RUN:
        log_local("dryrun_firewall_verify_remoteip", {"cmd": cmd, "rule_name": rule_name, "expected_ip": expected_ip})
        return True, "(DRY_RUN) verify skipped", ""

    ok, out, err, rc = run_cmd(cmd)
    log_local("firewall_verify_show_rule", {"ok": ok, "rc": rc, "out": out, "err": err, "cmd": cmd})

    if not ok:
        return False, out, err

    low = (out or "").lower()
    exp = expected_ip.strip().lower()

    if ("remoteip" not in low) and ("remote ip" not in low):
        return False, out, "verify failed: remoteip field not found"

    if exp not in low:
        return False, out, f"verify failed: expected remoteip={expected_ip} not found"

    return True, out, ""

# ============================================================
# Relay expiresAt 기반 유지
# ============================================================
def compute_hold_seconds_from_expires_at(expires_at):
    try:
        if expires_at is None:
            return None
        ea = int(expires_at)
        remain = ea - int(time.time())
        if remain < 0:
            remain = 0
        return remain
    except Exception:
        return None

# ============================================================
# Cleanup helper
# ============================================================

def cleanup_always_closed(session_id=None):
    """
    Always-Closed 보장: 열려있으면 반드시 닫는다.
    (서비스 stop/예외/인터럽트/사이클 종료 등에서 호출)
    """
    try:
        if STATE.get("opened") and STATE.get("rule_name"):
            rn = STATE.get("rule_name")
            ap = STATE.get("assigned_port")
            cip = STATE.get("client_ip")
            su = STATE.get("server_uuid")
            st = STATE.get("server_token")

            out_print("\n[cleanup] Windows Firewall 룰 CLOSE(강제 삭제) ...")
            okc, outc, errc, rcc = firewall_delete_rule(rn)

            if okc and firewall_rule_exists(rn):
                log_local("cleanup_close_verify_rule_still_exists", {"rule_name": rn})
                firewall_delete_rule(rn)
                if ap:
                    firewall_delete_all_for_port(ap)

            if okc:
                out_print(" [cleanup] 방화벽 CLOSE 성공!")

                # report best-effort
                try:
                    report_firewall(
                        su,
                        st,
                        event="FIREWALL_CLOSE_OK",
                        session_id=session_id,
                        assigned_port=ap,
                        rule_name=rn,
                        message="cleanup: rule deleted (Ctrl+C/exception/service stop/cycle end)",
                        remote_ip=cip
                    )
                    report_firewall(
                        su,
                        st,
                        event="FIREWALL_CLOSED",
                        session_id=session_id,
                        assigned_port=ap,
                        rule_name=rn,
                        message="cleanup: rule deleted (alias)",
                        remote_ip=cip
                    )
                except Exception:
                    pass

                STATE["opened"] = False
            else:
                msg = f"cleanup 방화벽 CLOSE 실패(rc={rcc}) out={safe_str(outc)} err={safe_str(errc)}"
                out_print(" [cleanup]", msg)
                log_local("cleanup_firewall_close_fail", {"rule_name": rn, "port": ap, "client_ip": cip, "out": outc, "err": errc, "rc": rcc})

                try:
                    report_firewall(
                        su,
                        st,
                        event="FIREWALL_CLOSE_FAIL",
                        session_id=session_id,
                        assigned_port=ap,
                        rule_name=rn,
                        message=msg,
                        remote_ip=cip
                    )
                    fail_block(su, st, session_id, "CLEANUP_CLOSE_FAIL", {"rc": rcc, "out": safe_str(outc), "err": safe_str(errc)})
                except Exception:
                    pass
    except Exception as e:
        log_local("cleanup_exception", {"error": safe_str(e)})
    finally:
        # 상태 reset (다음 사이클로 안전 복귀)
        reset_state()

# ============================================================
# One cycle (confirm-open -> open -> hold -> close)
# ============================================================

def run_one_cycle(server_uuid, server_token=None):
    """
    1회 사이클:
    - confirm-open 성공할 때까지 폴링(UNATTENDED)
    - 승인되면 firewall open/verify
    - expiresAt 기반 hold + session poll
    - close
    - 서비스면 다음 사이클로 복귀 가능하도록 return
    """
    session_id = None

    STATE["server_uuid"] = server_uuid
    STATE["server_token"] = server_token

    # ---------- confirm-open polling ----------
    if UNATTENDED:
        out_print("[1] Relay confirm-open 무인 대기(폴링) 시작...")
        last_print = 0.0
        while True:
            if should_stop_service():
                log_local("service_stop_seen_during_confirm_open", {"stopEvent": SERVICE_STOP_EVENT_NAME})
                service_log("INFO", "stop_event_seen_during_confirm_open", {"stopEvent": SERVICE_STOP_EVENT_NAME})
                cleanup_always_closed(session_id=None)
                return "STOP"

            try:
                code, resp = confirm_open(server_uuid, server_token)
            except Exception as e:
                # 서비스 모드에서는 exit 금지: 백오프 후 재시도
                msg = f"confirm-open 예외(대기/재시도): {safe_str(e)}"
                out_print(msg)
                log_local("confirm_open_exception", {"error": safe_str(e)})
                time.sleep(max(1.0, SERVICE_ERROR_BACKOFF_SEC if SERVICE_MODE else 1.0))
                continue

            if code == 200 and isinstance(resp, dict) and resp.get("ok", False):
                break

            err = resp.get("error") if isinstance(resp, dict) else str(resp)
            if code == 409 and str(err) == "no_consumable_opened_session":
                now_t = time.time()
                if (now_t - last_print) >= CONFIRM_OPEN_STATUS_PRINT_SEC:
                    last_print = now_t
                    out_print("  ... 승인 대기 중 (dashboard OPEN 승인 후 자동 진행) ...")
                log_local("confirm_open_wait", {"code": code, "error": safe_str(err)})
                time.sleep(CONFIRM_OPEN_POLL_INTERVAL_SEC)
                continue

            # 치명 실패: 서비스면 루프 유지(백오프), 일반 모드면 종료
            msg = f"confirm-open 실패(치명): HTTP {code} / {safe_str(err)}"
            out_print(msg)
            log_local("confirm_open_fail", {"code": code, "resp": resp})
            try:
                report_firewall(server_uuid, server_token, event="CONFIRM_OPEN_FAIL", message=msg)
            except Exception:
                pass

            if SERVICE_MODE:
                time.sleep(max(1.0, SERVICE_ERROR_BACKOFF_SEC))
                continue

            pause_if_enabled()
            return "END"
    else:
        out_print("[1] Relay confirm-open 요청 중...")
        code, resp = confirm_open(server_uuid, server_token)
        if code != 200 or not isinstance(resp, dict) or not resp.get("ok", False):
            err = resp.get("error") if isinstance(resp, dict) else str(resp)
            msg = f"confirm-open 실패: HTTP {code} / {safe_str(err)}"
            out_print(msg)
            log_local("confirm_open_fail", {"code": code, "resp": resp})
            report_firewall(server_uuid, server_token, event="CONFIRM_OPEN_FAIL", message=msg)
            pause_if_enabled()
            return "END"

    session_id = resp.get("sessionId") or resp.get("sid") or ""
    assigned_port = resp.get("assignedPort")
    client_ip_raw = resp.get("clientIp") or resp.get("allowedIp") or ""

    expires_at = resp.get("expiresAt")

    # Export local snapshot for local hooks (e.g., SSH command guard)
    try:
        write_current_session(session_id=session_id, assigned_port=assigned_port, client_ip=client_ip_raw, expires_at=expires_at)
    except Exception:
        pass

    hold_sec = compute_hold_seconds_from_expires_at(expires_at)
    if hold_sec is None:
        hold_sec = FIREWALL_OPEN_SEC

    client_ip = normalize_client_ip(client_ip_raw)
    if not client_ip:
        msg = f"clientIp 누락/비정상. raw={safe_str(client_ip_raw)} (remoteip 강제 정책)"
        out_print(msg)
        log_local("client_ip_invalid", {"raw": client_ip_raw, "resp": resp})

        try:
            report_firewall(server_uuid, server_token, event="REMOTEIP_INVALID", session_id=session_id, message=msg)
            fail_block(server_uuid, server_token, session_id, "REMOTEIP_INVALID", {"raw": client_ip_raw})
        except Exception:
            pass

        # 서비스면 다음 사이클로 복귀
        if SERVICE_MODE:
            cleanup_always_closed(session_id=session_id)
            return "CONTINUE"

        pause_if_enabled()
        return "END"

    try:
        assigned_port = int(assigned_port)
        if assigned_port < 1 or assigned_port > 65535:
            raise ValueError("port range")
    except Exception:
        msg = f"assignedPort 비정상: {safe_str(assigned_port)}"
        out_print(msg)
        log_local("assigned_port_invalid", {"assigned_port": assigned_port, "resp": resp})

        try:
            report_firewall(server_uuid, server_token, event="ASSIGNEDPORT_INVALID", session_id=session_id, message=msg, remote_ip=client_ip)
            fail_block(server_uuid, server_token, session_id, "ASSIGNEDPORT_INVALID", {"assignedPort": assigned_port})
        except Exception:
            pass

        if SERVICE_MODE:
            cleanup_always_closed(session_id=session_id)
            return "CONTINUE"

        pause_if_enabled()
        return "END"

    rule_name = build_rule_name(session_id, assigned_port)

    STATE["rule_name"] = rule_name
    STATE["assigned_port"] = assigned_port
    STATE["client_ip"] = client_ip

    out_print(f"\n 승인됨: sessionId={session_id}")
    out_print(f" assignedPort={assigned_port}")
    out_print(f" clientIp={client_ip}")
    out_print(f" ruleName={rule_name}")

    if expires_at is not None:
        out_print(f" expiresAt={expires_at} (Relay TTL)")
        out_print(f" holdSec={hold_sec} (expiresAt 기반 유지)")
    else:
        out_print(f"⚠ expiresAt 없음 → holdSec={hold_sec} (FIREWALL_OPEN_SEC fallback)")
    out_print("")

    firewall_delete_all_for_port(assigned_port)
    firewall_delete_rule(rule_name)
    firewall_delete_rule(rule_name)

    out_print("[2] Windows Firewall 룰 생성(remoteip=clientIp) ...")
    ok, out, err, rc = firewall_add_rule(assigned_port, rule_name, client_ip)
    if not ok:
        msg = f"방화벽 룰 OPEN 실패(rc={rc}) out={safe_str(out)} err={safe_str(err)}"
        out_print(msg)
        log_local("firewall_open_fail", {"rule_name": rule_name, "port": assigned_port, "client_ip": client_ip, "out": out, "err": err, "rc": rc})

        try:
            report_firewall(server_uuid, server_token, event="FIREWALL_OPEN_FAIL", session_id=session_id, assigned_port=assigned_port, rule_name=rule_name, message=msg, remote_ip=client_ip)
            fail_block(server_uuid, server_token, session_id, "FIREWALL_OPEN_FAIL", {"rc": rc, "out": safe_str(out), "err": safe_str(err)})
        except Exception:
            pass

        if SERVICE_MODE:
            cleanup_always_closed(session_id=session_id)
            return "CONTINUE"

        pause_if_enabled()
        return "END"

    v_ok, v_out, v_err = firewall_verify_remoteip(rule_name, client_ip)
    if not v_ok:
        msg = f"방화벽 룰 VERIFY 실패: remoteip={client_ip} 확인 불가. err={safe_str(v_err)}"
        out_print(msg)
        log_local("firewall_verify_fail", {"rule_name": rule_name, "port": assigned_port, "client_ip": client_ip, "out": v_out, "err": v_err})

        firewall_delete_rule(rule_name)

        try:
            report_firewall(server_uuid, server_token, event="FIREWALL_VERIFY_FAIL", session_id=session_id, assigned_port=assigned_port, rule_name=rule_name, message=msg, remote_ip=client_ip)
            fail_block(server_uuid, server_token, session_id, "FIREWALL_VERIFY_FAIL", {"err": safe_str(v_err)})
        except Exception:
            pass

        if SERVICE_MODE:
            cleanup_always_closed(session_id=session_id)
            return "CONTINUE"

        pause_if_enabled()
        return "END"

    out_print(" 방화벽 OPEN 성공 + RemoteIP 검증 OK!")
    STATE["opened"] = True

    try:
        report_firewall(
            server_uuid,
            server_token,
            event="FIREWALL_OPEN_OK",
            session_id=session_id,
            assigned_port=assigned_port,
            rule_name=rule_name,
            message="remoteip=clientIp only allow (verified)",
            remote_ip=client_ip
        )
    except Exception:
        pass

    try:
        out_print(f"\n[3] {hold_sec}초 동안 포트 OPEN 유지... (Relay expiresAt 기반)")
        out_print(f"    (Extend 동기화: {SESSION_POLL_INTERVAL_SEC}초마다 session expiresAt 재조회)")

        end_at = int(time.time()) + int(hold_sec)

        last_poll = 0
        last_seen_expires_at = int(expires_at) if expires_at is not None else None

        while True:
            if should_stop_service():
                log_local("service_stop_seen_during_hold", {"stopEvent": SERVICE_STOP_EVENT_NAME, "sessionId": session_id})
                service_log("INFO", "stop_event_seen_during_hold", {"stopEvent": SERVICE_STOP_EVENT_NAME, "sessionId": session_id})
                break

            now = int(time.time())

            if (now - last_poll) >= SESSION_POLL_INTERVAL_SEC:
                last_poll = now
                try:
                    scode, sresp = get_session(session_id)
                    if scode == 200 and isinstance(sresp, dict) and sresp.get("ok", False):
                        s = sresp.get("session") or {}
                        s_expires_at = s.get("expiresAt")
                        s_status = (s.get("status") or "").strip().upper()
                  
                        if not STATE["connected"] and s_status == "OPEN":
                            STATE["connected"] = True
                            log_local("SESSION_CONNECTED", {"sessionId": session_id, "expiresAt": s_expires_at})
    


                        if s_status in ["EXPIRED", "REJECTED", "CLOSED"]:
                            log_local("session_status_terminal", {"status": s_status, "session": s})
                            break

                        try:
                            if s_expires_at is not None:
                                s_expires_at = int(s_expires_at)
                                if (last_seen_expires_at is None) or (s_expires_at != last_seen_expires_at):
                                    last_seen_expires_at = s_expires_at
                                    end_at = s_expires_at
                                    log_local("expiresAt_synced", {"new_expiresAt": s_expires_at, "end_at": end_at, "status": s_status})
                        except Exception:
                            pass
                except Exception as e:
                    log_local("session_poll_error", {"error": safe_str(e)})

            remain = end_at - now
            if remain <= 0:
                break

            time.sleep(1)

        out_print("\n[4] Windows Firewall 룰 CLOSE(강제 삭제) ...")
        ok2, out2, err2, rc2 = firewall_delete_rule(rule_name)

        if ok2 and firewall_rule_exists(rule_name):
            log_local("close_verify_rule_still_exists", {"rule_name": rule_name})
            firewall_delete_rule(rule_name)
            firewall_delete_all_for_port(assigned_port)

        if not ok2:
            msg = f"방화벽 CLOSE 실패(rc={rc2}) out={safe_str(out2)} err={safe_str(err2)}"
            out_print(msg)
            log_local("firewall_close_fail", {"rule_name": rule_name, "port": assigned_port, "client_ip": client_ip, "out": out2, "err": err2, "rc": rc2})

            try:
                report_firewall(server_uuid, server_token, event="FIREWALL_CLOSE_FAIL", session_id=session_id, assigned_port=assigned_port, rule_name=rule_name, message=msg, remote_ip=client_ip)
                fail_block(server_uuid, server_token, session_id, "FIREWALL_CLOSE_FAIL", {"rc": rc2, "out": safe_str(out2), "err": safe_str(err2)})
            except Exception:
                pass

            if SERVICE_MODE:
                cleanup_always_closed(session_id=session_id)
                return "CONTINUE"

            pause_if_enabled()
            return "END"

        out_print(" 방화벽 CLOSE 성공!")

        try:
            report_firewall(server_uuid, server_token, event="FIREWALL_CLOSE_OK", session_id=session_id, assigned_port=assigned_port, rule_name=rule_name, message="rule deleted", remote_ip=client_ip)
            report_firewall(server_uuid, server_token, event="FIREWALL_CLOSED", session_id=session_id, assigned_port=assigned_port, rule_name=rule_name, message="rule deleted (alias)", remote_ip=client_ip)
        except Exception:
            pass

        STATE["opened"] = False

        out_print("\n Step 완료 (expiresAt 기준 OPEN → CLOSE + audit report 완료)")
        pause_if_enabled()

    except KeyboardInterrupt:
        out_print("\n⚠ Ctrl+C 감지: cleanup에서 강제 회수 진행...")
        log_local("keyboard_interrupt", {"message": "Ctrl+C detected. cleanup will run."})

    except Exception as e:
        msg = f"예외 발생: {safe_str(e)}"
        out_print(msg)
        log_local("exception", {"error": safe_str(e)})

        try:
            report_firewall(server_uuid, server_token, event="AGENT_EXCEPTION", session_id=session_id, assigned_port=assigned_port, rule_name=rule_name, message=msg, remote_ip=client_ip)
            fail_block(server_uuid, server_token, session_id, "AGENT_EXCEPTION", {"error": safe_str(e)})
        except Exception:
            pass

    finally:
        # Always-Closed 보장 + 상태 reset
        cleanup_always_closed(session_id=session_id)

        # 서비스 모드에서 stop event면 정상 종료로 마무리
        if SERVICE_MODE and should_stop_service():
            log_local("service_stop_exit", {"stopEvent": SERVICE_STOP_EVENT_NAME})
            service_log("INFO", "service_stop_exit", {"stopEvent": SERVICE_STOP_EVENT_NAME})
            return "STOP"

    return "CONTINUE"

# ============================================================
# Main Flow
# ============================================================

def main():
    flags = parse_args(sys.argv[1:])

    global SERVICE_MODE, UNATTENDED, PAUSE_ON_EXIT
    SERVICE_MODE = bool(flags.get("service", False))
    if SERVICE_MODE:
        # Service 모드 강제 정책
        _init_service_paths()
        UNATTENDED = True
        PAUSE_ON_EXIT = False
        service_log("INFO", "service_mode_start", {
            "RELAY_BASE": RELAY_BASE,
            "FIREWALL_OPEN_SEC": FIREWALL_OPEN_SEC,
            "DRY_RUN": DRY_RUN,
            "AUDIT_PATH": AUDIT_PATH,
            "LAST_INPUTS_PATH": LAST_INPUTS_PATH,
            "SERVER_TOKEN_DPAPI_PATH": SERVER_TOKEN_DPAPI_PATH,
            "REGISTRY_PATH": REGISTRY_PATH,
            "STOP_EVENT": SERVICE_STOP_EVENT_NAME,
        })
        # Identity Proof는 service에서 무조건 선 로드(없으면 Always-Closed 대기)
        ident, st = load_identity_dpapi()
        if not ident:
            service_log("WARN", "service_missing_identity", {"path": SERVER_IDENTITY_DPAPI_PATH, "status": st})
        else:
            service_log("INFO", "identity_loaded", {"kid": ident.get("kid"), "alg": ident.get("alg")})

    # --unattended 옵션도 유지 (service는 이미 unattended 강제)
    if flags.get("unattended"):
        UNATTENDED = True

    # ---- Token provisioning: UAC 없이 실행 가능(방화벽 안 만짐) ----
    if flags.get("token_status"):
        exists = bool(SERVER_TOKEN_DPAPI_PATH and os.path.exists(SERVER_TOKEN_DPAPI_PATH))
        out_print(f"DPAPI_TOKEN_FILE = {SERVER_TOKEN_DPAPI_PATH}")
        out_print(f"DPAPI_SCOPE      = {DPAPI_SCOPE}")
        out_print(f"EXISTS           = {exists}")
        sys.exit(0)

    if flags.get("clear_token"):
        ok, msg = clear_token_dpapi()
        out_print(f"DPAPI_TOKEN_CLEAR = {ok} ({msg}) path={SERVER_TOKEN_DPAPI_PATH}")
        sys.exit(0 if ok else 2)

    if flags.get("store_token"):
        token = os.environ.get("SERVER_TOKEN", "").strip()
        if not token:
            out_print("ERROR: --store-token requires env SERVER_TOKEN to be set. (Always-closed)")
            out_print("예) set SERVER_TOKEN=DEV_TOKEN_001")
            sys.exit(2)
        ok = save_token_dpapi(token)
        if ok:
            out_print(f"DPAPI_TOKEN_SAVED = True  path={SERVER_TOKEN_DPAPI_PATH} scope={DPAPI_SCOPE}")
            sys.exit(0)
        out_print("DPAPI_TOKEN_SAVED = False")
        sys.exit(2)


    # ---- Identity provisioning: Long-term server key (DPAPI) ----
    if flags.get("identity_status"):
        exists = bool(SERVER_IDENTITY_DPAPI_PATH and os.path.exists(SERVER_IDENTITY_DPAPI_PATH))
        out_print(f"DPAPI_IDENTITY_FILE = {SERVER_IDENTITY_DPAPI_PATH}")
        out_print(f"DPAPI_SCOPE         = {DPAPI_SCOPE}")
        out_print(f"EXISTS              = {exists}")
        if exists:
            ident, st = load_identity_dpapi()
            out_print(f"LOAD_STATUS         = {st}")
            if ident and st == "ok":
                out_print(f"KID                 = {ident.get('kid')}")
                out_print(f"ALG                 = {ident.get('alg')}")
                out_print(f"PUB_B64             = {ident.get('pub')}")
                out_print(f"SIG_PUB_B64         = {ident.get('sig_pub')}")
        sys.exit(0 if exists else 2)

    if flags.get("clear_identity"):
        ok, msg = clear_identity_dpapi()
        out_print(f"DPAPI_IDENTITY_CLEAR = {ok} ({msg}) path={SERVER_IDENTITY_DPAPI_PATH}")
        sys.exit(0 if ok else 2)

    if flags.get("provision_identity"):
        # Force machine scope for identity provisioning (운영 정석)
        try:
            kid, pub_b64, priv_raw_b64, sig_pub_b64, sig_priv_raw_b64 = generate_server_identity()
            ok, msg = save_identity_dpapi(kid, pub_b64, priv_raw_b64, sig_pub_b64, sig_priv_raw_b64)
            if not ok:
                out_print(f"ERROR: identity_save_failed: {msg}")
                sys.exit(2)
            out_print("DPAPI_IDENTITY_SAVED = True")
            out_print(f"KID         = {kid}")
            out_print(f"PUBLIC_B64   = {pub_b64}")
            out_print(f"SIGN_PUB_B64 = {sig_pub_b64}")
            out_print(f"PATH        = {SERVER_IDENTITY_DPAPI_PATH}")
            out_print(f"SCOPE       = {DPAPI_SCOPE}")
            sys.exit(0)
        except Exception as e:
            out_print(f"ERROR: provision_identity_failed: {safe_str(e)}")
            sys.exit(2)

    # Service Stop 요청이면 즉시 종료
    if should_stop_service():
        log_local("service_stop_seen_before_start", {"stopEvent": SERVICE_STOP_EVENT_NAME})
        service_log("INFO", "stop_event_seen_before_start", {"name": SERVICE_STOP_EVENT_NAME})
        sys.exit(0)

    # ---- Firewall flow: admin required ----
    if not is_admin():
        if SERVICE_MODE:
            # 서비스는 LocalSystem/admin으로 떠야 정상. UAC 재실행 금지.
            msg = "SERVICE_MODE but not admin. keep running and wait (always-closed)."
            log_local("service_not_admin", {"message": msg})
            service_log("ERROR", "service_not_admin", {"message": msg})
            # exit 금지(서비스 재시작 루프 방지) -> 아래 서비스 루프에서 백오프 처리
        else:
            out_print("⚠ 관리자 권한이 아닙니다. 자동으로 관리자 권한(UAC)으로 재실행합니다...")
            relaunch_as_admin()
            return

    print_banner()

    # Startup Sweep (이전 잔재 룰 전부 삭제) - service는 최초 1회만
    did_sweep = False

    def do_sweep_once():
        nonlocal did_sweep
        if did_sweep:
            return
        if STARTUP_SWEEP_ALL_RULES:
            out_print("[BOOT] Startup Sweep: 잔재 GenieSecurityTempRule_* 전부 삭제 ...")
            ok_s, out_s, err_s, rc_s = firewall_delete_all_genie_rules()
            if ok_s:
                out_print(" [BOOT] Sweep 완료 (잔재 룰 정리)")
            else:
                out_print(f"⚠ [BOOT] Sweep 실패(rc={rc_s}) out={safe_str(out_s)} err={safe_str(err_s)}")
            out_print("")
        did_sweep = True

    # ========================================================
    # SERVICE LOOP: 절대 종료하지 않고 승인 대기/세션 처리 반복
    # ========================================================
    if SERVICE_MODE:
        service_log("INFO", "service_loop_enter", {"note": "service mode will not exit until stop event is seen"})
        while True:
            if should_stop_service():
                log_local("service_stop_seen_top", {"stopEvent": SERVICE_STOP_EVENT_NAME})
                service_log("INFO", "stop_event_seen_top", {"stopEvent": SERVICE_STOP_EVENT_NAME})
                cleanup_always_closed(session_id=None)
                return

            # 서비스는 관리자 권한이 아니면 동작 불가 -> exit 금지, 대기 후 재시도
            if not is_admin():
                service_log("ERROR", "service_not_admin_wait", {"sleepSec": SERVICE_NOT_ADMIN_BACKOFF_SEC})
                time.sleep(max(1.0, SERVICE_NOT_ADMIN_BACKOFF_SEC))
                continue

            # sweep 1회
            do_sweep_once()

            # 매 루프마다 최신 입력/토큰 재확인 (운영 중 프로비저닝 대응)
            env_uuid = os.environ.get("SERVER_UUID", "").strip()
            env_token = os.environ.get("SERVER_TOKEN", "").strip()

            dpapi_token = None
            if not env_token:
                dpapi_token = load_token_dpapi()

            reg_uuid = None
            if not env_uuid:
                reg_uuid = load_registry_uuid_only()

            last_uuid = None
            if not env_uuid:
                last_uuid = load_last_inputs()

            default_uuid = env_uuid or reg_uuid or last_uuid or DEFAULT_SERVER_UUID

            server_uuid = env_uuid or default_uuid
            server_token = env_token or dpapi_token

            # 토큰/UUID 없으면 exit 금지: 대기 후 재시도
            ident, st_ident = load_identity_dpapi()
            if not server_uuid or st_ident != "ok":
                out_print(" [SERVICE] SERVER_UUID 또는 server_identity.dpapi 없음. (Always-closed) 대기...")
                log_local("service_missing_identity", {"SERVER_UUID": bool(server_uuid), "IDENT_OK": (st_ident == "ok")})
                service_log("ERROR", "service_missing_identity", {"SERVER_UUID": bool(server_uuid), "IDENT_OK": (st_ident == "ok")})
                time.sleep(max(1.0, SERVICE_MISSING_TOKEN_BACKOFF_SEC))
                continue
            # SERVER_TOKEN은 더 이상 필수 아님 (하위호환/운영 로그용)
            

            # 1사이클 수행 (승인 대기 -> OPEN/CLOSE -> 다음 대기)
            try:
                result = run_one_cycle(server_uuid, None)
                if result == "STOP":
                    return
                time.sleep(max(0.0, SERVICE_LOOP_IDLE_SEC))
                continue
            except Exception as e:
                msg = f"[SERVICE] cycle exception: {safe_str(e)}"
                out_print(msg)
                log_local("service_cycle_exception", {"error": safe_str(e)})
                service_log("ERROR", "service_cycle_exception", {"error": safe_str(e)})
                cleanup_always_closed(session_id=None)
                time.sleep(max(1.0, SERVICE_ERROR_BACKOFF_SEC))
                continue

    # ========================================================
    # NORMAL MODE: 기존 동작 유지(한 번 실행 후 종료)
    # ========================================================

    # Startup Sweep (이전 잔재 룰 전부 삭제)
    if STARTUP_SWEEP_ALL_RULES:
        out_print("[BOOT] Startup Sweep: 잔재 GenieSecurityTempRule_* 전부 삭제 ...")
        ok_s, out_s, err_s, rc_s = firewall_delete_all_genie_rules()
        if ok_s:
            out_print(" [BOOT] Sweep 완료 (잔재 룰 정리)")
        else:
            out_print(f"⚠ [BOOT] Sweep 실패(rc={rc_s}) out={safe_str(out_s)} err={safe_str(err_s)}")
        out_print("")

    env_uuid = os.environ.get("SERVER_UUID", "").strip()
    env_token = os.environ.get("SERVER_TOKEN", "").strip()

    dpapi_token = None
    if not env_token:
        dpapi_token = load_token_dpapi()

    reg_uuid = None
    if not env_uuid:
        reg_uuid = load_registry_uuid_only()

    last_uuid = None
    if not env_uuid:
        last_uuid = load_last_inputs()

    default_uuid = env_uuid or reg_uuid or last_uuid or DEFAULT_SERVER_UUID

    # Service 모드/Unattended는 무조건 프롬프트 금지
    if UNATTENDED:
        server_uuid = env_uuid or default_uuid
        ident, st_ident = load_identity_dpapi()
        if not server_uuid or st_ident != "ok":
            out_print(" UNATTENDED=1 인데 SERVER_UUID 또는 server_identity.dpapi가 없습니다. (Always-closed)")
            log_local("unattended_missing_identity", {"SERVER_UUID": bool(server_uuid), "IDENT_OK": (st_ident == "ok")})
            if SERVICE_MODE:
                service_log("ERROR", "unattended_missing_identity", {"SERVER_UUID": bool(server_uuid), "IDENT_OK": (st_ident == "ok")})
            sys.exit(2)
        server_token = None  # Step2: token 제거
    else:
        server_uuid = prompt_with_default("SERVER_UUID 입력", default_uuid, secret=False)
        server_token = None  # Step2: token 제거
        # (token prompt removed)
        if not server_uuid:
            out_print(" SERVER_UUID 또는 SERVER_TOKEN이 비어있습니다.")
            sys.exit(2)
        save_last_inputs(server_uuid)
        
    # 1회 실행
    try:
        run_one_cycle(server_uuid, None)
    except Exception as e:
        out_print(f"예외 발생: {safe_str(e)}")
        log_local("exception", {"error": safe_str(e)})
        cleanup_always_closed(session_id=None)

if __name__ == "__main__":
    main()
