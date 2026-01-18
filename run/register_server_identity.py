#!/usr/bin/env python3
# GenieSecurity - register server identity to Relay (internal/offline product)
# - Reads server identity via server_agent.py --identity-status
# - Calls Relay APIs: /api/server/register-intent -> /api/operator/approve-server
# - No external deps (urllib)
import os, sys, subprocess, json
from pathlib import Path
from urllib import request, error

def parse_dotenv(path: Path) -> dict:
    out = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            continue
        k, v = s.split("=", 1)
        out[k.strip()] = v.strip()
    return out

def http_post_json(url: str, body: dict, headers: dict | None = None, timeout: int = 8):
    data = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = request.Request(url, data=data, headers=h, method="POST")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            txt = resp.read().decode("utf-8", errors="replace")
            return resp.status, txt
    except error.HTTPError as e:
        txt = e.read().decode("utf-8", errors="replace")
        return e.code, txt
    except Exception as e:
        return 0, str(e)

def extract_identity(server_agent_py: Path, py_exe: Path) -> dict:
    # run: python server_agent.py --identity-status
    p = subprocess.run(
        [str(py_exe), "-u", str(server_agent_py), "--identity-status"],
        capture_output=True,
        text=True,
        cwd=str(server_agent_py.parent.parent.parent),  # base dir
    )
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    kid = pub = sig_pub = ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("KID"):
            kid = line.split("=", 1)[-1].strip()
        elif line.startswith("PUB_B64"):
            pub = line.split("=", 1)[-1].strip()
        elif line.startswith("SIG_PUB_B64"):
            sig_pub = line.split("=", 1)[-1].strip()
    if not (kid and pub and sig_pub):
        raise RuntimeError("identity_status_missing_fields")
    return {"kid": kid, "pub": pub, "sigPub": sig_pub, "raw": out}

def main():
    # BASE_DIR = repo root (this script expected under BASE_DIR\\run or anywhere)
    here = Path(__file__).resolve()
    # If placed in BASE_DIR\\run, BASE_DIR is parent
    base_dir = here.parent.parent if here.parent.name.lower() == "run" else here.parent
    # fallback: walk up until find relay folder
    cur = here.parent
    for _ in range(6):
        if (cur / "relay").exists() and (cur / "agents").exists():
            base_dir = cur
            break
        cur = cur.parent

    py_exe = base_dir / "tools" / "python" / "python.exe"
    server_agent_py = base_dir / "agents" / "server" / "server_agent.py"

    if not py_exe.exists():
        print("[ERROR] bundled python not found:", py_exe)
        return 2
    if not server_agent_py.exists():
        print("[ERROR] server_agent.py not found:", server_agent_py)
        return 2

    relay_base = os.environ.get("RELAY_BASE", "").strip() or "http://127.0.0.1:3000"
    server_uuid = os.environ.get("SERVER_UUID", "").strip() or "serverUuidA"

    # operator creds: env -> config/.env.internal -> relay/.env
    operator_id = os.environ.get("OPERATOR_ID", "").strip()
    operator_key = os.environ.get("OPERATOR_KEY", "").strip()
    if not (operator_id and operator_key):
        env_internal = parse_dotenv(base_dir / "config" / ".env.internal")
        relay_env = parse_dotenv(base_dir / "relay" / ".env")
        operator_id = operator_id or env_internal.get("OPERATOR_ID") or relay_env.get("OPERATOR_ID") or ""
        operator_key = operator_key or env_internal.get("OPERATOR_KEY") or relay_env.get("OPERATOR_KEY") or ""

    if not (operator_id and operator_key):
        print("[ERROR] OPERATOR_ID/OPERATOR_KEY not found (env or config/.env.internal or relay/.env).")
        return 2

    try:
        ident = extract_identity(server_agent_py, py_exe)
    except Exception as e:
        print("[ERROR] Failed to read server identity:", str(e))
        return 2

    kid = ident["kid"]
    pub = ident["pub"]
    sig_pub = ident["sigPub"]

    print("============================================================")
    print("[BASE_DIR]   ", base_dir)
    print("[RELAY_BASE] ", relay_base)
    print("[SERVER_UUID]", server_uuid)
    print("[KID]        ", kid)
    print("============================================================")

    # 1) register-intent
    url1 = relay_base.rstrip("/") + "/api/server/register-intent"
    st1, tx1 = http_post_json(url1, {"serverUuid": server_uuid, "kid": kid, "pub": pub, "sigPub": sig_pub})
    print("[1] register-intent:", st1, tx1[:300])

    if st1 not in (200, 201):
        print("[ERROR] register-intent failed")
        return 3

    # 2) approve-server (legacy operator key in body)
    url2 = relay_base.rstrip("/") + "/api/operator/approve-server"
    st2, tx2 = http_post_json(url2, {"operatorId": operator_id, "operatorKey": operator_key, "serverUuid": server_uuid})
    print("[2] approve-server :", st2, tx2[:300])

    if st2 not in (200, 201):
        print("[ERROR] approve-server failed")
        return 4

    print("[OK] Server identity registered + approved. Now run server_agent again.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
